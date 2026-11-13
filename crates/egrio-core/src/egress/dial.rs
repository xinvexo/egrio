//! Connection scheduling over resolved addresses, for TCP dials and the
//! Hysteria2 QUIC carrier. DNS and connects overlap; a silent address does
//! not monopolize the entire dial budget, and IPv6 goes first when both
//! families answer (RFC 8305). All attempts belong to this future.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use tokio::net::TcpStream;
use tokio::time::{sleep_until, timeout_at, Duration, Instant};

use super::pending::Pending;
use super::{DialError, DialFailureKind, EgressBinding, EgressRuntime};
use crate::dns::service::QueryPurpose;
use crate::target::authority;

const DIAL_BUDGET: Duration = Duration::from_secs(16);
const CONNECT_BUDGET: Duration = Duration::from_secs(8);
const ATTEMPT_STAGGER: Duration = Duration::from_millis(250);
const MIN_ATTEMPT_DELAY: Duration = Duration::from_millis(10);
/// RFC 8305 section 3's recommended Resolution Delay.
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const MAX_PARALLEL_ATTEMPTS: usize = 4;
const MAX_REPORTED_ERRORS: usize = 16;
/// A proxy address's attempt that has not connected within this many times
/// the fastest handshake seen to the address, and at least [`HEDGE_MARGIN`]
/// over it, gets a second attempt from another socket; before a handshake was
/// seen, the second attempt starts at once unless the address has one path.
const HEDGE_FACTOR: f64 = 1.5;
const HEDGE_MARGIN: Duration = Duration::from_millis(25);
/// How long the fastest handshake to an address stands before any slower one
/// replaces it, since paths change.
const HANDSHAKE_MEMORY: Duration = Duration::from_secs(600);
/// Times a proxy connection dialed ahead is dialed again when its handshake
/// met a slow path.
const AHEAD_REDIALS: usize = 2;

impl EgressRuntime {
    pub(crate) async fn connect_tcp_host(
        &self,
        host: &str,
        port: u16,
        peer_label: &str,
    ) -> Result<TcpStream, DialError> {
        let (stream, _) = self
            .connect_tcp_host_for(host, port, peer_label, QueryPurpose::ProxyEndpoint)
            .await?;
        Ok(stream)
    }

    /// Dials a proxy endpoint for a connection still to come, or for one a
    /// connection will hold for long (a Trojan UDP association), whose path
    /// matters more than a moment's wait: a connection whose handshake took
    /// longer than the hedge point, its attempts having both met slow paths,
    /// is dropped and dialed again, up to [`AHEAD_REDIALS`] times.
    pub(crate) async fn connect_tcp_host_ahead(
        &self,
        host: &str,
        port: u16,
        peer_label: &str,
    ) -> Result<TcpStream, DialError> {
        let dial =
            || self.connect_tcp_host_for(host, port, peer_label, QueryPurpose::ProxyEndpoint);
        let slow = |(stream, took): &(TcpStream, Duration)| {
            stream
                .peer_addr()
                .ok()
                .and_then(|peer| self.handshakes().hedge_after(peer))
                .is_some_and(|after| *took > after)
        };
        let (stream, _) = until_fast(dial, slow, AHEAD_REDIALS).await?;
        Ok(stream)
    }

    /// Dials `host:port` and returns the connection with how long its
    /// handshake took.
    pub(super) async fn connect_tcp_host_for(
        &self,
        host: &str,
        port: u16,
        peer_label: &str,
        purpose: QueryPurpose,
    ) -> Result<(TcpStream, Duration), DialError> {
        let deadline = Instant::now() + DIAL_BUDGET;
        let resolutions = self
            .resolve_candidates(host, port, purpose)
            .map_err(DialError::local)?;
        let result = race_connections(resolutions, deadline, |address| async move {
            let budget = CONNECT_BUDGET.min(deadline.saturating_duration_since(Instant::now()));
            if purpose == QueryPurpose::ProxyEndpoint {
                self.connect_proxy_addr(address, budget).await
            } else {
                let began = Instant::now();
                let connected = self.connect_tcp_addr(address, budget).await?;
                Ok((connected, began.elapsed()))
            }
        })
        .await;
        match result {
            Ok((_, ((stream, binding), took))) => {
                // DNS and losing TCP attempts never write the selected binding.
                self.record_binding(binding);
                Ok((stream, took))
            }
            Err(failure) => {
                let message = format!(
                    "failed to connect {peer_label} {}: {failure}",
                    authority(host, port)
                );
                Err(DialError {
                    kind: failure.dial_kind(),
                    message,
                })
            }
        }
    }

    /// Dials a proxy address, starting a second attempt from another socket
    /// when the first has not connected by the point the fastest handshake
    /// seen to the address sets, or at once before one was seen (see
    /// [`Handshakes::hedge_point`]). The two
    /// leave from different ports, which a network that spreads connections
    /// over paths by their flow can give paths of their own, and the first to
    /// connect keeps its path for the connection's life. A lost SYN then
    /// costs the hedge point rather than the
    /// retransmission timeout.
    async fn connect_proxy_addr(
        &self,
        address: SocketAddr,
        budget: Duration,
    ) -> Result<((TcpStream, EgressBinding), Duration), DialError> {
        let started = Instant::now();
        let attempt = || async move {
            let began = Instant::now();
            let budget = budget.saturating_sub(began.duration_since(started));
            let connected = self.connect_tcp_addr(address, budget).await?;
            Ok((connected, began.elapsed()))
        };
        let (connected, took) = hedged(attempt, self.handshakes().hedge_point(address)).await?;
        self.handshakes().handshook(address, took);
        Ok((connected, took))
    }
}

/// Runs `dial` until what it dialed is not `slow`, at most `1 + redials`
/// times; the last dial stands whatever it met.
async fn until_fast<T, E, Fut>(
    dial: impl Fn() -> Fut,
    slow: impl Fn(&T) -> bool,
    redials: usize,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
{
    let mut left = redials;
    loop {
        let dialed = dial().await?;
        if left == 0 || !slow(&dialed) {
            return Ok(dialed);
        }
        left -= 1;
    }
}

/// Runs `attempt`, and runs it again once the first has gone `after`
/// without finishing (at once for a zero `after`, never for none); the first
/// to succeed wins and the other is dropped. If both fail, the first's
/// failure stands.
async fn hedged<T, E, Fut>(attempt: impl Fn() -> Fut, after: Option<Duration>) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
{
    let first = attempt();
    let Some(after) = after else {
        return first.await;
    };
    tokio::pin!(first);
    if !after.is_zero() {
        tokio::select! {
            biased;
            outcome = &mut first => return outcome,
            () = tokio::time::sleep(after) => {}
        }
    }
    let second = attempt();
    tokio::pin!(second);
    tokio::select! {
        outcome = &mut first => match outcome {
            Ok(value) => Ok(value),
            Err(error) => second.await.map_err(|_| error),
        },
        outcome = &mut second => match outcome {
            Ok(value) => Ok(value),
            Err(_) => first.await,
        },
    }
}

/// The fastest TCP handshake seen to each proxy address under one egress
/// policy, with when it was seen; it sets when a dial there starts a second
/// attempt.
#[derive(Debug, Default)]
pub(super) struct Handshakes(Mutex<HashMap<SocketAddr, (Duration, Instant)>>);

impl Handshakes {
    /// How long a dial to `address` waits before a second attempt:
    /// [`HEDGE_FACTOR`] times the fastest handshake seen to it, and at least
    /// [`HEDGE_MARGIN`] over it; no second attempt before one was seen.
    fn hedge_after(&self, address: SocketAddr) -> Option<Duration> {
        let (fastest, _) = *self.0.lock().expect("proxy handshakes").get(&address)?;
        Some(fastest.mul_f64(HEDGE_FACTOR).max(fastest + HEDGE_MARGIN))
    }

    /// When a dial to `address` starts its second attempt: at the hedge point
    /// once a handshake was seen ([`Self::hedge_after`]). Before that it
    /// starts at once, since the first connection to a node draws its path
    /// like any other and only a second draw keeps it off a slow one; except
    /// to an address with one path, which a second attempt cannot change.
    fn hedge_point(&self, address: SocketAddr) -> Option<Duration> {
        self.hedge_after(address)
            .or((!single_path(address.ip())).then_some(Duration::ZERO))
    }

    /// Notes a handshake to `address` that took `took`: the fastest yet, or
    /// any once the fastest is older than [`HANDSHAKE_MEMORY`].
    fn handshook(&self, address: SocketAddr, took: Duration) {
        let now = Instant::now();
        let mut handshakes = self.0.lock().expect("proxy handshakes");
        let fastest = handshakes.entry(address).or_insert((took, now));
        if took <= fastest.0 || now.duration_since(fastest.1) > HANDSHAKE_MEMORY {
            *fastest = (took, now);
        }
    }
}

/// Whether every connection to `ip` takes one path: an address of this host,
/// its link or a private network, which no route spreads flows from.
fn single_path(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => single_path(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
        },
    }
}

/// One attempt's failure as the race sees it.
pub(crate) trait AttemptError: fmt::Display {
    /// Whether no other address can succeed either, which ends the race.
    fn ends_race(&self) -> bool {
        false
    }
}

impl AttemptError for String {}

impl AttemptError for DialError {}

/// How one launched attempt failed.
#[derive(Debug)]
pub(crate) enum AttemptFailure<E> {
    Failed(E),
    /// The attempt's own budget ran out.
    TimedOut,
}

impl<E: fmt::Display> fmt::Display for AttemptFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(error) => error.fmt(formatter),
            Self::TimedOut => formatter.write_str("connection attempt budget exhausted"),
        }
    }
}

/// What a race saw when no address connected.
#[derive(Debug)]
pub(crate) struct RaceFailure<E> {
    /// Failed attempts in completion order, bounded.
    pub(crate) attempts: Vec<(SocketAddr, AttemptFailure<E>)>,
    /// Attempts launched, including any still pending when the race ended.
    pub(crate) launched: usize,
    /// Resolution failures, bounded.
    pub(crate) resolution: Vec<String>,
    /// The race ran out its deadline.
    pub(crate) budget_exhausted: bool,
    /// The failure that ended the race early (see [`AttemptError::ends_race`]).
    pub(crate) ended_by: Option<(SocketAddr, E)>,
}

impl<E> RaceFailure<E> {
    /// Every completed attempt failed with an error `is_local` accepts and
    /// the deadline did not cut a pending one short.
    pub(crate) fn only_local(&self, is_local: impl Fn(&E) -> bool) -> bool {
        self.launched > 0
            && !self.budget_exhausted
            && self.ended_by.is_none()
            && self.attempts.len() == self.launched
            && self.attempts.iter().all(
                |(_, failure)| matches!(failure, AttemptFailure::Failed(error) if is_local(error)),
            )
    }
}

impl RaceFailure<DialError> {
    /// The plain-socket reading: nothing launched means the name never
    /// resolved, only local refusals stay local, and anything else is the
    /// remote not accepting.
    pub(crate) fn dial_kind(&self) -> DialFailureKind {
        if self.launched == 0 {
            DialFailureKind::Resolve
        } else if self.only_local(|error| error.kind == DialFailureKind::Local) {
            DialFailureKind::Local
        } else {
            DialFailureKind::Connect
        }
    }
}

impl<E: fmt::Display> fmt::Display for RaceFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = self
            .attempts
            .iter()
            .map(|(address, failure)| format!("{address}: {failure}"))
            .collect();
        if let Some((address, error)) = &self.ended_by {
            parts.push(format!("{address}: {error}"));
        }
        parts.extend(self.resolution.iter().cloned());
        if self.budget_exhausted {
            parts.push("dial budget exhausted".into());
        }
        if parts.is_empty() {
            formatter.write_str("no addresses resolved")
        } else {
            formatter.write_str(&parts.join("; "))
        }
    }
}

pub(crate) async fn race_connections<'a, T, E, F, Fut>(
    mut resolutions: Pending<'a, Result<Vec<SocketAddr>, String>>,
    deadline: Instant,
    connect: F,
) -> Result<(SocketAddr, T), RaceFailure<E>>
where
    T: Send + 'a,
    E: AttemptError + Send + 'a,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>> + Send + 'a,
{
    let mut candidates = VecDeque::new();
    let mut seen = HashSet::new();
    let mut attempts = Pending::new();
    let mut last_ipv6 = None;
    let mut next_attempt = Instant::now();
    let mut last_attempt = None;
    let mut ipv4_answered = None;
    let mut failure = RaceFailure {
        attempts: Vec::new(),
        launched: 0,
        resolution: Vec::new(),
        budget_exhausted: false,
        ended_by: None,
    };
    loop {
        // Configured DNS emits A and AAAA independently. Until the remaining
        // family resolves, keep one slot available so several silent addresses
        // from the early family cannot block the late family's first attempt.
        // A system-resolver batch is its only future and needs no reservation.
        let parallel_limit = MAX_PARALLEL_ATTEMPTS - usize::from(!resolutions.is_empty());
        if !candidates.is_empty()
            && attempts.len() < parallel_limit
            && Instant::now() >= next_attempt
        {
            // Preserve each family's DNS order, alternating families when both
            // have answers. A late AAAA joins the same candidate queue.
            let index = last_ipv6
                .and_then(|ipv6| {
                    candidates
                        .iter()
                        .position(|address: &SocketAddr| address.is_ipv6() != ipv6)
                })
                .unwrap_or(0);
            let address = candidates.remove(index).expect("queued address");
            last_ipv6 = Some(address.is_ipv6());
            let attempt = connect(address);
            let attempt_deadline = deadline.min(Instant::now() + CONNECT_BUDGET);
            attempts.push(async move {
                let outcome = match timeout_at(attempt_deadline, attempt).await {
                    Ok(Ok(connected)) => Ok(connected),
                    Ok(Err(error)) => Err(AttemptFailure::Failed(error)),
                    Err(_) => Err(AttemptFailure::TimedOut),
                };
                (address, outcome)
            });
            failure.launched += 1;
            last_attempt = Some(Instant::now());
            next_attempt = Instant::now() + ATTEMPT_STAGGER;
        }
        if attempts.is_empty() && resolutions.is_empty() && candidates.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => {
                failure.budget_exhausted = true;
                break;
            }
            result = attempts.next(), if !attempts.is_empty() => {
                let (address, outcome) = result.expect("pending dial");
                match outcome {
                    Ok(connected) => return Ok((address, connected)),
                    Err(AttemptFailure::Failed(error)) if error.ends_race() => {
                        failure.ended_by = Some((address, error));
                        return Err(failure);
                    }
                    Err(attempt_failure) => if failure.attempts.len() < MAX_REPORTED_ERRORS {
                        failure.attempts.push((address, attempt_failure));
                    },
                }
                // A hard failure skips the normal stagger, while retaining
                // RFC 8305's 10ms floor against bursts of failed connections.
                next_attempt = Instant::now().max(last_attempt.expect("launched attempt") + MIN_ATTEMPT_DELAY);
            }
            result = resolutions.next(), if !resolutions.is_empty() => {
                match result.expect("pending DNS resolution") {
                    Ok(addresses) => {
                        let fresh: Vec<SocketAddr> = addresses
                            .into_iter()
                            .filter(|address| seen.insert(*address))
                            .collect();
                        if failure.launched == 0
                            && !fresh.is_empty()
                            && fresh.iter().all(SocketAddr::is_ipv6)
                        {
                            // RFC 8305 section 4 sorts by RFC 6724, whose default
                            // policy ranks IPv6 above IPv4: an AAAA answer goes
                            // ahead of IPv4 not tried yet. A resolver batch with
                            // both families keeps the resolver's order.
                            for address in fresh.into_iter().rev() {
                                candidates.push_front(address);
                            }
                        } else {
                            if ipv4_answered.is_none() && fresh.iter().any(SocketAddr::is_ipv4) {
                                ipv4_answered = Some(Instant::now());
                            }
                            candidates.extend(fresh);
                        }
                    }
                    Err(error) => if failure.resolution.len() < MAX_REPORTED_ERRORS { failure.resolution.push(error); },
                }
                if failure.launched == 0 {
                    // RFC 8305 section 3: an A answer that comes first waits a
                    // short time for AAAA, so that IPv6 is tried first when
                    // both families answer.
                    let waiting = !resolutions.is_empty() && !candidates.iter().any(SocketAddr::is_ipv6);
                    next_attempt = match ipv4_answered {
                        Some(answered) if waiting => answered + RESOLUTION_DELAY,
                        _ => Instant::now(),
                    };
                }
            }
            _ = sleep_until(next_attempt), if !candidates.is_empty() && attempts.len() < parallel_limit => {},
        }
    }
    Err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct LiveAttempt(Arc<AtomicUsize>);
    impl LiveAttempt {
        fn new(live: Arc<AtomicUsize>) -> Self {
            live.fetch_add(1, Ordering::SeqCst);
            Self(live)
        }
    }
    impl Drop for LiveAttempt {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Attempts that take `takes[n]` for the n-th start and then succeed
    /// with n, or fail when it is `None`; counts the live ones.
    fn attempts(
        takes: Vec<(Duration, bool)>,
        live: Arc<AtomicUsize>,
    ) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<usize, String>>>> {
        let started = Arc::new(AtomicUsize::new(0));
        move || {
            let index = started.fetch_add(1, Ordering::SeqCst);
            let (take, succeeds) = takes[index];
            let live = live.clone();
            Box::pin(async move {
                let _live = LiveAttempt::new(live);
                tokio::time::sleep(take).await;
                if succeeds {
                    Ok(index)
                } else {
                    Err(format!("attempt {index} failed"))
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_handshake_gets_a_second_attempt_and_the_first_to_connect_wins() {
        let live = Arc::new(AtomicUsize::new(0));
        let attempt = attempts(
            vec![
                (Duration::from_millis(250), true),
                (Duration::from_millis(62), true),
            ],
            live.clone(),
        );
        let started = Instant::now();
        let winner = hedged(attempt, Some(Duration::from_millis(93))).await;
        assert_eq!(winner, Ok(1));
        assert_eq!(Instant::now() - started, Duration::from_millis(93 + 62));
        assert_eq!(
            live.load(Ordering::SeqCst),
            0,
            "the slow attempt is dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_by_the_hedge_point_starts_no_second_attempt() {
        let live = Arc::new(AtomicUsize::new(0));
        let attempt = attempts(vec![(Duration::from_millis(62), true)], live.clone());
        assert_eq!(
            hedged(attempt, Some(Duration::from_millis(93))).await,
            Ok(0)
        );
        // A dial with no second attempt waits for its one attempt.
        let attempt = attempts(vec![(Duration::from_millis(250), true)], live);
        assert_eq!(hedged(attempt, None).await, Ok(0));
    }

    #[tokio::test(start_paused = true)]
    async fn either_attempt_failing_leaves_the_dial_to_the_other() {
        let live = Arc::new(AtomicUsize::new(0));
        let attempt = attempts(
            vec![
                (Duration::from_millis(200), false),
                (Duration::from_millis(300), true),
            ],
            live.clone(),
        );
        let started = Instant::now();
        assert_eq!(
            hedged(attempt, Some(Duration::from_millis(93))).await,
            Ok(1)
        );
        assert_eq!(Instant::now() - started, Duration::from_millis(393));

        let attempt = attempts(
            vec![
                (Duration::from_millis(250), true),
                (Duration::from_millis(10), false),
            ],
            live.clone(),
        );
        assert_eq!(
            hedged(attempt, Some(Duration::from_millis(93))).await,
            Ok(0)
        );

        // Both failing reports the first's failure.
        let attempt = attempts(
            vec![
                (Duration::from_millis(250), false),
                (Duration::from_millis(10), false),
            ],
            live.clone(),
        );
        assert_eq!(
            hedged(attempt, Some(Duration::from_millis(93))).await,
            Err("attempt 0 failed".to_string())
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_to_a_new_address_starts_two_attempts_at_once() {
        let handshakes = Handshakes::default();
        let node: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(handshakes.hedge_point(node), Some(Duration::ZERO));
        handshakes.handshook(node, Duration::from_millis(62));
        assert_eq!(
            handshakes.hedge_point(node),
            Some(Duration::from_millis(93))
        );
        // An address with one path gets no second attempt before a
        // handshake, and the usual one after.
        for local in [
            "127.0.0.1:7890",
            "192.168.1.10:443",
            "[::1]:443",
            "[fd00::1]:443",
            "[::ffff:10.0.0.1]:443",
        ] {
            let local: SocketAddr = local.parse().unwrap();
            assert_eq!(handshakes.hedge_point(local), None, "{local}");
        }
        let lan: SocketAddr = "192.168.1.10:443".parse().unwrap();
        handshakes.handshook(lan, Duration::from_millis(2));
        assert_eq!(handshakes.hedge_point(lan), Some(Duration::from_millis(27)));

        // Both attempts run from the start; the faster path wins.
        let live = Arc::new(AtomicUsize::new(0));
        let attempt = attempts(
            vec![
                (Duration::from_millis(250), true),
                (Duration::from_millis(62), true),
            ],
            live.clone(),
        );
        let started = Instant::now();
        assert_eq!(hedged(attempt, Some(Duration::ZERO)).await, Ok(1));
        assert_eq!(Instant::now() - started, Duration::from_millis(62));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_dial_ahead_is_made_again_while_it_meets_slow_paths() {
        let dials = |takes: Vec<u64>| {
            let next = Arc::new(AtomicUsize::new(0));
            move || {
                let take = takes[next.fetch_add(1, Ordering::SeqCst)];
                async move { Ok::<_, String>(take) }
            }
        };
        let slow = |took: &u64| *took > 93;
        assert_eq!(until_fast(dials(vec![62]), slow, 2).await, Ok(62));
        assert_eq!(until_fast(dials(vec![220, 230, 62]), slow, 2).await, Ok(62));
        // Out of redials, the last stands.
        assert_eq!(
            until_fast(dials(vec![220, 230, 240]), slow, 2).await,
            Ok(240)
        );
        let failing = || async { Err::<u64, _>("refused".to_string()) };
        assert_eq!(
            until_fast(failing, slow, 2).await,
            Err("refused".to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_hedge_point_follows_the_fastest_recent_handshake() {
        let handshakes = Handshakes::default();
        let node: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let near: SocketAddr = "192.0.2.2:443".parse().unwrap();
        assert_eq!(handshakes.hedge_after(node), None);

        handshakes.handshook(node, Duration::from_millis(220));
        handshakes.handshook(node, Duration::from_millis(62));
        handshakes.handshook(node, Duration::from_millis(250));
        assert_eq!(
            handshakes.hedge_after(node),
            Some(Duration::from_millis(93))
        );
        // A near node waits its margin over the handshake, not just half again.
        handshakes.handshook(near, Duration::from_millis(4));
        assert_eq!(
            handshakes.hedge_after(near),
            Some(Duration::from_millis(29))
        );

        // Paths change: past the memory, a slower handshake sets the point.
        tokio::time::advance(HANDSHAKE_MEMORY + Duration::from_secs(1)).await;
        handshakes.handshook(node, Duration::from_millis(100));
        assert_eq!(
            handshakes.hedge_after(node),
            Some(Duration::from_millis(150))
        );
    }

    fn resolved(addresses: Vec<SocketAddr>) -> Pending<'static, Result<Vec<SocketAddr>, String>> {
        let mut resolutions = Pending::new();
        resolutions.push(async move { Ok(addresses) });
        resolutions
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_handshakes_release_slots_for_later_targets() {
        let addresses: Vec<SocketAddr> = (1..=5)
            .map(|index| SocketAddr::from(([192, 0, 2, index], 443)))
            .collect();
        let good = addresses[4];
        let live = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let result = race_connections(resolved(addresses), started + DIAL_BUDGET, |address| {
            let live = live.clone();
            async move {
                let _live = LiveAttempt::new(live);
                if address == good {
                    Ok::<_, String>(())
                } else {
                    std::future::pending().await
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result.0, good);
        assert_eq!(Instant::now() - started, CONNECT_BUDGET);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn blackholed_v4_addresses_cannot_starve_working_v6_and_losers_drop() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let second = "192.0.2.2:443".parse().unwrap();
        let good = "[2001:db8::1]:443".parse().unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let launched = Arc::new(Mutex::new(Vec::new()));
        let started = Instant::now();
        let result = race_connections(
            resolved(vec![first, second, good]),
            started + DIAL_BUDGET,
            |address| {
                let live = live.clone();
                let launched = launched.clone();
                async move {
                    let _live = LiveAttempt::new(live);
                    launched.lock().unwrap().push(address);
                    if address == good {
                        Ok::<_, String>(())
                    } else {
                        std::future::pending().await
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, good);
        assert_eq!(Instant::now() - started, ATTEMPT_STAGGER);
        assert_eq!(*launched.lock().unwrap(), vec![first, good]);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn later_dns_family_can_join_an_already_running_dial() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let good: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut resolutions = resolved(vec![first]);
        resolutions.push(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(vec![good])
        });
        let started = Instant::now();
        let result = race_connections(resolutions, started + DIAL_BUDGET, |address| async move {
            if address == good {
                Ok::<_, String>(())
            } else {
                std::future::pending().await
            }
        })
        .await
        .unwrap();
        assert_eq!(result.0, good);
        assert_eq!(Instant::now() - started, RESOLUTION_DELAY + ATTEMPT_STAGGER);
    }

    /// Races A and AAAA answers arriving after the given delays, where every
    /// address connects at once, and returns the winner and when it won.
    async fn first_family(a_after: Duration, aaaa: Option<Duration>) -> (SocketAddr, Duration) {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut resolutions = Pending::new();
        resolutions.push(async move {
            tokio::time::sleep(a_after).await;
            Ok(vec![ipv4])
        });
        if let Some(after) = aaaa {
            resolutions.push(async move {
                tokio::time::sleep(after).await;
                Ok(vec![ipv6])
            });
        }
        let started = Instant::now();
        let (winner, ()) = race_connections(resolutions, started + DIAL_BUDGET, |_| async {
            Ok::<_, String>(())
        })
        .await
        .unwrap();
        (winner, Instant::now() - started)
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_goes_first_when_aaaa_answers_within_the_resolution_delay() {
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(
            first_family(Duration::ZERO, Some(Duration::ZERO)).await,
            (ipv6, Duration::ZERO)
        );
        assert_eq!(
            first_family(Duration::ZERO, Some(Duration::from_millis(30))).await,
            (ipv6, Duration::from_millis(30))
        );
        assert_eq!(
            first_family(Duration::from_millis(80), Some(Duration::from_millis(5))).await,
            (ipv6, Duration::from_millis(5)),
            "an AAAA answer that comes first waits for nothing"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ipv4_waits_no_longer_than_the_resolution_delay() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            first_family(Duration::from_millis(10), Some(Duration::from_millis(200))).await,
            (ipv4, Duration::from_millis(10) + RESOLUTION_DELAY)
        );
        assert_eq!(
            first_family(Duration::from_millis(10), None).await,
            (ipv4, Duration::from_millis(10)),
            "nothing to wait for without an AAAA query"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_aaaa_answer_ends_the_resolution_delay() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut resolutions = resolved(vec![ipv4]);
        resolutions.push(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Vec::new())
        });
        let started = Instant::now();
        let (winner, ()) = race_connections(resolutions, started + DIAL_BUDGET, |_| async {
            Ok::<_, String>(())
        })
        .await
        .unwrap();
        assert_eq!(winner, ipv4);
        assert_eq!(Instant::now() - started, Duration::from_millis(20));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_dns_family_keeps_a_slot_when_the_early_family_has_many_blackholes() {
        let first_family: Vec<SocketAddr> = (1..=6)
            .map(|index| SocketAddr::from(([192, 0, 2, index], 443)))
            .collect();
        let good: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut resolutions = resolved(first_family.clone());
        resolutions.push(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(vec![good])
        });
        let live = Arc::new(AtomicUsize::new(0));
        let launched = Arc::new(Mutex::new(Vec::new()));
        let started = Instant::now();
        let result = race_connections(resolutions, started + DIAL_BUDGET, |address| {
            let live = live.clone();
            let launched = launched.clone();
            async move {
                let _live = LiveAttempt::new(live);
                launched.lock().unwrap().push(address);
                if address == good {
                    Ok::<_, String>(())
                } else {
                    std::future::pending().await
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result.0, good);
        assert_eq!(Instant::now() - started, Duration::from_secs(1));
        assert_eq!(
            *launched.lock().unwrap(),
            vec![first_family[0], first_family[1], first_family[2], good]
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_failure_keeps_only_the_minimum_attempt_delay() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let good: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let started = Instant::now();
        let result = race_connections(
            resolved(vec![first, good]),
            started + DIAL_BUDGET,
            |address| async move {
                if address == good {
                    Ok(())
                } else {
                    Err::<(), String>("connection refused".into())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, good);
        assert_eq!(Instant::now() - started, MIN_ATTEMPT_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_covers_resolution_and_drops_all_bounded_attempts() {
        let live = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let mut resolutions = Pending::new();
        resolutions.push(async {
            tokio::time::sleep(Duration::from_secs(4)).await;
            Ok((1..20)
                .map(|index| SocketAddr::from(([192, 0, 2, index], 443)))
                .collect())
        });
        let peak = Arc::new(AtomicUsize::new(0));
        let result: Result<(SocketAddr, ()), RaceFailure<String>> =
            race_connections(resolutions, started + DIAL_BUDGET, |_| {
                let live = live.clone();
                let peak = peak.clone();
                async move {
                    let _live = LiveAttempt::new(live.clone());
                    peak.fetch_max(live.load(Ordering::SeqCst), Ordering::SeqCst);
                    std::future::pending().await
                }
            })
            .await;
        let failure = result.unwrap_err();
        assert!(failure.budget_exhausted);
        assert!(failure.to_string().contains("budget exhausted"));
        assert_eq!(Instant::now() - started, DIAL_BUDGET);
        assert_eq!(peak.load(Ordering::SeqCst), MAX_PARALLEL_ATTEMPTS);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// Fails at once and, for the marked address, says no other address
    /// can succeed either.
    #[derive(Debug)]
    struct Verdict {
        final_answer: bool,
    }

    impl fmt::Display for Verdict {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(if self.final_answer { "final" } else { "retry" })
        }
    }

    impl AttemptError for Verdict {
        fn ends_race(&self) -> bool {
            self.final_answer
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_that_ends_the_race_drops_the_other_attempts() {
        let addresses: Vec<SocketAddr> = (1..=4)
            .map(|index| SocketAddr::from(([192, 0, 2, index], 443)))
            .collect();
        let fatal = addresses[1];
        let live = Arc::new(AtomicUsize::new(0));
        let launched = Arc::new(Mutex::new(Vec::new()));
        let started = Instant::now();
        let failure = race_connections(
            resolved(addresses.clone()),
            started + DIAL_BUDGET,
            |address| {
                let live = live.clone();
                let launched = launched.clone();
                async move {
                    let _live = LiveAttempt::new(live);
                    launched.lock().unwrap().push(address);
                    if address == fatal {
                        Err::<(), _>(Verdict { final_answer: true })
                    } else {
                        std::future::pending().await
                    }
                }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(failure.ended_by.map(|(address, _)| address), Some(fatal));
        assert_eq!(failure.launched, 2, "the race stops launching");
        assert_eq!(Instant::now() - started, ATTEMPT_STAGGER);
        assert_eq!(*launched.lock().unwrap(), addresses[..2]);
        assert_eq!(live.load(Ordering::SeqCst), 0, "pending attempts dropped");
    }

    #[test]
    fn a_race_reads_as_resolve_local_or_connect() {
        let address: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let failure =
            |attempts: Vec<AttemptFailure<DialError>>, launched, budget_exhausted| RaceFailure {
                attempts: attempts
                    .into_iter()
                    .map(|failure| (address, failure))
                    .collect(),
                launched,
                resolution: vec![],
                budget_exhausted,
                ended_by: None,
            };
        assert_eq!(
            failure(vec![], 0, true).dial_kind(),
            DialFailureKind::Resolve,
            "nothing launched before the deadline"
        );
        assert_eq!(
            failure(
                vec![AttemptFailure::Failed(DialError::local("guard"))],
                1,
                false
            )
            .dial_kind(),
            DialFailureKind::Local
        );
        assert_eq!(
            failure(
                vec![AttemptFailure::Failed(DialError::local("guard"))],
                2,
                true
            )
            .dial_kind(),
            DialFailureKind::Connect,
            "an attempt still pending at the deadline reached the remote"
        );
        assert_eq!(
            failure(
                vec![
                    AttemptFailure::Failed(DialError::local("guard")),
                    AttemptFailure::TimedOut,
                ],
                2,
                false
            )
            .dial_kind(),
            DialFailureKind::Connect
        );
    }

    #[tokio::test(start_paused = true)]
    async fn caller_cancellation_drops_every_inflight_attempt() {
        let live = Arc::new(AtomicUsize::new(0));
        let addresses = (1..4)
            .map(|index| SocketAddr::from(([192, 0, 2, index], 443)))
            .collect();
        let mut dial = Box::pin(race_connections(
            resolved(addresses),
            Instant::now() + DIAL_BUDGET,
            |_| {
                let live = live.clone();
                async move {
                    let _live = LiveAttempt::new(live);
                    std::future::pending::<Result<(), String>>().await
                }
            },
        ));
        tokio::select! {
            result = &mut dial => panic!("unexpected dial completion: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(400)) => {},
        }
        assert_eq!(live.load(Ordering::SeqCst), 2);
        drop(dial);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}
