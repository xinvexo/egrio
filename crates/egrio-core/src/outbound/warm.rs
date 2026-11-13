//! Carriers dialed ahead of need. A stream protocol's new connection spends
//! the TCP and TLS handshakes with its node before it can send its request.
//! For a node in repeated use, carriers whose handshakes are done wait here,
//! so the next
//! connection starts with its request.
//!
//! A carrier waits at most [`WARM_LIFETIME`], limiting idle retention.
//! Before a carrier is
//! handed out it must not have turned readable: the node closing it (EOF, a
//! TLS alert) or anything else it sent unasked means the carrier is no longer
//! one a request can start on. A sleep ends every waiting carrier, since
//! `Instant` stops while the host sleeps, and a changed network every waiting
//! and dialing one. Handing one out or dialing afresh starts dialing a
//! replacement, but only while the node is in repeated use (its previous dial
//! within the lifetime), so a node only a health probe touches now and then
//! keeps none.
//!
//! A node once in repeated use keeps one carrier waiting for [`WARM_KEEP`]
//! after its last dial, each replaced before its lifetime runs out: browsing
//! comes in bursts a reading pause apart, and the first connection after the
//! pause would otherwise pay both handshakes again.
//!
//! With nobody waiting on it, a carrier dialed ahead whose TCP handshake met
//! a slow path is dialed again (see `EgressRuntime::connect_tcp_host_ahead`),
//! so the carriers that wait sit on the fast paths a connection's own dial
//! could only hope to draw.
//!
//! A carrier is dialed on the executor of the connection that set it off and
//! may be taken by a connection on another, as on a capture with several
//! queues: its socket then moves to the taker's I/O driver, so none of the
//! connection's readiness events cross threads.
//!
//! A node with a `dialer-proxy` keeps none: its carrier is a stream through
//! another outbound, whose hop is resolved for each connection.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Handle;

use crate::egress::EgressRuntime;
use crate::outbound::{
    dial_carrier, dial_lasting_carrier, BoxedOutboundStream, Dialer, OutboundError,
};
use crate::tls::{ClientTlsStream, TlsClient};

/// How long a carrier waits for a connection.
const WARM_LIFETIME: Duration = Duration::from_secs(25);
/// How long after a node's last dial it keeps one carrier waiting.
const WARM_KEEP: Duration = Duration::from_secs(600);
/// Carriers kept waiting for one node: a connection takes one and the
/// replacement is a handshake away, so two cover a short burst.
const WARM_CARRIERS: usize = 2;
/// How long a dial ahead may take: no connection waits on it to bound it.
const DIAL_AHEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Where and how a node's carriers are dialed.
pub(crate) struct CarrierDial {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) dialer: Dialer,
    pub(crate) label: &'static str,
    pub(crate) tls: Option<TlsClient>,
}

/// One node's carriers: dialed for each connection, or ahead of them while
/// the node is in repeated use.
pub(crate) struct WarmCarriers {
    carrier: CarrierDial,
    /// [`WARM_LIFETIME`] and [`WARM_KEEP`]; tests shorten them.
    lifetime: Duration,
    keep: Duration,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    waiting: VecDeque<Warm>,
    /// Dials ahead in flight on the current network.
    dialing: usize,
    last_dial: Option<Instant>,
    /// A task keeps one carrier waiting.
    keeping: bool,
    /// Network changes so far: a dial ahead begun before the latest lands
    /// for nothing.
    network: u64,
}

struct Warm {
    carrier: Parked,
    /// The executor whose I/O driver the socket is registered with.
    runtime: tokio::runtime::Id,
    ready_at: Instant,
    /// The suspension mark when it became ready.
    awake: i64,
}

impl WarmCarriers {
    pub(crate) fn new(carrier: CarrierDial) -> Self {
        Self {
            carrier,
            lifetime: WARM_LIFETIME,
            keep: WARM_KEEP,
            state: Mutex::default(),
        }
    }

    /// The TLS layer the carriers are dialed with.
    pub(crate) fn tls(&self) -> Option<&TlsClient> {
        self.carrier.tls.as_ref()
    }

    /// A carrier for a connection: a waiting one if one is still good, or a
    /// fresh dial; either way replacements are dialed ahead when the node is
    /// in repeated use, or one is while it keeps a carrier.
    pub(crate) async fn dial(
        self: &Arc<Self>,
        egress: &EgressRuntime,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        self.dial_for(egress, false).await
    }

    /// [`Self::dial`] for a connection that will hold its carrier for long:
    /// a fresh dial sees to its path as a dial ahead does.
    pub(crate) async fn dial_lasting(
        self: &Arc<Self>,
        egress: &EgressRuntime,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        self.dial_for(egress, true).await
    }

    async fn dial_for(
        self: &Arc<Self>,
        egress: &EgressRuntime,
        lasting: bool,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        if self.carrier.dialer.is_chained() {
            return self.dial_fresh(egress, lasting).await;
        }
        let now = Instant::now();
        let (waiting, ahead, network, keep) = {
            let mut state = self.state.lock().expect("warm carriers");
            let in_use = state
                .last_dial
                .is_some_and(|last| now.duration_since(last) < self.lifetime);
            state.last_dial = Some(now);
            let waiting = take_good(&mut state.waiting, self.lifetime, now);
            let wanted = match (in_use, state.keeping) {
                (true, _) => WARM_CARRIERS,
                (false, true) => 1,
                (false, false) => 0,
            };
            let ahead = wanted.saturating_sub(state.waiting.len() + state.dialing);
            state.dialing += ahead;
            let keep = in_use && !state.keeping;
            state.keeping |= keep;
            (waiting, ahead, state.network, keep)
        };
        for _ in 0..ahead {
            // Tracked, so a policy that retires waits for the dial instead of
            // letting it reach the node afterwards, and refused once retired.
            if egress
                .spawn_policy_task(Arc::clone(self).dial_ahead(egress.clone(), network))
                .is_err()
            {
                self.undial();
            }
        }
        if keep {
            if egress
                .spawn_policy_task(keep_one(Arc::downgrade(self), egress.clone()))
                .is_err()
            {
                self.state.lock().expect("warm carriers").keeping = false;
            }
        }
        if let Some(carrier) = waiting.and_then(Warm::here) {
            return Ok(carrier);
        }
        self.dial_fresh(egress, lasting).await
    }

    async fn dial_fresh(
        &self,
        egress: &EgressRuntime,
        lasting: bool,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        let carrier = &self.carrier;
        let (host, port, dialer) = (&carrier.host, carrier.port, &carrier.dialer);
        let tls = carrier.tls.as_ref();
        let (stream, _) = if lasting {
            dial_lasting_carrier(egress, dialer, host, port, carrier.label, tls).await?
        } else {
            dial_carrier(egress, dialer, host, port, carrier.label, tls).await?
        };
        Ok(stream)
    }

    /// Ends every waiting carrier and every dial ahead: the network they
    /// were dialed on changed.
    pub(crate) fn clear(&self) {
        let mut state = self.state.lock().expect("warm carriers");
        state.waiting.clear();
        state.dialing = 0;
        state.network += 1;
    }

    /// Gives back a dial ahead that was counted and never begun.
    fn undial(&self) {
        let mut state = self.state.lock().expect("warm carriers");
        state.dialing = state.dialing.saturating_sub(1);
    }

    async fn dial_ahead(self: Arc<Self>, egress: EgressRuntime, network: u64) {
        let cancel = egress.policy_cancel();
        let dialed = tokio::select! { biased;
            () = cancel.cancelled() => None,
            dialed = tokio::time::timeout(DIAL_AHEAD_TIMEOUT, self.dial_parked(&egress)) => {
                dialed.ok().flatten()
            }
        };
        if cancel.is_cancelled() {
            // The policy these carriers were dialed under is gone: what was
            // waiting goes with it, and so does whatever this dial reached.
            self.clear();
            return;
        }
        self.land(network, dialed);
    }

    /// A carrier dialed ahead, its socket free to move; a failure is no
    /// connection's, so it reports none.
    async fn dial_parked(&self, egress: &EgressRuntime) -> Option<Parked> {
        let carrier = &self.carrier;
        let tcp = egress
            .connect_tcp_host_ahead(&carrier.host, carrier.port, carrier.label)
            .await
            .ok()?;
        let socket = Movable(Some(tcp));
        Some(match &carrier.tls {
            None => Parked::Plain(socket),
            Some(tls) => Parked::Tls(Box::new(tls.connect(socket).await.ok()?)),
        })
    }

    /// Ends a dial ahead begun on `network`, keeping what it dialed if that
    /// is still the network: in place of carriers past their lifetime, and of
    /// the oldest when [`WARM_CARRIERS`] still wait.
    fn land(&self, network: u64, dialed: Option<Parked>) {
        let mut state = self.state.lock().expect("warm carriers");
        if state.network != network {
            return;
        }
        state.dialing = state.dialing.saturating_sub(1);
        let Some(carrier) = dialed else {
            return;
        };
        let now = Instant::now();
        state
            .waiting
            .retain(|warm| now.duration_since(warm.ready_at) < self.lifetime);
        if state.waiting.len() >= WARM_CARRIERS {
            state.waiting.pop_front();
        }
        state.waiting.push_back(Warm {
            carrier,
            runtime: Handle::current().id(),
            ready_at: now,
            awake: crate::suspension::mark(),
        });
    }

    /// How long before a waiting carrier's lifetime runs out a kept node
    /// dials its replacement: a fifth of the lifetime, a handshake's worth
    /// with room to spare.
    fn renew(&self) -> Duration {
        self.lifetime / 5
    }
}

impl Warm {
    /// The carrier as a stream for a connection on the current executor,
    /// its socket moved here from the one it was dialed on; none if the
    /// move failed.
    fn here(mut self) -> Option<BoxedOutboundStream> {
        if self.runtime != Handle::current().id() {
            self.carrier.socket().move_here().ok()?;
        }
        Some(self.carrier.boxed())
    }
}

/// Keeps one carrier waiting for the node until its keep ([`WARM_KEEP`]) has
/// passed since its last dial: whenever none is waiting or dialing, or the
/// youngest is a renewal ([`WarmCarriers::renew`]) from the end of its
/// lifetime, it dials one, and it drops carriers past their lifetime. Ends
/// once the last carrier has run out after the keep, or with the node's
/// connector or its egress policy.
async fn keep_one(pool: Weak<WarmCarriers>, egress: EgressRuntime) {
    let cancel = egress.policy_cancel();
    loop {
        let (wait, network) = {
            let Some(pool) = pool.upgrade() else {
                return;
            };
            let now = Instant::now();
            let mut state = pool.state.lock().expect("warm carriers");
            state
                .waiting
                .retain(|warm| now.duration_since(warm.ready_at) < pool.lifetime);
            if state
                .last_dial
                .is_none_or(|last| now.duration_since(last) >= pool.keep)
            {
                // The keep is over: the last carriers run out and go with
                // the task, so none holds a socket the node has closed.
                let expiry = state
                    .waiting
                    .iter()
                    .map(|warm| warm.ready_at + pool.lifetime)
                    .max();
                match expiry {
                    Some(at) => (at - now, None),
                    None if state.dialing > 0 => (pool.renew(), None),
                    None => {
                        state.keeping = false;
                        return;
                    }
                }
            } else {
                let renew = pool.renew();
                let renew_at = state
                    .waiting
                    .iter()
                    .map(|warm| warm.ready_at + (pool.lifetime - renew))
                    .max();
                match renew_at {
                    Some(at) if at > now => (at - now, None),
                    // Being dialed: look again once the dial is due to be done.
                    _ if state.dialing > 0 => (renew, None),
                    _ => {
                        state.dialing += 1;
                        (renew, Some(state.network))
                    }
                }
            }
        };
        if let (Some(network), Some(pool)) = (network, pool.upgrade()) {
            if egress
                .spawn_policy_task(Arc::clone(&pool).dial_ahead(egress.clone(), network))
                .is_err()
            {
                pool.undial();
            }
        }
        tokio::select! { biased;
            _ = cancel.cancelled() => {
                if let Some(pool) = pool.upgrade() {
                    pool.clear();
                }
                return;
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// The oldest waiting carrier still good for a connection; those past
/// `lifetime`, from before a sleep, or no longer quiet are dropped.
fn take_good(waiting: &mut VecDeque<Warm>, lifetime: Duration, now: Instant) -> Option<Warm> {
    while let Some(mut warm) = waiting.pop_front() {
        if now.duration_since(warm.ready_at) < lifetime
            && !crate::suspension::slept_since(warm.awake)
            && warm.carrier.quiet()
        {
            return Some(warm);
        }
    }
    None
}

/// A waiting carrier: TLS, or the bare TCP connection a protocol speaks
/// over, on a socket that can move.
enum Parked {
    Plain(Movable),
    Tls(Box<ClientTlsStream<Movable>>),
}

impl Parked {
    fn socket(&mut self) -> &mut Movable {
        match self {
            Self::Plain(socket) => socket,
            Self::Tls(stream) => stream.transport_mut(),
        }
    }

    fn boxed(self) -> BoxedOutboundStream {
        match self {
            Self::Plain(socket) => Box::new(socket),
            Self::Tls(stream) => stream,
        }
    }

    /// Whether nothing has arrived: a read would wait. The node closing it,
    /// a TLS alert or bytes it sent unasked all make it readable, and the
    /// byte a successful read takes is lost with the dropped carrier.
    fn quiet(&mut self) -> bool {
        let mut byte = [0_u8; 1];
        let mut buffer = ReadBuf::new(&mut byte);
        let mut context = Context::from_waker(Waker::noop());
        let read = match self {
            Self::Plain(socket) => Pin::new(socket).poll_read(&mut context, &mut buffer),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(&mut context, &mut buffer),
        };
        read.is_pending()
    }
}

/// A carrier's TCP connection, whose socket can leave the I/O driver it was
/// registered with for the current executor's.
struct Movable(Option<TcpStream>);

impl Movable {
    fn stream(&mut self) -> io::Result<Pin<&mut TcpStream>> {
        self.0
            .as_mut()
            .map(Pin::new)
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }

    /// Registers the socket with the current executor's I/O driver instead.
    fn move_here(&mut self) -> io::Result<()> {
        let stream = self.0.take().ok_or(io::ErrorKind::NotConnected)?;
        self.0 = Some(TcpStream::from_std(stream.into_std()?)?);
        Ok(())
    }
}

impl AsyncRead for Movable {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().stream()?.poll_read(context, buffer)
    }
}

impl AsyncWrite for Movable {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().stream()?.poll_write(context, buffer)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .stream()?
            .poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|stream| stream.is_write_vectored())
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().stream()?.poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().stream()?.poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn plain(address: SocketAddr) -> WarmCarriers {
        WarmCarriers::new(CarrierDial {
            host: address.ip().to_string(),
            port: address.port(),
            dialer: Dialer::default(),
            label: "test proxy",
            tls: None,
        })
    }

    /// [`plain`] with a carrier's lifetime and a node's keep this short.
    fn hasty(address: SocketAddr, lifetime: Duration, keep: Duration) -> WarmCarriers {
        WarmCarriers {
            lifetime,
            keep,
            ..plain(address)
        }
    }

    /// The age of the youngest waiting carrier.
    fn youngest(pool: &WarmCarriers) -> Option<Duration> {
        let state = pool.state.lock().unwrap();
        state
            .waiting
            .iter()
            .map(|warm| warm.ready_at.elapsed())
            .min()
    }

    /// Accepts connections and hands each, in order, to the test.
    async fn node() -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<tokio::net::TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted, accepts) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                if accepted.send(stream).is_err() {
                    return;
                }
            }
        });
        (address, accepts)
    }

    fn waiting(pool: &WarmCarriers) -> usize {
        pool.state.lock().unwrap().waiting.len()
    }

    async fn settle(pool: &WarmCarriers, carriers: usize) {
        for _ in 0..200 {
            if waiting(pool) == carriers && pool.state.lock().unwrap().dialing == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("{} carriers wait, not {carriers}", waiting(pool));
    }

    /// The accepted connection that receives `bytes` within a moment.
    async fn receiver_of(
        accepts: &mut tokio::sync::mpsc::UnboundedReceiver<tokio::net::TcpStream>,
        bytes: &[u8],
    ) -> Option<tokio::net::TcpStream> {
        let mut found = None;
        while let Ok(Some(mut server)) =
            tokio::time::timeout(Duration::from_millis(300), accepts.recv()).await
        {
            let mut buffer = vec![0_u8; bytes.len()];
            if let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_millis(100), server.read_exact(&mut buffer))
                    .await
            {
                if buffer == bytes {
                    found = Some(server);
                }
            }
        }
        found
    }

    #[tokio::test]
    async fn a_node_in_repeated_use_gets_carriers_ahead_of_its_connections() {
        let (address, mut accepts) = node().await;
        let pool = Arc::new(plain(address));
        let egress = EgressRuntime::default();

        // A first connection dials on its own; nothing is dialed ahead for a
        // node used once.
        let mut first = pool.dial(&egress).await.unwrap();
        settle(&pool, 0).await;
        let mut first_server = accepts.recv().await.unwrap();
        first.write_all(b"one").await.unwrap();
        let mut seen = [0_u8; 3];
        first_server.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"one");

        // The second, soon after, dials too and starts two carriers ahead.
        let _second = pool.dial(&egress).await.unwrap();
        settle(&pool, WARM_CARRIERS).await;

        // The third takes a waiting carrier: its bytes reach one of the
        // connections the node accepted before it.
        let mut third = pool.dial(&egress).await.unwrap();
        third.write_all(b"three").await.unwrap();
        let mut earlier = Vec::new();
        for _ in 0..1 + WARM_CARRIERS {
            earlier.push(accepts.recv().await.unwrap());
        }
        let mut received = 0;
        for server in &mut earlier {
            let mut buffer = [0_u8; 5];
            if let Ok(Ok(5)) =
                tokio::time::timeout(Duration::from_millis(200), server.read_exact(&mut buffer))
                    .await
            {
                assert_eq!(&buffer, b"three");
                received += 1;
            }
        }
        assert_eq!(received, 1, "one carrier dialed ahead carried it");
    }

    #[tokio::test]
    async fn a_node_once_in_repeated_use_keeps_one_carrier_through_a_pause() {
        let (address, mut accepts) = node().await;
        let lifetime = Duration::from_millis(300);
        let pool = Arc::new(hasty(address, lifetime, Duration::from_millis(1500)));
        let egress = EgressRuntime::default();
        let _ = pool.dial(&egress).await.unwrap();
        let _ = pool.dial(&egress).await.unwrap();
        settle(&pool, WARM_CARRIERS).await;

        // Well past the lifetime of the carriers dialed for the burst, a
        // fresh one still waits.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let age = youngest(&pool).expect("a carrier waits");
        assert!(age < lifetime, "the youngest carrier is {age:?} old");

        // The first connection after the pause starts on it: its bytes reach
        // a connection the node accepted before.
        let mut before = Vec::new();
        while let Ok(Some(server)) =
            tokio::time::timeout(Duration::from_millis(50), accepts.recv()).await
        {
            before.push(server);
        }
        let mut resumed = pool.dial(&egress).await.unwrap();
        resumed.write_all(b"after").await.unwrap();
        let mut carried = false;
        for server in &mut before {
            let mut buffer = [0_u8; 5];
            if let Ok(Ok(5)) =
                tokio::time::timeout(Duration::from_millis(200), server.read_exact(&mut buffer))
                    .await
            {
                carried |= &buffer == b"after";
            }
        }
        assert!(
            carried,
            "a kept carrier carried the connection after the pause"
        );

        // Once the keep has passed since that dial, none is renewed.
        tokio::time::sleep(Duration::from_millis(1500) + lifetime * 2).await;
        assert_eq!(youngest(&pool), None);
        assert!(!pool.state.lock().unwrap().keeping);
    }

    /// A policy that retires takes its carriers with it: what waits is
    /// dropped, no dial ahead reaches the node afterwards, and the barrier
    /// `retire_policy` returns does not complete while one is still being
    /// dialed.
    #[tokio::test]
    async fn a_retired_policy_ends_the_carriers_and_dials_nothing_more() {
        let (address, mut accepts) = node().await;
        let pool = Arc::new(plain(address));
        let egress = EgressRuntime::default();

        // Two connections in a row put the node in repeated use, so the pool
        // keeps WARM_CARRIERS waiting and a keeper running.
        let _first = pool.dial(&egress).await.unwrap();
        let _second = pool.dial(&egress).await.unwrap();
        settle(&pool, WARM_CARRIERS).await;
        assert!(pool.state.lock().unwrap().keeping);
        while accepts.try_recv().is_ok() {}

        // The policy retires: the barrier waits for the tracked dials, and
        // every waiting carrier goes.
        let retired = egress.retire_policy();
        tokio::time::timeout(Duration::from_secs(5), retired.wait())
            .await
            .expect("the tracked dials end with the policy");
        for _ in 0..200 {
            if waiting(&pool) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(waiting(&pool), 0, "no carrier waits for a retired policy");

        // A dial under the retired policy counts nothing ahead and leaves
        // nothing behind, whatever it does with the connection itself.
        let _ = pool.dial(&egress).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(pool.state.lock().unwrap().dialing, 0, "nothing dials ahead");
        assert_eq!(waiting(&pool), 0, "nothing lands");
    }

    #[tokio::test]
    async fn a_node_used_once_now_and_then_keeps_none() {
        let (address, _accepts) = node().await;
        let pool = Arc::new(hasty(
            address,
            Duration::from_millis(100),
            Duration::from_secs(5),
        ));
        let egress = EgressRuntime::default();
        let _ = pool.dial(&egress).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = pool.dial(&egress).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(youngest(&pool), None);
        assert!(!pool.state.lock().unwrap().keeping);
    }

    #[tokio::test]
    async fn a_carrier_the_node_closed_is_never_handed_out() {
        let (address, mut accepts) = node().await;
        let pool = Arc::new(plain(address));
        let egress = EgressRuntime::default();
        let _ = pool.dial(&egress).await.unwrap();
        let _ = pool.dial(&egress).await.unwrap();
        settle(&pool, WARM_CARRIERS).await;

        // The node closes every connection it accepted.
        let mut closed = 0;
        while let Ok(Some(server)) =
            tokio::time::timeout(Duration::from_millis(200), accepts.recv()).await
        {
            drop(server);
            closed += 1;
        }
        assert_eq!(closed, 2 + WARM_CARRIERS);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Both waiting carriers turned readable (EOF): the connection dials
        // afresh and the node sees it.
        let mut fresh = pool.dial(&egress).await.unwrap();
        fresh.write_all(b"fresh").await.unwrap();
        assert!(
            receiver_of(&mut accepts, b"fresh").await.is_some(),
            "the connection went out on a new carrier"
        );
    }

    #[test]
    fn a_carrier_dialed_on_one_executor_serves_a_connection_on_another() {
        let background = tokio::runtime::Runtime::new().unwrap();
        let (address, mut accepts) = background.block_on(node());
        let current = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let (dialer, taker) = (current(), current());
        let pool = Arc::new(plain(address));
        dialer.block_on(async {
            let egress = EgressRuntime::default();
            let _ = pool.dial(&egress).await.unwrap();
            let _ = pool.dial(&egress).await.unwrap();
            settle(&pool, WARM_CARRIERS).await;
        });

        // The dialer's executor runs no more: only the taker's I/O driver can
        // deliver what the node sends back on the carrier the taker gets.
        taker.block_on(async {
            let egress = EgressRuntime::default();
            let mut stream = pool.dial(&egress).await.unwrap();
            stream.write_all(b"moved").await.unwrap();
            let mut server = receiver_of(&mut accepts, b"moved")
                .await
                .expect("a carrier dialed ahead carried it");
            server.write_all(b"back").await.unwrap();
            let mut reply = [0_u8; 4];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
                .await
                .expect("the reply arrives on the taker's executor")
                .unwrap();
            assert_eq!(&reply, b"back");
        });
    }

    #[tokio::test]
    async fn a_changed_network_ends_the_waiting_carriers_and_the_dials_ahead() {
        let (address, _accepts) = node().await;
        let pool = Arc::new(plain(address));
        let egress = EgressRuntime::default();
        let _ = pool.dial(&egress).await.unwrap();
        let _ = pool.dial(&egress).await.unwrap();
        settle(&pool, WARM_CARRIERS).await;
        let before = pool.state.lock().unwrap().network;
        pool.clear();
        assert_eq!(waiting(&pool), 0);

        // A dial ahead begun on the old network lands for nothing.
        let tcp = TcpStream::connect(address).await.unwrap();
        pool.land(before, Some(Parked::Plain(Movable(Some(tcp)))));
        assert_eq!(waiting(&pool), 0);
    }
}
