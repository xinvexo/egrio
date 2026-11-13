//! The established-phase relay step: every session has an idle timeout in
//! both directions.
//!
//! Two pieces live here, both structural — they run for every relay, not
//! behind a host opt-in:
//!
//! - [`CountingStream`] streams relayed byte counts into the session
//!   ledger's shared atomics as IO completes, replacing the old one-shot
//!   store at relay end. Live sessions expose real byte totals to the
//!   connection table, and the budget watcher below reads the same
//!   counters — no second bookkeeping surface.
//! - [`watch_established_budgets`] bounds the Established phase, the last
//!   pipeline step without a budget: dialing is bounded per connect (the
//!   egress 16s step deadline) and per attempt end to end (the 30s
//!   whole-dial ceiling in `open_outbound_connection`, covering resolve
//!   and proxy handshakes), sniff and DNS waits carry their own, but a
//!   session whose egress handshake succeeded against a
//!   middlebox that ACKs everything and answers nothing sat in Established
//!   forever (the 2026-07-04 stacked-proxy incident pinned hundreds of
//!   sessions this way: registry active == accepted, killed_total 0). The
//!   OS never errors such a connection — every segment is ACKed — so only
//!   the relay itself can conclude it is dead.
//!
//! Budget semantics are deliberately activity-based, never a session
//! lifetime, so legitimately idle long-lived flows (IMAP IDLE re-issues at
//! most every 29 minutes; websocket keepalives are minutes apart) and
//! upload-only flows (syslog-style sinks that never answer) survive:
//! reaping requires the flow to be *provably stuck*, meaning no byte moved
//! in either direction for the whole applicable budget.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::inbound::acceptor::InboundStream;
use crate::outbound::BoxedOutboundStream;
use crate::session_registry::{SessionByteCounters, SessionGuard, SessionPhase};
use crate::tcp_flow::{TcpFlowBudget, TcpFlowFailure, TcpFlowIoAction, TcpFlowIoSide};

mod captured;
mod copy;
#[cfg(feature = "bench-internals")]
pub use copy::relay_buffer_borrows;

#[derive(Debug)]
pub(crate) struct RelayFailure {
    pub(crate) cause: TcpFlowFailure,
    pub(crate) upload_bytes: u64,
    pub(crate) download_bytes: u64,
}

impl std::fmt::Display for RelayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(f)
    }
}

/// Budget for the upstream's first byte ever: once the client has sent
/// data and then gone quiet, the upstream has this long to produce its
/// first response byte before the session is reaped. Ordinary
/// request/response upstreams answer within seconds; a middlebox that
/// black-holes the response never answers at all, and its sessions die
/// here instead of pinning the table.
///
/// An upload still moving does not fall in here, however slowly: every
/// write that lands moves the counter and re-arms the budget. What this
/// reaps is an upstream that takes no byte at all for a whole minute and
/// has never answered -- a server that buffers the request body and holds
/// its receive window shut that long, which the client has given up on by
/// then anyway. The counters cannot tell such a stall from a client that
/// stopped talking, because a client the engine has stopped reading from
/// looks the same.
pub(crate) const RELAY_FIRST_UPSTREAM_BYTE_TIMEOUT: Duration = Duration::from_secs(60);

/// Backstop idle budget: no byte relayed in either direction for this long
/// reaps the session. Generous by design — it exists so nothing can hold a
/// session-table slot forever, not to police slow traffic; every sane
/// long-lived protocol keepalives far inside an hour (IMAP IDLE must
/// re-issue within 29 minutes, and NAT middleboxes force sub-hour
/// keepalives on everything else anyway).
pub(crate) const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

/// The established-phase budgets; a value object so tests (and later a
/// host profile knob, if a product need appears) can shrink them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayBudgets {
    pub(crate) first_upstream_byte: Duration,
    pub(crate) idle: Duration,
}

impl Default for RelayBudgets {
    fn default() -> Self {
        Self {
            first_upstream_byte: RELAY_FIRST_UPSTREAM_BYTE_TIMEOUT,
            idle: RELAY_IDLE_TIMEOUT,
        }
    }
}

/// Runs the established-phase relay under the session's leaf of the
/// cancellation tree and the default [`RelayBudgets`]: a kill switch or
/// device close cancels the token, an exhausted budget reaps the session,
/// and in both cases the relay future is dropped (closing both sockets)
/// and the session unwinds through its guard. `early_len` is the sniffed
/// prefix the dial already delivered upstream, credited as upload before
/// the copy starts — it is client data, so it arms the first-byte budget.
pub(crate) async fn relay_registered_session<S>(
    client: &mut S,
    upstream: BoxedOutboundStream,
    session: &SessionGuard,
    early_len: u64,
) -> Result<(), RelayFailure>
where
    S: InboundStream + ?Sized,
{
    relay_registered_session_with_budgets(
        client,
        upstream,
        session,
        early_len,
        RelayBudgets::default(),
    )
    .await
}

pub(crate) async fn relay_registered_session_with_budgets<S>(
    client: &mut S,
    upstream: BoxedOutboundStream,
    session: &SessionGuard,
    early_len: u64,
    budgets: RelayBudgets,
) -> Result<(), RelayFailure>
where
    S: InboundStream + ?Sized,
{
    session.set_phase(SessionPhase::Established);
    let counters = session.byte_counters();
    if early_len > 0 {
        counters.add_up(early_len);
    }
    let upstream = CountingStream {
        inner: upstream,
        counters: counters.clone(),
    };
    // The copy keeps Tokio's half-close/backpressure state machine (see
    // `copy.rs`). These wrappers observe the first exceptional operation,
    // without a lock or allocation on successful IO, and return the original
    // io::Error to it.
    let first_error = Mutex::new(None);
    let mut upstream = ObservedStream {
        inner: upstream,
        side: TcpFlowIoSide::Upstream,
        first_error: &first_error,
    };
    let cancel = session.cancellation();
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(TcpFlowFailure::Cancelled),
        result = copy_session(client, &mut upstream, &first_error) => {
            result.map(|_| ()).map_err(|error| {
                let origin = first_error.lock().expect("relay error origin").take();
                match origin {
                    Some((side, action)) => TcpFlowFailure::io(side, action, error),
                    // All underlying read/write/flush/shutdown errors are
                    // observed. Keep any unexpected copy error visible.
                    None => TcpFlowFailure::UnattributedIo(error),
                }
            })
        }
        reason = watch_established_budgets(&counters.up, &counters.down, budgets) => {
            session.record_budget_reap();
            Err(reason)
        }
    };
    result.map_err(|cause| RelayFailure {
        cause,
        upload_bytes: counters.up.load(Ordering::Relaxed),
        download_bytes: counters.down.load(Ordering::Relaxed),
    })
}

/// The established-phase copy: copy-free for a captured TCP flow, through
/// the pooled copy buffers otherwise.
async fn copy_session<S, U>(
    client: &mut S,
    upstream: &mut U,
    first_error: &Mutex<Option<(TcpFlowIoSide, TcpFlowIoAction)>>,
) -> io::Result<(u64, u64)>
where
    S: InboundStream + ?Sized,
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if let Some(captured) = client.as_captured_tcp() {
        let record = |action| {
            first_error
                .lock()
                .expect("relay error origin")
                .get_or_insert((TcpFlowIoSide::Client, action));
        };
        return captured::copy_captured(captured, upstream, &record).await;
    }
    let mut client = ObservedStream {
        inner: client,
        side: TcpFlowIoSide::Client,
        first_error,
    };
    copy::copy_bidirectional(&mut client, upstream).await
}

/// Resolves with a reap reason once an established-phase budget is
/// exhausted; never resolves while the session stays within budget.
///
/// One mechanism, change detection on the shared byte counters, with a
/// state-dependent threshold:
///
/// - the client has sent data but no upstream byte has *ever* arrived →
///   the first-upstream-byte budget applies. A black-holed
///   request/response session (client asked, then waited) trips it;
///   upload-only flows keep moving the upload counter and never look idle.
/// - anything else → the generous idle budget applies: fully silent
///   sessions (e.g. preconnect spares against a dead upstream) and
///   sessions that stall after traffic flowed both die eventually, but
///   never at request/response cadence.
///
/// Observation is edge-based, not per-IO: while no upstream byte has ever
/// arrived the watcher wakes at most once per first-byte budget, and
/// afterwards once per quiet idle budget (steady traffic re-arms the same
/// sleep). A change timestamp is therefore observed up to one wake late,
/// so a reap lands within twice the applicable budget in the worst case —
/// the deliberate price for a watcher that costs a long-lived healthy
/// session one wakeup per idle budget and the hot path nothing at all.
async fn watch_established_budgets(
    up: &AtomicU64,
    down: &AtomicU64,
    budgets: RelayBudgets,
) -> TcpFlowFailure {
    let mut last_seen = (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed));
    let mut last_change = Instant::now();
    loop {
        let deadline = last_change + applicable_budget(last_seen, &budgets);
        // While the upstream has never answered, cap the sleep at the
        // first-byte budget so a client that starts talking mid-session is
        // observed (and its response deadline armed) within one budget.
        let wake = if last_seen.1 == 0 {
            deadline.min(Instant::now() + budgets.first_upstream_byte)
        } else {
            deadline
        };
        tokio::time::sleep_until(wake).await;

        let current = (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed));
        if current != last_seen {
            last_seen = current;
            last_change = Instant::now();
            continue;
        }
        let budget = applicable_budget(current, &budgets);
        if Instant::now() >= last_change + budget {
            return TcpFlowFailure::Budget {
                budget: if current.1 == 0 && current.0 > 0 {
                    TcpFlowBudget::FirstUpstreamByte
                } else {
                    TcpFlowBudget::Idle
                },
                duration: budget,
            };
        }
    }
}

fn applicable_budget((up, down): (u64, u64), budgets: &RelayBudgets) -> Duration {
    if down == 0 && up > 0 {
        budgets.first_upstream_byte
    } else {
        budgets.idle
    }
}

struct ObservedStream<'a, S> {
    inner: S,
    side: TcpFlowIoSide,
    first_error: &'a Mutex<Option<(TcpFlowIoSide, TcpFlowIoAction)>>,
}

impl<S> ObservedStream<'_, S> {
    fn record_error(&self, action: TcpFlowIoAction) {
        self.first_error
            .lock()
            .expect("relay error origin")
            .get_or_insert((self.side, action));
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedStream<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Err(_))) {
            this.record_error(TcpFlowIoAction::Read);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedStream<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Err(_)))
            || matches!(result, Poll::Ready(Ok(0)) if !buf.is_empty())
        {
            this.record_error(TcpFlowIoAction::Write);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.record_error(TcpFlowIoAction::Flush);
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Err(_)))
            || matches!(result, Poll::Ready(Ok(0)) if bufs.iter().any(|buf| !buf.is_empty()))
        {
            this.record_error(TcpFlowIoAction::Write);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.record_error(TcpFlowIoAction::Shutdown);
        }
        result
    }
}

/// Wraps the upstream side of the relay and streams completed IO sizes
/// into the session's shared byte counters: bytes written to the upstream
/// are upload, bytes read from it are download, so one wrapper accounts
/// both directions. Counter stores are relaxed — the ledger is advisory —
/// and cost a few atomic adds per completed read/write against IO that
/// costs a syscall.
struct CountingStream<S> {
    inner: S,
    counters: SessionByteCounters,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len() - before;
            if read > 0 {
                this.counters.add_down(read as u64);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            if *written > 0 {
                this.counters.add_up(*written as u64);
            }
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = &result {
            if *written > 0 {
                this.counters.add_up(*written as u64);
            }
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::*;
    use crate::session_registry::SessionRegistry;

    fn test_budgets(first_secs: u64, idle_secs: u64) -> RelayBudgets {
        RelayBudgets {
            first_upstream_byte: Duration::from_secs(first_secs),
            idle: Duration::from_secs(idle_secs),
        }
    }

    fn shared_counters(up: u64, down: u64) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (Arc::new(AtomicU64::new(up)), Arc::new(AtomicU64::new(down)))
    }

    #[derive(Default)]
    struct FaultIo {
        bytes: &'static [u8],
        eof: bool,
        read_error: Option<io::Error>,
        write_error: Option<io::Error>,
        shutdown_error: Option<io::Error>,
    }

    impl AsyncRead for FaultIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(error) = this.read_error.take() {
                return Poll::Ready(Err(error));
            }
            if !this.bytes.is_empty() {
                let len = this.bytes.len().min(buf.remaining());
                buf.put_slice(&this.bytes[..len]);
                this.bytes = &this.bytes[len..];
                Poll::Ready(Ok(()))
            } else if this.eof {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for FaultIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut().write_error.take() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(buf.len())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut().shutdown_error.take() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relay_attributes_endpoint_action_and_keeps_upstream_failures_visible() {
        use TcpFlowIoAction::{Read, Shutdown, Write};
        use TcpFlowIoSide::{Client, Upstream};
        let cases = [
            (Client, Read, libc::ECONNRESET),
            (Upstream, Read, libc::ECONNRESET),
            (Client, Write, libc::EPIPE),
            (Upstream, Write, libc::EPIPE),
            (Upstream, Shutdown, libc::EPIPE),
        ];
        for (side, action, code) in cases {
            let registry = SessionRegistry::with_capacity(1);
            let session = registry.register("test", None, "test:443".into()).unwrap();
            let mut client = FaultIo::default();
            let mut upstream = FaultIo::default();
            let error = io::Error::from_raw_os_error(code);
            let fault = match side {
                Client => &mut client,
                Upstream => &mut upstream,
            };
            match action {
                Read => fault.read_error = Some(error),
                Write => fault.write_error = Some(error),
                Shutdown => fault.shutdown_error = Some(error),
                _ => unreachable!(),
            }
            match (side, action) {
                (Client, Write) => upstream.bytes = b"response",
                (Upstream, Write) => client.bytes = b"request",
                (Upstream, Shutdown) => client.eof = true,
                _ => {}
            }
            let error = timeout(
                Duration::from_secs(1),
                relay_registered_session(&mut client, Box::new(upstream), &session, 0),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(
                matches!(&error.cause, TcpFlowFailure::Io { side: actual_side, action: actual_action, error } if *actual_side == side && *actual_action == action && error.raw_os_error() == Some(code)),
                "{error}"
            );
            assert_eq!(error.cause.is_expected_close(), side == Client, "{error}");
            if side == Upstream {
                assert_eq!(error.download_bytes, 0);
            } else if action == Write {
                assert_eq!(error.download_bytes, b"response".len() as u64);
            }
        }
    }

    #[tokio::test]
    async fn relay_preserves_bidirectional_half_close_and_delayed_response() {
        let registry = SessionRegistry::with_capacity(1);
        let session = registry
            .register("test", None, "half-close:443".into())
            .unwrap();
        let (mut client, mut inbound) = tokio::io::duplex(32);
        let (upstream, mut peer) = tokio::io::duplex(32);
        let relay = tokio::spawn(async move {
            relay_registered_session(&mut inbound, Box::new(upstream), &session, 0).await
        });
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        timeout(Duration::from_secs(1), peer.read_to_end(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, b"request");
        tokio::task::yield_now().await;
        peer.write_all(b"delayed-response").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"delayed-response");
        timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(registry.counters().active, 0);
    }

    #[tokio::test]
    async fn relay_cancellation_is_typed_even_when_both_sides_are_quiet() {
        let registry = SessionRegistry::with_capacity(1);
        let session = registry
            .register("test", None, "cancel:443".into())
            .unwrap();
        session.cancellation().cancel();
        let error = relay_registered_session(
            &mut FaultIo::default(),
            Box::new(FaultIo::default()),
            &session,
            3,
        )
        .await
        .unwrap_err();
        assert!(matches!(error.cause, TcpFlowFailure::Cancelled));
        assert!(error.cause.is_expected_close());
        assert_eq!((error.upload_bytes, error.download_bytes), (3, 0));
        assert_eq!(registry.counters().reaped_total, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_reaps_asked_and_never_answered_session_within_twice_the_budget() {
        // The incident shape: the client's first flight went out (here as
        // pre-credited upload) and the upstream never produces a byte.
        let (up, down) = shared_counters(5, 0);
        let started = Instant::now();

        let reason = watch_established_budgets(&up, &down, test_budgets(60, 3600)).await;

        let elapsed = started.elapsed();
        assert!(
            matches!(
                reason,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::FirstUpstreamByte,
                    ..
                }
            ),
            "{reason}"
        );
        assert!(
            elapsed >= Duration::from_secs(60) && elapsed <= Duration::from_secs(121),
            "reap landed at {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_gives_upstream_a_full_budget_after_a_late_first_upload() {
        // A client that connects, stays quiet, and only speaks later: the
        // response deadline must run from the (observed) first upload, not
        // from establishment.
        let (up, down) = shared_counters(0, 0);
        let bumper = Arc::clone(&up);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(470)).await;
            bumper.fetch_add(1, Ordering::Relaxed);
        });
        let started = Instant::now();

        let reason = watch_established_budgets(&up, &down, test_budgets(60, 3600)).await;

        let elapsed = started.elapsed();
        assert!(
            matches!(
                reason,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::FirstUpstreamByte,
                    ..
                }
            ),
            "{reason}"
        );
        assert!(
            elapsed >= Duration::from_secs(470 + 60) && elapsed <= Duration::from_secs(470 + 121),
            "reap landed at {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_reaps_fully_silent_session_on_the_idle_budget_not_the_first_byte_budget() {
        // No client data ever (a preconnect spare against a dead upstream):
        // the aggressive first-byte budget must not apply.
        let (up, down) = shared_counters(0, 0);
        let started = Instant::now();

        let reason = watch_established_budgets(&up, &down, test_budgets(60, 600)).await;

        let elapsed = started.elapsed();
        assert!(
            matches!(
                reason,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::Idle,
                    ..
                }
            ),
            "{reason}"
        );
        assert!(
            elapsed >= Duration::from_secs(600) && elapsed <= Duration::from_secs(661),
            "reap landed at {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_switches_to_the_idle_budget_once_the_upstream_answers() {
        let (up, down) = shared_counters(5, 0);
        let bumper = Arc::clone(&down);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            bumper.fetch_add(100, Ordering::Relaxed);
        });
        let started = Instant::now();

        let reason = watch_established_budgets(&up, &down, test_budgets(60, 600)).await;

        let elapsed = started.elapsed();
        assert!(
            matches!(
                reason,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::Idle,
                    ..
                }
            ),
            "{reason}"
        );
        // The answer is observed at the first wake (60s); the idle clock
        // runs from there.
        assert!(
            elapsed >= Duration::from_secs(60 + 600) && elapsed <= Duration::from_secs(60 + 601),
            "reap landed at {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn upload_only_session_is_never_reaped_by_the_first_byte_budget() {
        // syslog-style sink: the upstream never says a word but the client
        // keeps sending. The counters keep changing, so neither budget
        // applies — "no response yet" alone must never reap.
        let (up, down) = shared_counters(0, 0);
        let bumper = Arc::clone(&up);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                bumper.fetch_add(1024, Ordering::Relaxed);
            }
        });

        let watch = watch_established_budgets(&up, &down, test_budgets(60, 600));
        let outcome = timeout(Duration::from_secs(6_000), watch).await;

        assert!(
            outcome.is_err(),
            "upload-only session was reaped: {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_cadence_inside_the_idle_budget_survives_indefinitely() {
        // IMAP IDLE shape: silence in units just under the idle budget,
        // broken by a tiny keepalive, forever.
        let (up, down) = shared_counters(10, 10);
        let bumper = Arc::clone(&down);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(500)).await;
                bumper.fetch_add(2, Ordering::Relaxed);
            }
        });

        let watch = watch_established_budgets(&up, &down, test_budgets(60, 600));
        let outcome = timeout(Duration::from_secs(50_000), watch).await;

        assert!(
            outcome.is_err(),
            "keepalive session was reaped: {outcome:?}"
        );
    }

    /// An upstream that completes the write side instantly and never
    /// produces a byte — the IO shape of an ACK-everything black hole.
    #[derive(Debug, Default)]
    struct BlackHoleUpstream;

    impl AsyncRead for BlackHoleUpstream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for BlackHoleUpstream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect loopback");
        let (server, _) = listener.accept().await.expect("accept loopback");
        (client, server)
    }

    #[tokio::test]
    async fn established_relay_reaps_a_black_holed_upstream_and_counts_the_reap() {
        let registry = SessionRegistry::with_capacity(4);
        let session = registry
            .register("test", None, "blackhole.example:443".into())
            .expect("register session");
        let (_client, mut inbound) = loopback_pair().await;

        let result = relay_registered_session_with_budgets(
            &mut inbound,
            Box::new(BlackHoleUpstream),
            &session,
            5,
            RelayBudgets {
                first_upstream_byte: Duration::from_millis(150),
                idle: Duration::from_secs(30),
            },
        )
        .await;

        let error = result.expect_err("black-holed relay must be reaped");
        assert!(
            matches!(
                error.cause,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::FirstUpstreamByte,
                    ..
                }
            ),
            "{error}"
        );
        let counters = registry.counters();
        assert_eq!(counters.reaped_total, 1);
        assert_eq!(counters.killed_total, 0, "a reap is not a kill-switch kill");
        drop(session);
        assert_eq!(registry.counters().active, 0);
    }

    #[tokio::test]
    async fn established_relay_streams_live_byte_counts_into_the_ledger() {
        let registry = SessionRegistry::with_capacity(4);
        let session = registry
            .register("test", None, "echo.example:443".into())
            .expect("register session");
        let (mut client, mut inbound) = loopback_pair().await;
        let (upstream, mut upstream_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            let result =
                relay_registered_session(&mut inbound, Box::new(upstream), &session, 0).await;
            drop(session);
            result
        });

        client.write_all(b"ping").await.expect("client sends");
        let mut request = [0_u8; 4];
        upstream_peer
            .read_exact(&mut request)
            .await
            .expect("upstream sees the request");
        assert_eq!(&request, b"ping");
        wait_for_counters(&registry, 4, 0).await;

        upstream_peer
            .write_all(b"pong!")
            .await
            .expect("upstream answers");
        let mut response = [0_u8; 5];
        client
            .read_exact(&mut response)
            .await
            .expect("client sees the response");
        assert_eq!(&response, b"pong!");
        wait_for_counters(&registry, 4, 5).await;

        // Close both ends so the copy finishes cleanly.
        drop(upstream_peer);
        client.shutdown().await.expect("client shutdown");
        drop(client);
        relay
            .await
            .expect("relay task")
            .expect("relay completes without a reap");
        let counters = registry.counters();
        assert_eq!(counters.reaped_total, 0);
        assert_eq!(counters.active, 0);
    }

    async fn wait_for_counters(registry: &SessionRegistry, upload: u64, download: u64) {
        for _ in 0..400 {
            let snapshot = registry.snapshot();
            if snapshot.len() == 1
                && snapshot[0].upload_bytes == upload
                && snapshot[0].download_bytes == download
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "ledger never showed {upload}/{download}: {:?}",
            registry.snapshot()
        );
    }
}
