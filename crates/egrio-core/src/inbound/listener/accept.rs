//! The accept loop of one listener generation: admits each connection under
//! the session limit and the listener's scope, runs its inbound handshake
//! while the client's owner lookup runs, and drives the session through
//! dispatch.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, Instant};

use super::compose::InboundStrategy;
use super::scope::{ListenerScope, ScopeChange};
use super::state::{
    mark_failed, mark_listener_error, mark_session_accepted, mark_session_cancelled,
    mark_session_finished, mark_session_rejected, mark_session_task_join_error,
    CoreSessionManagerInner,
};
use super::wait_for_shutdown;
use crate::attribution::{ClientOwner, FlowKey, FlowProtocol, OwnerLookup};
use crate::device::NativeCoreDevice;
use crate::inbound::acceptor::InboundSession;
use crate::inbound::dispatch::{dispatch_session, InboundSessionError, InboundSessionOutcome};
use crate::runtime::NativeCoreRuntime;
use crate::status::{now_unix, NativeCoreState};

/// How long a freshly accepted connection has to finish its inbound
/// handshake before the listener drops it. This bounds a slow-loris on a
/// public port — a peer that connects and then stalls mid-handshake would
/// otherwise park an accept task and hold its session permit indefinitely.
/// It wraps only the handshake: the relay that follows a completed handshake
/// is unbounded, as a live tunnel must be. Every acceptor (SOCKS5, HTTP
/// CONNECT, Shadowsocks) defers its handshake-read timeout to this one
/// listener-level wrap rather than arming its own. The one exception is the
/// Hysteria2 acceptor: it serves its own QUIC endpoint, so no connection of
/// its own ever passes through here and it arms this budget itself, per
/// proxied stream.
pub(crate) const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// TCP keepalive on every accepted connection: the first probe after this
/// long without traffic, then one every [`INBOUND_KEEPALIVE_INTERVAL`] until
/// the client answers or the OS gives up. Without it a half-open inbound
/// connection never errors: when a client disappears without a FIN -- a phone
/// that loses its network, a NAT that drops the mapping -- and the upstream
/// is quiet too, neither socket reports anything, and the session sits in
/// Established for the whole hour of the relay's idle budget holding a
/// registry row, a listener permit and two sockets. The egress side's
/// keepalive cannot stand in for it: it only proves the *upstream* is alive.
/// The ledger does not flag such a session either, because bytes did come
/// down once.
const INBOUND_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const INBOUND_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Nagle off, keepalive on. The relay forwards small, latency-sensitive
/// control frames back to the client -- an HTTP/2 WINDOW_UPDATE the upstream
/// sends during an upload -- and Nagle holding them against the client's
/// delayed ACK stalls the tunnel, collapsing upload throughput. Both are
/// best effort, as on the egress side: a socket that refuses an option still
/// relays.
fn prepare_inbound_socket(client: &TcpStream) {
    let _ = client.set_nodelay(true);
    let _ = socket2::SockRef::from(client).set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(INBOUND_KEEPALIVE_IDLE)
            .with_interval(INBOUND_KEEPALIVE_INTERVAL),
    );
}

/// The pause before the next `accept` after one that failed for anything but
/// the connection it was about to return: the first is this long, and each
/// further failure in a row doubles it up to [`ACCEPT_PAUSE_MAX`]. Out of
/// descriptors is the usual reason, and accepting again at once only spins
/// until a session ends and gives one back.
const ACCEPT_PAUSE_MIN: Duration = Duration::from_millis(10);
const ACCEPT_PAUSE_MAX: Duration = Duration::from_secs(1);

/// Whether a failed `accept` lost only the connection it was about to return,
/// so the next can be taken at once: the client reset or aborted it while it
/// waited in the queue (POSIX `ECONNABORTED`; Winsock's `accept` reports
/// `WSAECONNRESET` for a connection "terminated by the remote peer prior to
/// accepting the call"), or the call was interrupted.
fn lost_one_connection(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
    )
}

/// When the listener may accept again after a failure that was not one
/// connection's. No `accept` error ends the listener: the socket is the
/// listener's own and stays valid, and every error the call reports is about
/// what was arriving or what the process ran out of. Out of descriptors
/// (`EMFILE`, `ENFILE`) or buffers (`ENOBUFS`, `ENOMEM`) passes when a session
/// ends (the connection that met it stays queued on Linux and is closed by
/// XNU); Linux also returns the pending network error of the new connection
/// here and asks that it be retried like `EAGAIN` (accept(2), "Error
/// handling"). Ending on any of these took the whole listener generation down
/// with it -- on a desktop the system proxy then points at a closed port until
/// someone turns it off and on, and on a public port whoever can open
/// connections can stop the service for good.
#[derive(Default)]
struct AcceptPause {
    until: Option<Instant>,
    pause: Duration,
}

impl AcceptPause {
    fn failed(&mut self) {
        self.pause = (self.pause * 2).clamp(ACCEPT_PAUSE_MIN, ACCEPT_PAUSE_MAX);
        self.until = Some(Instant::now() + self.pause);
    }

    fn accepted(&mut self) {
        *self = Self::default();
    }
}

pub(super) async fn run_listener(
    inner: Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    listener: TcpListener,
    device: NativeCoreDevice,
    session_limit: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
    strategy: InboundStrategy,
    mut scope_changes: mpsc::Receiver<ScopeChange>,
) {
    let mut scope = match ListenerScope::new(listener) {
        Ok(scope) => scope,
        Err(error) => {
            mark_failed(
                &inner,
                generation,
                format!("failed to inspect listener: {error}"),
            );
            return;
        }
    };
    let mut sessions = JoinSet::new();
    let mut accept_pause = AcceptPause::default();
    loop {
        let accept_after = accept_pause.until;
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                break;
            }
            Some(change) = scope_changes.recv() => {
                let result = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown_rx) => break,
                    result = scope.reconfigure(change.address) => result,
                };
                if let Ok(report) = &result {
                    let mut state = inner.lock().expect("native core manager mutex");
                    if state.generation == generation && state.status.state == NativeCoreState::Running {
                        state.status.listen_addr = report.effective_addr.map(|address| address.to_string());
                        // A fallback port moves with the scope; what was asked
                        // for moves to the same scope.
                        if let (Some(fallback), Some(effective)) =
                            (state.status.listener_fallback.as_mut(), report.effective_addr)
                        {
                            if let Ok(mut requested) = fallback.requested.parse::<SocketAddr>() {
                                requested.set_ip(effective.ip());
                                fallback.requested = requested.to_string();
                            }
                        }
                        state.scope_cleanup = scope.pending_cleanup();
                        state.status.last_error = report.error.clone();
                        state.status.updated_at_unix = now_unix();
                    }
                }
                let _ = change.reply.send(result);
            }
            Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                if let Err(error) = result {
                    mark_session_task_join_error(&inner, generation, error);
                }
            }
            accepted = async {
                // Sessions that end meanwhile are still joined above, which
                // is what gives descriptors back.
                if let Some(after) = accept_after {
                    tokio::time::sleep_until(after).await;
                }
                match scope.listener.as_ref() {
                    Some(listener) => listener.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                match accepted {
                    Ok((client, peer)) => {
                        accept_pause.accepted();
                        if !scope.accepts(peer) {
                            mark_session_rejected(&inner, generation, "listener only permits loopback clients");
                            continue;
                        }
                        prepare_inbound_socket(&client);
                        let Some(session_permit) =
                            acquire_session_permit(&inner, generation, &session_limit)
                        else {
                            continue;
                        };
                        mark_session_accepted(&inner, generation);
                        let owner = local_client_owner(&device, &client, peer);
                        let inner = inner.clone();
                        // Pin the snapshot and admission epoch together. A
                        // routing change cancels unfinished handshakes before
                        // they can register a route from this snapshot.
                        let strategy = strategy.clone();
                        let mut session_shutdown_rx = shutdown_rx.clone();
                        let remote_scope = scope.session_scope(peer);
                        let scope_cancel = remote_scope.as_ref().map(|(cancel, _)| cancel.clone());
                        let future = device.tracked_session(move |runtime| async move {
                            let _session_permit = session_permit;
                            tokio::select! {
                                biased;
                                _ = async {
                                    match scope_cancel {
                                        Some(cancel) => cancel.cancelled().await,
                                        None => std::future::pending().await,
                                    }
                                } => {
                                    mark_session_cancelled(&inner, generation);
                                }
                                result = serve_inbound_session(client, owner, &runtime, &strategy) => {
                                    mark_session_finished(&inner, generation, result);
                                }
                                _ = wait_for_shutdown(&mut session_shutdown_rx) => {
                                    mark_session_cancelled(&inner, generation);
                                }
                            }
                        });
                        if let Some((_, tracker)) = remote_scope {
                            sessions.spawn(tracker.track_future(future));
                        } else {
                            sessions.spawn(future);
                        }
                    }
                    Err(error) if lost_one_connection(&error) => {}
                    Err(error) => {
                        mark_listener_error(&inner, generation, "accept", &error);
                        accept_pause.failed();
                    }
                }
            }
        }
    }
    drop(scope);
    while let Some(result) = sessions.join_next().await {
        if let Err(error) = result {
            mark_session_task_join_error(&inner, generation, error);
        }
    }
}

/// Starts the owner lookup of a loopback client's socket, keyed as the client
/// sees it: from its own address to the listener address it dialed. A
/// remote client has no local owner.
fn local_client_owner(
    device: &NativeCoreDevice,
    client: &TcpStream,
    peer: SocketAddr,
) -> Option<OwnerLookup> {
    let source_ip = peer.ip().to_canonical();
    if !source_ip.is_loopback() {
        return None;
    }
    let listener = client.local_addr().ok()?;
    // The routing waits on the answer only while a rule reads the process.
    device.request_owner(
        FlowKey {
            protocol: FlowProtocol::Tcp,
            source_ip,
            source_port: peer.port(),
            destination_ip: listener.ip().to_canonical(),
            destination_port: listener.port(),
        },
        device.routes_by_process(),
    )
}

/// Serves one accepted connection: runs its inbound handshake under
/// [`INBOUND_HANDSHAKE_TIMEOUT`] while the client's owner lookup runs, then
/// drives the resulting session through the dispatch pipeline. Only the
/// handshake is bounded — the relay that follows a completed handshake is a
/// live tunnel and must not be cut short. The lookup is bounded by the
/// attribution budget from accept, and an unknown owner routes like the TUN.
async fn serve_inbound_session(
    client: TcpStream,
    owner: Option<OwnerLookup>,
    runtime: &NativeCoreRuntime,
    strategy: &InboundStrategy,
) -> Result<InboundSessionOutcome, InboundSessionError> {
    let source = client.peer_addr().ok().map(|addr| addr.to_string());
    let admission_cancel = runtime.connection_cancellation();
    let handshake = async {
        timeout(INBOUND_HANDSHAKE_TIMEOUT, strategy.accept(client))
            .await
            .map_err(|_| InboundSessionError::Handshake("inbound handshake timed out".into()))?
            .map_err(InboundSessionError::Handshake)
    };
    // The lookup is waited for beside the handshake only while a rule reads
    // the process; otherwise the session goes on and takes the owner later.
    let (owner, late_owner) = match owner {
        Some(owner) if !runtime.routes_by_process() => (None, Some(owner)),
        owner => (owner, None),
    };
    let owner = async {
        Ok::<_, InboundSessionError>(match owner {
            Some(owner) => owner.resolve().await,
            None => None,
        })
    };
    let (mut session, process) = tokio::select! {
        biased;
        _ = admission_cancel.cancelled() => return Err(InboundSessionError::Cancelled),
        result = async { tokio::try_join!(handshake, owner) } => result?,
    };
    if let InboundSession::Stream(stream) = &mut session {
        stream.process = match late_owner {
            Some(lookup) => ClientOwner::Pending(lookup),
            None => ClientOwner::Known(process),
        };
    }
    dispatch_session(runtime, source, session).await
}

pub(super) fn acquire_session_permit(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    session_limit: &Arc<Semaphore>,
) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(session_limit).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            mark_session_rejected(
                inner,
                generation,
                "native core active session limit reached",
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that disappears without a FIN has to be found by the socket,
    /// not waited out by the relay's hour.
    #[tokio::test]
    async fn an_accepted_socket_carries_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address).await.expect("client");
        let (accepted, _) = listener.accept().await.expect("accept");

        prepare_inbound_socket(&accepted);

        let socket = socket2::SockRef::from(&accepted);
        assert!(socket.keepalive().expect("keepalive flag"));
        assert!(accepted.nodelay().expect("nodelay flag"));
        drop(client);
    }

    #[test]
    fn an_accept_that_lost_its_connection_is_not_waited_out() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            assert!(lost_one_connection(&Error::from(kind)), "{kind:?}");
        }
        // Out of descriptors, and an error the platform does not explain.
        #[cfg(unix)]
        assert!(!lost_one_connection(&Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!lost_one_connection(&Error::from(ErrorKind::Other)));
    }

    /// Failures in a row wait longer each time up to the bound, and one
    /// accepted connection starts over.
    #[tokio::test(start_paused = true)]
    async fn the_pause_doubles_to_its_bound_and_ends_with_an_accept() {
        let mut pause = AcceptPause::default();
        assert!(pause.until.is_none());
        let mut waits = Vec::new();
        for _ in 0..9 {
            pause.failed();
            waits.push(pause.until.unwrap() - Instant::now());
        }
        assert_eq!(waits[0], ACCEPT_PAUSE_MIN);
        assert_eq!(waits[1], ACCEPT_PAUSE_MIN * 2);
        assert!(waits.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(waits[8], ACCEPT_PAUSE_MAX);
        pause.accepted();
        assert!(pause.until.is_none());
        pause.failed();
        assert_eq!(pause.until.unwrap() - Instant::now(), ACCEPT_PAUSE_MIN);
    }
}
