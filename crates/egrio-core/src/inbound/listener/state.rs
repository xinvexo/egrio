//! The listener manager's generation state and its transitions: the start
//! reservation, the session counters the accept loop moves, and the failure
//! and release paths that end a generation.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, watch};

use super::scope::ScopeChange;
use crate::device::NativeCoreDevice;
use crate::inbound::dispatch::{InboundSessionError, InboundSessionOutcome};
use crate::status::{now_unix, NativeCoreState, NativeCoreStatus};
use crate::ConnectionTermination;

#[derive(Debug)]
pub(super) struct CoreSessionManagerInner {
    pub(super) generation: u64,
    pub(super) next_generation: u64,
    pub(super) starting_generation: Option<u64>,
    /// The reserved or serving generation whose sockets/tasks have not yet
    /// crossed their release barrier. This outlives `shutdown_tx` and
    /// `device`: failure takes those handles to trigger teardown, but `stop`
    /// must still wait for the generation supervisor before publishing
    /// `Stopped`.
    pub(super) active_generation: Option<u64>,
    /// Failure to publish after the active generation has fully released.
    /// Until then the public state remains `Stopping`, so callers cannot
    /// mistake a still-draining failure for a restartable terminal state.
    pub(super) pending_failure: Option<String>,
    pub(super) status: NativeCoreStatus,
    pub(super) shutdown_tx: Option<watch::Sender<bool>>,
    pub(super) scope_changes: Option<mpsc::Sender<ScopeChange>>,
    pub(super) scope_cleanup: Option<tokio_util::task::TaskTracker>,
    pub(super) device: Option<NativeCoreDevice>,
    /// Whether this listener owns the device and must close it. A listener
    /// started with `start_on_device` only stops its inbound tasks.
    pub(super) owns_device: bool,
    pub(super) inbound: InboundHandles,
}

impl Default for CoreSessionManagerInner {
    fn default() -> Self {
        Self {
            generation: 0,
            next_generation: 0,
            starting_generation: None,
            active_generation: None,
            pending_failure: None,
            status: NativeCoreStatus::stopped(),
            shutdown_tx: None,
            scope_changes: None,
            scope_cleanup: None,
            device: None,
            owns_device: true,
            inbound: InboundHandles::default(),
        }
    }
}

/// What the running inbounds surface on the control surface. Plain handles
/// rather than the acceptors, so these fields — and the methods reading them —
/// stay ungated; only the code that populates them is server-only.
#[derive(Debug, Default)]
pub(super) struct InboundHandles {
    /// Failed authentications of the encrypted stream inbound (Shadowsocks or
    /// Trojan).
    pub(super) auth_failures: Option<Arc<AtomicU64>>,
    /// The Hysteria2 QUIC/H3 inbound's failed authentications and the address
    /// its endpoint bound (it may bind an ephemeral port).
    pub(super) hysteria2_auth_failures: Option<Arc<AtomicU64>>,
    pub(super) hysteria2_listen_addr: Option<String>,
}

pub(super) struct CoreSessionStartReservation {
    inner: Arc<Mutex<CoreSessionManagerInner>>,
    pub(super) generation: u64,
    committed: bool,
}

impl CoreSessionStartReservation {
    pub(super) fn new(inner: Arc<Mutex<CoreSessionManagerInner>>, generation: u64) -> Self {
        Self {
            inner,
            generation,
            committed: false,
        }
    }

    pub(super) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for CoreSessionStartReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut inner = self.inner.lock().expect("native core manager mutex");
        if inner.starting_generation == Some(self.generation) {
            inner.starting_generation = None;
        }
        if inner.active_generation == Some(self.generation) {
            inner.active_generation = None;
            if inner.status.state == NativeCoreState::Stopping {
                inner.status = NativeCoreStatus::stopped();
            }
        }
    }
}

pub(super) fn mark_session_accepted(inner: &Arc<Mutex<CoreSessionManagerInner>>, generation: u64) {
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.generation != generation {
        return;
    }
    inner.status.active_sessions += 1;
    inner.status.accepted_sessions += 1;
    inner.status.updated_at_unix = now_unix();
}

pub(super) fn mark_session_finished(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    result: Result<InboundSessionOutcome, InboundSessionError>,
) {
    let (termination, diagnostic) = match result {
        Ok(outcome) => (outcome.termination, None),
        Err(error) => {
            let termination = error.termination();
            let diagnostic = matches!(termination, ConnectionTermination::Failed { .. })
                .then(|| error.to_string());
            (termination, diagnostic)
        }
    };
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.generation != generation {
        return;
    }
    inner.status.active_sessions = inner.status.active_sessions.saturating_sub(1);
    match termination {
        ConnectionTermination::Completed => inner.status.completed_sessions += 1,
        ConnectionTermination::Failed { .. } => {
            inner.status.failed_sessions += 1;
            inner.status.last_error = diagnostic;
        }
        _ => {}
    }
    inner.status.updated_at_unix = now_unix();
}

pub(super) fn mark_session_cancelled(inner: &Arc<Mutex<CoreSessionManagerInner>>, generation: u64) {
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.generation != generation {
        return;
    }
    inner.status.active_sessions = inner.status.active_sessions.saturating_sub(1);
    inner.status.updated_at_unix = now_unix();
}

pub(super) fn mark_session_task_join_error(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    error: tokio::task::JoinError,
) {
    if error.is_cancelled() {
        mark_session_cancelled(inner, generation);
    } else {
        mark_session_finished(
            inner,
            generation,
            Err(InboundSessionError::Handshake(format!(
                "native core session task failed: {error}"
            ))),
        );
    }
}

pub(super) fn mark_session_rejected(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    error: &str,
) {
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.generation != generation {
        return;
    }
    inner.status.failed_sessions += 1;
    inner.status.last_error = Some(error.into());
    inner.status.updated_at_unix = now_unix();
}

/// Records an error of a listening socket that the listener outlives -- an
/// `accept` or a datagram receive that failed without one peer to blame --
/// so the status says why new clients wait.
pub(super) fn mark_listener_error(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    operation: &str,
    error: &std::io::Error,
) {
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.generation != generation {
        return;
    }
    inner.status.last_error = Some(format!("native core {operation} failed: {error}"));
    inner.status.updated_at_unix = now_unix();
}

pub(super) fn mark_failed(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    error: String,
) {
    let (device, owns_device) = {
        let mut inner = inner.lock().expect("native core manager mutex");
        if inner.generation != generation {
            return;
        }
        if inner.status.state == NativeCoreState::Stopping {
            return;
        }
        inner.status.state = NativeCoreState::Stopping;
        inner.status.last_error = Some(error.clone());
        inner.status.updated_at_unix = now_unix();
        inner.pending_failure = Some(error);
        inner.shutdown_tx = None;
        inner.inbound = InboundHandles::default();
        inner.scope_changes = None;
        (inner.device.take(), inner.owns_device)
    };
    if owns_device {
        if let Some(device) = device {
            device.close();
        }
    }
}

pub(super) fn finish_listener_generation(
    inner: &Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
) {
    let mut inner = inner.lock().expect("native core manager mutex");
    if inner.active_generation == Some(generation) {
        inner.active_generation = None;
    }
    if inner.generation != generation {
        return;
    }
    inner.device = None;
    let pending_failure = inner.pending_failure.take();
    inner.status.state = if pending_failure.is_some() {
        NativeCoreState::Failed
    } else {
        NativeCoreState::Stopped
    };
    inner.status.listen_addr = None;
    inner.status.listener_fallback = None;
    inner.status.dns_listen_addr = None;
    inner.status.started_at_unix = None;
    inner.status.updated_at_unix = now_unix();
    inner.status.active_sessions = 0;
    inner.status.last_error = pending_failure;
    inner.shutdown_tx = None;
    inner.inbound = InboundHandles::default();
    inner.scope_changes = None;
    inner.scope_cleanup = None;
}
