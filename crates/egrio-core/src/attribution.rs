//! Best-effort process attribution for local flows.
//!
//! A host supplies a [`FlowScanner`] with the Core's start inputs; it maps a
//! client socket's five-tuple to the local process owning that socket. Core
//! owns everything else: one bounded cache, request queue and scanner worker
//! per Core, shared by the packet gate and by the listener that looks up a
//! loopback proxy client. A flow waits for its owner only while a routing
//! rule reads the process (the gate briefly holds a captured flow's first
//! packet; the listener waits beside the handshake); otherwise it goes on at
//! once and its connection record is filled in when the lookup answers.
//! Results describe a socket snapshot, not an authenticated sender, so an
//! unknown owner never blocks a connection.

mod gate;
mod worker;

pub(crate) use gate::AttributionGate;
pub(crate) use worker::{AttributionWorker, OwnerLookup};

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// How long a new flow waits for its owner before it proceeds as unknown:
/// a captured flow's first packet, or a proxy client's routing decision.
const ATTRIBUTION_BUDGET: Duration = Duration::from_millis(150);
/// How long a connection record that did not wait for its owner keeps
/// listening for the lookup: nothing is held meanwhile, so a slow scan still
/// names the owner.
const RECORD_BUDGET: Duration = Duration::from_secs(2);

/// The local process owning a flow's client socket, as far as the Core knows
/// when the flow starts.
pub(crate) enum ClientOwner {
    /// Looked up: the owner, or `None` when unknown.
    Known(Option<Arc<ProcessInfo>>),
    /// Still being looked up. Routing waits for it only when a rule reads
    /// the process; otherwise the flow goes on and its record is filled in
    /// when the answer comes.
    Pending(OwnerLookup),
}

impl ClientOwner {
    /// The owner if it is already known.
    pub(crate) fn known(&self) -> Option<&Arc<ProcessInfo>> {
        match self {
            Self::Known(process) => process.as_ref(),
            Self::Pending(_) => None,
        }
    }
}

impl fmt::Debug for ClientOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(process) => formatter.debug_tuple("Known").field(process).finish(),
            Self::Pending(_) => formatter.write_str("Pending"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

/// The flow exactly as the client's socket sees it: its own address as the
/// source and the numeric address it dialed (before any Fake-IP resolution)
/// as the destination, so a scanner can match that socket's tuple.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessInfo {
    pub name: Option<String>,
    pub path: Option<String>,
}

/// Platform socket-ownership lookup. Called only from Core's attribution
/// worker thread, at most [`FLOW_SCAN_BATCH`] flows per call. Matching is
/// directional: the source is the owning socket's local endpoint, which
/// keeps a loopback client apart from the Core's own accepted socket.
pub trait FlowScanner: Send + Sync + fmt::Debug {
    /// Returns one entry per requested flow, in order. Ambiguous, shared or
    /// incomplete observations must be `None` rather than a guess. The scan
    /// must respect `budget` and return promptly once `stop` is set.
    fn scan(
        &self,
        flows: &[FlowKey],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Vec<Option<ProcessInfo>>;
}

pub const FLOW_SCAN_BATCH: usize = worker::BATCH;
