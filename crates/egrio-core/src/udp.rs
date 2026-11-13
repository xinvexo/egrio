//! UDP flow sessions and their relay. This module holds the limits and the
//! vocabulary -- a session's key and statistics, a datagram, what a drain
//! returns -- and its parts hold the rest:
//!
//! - `table` — the session table: its entries, what closes, sweeps and
//!   counts them, and the ready hubs of its consumers;
//! - `entry` — one session: the target identities its client addressed and
//!   the transports they share or own;
//! - `socket` — one transport of a session: its actor task, send mailbox
//!   and response queue (`actor` owns the transport's connect, I/O and end);
//! - `send` — one datagram's way in: admission, the route of its identity,
//!   the transport it joins or opens (`preparation` resolves a fake IP's
//!   name first; `target` prepares the business target);
//! - `reclaim` — what a full table gives up;
//! - `ready` and `drain` — the sockets with responses waiting, and the
//!   packet pumps and datagram faces that take them;
//! - `pump` — an established captured flow the packet pump sends itself;
//! - `association` — which replies belong to which identity.

#[cfg(test)]
use crate::outbound::DatagramFuture;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::Wake;

use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration, Instant};

use crate::egress::{EgressBindingRecorder, EgressRuntime, NetworkChange};
use crate::outbound::{
    DatagramError, DatagramOperation, OutboundConnector, OutboundDatagramTransport, PumpDatagrams,
    PumpTo, UDP_DATAGRAM_BUFFERS,
};
use crate::rule_engine::{RouteMatchInput, RouteStep, RuleAddress};
use crate::runtime::NativeCoreRuntime;
use crate::status::now_unix;
use crate::target::ConnectTarget;

mod actor;
mod association;
#[cfg(test)]
mod association_tests;
#[cfg(feature = "bench-internals")]
pub mod bench;
mod drain;
mod entry;
mod preparation;
mod pump;
mod ready;
mod reclaim;
mod send;
mod socket;
mod table;
mod target;
#[cfg(test)]
mod tests;
pub use actor::{
    UdpTransportDiagnostics, UdpTransportErrorSource, UdpTransportFailure,
    UdpTransportFailureCause, UdpTransportStage,
};
use association::{AssociationKey, Claim, ReplyTable};
pub(crate) use drain::*;
use entry::*;
use preparation::*;
pub(crate) use pump::*;
pub(crate) use ready::*;
use reclaim::*;
pub(crate) use send::*;
pub(crate) use socket::*;
pub(crate) use table::*;

const UDP_RESPONSE_QUEUE: usize = 16;
/// Bounded per-session send mailbox. A full mailbox drops the datagram
/// (normal UDP loss semantics) instead of blocking the caller.
const UDP_SEND_MAILBOX: usize = 64;
/// Bytes a queue that drops when it is full may hold: the send mailbox and a
/// preparation's waiting datagrams. The counts above bound datagrams, and a
/// captured datagram carries up to 65 535 bytes once the pump has reassembled
/// its fragments, so counts alone let the mailboxes of a thousand
/// associations against a stalled transport reach gigabytes. Count and bytes
/// together is the same shape of bound as the attribution gate's and the
/// reassembler's. The reply queue is not bounded here: a full one parks the
/// receive half so the upstream socket's buffer fills and the kernel drops at
/// the source, which is what a UDP peer should see.
const UDP_QUEUE_BYTES: usize = 512 * 1024;
const UDP_FLOW_DRAIN_MAX_DATAGRAMS: usize = 256;
const UDP_SESSION_MAX_ENTRIES: usize = 1024;
/// Places in the session table kept for local capture. A client of an
/// authenticated datagram face chooses the source it claims, and the face
/// gives each claimed source its own flow id, so one user's frames mint a
/// session entry each and the per-owner association limit never aggregates
/// them: without a reserve one authenticated user filled the table and every
/// local application's UDP -- the tunnel's own DNS included -- was refused.
const UDP_SESSION_CAPTURE_RESERVE: usize = 256;
/// Session entries one authenticated user may hold. The reserve above keeps
/// local capture out of an inbound user's way, but not the inbound users out
/// of each other's: the places left are first come, and one user claiming a
/// thousand sources took them all. A share of the places divided by the users
/// holding them cannot fix that -- it only binds once a user has taken the
/// pool, and by then the newcomer is already refused -- so the cap is
/// absolute, and twelve users at this one fill the places the reserve leaves.
/// It counts entries, not identities inside one, which is the axis
/// [`UDP_ASSOCIATIONS_PER_OWNER`] cannot see; the count is kept as entries
/// come and go, because working it out at admission is a walk over the whole
/// table on every datagram of a flood.
const UDP_SESSION_PER_USER_ENTRIES: usize = 64;
/// RFC 4787 REQ-5: a NAT UDP mapping timer must not expire in less than two
/// minutes.
const UDP_SESSION_IDLE_SECONDS: i64 = 120;
/// A session whose traffic ended within this many seconds of its start was
/// an exchange (a lookup, a probe); one whose traffic outlasted it is a
/// stream. A full table reclaims exchanges, see
/// [`UdpSessionEntry::reclaimable`].
const UDP_EXCHANGE_SECONDS: i64 = 2;
/// A session waiting this long for its first transport with nothing come back
/// has outlasted a working preparation: a name resolves inside the DNS query
/// budget and a reachable node answers a dial in well under a second. Past it
/// a full table takes its place, because the dial it waits on may run the
/// whole 30-second outbound budget, and until then every new UDP flow -- the
/// tunnel's own DNS included -- was refused. Refusing the newcomer instead is
/// what keeps a burst of new flows stable, so this waits out a preparation
/// that could still work.
const UDP_PREPARING_YIELD_SECONDS: i64 = 10;
/// How long a fruitless sweep of a full session table stands: within it an
/// admission that needs room is refused without sweeping again. A refused
/// datagram is a dropped datagram either way and a UDP client retries, so
/// standing by a sweep this briefly costs nothing and takes the sweep from
/// once per datagram to at most twenty times a second.
const UDP_FULL_SWEEP_STANDS: Duration = Duration::from_millis(50);
/// Datagrams that may wait at once for a name to resolve. The send path never
/// waits on DNS, so a datagram whose IP rules need its name's address waits in
/// a task of its own, holding its payload until the name resolves -- the DNS
/// query budget, five seconds. Without a bound a client streaming to a fake IP
/// at ten thousand datagrams a second had fifty thousand of them alive at
/// once; past the bound they are dropped, which is where they ended up anyway
/// once the resolution admitted them all into a mailbox that holds 64.
const UDP_RESOLVING_DATAGRAMS: usize = 256;
/// Sessions a full table reclaims in one pass, so the scan behind it is paid
/// once for a batch of new flows instead of for each one.
const UDP_RECLAIM_BATCH: usize = 256;
const UDP_RETIRED_SOCKET_MAX: usize = 4;
const UDP_ASSOCIATIONS_PER_OWNER: usize = 64;
const UDP_ASSOCIATIONS_GLOBAL: usize = 1024;
/// The prefix of the flow ids the packet pumps mint for captured flows
/// (`ptun-udp|<client>`).
pub(crate) const PUMP_FLOW_PREFIX: &str = "ptun-udp|";
/// Datagrams the pump reads from one socket before the next socket's turn.
const PUMP_READ_QUANTUM: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UdpSessionKey {
    /// Authenticated peer identity on multi-user inbounds:
    /// two users claiming the same private source address must not share a
    /// flow session. `None` for local capture inbounds.
    pub(crate) user: Option<Arc<str>>,
    /// Authenticated stream faces need a connection-local discriminator in
    /// addition to the user: two simultaneous connections may authenticate as
    /// the same user and claim the same private source tuple. Capture flows and
    /// connectionless UDP inbounds leave this `None`.
    pub(crate) face_flow: Option<String>,
    /// The client 2-tuple (RFC 4787 EIM+EIF, capture-redesign R2): one session
    /// per (source ip, source port), endpoint-independent of the remote. The
    /// target is deliberately not in the key, so one mapping serves every
    /// remote the client addresses and replies from any remote are accepted.
    pub(crate) source: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeUdpSession {
    pub(crate) key: UdpSessionKey,
    /// Which inbound opened the session: `tun` (packet capture) or
    /// `udp-associate` (an authenticated datagram face), taken from the first
    /// datagram and projected to the connection table.
    pub(crate) inbound: &'static str,
    /// The session's representative target: its first datagram's. One 2-tuple
    /// session addresses many remotes (EIM), so this is a connection-table
    /// label, never part of identity.
    pub(crate) target: ConnectTarget,
    pub(crate) flow_id: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) process_path: Option<String>,
    pub(crate) outbound: String,
    pub(crate) matched_rule: Option<String>,
    pub(crate) egress_interface: Option<u32>,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
    pub(crate) packets_sent: u64,
    pub(crate) packets_received: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct UdpDatagram {
    pub(crate) flow_id: Option<String>,
    /// For a captured datagram, the capture queue whose pump read it. The
    /// session it opens hands its replies, and its transport once DIRECT or
    /// otherwise pump-driven, to that queue's pump, whichever queue the
    /// flow's later datagrams arrive on.
    pub(crate) pump_queue: Option<usize>,
    /// Which inbound admitted this datagram: `tun` (packet capture) or
    /// `udp-associate` (an authenticated datagram face). Carried on the datagram
    /// like `user` so the session it opens can project its admission origin to
    /// the connection table.
    pub(crate) inbound: &'static str,
    /// Authenticated peer identity from the inbound acceptor's datagram
    /// face; `None` for local capture inbounds.
    pub(crate) user: Option<Arc<str>>,
    pub(crate) source: SocketAddr,
    /// The client-addressed endpoint, including its original numeric fake IP.
    /// route_and_session_socket owns the logical rewrite and reply binding.
    pub(crate) target: ConnectTarget,
    pub(crate) payload: Vec<u8>,
    pub(crate) process_name: Option<String>,
    pub(crate) process_path: Option<String>,
}

/// Outcome of the no-wait flow send: whether the datagram made it into the
/// session mailbox (`false` means it was dropped on a full mailbox).
#[derive(Debug, Clone)]
pub(crate) struct UdpSendOutcome {
    pub(crate) enqueued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpPendingFlowDatagram {
    pub(crate) flow_id: String,
    /// The client socket the reply goes back to: its session's 2-tuple.
    pub(crate) source: SocketAddr,
    /// The client-facing address this reply is sourced from (EIF): the reply's
    /// real remote, translated only through its association's prepared binding.
    pub(crate) source_endpoint: ConnectTarget,
    pub(crate) payload: Vec<u8>,
}

type SessionUdpSocket = Arc<UdpSessionSocket>;

/// A drained reply: a response for its consumer to frame, or datagrams the
/// packet pump read itself, already framed to their client.
pub(crate) enum UdpReply {
    Response(ConnectTarget, Vec<u8>),
    Packet(Vec<u8>),
    Train(UdpTrain),
}

/// Datagrams from one sender to one client that arrived together, for a
/// device that takes them as one frame
/// ([`PacketDevice::try_send_udp_train`](crate::packet::PacketDevice::try_send_udp_train)).
pub(crate) struct UdpTrain {
    pub(crate) header: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) segment: usize,
}

/// What a drain hands the packet pump: packets and trains read on its own
/// sockets, and responses the other session actors queued.
#[derive(Default)]
pub(crate) struct PumpReplies {
    pub(crate) packets: Vec<Vec<u8>>,
    pub(crate) trains: Vec<UdpTrain>,
    pub(crate) responses: Vec<UdpPendingFlowDatagram>,
}
