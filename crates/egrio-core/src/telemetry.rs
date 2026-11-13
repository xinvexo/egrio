use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ConnectionTermination, NativeCoreStatus};

/// Bytes one Core has relayed since it started. Every TCP relay and UDP
/// session adds to it where it counts its own bytes, so it only grows: a
/// rate is its difference over time, unlike a sum over connection rows,
/// which shrinks when rows leave a bounded history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficVolume {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// The shared counter behind [`TrafficVolume`]: relaxed adds next to the
/// per-session counters, one per completed read, write or datagram.
///
/// The two directions sit a cache line apart. Every relay and every capture
/// queue's pump adds to them, and a download's adds and an upload's would
/// otherwise take turns owning one line between all of those threads. It
/// costs 128 bytes once per Core. Nothing here measures the win: the adds
/// are one per relay chunk (64 KiB) or per datagram, so the rate the
/// instruments reach -- a quarter of a million a second on the UDP harness,
/// which drives one queue -- is far from where a contended line shows.
#[derive(Debug, Default)]
pub(crate) struct TrafficVolumeCounter {
    upload: CacheLine<AtomicU64>,
    download: CacheLine<AtomicU64>,
}

/// A value with a cache line to itself.
#[derive(Debug, Default)]
#[repr(align(64))]
struct CacheLine<T>(T);

impl TrafficVolumeCounter {
    pub(crate) fn add_upload(&self, bytes: u64) {
        self.upload.0.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn add_download(&self, bytes: u64) {
        self.download.0.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn volume(&self) -> TrafficVolume {
        TrafficVolume {
            upload_bytes: self.upload.0.load(Ordering::Relaxed),
            download_bytes: self.download.0.load(Ordering::Relaxed),
        }
    }
}

/// What a host reads of a running Core's traffic: its counters and its
/// connection table. A host in the Core's process reads it as it is; one
/// that serves it elsewhere serializes it.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficTelemetrySnapshot {
    pub sampled_at_unix: i64,
    pub active_connections: u64,
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    /// The Core's [`TrafficVolume`] since it started.
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub connections: Vec<TrafficConnectionSnapshot>,
}

/// One connection as the connection table shows it.
///
/// Its texts are shared, not owned: a row of a live TCP session holds the
/// session ledger's own strings, so reading the table copies none of them,
/// and a host that keeps rows -- a history, the table that shows it -- keeps
/// them by cloning pointers rather than allocating every text again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficConnectionSnapshot {
    pub id: Arc<str>,
    pub protocol: TrafficConnectionProtocol,
    pub process_name: Option<Arc<str>>,
    /// Absolute path of the owning executable when the capture layer
    /// attributed one (e.g. Windows Wintun flows). Display-only: the
    /// connections UI resolves the app icon from it. `None` on platforms or
    /// paths without process attribution.
    pub process_path: Option<Arc<str>>,
    pub source: Option<Arc<str>>,
    pub destination: Arc<str>,
    pub host: Option<Arc<str>>,
    /// The rule that routed the connection, as its profile writes it
    /// ([`crate::RouteRule::text`]: `DOMAIN-SUFFIX,example.com,Proxy`);
    /// `None` when no rule did (direct and global mode, or no rule matched).
    /// It names the rule by what the rule says, so a row a host keeps stays
    /// true after the profile's list of rules is edited or another profile
    /// takes its place.
    pub rule: Option<Arc<str>>,
    /// Which inbound admitted the connection: `http-connect`, `http-forward`
    /// or `socks5-connect` (the local listener's faces: a CONNECT tunnel, a
    /// forwarded plain `http://` request, a SOCKS5 CONNECT), `tun` (packet
    /// capture), `udp-associate` (a datagram face), or an authenticated server
    /// inbound's face id (`hysteria2`, `shadowsocks`, `trojan`). Pairs with
    /// `outbound` so a row answers "which path in, which path out".
    pub inbound: &'static str,
    pub outbound: Arc<str>,
    /// Physical egress interface index the dial bound to (Windows
    /// `IP_UNICAST_IF`). `None` on hosts without an interface-binding guard, and
    /// on rows whose dial funnel does not thread it (UDP sessions today).
    pub egress_interface: Option<u32>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub opened_at_unix: i64,
    pub updated_at_unix: i64,
    pub state: TrafficConnectionState,
    /// Explicit terminal fact. Active rows have no termination.
    pub termination: Option<ConnectionTermination>,
    /// Set exactly when `state` is a terminal one; duration is derived as
    /// `(closed_at_unix or now) - opened_at_unix` so active rows never
    /// carry a stale figure. For a host-inferred Unknown row, this is the
    /// observation-gap time, not proof of when the socket actually closed.
    pub closed_at_unix: Option<i64>,
}

/// Live per-user traffic accounting: the authenticated `user`
/// the inbound handshake proved, folded across the live TCP relay ledger and the
/// UDP session table. This is *current* usage, not cumulative billing — it sums
/// the bytes of a user's active sessions, and a closed session leaves the live
/// tables, so a host that wants durable totals polls this and accumulates.
/// Local-capture sessions carry no user and never appear here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerUserTraffic {
    pub user: String,
    pub tcp_connections: u64,
    pub udp_flows: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// Lifecycle state derived from the explicit terminal fact, never traffic volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficConnectionState {
    Active,
    Completed,
    Cancelled,
    Rejected,
    Failed,
    Unknown,
}

impl From<&ConnectionTermination> for TrafficConnectionState {
    fn from(termination: &ConnectionTermination) -> Self {
        match termination {
            ConnectionTermination::Completed => Self::Completed,
            ConnectionTermination::Cancelled | ConnectionTermination::ClientClosed { .. } => {
                Self::Cancelled
            }
            ConnectionTermination::RouteRejected | ConnectionTermination::PolicyRejected { .. } => {
                Self::Rejected
            }
            ConnectionTermination::Failed { .. } => Self::Failed,
            ConnectionTermination::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficConnectionProtocol {
    Tcp,
    Udp,
}

/// What a listener that runs no Core has to report: its counters, and no
/// connection.
pub fn traffic_telemetry_snapshot(status: &NativeCoreStatus) -> TrafficTelemetrySnapshot {
    TrafficTelemetrySnapshot {
        sampled_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        active_connections: status.active_sessions,
        accepted_connections: status.accepted_sessions,
        completed_connections: status.completed_sessions,
        failed_connections: status.failed_sessions,
        upload_bytes: 0,
        download_bytes: 0,
        connections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeCoreState, NativeCoreStatus};

    #[test]
    fn telemetry_snapshot_exposes_manager_counters_without_fake_connections() {
        let status = NativeCoreStatus {
            state: NativeCoreState::Running,
            listen_addr: Some("127.0.0.1:7890".into()),
            listener_fallback: None,
            dns_listen_addr: Some("127.0.0.1:5353".into()),
            started_at_unix: Some(10),
            updated_at_unix: 20,
            active_sessions: 2,
            accepted_sessions: 5,
            completed_sessions: 2,
            failed_sessions: 1,
            last_error: None,
        };

        let snapshot = traffic_telemetry_snapshot(&status);

        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.accepted_connections, 5);
        assert_eq!(snapshot.completed_connections, 2);
        assert_eq!(snapshot.failed_connections, 1);
        assert_eq!(snapshot.connections.len(), 0);
        assert_eq!(snapshot.upload_bytes, 0);
        assert_eq!(snapshot.download_bytes, 0);
    }
}
