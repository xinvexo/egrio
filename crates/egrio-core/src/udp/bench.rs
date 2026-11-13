//! Bench-only handles over the crate-internal UDP session table
//! (`--features bench-internals`). The criterion bench measures the exact
//! per-datagram bookkeeping sequence of [`send_udp_flow_datagram`] — idle
//! sweep, socket-cache lookup, stats record — without the socket send, which is
//! the coarse-mutex cost the session-table sharding follow-up is gated on.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use super::{udp_session_key, UdpDatagram, UdpSessionKey, UdpSessionTable};
use crate::profile::TrafficPolicyMode;
use crate::rule_engine::RouteDecision;
use crate::target::ConnectTarget;

/// Cloning shares the underlying table, like the production handle.
#[derive(Clone)]
pub struct BenchUdpSessionTable {
    table: UdpSessionTable,
    route: RouteDecision,
}

/// A prebuilt datagram identity: production receives the datagram and
/// its route already materialized, so the bench keeps their construction
/// outside the measured loop. Distinct `flow` values produce distinct
/// session keys.
pub struct BenchUdpDatagram {
    datagram: UdpDatagram,
    key: UdpSessionKey,
}

impl Default for BenchUdpSessionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchUdpSessionTable {
    pub fn new() -> Self {
        Self {
            table: UdpSessionTable::default(),
            route: RouteDecision {
                traffic_policy_mode: TrafficPolicyMode::Rule,
                outbound: "DIRECT".into(),
                matched_rule: Some("bench-rule".into()),
                matched_kind: None,
                matched_payload: None,
                no_resolve: false,
            },
        }
    }

    pub fn datagram(&self, flow: u32) -> BenchUdpDatagram {
        let datagram = UdpDatagram {
            flow_id: Some(format!("bench-flow-{flow}")),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((
                Ipv4Addr::new(10, (flow >> 16) as u8, (flow >> 8) as u8, flow as u8),
                40_000,
            )),
            target: ConnectTarget {
                host: "203.0.113.9".into(),
                port: 4_500,
            },
            payload: vec![0xa5; 64],
            process_name: None,
            process_path: None,
        };
        let key = udp_session_key(&datagram);
        BenchUdpDatagram { datagram, key }
    }

    /// Like [`Self::datagram`] but tagged with an authenticated `user`:
    /// the session key then carries an `Arc<str>`, so
    /// this measures whether the multi-user server keying changes the
    /// table's contention profile versus the local capture keying.
    pub fn user_datagram(&self, flow: u32, user: u32) -> BenchUdpDatagram {
        let mut datagram = self.datagram(flow).datagram;
        datagram.user = Some(Arc::from(format!("bench-user-{user}").as_str()));
        let key = udp_session_key(&datagram);
        BenchUdpDatagram { datagram, key }
    }

    /// Seeds `flows` distinct resident sessions (stats entries only; the
    /// socket cache stays empty, so lookups in [`Self::per_datagram`]
    /// miss — a hit differs by one `Arc` clone).
    pub fn populate(&self, flows: u32, now: i64) {
        for flow in 0..flows {
            let datagram = self.datagram(flow);
            self.record(&datagram, now);
        }
    }

    /// Seeds `flows` resident sessions each under its own authenticated
    /// user — the resident load a multi-user server carries.
    pub fn populate_per_user(&self, flows: u32, now: i64) {
        for flow in 0..flows {
            let datagram = self.user_datagram(flow, flow);
            self.record(&datagram, now);
        }
    }

    /// The full per-datagram table sequence of [`super::send_udp_flow_datagram`]:
    /// idle sweep, socket-cache lookup, stats record.
    pub fn per_datagram(&self, datagram: &BenchUdpDatagram, now: i64) {
        self.table.sweep_idle(now);
        let _ = self.table.socket_lookup_for_bench(&datagram.key, "DIRECT");
        self.record(datagram, now);
    }

    /// Stats upsert alone (one lock on the stats map).
    pub fn record(&self, datagram: &BenchUdpDatagram, now: i64) {
        self.table.record_for_bench(
            &datagram.datagram,
            &self.route,
            "DIRECT",
            datagram.datagram.payload.len(),
            datagram.datagram.payload.len(),
            now,
        );
    }

    /// Idle sweep alone (full-table retain under the stats lock; runs
    /// once per datagram in production).
    pub fn sweep(&self, now: i64) -> usize {
        self.table.sweep_idle(now)
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
