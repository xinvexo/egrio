//! Read-only projections over the device's live session state: the
//! connection table, per-user traffic, finished-session history, the traffic
//! telemetry panel, the bounded-state audit, stalled-session diagnostics, and
//! the heartbeat line. These borrow only `inner.sessions`, `packet_tcp_active`,
//! and the watchdog stats — no lifecycle, snapshot-publish, or TCP engine state —
//! so they live apart from the device lifecycle in `mod.rs`. The free-fn
//! helpers they lean on (`fold_per_user_traffic`, the `*_connection_snapshot`
//! builders) stay in `mod.rs` and reach here through `use super::*`.

use super::*;

impl NativeCoreDevice {
    /// Stalled TCP relay sessions for host diagnostics, longest-stuck
    /// first: sessions past the stall threshold in a pre-Established phase,
    /// or Established without a single downstream byte (the black-hole
    /// signature). Empty under healthy traffic, so a periodic logger
    /// prints no destinations in normal operation. UDP flows keep their
    /// own table and are audited through the `udp_*` counters instead.
    pub fn stalled_sessions(&self, limit: usize) -> Vec<SessionSnapshot> {
        self.inner
            .sessions
            .registry
            .stalled_snapshot(limit, now_unix())
    }

    /// One heartbeat diagnostic event as a single JSON line: device status,
    /// the bounded-state audit (whose registry counters carry the per-phase
    /// session population), and up to `stalled_limit` stalled sessions.
    /// Destinations appear only while something is actually stuck —
    /// `stalled_sessions` is empty under healthy traffic — so a periodic
    /// logger stays free of browsing history. Hosts print the line verbatim
    /// on their diagnostic channel (macOS NE host stderr, the Windows
    /// wintun packet loop), keeping every platform's heartbeat vocabulary
    /// identical and machine-parseable.
    pub fn heartbeat_event(&self, event: &str, stalled_limit: usize) -> String {
        serde_json::json!({
            "event": event,
            "status": self.status(),
            "audit": self.state_audit(),
            "stalled": self.stalled_sessions(stalled_limit),
        })
        .to_string()
    }

    /// The UI connection table: live TCP relay sessions from the registry
    /// (captured TUN flows included — the packet path relays through the
    /// ordinary session pipeline) and live UDP sessions from their table,
    /// in one projection.
    pub fn connections_snapshot(&self) -> Vec<TrafficConnectionSnapshot> {
        let mut connections: Vec<TrafficConnectionSnapshot> = self
            .inner
            .sessions
            .registry
            .snapshot()
            .into_iter()
            .map(tcp_connection_snapshot)
            .collect();
        connections.extend(
            self.inner
                .sessions
                .udp_sessions
                .sessions_snapshot()
                .into_iter()
                .map(udp_connection_snapshot),
        );
        connections
    }

    /// Live per-user traffic accounting: folds the authenticated
    /// `user` across the live TCP relay ledger and the UDP session table. Current
    /// usage, not cumulative — a closed session leaves the live tables. Empty in
    /// the local-capture role, where sessions carry no user.
    pub fn per_user_traffic(&self) -> Vec<crate::PerUserTraffic> {
        fold_per_user_traffic(
            &self.inner.sessions.registry.snapshot(),
            &self.inner.sessions.udp_sessions.sessions_snapshot(),
        )
    }

    /// Terminal records from the registry's bounded history ring, oldest
    /// first, in connection-table shape. Kept out of
    /// [`Self::connections_snapshot`] so "the live table" stays a leak
    /// detector; the UI-facing telemetry projection concatenates both.
    pub fn finished_connections_snapshot(&self) -> Vec<TrafficConnectionSnapshot> {
        self.inner
            .sessions
            .registry
            .finished_snapshot()
            .into_iter()
            .map(finished_connection_snapshot)
            .collect()
    }

    /// Bytes this Core has relayed since it started.
    pub fn traffic_volume(&self) -> crate::TrafficVolume {
        self.inner.sessions.traffic_volume.volume()
    }

    /// What a host reads of this Core's traffic in one projection: the
    /// session registry's counters, the live connection table and the
    /// finished-session ring.
    pub fn traffic_telemetry_snapshot(&self) -> TrafficTelemetrySnapshot {
        self.traffic_telemetry_since(0).0
    }

    /// [`Self::traffic_telemetry_snapshot`] with only the terminal records
    /// newer than `after`, and the sequence number to ask after next time.
    /// A poller that keeps it rebuilds only what changed instead of the
    /// whole ring every time.
    pub fn traffic_telemetry_since(&self, after: u64) -> (TrafficTelemetrySnapshot, u64) {
        let counters = self.inner.sessions.registry.counters();
        let (completed_connections, failed_connections) =
            self.inner.sessions.registry.terminal_counts();
        let mut connections = self.connections_snapshot();
        let active_connections = connections.len() as u64;
        let (finished, newest) = self.inner.sessions.registry.finished_since(after);
        connections.extend(finished.into_iter().map(finished_connection_snapshot));
        let volume = self.traffic_volume();
        let snapshot = TrafficTelemetrySnapshot {
            sampled_at_unix: now_unix(),
            active_connections,
            accepted_connections: counters.accepted_total,
            completed_connections,
            failed_connections,
            upload_bytes: volume.upload_bytes,
            download_bytes: volume.download_bytes,
            connections,
        };
        (snapshot, newest)
    }

    /// Bounded-state audit across every session/cache table. Soak and churn
    /// gates assert the counts drain; hosts can expose it for diagnostics.
    pub fn state_audit(&self) -> CoreStateAudit {
        CoreStateAudit {
            tcp_relay_sessions: self.inner.sessions.registry.counters(),
            udp_sessions: self.inner.sessions.udp_sessions.len(),
            udp_session_sockets: self.inner.sessions.udp_sessions.session_socket_count(),
            udp_send_drops: self.inner.sessions.udp_sessions.send_drops(),
            udp_dns_answer_failures: self.inner.sessions.udp_sessions.dns_answer_failures(),
            udp_transport: self.inner.sessions.udp_sessions.transport_diagnostics(),
            packet_tcp_sessions: self.inner.packet_tcp_active.load(Ordering::Relaxed),
            fake_dns_entries: self.inner.sessions.fake_dns.len(),
            watchdog: self.inner.watchdog.stats(),
            sniff: self.inner.sessions.sniff_stats.counters(),
        }
    }
}
