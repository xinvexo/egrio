//! Replacing what a running device decides with: a new profile or egress,
//! a network change, a group's chosen member, and the cutover of the
//! connections the old decision made.

use super::*;

impl NativeCoreDevice {
    /// Replaces configuration and cuts off old connections, preserving Fake-IP
    /// mappings. The packet-link MTU belongs to this device generation; changing
    /// it requires a new device and its matching OS adapter transaction.
    /// Rejection occurs before compiling/publishing or retiring any old state.
    pub fn apply_config(
        &self,
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
    ) -> Result<(), String> {
        capture_config.validate()?;
        let current_mtu = self.capture_mtu();
        if capture_config.mtu != current_mtu {
            return Err(format!(
                "Core packet MTU is fixed at {current_mtu} for this device generation; requested {}; create a new Core device to change it",
                capture_config.mtu,
            ));
        }
        self.publish_config(profile, egress_config, capture_config);
        Ok(())
    }

    /// Publishes an already-admitted configuration. Profile/egress-only APIs
    /// retain the existing capture contract rather than replacing link settings.
    fn publish_config(
        &self,
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
    ) {
        let snapshot = Arc::new(RuntimeSnapshot::compile(
            profile,
            egress_config,
            capture_config,
            self.inner.socket_guard.clone(),
            self.inner.sessions.group_state.clone(),
        ));
        snapshot.rule_engine.log_warnings();
        let mut admission = self
            .inner
            .sessions
            .route_admission
            .write()
            .expect("route admission lock");
        // The durable group state is keyed by profile names; dropping entries
        // the new snapshot no longer defines is what keeps the table bounded
        // across profile churn.
        self.inner.sessions.group_state.prune_unknown(
            |outbound| snapshot.has_outbound(outbound),
            |group| snapshot.has_group(group),
        );
        let previous = self.inner.snapshot.swap(snapshot.clone());
        previous.dns.retire();
        let retired = admission.advance();
        self.cutover_sessions_locked();
        drop(admission);
        drop(retired);
        // Refresh the probe schedule against the new snapshot (new nodes get
        // probed promptly); surviving nodes keep their cadence.
        self.kick_probe_loop();
    }

    /// Publishes a new profile while keeping the current egress and capture
    /// configuration.
    pub fn apply_profile(&self, profile: &RuntimeProfile) {
        let current = self.inner.snapshot.load();
        let egress_config = current.egress.config().clone();
        let capture_config = current.capture.clone();
        drop(current);
        self.publish_config(profile, egress_config, capture_config);
    }

    /// Replaces the complete profile and egress configuration while retaining
    /// capture configuration. Local policy commands use prepare/apply_policy_update
    /// instead; this path deliberately recompiles the supplied profile.
    pub fn apply_profile_and_egress(
        &self,
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
    ) {
        let capture_config = self.inner.snapshot.load().capture.clone();
        self.publish_config(profile, egress_config, capture_config);
    }

    /// The host's network changed, as the egress guard reported it, or the
    /// host slept: the connections whose egress the change took away end so
    /// their clients reconnect, carriers kept for later dials retire, and
    /// cached DNS answers go, as the new network's resolvers may answer
    /// differently. Latency measured on the old network is noise on the new
    /// one and ejections earned there are stale evidence, so both are dropped
    /// and the probe loop re-probes everything. The user's selector choices
    /// are kept.
    pub(crate) fn apply_network_change(&self, change: &NetworkChange) {
        let runtime = self.pinned_runtime();
        for connector in runtime.outbound_table().values() {
            connector.network_changed(change, runtime.egress());
        }
        runtime.dns_service().network_changed();
        self.inner.sessions.registry.kill_stranded(change);
        self.inner.sessions.udp_sessions.close_stranded(change);
        self.inner.sessions.group_state.reset_for_network_change();
        self.inner.probe_reset.store(true, Ordering::Relaxed);
        self.kick_probe_loop();
    }

    /// Persists a Select choice and cuts off every old connection. The
    /// selection survives snapshot swaps and is validated before any cutover.
    pub fn select_group_member(&self, group: &str, member: &str) -> Result<(), String> {
        let prepared = self.prepare_policy_update(&[CorePolicyUpdate::SelectGroup {
            group: group.into(),
            member: member.into(),
        }])?;
        self.apply_policy_update(prepared).map(|_| ())
    }

    /// Ends every existing connection and fences unfinished admissions. The
    /// device and fake-IP mappings remain usable for the next connection.
    pub fn cutover_sessions(&self) -> ConnectionCutoverReport {
        let mut admission = self
            .inner
            .sessions
            .route_admission
            .write()
            .expect("route admission lock");
        let retired = admission.advance();
        let report = self.cutover_sessions_locked();
        drop(admission);
        drop(retired);
        report
    }

    /// Waits for the captured old generations to drop all their resources.
    /// New-generation connections are outside this completion ticket.
    pub async fn cutover_sessions_and_wait(
        &self,
        timeout: Duration,
    ) -> Result<ConnectionCutoverReport, String> {
        let (report, retired) = {
            let mut admission = self
                .inner
                .sessions
                .route_admission
                .write()
                .expect("route admission lock");
            admission.advance();
            let report = self.cutover_sessions_locked();
            (report, admission.retired.clone())
        };
        tokio::time::timeout(timeout, async {
            for ticket in retired {
                if !ticket.wait(timeout).await {
                    return Err("timed out waiting for old Core connections to close".to_string());
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| "timed out waiting for old Core connections to close".to_string())??;
        Ok(report)
    }

    /// A policy change: the live sessions the new policy would route
    /// somewhere else end, and the rest keep running in the epoch it opened.
    /// Ending one resets its client at once, as the kill switch does, and the
    /// captured TCP engines stay up: a captured flow is a relay session like
    /// any other, judged with the rest.
    pub(super) fn reroute_sessions_locked(
        &self,
        admission: &crate::runtime::RouteAdmission,
        dns_rebuilt: bool,
    ) -> ConnectionCutoverReport {
        let runtime = NativeCoreRuntime::pinned_at(
            self.inner.snapshot.load_full(),
            self.inner.sessions.clone(),
            admission,
        );
        let keeps_route = |question: &crate::session_registry::RouteQuestion, outbound: &str| {
            keeps_its_route(&runtime, question, outbound)
        };
        let keeps_identity = |decision: &crate::rule_engine::RouteDecision,
                              target: &crate::target::ConnectTarget,
                              outbound: &str| {
            udp_identity_keeps_route(&runtime, decision, target, outbound)
        };
        ConnectionCutoverReport {
            tcp_relay_sessions: self
                .inner
                .sessions
                .registry
                .reroute(&keeps_route, &admission.tasks),
            // A UDP session resolves its targets through the DNS generation
            // that admitted it, so it can only outlive a change that leaves
            // that generation alone.
            udp_sessions: if dns_rebuilt {
                self.inner.sessions.udp_sessions.cutover()
            } else {
                self.inner
                    .sessions
                    .udp_sessions
                    .reroute(&keeps_identity, &admission.tasks)
            },
        }
    }

    pub(super) fn cutover_sessions_locked(&self) -> ConnectionCutoverReport {
        self.retire_packet_tcp();
        let tcp_relay_sessions = self.inner.sessions.registry.kill_all();
        let udp_sessions = self.inner.sessions.udp_sessions.cutover();
        ConnectionCutoverReport {
            tcp_relay_sessions,
            udp_sessions,
        }
    }

    /// Kill switch: terminates every live session
    /// relaying through `outbound` across all three ledgers. New sessions
    /// resolve immediately; explicit cutovers close all sessions. This
    /// targeted call remains for host-driven policies
    /// (e.g. firewall kill switches) that target one node regardless of
    /// routing.
    pub fn kill_sessions_by_outbound(&self, outbound: &str) -> KillSessionsReport {
        KillSessionsReport {
            outbound: outbound.to_string(),
            tcp_relay_sessions: self.inner.sessions.registry.kill_by_outbound(outbound),
            udp_sessions: self.inner.sessions.udp_sessions.close_by_outbound(outbound),
        }
    }
}
