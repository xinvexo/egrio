use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::task::TaskTracker;

use super::{NativeCoreDevice, NativeCoreDeviceInner};
use crate::runtime::RuntimeSnapshot;
use crate::{PolicyGroupKind, TrafficPolicyMode};

const MAX_RETIRED_EPOCHS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorePolicyUpdate {
    SelectGroup {
        group: String,
        member: String,
    },
    TrafficPolicy {
        mode: TrafficPolicyMode,
        global_outbound: Option<String>,
    },
    /// Enable AAAA answers and IPv6 domain-resolution candidates.
    Ipv6Enabled(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorePolicyState {
    pub profile_id: String,
    pub epoch: u64,
    /// Effective IPv6 DNS policy; does not forbid numeric IPv6 connections.
    pub ipv6_enabled: bool,
    pub traffic_policy_mode: TrafficPolicyMode,
    pub global_outbound: String,
    /// What each Select group is set to, the user's choice being the whole
    /// of it.
    pub selected_members: BTreeMap<String, String>,
    /// The member each automatic group uses right now, as declared in the
    /// group: a UrlTest group's pick, a Fallback group's first member whose
    /// node is not ejected. A LoadBalance group maps each target to its own
    /// member and a Relay group dials all of them, so neither reports one.
    /// Health moves these without the user or the profile moving, so a host
    /// that shows them polls this.
    pub automatic_members: BTreeMap<String, String>,
}

/// A validated candidate bound to one device and one admission epoch.
/// Dropping it before commit has no effect on the running Core.
#[derive(Debug)]
pub struct PreparedCorePolicyUpdate {
    device: Weak<NativeCoreDeviceInner>,
    base_epoch: u64,
    snapshot: Arc<RuntimeSnapshot>,
    selections: BTreeMap<String, String>,
    ipv6_changed: bool,
    /// Whether the DNS generation is a new one, which retires the old: its
    /// cache, and with it every UDP session still resolving through it.
    dns_rebuilt: bool,
    changed: bool,
}

impl PreparedCorePolicyUpdate {
    pub fn is_changed(&self) -> bool {
        self.changed
    }
}

#[derive(Debug, Clone)]
pub struct CorePolicyApplyReport {
    pub changed: bool,
    pub epoch: u64,
    pub retirement: RetirementTicket,
}

#[derive(Debug)]
struct RetirementInner {
    epoch: u64,
    tasks: TaskTracker,
    policy_tasks: Mutex<Option<TaskTracker>>,
}

/// Completion of exactly the old epoch: its handshakes, sniffs, dials and
/// TCP/UDP tasks. New traffic never extends it.
#[derive(Debug, Clone)]
pub struct RetirementTicket(Arc<RetirementInner>);

impl RetirementTicket {
    pub(crate) fn new(epoch: u64, tasks: TaskTracker) -> Self {
        Self(Arc::new(RetirementInner {
            epoch,
            tasks,
            policy_tasks: Mutex::new(None),
        }))
    }

    fn completed(epoch: u64) -> Self {
        let tasks = TaskTracker::new();
        tasks.close();
        Self::new(epoch, tasks)
    }

    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    pub fn is_complete(&self) -> bool {
        self.0.tasks.is_empty()
            && self
                .0
                .policy_tasks
                .lock()
                .expect("retired policy tasks")
                .as_ref()
                .is_none_or(TaskTracker::is_empty)
    }

    pub async fn wait(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            self.0.tasks.wait().await;
            let policy_tasks = self
                .0
                .policy_tasks
                .lock()
                .expect("retired policy tasks")
                .clone();
            if let Some(tasks) = policy_tasks {
                tasks.wait().await;
            }
        })
        .await
        .is_ok()
    }
}

impl NativeCoreDevice {
    pub fn observe_policy(&self) -> CorePolicyState {
        let admission = self
            .inner
            .sessions
            .route_admission
            .read()
            .expect("route admission lock");
        let snapshot = self.inner.snapshot.load();
        CorePolicyState {
            profile_id: snapshot.profile_id.clone(),
            epoch: admission.epoch,
            ipv6_enabled: snapshot.egress.ipv6_enabled(),
            traffic_policy_mode: snapshot.traffic_policy_mode,
            global_outbound: snapshot.global_outbound.clone(),
            selected_members: snapshot
                .groups
                .iter()
                .filter_map(|(name, group)| {
                    if !matches!(group.kind, PolicyGroupKind::Select) {
                        return None;
                    }
                    self.inner
                        .sessions
                        .group_state
                        .effective_selection(name, group)
                        .map(|member| (name.clone(), member))
                })
                .collect(),
            automatic_members: snapshot.automatic_members(&self.inner.sessions.group_state),
        }
    }

    pub fn prepare_policy_update(
        &self,
        updates: &[CorePolicyUpdate],
    ) -> Result<PreparedCorePolicyUpdate, String> {
        let admission = self
            .inner
            .sessions
            .route_admission
            .read()
            .expect("route admission lock");
        if self.inner.sessions.lifetime.is_cancelled() {
            return Err("native core device is closed".into());
        }
        let current = self.inner.snapshot.load_full();
        let mut snapshot = (*current).clone();
        let mut selections = BTreeMap::new();
        // The configured switch, not the effective one: an active TUN can
        // forbid IPv6 egress regardless, and comparing against that would
        // drop a change of the switch itself.
        let mut ipv6_enabled = current.egress.config().ipv6_enabled;
        for update in updates {
            match update {
                CorePolicyUpdate::SelectGroup { group, member } => {
                    let compiled = snapshot
                        .policy_group(group)
                        .ok_or_else(|| format!("policy group '{group}' does not exist"))?;
                    if !matches!(compiled.kind, PolicyGroupKind::Select) {
                        return Err(format!("policy group '{group}' is not selectable"));
                    }
                    if !compiled.members.contains(member) {
                        return Err(format!(
                            "'{member}' is not a member of policy group '{group}'"
                        ));
                    }
                    selections.insert(group.clone(), member.clone());
                }
                CorePolicyUpdate::TrafficPolicy {
                    mode,
                    global_outbound,
                } => {
                    if let Some(name) = global_outbound {
                        if !snapshot.has_outbound(name)
                            && !snapshot.has_group(name)
                            && !crate::rule_engine::is_reject_outbound(name)
                        {
                            return Err(format!("global outbound '{name}' does not exist"));
                        }
                        snapshot.global_outbound = name.clone();
                    }
                    snapshot.traffic_policy_mode = *mode;
                }
                CorePolicyUpdate::Ipv6Enabled(enabled) => ipv6_enabled = *enabled,
            }
        }
        selections.retain(|group, member| {
            let effective = current.policy_group(group).and_then(|compiled| {
                self.inner
                    .sessions
                    .group_state
                    .effective_selection(group, compiled)
            });
            effective.as_ref() != Some(member)
        });
        let ipv6_changed = ipv6_enabled != current.egress.config().ipv6_enabled;
        let changed = !selections.is_empty()
            || ipv6_changed
            || snapshot.traffic_policy_mode != current.traffic_policy_mode
            || snapshot.global_outbound != current.global_outbound;
        if changed
            && admission
                .retired
                .iter()
                .filter(|ticket| !ticket.is_complete())
                .count()
                >= MAX_RETIRED_EPOCHS
        {
            return Err("Core policy cleanup backlog is full".into());
        }
        if ipv6_changed {
            snapshot.egress = current.egress.with_ipv6_policy(ipv6_enabled);
        }
        // What the DNS service reads of the policy: the mode and the global
        // outbound it answers by, and the egress view the IPv6 switch
        // changes. A group's selection is not among them -- the service
        // reads selections live, through the group state every generation
        // shares -- so selecting a node keeps the generation, its cache and
        // the UDP sessions resolving through it.
        let dns_rebuilt = ipv6_changed
            || snapshot.traffic_policy_mode != current.traffic_policy_mode
            || snapshot.global_outbound != current.global_outbound;
        if dns_rebuilt {
            snapshot.rebuild_dns();
        }
        Ok(PreparedCorePolicyUpdate {
            device: Arc::downgrade(&self.inner),
            base_epoch: admission.epoch,
            snapshot: Arc::new(snapshot),
            selections,
            ipv6_changed,
            dns_rebuilt,
            changed,
        })
    }

    pub fn apply_policy_update(
        &self,
        prepared: PreparedCorePolicyUpdate,
    ) -> Result<CorePolicyApplyReport, String> {
        if !prepared.device.ptr_eq(&Arc::downgrade(&self.inner)) {
            return Err("Core policy candidate belongs to another device".into());
        }
        let mut admission = self
            .inner
            .sessions
            .route_admission
            .write()
            .expect("route admission lock");
        if self.inner.sessions.lifetime.is_cancelled() {
            return Err("native core device is closed".into());
        }
        if admission.epoch != prepared.base_epoch {
            return Err("Core policy epoch conflict".into());
        }
        if !prepared.changed {
            return Ok(CorePolicyApplyReport {
                changed: false,
                epoch: admission.epoch,
                retirement: RetirementTicket::completed(admission.epoch),
            });
        }
        if admission
            .retired
            .iter()
            .filter(|ticket| !ticket.is_complete())
            .count()
            >= MAX_RETIRED_EPOCHS
        {
            return Err("Core policy cleanup backlog is full".into());
        }
        let old = self.inner.snapshot.load_full();
        let retirement = admission.advance();
        for (group, member) in prepared.selections {
            self.inner.sessions.group_state.select(&group, &member);
        }
        self.inner.snapshot.store(prepared.snapshot);
        if prepared.dns_rebuilt {
            old.dns.retire();
        }
        if prepared.ipv6_changed {
            *retirement
                .0
                .policy_tasks
                .lock()
                .expect("retired policy tasks") = Some(old.egress.retire_policy());
        }
        self.reroute_sessions_locked(&admission, prepared.dns_rebuilt);
        let epoch = admission.epoch;
        drop(admission);
        Ok(CorePolicyApplyReport {
            changed: true,
            epoch,
            retirement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicyGroup, RouteRule, RuleKind, RuntimeProfile};

    fn core() -> NativeCoreDevice {
        let mut profile = RuntimeProfile::new("policy-test");
        profile.groups.push(PolicyGroup {
            id: "choice".into(),
            name: "Choice".into(),
            kind: PolicyGroupKind::Select,
            members: vec!["DIRECT".into(), "direct".into()],
            interval_seconds: None,
            test_url: None,
            selected: Some("direct".into()),
        });
        profile.rules = [RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "Choice",
            no_resolve: false,
        }]
        .into();
        NativeCoreDevice::compile(&profile)
    }

    /// What a host reads to show which member an automatic group uses: the
    /// Core's own choice, not the host's guess at it.
    #[test]
    fn a_report_carries_the_member_each_automatic_group_uses() {
        let mut profile = RuntimeProfile::new("automatic-members");
        profile.groups.push(PolicyGroup {
            id: "fast".into(),
            name: "Fast".into(),
            kind: PolicyGroupKind::UrlTest,
            members: vec!["DIRECT".into(), "direct".into()],
            interval_seconds: None,
            test_url: None,
            selected: None,
        });
        profile.groups.push(PolicyGroup {
            id: "choice".into(),
            name: "Choice".into(),
            kind: PolicyGroupKind::Select,
            members: vec!["DIRECT".into(), "direct".into()],
            interval_seconds: None,
            test_url: None,
            selected: Some("direct".into()),
        });
        let core = NativeCoreDevice::compile(&profile);

        let initial = core.observe_policy();
        assert_eq!(
            initial.automatic_members["Fast"], "DIRECT",
            "declared order until a probe says otherwise"
        );
        assert!(
            !initial.automatic_members.contains_key("Choice"),
            "a Select group's member is the user's choice, reported as one"
        );
        assert_eq!(initial.selected_members["Choice"], "direct");
        assert!(!initial.selected_members.contains_key("Fast"));

        core.inner
            .sessions
            .group_state
            .set_probe_ewma_for_test("direct", 10_000);
        assert_eq!(
            core.observe_policy().automatic_members["Fast"],
            "direct",
            "the member the probes made fastest"
        );
    }

    /// A TUN whose IPv6 posture forbids IPv6 egress whatever the profile says.
    #[derive(Debug)]
    struct Ipv6BlockingTun;

    impl crate::egress::EgressSocketGuard for Ipv6BlockingTun {
        fn protect_socket(
            &self,
            _: crate::egress::EgressSocketDescriptor,
            _: crate::egress::EgressSocketContext,
        ) -> Result<crate::egress::EgressBinding, String> {
            Ok(crate::egress::EgressBinding::unbound())
        }

        fn capture_overlay(&self) -> Option<Arc<crate::egress::CaptureEgressOverlay>> {
            Some(Arc::new(crate::egress::CaptureEgressOverlay {
                dns_servers: Vec::new(),
                ipv6_enabled: false,
            }))
        }
    }

    /// A Core that goes live without some of its profile's rules says so
    /// where the host logs: on its start and on each profile it takes, the
    /// first twenty by what they say and the rest as a count.
    #[test]
    fn a_core_going_live_tells_the_log_which_rules_it_left_out() {
        use std::sync::Mutex;

        static HEARD: Mutex<Vec<String>> = Mutex::new(Vec::new());
        struct Hears;
        impl log::Log for Hears {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                let line = record.args().to_string();
                // The other tests of this binary start Cores too.
                if record.target() == "rules"
                    && (line.contains("left-out") || line.contains("more rules"))
                {
                    HEARD.lock().unwrap().push(line);
                }
            }
            fn flush(&self) {}
        }
        log::set_logger(&Hears).expect("the only logger of this test binary");
        log::set_max_level(log::LevelFilter::Warn);
        let heard = || std::mem::take(&mut *HEARD.lock().unwrap());

        let rule = |kind, payload, outbound| RouteRule {
            kind,
            payload: Some(payload),
            outbound,
            no_resolve: false,
        };
        let mut profile = RuntimeProfile::new("left-out");
        profile.rules = [
            rule(RuleKind::Domain, "kept.example", "DIRECT"),
            rule(RuleKind::IpCidr, "left-out/8", "DIRECT"),
            rule(RuleKind::GeoIp, "left-out", "REJECT"),
        ]
        .into();
        let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
            profile: profile.clone(),
            egress: Default::default(),
            egress_socket_guard: None,
            capture: Default::default(),
            flow_scanner: None,
            fake_ip_mappings: None,
        });
        assert_eq!(
            heard(),
            [
                "IP-CIDR,left-out/8,DIRECT: IP CIDR rule has invalid payload",
                "GEOIP,left-out,REJECT: GEOIP rules need GeoIP data, which is not loaded; \
                 update GEODATA in Settings",
            ]
        );

        // A preview compiles the same rules and is not a Core going live.
        let _preview = NativeCoreDevice::compile(&profile);
        assert!(heard().is_empty());

        let names: Vec<String> = (0..25).map(|index| format!("left-out-{index}")).collect();
        profile.rules = names
            .iter()
            .map(|name| rule(RuleKind::Unknown, name, "DIRECT"))
            .collect();
        core.apply_profile(&profile);
        let heard = heard();
        assert_eq!(heard.len(), 21, "{heard:?}");
        assert_eq!(
            heard[19],
            "UNKNOWN,left-out-19,DIRECT: rule kind is not implemented by the native rule engine yet"
        );
        assert_eq!(heard[20], "5 more rules are left out or cut short");
    }

    #[test]
    fn the_ipv6_switch_follows_requests_while_a_tun_forbids_ipv6() {
        let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
            profile: RuntimeProfile::new("tun-ipv6"),
            egress: Default::default(),
            egress_socket_guard: Some(Arc::new(Ipv6BlockingTun)),
            capture: Default::default(),
            flow_scanner: None,
            fake_ip_mappings: None,
        });
        let configured =
            |core: &NativeCoreDevice| core.inner.snapshot.load().egress.config().ipv6_enabled;

        let on = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        assert!(on.ipv6_changed);
        core.apply_policy_update(on).unwrap();
        assert!(configured(&core));
        assert!(!core.ipv6_enabled(), "the TUN still forbids IPv6");

        let off = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(false)])
            .unwrap();
        assert!(
            off.changed && off.ipv6_changed,
            "switching back is a change"
        );
        core.apply_policy_update(off).unwrap();
        assert!(!configured(&core));

        let unrelated = core.prepare_policy_update(&[]).unwrap();
        assert!(!unrelated.ipv6_changed);
    }

    #[tokio::test]
    async fn preparation_noop_and_invalid_update_do_not_touch_live_policy() {
        let core = core();
        let initial = core.observe_policy();
        assert_eq!(initial.profile_id, "policy-test");
        assert_eq!(initial.selected_members["Choice"], "direct");
        assert_eq!(
            core.evaluate_route(&crate::RouteMatchInput::default())
                .await
                .unwrap()
                .resolved_outbound,
            "direct"
        );
        let runtime = core.pinned_runtime();
        let same = core
            .prepare_policy_update(&[CorePolicyUpdate::SelectGroup {
                group: "Choice".into(),
                member: "direct".into(),
            }])
            .unwrap();
        assert!(!same.is_changed());
        assert!(!core.apply_policy_update(same).unwrap().changed);
        assert!(!runtime.connection_cancellation().is_cancelled());
        let prepared = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        assert!(prepared.is_changed());
        drop(prepared);
        assert_eq!(core.observe_policy(), initial);
        assert!(core
            .prepare_policy_update(&[CorePolicyUpdate::SelectGroup {
                group: "Choice".into(),
                member: "missing".into(),
            }])
            .is_err());
        assert_eq!(core.observe_policy(), initial);
        assert!(!runtime.connection_cancellation().is_cancelled());
        let prepared = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        core.close();
        assert!(core.apply_policy_update(prepared).is_err());
    }

    #[tokio::test]
    async fn publication_is_one_epoch_reuses_rules_and_checks_candidate_identity() {
        let core = core();
        let before_runtime = core.pinned_runtime();
        let before = core.inner.snapshot.load_full();
        let stale = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        let prepared = core
            .prepare_policy_update(&[
                CorePolicyUpdate::SelectGroup {
                    group: "Choice".into(),
                    member: "DIRECT".into(),
                },
                CorePolicyUpdate::TrafficPolicy {
                    mode: TrafficPolicyMode::Direct,
                    global_outbound: None,
                },
                CorePolicyUpdate::Ipv6Enabled(true),
            ])
            .unwrap();
        let report = core.apply_policy_update(prepared).unwrap();
        assert_eq!(report.epoch, 1);
        assert!(report.changed && report.retirement.is_complete());
        let after = core.inner.snapshot.load_full();
        let after_runtime = core.pinned_runtime();
        assert!(Arc::ptr_eq(
            before_runtime.outbound_table().get("DIRECT").unwrap(),
            after_runtime.outbound_table().get("DIRECT").unwrap(),
        ));
        assert!(Arc::ptr_eq(&before.rule_engine, &after.rule_engine));
        assert!(Arc::ptr_eq(&before.groups, &after.groups));
        assert!(core.apply_policy_update(stale).is_err());
        let other = NativeCoreDevice::compile(&RuntimeProfile::new("other"));
        let candidate = core.prepare_policy_update(&[]).unwrap();
        assert!(other.apply_policy_update(candidate).is_err());
        let route = core
            .evaluate_route(&crate::RouteMatchInput::default())
            .await
            .unwrap();
        assert_eq!(
            route.decision.traffic_policy_mode,
            TrafficPolicyMode::Direct
        );
        assert_eq!(route.resolved_outbound, "DIRECT");
        assert!(core.ipv6_enabled());
    }

    #[tokio::test]
    async fn waiting_old_epoch_does_not_cancel_or_wait_for_new_epoch() {
        let core = core();
        let old = core.pinned_runtime();
        let old_holder = old.task_tracker().token();
        let prepared = core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        let applied = core.apply_policy_update(prepared).unwrap();
        let current = core.pinned_runtime();
        let new_holder = current.task_tracker().token();
        assert!(old.connection_cancellation().is_cancelled());
        assert!(!applied.retirement.wait(Duration::from_millis(10)).await);
        drop(old_holder);
        assert!(applied.retirement.wait(Duration::from_secs(1)).await);
        assert!(!current.connection_cancellation().is_cancelled());
        assert_eq!(core.observe_policy().epoch, applied.epoch);
        drop(new_holder);
    }

    #[test]
    fn retired_epoch_backlog_is_bounded_and_recovers() {
        let core = core();
        let mut holders = Vec::new();
        for step in 0..MAX_RETIRED_EPOCHS {
            holders.push(core.pinned_runtime().task_tracker().token());
            let update = CorePolicyUpdate::Ipv6Enabled(step % 2 == 0);
            let prepared = core.prepare_policy_update(&[update]).unwrap();
            core.apply_policy_update(prepared).unwrap();
        }
        assert!(core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .is_err());
        assert_eq!(core.observe_policy().epoch, MAX_RETIRED_EPOCHS as u64);
        drop(holders);
        assert!(core
            .prepare_policy_update(&[CorePolicyUpdate::Ipv6Enabled(true)])
            .is_ok());
    }

    #[test]
    fn traffic_policy_dns_and_sniff_decisions_use_shared_rule_index() {
        let mut profile = RuntimeProfile::new("policy-route");
        profile.traffic_policy_mode = TrafficPolicyMode::Direct;
        profile.rules = [RouteRule {
            kind: RuleKind::Domain,
            payload: Some("example.com"),
            outbound: "REJECT",
            no_resolve: false,
        }]
        .into();
        let core = NativeCoreDevice::compile(&profile);
        let rules = core.inner.snapshot.load_full().rule_engine.clone();
        let input = crate::RouteMatchInput {
            host: Some("example.com".into()),
            ..Default::default()
        };
        assert_eq!(core.pinned_runtime().route(&input).outbound, "DIRECT");
        let candidate = core
            .prepare_policy_update(&[CorePolicyUpdate::TrafficPolicy {
                mode: TrafficPolicyMode::Rule,
                global_outbound: None,
            }])
            .unwrap();
        core.apply_policy_update(candidate).unwrap();
        let runtime = core.pinned_runtime();
        assert_eq!(runtime.route(&input).outbound, "REJECT");
        assert!(runtime.should_sniff(&crate::target::ConnectTarget {
            host: "192.0.2.1".into(),
            port: 443
        }));
        assert_eq!(
            runtime
                .dns_service()
                .evaluate(&crate::DnsQueryInput {
                    query_class: 1,
                    domain: "example.com".into(),
                    record_type: crate::DnsRecordType::A,
                    process_name: None,
                    process_path: None,
                })
                .action,
            crate::DnsDecisionAction::Block
        );
        assert!(Arc::ptr_eq(
            &rules,
            &core.inner.snapshot.load_full().rule_engine
        ));
    }
}
