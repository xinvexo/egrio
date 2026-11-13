use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::capture::NativeCoreCaptureConfig;
use crate::device::{NativeCoreDevice, NativeCoreDeviceStatus};
use crate::dns::fake_ip::FakeDnsStore;
use crate::dns::service::DnsService;
use crate::egress::{EgressBinding, EgressRuntime, EgressSocketGuard, NativeCoreEgressConfig};
use crate::outbound::options::udp_switch;
use crate::outbound::probe::{parse_probe_url, verify_response, OutboundProbeRequest};
use crate::outbound::{
    chain_issue, proxy_auth, BoxedOutboundStream, Dialer, DirectConnector, Hops, OutboundConnector,
    OutboundTable, ProxyTls, OUTBOUND_DIAL_BUDGET,
};

use crate::policy_group::{
    compile_policy_groups, derive_probe_plans, group_member_in_use, now_unix, outbound_takes_udp,
    resolve_outbound_name, resolve_outbound_until, CompiledPolicyGroup, GroupStateTable,
    OutboundProbePlan, PROBE_TIMEOUT,
};
use crate::profile::{
    PolicyGroupKind, ProxyNode, ProxyProtocol, RuntimeProfile, TrafficPolicyMode,
};
use crate::protocols::http::HttpProxyConnector;
use crate::protocols::hysteria2::Hysteria2Connector;
use crate::protocols::openvpn::OpenVpnConnector;
use crate::protocols::shadowsocks::ShadowsocksConnector;
use crate::protocols::socks5::Socks5ProxyConnector;
use crate::protocols::trojan::TrojanConnector;
use crate::rule_engine::{RouteMatchInput, RouteStep, RuleAddress, RuleEngine, TransportNetwork};
use crate::session_registry::{SessionGuard, SessionRegistry};
use crate::target::ConnectTarget;
use crate::tcp_flow::{TcpFlowBudget, TcpFlowFailure};

mod target;

/// Compiled, immutable decision state produced from one profile: rule/DNS
/// engines, egress runtime, capture config, and the outbound endpoint table.
/// Sessions pin the snapshot that was current when they were established;
/// profile changes publish a new snapshot and never mutate a pinned one.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeSnapshot {
    pub(crate) profile_id: String,
    pub(crate) rule_engine: Arc<RuleEngine>,
    pub(crate) egress: EgressRuntime,
    pub(crate) capture: NativeCoreCaptureConfig,
    /// Concrete dialable outbounds only: DIRECT plus each proxy node, as
    /// protocol connector objects. Policy groups are kept separately and
    /// resolved to a concrete outbound at dial time, so a group's choice
    /// reflects live health
    /// and the user's selection instead of a value frozen at compile time.
    outbounds: Arc<OutboundTable>,
    pub(crate) groups: Arc<HashMap<String, CompiledPolicyGroup>>,
    /// The groups a rejecting outbound can be reached through, so that only
    /// a route to one of them looks up what the group chooses.
    rejecting_groups: Arc<HashSet<String>>,
    /// What the chained nodes' dials go through. Only held: the egress
    /// refers to it weakly.
    #[allow(dead_code)]
    hops: Arc<Hops>,
    /// The nodes' own `test-url`s, by name.
    node_test_urls: Arc<HashMap<String, String>>,
    pub(crate) traffic_policy_mode: TrafficPolicyMode,
    pub(crate) global_outbound: String,
    pub(crate) dns: Arc<DnsService>,
}

/// Why the Core cannot connect through `proxy` of `profile`, if it cannot:
/// a protocol [`RuntimeSnapshot::compile`] builds no connector for, an option
/// its protocol's connector does not speak, a node without an address, or a
/// `dialer-proxy` that cannot carry it. Hosts list such nodes without
/// offering them.
pub fn proxy_support_issue(profile: &RuntimeProfile, proxy: &ProxyNode) -> Option<String> {
    node_issue(proxy).or_else(|| chain_issue(profile, proxy))
}

/// [`proxy_support_issue`] for the node alone, its chain aside. Keep the
/// protocols in step with `compile`, the only other place that names them.
pub(crate) fn node_issue(proxy: &ProxyNode) -> Option<String> {
    let issue = match proxy.protocol {
        ProxyProtocol::Direct => None,
        ProxyProtocol::Http | ProxyProtocol::Socks5 => ProxyTls::unsupported_option(&proxy.options),
        ProxyProtocol::Shadowsocks => {
            crate::protocols::shadowsocks::unsupported_option(&proxy.options)
        }
        ProxyProtocol::Trojan => crate::protocols::trojan::unsupported_option(&proxy.options),
        ProxyProtocol::Hysteria2 => crate::protocols::hysteria2::unsupported_option(&proxy.options),
        // The server is in the node's config, not its `server` and `port`.
        ProxyProtocol::OpenVpn => {
            return crate::protocols::openvpn::unsupported_option(&proxy.options)
        }
        ProxyProtocol::Reject
        | ProxyProtocol::Vmess
        | ProxyProtocol::Vless
        | ProxyProtocol::Tuic
        | ProxyProtocol::Unknown => Some(format!(
            "{} nodes are not supported yet",
            proxy.protocol.as_str()
        )),
    };
    issue.or_else(|| {
        (proxy.server.is_none() || proxy.port.is_none())
            .then(|| "the node has no server address".to_string())
    })
}

/// The target a route input names, for resolving policy groups before a
/// dial: its domain or else its IP, and its port (443 when it has none).
pub(crate) fn route_target(input: &RouteMatchInput) -> ConnectTarget {
    ConnectTarget {
        host: input
            .host
            .clone()
            .or_else(|| input.destination_ip.map(|ip| ip.to_string()))
            .unwrap_or_default(),
        port: input.destination_port.unwrap_or(443),
    }
}

impl RuntimeSnapshot {
    /// The health probes this snapshot's groups call for, one per node.
    pub(crate) fn probe_plans(&self) -> Vec<OutboundProbePlan> {
        derive_probe_plans(&self.groups, &self.outbounds, &self.node_test_urls)
    }

    pub(crate) fn compile(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
        group_state: GroupStateTable,
    ) -> Self {
        let direct: Arc<dyn OutboundConnector> = Arc::new(DirectConnector);
        let mut outbounds = OutboundTable::from([
            ("DIRECT".into(), Arc::clone(&direct)),
            ("direct".into(), Arc::clone(&direct)),
        ]);

        // The vocabulary point: the only place a protocol is
        // named. Everything downstream of here speaks `dyn OutboundConnector`.
        for proxy in &profile.proxies {
            if matches!(proxy.protocol, ProxyProtocol::OpenVpn) {
                outbounds.insert(
                    proxy.name.clone(),
                    Arc::new(OpenVpnConnector::new(&proxy.options)),
                );
                continue;
            }
            if let (Some(host), Some(port)) = (&proxy.server, proxy.port) {
                let connector: Option<Arc<dyn OutboundConnector>> = match proxy.protocol {
                    ProxyProtocol::Http => Some(Arc::new(HttpProxyConnector {
                        host: host.clone(),
                        port,
                        dialer: Dialer::from_options(&proxy.options),
                        auth: proxy_auth(&proxy.options),
                        tls: ProxyTls::from_node(host, &proxy.options),
                    })),
                    ProxyProtocol::Socks5 => Some(Arc::new(Socks5ProxyConnector {
                        host: host.clone(),
                        port,
                        dialer: Dialer::from_options(&proxy.options),
                        auth: proxy_auth(&proxy.options),
                        tls: ProxyTls::from_node(host, &proxy.options),
                        udp: udp_switch(&proxy.options),
                    })),
                    ProxyProtocol::Hysteria2 => Some(Arc::new(Hysteria2Connector::new(
                        host.clone(),
                        port,
                        &proxy.options,
                    ))),
                    ProxyProtocol::Shadowsocks => Some(Arc::new(ShadowsocksConnector::new(
                        host.clone(),
                        port,
                        &proxy.options,
                    ))),
                    ProxyProtocol::Trojan => Some(Arc::new(TrojanConnector::new(
                        host.clone(),
                        port,
                        &proxy.options,
                    ))),
                    ProxyProtocol::Direct => Some(Arc::clone(&direct)),
                    _ => None,
                };
                if let Some(connector) = connector {
                    outbounds.insert(proxy.name.clone(), connector);
                }
            }
        }

        let rule_engine = Arc::new(RuleEngine::compile(profile));
        let global_outbound = rule_engine.traffic_policy().1.to_owned();
        let outbounds = Arc::new(outbounds);
        let groups = Arc::new(compile_policy_groups(profile));
        let rejecting_groups = Arc::new(groups_reaching_a_reject(&groups));
        let node_test_urls = Arc::new(
            profile
                .proxies
                .iter()
                .filter_map(|proxy| Some((proxy.name.clone(), proxy.test_url()?.to_owned())))
                .collect(),
        );
        let hops = Arc::new(Hops::new(
            outbounds.clone(),
            groups.clone(),
            group_state.clone(),
        ));
        let physical =
            EgressRuntime::with_socket_guard(egress_config, socket_guard).with_hops(&hops);
        let dns = DnsService::new(
            Arc::new(profile.dns.clone()),
            physical.clone(),
            rule_engine.clone(),
            outbounds.clone(),
            groups.clone(),
            group_state,
            profile.traffic_policy_mode,
            global_outbound.clone(),
        );
        Self {
            profile_id: profile.id.clone(),
            traffic_policy_mode: profile.traffic_policy_mode,
            global_outbound,
            rule_engine,
            egress: physical.with_dns_service(dns.clone(), Default::default()),
            capture: capture_config,
            outbounds,
            groups,
            rejecting_groups,
            hops,
            node_test_urls,
            dns,
        }
    }

    pub(crate) fn rebuild_dns(&mut self) {
        self.dns = DnsService::new(
            self.dns.config.clone(),
            self.egress.physical_dns_view(),
            self.rule_engine.clone(),
            self.outbounds.clone(),
            self.groups.clone(),
            self.dns.group_state(),
            self.traffic_policy_mode,
            self.global_outbound.clone(),
        );
        self.egress = self
            .egress
            .with_dns_service(self.dns.clone(), Default::default());
    }

    pub(crate) fn has_outbound(&self, name: &str) -> bool {
        self.outbounds.contains_key(name)
    }

    pub(crate) fn has_group(&self, name: &str) -> bool {
        self.groups.contains_key(name)
    }

    pub(crate) fn policy_group(&self, name: &str) -> Option<&CompiledPolicyGroup> {
        self.groups.get(name)
    }

    /// Which member each group that chooses one itself uses right now, for
    /// a host that reports it (see
    /// [`CorePolicyState::automatic_members`](crate::CorePolicyState)). The
    /// Select groups are the user's own choices, reported from the same
    /// state.
    pub(crate) fn automatic_members(
        &self,
        state: &GroupStateTable,
    ) -> std::collections::BTreeMap<String, String> {
        let now = now_unix();
        self.groups
            .iter()
            .filter(|(_, group)| !matches!(group.kind, PolicyGroupKind::Select))
            .filter_map(|(name, _)| {
                group_member_in_use(&self.groups, &self.outbounds, state, name, now)
                    .map(|member| (name.clone(), member))
            })
            .collect()
    }

    /// Registers a connector outside the profile vocabulary: the injection
    /// point of the protocol-vocabulary gate, where a protocol defined
    /// entirely in a test module rides the unmodified dispatcher end to end.
    #[cfg(test)]
    pub(crate) fn insert_outbound_for_test(
        &mut self,
        name: &str,
        connector: Arc<dyn OutboundConnector>,
    ) {
        Arc::make_mut(&mut self.outbounds).insert(name.to_string(), connector);
        self.hops = Arc::new(Hops::new(
            self.outbounds.clone(),
            self.groups.clone(),
            self.dns.group_state(),
        ));
        self.egress = self.egress.with_hops(&self.hops);
        self.rebuild_dns();
    }
}

/// The groups with a rejecting outbound among their members, or among the
/// members of a group they hold.
fn groups_reaching_a_reject(groups: &HashMap<String, CompiledPolicyGroup>) -> HashSet<String> {
    let mut reaching = HashSet::new();
    loop {
        let found = reaching.len();
        for (name, group) in groups {
            if !reaching.contains(name)
                && group.members.iter().any(|member| {
                    crate::rule_engine::is_reject_outbound(member) || reaching.contains(member)
                })
            {
                reaching.insert(name.clone());
            }
        }
        if reaching.len() == found {
            return reaching;
        }
    }
}

/// A group name resolved to the concrete outbound that will actually be
/// dialed. `name` is the concrete node (`DIRECT` or a proxy name) used for
/// health accounting and stats; `connector` borrows the pinned snapshot.
pub(crate) struct ResolvedOutbound<'a> {
    pub(crate) name: String,
    pub(crate) connector: &'a dyn OutboundConnector,
}

/// Session state that must survive snapshot swaps: fake-IP mappings that
/// clients already hold and the live flow/session tables. Cloning shares
/// the underlying tables.
#[derive(Debug, Clone)]
pub(crate) struct NativeCoreSessionState {
    pub(crate) route_admission: Arc<RwLock<RouteAdmission>>,
    pub(crate) lifetime: CancellationToken,
    pub(crate) fake_dns: FakeDnsStore,
    pub(crate) udp_sessions: crate::udp::UdpSessionTable,
    /// Persistent selector choices and per-outbound passive health. Durable
    /// across snapshot swaps so re-applying a profile neither forgets the
    /// user's selection nor amnesties a node the failure signal just ejected.
    pub(crate) group_state: GroupStateTable,
    /// Ledger of live TCP relay sessions: admission control, kill switch,
    /// connection table, leak audit.
    pub(crate) registry: SessionRegistry,
    /// Sniff-stage counters; the zero-latency gate asserts
    /// `attempted` stays zero when no rule could use a sniffed domain.
    pub(crate) sniff_stats: crate::sniff::SniffStats,
    /// Bytes relayed since the device started, fed by the TCP relays the
    /// registry hands out and by the UDP session table.
    pub(crate) traffic_volume: Arc<crate::telemetry::TrafficVolumeCounter>,
    /// The runtime each capture queue's pump runs on.
    pub(crate) pump_runtimes: crate::packet::PumpRuntimes,
}

impl Default for NativeCoreSessionState {
    fn default() -> Self {
        let traffic_volume = Arc::new(crate::telemetry::TrafficVolumeCounter::default());
        Self {
            route_admission: Arc::default(),
            lifetime: CancellationToken::default(),
            fake_dns: FakeDnsStore::default(),
            udp_sessions: crate::udp::UdpSessionTable::counting_into(Arc::clone(&traffic_volume)),
            group_state: GroupStateTable::default(),
            registry: SessionRegistry::counting_into(Arc::clone(&traffic_volume)),
            sniff_stats: crate::sniff::SniffStats::default(),
            pump_runtimes: crate::packet::PumpRuntimes::default(),
            traffic_volume,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct RouteAdmission {
    pub(crate) epoch: u64,
    pub(crate) cancellation: CancellationToken,
    pub(crate) tasks: TaskTracker,
    pub(crate) retired: Vec<crate::RetirementTicket>,
}

/// A live session's place in the route epoch that admitted it.
///
/// Held by the session's pinned runtime, so it lasts exactly as long as the
/// session's task does, and by the ledger entry the session registered, so
/// the ledger is where a policy change finds it.
#[derive(Debug)]
pub(crate) struct EpochMembership(Mutex<tokio_util::task::task_tracker::TaskTrackerToken>);

impl EpochMembership {
    pub(crate) fn of(tasks: &TaskTracker) -> Arc<Self> {
        Arc::new(Self(Mutex::new(tasks.token())))
    }

    /// Joins `tasks` instead, which the session's own task cannot do for
    /// itself: its place moves while it runs.
    pub(crate) fn move_to(&self, tasks: &TaskTracker) {
        // The new place is taken before the old one is given up, so the
        // epoch being left never looks complete while this session is
        // between the two.
        *self.0.lock().expect("session epoch membership") = tasks.token();
    }
}

impl RouteAdmission {
    pub(crate) fn advance(&mut self) -> crate::RetirementTicket {
        self.cancellation.cancel();
        self.tasks.close();
        let ticket = crate::RetirementTicket::new(self.epoch, self.tasks.clone());
        self.retired.retain(|ticket| !ticket.is_complete());
        self.retired.push(ticket.clone());
        self.epoch = self.epoch.wrapping_add(1);
        self.cancellation = CancellationToken::new();
        self.tasks = TaskTracker::new();
        ticket
    }
}

/// One session's pinned view of the data plane: the snapshot current at pin
/// time plus shared handles to the durable session state. Cloning shares
/// both; a clone held by a spawned task keeps its snapshot alive until the
/// task ends, which is the drain semantic.
#[derive(Debug, Clone)]
pub(crate) struct NativeCoreRuntime {
    snapshot: Arc<RuntimeSnapshot>,
    sessions: NativeCoreSessionState,
    connection_cancellation: CancellationToken,
    tasks: TaskTracker,
    /// Set for one inbound session, whose task holds this runtime: that is
    /// what puts the session in its route epoch's completion ticket. A
    /// runtime pinned for anything else -- a packet pump, a health probe, a
    /// status read -- is in no epoch of its own.
    epoch: Option<Arc<EpochMembership>>,
}

impl NativeCoreRuntime {
    #[cfg(test)]
    pub(crate) fn compile(profile: &RuntimeProfile) -> Self {
        Self::compile_with_egress(profile, NativeCoreEgressConfig::default())
    }

    pub(crate) fn compile_with_egress(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
    ) -> Self {
        Self::compile_with_egress_and_capture(
            profile,
            egress_config,
            NativeCoreCaptureConfig::default(),
        )
    }

    pub(crate) fn compile_with_egress_and_capture(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
    ) -> Self {
        let sessions = NativeCoreSessionState::default();
        Self::pinned(
            Arc::new(RuntimeSnapshot::compile(
                profile,
                egress_config,
                capture_config,
                None,
                sessions.group_state.clone(),
            )),
            sessions,
        )
    }

    pub(crate) fn pinned(snapshot: Arc<RuntimeSnapshot>, sessions: NativeCoreSessionState) -> Self {
        let admission = sessions
            .route_admission
            .read()
            .expect("route admission lock");
        Self::pinned_at(snapshot, sessions.clone(), &admission)
    }

    pub(crate) fn pinned_at(
        snapshot: Arc<RuntimeSnapshot>,
        mut sessions: NativeCoreSessionState,
        admission: &RouteAdmission,
    ) -> Self {
        // Global mode answers names with fake IPs whatever the DNS mode, so
        // its pool is active too.
        let dns = &snapshot.dns.config;
        let fake_ip_mode = dns.enabled && dns.enhanced_mode == crate::dns::config::DnsMode::FakeIp;
        let active_range = (fake_ip_mode
            || snapshot.traffic_policy_mode == TrafficPolicyMode::Global)
            .then_some(dns.fake_ip_range);
        sessions.fake_dns = sessions.fake_dns.with_range(active_range);
        Self {
            snapshot,
            sessions,
            connection_cancellation: admission.cancellation.clone(),
            tasks: admission.tasks.clone(),
            epoch: None,
        }
    }

    /// The same view, as one session's: it takes a place in the route epoch
    /// and holds it for as long as the session's task holds this runtime.
    pub(crate) fn joining_epoch(mut self) -> Self {
        self.epoch = Some(EpochMembership::of(&self.tasks));
        self
    }

    pub(crate) fn connection_cancellation(&self) -> CancellationToken {
        self.connection_cancellation.clone()
    }

    /// This session's place in its route epoch, for the ledger it registers
    /// in to hold.
    pub(crate) fn epoch_membership(&self) -> Option<Arc<EpochMembership>> {
        self.epoch.clone()
    }

    pub(crate) fn with_route_admission<T>(&self, commit: impl FnOnce() -> T) -> Result<T, String> {
        // Route publication takes the write side. Keep this read side only
        // through the synchronous ledger/mailbox commit, never across IO.
        let _admission = self
            .sessions
            .route_admission
            .read()
            .expect("route admission lock");
        if self.connection_cancellation.is_cancelled() {
            return Err("routing changed before session admission".into());
        }
        Ok(commit())
    }

    pub(crate) fn task_tracker(&self) -> &TaskTracker {
        &self.tasks
    }

    /// Routes with only the address the input carries: a rule asking for a
    /// resolved address does not match. Flows resolve first through
    /// [`Self::rule_address`].
    pub(crate) fn route(&self, input: &RouteMatchInput) -> crate::RouteDecision {
        self.route_unresolved(input).0
    }

    /// [`Self::route`], and whether a rule asked for the destination's
    /// address: the packet stage cannot wait on DNS and leaves such a
    /// datagram to the UDP session.
    pub(crate) fn route_unresolved(&self, input: &RouteMatchInput) -> (crate::RouteDecision, bool) {
        let (decision, address_pending) = self.snapshot.rule_engine.route_unresolved(
            input,
            self.snapshot.traffic_policy_mode,
            &self.snapshot.global_outbound,
            &self.udp_acceptance(input),
        );
        (self.settled(decision, input), address_pending)
    }

    /// The decision, with a group that chooses a rejecting outbound right
    /// now replaced by that outbound: the "ad blocking: REJECT or DIRECT"
    /// selector most converted subscriptions carry refuses a flow as a rule
    /// to `REJECT` does, and everything that asks whether a route rejects
    /// asks the decision.
    fn settled(
        &self,
        mut decision: crate::RouteDecision,
        input: &RouteMatchInput,
    ) -> crate::RouteDecision {
        if self.snapshot.rejecting_groups.contains(&decision.outbound) {
            let chosen = resolve_outbound_name(
                &self.snapshot.groups,
                &self.snapshot.outbounds,
                &self.sessions.group_state,
                &decision.outbound,
                &route_target(input),
                now_unix(),
            );
            if let Some(reject) = chosen.filter(|name| crate::rule_engine::is_reject_outbound(name))
            {
                decision.outbound = reject;
            }
        }
        decision
    }

    /// Resolves the input's name when the rules reach an IP rule that may
    /// resolve it before anything else matches; `None` when no rule asks.
    /// The name resolves with the profile's DNS for applications, as an
    /// application's own query would.
    pub(crate) async fn rule_address(&self, input: &RouteMatchInput) -> Option<RuleAddress> {
        let host = input
            .host
            .as_deref()
            .filter(|_| input.destination_ip.is_none())?;
        let RouteStep::NeedsAddress(from_rule) = self.route_step(input, None) else {
            return None;
        };
        let target = ConnectTarget {
            host: host.to_owned(),
            port: input.destination_port.unwrap_or(0),
        };
        let ip = self
            .dns_service()
            .resolve_target(
                &target,
                crate::dns::service::QueryPurpose::Application,
                crate::dns::service::QueryContext::default(),
            )
            .await
            .ok()
            .and_then(|resolved| resolved.ip());
        Some(RuleAddress { from_rule, ip })
    }

    /// Routes with the address [`Self::rule_address`] resolved.
    pub(crate) fn route_with_address(
        &self,
        input: &RouteMatchInput,
        address: Option<RuleAddress>,
    ) -> crate::RouteDecision {
        match self.route_step(input, address) {
            RouteStep::Decided(decision) => decision,
            RouteStep::NeedsAddress(_) => self.route(input),
        }
    }

    /// One routing step: the route, or the rule that needs the address of a
    /// destination known only by name.
    pub(crate) fn route_step(
        &self,
        input: &RouteMatchInput,
        address: Option<RuleAddress>,
    ) -> RouteStep {
        match self.snapshot.rule_engine.route_with_policy(
            input,
            self.snapshot.traffic_policy_mode,
            &self.snapshot.global_outbound,
            &self.udp_acceptance(input),
            address,
        ) {
            RouteStep::Decided(decision) => RouteStep::Decided(self.settled(decision, input)),
            step => step,
        }
    }

    /// Which outbounds a flow may take: a UDP flow only those that carry it.
    fn udp_acceptance(&self, input: &RouteMatchInput) -> impl Fn(&str) -> bool + '_ {
        let udp_target =
            (input.network == Some(TransportNetwork::Udp)).then(|| route_target(input));
        move |outbound| {
            udp_target.as_ref().is_none_or(|target| {
                outbound_takes_udp(
                    &self.snapshot.groups,
                    &self.snapshot.outbounds,
                    &self.sessions.group_state,
                    outbound,
                    target,
                )
            })
        }
    }

    #[cfg(test)]
    pub(crate) fn rule_engine(&self) -> &RuleEngine {
        &self.snapshot.rule_engine
    }

    pub(crate) fn egress(&self) -> &EgressRuntime {
        &self.snapshot.egress
    }

    pub(crate) fn dns_service(&self) -> &Arc<DnsService> {
        &self.snapshot.dns
    }

    pub(crate) fn capture(&self) -> &NativeCoreCaptureConfig {
        &self.snapshot.capture
    }

    /// The mode and global outbound this view routes by.
    pub(crate) fn traffic_policy(&self) -> (TrafficPolicyMode, &str) {
        (
            self.snapshot.traffic_policy_mode,
            &self.snapshot.global_outbound,
        )
    }

    /// Resolves a routed outbound name — a concrete node or a policy group —
    /// to the concrete endpoint to dial right now. Group
    /// resolution consults the durable [`GroupStateTable`], so the answer
    /// reflects live health and the user's selection.
    pub(crate) fn resolve_outbound(
        &self,
        outbound: &str,
        target: &ConnectTarget,
    ) -> Option<ResolvedOutbound<'_>> {
        let name = resolve_outbound_name(
            &self.snapshot.groups,
            &self.snapshot.outbounds,
            &self.sessions.group_state,
            outbound,
            target,
            now_unix(),
        )?;
        let connector = self.snapshot.outbounds.get(&name)?.as_ref();
        Some(ResolvedOutbound { name, connector })
    }

    /// [`Self::resolve_outbound`], with the unix second until which the
    /// answer stands while the group state's version does not move (see
    /// [`resolve_outbound_until`]).
    pub(crate) fn resolve_outbound_until(
        &self,
        outbound: &str,
        target: &ConnectTarget,
    ) -> Option<(ResolvedOutbound<'_>, i64)> {
        let (name, until) = resolve_outbound_until(
            &self.snapshot.groups,
            &self.snapshot.outbounds,
            &self.sessions.group_state,
            outbound,
            target,
            now_unix(),
        )?;
        let connector = self.snapshot.outbounds.get(&name)?.as_ref();
        Some((ResolvedOutbound { name, connector }, until))
    }

    /// Lets the UrlTest groups take in new probe latencies: resolving each
    /// one moves its pick to a node that is now faster by the tolerance, and
    /// only a moved pick advances the group state's version, which is what
    /// sends the flows routed through the group to the new member. Flows do
    /// not resolve their group again while the version stands.
    fn repick_url_test_groups(&self, target: &ConnectTarget) {
        for (name, group) in self.snapshot.groups.iter() {
            if matches!(group.kind, PolicyGroupKind::UrlTest) {
                let _ = self.resolve_outbound(name, target);
            }
        }
    }

    pub(crate) fn group_state(&self) -> &GroupStateTable {
        &self.sessions.group_state
    }

    pub(crate) fn session_registry(&self) -> &SessionRegistry {
        &self.sessions.registry
    }

    pub(crate) fn sniff_stats(&self) -> &crate::sniff::SniffStats {
        &self.sessions.sniff_stats
    }

    /// Whether a route can depend on the flow's process, so a new flow waits
    /// for attribution before it is routed.
    pub(crate) fn routes_by_process(&self) -> bool {
        self.snapshot
            .rule_engine
            .routes_by_process_for(self.snapshot.traffic_policy_mode)
    }

    /// Whether the sniff stage applies to this target at all:
    /// the profile must have a reachable domain rule, the target must be a
    /// bare IP the fake-IP table cannot name, and the port must plausibly
    /// carry a client-first TLS/HTTP flight.
    pub(crate) fn should_sniff(&self, target: &ConnectTarget) -> bool {
        self.snapshot
            .rule_engine
            .wants_sniffed_host_for(self.snapshot.traffic_policy_mode)
            && crate::sniff::is_sniffable_port(target.port)
            && target.ip().is_some()
    }

    pub(crate) fn outbound_table(&self) -> &OutboundTable {
        &self.snapshot.outbounds
    }

    pub(crate) fn fake_dns(&self) -> &FakeDnsStore {
        &self.sessions.fake_dns
    }

    /// The runtime each capture queue's pump runs on.
    pub(crate) fn pump_runtimes(&self) -> &crate::packet::PumpRuntimes {
        &self.sessions.pump_runtimes
    }

    pub(crate) fn udp_sessions(&self) -> &crate::udp::UdpSessionTable {
        &self.sessions.udp_sessions
    }

    pub(crate) fn fake_dns_domain_for_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ip) => self.sessions.fake_dns.lookup_ipv4(ip),
            IpAddr::V6(ip) => self.sessions.fake_dns.lookup_ipv6(ip),
        }
    }

    /// A fake-range IP the store cannot name, for example an answer minted
    /// by an earlier capture session. Fake ranges are virtual, so a
    /// dial to such a target can only black-hole — callers reject the flow.
    pub(crate) fn is_stale_fake_target(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                self.sessions.fake_dns.contains_ipv4(ip)
                    && self.sessions.fake_dns.lookup_ipv4(ip).is_none()
            }
            IpAddr::V6(ip) => {
                self.sessions.fake_dns.contains_ipv6(ip)
                    && self.sessions.fake_dns.lookup_ipv6(ip).is_none()
            }
        }
    }

    /// Whether `ip` sits inside a core-owned fake-IP block, mapped or stale.
    /// ICMP echo requests to these ranges are answered locally (matrix #11)
    /// because they are virtual and ICMP cannot be relayed through the proxy.
    pub(crate) fn is_fake_range_target(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.sessions.fake_dns.contains_ipv4(ip),
            IpAddr::V6(ip) => self.sessions.fake_dns.contains_ipv6(ip),
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve_packet_destination_host(&self, ip: IpAddr) -> String {
        self.fake_dns_domain_for_ip(ip)
            .unwrap_or_else(|| ip.to_string())
    }
}

/// The rule-match input for a TCP dial, built from the dial target: a fake
/// IP has already given way to its domain and is no address of the
/// destination, while a real IP stays beside a sniffed host so IP rules keep
/// matching it. Process metadata is added by the ingress dispatcher.
pub(crate) fn tcp_route_match_input(target: &ConnectTarget, host: Option<&str>) -> RouteMatchInput {
    RouteMatchInput {
        host: host.map(str::to_string).or_else(|| target.host_for_route()),
        destination_ip: target.ip(),
        destination_port: Some(target.port),
        network: Some(crate::rule_engine::TransportNetwork::Tcp),
        ..Default::default()
    }
}

/// Whole-dial safety net: resolve, connect, and protocol
/// handshake together. Inner steps carry tighter budgets for precise errors
/// (the per-connect slices and the 5s DNS query budget); this ceiling exists so
/// no connector step — a proxy that accepts TCP and never answers its
/// handshake, an unbudgeted system resolve — can hold a session in Dialing
/// indefinitely.
#[cfg(test)]
pub(crate) async fn open_outbound_connection(
    runtime: &NativeCoreRuntime,
    target: &ConnectTarget,
    outbound: &str,
    early_data: &[u8],
) -> Result<(BoxedOutboundStream, EgressBinding), TcpFlowFailure> {
    open_outbound_connection_with_budget(
        runtime,
        target,
        outbound,
        early_data,
        OUTBOUND_DIAL_BUDGET,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn open_outbound_connection_with_budget(
    runtime: &NativeCoreRuntime,
    target: &ConnectTarget,
    outbound: &str,
    early_data: &[u8],
    dial_budget: Duration,
) -> Result<(BoxedOutboundStream, EgressBinding), TcpFlowFailure> {
    let resolved = runtime.resolve_outbound(outbound, target).ok_or_else(|| {
        TcpFlowFailure::Message(format!("outbound '{outbound}' is not implemented"))
    })?;
    open_resolved_outbound_connection_with_budget(
        runtime,
        target,
        &resolved,
        early_data,
        dial_budget,
    )
    .await
}

async fn open_resolved_outbound_connection_with_budget(
    runtime: &NativeCoreRuntime,
    target: &ConnectTarget,
    resolved: &ResolvedOutbound<'_>,
    early_data: &[u8],
    dial_budget: Duration,
) -> Result<(BoxedOutboundStream, EgressBinding), TcpFlowFailure> {
    let evidence = target::DialEvidence::default();
    let egress = runtime.egress().with_dns_context(
        crate::dns::service::QueryContext::for_business_outbound(&resolved.name),
    );
    let result = match tokio::time::timeout(
        dial_budget,
        target::connect(
            &egress,
            resolved.connector,
            target,
            early_data,
            tokio::time::Instant::now() + dial_budget,
            &evidence,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(TcpFlowFailure::Budget {
            budget: TcpFlowBudget::Dial,
            duration: dial_budget,
        }),
    };
    // DNS and local policy failures precede the node dial. Only an actual
    // connector attempt contributes passive evidence to that node's health,
    // and only for what it shows: a node that reported the target refused
    // is working, a local refusal says nothing about it, and a dial that ran
    // out its budget stays charged to the node.
    if evidence.attempted() {
        let group_state = runtime.group_state();
        match &result {
            Ok(_) => group_state.record_success(&resolved.name),
            Err(TcpFlowFailure::Outbound { stage, .. }) if stage.charges_node() => {
                group_state.record_failure(&resolved.name, now_unix());
            }
            Err(TcpFlowFailure::Outbound {
                stage: crate::outbound::OutboundStage::Target,
                ..
            }) => group_state.record_success(&resolved.name),
            Err(TcpFlowFailure::Outbound { .. }) => {}
            Err(_) => group_state.record_failure(&resolved.name, now_unix()),
        }
    }
    result
}

/// [`open_outbound_connection`] raced against the session's cancellation
/// leaf: a kill switch, connection cutover, or device close reaps a session
/// mid-dial instead of waiting out the dial budget. Cancellation drops the
/// dial future before the health accounting runs, so an aborted dial
/// charges no failure evidence to the node.
pub(crate) async fn open_outbound_connection_for_session(
    runtime: &NativeCoreRuntime,
    target: &ConnectTarget,
    resolved: &ResolvedOutbound<'_>,
    early_data: &[u8],
    session: &SessionGuard,
) -> Result<BoxedOutboundStream, TcpFlowFailure> {
    let cancel = session.cancellation();
    let (stream, binding) = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(TcpFlowFailure::Cancelled),
        result = open_resolved_outbound_connection_with_budget(
            runtime,
            target,
            resolved,
            early_data,
            OUTBOUND_DIAL_BUDGET,
        ) => result,
    }?;
    session.set_egress(binding);
    Ok(stream)
}

/// The latency of `node` of `profile` while no Core runs: one request for
/// `test_url` through it, as a running Core's probe makes, over a snapshot
/// of the profile's nodes and groups (its rules are not compiled) on the
/// host's physical egress. What it learns of the node's health goes with
/// the snapshot.
pub async fn probe_profile_node(
    mut profile: RuntimeProfile,
    node: &str,
    test_url: &str,
    egress: NativeCoreEgressConfig,
    socket_guard: Option<Arc<dyn EgressSocketGuard>>,
) -> Result<Duration, String> {
    let probe = parse_probe_url(test_url)
        .ok_or_else(|| format!("probe URL '{test_url}' is not supported"))?;
    profile.rules = Default::default();
    profile.rule_sets.clear();
    profile.geodata = Default::default();
    let sessions = NativeCoreSessionState::default();
    let snapshot = RuntimeSnapshot::compile(
        &profile,
        egress,
        NativeCoreCaptureConfig::default(),
        socket_guard,
        sessions.group_state.clone(),
    );
    let runtime = NativeCoreRuntime::pinned(Arc::new(snapshot), sessions);
    probe_outbound_once(&runtime, node, &probe).await
}

/// Runs one active health probe: dial the outbound's own
/// chain to the probe target, perform origin TLS for HTTPS, and validate
/// a complete HTTP response head. Success feeds the EWMA and rise counter;
/// failure and timeout feed the same fall/ejection evidence stream as
/// passive dial failures.
pub(crate) async fn probe_outbound_once(
    runtime: &NativeCoreRuntime,
    outbound: &str,
    probe: &OutboundProbeRequest,
) -> Result<std::time::Duration, String> {
    let resolved = runtime
        .resolve_outbound(outbound, &probe.target)
        .ok_or_else(|| format!("outbound '{outbound}' is not implemented"))?;
    runtime
        .egress()
        .validate_outbound_target(&probe.target, resolved.connector.is_direct())
        .map_err(|reason| TcpFlowFailure::PolicyRejected(reason).to_string())?;

    let started = std::time::Instant::now();
    let evidence = target::DialEvidence::default();
    // The latency counts from the first address the dial had: looking up the
    // node's server is the resolver's time, which later connections take
    // from its cache.
    let clock = crate::egress::LookupClock::default();
    let egress = runtime
        .egress()
        .with_dns_context(crate::dns::service::QueryContext::for_business_outbound(
            &resolved.name,
        ))
        .with_lookup_clock(&clock);
    let attempt = tokio::time::timeout(PROBE_TIMEOUT, async {
        let (stream, _) = target::connect(
            &egress,
            resolved.connector,
            &probe.target,
            &[],
            tokio::time::Instant::now() + PROBE_TIMEOUT,
            &evidence,
        )
        .await
        .map_err(|error| error.to_string())?;
        // The numeric transport target does not change the origin's HTTP
        // Host header or HTTPS certificate/SNI verification name.
        verify_response(stream, probe).await
    })
    .await;

    let outcome = match attempt {
        Ok(Ok(())) => Ok(clock.elapsed_since(started)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(format!(
            "probe of outbound '{}' timed out after {PROBE_TIMEOUT:?}",
            resolved.name
        )),
    };
    if evidence.attempted() {
        match &outcome {
            Ok(latency) => runtime
                .group_state()
                .record_probe_success(&resolved.name, *latency),
            Err(_) => runtime
                .group_state()
                .record_failure(&resolved.name, now_unix()),
        }
        runtime.repick_url_test_groups(&probe.target);
    }
    outcome
}

/// Reusable proxy data-plane runtime facade for SDK users and platform
/// adapters over an owned [`NativeCoreDevice`].
#[derive(Debug, Clone)]
pub struct CoreRuntime {
    device: NativeCoreDevice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreRuntimeConfig {
    pub profile: RuntimeProfile,
    #[serde(default)]
    pub egress: NativeCoreEgressConfig,
    #[serde(default)]
    pub capture: NativeCoreCaptureConfig,
}

impl CoreRuntime {
    pub fn start(config: CoreRuntimeConfig) -> Self {
        Self::start_with_socket_guard(config, None)
    }

    /// Starts the runtime with a physical egress socket guard installed.
    /// The guard is device-durable: every hot-applied snapshot re-attaches
    /// it, so profile changes cannot silently drop egress loop protection.
    pub fn start_with_socket_guard(
        config: CoreRuntimeConfig,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    ) -> Self {
        Self {
            device: NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
                profile: config.profile,
                egress: config.egress,
                egress_socket_guard: socket_guard,
                capture: config.capture,
                flow_scanner: None,
                fake_ip_mappings: None,
            }),
        }
    }

    pub fn from_profile(profile: RuntimeProfile) -> Self {
        Self::start(CoreRuntimeConfig::from_profile(profile))
    }

    pub fn from_device(device: NativeCoreDevice) -> Self {
        Self { device }
    }

    pub fn device(&self) -> &NativeCoreDevice {
        &self.device
    }

    pub fn status(&self) -> NativeCoreDeviceStatus {
        self.device.status()
    }

    /// Replaces configuration and cuts off old connections while preserving
    /// Fake-IP mappings. Invalid or changed packet-link MTU is rejected before
    /// publication; a new Core device is required to change that link contract.
    pub fn apply_config(&self, config: CoreRuntimeConfig) -> Result<(), String> {
        self.device
            .apply_config(&config.profile, config.egress, config.capture)
    }

    /// Hot-swaps the profile while keeping the current egress and capture
    /// configuration, cutting off all old connections.
    pub fn apply_profile(&self, profile: &RuntimeProfile) {
        self.device.apply_profile(profile);
    }

    /// Persists the user's choice for a Select policy group and cuts off
    /// every existing connection. Only new admissions can use the new choice.
    pub fn select_group_member(&self, group: &str, member: &str) -> Result<(), String> {
        self.device.select_group_member(group, member)
    }

    /// Runs one active health probe of `outbound` against `test_url`,
    /// recording latency EWMA / rise / fall evidence. Also the manual
    /// "test latency" entrypoint for hosts.
    pub async fn probe_outbound(
        &self,
        outbound: &str,
        test_url: &str,
    ) -> Result<std::time::Duration, String> {
        self.device.probe_outbound(outbound, test_url).await
    }

    /// Spawns the serial, jittered health-probe scheduler for the groups in
    /// the current (and any later hot-swapped) profile. The task ends when
    /// the runtime shuts down; aborting the handle is also safe. Idempotent
    /// per device: returns `None` while a previously spawned loop is alive.
    pub fn spawn_health_probe_loop(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.device.spawn_health_probe_loop()
    }

    /// Kill switch: terminates every live session relaying through
    /// `outbound` across the TCP relay registry, the UDP session table, and
    /// the packet-bridge session table.
    pub fn kill_sessions_by_outbound(&self, outbound: &str) -> crate::KillSessionsReport {
        self.device.kill_sessions_by_outbound(outbound)
    }

    /// Cancels all existing connections and fences old-generation admission.
    pub fn cutover_sessions(&self) -> crate::ConnectionCutoverReport {
        self.device.cutover_sessions()
    }

    pub async fn cutover_sessions_and_wait(
        &self,
        timeout: Duration,
    ) -> Result<crate::ConnectionCutoverReport, String> {
        self.device.cutover_sessions_and_wait(timeout).await
    }

    /// Live connection table (TCP relay + UDP sessions).
    pub fn connections_snapshot(&self) -> Vec<crate::TrafficConnectionSnapshot> {
        self.device.connections_snapshot()
    }

    /// Stalled TCP relay sessions, longest-stuck first; the attribution
    /// companion to the phase counters in [`Self::state_audit`].
    pub fn stalled_sessions(&self, limit: usize) -> Vec<crate::SessionSnapshot> {
        self.device.stalled_sessions(limit)
    }

    /// Bounded-state audit across every session/cache table; the soak and
    /// churn gates assert these counts drain after load.
    pub fn state_audit(&self) -> crate::CoreStateAudit {
        self.device.state_audit()
    }

    /// Spawns the optional event-loop watchdog heartbeat.
    pub fn spawn_event_loop_watchdog(&self) -> tokio::task::JoinHandle<()> {
        self.device.spawn_event_loop_watchdog()
    }

    pub fn watchdog_stats(&self) -> crate::WatchdogStats {
        self.device.watchdog_stats()
    }

    pub fn shutdown(&self) -> NativeCoreDeviceStatus {
        self.device.close()
    }

    pub async fn resolve_dns_query_payload(
        &self,
        payload: &[u8],
        process_name: Option<String>,
        process_path: Option<String>,
    ) -> Result<Vec<u8>, String> {
        self.device
            .resolve_dns_query_payload(payload, process_name, process_path)
            .await
    }
}

impl CoreRuntimeConfig {
    pub fn from_profile(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            egress: NativeCoreEgressConfig::default(),
            capture: NativeCoreCaptureConfig::default(),
        }
    }

    pub fn with_egress(mut self, egress: NativeCoreEgressConfig) -> Self {
        self.egress = egress;
        self
    }

    pub fn with_capture(mut self, capture: NativeCoreCaptureConfig) -> Self {
        self.capture = capture;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundFuture;
    use crate::profile::{RouteRule, RuleKind};

    #[test]
    fn support_issues_name_what_the_core_cannot_connect() {
        let node = |protocol, options| ProxyNode {
            id: "node".into(),
            name: "node".into(),
            protocol,
            server: Some("proxy.example".into()),
            port: Some(443),
            options,
        };
        let issue = |protocol, options| {
            proxy_support_issue(&RuntimeProfile::new("issues"), &node(protocol, options))
        };
        assert_eq!(
            issue(ProxyProtocol::Trojan, serde_json::json!({"password": "x"})),
            None
        );
        assert_eq!(
            issue(
                ProxyProtocol::Hysteria2,
                serde_json::json!({"password": "x", "dialer-proxy": "DIRECT"})
            ),
            None
        );
        for (protocol, options, named) in [
            (
                ProxyProtocol::Trojan,
                serde_json::json!({"password": "x", "network": "ws"}),
                "ws",
            ),
            (
                ProxyProtocol::Shadowsocks,
                serde_json::json!({"cipher": "aes-256-gcm", "password": "x", "plugin": "obfs"}),
                "obfs",
            ),
            (
                ProxyProtocol::Hysteria2,
                serde_json::json!({"password": "x", "obfs": "salamander"}),
                "obfs",
            ),
            (ProxyProtocol::Vmess, serde_json::json!({}), "vmess"),
        ] {
            let reason = issue(protocol, options).expect("an issue");
            assert!(reason.contains(named), "{reason}");
        }
        let mut addressless = node(ProxyProtocol::Socks5, serde_json::json!({}));
        addressless.port = None;
        assert!(proxy_support_issue(&RuntimeProfile::new("issues"), &addressless).is_some());
    }

    #[test]
    fn a_dialer_proxy_chain_of_nodes_is_judged_whole() {
        let node = |name: &str, protocol, via: Option<&str>| ProxyNode {
            id: name.into(),
            name: name.into(),
            protocol,
            server: Some("proxy.example".into()),
            port: Some(443),
            options: match via {
                Some(via) => serde_json::json!({"password": "x", "dialer-proxy": via}),
                None => serde_json::json!({"password": "x"}),
            },
        };
        let mut profile = RuntimeProfile::new("chains");
        profile.proxies = vec![
            node("exit", ProxyProtocol::Trojan, Some("relay")),
            node("relay", ProxyProtocol::Trojan, Some("entry")),
            node("entry", ProxyProtocol::Trojan, None),
            node("grouped", ProxyProtocol::Trojan, Some("pick")),
            node("plain", ProxyProtocol::Trojan, Some("DIRECT")),
            node("loop-a", ProxyProtocol::Trojan, Some("loop-b")),
            node("loop-b", ProxyProtocol::Trojan, Some("loop-a")),
            node("lost", ProxyProtocol::Trojan, Some("nowhere")),
            node("over-vmess", ProxyProtocol::Trojan, Some("vmess")),
            node("vmess", ProxyProtocol::Vmess, None),
        ];
        profile.groups = vec![crate::profile::PolicyGroup {
            id: "pick".into(),
            name: "pick".into(),
            kind: PolicyGroupKind::Select,
            members: vec!["entry".into()],
            interval_seconds: None,
            test_url: None,
            selected: None,
        }];
        let issue = |name: &str| {
            let proxy = profile.proxies.iter().find(|proxy| proxy.name == name);
            proxy_support_issue(&profile, proxy.expect("node"))
        };
        for usable in ["exit", "relay", "entry", "grouped", "plain"] {
            assert_eq!(issue(usable), None, "{usable}");
        }
        for (name, named) in [
            ("loop-a", "loops back to 'loop-a'"),
            ("lost", "'nowhere'"),
            ("over-vmess", "vmess"),
        ] {
            let reason = issue(name).expect("an issue");
            assert!(reason.contains(named), "{name}: {reason}");
        }
    }

    #[test]
    fn udp_flows_skip_rules_whose_node_has_udp_off_now() {
        let node = |name: &str, protocol, options| ProxyNode {
            id: name.into(),
            name: name.into(),
            protocol,
            server: Some("proxy.example".into()),
            port: Some(443),
            options,
        };
        fn rule<'a>(kind: RuleKind, payload: Option<&'a str>, outbound: &'a str) -> RouteRule<'a> {
            RouteRule {
                kind,
                payload,
                outbound,
                no_resolve: false,
            }
        }
        let ss = |udp| serde_json::json!({"cipher": "aes-128-gcm", "password": "x", "udp": udp});
        let mut profile = RuntimeProfile::new("udp-switch");
        profile.proxies = vec![
            node(
                "no-udp",
                ProxyProtocol::Shadowsocks,
                serde_json::json!({"cipher": "aes-128-gcm", "password": "x"}),
            ),
            node("udp", ProxyProtocol::Shadowsocks, ss(true)),
            node("off", ProxyProtocol::Shadowsocks, ss(false)),
            node(
                "hy2",
                ProxyProtocol::Hysteria2,
                serde_json::json!({"password": "x"}),
            ),
        ];
        profile.groups = vec![crate::profile::PolicyGroup {
            id: "pick".into(),
            name: "Pick".into(),
            kind: crate::profile::PolicyGroupKind::Select,
            members: vec!["no-udp".into(), "udp".into()],
            interval_seconds: None,
            test_url: None,
            selected: Some("no-udp".into()),
        }];
        profile.rules = vec![
            rule(RuleKind::DomainSuffix, Some("game.test"), "Pick"),
            rule(RuleKind::DomainSuffix, Some("game.test"), "off"),
            rule(RuleKind::DomainSuffix, Some("game.test"), "hy2"),
            rule(RuleKind::Match, None, "udp"),
        ]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let route = |host: &str, network| {
            runtime
                .route(&RouteMatchInput {
                    host: Some(host.into()),
                    destination_port: Some(443),
                    network: Some(network),
                    ..Default::default()
                })
                .matched_rule
        };
        // The group's pick and the explicit switch both carry no UDP, while
        // Hysteria2 always does.
        assert_eq!(
            route("game.test", TransportNetwork::Udp).as_deref(),
            Some("DOMAIN-SUFFIX,game.test,hy2")
        );
        assert_eq!(
            route("game.test", TransportNetwork::Tcp).as_deref(),
            Some("DOMAIN-SUFFIX,game.test,Pick")
        );
        assert_eq!(
            route("other.test", TransportNetwork::Udp).as_deref(),
            Some("MATCH,udp")
        );

        runtime.group_state().select("Pick", "udp");
        assert_eq!(
            route("game.test", TransportNetwork::Udp).as_deref(),
            Some("DOMAIN-SUFFIX,game.test,Pick")
        );
    }

    #[tokio::test]
    async fn core_runtime_exposes_dns_entrypoint() {
        let runtime = CoreRuntime::from_profile(blocked_dns_profile());

        let response = runtime
            .resolve_dns_query_payload(&dns_query(0x1234, "blocked.example", 1), None, None)
            .await
            .expect("DNS response is generated");

        assert_eq!(response.get(0..2), Some(&0x1234_u16.to_be_bytes()[..]));
        assert_ne!(response[2] & 0x80, 0);
        assert_eq!(response[3] & 0x0f, 3);
    }

    /// A probe's latency reaches a UrlTest group's pick on the health side:
    /// the pick moves to a node faster by the tolerance and the version
    /// advances, which is what moves the flows routed through the group;
    /// latencies that change no pick leave the version alone.
    #[test]
    fn new_probe_latencies_repick_url_test_groups_on_the_health_side() {
        let mut profile = RuntimeProfile::new("repick");
        profile.proxies = ["A", "B"]
            .into_iter()
            .map(|name| ProxyNode {
                id: format!("node-{name}"),
                name: name.into(),
                protocol: ProxyProtocol::Http,
                server: Some("127.0.0.1".into()),
                port: Some(9),
                options: serde_json::Value::Null,
            })
            .collect();
        profile.groups = vec![crate::profile::PolicyGroup {
            id: "group-auto".into(),
            name: "Auto".into(),
            kind: PolicyGroupKind::UrlTest,
            members: vec!["A".into(), "B".into()],
            interval_seconds: None,
            test_url: None,
            selected: None,
        }];
        let runtime = NativeCoreRuntime::compile(&profile);
        let target = ConnectTarget {
            host: "www.gstatic.com".into(),
            port: 80,
        };
        let state = runtime.group_state();
        state.set_probe_ewma_for_test("A", 50_000);
        state.set_probe_ewma_for_test("B", 200_000);
        assert_eq!(
            runtime
                .resolve_outbound("Auto", &target)
                .map(|resolved| resolved.name),
            Some("A".into())
        );
        let picked = state.version();

        state.set_probe_ewma_for_test("B", 40_000);
        runtime.repick_url_test_groups(&target);
        assert_eq!(
            state.version(),
            picked,
            "within the tolerance the pick stays"
        );

        state.set_probe_ewma_for_test("B", 10_000);
        runtime.repick_url_test_groups(&target);
        let moved = state.version();
        assert_ne!(moved, picked, "the pick moved to B");
        assert_eq!(
            runtime
                .resolve_outbound("Auto", &target)
                .map(|resolved| resolved.name),
            Some("B".into())
        );
        runtime.repick_url_test_groups(&target);
        assert_eq!(state.version(), moved, "nothing changed since");
    }

    fn blocked_dns_profile() -> RuntimeProfile {
        let mut profile = RuntimeProfile::new("core-runtime-dns");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        }]
        .into();
        profile
    }

    fn dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    /// A connector whose dial never resolves: the IO shape of a proxy that
    /// accepts nothing or a handshake wedged past every inner budget.
    #[derive(Debug)]
    struct HangingConnector;

    impl OutboundConnector for HangingConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
            _early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(std::future::pending())
        }
    }

    fn runtime_with_hanging_outbound(name: &str) -> NativeCoreRuntime {
        let mut profile = RuntimeProfile::new("dial-budget");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: name,
            no_resolve: false,
        }]
        .into();
        let mut snapshot = RuntimeSnapshot::compile(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test(name, Arc::new(HangingConnector));
        NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default())
    }

    #[derive(Debug)]
    struct RecordingFailureConnector {
        stage: crate::outbound::OutboundStage,
        direct: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl OutboundConnector for RecordingFailureConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
            _early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let stage = self.stage;
            Box::pin(async move {
                Err(crate::outbound::OutboundError::new(
                    stage,
                    "injected dial failure",
                ))
            })
        }

        fn is_direct(&self) -> bool {
            self.direct
        }
    }

    fn runtime_with_recording_connector(
        direct: bool,
        ipv6_enabled: bool,
    ) -> (NativeCoreRuntime, Arc<std::sync::atomic::AtomicUsize>) {
        runtime_failing_at(
            direct,
            ipv6_enabled,
            crate::outbound::OutboundStage::HopConnect,
        )
    }

    fn runtime_failing_at(
        direct: bool,
        ipv6_enabled: bool,
        stage: crate::outbound::OutboundStage,
    ) -> (NativeCoreRuntime, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut snapshot = RuntimeSnapshot::compile(
            &RuntimeProfile::new("target-policy"),
            NativeCoreEgressConfig {
                ipv6_enabled,
                ..Default::default()
            },
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test(
            "tested",
            Arc::new(RecordingFailureConnector {
                stage,
                direct,
                calls: calls.clone(),
            }),
        );
        (
            NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default()),
            calls,
        )
    }

    #[tokio::test]
    async fn target_policy_rejection_precedes_dial_and_passive_health_accounting() {
        use crate::egress::EgressPolicyRejection::*;
        for (direct, ipv6, host, expected) in [
            (true, false, "fe80::1%test-interface", UnresolvedIpv6Scope),
            (true, true, "fe80::1%test-interface", UnresolvedIpv6Scope),
            (false, false, "fe80::1%7", ScopedTargetRequiresDirect),
            (
                false,
                true,
                "fe80::1%test-interface",
                ScopedTargetRequiresDirect,
            ),
        ] {
            let (runtime, calls) = runtime_with_recording_connector(direct, ipv6);
            let target = ConnectTarget {
                host: host.into(),
                port: 443,
            };
            let error = match open_outbound_connection(&runtime, &target, "tested", &[]).await {
                Ok(_) => panic!("target must be rejected before dial"),
                Err(error) => error,
            };
            assert!(
                matches!(error, TcpFlowFailure::PolicyRejected(actual) if actual == expected),
                "{error}"
            );
            assert!(error.is_expected_close());
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(runtime.group_state().health_snapshot("tested").is_none());
        }
    }

    #[tokio::test]
    async fn active_probe_uses_the_same_target_policy_without_health_penalty() {
        for (direct, ipv6, host) in [
            (true, false, "fe80::1%test-interface"),
            (true, true, "fe80::1%test-interface"),
            (false, true, "fe80::1%7"),
        ] {
            let (runtime, calls) = runtime_with_recording_connector(direct, ipv6);
            let probe = OutboundProbeRequest {
                target: ConnectTarget {
                    host: host.into(),
                    port: 443,
                },
                tls: true,
                http_request: Vec::new(),
            };
            let error = probe_outbound_once(&runtime, "tested", &probe)
                .await
                .unwrap_err();
            assert!(error.starts_with("TCP flow rejected by policy:"), "{error}");
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(runtime.group_state().health_snapshot("tested").is_none());
        }
    }

    /// Without a Core, a node of a stored profile is tested over a snapshot
    /// of its nodes: a request for the test URL through it.
    #[tokio::test]
    async fn a_node_is_probed_without_a_core_through_its_profile() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut profile = RuntimeProfile::new("standalone-probe");
        profile.proxies = vec![ProxyNode {
            id: "node-local".into(),
            name: "Local".into(),
            protocol: ProxyProtocol::Direct,
            server: Some("127.0.0.1".into()),
            port: Some(1),
            options: serde_json::Value::Null,
        }];
        let url = format!("http://127.0.0.1:{}/generate_204", address.port());
        let latency = probe_profile_node(
            profile.clone(),
            "Local",
            &url,
            NativeCoreEgressConfig::default(),
            None,
        )
        .await
        .unwrap();
        assert!(latency < Duration::from_secs(5));
        server.await.unwrap();
        assert!(probe_profile_node(
            profile,
            "Missing",
            &url,
            NativeCoreEgressConfig::default(),
            None
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn ordinary_targets_still_dial_and_real_failures_count_against_health() {
        for (direct, ipv6, host) in [
            (false, false, "example.com"),
            (true, false, "2001:db8::1"),
            (true, false, "fe80::1%7"),
            (true, true, "fe80::1%7"),
            (false, false, "2001:db8::1"),
        ] {
            let (runtime, calls) = runtime_with_recording_connector(direct, ipv6);
            let target = ConnectTarget {
                host: host.into(),
                port: 443,
            };
            let error = match open_outbound_connection(&runtime, &target, "tested", &[]).await {
                Ok(_) => panic!("recording connector always fails"),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    TcpFlowFailure::Outbound {
                        stage: crate::outbound::OutboundStage::HopConnect,
                        ..
                    }
                ),
                "{error}"
            );
            assert!(!error.is_expected_close());
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                runtime
                    .group_state()
                    .health_snapshot("tested")
                    .unwrap()
                    .consecutive_failures,
                1
            );
        }
        let (runtime, calls) = runtime_with_recording_connector(false, false);
        let probe = OutboundProbeRequest {
            target: ConnectTarget {
                host: "example.com".into(),
                port: 443,
            },
            tls: true,
            http_request: Vec::new(),
        };
        assert_eq!(
            probe_outbound_once(&runtime, "tested", &probe)
                .await
                .unwrap_err(),
            "outbound HopConnect: injected dial failure"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            runtime
                .group_state()
                .health_snapshot("tested")
                .unwrap()
                .consecutive_failures,
            1
        );
    }

    /// Passive evidence follows the stage: the node is charged only for its
    /// own failures, a target it reported refused shows it working, and a
    /// local refusal says nothing about it.
    #[tokio::test]
    async fn passive_health_charges_only_node_failures() {
        use crate::outbound::OutboundStage::*;
        for (stage, failures, successes) in [
            (HopAuth, Some(1), Some(0)),
            (HopProtocol, Some(1), Some(0)),
            (Target, Some(0), Some(1)),
            (Local, None, None),
        ] {
            let (runtime, calls) = runtime_failing_at(false, false, stage);
            let target = ConnectTarget {
                host: "192.0.2.1".into(),
                port: 443,
            };
            let error = match open_outbound_connection(&runtime, &target, "tested", &[]).await {
                Ok(_) => panic!("recording connector always fails"),
                Err(error) => error,
            };
            assert!(
                matches!(error, TcpFlowFailure::Outbound { stage: actual, .. } if actual == stage),
                "{error}"
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            let health = runtime.group_state().health_snapshot("tested");
            assert_eq!(
                health.as_ref().map(|health| health.consecutive_failures),
                failures,
                "{stage:?}"
            );
            assert_eq!(
                health.map(|health| health.consecutive_successes),
                successes,
                "{stage:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dial_budget_reaps_a_hung_connector_and_charges_the_node() {
        let runtime = runtime_with_hanging_outbound("hang");
        let target = ConnectTarget {
            // Isolate the connector budget from the separately bounded DNS stage.
            host: "192.0.2.1".into(),
            port: 443,
        };

        let error = match open_outbound_connection(&runtime, &target, "hang", &[]).await {
            Ok(_) => panic!("hung dial must hit the budget"),
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::Dial,
                    ..
                }
            ),
            "{error}"
        );
        let health = runtime
            .group_state()
            .health_snapshot("hang")
            .expect("a budget hit is failure evidence");
        assert_eq!(health.consecutive_failures, 1);
    }

    #[tokio::test]
    async fn cancelled_session_ends_a_mid_dial_connection_without_failure_evidence() {
        let runtime = runtime_with_hanging_outbound("hang");
        let target = ConnectTarget {
            host: "hang.example".into(),
            port: 443,
        };
        let session = runtime
            .session_registry()
            .register("test", None, "hang.example:443".into())
            .expect("register session");
        session.cancellation().cancel();

        let resolved = runtime
            .resolve_outbound("hang", &target)
            .expect("resolve hanging outbound");
        let error =
            match open_outbound_connection_for_session(&runtime, &target, &resolved, &[], &session)
                .await
            {
                Ok(_) => panic!("cancelled dial must end"),
                Err(error) => error,
            };

        assert!(matches!(error, TcpFlowFailure::Cancelled), "{error}");
        assert!(
            runtime.group_state().health_snapshot("hang").is_none(),
            "an aborted dial charges no failure evidence"
        );
    }
}
