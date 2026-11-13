//! One DNS policy/execution boundary for application questions, direct targets,
//! proxy endpoints and resolver bootstrap. Configuration is already typed.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use tokio::time::{timeout_at, Instant};

use super::cache::{DnsCache, QuerySharing};
use super::config::{DnsMode, DnsRoute, DnsTransport, DnsUpstream, RuntimeDnsConfig};
use super::{transport, wire};
use crate::egress::{pending::Pending, EgressRuntime};
use crate::outbound::{BoxedOutboundStream, OutboundDatagramTransport, OutboundTable};
use crate::policy_group::{
    now_unix, outbound_takes_udp, resolve_outbound_name, CompiledPolicyGroup, GroupStateTable,
};
use crate::profile::{PolicyGroupKind, TrafficPolicyMode};
use crate::rule_engine::{RouteMatchInput, RuleEngine, TransportNetwork};
use crate::target::ConnectTarget;

const QUERY_BUDGET: Duration = Duration::from_secs(5);
/// Lookups refreshing answers served past their TTL at once (see
/// `answers.rs`); past it a stale answer serves without one, and a later
/// lookup refreshes it.
const MAX_REFRESHES: usize = 32;

type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;
const SERVER_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum QueryPurpose {
    Application,
    DirectTarget,
    ProxyEndpoint,
    Bootstrap,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct QueryContext {
    ancestors: Arc<Vec<(QueryPurpose, String)>>,
    business_outbound: Option<String>,
}
impl QueryContext {
    pub(crate) fn for_business_outbound(outbound: &str) -> Self {
        Self {
            business_outbound: Some(outbound.into()),
            ..Default::default()
        }
    }

    fn enter(&self, purpose: QueryPurpose, host: &str) -> Result<Self, String> {
        let identity = (purpose, host.to_owned());
        if self.ancestors.len() >= 8 || self.ancestors.contains(&identity) {
            return Err(format!(
                "DNS dependency cycle while resolving {host} ({purpose:?})"
            ));
        }
        let mut ancestors = self.ancestors.as_ref().clone();
        ancestors.push(identity);
        Ok(Self {
            ancestors: Arc::new(ancestors),
            business_outbound: self.business_outbound.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    request: Vec<u8>,
    purpose: QueryPurpose,
    path: String,
}

/// Which of a question's sources a plan asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanSources {
    /// Every source the profile names for the question, the local resolver
    /// among them.
    All,
    /// Only the servers the profile names. The local resolver answered from
    /// the range this configuration hands out, so it is not asked again
    /// (see [`DnsService::fetch_family`]).
    NotLocal,
}

#[derive(Debug, Clone)]
struct PlannedUpstream {
    upstream: DnsUpstream,
    outbound: Option<String>,
    requires_resolution: bool,
}

/// What one source's answer gave: its addresses, whether any were left out
/// because this configuration hands them out, and the answer's TTL.
struct AskedFamily {
    addresses: Vec<IpAddr>,
    dropped: bool,
    ttl: Option<Duration>,
}

/// A query's answer decided, and for one that goes upstream the plan it
/// runs.
pub(crate) struct PreparedApplicationQuery {
    pub(super) action: super::policy::DnsDecisionAction,
    purpose: QueryPurpose,
    upstreams: Vec<PlannedUpstream>,
    context: QueryContext,
}

#[derive(Debug)]
pub(crate) struct DnsService {
    pub(crate) config: Arc<RuntimeDnsConfig>,
    pub(super) physical: EgressRuntime,
    rules: Arc<RuleEngine>,
    outbounds: Arc<OutboundTable>,
    groups: Arc<HashMap<String, CompiledPolicyGroup>>,
    group_state: GroupStateTable,
    mode: TrafficPolicyMode,
    global: String,
    cache: DnsCache<CacheKey>,
    /// Names mapped to fixed addresses, ahead of every lookup.
    hosts: super::hosts::Hosts,
    /// The names fake-IP mode answers with their real addresses.
    fake_ip_filter: super::pattern::PatternTrie<()>,
    /// Decoded answers of [`Self::resolve_family`], ahead of `cache`.
    answers: super::answers::FamilyAnswers,
    /// Lookups refreshing answers served past their TTL.
    refreshes: std::sync::atomic::AtomicUsize,
    pub(super) tls: Arc<rustls::ClientConfig>,
    pub(super) https_tls: Arc<rustls::ClientConfig>,
    /// Connections to stream servers kept for later queries.
    pub(super) connections: super::connections::DnsConnections,
    pub(super) cancel: tokio_util::sync::CancellationToken,
}

impl DnsService {
    pub(crate) fn retire(&self) {
        self.cancel.cancel();
        self.connections.clear();
    }

    /// Forgets every cached answer, since they may name addresses the new
    /// network's resolvers would not give, and closes the connections kept
    /// to servers, which went out on the old one.
    pub(crate) fn network_changed(&self) {
        self.cache.clear();
        self.answers.clear();
        self.connections.clear();
    }
    pub(crate) fn group_state(&self) -> GroupStateTable {
        self.group_state.clone()
    }
    /// What a query would be answered by, described: the plan a real query
    /// runs, with each source it would try written out.
    pub(crate) fn evaluate(
        &self,
        input: &super::policy::DnsQueryInput,
    ) -> super::policy::DnsDecision {
        let prepared = self.prepare_application_query(input);
        let upstreams = prepared
            .upstreams
            .iter()
            .map(|server| super::policy::DnsUpstreamDecision {
                transport: format!("{:?}", server.upstream.transport).to_ascii_lowercase(),
                endpoint: if server.upstream.transport == DnsTransport::System {
                    "system".into()
                } else {
                    format!(
                        "{}{}",
                        ConnectTarget {
                            host: server.upstream.host.clone(),
                            port: server.upstream.port
                        }
                        .authority(),
                        server.upstream.path
                    )
                },
                outbound: server.outbound.clone(),
                requires_resolution: server.requires_resolution,
            })
            .collect();
        super::policy::DnsDecision {
            action: prepared.action,
            upstreams,
        }
    }

    pub(super) fn prepare_application_query(
        &self,
        input: &super::policy::DnsQueryInput,
    ) -> PreparedApplicationQuery {
        use super::policy::{DnsDecisionAction, DnsRecordType};
        let route = RouteMatchInput {
            host: Some(super::resolver::normalize_domain(&input.domain)),
            process_name: input.process_name.clone(),
            process_path: input.process_path.clone(),
            ..Default::default()
        };
        let (business, depends_on_address) =
            self.rules
                .route_unresolved(&route, self.mode, &self.global, &|_| true);
        let domain = route.host.as_deref().unwrap_or_default();
        // DNS has no future application port or destination IP. Classify only
        // a definite DIRECT route; never invent port zero to select a member
        // of a mixed, target-dependent group. Keep the actual routed name so
        // a proxy DNS source uses that group, not an unrelated global group.
        // When an IP rule comes first, the route depends on the address this
        // very answer gives, so it is neither definitely DIRECT nor rejected.
        let context = QueryContext::for_business_outbound(&business.outbound);
        let purpose =
            if !depends_on_address && self.definitely_direct(&business.outbound, &mut Vec::new()) {
                QueryPurpose::DirectTarget
            } else {
                QueryPurpose::Application
            };
        let address = input.query_class == 1
            && matches!(input.record_type, DnsRecordType::A | DnsRecordType::Aaaa);
        let action = if super::resolver::is_localhost_name(domain) {
            // RFC 6761 section 6.3: loopback for address queries, nothing for
            // any other type, and no upstream either way.
            if address && !(input.record_type == DnsRecordType::Aaaa && !self.ipv6_enabled()) {
                DnsDecisionAction::Loopback
            } else {
                DnsDecisionAction::Empty
            }
        } else if !depends_on_address && crate::rule_engine::is_reject_outbound(&business.outbound)
        {
            // The rules reject the name.
            DnsDecisionAction::Block
        } else if input.query_class == 1
            && input.record_type == DnsRecordType::Aaaa
            && !self.ipv6_enabled()
        {
            // IPv6 address queries are off.
            DnsDecisionAction::Empty
        } else if let Some(mapped) = self.answers_from_hosts(domain, input) {
            mapped
        } else if address && self.fake_ip(domain) {
            // Fake-IP mode and its filter, or global mode, where the proxy
            // resolves every name.
            DnsDecisionAction::FakeIp
        } else if input.query_class == 1
            && matches!(
                input.record_type,
                DnsRecordType::Https | DnsRecordType::Svcb
            )
            && self.fake_ip(domain)
        {
            // A name the apps reach through a fake IP binds no service: the
            // upstream's record would hand them the name's real addresses
            // as hints, past the fake IP, and a browser waits for it before
            // it connects (an upstream round trip for every new name).
            DnsDecisionAction::Empty
        } else {
            DnsDecisionAction::Resolve
        };
        let plan = if action == DnsDecisionAction::Resolve {
            self.plan(domain, purpose, &context)
        } else {
            Vec::new()
        };
        // Only strict global mode can leave no source: it resolves only
        // through the proxy, and no DNS source besides the local resolver is
        // configured. A question without one that reaches past the proxy
        // gets no answer, never a direct one.
        let action = if action == DnsDecisionAction::Resolve && plan.is_empty() {
            DnsDecisionAction::Empty
        } else {
            action
        };
        PreparedApplicationQuery {
            action,
            purpose,
            upstreams: plan,
            context,
        }
    }

    fn definitely_direct(&self, name: &str, path: &mut Vec<String>) -> bool {
        if let Some(connector) = self.outbounds.get(name) {
            return connector.is_direct();
        }
        let Some(group) = self.groups.get(name) else {
            return false;
        };
        if path.len() >= crate::policy_group::MAX_GROUP_RESOLVE_DEPTH
            || path.iter().any(|parent| parent == name)
        {
            return false;
        }
        path.push(name.into());
        let direct = match group.kind {
            PolicyGroupKind::Select => self
                .group_state
                .effective_selection(name, group)
                .is_some_and(|member| self.definitely_direct(&member, path)),
            PolicyGroupKind::Fallback | PolicyGroupKind::UrlTest | PolicyGroupKind::LoadBalance => {
                !group.members.is_empty()
                    && group
                        .members
                        .iter()
                        .all(|member| self.definitely_direct(member, path))
            }
            PolicyGroupKind::Relay | PolicyGroupKind::Unknown => false,
        };
        path.pop();
        direct
    }

    pub(crate) fn new(
        config: Arc<RuntimeDnsConfig>,
        physical: EgressRuntime,
        rules: Arc<RuleEngine>,
        outbounds: Arc<OutboundTable>,
        groups: Arc<HashMap<String, CompiledPolicyGroup>>,
        group_state: GroupStateTable,
        mode: TrafficPolicyMode,
        global: String,
    ) -> Arc<Self> {
        let mut fake_ip_filter = super::pattern::PatternTrie::default();
        for pattern in &config.fake_ip_filter {
            fake_ip_filter.insert(pattern, ());
        }
        Arc::new(Self {
            hosts: super::hosts::Hosts::new(&config),
            fake_ip_filter,
            config,
            physical: physical.physical_dns_view(),
            rules,
            outbounds,
            groups,
            group_state,
            mode,
            global,
            cache: DnsCache::default(),
            answers: Default::default(),
            refreshes: Default::default(),
            tls: crate::tls::client_config(false, &[]),
            https_tls: crate::tls::client_config(false, &[b"h2".to_vec(), b"http/1.1".to_vec()]),
            connections: Default::default(),
            cancel: Default::default(),
        })
    }

    /// Global mode through a proxy: every connection leaves through the
    /// global outbound, so business names resolve only past it. A global
    /// outbound that is definitely DIRECT makes it direct mode by another
    /// name.
    pub(crate) fn strict_global(&self) -> bool {
        self.mode == TrafficPolicyMode::Global
            && !self.definitely_direct(&self.global, &mut Vec::new())
    }

    /// Whether an application's address question gets a fake IP: every name
    /// in strict global mode, where the proxy resolves it as the connection
    /// opens, else in fake-IP mode for names outside the filter. `host` is
    /// normalized.
    pub(crate) fn fake_ip(&self, host: &str) -> bool {
        if self.strict_global() {
            return true;
        }
        self.config.enabled
            && self.config.enhanced_mode == DnsMode::FakeIp
            && self.fake_ip_filter.get(host).is_none()
    }

    /// Whether an address inside the fake-IP pool is this configuration's
    /// own, and so no address to dial (see [`Self::ask_family`]): the Core
    /// answers applications out of the pool -- in fake-IP mode, and in
    /// strict global mode, which gives every name an address of its own --
    /// and a capture layer is active, which routes the pool into the tunnel.
    /// Without capture nothing claims the range, and an upstream fake-IP
    /// resolver's address in it is reachable the way that resolver means it.
    fn pool_claimed(&self) -> bool {
        self.physical.capture_active()
            && (self.strict_global()
                || (self.config.enabled && self.config.enhanced_mode == DnsMode::FakeIp))
    }

    pub(crate) fn ipv6_enabled(&self) -> bool {
        self.physical.ipv6_enabled()
    }

    /// The addresses the hosts map `name` to, if they map it.
    pub(crate) fn hosts(&self, name: &str) -> Option<Arc<[IpAddr]>> {
        self.hosts.lookup(name)
    }

    /// How an app's question for a name the hosts map is answered, with
    /// `use-hosts`: its address questions from the mapping, ahead of a fake
    /// IP and of any upstream; a service binding question (HTTPS) with
    /// nothing, since its address hints would lead past the mapping. Other
    /// questions go upstream as for any name.
    fn answers_from_hosts(
        &self,
        domain: &str,
        input: &super::policy::DnsQueryInput,
    ) -> Option<super::policy::DnsDecisionAction> {
        use super::policy::{DnsDecisionAction, DnsRecordType};
        if !self.config.use_hosts || input.query_class != 1 {
            return None;
        }
        match input.record_type {
            // The hosts map the name to its addresses.
            DnsRecordType::A | DnsRecordType::Aaaa => {
                self.hosts(domain).map(|_| DnsDecisionAction::Hosts)
            }
            // A name the hosts map has no service bindings.
            DnsRecordType::Https | DnsRecordType::Svcb => {
                self.hosts(domain).map(|_| DnsDecisionAction::Empty)
            }
            _ => None,
        }
    }

    pub(crate) fn resolve_family<'a>(
        self: &'a Arc<Self>,
        host: &'a str,
        port: u16,
        ipv6: bool,
        purpose: QueryPurpose,
        context: QueryContext,
    ) -> DnsFuture<'a, Vec<SocketAddr>> {
        Box::pin(async move {
            if ipv6 && !self.ipv6_enabled() {
                return Ok(Vec::new());
            }
            // A mapped name has the mapping's addresses of the family, and
            // no server is asked for the other.
            if let Some(addresses) = self.hosts(host) {
                return Ok(addresses
                    .iter()
                    .filter(|address| address.is_ipv6() == ipv6)
                    .map(|address| SocketAddr::new(*address, port))
                    .collect());
            }
            // A nested lookup (a DNS server's own name) keeps the full path
            // and its cycle check.
            let cached = context.ancestors.is_empty().then(|| {
                let name = if host.trim() == host
                    && !host.ends_with('.')
                    && !host.bytes().any(|byte| byte.is_ascii_uppercase())
                {
                    std::borrow::Cow::Borrowed(host)
                } else {
                    std::borrow::Cow::Owned(super::resolver::normalize_domain(host))
                };
                let key_version = self.group_state.version();
                (name, key_version, self.answers.clears())
            });
            let key = |group_version| super::answers::AnswerKey {
                ipv6,
                purpose,
                business_outbound: context.business_outbound.as_deref(),
                group_version,
            };
            let with_port = |addresses: &[IpAddr]| {
                addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect()
            };
            if let Some((name, group_version, _)) = &cached {
                let key = key(*group_version);
                if let Some(addresses) = self.answers.get(name, &key) {
                    return Ok(with_port(&addresses));
                }
                if let Some((addresses, refresh)) = self.answers.stale(name, &key) {
                    if refresh {
                        self.refresh_family(host, ipv6, purpose, &context, name, *group_version);
                    }
                    return Ok(with_port(&addresses));
                }
            }
            self.fetch_family(host, ipv6, purpose, context, cached)
                .await
                .map(|addresses| with_port(&addresses))
        })
    }

    /// Asks for `name`'s answer again in the background, for an answer a
    /// lookup took past its TTL: it serves the lookup while this refreshes it
    /// for the next. Bounded by [`MAX_REFRESHES`], and ends with the service.
    fn refresh_family(
        self: &Arc<Self>,
        host: &str,
        ipv6: bool,
        purpose: QueryPurpose,
        context: &QueryContext,
        name: &str,
        group_version: u64,
    ) {
        use std::sync::atomic::Ordering;
        let failed = move |service: &Self, name: &str, context: &QueryContext| {
            service.answers.refresh_failed(
                name,
                &super::answers::AnswerKey {
                    ipv6,
                    purpose,
                    business_outbound: context.business_outbound.as_deref(),
                    group_version,
                },
            );
        };
        if self.refreshes.fetch_add(1, Ordering::AcqRel) >= MAX_REFRESHES {
            self.refreshes.fetch_sub(1, Ordering::AcqRel);
            failed(self, name, context);
            return;
        }
        let service = Arc::clone(self);
        let (host, name, context) = (host.to_owned(), name.to_owned(), context.clone());
        let clears = self.answers.clears();
        tokio::spawn(async move {
            let cached = Some((
                std::borrow::Cow::Borrowed(name.as_str()),
                group_version,
                clears,
            ));
            let fetch = service.fetch_family(&host, ipv6, purpose, context.clone(), cached);
            let refreshed = tokio::select! {
                biased;
                _ = service.cancel.cancelled() => false,
                fetched = tokio::time::timeout(QUERY_BUDGET, fetch) => matches!(fetched, Ok(Ok(_))),
            };
            if !refreshed {
                failed(&service, &name, &context);
            }
            service.refreshes.fetch_sub(1, Ordering::AcqRel);
        });
    }

    /// Asks for `host`'s addresses of one family and keeps the answer under
    /// `cached`'s name, group version and clear count.
    async fn fetch_family(
        self: &Arc<Self>,
        host: &str,
        ipv6: bool,
        purpose: QueryPurpose,
        context: QueryContext,
        cached: Option<(std::borrow::Cow<'_, str>, u64, u64)>,
    ) -> Result<Arc<[IpAddr]>, String> {
        let key = |group_version| super::answers::AnswerKey {
            ipv6,
            purpose,
            business_outbound: context.business_outbound.as_deref(),
            group_version,
        };
        let query = wire::query(
            host,
            if ipv6 {
                RecordType::AAAA
            } else {
                RecordType::A
            },
        )?;
        let mut answer = self
            .ask_family(&query, host, purpose, &context, PlanSources::All)
            .await?;
        // Another fake-IP resolver on the way -- a router or a host running
        // one -- can answer from the same range this configuration hands
        // out. Its answer stands for the name inside its own tunnel and is
        // no address of the name here: this host routes that range into its
        // own tunnel, where the mapping is not ours and the dial fails. The
        // servers the profile names answer with the name's real address,
        // which is the better answer anyway, the connection then leaving
        // from here instead of through the other proxy.
        if answer.addresses.is_empty() && answer.dropped {
            answer = self
                .ask_family(&query, host, purpose, &context, PlanSources::NotLocal)
                .await
                .map_err(|error| {
                    format!(
                        "the local resolver answers {host} inside the fake-IP pool, and the \
                         profile's own servers did not answer it: {error}"
                    )
                })?;
            if answer.addresses.is_empty() {
                return Err(format!(
                    "every source answers {host} inside the fake-IP pool"
                ));
            }
        }
        let addresses: Arc<[IpAddr]> = Arc::from(answer.addresses);
        if let (Some((name, group_version, clears)), Some(ttl)) = (cached, answer.ttl) {
            if !addresses.is_empty() {
                self.answers.insert(
                    name.into_owned(),
                    &key(group_version),
                    addresses.clone(),
                    ttl,
                    clears,
                );
            }
        }
        Ok(addresses)
    }

    /// One question put to `sources`, with the addresses this configuration
    /// hands out itself left out of the answer.
    async fn ask_family(
        self: &Arc<Self>,
        query: &Message,
        host: &str,
        purpose: QueryPurpose,
        context: &QueryContext,
        sources: PlanSources,
    ) -> Result<AskedFamily, String> {
        let plan = self.plan_sources(host, purpose, context, sources);
        if plan.is_empty() {
            return Err(format!("no DNS source is configured for {host}"));
        }
        let reply = self
            .exchange_with_plan(query.clone(), purpose, context.clone(), plan)
            .await?;
        if reply.response_code != ResponseCode::NoError {
            return Err(format!(
                "DNS resolution for {host} returned {}",
                reply.response_code
            ));
        }
        let answered = wire::addresses(&reply)?;
        let claimed = self.pool_claimed();
        let addresses: Vec<IpAddr> = answered
            .iter()
            .copied()
            .filter(|ip| !claimed || !self.config.fake_ip_range.holds(*ip))
            .collect();
        Ok(AskedFamily {
            dropped: addresses.len() != answered.len(),
            addresses,
            ttl: wire::positive_ttl(&reply),
        })
    }

    pub(crate) fn resolve_target<'a>(
        self: &'a Arc<Self>,
        target: &'a ConnectTarget,
        purpose: QueryPurpose,
        context: QueryContext,
    ) -> DnsFuture<'a, ConnectTarget> {
        Box::pin(async move {
            if target.ip().is_some() {
                return Ok(target.clone());
            }
            let deadline = Instant::now() + QUERY_BUDGET;
            let mut lookups = Pending::new();
            for ipv6 in [false, true] {
                if ipv6 && !self.ipv6_enabled() {
                    continue;
                }
                lookups.push(self.resolve_family(
                    &target.host,
                    target.port,
                    ipv6,
                    purpose,
                    context.clone(),
                ));
            }
            let mut addresses = Vec::new();
            let mut errors = Vec::new();
            while !lookups.is_empty() {
                match timeout_at(deadline, lookups.next()).await {
                    Ok(Some(Ok(batch))) => addresses.extend(batch),
                    Ok(Some(Err(error))) => errors.push(error),
                    _ => break,
                }
            }
            addresses.sort_by_key(SocketAddr::is_ipv6);
            addresses
                .first()
                .map(|address| ConnectTarget {
                    host: address.ip().to_string(),
                    port: target.port,
                })
                .ok_or_else(|| {
                    format!(
                        "no DNS address for {}: {}",
                        target.authority(),
                        errors.join("; ")
                    )
                })
        })
    }

    pub(super) fn exchange_application_query<'a>(
        self: &'a Arc<Self>,
        request: Message,
        prepared: PreparedApplicationQuery,
    ) -> DnsFuture<'a, Message> {
        self.exchange_with_plan(
            request,
            prepared.purpose,
            prepared.context,
            prepared.upstreams,
        )
    }

    fn exchange_with_plan<'a>(
        self: &'a Arc<Self>,
        mut request: Message,
        purpose: QueryPurpose,
        context: QueryContext,
        plan: Vec<PlannedUpstream>,
    ) -> DnsFuture<'a, Message> {
        Box::pin(async move {
            wire::validate_request(&request)?;
            let question = request.queries.first().ok_or("DNS query has no question")?;
            if question.query_class() == hickory_proto::rr::DNSClass::IN
                && question.query_type() == RecordType::AAAA
                && !self.ipv6_enabled()
            {
                return Ok(wire::response(&request, ResponseCode::NoError));
            }
            let host = question
                .name()
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            // Bootstrap is constrained to numeric, physical upstreams and
            // cannot acquire another proxy-resolution dependency.
            let sharing = if context.ancestors.is_empty() || purpose == QueryPurpose::Bootstrap {
                QuerySharing::Shared
            } else {
                QuerySharing::Independent
            };
            let context = context.enter(purpose, &host)?;
            let id = request.id;
            request.metadata.id = rand::random();
            let deadline = Instant::now() + QUERY_BUDGET;
            let reply = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err("DNS service generation retired".into()),
                result = self.exchange_plan(request, plan, purpose, context, sharing, deadline) => result,
            }?;
            Ok({
                let mut reply = reply;
                reply.metadata.id = id;
                reply
            })
        })
    }

    /// The servers configured for `host`'s questions of `purpose`: none when
    /// DNS is off or the list is omitted, which leaves the system resolver.
    fn configured_sources(&self, host: &str, purpose: QueryPurpose) -> &[DnsUpstream] {
        if !self.config.enabled {
            return &[];
        }
        match purpose {
            QueryPurpose::Bootstrap => &self.config.bootstrap_nameservers,
            // Node bootstrap is independent of business DNS and its policies.
            // An omitted node source list uses direct system DNS.
            QueryPurpose::ProxyEndpoint => &self.config.proxy_nameservers,
            QueryPurpose::DirectTarget if !self.config.direct_nameservers.is_empty() => {
                &self.config.direct_nameservers
            }
            QueryPurpose::Application | QueryPurpose::DirectTarget => self
                .config
                .policies
                .iter()
                .find(|rule| rule.pattern.matches(host))
                .map_or(&self.config.nameservers, |policy| &policy.nameservers),
        }
    }

    /// Whether only the local resolver answers `host`'s business questions:
    /// DNS is off, or every server configured for the name is `system`.
    /// Strict global mode asks no local resolver, so it leaves such a name to
    /// the proxy.
    pub(crate) fn only_system_answers(&self, host: &str) -> bool {
        self.configured_sources(host, QueryPurpose::Application)
            .iter()
            .all(|server| server.transport == DnsTransport::System)
    }

    fn plan(
        &self,
        host: &str,
        purpose: QueryPurpose,
        context: &QueryContext,
    ) -> Vec<PlannedUpstream> {
        self.plan_sources(host, purpose, context, PlanSources::All)
    }

    fn plan_sources(
        &self,
        host: &str,
        purpose: QueryPurpose,
        context: &QueryContext,
        sources: PlanSources,
    ) -> Vec<PlannedUpstream> {
        let chosen = match sources {
            PlanSources::All => self.configured_sources(host, purpose).to_vec(),
            // A question whose own servers are the local resolver -- a
            // node's address, by default -- asks the business ones instead;
            // a bootstrap question has nowhere else to go, its servers
            // being numeric and physical by definition.
            PlanSources::NotLocal => {
                let named = |list: &[DnsUpstream]| -> Vec<DnsUpstream> {
                    list.iter()
                        .filter(|server| server.transport != DnsTransport::System)
                        .cloned()
                        .collect()
                };
                let own = named(self.configured_sources(host, purpose));
                if own.is_empty() && purpose != QueryPurpose::Bootstrap {
                    named(self.configured_sources(host, QueryPurpose::Application))
                } else {
                    own
                }
            }
        };
        let chosen = if purpose == QueryPurpose::Application && self.strict_global() {
            // Strict global mode sends business questions only through the
            // proxy: the local resolvers drop out, and every other source
            // takes the global outbound instead of its own route.
            chosen
                .into_iter()
                .filter(|server| server.transport != DnsTransport::System)
                .map(|server| DnsUpstream {
                    route: Some(DnsRoute::Proxy),
                    ..server
                })
                .collect()
        } else if chosen.is_empty() && sources == PlanSources::All {
            vec![DnsUpstream {
                route: Some(DnsRoute::Direct),
                ..DnsUpstream::system()
            }]
        } else {
            chosen
        };
        let physical_servers = self.physical.dns_servers();
        let mut expanded = Vec::new();
        for server in chosen {
            if server.transport == DnsTransport::System && !physical_servers.is_empty() {
                for address in &physical_servers {
                    expanded.push(DnsUpstream {
                        transport: DnsTransport::Udp,
                        host: address.ip().to_string(),
                        port: address.port(),
                        path: String::new(),
                        server_name: None,
                        route: server.route.clone(),
                    });
                }
            } else {
                expanded.push(server);
            }
        }
        expanded
            .into_iter()
            .map(|upstream| {
                let route = self.effective_route(&upstream, purpose);
                let requires_resolution = upstream.transport != DnsTransport::System
                    && upstream.host.parse::<IpAddr>().is_err();
                let outbound = if requires_resolution && route == DnsRoute::Rules {
                    None
                } else {
                    // A missing/unsuitable proxy only fails this source when
                    // executed. Planning must not prevent a later fallback.
                    self.select_outbound(&upstream, purpose, upstream.host.parse().ok(), context)
                        .ok()
                };
                PlannedUpstream {
                    upstream,
                    outbound,
                    requires_resolution,
                }
            })
            .collect()
    }

    /// An application's question reaches its resolver as the rules route the
    /// resolver's address. The address of a target that goes DIRECT is asked
    /// over DIRECT: the connection leaves from this network, and a resolver
    /// answers for where the question comes from (a CDN picks its nearest
    /// servers), so asking through a proxy gives addresses near the proxy and
    /// hides nothing the DIRECT connection itself does not show. Nodes and
    /// resolvers' own names go DIRECT too, as a proxy cannot depend on itself.
    fn effective_route(&self, upstream: &DnsUpstream, purpose: QueryPurpose) -> DnsRoute {
        upstream.route.clone().unwrap_or_else(|| {
            if self.config.enabled && purpose == QueryPurpose::Application {
                DnsRoute::Rules
            } else {
                DnsRoute::Direct
            }
        })
    }

    fn select_outbound(
        &self,
        upstream: &DnsUpstream,
        purpose: QueryPurpose,
        resolved_ip: Option<IpAddr>,
        context: &QueryContext,
    ) -> Result<String, String> {
        let target = ConnectTarget {
            host: upstream.host.clone(),
            port: upstream.port,
        };
        let route = self.effective_route(upstream, purpose);
        let selected = match &route {
            DnsRoute::Direct => "DIRECT".to_owned(),
            DnsRoute::NamedOutbound(name) => name.clone(),
            DnsRoute::Proxy => {
                if purpose == QueryPurpose::DirectTarget {
                    return Err(
                        "DNS proxy source is not applicable to a DIRECT business target".into(),
                    );
                }
                context
                    .business_outbound
                    .as_ref()
                    .unwrap_or(&self.global)
                    .clone()
            }
            DnsRoute::Rules => {
                self.rules
                    .route_unresolved(
                        &RouteMatchInput {
                            host: target.ip().is_none().then(|| target.host.clone()),
                            destination_ip: resolved_ip.or_else(|| target.ip()),
                            destination_port: Some(target.port),
                            network: Some(if upstream.transport == DnsTransport::Udp {
                                TransportNetwork::Udp
                            } else {
                                TransportNetwork::Tcp
                            }),
                            ..Default::default()
                        },
                        self.mode,
                        &self.global,
                        &|outbound| {
                            upstream.transport != DnsTransport::Udp
                                || outbound_takes_udp(
                                    &self.groups,
                                    &self.outbounds,
                                    &self.group_state,
                                    outbound,
                                    &target,
                                )
                        },
                    )
                    .0
                    .outbound
            }
        };
        let outbound = resolve_outbound_name(
            &self.groups,
            &self.outbounds,
            &self.group_state,
            &selected,
            &target,
            now_unix(),
        )
        .ok_or_else(|| format!("DNS outbound '{selected}' is unavailable"))?;
        let connector = self
            .outbounds
            .get(&outbound)
            .ok_or("DNS outbound disappeared")?;
        if route == DnsRoute::Proxy && connector.is_direct() {
            return Err("DNS proxy source has no selected proxy outbound".into());
        }
        let supports_transport = if upstream.transport == DnsTransport::Udp {
            connector.supports_udp()
        } else {
            connector.supports_tcp()
        };
        if !supports_transport {
            return Err(format!(
                "DNS outbound '{outbound}' does not support {:?}",
                upstream.transport
            ));
        }
        Ok(outbound)
    }

    async fn exchange_plan(
        self: &Arc<Self>,
        request: Message,
        plan: Vec<PlannedUpstream>,
        purpose: QueryPurpose,
        context: QueryContext,
        sharing: QuerySharing,
        deadline: Instant,
    ) -> Result<Message, String> {
        let count = plan.len();
        let mut failure = None;
        for (index, server) in plan.into_iter().enumerate() {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                break;
            }
            // Reserve a share of the remaining query budget for every later
            // source. No later source starts until this one has failed.
            let sources_left = u32::try_from(count - index).unwrap_or(u32::MAX);
            let attempt_deadline = now + (remaining / sources_left).min(SERVER_BUDGET);
            let result = timeout_at(
                attempt_deadline,
                self.exchange_upstream(
                    &request,
                    &server,
                    purpose,
                    context.clone(),
                    sharing,
                    attempt_deadline,
                ),
            )
            .await
            .map_err(|_| "DNS upstream attempt timed out".to_string())
            .and_then(|result| result);
            match result {
                Ok(reply)
                    if !matches!(
                        reply.response_code,
                        ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
                    ) =>
                {
                    return Ok(reply)
                }
                Ok(reply) => failure = Some(Ok(reply)),
                Err(error) => {
                    if failure.as_ref().is_none_or(|result| result.is_err()) {
                        failure = Some(Err(error));
                    }
                }
            }
        }
        failure.unwrap_or_else(|| Err("DNS query timed out after 5s".into()))
    }

    async fn exchange_upstream(
        self: &Arc<Self>,
        request: &Message,
        server: &PlannedUpstream,
        purpose: QueryPurpose,
        context: QueryContext,
        sharing: QuerySharing,
        deadline: Instant,
    ) -> Result<Message, String> {
        if purpose == QueryPurpose::Bootstrap
            && (self.effective_route(&server.upstream, purpose) != DnsRoute::Direct
                || (server.upstream.transport != DnsTransport::System
                    && server.upstream.host.parse::<IpAddr>().is_err()))
        {
            return Err("DNS bootstrap requires a numeric, direct upstream".into());
        }
        // Reject inapplicable sources before resolving their own endpoint.
        // Only RULES needs the bootstrap result to choose its carrier.
        let outbound = if server.requires_resolution
            && self.effective_route(&server.upstream, purpose) == DnsRoute::Rules
        {
            None
        } else {
            Some(self.select_outbound(
                &server.upstream,
                purpose,
                server.upstream.host.parse().ok(),
                &context,
            )?)
        };
        let endpoint = ConnectTarget {
            host: server.upstream.host.clone(),
            port: server.upstream.port,
        };
        let endpoint = if server.requires_resolution {
            self.resolve_target(&endpoint, QueryPurpose::Bootstrap, context.clone())
                .await?
        } else {
            endpoint
        };
        let outbound = match outbound {
            Some(outbound) => outbound,
            None => self.select_outbound(&server.upstream, purpose, endpoint.ip(), &context)?,
        };
        let mut canonical = request.clone();
        canonical.metadata.id = 0;
        let key = CacheKey {
            request: wire::encode(&canonical)?,
            purpose,
            path: format!("{:?}/{}/{outbound}", server.upstream, endpoint.authority()),
        };
        self.cache
            .resolve(
                key,
                request.id,
                deadline,
                sharing,
                self.exchange_prepared(request, &server.upstream, &outbound, &endpoint, context),
            )
            .await
    }

    async fn exchange_prepared(
        self: &Arc<Self>,
        request: &Message,
        upstream: &DnsUpstream,
        outbound: &str,
        endpoint: &ConnectTarget,
        context: QueryContext,
    ) -> Result<Message, String> {
        if upstream.transport == DnsTransport::System {
            if !outbound.eq_ignore_ascii_case("direct") {
                return Err("routing system DNS requires a physical DNS server snapshot".into());
            }
            let question = request.queries.first().ok_or("missing DNS question")?;
            if question.query_class() != hickory_proto::rr::DNSClass::IN {
                return Ok(wire::response(request, ResponseCode::NotImp));
            }
            if !matches!(question.query_type(), RecordType::A | RecordType::AAAA) {
                return Ok(wire::response(request, ResponseCode::NotImp));
            }
            let mut reply = wire::response(request, ResponseCode::NoError);
            let host = question.name().to_utf8();
            let addresses = self
                .physical
                .lookup_host_record(&host, 0, question.query_type() == RecordType::AAAA)
                .await?;
            for address in addresses {
                reply.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    match address.ip() {
                        IpAddr::V4(ip) => RData::A(A(ip)),
                        IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
                    },
                ));
            }
            return Ok(reply);
        }
        transport::exchange(self, request, upstream, outbound, endpoint, context).await
    }

    pub(super) async fn connect_stream(
        self: &Arc<Self>,
        outbound: &str,
        endpoint: &ConnectTarget,
        context: QueryContext,
    ) -> Result<BoxedOutboundStream, String> {
        if outbound.eq_ignore_ascii_case("direct") {
            self.physical
                .validate_outbound_target(endpoint, true)
                .map_err(|error| error.to_string())?;
            let address = endpoint
                .authority()
                .parse::<SocketAddr>()
                .map_err(|_| "DNS endpoint must be numeric")?;
            return self
                .physical
                .connect_tcp_endpoint(address, QUERY_BUDGET)
                .await
                .map(|(stream, _)| Box::new(stream) as BoxedOutboundStream)
                .map_err(|error| error.to_string());
        }
        let connector = self
            .outbounds
            .get(outbound)
            .ok_or("DNS outbound disappeared")?;
        if !connector.supports_tcp() {
            return Err("DNS upstream requires a TCP-capable outbound".into());
        }
        connector
            .connect_stream(
                &self.physical.with_dns_service(self.clone(), context),
                endpoint,
                &[],
            )
            .await
            .map_err(|error| error.to_string())
    }

    pub(super) async fn connect_datagram(
        self: &Arc<Self>,
        outbound: &str,
        endpoint: &ConnectTarget,
        context: QueryContext,
    ) -> Result<OutboundDatagramTransport, String> {
        let connector = self
            .outbounds
            .get(outbound)
            .ok_or("DNS outbound disappeared")?;
        if !connector.supports_udp() {
            return Err("DNS UDP upstream requires a UDP-capable outbound".into());
        }
        connector
            .connect_datagram(
                &self.physical.with_dns_service(self.clone(), context),
                endpoint,
            )
            .await
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests;
