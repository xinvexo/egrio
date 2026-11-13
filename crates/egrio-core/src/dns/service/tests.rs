use super::*;
use crate::dns::config::DnsNameServerPolicy;
use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::outbound::{OutboundError, OutboundFuture};
use crate::profile::{
    ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile, TrafficPolicyMode,
};
use crate::runtime::NativeCoreRuntime;
use crate::NativeCoreEgressConfig;
use hickory_proto::rr::rdata::TXT;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

/// A question as the service puts it: planned for its purpose, then
/// exchanged. The Core's own address lookups go through `ask_family`, which
/// also leaves out the addresses the configuration hands out; the tests
/// below are about the sources themselves, so they stop at the reply.
async fn exchange(
    dns: &Arc<DnsService>,
    request: Message,
    purpose: QueryPurpose,
    context: QueryContext,
) -> Result<Message, String> {
    let host = crate::dns::resolver::normalize_domain(
        &request.query().expect("a question").name().to_utf8(),
    );
    let plan = dns.plan(&host, purpose, &context);
    dns.exchange_with_plan(request, purpose, context, plan)
        .await
}

async fn resolve_udp_target(
    core: &NativeCoreRuntime,
    target: &ConnectTarget,
) -> Result<ConnectTarget, String> {
    let cancel = core.connection_cancellation();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("DNS resolution cancelled by policy change".into()),
        result = core.dns_service().resolve_target(target, QueryPurpose::Application, Default::default()) => result,
    }
}

struct Stub {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn udp_dns(ip: &str) -> Stub {
    udp_dns_reply(Some(ip), ResponseCode::NoError, Duration::ZERO).await
}

async fn udp_dns_reply(ip: Option<&str>, code: ResponseCode, delay: Duration) -> Stub {
    let ip = ip.map(|ip| ip.parse::<IpAddr>().unwrap());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let queries = count.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            queries.fetch_add(1, Ordering::SeqCst);
            let request = wire::decode(&bytes[..len]).unwrap();
            tokio::time::sleep(delay).await;
            let mut reply = wire::response(&request, code);
            let query = request.query().unwrap();
            let data = match (query.query_type(), ip) {
                (RecordType::A, Some(IpAddr::V4(ip))) => Some(RData::A(A(ip))),
                (RecordType::AAAA, Some(IpAddr::V6(ip))) => Some(RData::AAAA(AAAA(ip))),
                (RecordType::TXT, _) => {
                    Some(RData::TXT(TXT::new(vec!["complete TXT reply".into()])))
                }
                _ => None,
            };
            if let Some(data) = data {
                reply.add_answer(Record::from_rdata(query.name().clone(), 30, data));
            }
            socket
                .send_to(&wire::encode(&reply).unwrap(), peer)
                .await
                .unwrap();
        }
    });
    Stub {
        address,
        count,
        task,
    }
}
fn upstream(address: SocketAddr, transport: DnsTransport) -> DnsUpstream {
    DnsUpstream {
        transport,
        host: address.ip().to_string(),
        port: address.port(),
        path: String::new(),
        server_name: None,
        route: None,
    }
}

async fn tcp_dns(ip: &str) -> Stub {
    let ip: std::net::Ipv4Addr = ip.parse().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let queries = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            queries.fetch_add(1, Ordering::SeqCst);
            let request = wire::decode(&bytes).unwrap();
            let mut reply = wire::response(&request, ResponseCode::NoError);
            reply.add_answer(Record::from_rdata(
                request.query().unwrap().name().clone(),
                30,
                RData::A(A(ip)),
            ));
            let bytes = wire::encode(&reply).unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
    });
    Stub {
        address,
        count,
        task,
    }
}

fn proxy_node(name: &str, address: SocketAddr, protocol: ProxyProtocol) -> ProxyNode {
    ProxyNode {
        id: name.into(),
        name: name.into(),
        protocol,
        server: Some(address.ip().to_string()),
        port: Some(address.port()),
        options: serde_json::json!({}),
    }
}
fn profile(server: DnsUpstream) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("DNS service tests");
    profile.dns.enabled = true;
    profile.dns.nameservers = vec![server];
    profile.rules = [match_rule("DIRECT")].into();
    profile
}
/// The one rule the profile of these tests has: everything to `outbound`.
fn match_rule(outbound: &str) -> RouteRule<'_> {
    RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound,
        no_resolve: false,
    }
}
fn runtime(profile: &RuntimeProfile) -> NativeCoreRuntime {
    NativeCoreRuntime::compile_with_egress(
        profile,
        NativeCoreEgressConfig {
            ipv6_enabled: false,
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn actual_upstream_plan_separates_application_direct_node_and_bootstrap_queries() {
    let default = udp_dns("192.0.2.1").await;
    let direct = udp_dns("192.0.2.2").await;
    let node = udp_dns("192.0.2.3").await;
    let bootstrap = udp_dns("192.0.2.4").await;
    let policy = udp_dns("192.0.2.5").await;
    let mut profile = profile(upstream(default.address, DnsTransport::Udp));
    profile.dns.direct_nameservers = vec![upstream(direct.address, DnsTransport::Udp)];
    profile.dns.proxy_nameservers = vec![upstream(node.address, DnsTransport::Udp)];
    profile.dns.bootstrap_nameservers = vec![upstream(bootstrap.address, DnsTransport::Udp)];
    profile.dns.policies = vec![DnsNameServerPolicy {
        pattern: "+.policy.test".parse().unwrap(),
        nameservers: vec![upstream(policy.address, DnsTransport::Udp)],
    }];
    let core = runtime(&profile);
    for (purpose, host, ip) in [
        (QueryPurpose::Application, "normal.test", "192.0.2.1"),
        (QueryPurpose::DirectTarget, "normal.test", "192.0.2.2"),
        (QueryPurpose::DirectTarget, "a.policy.test", "192.0.2.2"),
        (QueryPurpose::ProxyEndpoint, "normal.test", "192.0.2.3"),
        (QueryPurpose::ProxyEndpoint, "a.policy.test", "192.0.2.3"),
        (QueryPurpose::Bootstrap, "normal.test", "192.0.2.4"),
        (QueryPurpose::Bootstrap, "a.policy.test", "192.0.2.4"),
        (QueryPurpose::Application, "a.policy.test", "192.0.2.5"),
    ] {
        let result = core
            .dns_service()
            .resolve_target(
                &ConnectTarget {
                    host: host.into(),
                    port: 3478,
                },
                purpose,
                Default::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.host, ip);
        assert_eq!(result.port, 3478);
    }
}

#[tokio::test]
async fn unconfigured_dns_uses_physical_snapshot_and_forwards_txt_records() {
    let dns = udp_dns("192.0.2.1").await;
    let profile = RuntimeProfile::new("system DNS");
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec![dns.address],
            ..Default::default()
        },
    );
    assert!(!core.dns_service().fake_ip("business.test"));
    let query = wire::query("business.test", RecordType::TXT).unwrap();
    let reply = crate::dns::resolver::resolve_dns_query_payload(
        &core,
        &wire::encode(&query).unwrap(),
        None,
        None,
    )
    .await
    .unwrap();
    let reply = wire::decode(&reply).unwrap();
    assert!(matches!(reply.answers()[0].data(), RData::TXT(_)));
    assert_eq!(reply.id(), query.id());
    assert_eq!(dns.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn application_preview_and_wire_execution_follow_the_selected_direct_connector() {
    let system = udp_dns("192.0.2.10").await;
    let business = tcp_dns("192.0.2.20").await;
    let proxy = socks_forwarder().await;
    let mut source = upstream(business.address, DnsTransport::Tcp);
    source.route = Some(DnsRoute::Proxy);
    let mut profile = profile(source);
    profile.dns.nameservers.push(DnsUpstream {
        route: Some(DnsRoute::Direct),
        ..DnsUpstream::system()
    });
    profile.global_outbound = Some("DIRECT".into());
    profile
        .proxies
        .push(proxy_node("proxy", proxy.address, ProxyProtocol::Socks5));
    profile.groups.push(crate::PolicyGroup {
        id: "selected".into(),
        name: "selected".into(),
        kind: crate::PolicyGroupKind::Select,
        members: vec!["DIRECT".into(), "proxy".into()],
        interval_seconds: None,
        test_url: None,
        selected: Some("DIRECT".into()),
    });
    profile.rules = [match_rule("selected")].into();
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec![system.address],
            ..Default::default()
        },
    );
    for (selected, expected) in [("DIRECT", "192.0.2.10"), ("proxy", "192.0.2.20")] {
        core.group_state().select("selected", selected);
        let preview = core.dns_service().evaluate(&crate::DnsQueryInput {
            query_class: 1,
            domain: "same-business.test".into(),
            record_type: crate::DnsRecordType::A,
            process_name: None,
            process_path: None,
        });
        assert_eq!(preview.upstreams.len(), 2);
        assert_eq!(preview.upstreams[0].endpoint, business.address.to_string());
        assert_eq!(
            preview.upstreams[0].outbound.as_deref(),
            (selected == "proxy").then_some("proxy")
        );
        assert_eq!(preview.upstreams[1].endpoint, system.address.to_string());
        let query = wire::query("same-business.test", RecordType::A).unwrap();
        let response = crate::dns::resolver::resolve_dns_query_payload(
            &core,
            &wire::encode(&query).unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            wire::addresses(&wire::decode(&response).unwrap()).unwrap(),
            vec![expected.parse::<IpAddr>().unwrap()]
        );
    }
    assert_eq!(system.count.load(Ordering::SeqCst), 1);
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn direct_targets_preserve_configured_sources_domain_policy_and_direct_overrides() {
    let system = udp_dns("192.0.2.10").await;
    let business = udp_dns("192.0.2.20").await;
    let policy = udp_dns("192.0.2.30").await;
    let direct = udp_dns("192.0.2.40").await;
    for explicit_direct in [false, true] {
        let mut profile = profile(upstream(business.address, DnsTransport::Udp));
        profile.dns.policies.push(DnsNameServerPolicy {
            pattern: "exception.test".parse().unwrap(),
            nameservers: vec![upstream(policy.address, DnsTransport::Udp)],
        });
        if explicit_direct {
            profile.dns.direct_nameservers = vec![upstream(direct.address, DnsTransport::Udp)];
        }
        let core = NativeCoreRuntime::compile_with_egress(
            &profile,
            NativeCoreEgressConfig {
                dns_servers: vec![system.address],
                ..Default::default()
            },
        );
        for host in ["exception.test", "ordinary.test"] {
            let expected = if host == "exception.test" && !explicit_direct {
                "192.0.2.30"
            } else if explicit_direct {
                "192.0.2.40"
            } else {
                "192.0.2.20"
            };
            let query = wire::query(host, RecordType::A).unwrap();
            let response = crate::dns::resolver::resolve_dns_query_payload(
                &core,
                &wire::encode(&query).unwrap(),
                None,
                None,
            )
            .await
            .unwrap();
            assert_eq!(
                wire::addresses(&wire::decode(&response).unwrap()).unwrap(),
                vec![expected.parse::<IpAddr>().unwrap()]
            );
            let target = core
                .dns_service()
                .resolve_target(
                    &ConnectTarget {
                        host: host.into(),
                        port: 443,
                    },
                    QueryPurpose::DirectTarget,
                    Default::default(),
                )
                .await
                .unwrap();
            assert_eq!(target.host, expected);
        }
    }
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(system.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_direct_target_with_only_proxy_source_does_not_invent_system_fallback() {
    let system = udp_dns("192.0.2.10").await;
    let business = tcp_dns("192.0.2.20").await;
    let proxy = socks_forwarder().await;
    let mut source = upstream(business.address, DnsTransport::Tcp);
    source.route = Some(DnsRoute::Proxy);
    source.host = "unneeded-resolver.invalid".into();
    let mut profile = profile(source);
    profile.global_outbound = Some("proxy".into());
    profile
        .proxies
        .push(proxy_node("proxy", proxy.address, ProxyProtocol::Socks5));
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec![system.address],
            ..Default::default()
        },
    );
    let query = wire::query("direct.test", RecordType::A).unwrap();
    let response = crate::dns::resolver::resolve_dns_query_payload(
        &core,
        &wire::encode(&query).unwrap(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        wire::decode(&response).unwrap().response_code(),
        ResponseCode::ServFail
    );
    assert_eq!(system.count.load(Ordering::SeqCst), 0);
    assert_eq!(business.count.load(Ordering::SeqCst), 0);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn proxy_source_preserves_the_explicit_business_outbound_through_query_context() {
    let business = tcp_dns("192.0.2.20").await;
    let selected = socks_forwarder().await;
    let unrelated = socks_forwarder().await;
    let mut source = upstream(business.address, DnsTransport::Tcp);
    source.route = Some(DnsRoute::Proxy);
    let mut profile = profile(source);
    profile.global_outbound = Some("unrelated".into());
    profile.proxies = vec![
        proxy_node("selected", selected.address, ProxyProtocol::Socks5),
        proxy_node("unrelated", unrelated.address, ProxyProtocol::Socks5),
    ];
    let core = runtime(&profile);
    let resolved = core
        .dns_service()
        .resolve_target(
            &ConnectTarget {
                host: "business.test".into(),
                port: 443,
            },
            QueryPurpose::Application,
            QueryContext::for_business_outbound("selected"),
        )
        .await
        .unwrap();
    assert_eq!(resolved.host, "192.0.2.20");
    assert_eq!(selected.count.load(Ordering::SeqCst), 1);
    assert_eq!(unrelated.count.load(Ordering::SeqCst), 0);
}

#[test]
fn bare_dns_only_classifies_groups_that_are_definitely_direct() {
    let mut source = upstream("192.0.2.53:53".parse().unwrap(), DnsTransport::Tcp);
    source.route = Some(DnsRoute::Proxy);
    let mut profile = profile(source);
    profile.proxies.push(proxy_node(
        "proxy",
        "192.0.2.2:1080".parse().unwrap(),
        ProxyProtocol::Socks5,
    ));
    for (name, kind, members, selected) in [
        (
            "mixed",
            crate::PolicyGroupKind::LoadBalance,
            vec!["DIRECT", "proxy"],
            None,
        ),
        (
            "all-direct",
            crate::PolicyGroupKind::LoadBalance,
            vec!["DIRECT"],
            None,
        ),
        (
            "selected",
            crate::PolicyGroupKind::Select,
            vec!["DIRECT", "mixed"],
            Some("DIRECT"),
        ),
    ] {
        profile.groups.push(crate::PolicyGroup {
            id: name.into(),
            name: name.into(),
            kind,
            members: members.into_iter().map(str::to_owned).collect(),
            interval_seconds: None,
            test_url: None,
            selected: selected.map(str::to_owned),
        });
    }
    for (routed, expected) in [
        ("DIRECT", QueryPurpose::DirectTarget),
        ("all-direct", QueryPurpose::DirectTarget),
        ("selected", QueryPurpose::DirectTarget),
        ("mixed", QueryPurpose::Application),
    ] {
        profile.rules = [match_rule(routed)].into();
        let core = runtime(&profile);
        let prepared = core
            .dns_service()
            .prepare_application_query(&crate::DnsQueryInput {
                query_class: 1,
                domain: "business.test".into(),
                record_type: crate::DnsRecordType::A,
                process_name: None,
                process_path: None,
            });
        assert_eq!(prepared.purpose, expected);
        assert_eq!(prepared.context.business_outbound.as_deref(), Some(routed));
    }
}

/// An IP rule ahead of the rule a name would match leaves the answer's
/// route open: the answer is what the rule reads. It is neither
/// definitely DIRECT nor rejected.
#[test]
fn bare_dns_neither_rejects_nor_directs_a_name_an_ip_rule_awaits() {
    use crate::dns::policy::DnsDecisionAction;
    let mut profile = profile(upstream(
        "192.0.2.53:53".parse().unwrap(),
        DnsTransport::Udp,
    ));
    profile.geodata.geoip = Some(vec![crate::geodata::GeoIpContent {
        code: "CN".into(),
        cidrs: ["1.0.1.0/24"].into_iter().collect(),
        inverse: false,
    }]);
    let rule = |kind, payload, outbound, no_resolve| crate::RouteRule {
        kind,
        payload,
        outbound,
        no_resolve,
    };
    for (no_resolve, purpose, action) in [
        (false, QueryPurpose::Application, DnsDecisionAction::Resolve),
        (true, QueryPurpose::DirectTarget, DnsDecisionAction::Resolve),
    ] {
        profile.rules = vec![
            rule(crate::RuleKind::GeoIp, Some("CN"), "REJECT", no_resolve),
            rule(crate::RuleKind::DomainSuffix, Some("test"), "DIRECT", false),
        ]
        .into();
        let core = runtime(&profile);
        let prepared = core
            .dns_service()
            .prepare_application_query(&crate::DnsQueryInput {
                query_class: 1,
                domain: "business.test".into(),
                record_type: crate::DnsRecordType::A,
                process_name: None,
                process_path: None,
            });
        assert_eq!(prepared.purpose, purpose, "no_resolve={no_resolve}");
        assert_eq!(prepared.action, action);
    }
    profile.rules = vec![
        rule(crate::RuleKind::GeoIp, Some("CN"), "DIRECT", false),
        rule(crate::RuleKind::Match, None, "REJECT", false),
    ]
    .into();
    let prepared =
        runtime(&profile)
            .dns_service()
            .prepare_application_query(&crate::DnsQueryInput {
                query_class: 1,
                domain: "business.test".into(),
                record_type: crate::DnsRecordType::A,
                process_name: None,
                process_path: None,
            });
    assert_eq!(
        prepared.action,
        DnsDecisionAction::Resolve,
        "a name whose address may be in CN is not rejected before it resolves"
    );
}

#[tokio::test]
async fn implicit_system_source_is_direct_even_with_proxy_rules() {
    let system = udp_dns("192.0.2.19").await;
    let proxy = socks_forwarder().await;
    let mut profile = profile(DnsUpstream::system());
    profile.dns.nameservers.clear();
    profile.rules = [match_rule("proxy")].into();
    profile
        .proxies
        .push(proxy_node("proxy", proxy.address, ProxyProtocol::Socks5));
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec![system.address],
            ..Default::default()
        },
    );
    let result = resolve_udp_target(
        &core,
        &ConnectTarget {
            host: "default.test".into(),
            port: 443,
        },
    )
    .await
    .unwrap();
    assert_eq!(result.host, "192.0.2.19");
    assert_eq!(system.count.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_direct_target_reaches_its_resolver_directly_whatever_the_rules_say() {
    let business = tcp_dns("192.0.2.30").await;
    let proxy = socks_forwarder().await;
    let mut profile = profile(upstream(business.address, DnsTransport::Tcp));
    profile.rules = [match_rule("proxy")].into();
    profile
        .proxies
        .push(proxy_node("proxy", proxy.address, ProxyProtocol::Socks5));
    let core = runtime(&profile);
    let target = |host: &str| ConnectTarget {
        host: host.into(),
        port: 443,
    };

    // The rules send the resolver's address through the proxy, but a target
    // that dials DIRECT is resolved over DIRECT, as its connection will be.
    let resolved = core
        .dns_service()
        .resolve_target(
            &target("direct.test"),
            QueryPurpose::DirectTarget,
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(resolved.host, "192.0.2.30");
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 0);

    // An application's question still follows the rules.
    core.dns_service()
        .resolve_target(
            &target("application.test"),
            QueryPurpose::Application,
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(business.count.load(Ordering::SeqCst), 2);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn node_default_system_source_is_independent_of_routed_business_dns_and_policy() {
    let system = udp_dns("127.0.0.1").await;
    let policy = udp_dns("192.0.2.250").await;
    let proxy = socks_forwarder().await;
    let business = tcp_dns("192.0.2.9").await;
    let mut profile = profile(upstream(business.address, DnsTransport::Tcp));
    profile.rules = [match_rule("proxy")].into();
    let mut node = proxy_node("proxy", proxy.address, ProxyProtocol::Socks5);
    node.server = Some("node.policy.test".into());
    profile.proxies.push(node);
    profile.dns.policies.push(DnsNameServerPolicy {
        pattern: "node.policy.test".parse().unwrap(),
        nameservers: vec![upstream(policy.address, DnsTransport::Udp)],
    });
    assert!(profile.dns.proxy_nameservers.is_empty());
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec![system.address],
            ..Default::default()
        },
    );
    let result = resolve_udp_target(
        &core,
        &ConnectTarget {
            host: "business.test".into(),
            port: 443,
        },
    )
    .await
    .unwrap();
    assert_eq!(result.host, "192.0.2.9");
    assert_eq!(system.count.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 1);
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(policy.count.load(Ordering::SeqCst), 0);
    let standalone = runtime(&profile);
    let plan = standalone.dns_service().plan(
        "node.policy.test",
        QueryPurpose::ProxyEndpoint,
        &Default::default(),
    );
    assert_eq!(plan[0].upstream.transport, DnsTransport::System);
    assert_eq!(plan[0].outbound.as_deref(), Some("DIRECT"));
}

/// A TUN that is active, with the resolvers of the network before it took
/// over: while it is, the fake-IP pool is routed into the tunnel.
#[derive(Debug)]
struct ActiveTun {
    resolvers: Vec<SocketAddr>,
}

impl crate::egress::EgressSocketGuard for ActiveTun {
    fn protect_socket(
        &self,
        _: crate::egress::EgressSocketDescriptor,
        _: crate::egress::EgressSocketContext,
    ) -> Result<crate::egress::EgressBinding, String> {
        Ok(crate::egress::EgressBinding::unbound())
    }

    fn capture_overlay(&self) -> Option<Arc<crate::egress::CaptureEgressOverlay>> {
        Some(Arc::new(crate::egress::CaptureEgressOverlay {
            dns_servers: self.resolvers.clone(),
            ipv6_enabled: false,
        }))
    }
}

/// A Core whose TUN is active, with `resolvers` as the network's own.
fn captured_core(profile: &RuntimeProfile, resolvers: Vec<SocketAddr>) -> crate::NativeCoreDevice {
    crate::NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
        profile: profile.clone(),
        egress: NativeCoreEgressConfig {
            ipv6_enabled: false,
            ..Default::default()
        },
        egress_socket_guard: Some(Arc::new(ActiveTun { resolvers })),
        capture: Default::default(),
        flow_scanner: None,
        fake_ip_mappings: None,
    })
}

/// A router or host on the way can run a fake-IP proxy of its own and
/// answer from the same range this configuration hands out. While a TUN of
/// ours routes that range into its own tunnel, such an answer is no address
/// of the name here, so the servers the profile names are asked instead.
#[tokio::test]
async fn an_answer_inside_the_pool_sends_the_question_to_the_profiles_servers() {
    let local = udp_dns("198.18.255.234").await;
    let business = udp_dns("192.0.2.9").await;
    let mut profile = profile(upstream(business.address, DnsTransport::Udp));
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    assert!(
        profile.dns.proxy_nameservers.is_empty(),
        "a node's address goes to the local resolver by default"
    );
    let node = ConnectTarget {
        host: "node.test".into(),
        port: 443,
    };
    let core = captured_core(&profile, vec![local.address]);
    let resolved = core
        .pinned_runtime()
        .dns_service()
        .resolve_target(&node, QueryPurpose::ProxyEndpoint, Default::default())
        .await
        .unwrap();
    assert_eq!(resolved.host, "192.0.2.9");
    assert_eq!(
        local.count.load(Ordering::SeqCst),
        1,
        "the local resolver is still asked first"
    );
    assert_eq!(business.count.load(Ordering::SeqCst), 1);

    // The range is only this configuration's while it hands addresses out
    // of it. Without fake-IP mode the same answer is the name's address,
    // and nothing else is asked.
    let plain_local = udp_dns("198.18.255.234").await;
    let plain_business = udp_dns("192.0.2.9").await;
    let mut plain = profile.clone();
    plain.dns.enhanced_mode = DnsMode::RedirHost;
    plain.dns.nameservers = vec![upstream(plain_business.address, DnsTransport::Udp)];
    let core = captured_core(&plain, vec![plain_local.address]);
    let resolved = core
        .pinned_runtime()
        .dns_service()
        .resolve_target(&node, QueryPurpose::ProxyEndpoint, Default::default())
        .await
        .unwrap();
    assert_eq!(resolved.host, "198.18.255.234");
    assert_eq!(plain_local.count.load(Ordering::SeqCst), 1);
    assert_eq!(plain_business.count.load(Ordering::SeqCst), 0);

    // Nor is the range claimed while no capture layer routes it anywhere:
    // the upstream resolver's address in it is then reachable the way that
    // resolver means it, through the proxy that handed it out.
    let open_local = udp_dns("198.18.255.234").await;
    let open_business = udp_dns("192.0.2.9").await;
    let mut open = profile.clone();
    open.dns.nameservers = vec![upstream(open_business.address, DnsTransport::Udp)];
    let core = NativeCoreRuntime::compile_with_egress(
        &open,
        NativeCoreEgressConfig {
            dns_servers: vec![open_local.address],
            ipv6_enabled: false,
            ..Default::default()
        },
    );
    let resolved = core
        .dns_service()
        .resolve_target(&node, QueryPurpose::ProxyEndpoint, Default::default())
        .await
        .unwrap();
    assert_eq!(resolved.host, "198.18.255.234");
    assert_eq!(open_business.count.load(Ordering::SeqCst), 0);
}

/// With no server but the local one, an answer inside the pool leaves the
/// name without an address, and the error says why.
#[tokio::test]
async fn with_only_the_local_resolver_an_answer_inside_the_pool_is_no_address() {
    let local = udp_dns("198.18.255.234").await;
    let mut profile = RuntimeProfile::new("pool collision");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    assert!(profile.dns.nameservers.is_empty());
    let core = captured_core(&profile, vec![local.address]);
    let error = core
        .pinned_runtime()
        .dns_service()
        .resolve_target(
            &ConnectTarget {
                host: "node.test".into(),
                port: 443,
            },
            QueryPurpose::ProxyEndpoint,
            Default::default(),
        )
        .await
        .unwrap_err();
    assert!(error.contains("inside the fake-IP pool"), "{error}");
}

#[tokio::test]
async fn node_doh_uses_direct_bootstrap_without_business_dns_or_policy_recursion() {
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let bootstrap = udp_dns("127.0.0.1").await;
    let unrelated = udp_dns("192.0.2.250").await;
    let business = tcp_dns("192.0.2.9").await;
    let proxy = socks_forwarder().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["resolver.test".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into(),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut node_dns = upstream(address, DnsTransport::Https);
    node_dns.host = "resolver.test".into();
    node_dns.path = "/dns-query".into();
    let mut profile = profile(upstream(business.address, DnsTransport::Tcp));
    profile.rules = [match_rule("proxy")].into();
    let mut node = proxy_node("proxy", proxy.address, ProxyProtocol::Socks5);
    node.server = Some("node.test".into());
    profile.proxies.push(node);
    profile.dns.bootstrap_nameservers = vec![upstream(bootstrap.address, DnsTransport::Udp)];
    profile.dns.proxy_nameservers = vec![node_dns];
    profile.dns.direct_nameservers = vec![upstream(unrelated.address, DnsTransport::Udp)];
    for host in ["resolver.test", "node.test"] {
        profile.dns.policies.push(DnsNameServerPolicy {
            pattern: host.parse().unwrap(),
            nameservers: vec![upstream(unrelated.address, DnsTransport::Udp)],
        });
    }
    let core = runtime(&profile);
    let source = core.dns_service();
    let mut dns = DnsService::new(
        source.config.clone(),
        source.physical.clone(),
        source.rules.clone(),
        source.outbounds.clone(),
        source.groups.clone(),
        source.group_state.clone(),
        source.mode,
        source.global.clone(),
    );
    client_config.alpn_protocols = dns.https_tls.alpn_protocols.clone();
    Arc::get_mut(&mut dns).unwrap().https_tls = Arc::new(client_config);
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(socket)
            .await
            .unwrap();
        let handler = service_fn(move |request: http::Request<hyper::body::Incoming>| {
            let count = count.clone();
            async move {
                assert_eq!(request.uri().path(), "/dns-query");
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                let query = wire::decode(&bytes).unwrap();
                assert_eq!(query.query().unwrap().name().to_utf8(), "node.test.");
                count.fetch_add(1, Ordering::SeqCst);
                let mut reply = wire::response(&query, ResponseCode::NoError);
                reply.add_answer(Record::from_rdata(
                    query.query().unwrap().name().clone(),
                    30,
                    RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                ));
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .body(Full::new(bytes::Bytes::from(wire::encode(&reply).unwrap())))
                        .unwrap(),
                )
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), handler)
            .await;
    });
    let reply = exchange(
        &dns,
        wire::query("business.test", RecordType::A).unwrap(),
        QueryPurpose::Application,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        wire::addresses(&reply).unwrap(),
        ["192.0.2.9".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(bootstrap.count.load(Ordering::SeqCst), 1);
    assert_eq!(queries.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.count.load(Ordering::SeqCst), 1);
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(unrelated.count.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_pending_earlier_source_never_starts_a_later_source() {
    let first = udp_dns_reply(
        Some("192.0.2.1"),
        ResponseCode::NoError,
        Duration::from_millis(600),
    )
    .await;
    let second = udp_dns("192.0.2.2").await;
    let mut profile = profile(upstream(first.address, DnsTransport::Udp));
    profile
        .dns
        .nameservers
        .push(upstream(second.address, DnsTransport::Udp));
    let core = runtime(&profile);
    let pending = tokio::spawn(async move {
        resolve_udp_target(
            &core,
            &ConnectTarget {
                host: "ordered.test".into(),
                port: 443,
            },
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while first.count.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(
        second.count.load(Ordering::SeqCst),
        0,
        "a slower first source must not cause speculative fallback"
    );
    assert_eq!(pending.await.unwrap().unwrap().host, "192.0.2.1");
    assert_eq!(second.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retryable_dns_failures_advance_but_valid_negative_answers_stop() {
    for code in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::NotImp,
        ResponseCode::NXDomain,
        ResponseCode::NoError,
    ] {
        let first = udp_dns_reply(None, code, Duration::ZERO).await;
        let second = udp_dns("192.0.2.2").await;
        let mut profile = profile(upstream(first.address, DnsTransport::Udp));
        profile
            .dns
            .nameservers
            .push(upstream(second.address, DnsTransport::Udp));
        let core = runtime(&profile);
        let reply = exchange(
            core.dns_service(),
            wire::query("outcome.test", RecordType::A).unwrap(),
            QueryPurpose::Application,
            Default::default(),
        )
        .await
        .unwrap();
        let fallback = matches!(
            code,
            ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
        );
        assert_eq!(first.count.load(Ordering::SeqCst), 1);
        assert_eq!(second.count.load(Ordering::SeqCst), usize::from(fallback));
        if fallback {
            assert_eq!(
                wire::addresses(&reply).unwrap(),
                vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
            );
        } else {
            assert_eq!(reply.response_code(), code);
            assert!(reply.answers().is_empty());
        }
    }
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let good = udp_dns("192.0.2.2").await;
    let mut profile = profile(upstream(address, DnsTransport::Tcp));
    profile
        .dns
        .nameservers
        .push(upstream(good.address, DnsTransport::Udp));
    assert_eq!(
        resolve_udp_target(
            &runtime(&profile),
            &ConnectTarget {
                host: "transport-error.test".into(),
                port: 443
            }
        )
        .await
        .unwrap()
        .host,
        "192.0.2.2"
    );
}

#[tokio::test]
async fn unavailable_or_incapable_proxy_source_does_not_dial_direct_and_can_fall_back() {
    let forbidden = udp_dns("192.0.2.250").await;
    let good = udp_dns("192.0.2.2").await;
    let proxy = socks_forwarder().await;
    for selection in ["DIRECT", "missing", "http-only"] {
        let mut source = upstream(forbidden.address, DnsTransport::Udp);
        source.route = Some(DnsRoute::Proxy);
        let mut profile = profile(source);
        profile.global_outbound = Some(selection.into());
        profile
            .proxies
            .push(proxy_node("http-only", proxy.address, ProxyProtocol::Http));
        profile
            .dns
            .nameservers
            .push(upstream(good.address, DnsTransport::Udp));
        let core = runtime(&profile);
        assert_eq!(
            core.dns_service()
                .plan(
                    "fallback.test",
                    QueryPurpose::Application,
                    &Default::default()
                )
                .len(),
            2
        );
        assert_eq!(
            resolve_udp_target(
                &core,
                &ConnectTarget {
                    host: "fallback.test".into(),
                    port: 443
                }
            )
            .await
            .unwrap()
            .host,
            "192.0.2.2"
        );
    }
    let mut source = upstream(forbidden.address, DnsTransport::Udp);
    source.route = Some(DnsRoute::NamedOutbound("missing".into()));
    let mut profile = profile(source);
    profile
        .dns
        .nameservers
        .push(upstream(good.address, DnsTransport::Udp));
    assert_eq!(
        resolve_udp_target(
            &runtime(&profile),
            &ConnectTarget {
                host: "missing.test".into(),
                port: 443
            }
        )
        .await
        .unwrap()
        .host,
        "192.0.2.2"
    );
    assert_eq!(
        forbidden.count.load(Ordering::SeqCst),
        0,
        "an unavailable proxy cannot silently become DIRECT"
    );
    assert_eq!(
        proxy.count.load(Ordering::SeqCst),
        0,
        "incompatible transports fail before opening the proxy"
    );
    assert_eq!(good.count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn proxy_source_tracks_global_group_selection_and_direct_selection_falls_back() {
    let proxy_a = socks_forwarder().await;
    let proxy_b = socks_forwarder().await;
    let business = tcp_dns("192.0.2.9").await;
    let fallback = udp_dns("192.0.2.19").await;
    let mut source = upstream(business.address, DnsTransport::Tcp);
    source.route = Some(DnsRoute::Proxy);
    let mut profile = profile(source);
    profile
        .dns
        .nameservers
        .push(upstream(fallback.address, DnsTransport::Udp));
    profile.global_outbound = Some("selected".into());
    profile.proxies = vec![
        proxy_node("A", proxy_a.address, ProxyProtocol::Socks5),
        proxy_node("B", proxy_b.address, ProxyProtocol::Socks5),
    ];
    profile.groups.push(crate::PolicyGroup {
        id: "selected".into(),
        name: "selected".into(),
        kind: crate::PolicyGroupKind::Select,
        members: vec!["A".into(), "B".into(), "DIRECT".into()],
        interval_seconds: None,
        test_url: None,
        selected: Some("A".into()),
    });
    let core = runtime(&profile);
    for selected in ["A", "B", "DIRECT"] {
        core.group_state().select("selected", selected);
        let result = resolve_udp_target(
            &core,
            &ConnectTarget {
                host: "group.test".into(),
                port: 443,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result.host,
            if selected == "DIRECT" {
                "192.0.2.19"
            } else {
                "192.0.2.9"
            }
        );
    }
    assert_eq!(proxy_a.count.load(Ordering::SeqCst), 1);
    assert_eq!(proxy_b.count.load(Ordering::SeqCst), 1);
    assert_eq!(business.count.load(Ordering::SeqCst), 2);
    assert_eq!(fallback.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn explicit_fake_mode_applies_to_direct_and_filter_is_the_only_real_address_exception() {
    let dns = udp_dns("192.0.2.1").await;
    let mut profile = profile(upstream(dns.address, DnsTransport::Udp));
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    profile.dns.fake_ip_filter = vec!["real.test".parse().unwrap()];
    let core = runtime(&profile);
    for (host, fake) in [
        ("stun.l.google.com", true),
        ("normal.test", true),
        ("real.test", false),
    ] {
        let query = wire::query(host, RecordType::A).unwrap();
        let reply = crate::dns::resolver::resolve_dns_query_payload(
            &core,
            &wire::encode(&query).unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
        let ips = wire::addresses(&wire::decode(&reply).unwrap()).unwrap();
        assert_eq!(
            matches!(ips[0], IpAddr::V4(ip) if matches!(ip.octets(), [198,18|19,_,_])),
            fake
        );
    }
    assert_eq!(dns.count.load(Ordering::SeqCst), 1);
}

/// In fake-IP mode a name the apps reach through a fake IP has no HTTPS or
/// SVCB record: the question is answered empty at once, without asking the
/// upstream, whose record would carry the name's real addresses as hints. A
/// name the filter leaves real is asked for as before.
#[tokio::test]
async fn fake_names_bind_no_service_and_ask_no_upstream_for_it() {
    let dns = udp_dns("192.0.2.1").await;
    let mut profile = profile(upstream(dns.address, DnsTransport::Udp));
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    profile.dns.fake_ip_filter = vec!["real.test".parse().unwrap()];
    let core = runtime(&profile);
    for (host, record, asked) in [
        ("fake.test", RecordType::HTTPS, 0),
        ("fake.test", RecordType::SVCB, 0),
        ("real.test", RecordType::HTTPS, 1),
    ] {
        let query = wire::query(host, record).unwrap();
        let reply = crate::dns::resolver::resolve_dns_query_payload(
            &core,
            &wire::encode(&query).unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
        let reply = wire::decode(&reply).unwrap();
        assert_eq!(
            reply.response_code(),
            ResponseCode::NoError,
            "{host} {record}"
        );
        if asked == 0 {
            assert!(reply.answers().is_empty(), "{host} {record}");
        }
        assert_eq!(dns.count.load(Ordering::SeqCst), asked, "{host} {record}");
    }
}

/// Strict global mode: every address question gets a fake IP whatever the DNS
/// mode and filter, and other questions leave only through the proxy. The
/// local resolver is never asked; with nothing else configured those
/// questions get no answer. A DIRECT global outbound is not strict.
#[tokio::test]
async fn strict_global_resolves_names_only_past_the_proxy() {
    let system = udp_dns("192.0.2.10").await;
    let business = tcp_dns("192.0.2.20").await;
    let proxy = socks_forwarder().await;
    let ask = |core: NativeCoreRuntime, host: &'static str, record: RecordType| async move {
        let query = wire::query(host, record).unwrap();
        let reply = crate::dns::resolver::resolve_dns_query_payload(
            &core,
            &wire::encode(&query).unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
        wire::decode(&reply).unwrap()
    };
    let mut profile = RuntimeProfile::new("strict global");
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("proxy".into());
    profile
        .proxies
        .push(proxy_node("proxy", proxy.address, ProxyProtocol::Socks5));
    profile.dns.fake_ip_filter = vec!["*".parse().unwrap()];
    let compile = |profile: &RuntimeProfile| {
        NativeCoreRuntime::compile_with_egress(
            profile,
            NativeCoreEgressConfig {
                dns_servers: vec![system.address],
                ..Default::default()
            },
        )
    };
    for enabled in [false, true] {
        profile.dns.enabled = enabled;
        profile.dns.nameservers = vec![DnsUpstream {
            route: Some(DnsRoute::Direct),
            ..DnsUpstream::system()
        }];
        let core = compile(&profile);
        let reply = ask(core.clone(), "business.test", RecordType::A).await;
        assert!(matches!(
            wire::addresses(&reply).unwrap()[..],
            [IpAddr::V4(ip)] if ip.octets()[..2] == [198, 18]
        ));
        let reply = ask(core, "business.test", RecordType::TXT).await;
        assert_eq!(reply.response_code(), ResponseCode::NoError);
        assert!(reply.answers().is_empty());
    }
    assert_eq!(system.count.load(Ordering::SeqCst), 0);

    // A configured source carries the question through the global proxy,
    // even one routed DIRECT; the local resolver still drops out.
    let mut direct = upstream(business.address, DnsTransport::Tcp);
    direct.route = Some(DnsRoute::Direct);
    profile.dns.nameservers.push(direct);
    let core = compile(&profile);
    ask(core, "business.test", RecordType::TXT).await;
    assert_eq!(proxy.count.load(Ordering::SeqCst), 1);
    assert_eq!(business.count.load(Ordering::SeqCst), 1);
    assert_eq!(system.count.load(Ordering::SeqCst), 0);

    // A DIRECT global outbound is direct mode by another name.
    profile.global_outbound = Some("DIRECT".into());
    profile.dns.nameservers.truncate(1);
    let core = compile(&profile);
    assert!(!core.dns_service().strict_global());
    let reply = ask(core, "business.test", RecordType::TXT).await;
    assert!(matches!(reply.answers()[0].data(), RData::TXT(_)));
    assert_eq!(system.count.load(Ordering::SeqCst), 1);
}

/// Only the local resolver answers a name when DNS is off or every server
/// configured for it is `system`, which strict global mode leaves to the
/// proxy; a policy decides for the names it covers.
#[tokio::test]
async fn only_the_local_resolver_answers_names_without_another_server() {
    let system = DnsUpstream {
        route: Some(DnsRoute::Direct),
        ..DnsUpstream::system()
    };
    let mut profile = RuntimeProfile::new("local resolver");
    profile.dns.nameservers = vec![upstream(
        "192.0.2.20:53".parse().unwrap(),
        DnsTransport::Udp,
    )];
    profile.dns.policies = vec![DnsNameServerPolicy {
        pattern: "+.lan".parse().unwrap(),
        nameservers: vec![system.clone()],
    }];
    let answers = |profile: &RuntimeProfile, host: &str| {
        NativeCoreRuntime::compile(profile)
            .dns_service()
            .only_system_answers(host)
    };
    assert!(answers(&profile, "business.test"), "DNS is off");
    profile.dns.enabled = true;
    assert!(!answers(&profile, "business.test"));
    assert!(answers(&profile, "printer.lan"));
    profile.dns.nameservers = vec![system];
    assert!(answers(&profile, "business.test"));
}

#[tokio::test]
async fn numeric_ipv6_is_not_rejected_by_the_aaaa_query_switch() {
    let dns = udp_dns("192.0.2.1").await;
    let profile = profile(upstream(dns.address, DnsTransport::Udp));
    for ipv6_enabled in [false, true] {
        let core = NativeCoreRuntime::compile_with_egress(
            &profile,
            NativeCoreEgressConfig {
                ipv6_enabled,
                ..Default::default()
            },
        );
        for purpose in [
            QueryPurpose::Application,
            QueryPurpose::DirectTarget,
            QueryPurpose::ProxyEndpoint,
            QueryPurpose::Bootstrap,
        ] {
            let target = ConnectTarget {
                host: "2001:db8::1".into(),
                port: 443,
            };
            assert_eq!(
                core.dns_service()
                    .resolve_target(&target, purpose, Default::default())
                    .await
                    .unwrap(),
                target
            );
        }
    }
    assert_eq!(dns.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ordered_budget_reserves_time_after_four_silent_sources_for_the_fifth() {
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    let good = udp_dns("192.0.2.1").await;
    let mut profile = profile(upstream(good.address, DnsTransport::Udp));
    profile.dns.nameservers = silent
        .iter()
        .map(|socket| upstream(socket.local_addr().unwrap(), DnsTransport::Udp))
        .chain([upstream(good.address, DnsTransport::Udp)])
        .collect();
    let core = runtime(&profile);
    let target = ConnectTarget {
        host: "fallback.test".into(),
        port: 443,
    };
    let answer = tokio::time::timeout(QUERY_BUDGET, resolve_udp_target(&core, &target))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer.host, "192.0.2.1");
}

#[tokio::test]
async fn dns_over_socks_tcp_uses_the_selected_connector_and_numeric_resolver_endpoint() {
    let dns = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = dns.local_addr().unwrap();
    let dns_task = tokio::spawn(async move {
        let (mut stream, _) = dns.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        let query = wire::decode(&bytes).unwrap();
        assert_eq!(query.query().unwrap().name().to_utf8(), "business.test.");
        let mut reply = wire::response(&query, ResponseCode::NoError);
        reply.add_answer(Record::from_rdata(
            query.query().unwrap().name().clone(),
            30,
            RData::A(A("192.0.2.9".parse().unwrap())),
        ));
        let bytes = wire::encode(&reply).unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let socks_task = tokio::spawn(async move {
        let (socket, _) = socks.accept().await.unwrap();
        let InboundSession::Stream(mut accepted) = crate::protocols::socks5::Socks5Acceptor
            .accept(Box::new(socket))
            .await
            .unwrap()
        else {
            panic!("expected stream");
        };
        assert_eq!(accepted.target.authority(), dns_addr.to_string());
        let mut remote = TcpStream::connect(dns_addr).await.unwrap();
        accepted
            .io
            .write_all(accepted.replies.success)
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut accepted.io, &mut remote).await;
    });
    let mut server = upstream(dns_addr, DnsTransport::Tcp);
    server.route = Some(DnsRoute::NamedOutbound("DNS proxy".into()));
    let mut profile = profile(server);
    profile.proxies.push(ProxyNode {
        id: "proxy".into(),
        name: "DNS proxy".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(socks_addr.ip().to_string()),
        port: Some(socks_addr.port()),
        options: serde_json::json!({}),
    });
    let core = runtime(&profile);
    let target = ConnectTarget {
        host: "business.test".into(),
        port: 3478,
    };
    let result = tokio::time::timeout(Duration::from_secs(2), resolve_udp_target(&core, &target))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.host, "192.0.2.9");
    assert_eq!(result.port, 3478);
    dns_task.await.unwrap();
    // The connection through the proxy stays for later queries until the
    // service retires.
    core.dns_service().retire();
    socks_task.await.unwrap();
}

#[tokio::test]
async fn recursive_dns_proxy_bootstrap_fails_before_waiting_on_its_own_singleflight() {
    let mut server = upstream("192.0.2.53:53".parse().unwrap(), DnsTransport::Tcp);
    server.route = Some(DnsRoute::NamedOutbound("cycle".into()));
    let mut profile = profile(server);
    profile.dns.proxy_nameservers = profile.dns.nameservers.clone();
    profile.proxies.push(ProxyNode {
        id: "cycle".into(),
        name: "cycle".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some("node.cycle.test".into()),
        port: Some(1080),
        options: serde_json::json!({}),
    });
    let core = runtime(&profile);
    let query = wire::query("business.test", RecordType::A).unwrap();
    let error = tokio::time::timeout(
        Duration::from_millis(500),
        exchange(
            core.dns_service(),
            query,
            QueryPurpose::Application,
            Default::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.contains("dependency cycle"), "{error}");
}

#[test]
fn routed_system_snapshot_preserves_explicit_and_rules_paths() {
    let mut server = DnsUpstream::system();
    server.route = Some(DnsRoute::NamedOutbound("proxy".into()));
    let mut profile = profile(server);
    profile.proxies.push(ProxyNode {
        id: "proxy".into(),
        name: "proxy".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some("127.0.0.1".into()),
        port: Some(1080),
        options: serde_json::json!({"udp": true}),
    });
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
            ..Default::default()
        },
    );
    assert_eq!(
        core.dns_service()
            .plan("test", QueryPurpose::Application, &Default::default())[0]
            .outbound
            .as_deref(),
        Some("proxy")
    );
    profile.dns.nameservers[0].route = None;
    profile.rules = [match_rule("proxy")].into();
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
            ..Default::default()
        },
    );
    assert_eq!(
        core.dns_service()
            .plan("test", QueryPurpose::Application, &Default::default())[0]
            .outbound
            .as_deref(),
        Some("proxy")
    );
    // A UDP upstream skips a rule whose node has UDP off, as UDP flows do.
    profile.proxies.last_mut().unwrap().options = serde_json::json!({});
    let core = NativeCoreRuntime::compile_with_egress(
        &profile,
        NativeCoreEgressConfig {
            dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
            ..Default::default()
        },
    );
    assert_eq!(
        core.dns_service()
            .plan("test", QueryPurpose::Application, &Default::default())[0]
            .outbound
            .as_deref(),
        Some("DIRECT")
    );
}

#[tokio::test]
async fn concurrent_dependency_roots_cannot_wait_on_each_others_singleflight() {
    #[derive(Debug)]
    struct RecursiveConnector {
        host: &'static str,
        barrier: Arc<tokio::sync::Barrier>,
    }
    impl crate::outbound::OutboundConnector for RecursiveConnector {
        fn connect_stream<'a>(
            &'a self,
            egress: &'a EgressRuntime,
            _: &'a ConnectTarget,
            _: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(async move {
                self.barrier.wait().await;
                egress
                    .connect_tcp_host(self.host, 1080, "recursive test proxy")
                    .await
                    .map(|stream| Box::new(stream) as BoxedOutboundStream)
                    .map_err(OutboundError::hop_dial)
            })
        }
    }
    let mut to_a = upstream("192.0.2.53:53".parse().unwrap(), DnsTransport::Tcp);
    to_a.route = Some(DnsRoute::NamedOutbound("A".into()));
    let mut profile = profile(to_a.clone());
    // The common proxy dependency explicitly resolves through itself. Both
    // roots must execute their dependency work, not join each other's flight.
    profile.dns.proxy_nameservers = vec![to_a];
    let mut snapshot = crate::runtime::RuntimeSnapshot::compile(
        &profile,
        Default::default(),
        Default::default(),
        None,
        Default::default(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    snapshot.insert_outbound_for_test(
        "A",
        Arc::new(RecursiveConnector {
            host: "node.test",
            barrier,
        }),
    );
    let service = snapshot.dns.clone();
    let results = tokio::time::timeout(Duration::from_millis(500), async {
        tokio::join!(
            exchange(
                &service,
                wire::query("a.test", RecordType::A).unwrap(),
                QueryPurpose::Application,
                Default::default()
            ),
            exchange(
                &service,
                wire::query("b.test", RecordType::A).unwrap(),
                QueryPurpose::Application,
                Default::default()
            ),
        )
    })
    .await
    .unwrap();
    assert!(results.0.unwrap_err().contains("dependency cycle"));
    assert!(results.1.unwrap_err().contains("dependency cycle"));
}

#[tokio::test]
async fn committed_policy_change_cancels_old_dns_but_preparation_does_not() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let profile = profile(upstream(socket.local_addr().unwrap(), DnsTransport::Udp));
    let core = crate::NativeCoreDevice::compile(&profile);
    let old = core.pinned_runtime();
    let task = tokio::spawn(async move {
        exchange(
            old.dns_service(),
            wire::query("waiting.test", RecordType::A).unwrap(),
            QueryPurpose::Application,
            Default::default(),
        )
        .await
    });
    let mut bytes = [0; 512];
    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let prepared = core
        .prepare_policy_update(&[crate::CorePolicyUpdate::TrafficPolicy {
            mode: TrafficPolicyMode::Direct,
            global_outbound: None,
        }])
        .unwrap();
    assert!(
        !task.is_finished(),
        "preparation cannot cancel the active DNS service"
    );
    core.apply_policy_update(prepared).unwrap();
    let error = tokio::time::timeout(Duration::from_millis(300), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("generation retired"));
    core.close();
}

#[tokio::test]
async fn non_in_questions_bypass_fake_mode_and_preserve_upstream_outcome() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 512];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let query = wire::decode(&bytes[..length]).unwrap();
        assert_eq!(
            query.query().unwrap().query_class(),
            hickory_proto::rr::DNSClass::CH
        );
        socket
            .send_to(
                &wire::encode(&wire::response(&query, ResponseCode::Refused)).unwrap(),
                peer,
            )
            .await
            .unwrap();
    });
    let mut profile = profile(upstream(address, DnsTransport::Udp));
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    let core = runtime(&profile);
    let mut query = wire::query("chaos.test", RecordType::A).unwrap();
    query.queries_mut()[0].set_query_class(hickory_proto::rr::DNSClass::CH);
    let response = crate::dns::resolver::resolve_dns_query_payload(
        &core,
        &wire::encode(&query).unwrap(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        wire::decode(&response).unwrap().response_code(),
        ResponseCode::Refused
    );
    server.await.unwrap();
}

async fn socks_forwarder() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let connections = count.clone();
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    connections.fetch_add(1, Ordering::SeqCst);
                    sessions.spawn(async move {
                        let InboundSession::Stream(mut accepted) = crate::protocols::socks5::Socks5Acceptor.accept(Box::new(stream)).await.unwrap() else { panic!("expected SOCKS stream"); };
                        assert!(accepted.target.ip().is_some(), "DNS upstream must be numerically prepared");
                        let mut remote = TcpStream::connect(accepted.target.authority()).await.unwrap();
                        accepted.io.write_all(accepted.replies.success).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut accepted.io, &mut remote).await;
                    });
                }
                result = sessions.join_next(), if !sessions.is_empty() => { result.unwrap().unwrap(); }
            }
        }
    });
    Stub {
        address,
        count,
        task,
    }
}

#[tokio::test]
async fn hostname_dns_routes_with_both_bootstrap_ip_and_domain_before_cache_lookup() {
    let bootstrap = udp_dns("127.0.0.1").await;
    let proxy_a = socks_forwarder().await;
    let proxy_b = socks_forwarder().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let dns_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            let request = wire::decode(&bytes).unwrap();
            let index = count.fetch_add(1, Ordering::SeqCst) + 1;
            let mut reply = wire::response(&request, ResponseCode::NoError);
            reply.add_answer(Record::from_rdata(
                request.query().unwrap().name().clone(),
                30,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, index as u8))),
            ));
            let bytes = wire::encode(&reply).unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
    });
    let mut server = upstream(address, DnsTransport::Tcp);
    server.host = "dns.upstream.test".into();
    server.route = Some(DnsRoute::Rules);
    let mut profile = profile(server);
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    profile.dns.bootstrap_nameservers = vec![upstream(bootstrap.address, DnsTransport::Udp)];
    for (name, proxy) in [("A", &proxy_a), ("B", &proxy_b)] {
        profile.proxies.push(ProxyNode {
            id: name.into(),
            name: name.into(),
            protocol: ProxyProtocol::Socks5,
            server: Some(proxy.address.ip().to_string()),
            port: Some(proxy.address.port()),
            options: serde_json::json!({}),
        });
    }
    profile.groups.push(crate::PolicyGroup {
        id: "DNS".into(),
        name: "DNS".into(),
        kind: crate::PolicyGroupKind::Select,
        members: vec!["A".into(), "B".into()],
        interval_seconds: None,
        test_url: None,
        selected: Some("A".into()),
    });
    profile.rules = [RouteRule {
        kind: RuleKind::IpCidr,
        payload: Some("127.0.0.0/8"),
        outbound: "DNS",
        no_resolve: false,
    }]
    .into_iter()
    .chain(&profile.rules)
    .collect();
    let core = runtime(&profile);
    let preview = core.dns_service().evaluate(&crate::DnsQueryInput {
        query_class: 1,
        domain: "business.test".into(),
        record_type: crate::DnsRecordType::A,
        process_name: None,
        process_path: None,
    });
    assert!(preview.upstreams[0].requires_resolution);
    assert_eq!(preview.upstreams[0].outbound, None);
    let target = ConnectTarget {
        host: "business.test".into(),
        port: 3478,
    };
    assert_eq!(
        resolve_udp_target(&core, &target).await.unwrap().host,
        "192.0.2.1"
    );
    assert_eq!(
        proxy_a.count.load(Ordering::SeqCst),
        1,
        "IP-CIDR selects proxy A instead of default DIRECT"
    );
    assert_eq!(
        resolve_udp_target(&core, &target).await.unwrap().host,
        "192.0.2.1"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "unchanged effective route hits its cache"
    );
    core.group_state().select("DNS", "B");
    assert_eq!(
        resolve_udp_target(&core, &target).await.unwrap().host,
        "192.0.2.2"
    );
    assert_eq!(
        proxy_b.count.load(Ordering::SeqCst),
        1,
        "new effective outbound cannot reuse the old route's cached answer"
    );
    profile.rules = [RouteRule {
        kind: RuleKind::Domain,
        payload: Some("dns.upstream.test"),
        outbound: "B",
        no_resolve: false,
    }]
    .into_iter()
    .chain(&profile.rules)
    .collect();
    let by_domain = runtime(&profile);
    assert_eq!(
        resolve_udp_target(&by_domain, &target).await.unwrap().host,
        "192.0.2.3"
    );
    assert_eq!(
        proxy_b.count.load(Ordering::SeqCst),
        2,
        "original DNS hostname remains available to domain rules after bootstrap"
    );
    dns_task.abort();
}

#[tokio::test]
async fn ordered_sources_wait_for_earlier_bootstrap_failure_before_fallback() {
    let good = udp_dns("192.0.2.1").await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut hostname = upstream("192.0.2.53:53".parse().unwrap(), DnsTransport::Tcp);
    hostname.host = "unresolvable.dns.test".into();
    hostname.route = Some(DnsRoute::Rules);
    for hostname_first in [false, true] {
        let mut profile = profile(upstream(good.address, DnsTransport::Udp));
        if hostname_first {
            profile.dns.nameservers.insert(0, hostname.clone());
        } else {
            profile.dns.nameservers.push(hostname.clone());
        }
        profile.dns.bootstrap_nameservers =
            vec![upstream(silent.local_addr().unwrap(), DnsTransport::Udp)];
        let core = runtime(&profile);
        let target = ConnectTarget {
            host: "fast.test".into(),
            port: 443,
        };
        let started = Instant::now();
        let reply =
            tokio::time::timeout(Duration::from_secs(3), resolve_udp_target(&core, &target))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(reply.host, "192.0.2.1");
        if hostname_first {
            assert!(started.elapsed() >= Duration::from_secs(1));
        } else {
            assert!(started.elapsed() < Duration::from_millis(500));
        }
    }
}

#[tokio::test]
async fn egress_metadata_does_not_own_dns_but_an_active_query_pins_it_until_cancelled() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut profile = profile(upstream(socket.local_addr().unwrap(), DnsTransport::Udp));
    profile.dns.proxy_nameservers = profile.dns.nameservers.clone();
    let snapshot = crate::runtime::RuntimeSnapshot::compile(
        &profile,
        Default::default(),
        Default::default(),
        None,
        Default::default(),
    );
    let rules = Arc::downgrade(&snapshot.rule_engine);
    let service = Arc::downgrade(&snapshot.dns);
    let egress = snapshot.egress.with_binding_recorder();
    let metadata = egress.binding_recorder();
    let lookup_egress = egress.clone();
    let query = tokio::spawn(async move { lookup_egress.lookup_host("pending.test", 443).await });
    let mut bytes = [0; 512];
    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    drop(snapshot);
    assert!(
        service.upgrade().is_some(),
        "the active DNS request owns its service"
    );
    assert!(
        rules.upgrade().is_some(),
        "the active request keeps its routing context valid"
    );
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());
    assert!(
        service.upgrade().is_none(),
        "idle egress and metadata must not retain the old generation"
    );
    assert!(
        rules.upgrade().is_none(),
        "query cancellation releases the last actual policy owner"
    );
    assert_eq!(metadata.current().interface_index, None);
    let error = egress.lookup_host("example.com", 443).await.unwrap_err();
    assert!(
        error.contains("generation retired"),
        "expired policy must not fall back to system DNS: {error}"
    );
}

#[tokio::test]
async fn an_answer_past_its_ttl_serves_at_once_while_one_lookup_refreshes_it() {
    // Answers with a one-second TTL, a new address each time it is asked.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let queries = count.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let asked = queries.fetch_add(1, Ordering::SeqCst) as u8 + 1;
            let request = wire::decode(&bytes[..len]).unwrap();
            let mut reply = wire::response(&request, ResponseCode::NoError);
            reply.add_answer(Record::from_rdata(
                request.query().unwrap().name().clone(),
                1,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, asked))),
            ));
            socket
                .send_to(&wire::encode(&reply).unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let _stub = Stub {
        address,
        count: count.clone(),
        task,
    };
    let core = runtime(&profile(upstream(address, DnsTransport::Udp)));
    let dns = core.dns_service();
    let resolve = || {
        dns.resolve_family(
            "stale.test",
            443,
            false,
            QueryPurpose::DirectTarget,
            Default::default(),
        )
    };
    let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
    assert_eq!(resolve().await.unwrap(), vec![first]);

    // Past the TTL the old address serves at once, and one lookup goes out.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(resolve().await.unwrap(), vec![first]);
    assert_eq!(resolve().await.unwrap(), vec![first]);
    for _ in 0..100 {
        if count.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(count.load(Ordering::SeqCst), 2, "one refresh");

    // The refresh's answer is the fresh one now, asking no one.
    assert_eq!(
        resolve().await.unwrap(),
        vec!["192.0.2.2:443".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
