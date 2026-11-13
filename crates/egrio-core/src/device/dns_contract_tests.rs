//! End-to-end target identity contracts across explicit and captured ingress.
//! All DNS and proxy peers are local, and a reserved name must never reach OS
//! DNS. A proxied TCP name reaches the node as the client gave it; DIRECT
//! resolves it with the configured DNS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::{NativeCoreDevice, NativeTcpFlowTarget};
use crate::dns::config::{DnsMode, DnsNameServerPolicy, DnsRoute, DnsTransport, DnsUpstream};
use crate::dns::wire;
use crate::profile::{
    PolicyGroup, PolicyGroupKind, ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile,
    TrafficPolicyMode,
};
use crate::target::{parse_socks_address, ConnectTarget};

const DOMAIN: &str = "business-dns-contract.invalid";
pub(super) const ANSWER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 42);
const DEADLINE: Duration = Duration::from_secs(3);

pub(super) struct DnsPeer {
    address: SocketAddr,
    tcp_address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, RecordType)>>>,
    task: JoinHandle<()>,
}

impl DnsPeer {
    fn configure(&self, profile: &mut RuntimeProfile) {
        profile.dns.enabled = true;
        profile.dns.nameservers = vec![self.upstream()];
    }

    fn upstream(&self) -> DnsUpstream {
        DnsUpstream {
            transport: DnsTransport::Udp,
            host: self.address.ip().to_string(),
            port: self.address.port(),
            path: String::new(),
            server_name: None,
            route: Some(DnsRoute::Direct),
        }
    }

    fn proxy_upstream(&self) -> DnsUpstream {
        DnsUpstream {
            transport: DnsTransport::Tcp,
            host: self.tcp_address.ip().to_string(),
            port: self.tcp_address.port(),
            route: Some(DnsRoute::Proxy),
            ..self.upstream()
        }
    }

    async fn start(rcode: ResponseCode, answer: Ipv4Addr) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_address = listener.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let observed = queries.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                tokio::select! {
                    packet = socket.recv_from(&mut buffer) => {
                        let (length, sender) = packet.unwrap();
                        let response = dns_response(&buffer[..length], &observed, rcode, answer);
                        socket.send_to(&response, sender).await.unwrap();
                    }
                    connection = listener.accept() => {
                        let (mut stream, _) = connection.unwrap();
                        let length = usize::from(stream.read_u16().await.unwrap());
                        let mut payload = vec![0; length];
                        stream.read_exact(&mut payload).await.unwrap();
                        let response = dns_response(&payload, &observed, rcode, answer);
                        stream.write_u16(response.len() as u16).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                        stream.shutdown().await.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            tcp_address,
            queries,
            task,
        }
    }
}

fn dns_response(
    payload: &[u8],
    observed: &Mutex<Vec<(String, RecordType)>>,
    rcode: ResponseCode,
    answer: Ipv4Addr,
) -> Vec<u8> {
    let request = wire::decode(payload).unwrap();
    let question = request.queries.first().unwrap();
    observed.lock().unwrap().push((
        question.name().to_utf8().trim_end_matches('.').into(),
        question.query_type(),
    ));
    let mut response = wire::response(&request, rcode);
    if rcode == ResponseCode::NoError && question.query_type() == RecordType::A {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            60,
            RData::A(A(answer)),
        ));
    }
    wire::encode(&response).unwrap()
}

pub(super) async fn configure_local_dns(profile: &mut RuntimeProfile) -> DnsPeer {
    configure_local_dns_answer(profile, ANSWER).await
}

pub(super) async fn configure_local_dns_answer(
    profile: &mut RuntimeProfile,
    answer: Ipv4Addr,
) -> DnsPeer {
    let dns = DnsPeer::start(ResponseCode::NoError, answer).await;
    dns.configure(profile);
    dns
}

impl Drop for DnsPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum ProxyKind {
    Http,
    Socks,
}

#[derive(Clone, Copy)]
enum SinkResponse {
    Echo,
    Http204,
}

#[derive(Debug)]
struct ProxyRequest {
    target: ConnectTarget,
    payload: Vec<u8>,
}

struct ProxyPeer {
    address: SocketAddr,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    requests: Arc<Mutex<Vec<ProxyRequest>>>,
    dns_target: Arc<Mutex<Option<SocketAddr>>>,
    dns_tunnels: Arc<std::sync::atomic::AtomicUsize>,
    task: JoinHandle<()>,
}

impl ProxyPeer {
    async fn start(kind: ProxyKind) -> Self {
        Self::with_response(kind, SinkResponse::Echo).await
    }

    async fn with_response(kind: ProxyKind, response: SinkResponse) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepts = accepted.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let dns_target = Arc::new(Mutex::new(None));
        let dns_route = dns_target.clone();
        let dns_tunnels = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let forwarded_dns = dns_tunnels.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Each connection on its own, as a proxy serves them: a DNS
                // tunnel stays open for later queries.
                let observed = observed.clone();
                let dns_route = dns_route.clone();
                let forwarded_dns = forwarded_dns.clone();
                tokio::spawn(async move {
                    let target = match kind {
                        ProxyKind::Http => {
                            let request = read_http_head(&mut stream).await;
                            let authority = request
                                .lines()
                                .next()
                                .unwrap()
                                .split_whitespace()
                                .nth(1)
                                .unwrap();
                            let target = crate::target::parse_connect_authority(authority).unwrap();
                            stream
                                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .await
                                .unwrap();
                            target
                        }
                        ProxyKind::Socks => {
                            let mut greeting = [0; 3];
                            stream.read_exact(&mut greeting).await.unwrap();
                            assert_eq!(greeting, [5, 1, 0]);
                            stream.write_all(&[5, 0]).await.unwrap();
                            let mut prefix = [0; 3];
                            stream.read_exact(&mut prefix).await.unwrap();
                            assert_eq!(prefix, [5, 1, 0]);
                            let target = read_socks_target(&mut stream).await;
                            stream
                                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                                .await
                                .unwrap();
                            target
                        }
                    };
                    let configured_dns = *dns_route.lock().unwrap();
                    if let Some(address) = configured_dns
                        .filter(|address: &SocketAddr| target.authority() == address.to_string())
                    {
                        forwarded_dns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let mut upstream = TcpStream::connect(address).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        return;
                    }
                    let payload = match response {
                        SinkResponse::Echo => {
                            let mut payload = Vec::new();
                            stream.read_to_end(&mut payload).await.unwrap();
                            payload
                        }
                        SinkResponse::Http204 => read_http_head(&mut stream).await.into_bytes(),
                    };
                    observed.lock().unwrap().push(ProxyRequest {
                        target,
                        payload: payload.clone(),
                    });
                    match response {
                        SinkResponse::Echo => stream.write_all(&payload).await.unwrap(),
                        SinkResponse::Http204 => stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap(),
                    }
                    stream.shutdown().await.unwrap();
                });
            }
        });
        Self {
            address,
            accepted,
            requests,
            dns_target,
            dns_tunnels,
            task,
        }
    }
}

impl Drop for ProxyPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct EchoPeer {
    address: SocketAddr,
    payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl EchoPeer {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let payloads = Arc::new(Mutex::new(Vec::new()));
        let received = payloads.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut payload = Vec::new();
                stream.read_to_end(&mut payload).await.unwrap();
                received.lock().unwrap().push(payload.clone());
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            payloads,
            task,
        }
    }
}

impl Drop for EchoPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16 * 1024);
        header.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(header).unwrap()
}

async fn read_socks_target(stream: &mut TcpStream) -> ConnectTarget {
    let kind = stream.read_u8().await.unwrap();
    let mut encoded = vec![kind];
    let length = match kind {
        1 => 4,
        4 => 16,
        3 => {
            let length = stream.read_u8().await.unwrap();
            encoded.push(length);
            usize::from(length)
        }
        _ => panic!("invalid SOCKS address type"),
    };
    let offset = encoded.len();
    encoded.resize(offset + length + 2, 0);
    stream.read_exact(&mut encoded[offset..]).await.unwrap();
    parse_socks_address(&encoded).unwrap().0
}

fn profile(dns: &DnsPeer, proxy: &ProxyPeer, kind: ProxyKind) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("shared business DNS contract");
    dns.configure(&mut profile);
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    profile.proxies.push(ProxyNode {
        id: "sink".into(),
        name: "sink".into(),
        protocol: match kind {
            ProxyKind::Http => ProxyProtocol::Http,
            ProxyKind::Socks => ProxyProtocol::Socks5,
        },
        server: Some(proxy.address.ip().to_string()),
        port: Some(proxy.address.port()),
        options: serde_json::Value::Null,
    });
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::Domain,
            payload: Some(DOMAIN),
            outbound: "sink",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "sink",
            no_resolve: false,
        },
    ]
    .into();
    profile
}

#[derive(Clone, Copy, Debug)]
enum Ingress {
    Http,
    Socks,
    Platform,
}

async fn exchange(
    core: &NativeCoreDevice,
    ingress: Ingress,
    host: &str,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (app, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut app = app.unwrap();
        let server = server.unwrap().0;
        let runtime = core.pinned_runtime();
        let handler = match ingress {
            Ingress::Platform => {
                let task = core.route_tcp_flow_io(
                    server,
                    None,
                    NativeTcpFlowTarget {
                        host: host.into(),
                        port,
                        process_name: Some("dns-contract-test".into()),
                        process_path: None,
                    },
                );
                tokio::spawn(async move { task.await.map(|_| ()).map_err(|e| e.to_string()) })
            }
            _ => tokio::spawn(async move {
                crate::inbound::dispatch::handle_connect_client(server, &runtime)
                    .await
                    .map(|_| ())
            }),
        };
        match ingress {
            Ingress::Http => {
                app.write_all(
                    format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
                let reply = read_http_head(&mut app).await;
                if !reply.starts_with("HTTP/1.1 200") {
                    drop(app);
                    return Err(handler.await.unwrap().err().unwrap_or(reply));
                }
            }
            Ingress::Socks => {
                app.write_all(&[5, 1, 0]).await.unwrap();
                let mut selected = [0; 2];
                app.read_exact(&mut selected).await.unwrap();
                assert_eq!(selected, [5, 0]);
                let target = ConnectTarget {
                    host: host.into(),
                    port,
                };
                let mut request = vec![5, 1, 0];
                request.extend(target.socks_address().unwrap());
                app.write_all(&request).await.unwrap();
                let mut reply = [0; 10];
                app.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 5);
                if reply[1] != 0 {
                    drop(app);
                    return Err(handler
                        .await
                        .unwrap()
                        .err()
                        .unwrap_or_else(|| format!("SOCKS rejected with {}", reply[1])));
                }
            }
            Ingress::Platform => {}
        }
        let written = app.write_all(payload).await;
        let finished = app.shutdown().await;
        let mut echoed = Vec::new();
        let read = app.read_to_end(&mut echoed).await;
        handler.await.unwrap()?;
        written.map_err(|error| error.to_string())?;
        finished.map_err(|error| error.to_string())?;
        read.map_err(|error| error.to_string())?;
        Ok(echoed)
    })
    .await
    .expect("isolated DNS/proxy exchange must finish within its deadline")
}

fn split_dns_profile(business: &DnsPeer, proxy: &ProxyPeer, group_direct: bool) -> RuntimeProfile {
    let mut profile = profile(business, proxy, ProxyKind::Http);
    *proxy.dns_target.lock().unwrap() = Some(business.tcp_address);
    profile.dns.nameservers = vec![
        business.proxy_upstream(),
        DnsUpstream {
            route: Some(DnsRoute::Direct),
            ..DnsUpstream::system()
        },
    ];
    profile.global_outbound = Some("sink".into());
    profile.dns.enhanced_mode = DnsMode::RedirHost;
    // A captured real address must retain its own IP routing semantics. The
    // local-only rule ahead of the profile's own represents the direct
    // network containing our echo peer.
    let direct = if group_direct { "choice" } else { "DIRECT" };
    profile.rules = [RouteRule {
        kind: RuleKind::IpCidr,
        payload: Some("127.0.0.1/32"),
        outbound: "DIRECT",
        no_resolve: true,
    }]
    .into_iter()
    .chain(profile.rules.iter().enumerate().map(|(place, rule)| {
        if place == 0 {
            RouteRule {
                outbound: direct,
                ..rule
            }
        } else {
            rule
        }
    }))
    .collect();
    if group_direct {
        profile.groups.push(PolicyGroup {
            name: "choice".into(),
            id: "choice".into(),
            kind: PolicyGroupKind::Select,
            members: vec!["sink".into(), "DIRECT".into()],
            selected: Some("DIRECT".into()),
            interval_seconds: None,
            test_url: None,
        });
    }
    profile
}

fn core_with_system_dns(profile: &RuntimeProfile, system: &DnsPeer) -> NativeCoreDevice {
    NativeCoreDevice::compile_with_egress(
        profile,
        crate::NativeCoreEgressConfig {
            dns_servers: vec![system.address],
            ..Default::default()
        },
    )
}

async fn direct_entries_use_one_dns_source(
    core: &NativeCoreDevice,
    echo: &EchoPeer,
    expected_dns: &DnsPeer,
) {
    let evaluation = core
        .pinned_runtime()
        .dns_service()
        .evaluate(&crate::DnsQueryInput {
            query_class: 1,
            domain: DOMAIN.into(),
            record_type: crate::DnsRecordType::A,
            process_name: None,
            process_path: None,
        });
    let usable: Vec<_> = evaluation
        .upstreams
        .iter()
        .filter(|upstream| upstream.outbound.is_some())
        .collect();
    assert_eq!(usable.len(), 1);
    assert_eq!(
        usable[0].endpoint,
        expected_dns.address.to_string(),
        "the read-only DNS plan must select the same source as direct data traffic"
    );
    let query = wire::query(DOMAIN, RecordType::A).unwrap();
    let answer = core
        .resolve_dns_query_payload(&wire::encode(&query).unwrap(), None, None)
        .await
        .unwrap();
    let answer = wire::decode(&answer).unwrap();
    assert_eq!(answer.response_code, ResponseCode::NoError);
    assert_eq!(
        wire::addresses(&answer).unwrap(),
        vec![echo.address.ip()],
        "captured DNS must return the address reachable by this direct route"
    );
    for (number, ingress, target) in [
        (0, Ingress::Platform, echo.address.ip().to_string()),
        (1, Ingress::Platform, DOMAIN.into()),
        (2, Ingress::Http, DOMAIN.into()),
        (3, Ingress::Socks, DOMAIN.into()),
    ] {
        let payload = format!("direct routing payload {number}").into_bytes();
        assert_eq!(
            exchange(core, ingress, &target, echo.address.port(), &payload)
                .await
                .unwrap(),
            payload
        );
    }
    assert_eq!(
        *echo.payloads.lock().unwrap(),
        (0..4)
            .map(|number| format!("direct routing payload {number}").into_bytes())
            .collect::<Vec<_>>(),
        "all entry paths reached the physical direct echo peer exactly once"
    );
    assert_eq!(
        *expected_dns.queries.lock().unwrap(),
        vec![(DOMAIN.into(), RecordType::A)],
        "captured DNS and direct target dials share one purpose and positive cache"
    );
}

#[tokio::test]
async fn direct_rules_and_selected_direct_groups_coordinate_dns_without_changing_proxy_routes() {
    for group_direct in [false, true] {
        let system = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
        let business = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
        let proxy = ProxyPeer::start(ProxyKind::Http).await;
        let echo = EchoPeer::start().await;
        let profile = split_dns_profile(&business, &proxy, group_direct);
        let core = core_with_system_dns(&profile, &system);
        let route = core
            .evaluate_route(&crate::RouteMatchInput {
                host: Some(DOMAIN.into()),
                destination_port: Some(echo.address.port()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(route.resolved_outbound, "DIRECT");
        assert_eq!(
            route.decision.matched_rule.as_deref(),
            Some(if group_direct {
                "DOMAIN,business-dns-contract.invalid,choice"
            } else {
                "DOMAIN,business-dns-contract.invalid,DIRECT"
            })
        );
        direct_entries_use_one_dns_source(&core, &echo, &system).await;
        assert!(
            business.queries.lock().unwrap().is_empty(),
            "DIRECT must not query the business proxy DNS"
        );
        assert_eq!(proxy.accepted.load(std::sync::atomic::Ordering::Relaxed), 0);

        let remote_domain = "proxied-business-dns-contract.invalid";
        let query = wire::query(remote_domain, RecordType::A).unwrap();
        let answer = core
            .resolve_dns_query_payload(&wire::encode(&query).unwrap(), None, None)
            .await
            .unwrap();
        assert_eq!(
            wire::addresses(&wire::decode(&answer).unwrap()).unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
        let payload = b"proxy routing remains distinct";
        assert_eq!(
            exchange(
                &core,
                Ingress::Platform,
                remote_domain,
                echo.address.port(),
                payload
            )
            .await
            .unwrap(),
            payload
        );
        let requests = proxy.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].target.authority(),
            format!("{remote_domain}:{}", echo.address.port()),
            "the node is handed the name, not the configured DNS answer"
        );
        assert_eq!(requests[0].payload, payload);
        assert_eq!(
            *business.queries.lock().unwrap(),
            vec![(remote_domain.into(), RecordType::A)],
            "only the explicit DNS query reaches the business DNS"
        );
        assert_eq!(
            proxy.dns_tunnels.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the configured proxy DNS source actually traversed a proxy CONNECT tunnel"
        );
        assert_eq!(
            *system.queries.lock().unwrap(),
            vec![(DOMAIN.into(), RecordType::A)]
        );
        assert_eq!(echo.payloads.lock().unwrap().len(), 4);
        core.close();
    }
}

#[tokio::test]
async fn direct_mode_coordinates_captured_and_explicit_domain_dns() {
    let system = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
    let business = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
    let proxy = ProxyPeer::start(ProxyKind::Http).await;
    let echo = EchoPeer::start().await;
    let mut profile = split_dns_profile(&business, &proxy, false);
    profile.traffic_policy_mode = TrafficPolicyMode::Direct;
    let core = core_with_system_dns(&profile, &system);
    direct_entries_use_one_dns_source(&core, &echo, &system).await;
    assert!(business.queries.lock().unwrap().is_empty());
    assert_eq!(proxy.accepted.load(std::sync::atomic::Ordering::Relaxed), 0);
    core.close();
}

#[tokio::test]
async fn explicit_domain_dns_policy_precedes_the_general_proxy_and_system_sources() {
    let system = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
    let business = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
    let selected = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
    let proxy = ProxyPeer::start(ProxyKind::Http).await;
    let echo = EchoPeer::start().await;
    let mut profile = split_dns_profile(&business, &proxy, false);
    profile.dns.policies.push(DnsNameServerPolicy {
        pattern: DOMAIN.parse().unwrap(),
        nameservers: vec![selected.upstream()],
    });
    let core = core_with_system_dns(&profile, &system);
    direct_entries_use_one_dns_source(&core, &echo, &selected).await;
    assert!(
        system.queries.lock().unwrap().is_empty(),
        "the explicit domain policy precedes the general source list"
    );
    assert!(business.queries.lock().unwrap().is_empty());
    assert_eq!(proxy.accepted.load(std::sync::atomic::Ordering::Relaxed), 0);
    core.close();
}

#[tokio::test]
async fn direct_single_explicit_dns_source_never_adds_system_dns() {
    let system = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
    let specified = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
    let proxy = ProxyPeer::start(ProxyKind::Http).await;
    let echo = EchoPeer::start().await;
    let mut profile = split_dns_profile(&specified, &proxy, false);
    profile.dns.nameservers = vec![specified.upstream()];
    let core = core_with_system_dns(&profile, &system);
    direct_entries_use_one_dns_source(&core, &echo, &specified).await;
    assert!(
        system.queries.lock().unwrap().is_empty(),
        "DIRECT does not authorize adding a system source that the user did not configure"
    );
    assert_eq!(proxy.accepted.load(std::sync::atomic::Ordering::Relaxed), 0);
    core.close();
}

#[tokio::test]
async fn direct_proxy_only_sources_fail_without_inventing_a_system_fallback() {
    for policy_only in [false, true] {
        let system = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
        let business = DnsPeer::start(ResponseCode::NoError, ANSWER).await;
        let proxy = ProxyPeer::start(ProxyKind::Http).await;
        let mut profile = split_dns_profile(&business, &proxy, false);
        if policy_only {
            profile.dns.policies.push(DnsNameServerPolicy {
                pattern: DOMAIN.parse().unwrap(),
                nameservers: vec![business.proxy_upstream()],
            });
        } else {
            profile.dns.nameservers = vec![business.proxy_upstream()];
        }
        let core = core_with_system_dns(&profile, &system);
        let query = wire::query(DOMAIN, RecordType::A).unwrap();
        let answer = core
            .resolve_dns_query_payload(&wire::encode(&query).unwrap(), None, None)
            .await
            .unwrap();
        let answer = wire::decode(&answer).unwrap();
        assert_eq!(answer.response_code, ResponseCode::ServFail);
        assert!(answer.answers.is_empty());
        for ingress in [Ingress::Platform, Ingress::Http, Ingress::Socks] {
            assert!(exchange(&core, ingress, DOMAIN, 443, b"must not escape the configured DNS list").await.is_err(),
                "{ingress:?}, policy_only={policy_only}: a direct target cannot use a proxy-only DNS source");
        }
        assert!(
            system.queries.lock().unwrap().is_empty(),
            "an unavailable explicit source does not authorize system or general-list fallback"
        );
        assert!(business.queries.lock().unwrap().is_empty());
        assert_eq!(proxy.accepted.load(std::sync::atomic::Ordering::Relaxed), 0);
        core.close();
    }
}

/// Whatever the configured DNS would answer -- an address, NXDOMAIN or
/// SERVFAIL -- every ingress hands a proxied connection's name to the node,
/// and the Core never asks the DNS about it.
#[tokio::test]
async fn every_ingress_hands_a_proxied_name_to_the_node() {
    for (kind, code) in [
        (ProxyKind::Http, ResponseCode::NoError),
        (ProxyKind::Socks, ResponseCode::NoError),
        (ProxyKind::Http, ResponseCode::NXDomain),
        (ProxyKind::Socks, ResponseCode::ServFail),
    ] {
        let dns = DnsPeer::start(code, ANSWER).await;
        let proxy = ProxyPeer::start(kind).await;
        let core = NativeCoreDevice::compile(&profile(&dns, &proxy, kind));
        let query = wire::query(DOMAIN, RecordType::A).unwrap();
        let answer = core
            .resolve_dns_query_payload(&wire::encode(&query).unwrap(), None, None)
            .await
            .unwrap();
        let fake = wire::addresses(&wire::decode(&answer).unwrap()).unwrap()[0];
        assert_ne!(fake, IpAddr::V4(ANSWER));

        for (number, ingress, host) in [
            (0, Ingress::Http, DOMAIN.to_string()),
            (1, Ingress::Socks, DOMAIN.to_string()),
            (2, Ingress::Platform, DOMAIN.to_string()),
            (3, Ingress::Platform, fake.to_string()),
        ] {
            let payload = format!("unique business prefix {number}").into_bytes();
            assert_eq!(
                exchange(&core, ingress, &host, 443, &payload)
                    .await
                    .unwrap(),
                payload
            );
        }

        let requests = proxy.requests.lock().unwrap();
        assert_eq!(requests.len(), 4, "each client opens one target tunnel");
        for (number, request) in requests.iter().enumerate() {
            assert_eq!(
                request.target.authority(),
                format!("{DOMAIN}:443"),
                "{kind:?} with {code}: request {number} carries the name"
            );
            assert_eq!(
                request.payload,
                format!("unique business prefix {number}").as_bytes(),
                "business bytes are delivered exactly once"
            );
        }
        assert!(
            dns.queries.lock().unwrap().is_empty(),
            "the Core resolves no proxied name"
        );
        core.close();
    }
}

/// An IP rule without `no-resolve` resolves a name before it matches, from
/// every ingress, a fake IP included; `no-resolve` keeps the name away from
/// the DNS, and the proxy then gets it as given.
#[tokio::test]
async fn an_ip_rule_resolves_a_name_unless_no_resolve() {
    for no_resolve in [false, true] {
        let dns = DnsPeer::start(ResponseCode::NoError, Ipv4Addr::LOCALHOST).await;
        let proxy = ProxyPeer::start(ProxyKind::Http).await;
        let echo = EchoPeer::start().await;
        let mut profile = profile(&dns, &proxy, ProxyKind::Http);
        profile.rules = vec![
            RouteRule {
                kind: RuleKind::GeoIp,
                payload: Some("CN"),
                outbound: "DIRECT",
                no_resolve,
            },
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "sink",
                no_resolve: false,
            },
        ]
        .into();
        profile.geodata.geoip = Some(vec![crate::geodata::GeoIpContent {
            code: "CN".into(),
            cidrs: ["127.0.0.0/8"].into_iter().collect(),
            inverse: false,
        }]);
        let core = NativeCoreDevice::compile(&profile);
        let fake = core.inner.sessions.fake_dns.allocate_ipv4(DOMAIN).unwrap();
        let port = echo.address.port();
        for (number, ingress, host) in [
            (0, Ingress::Http, DOMAIN.to_string()),
            (1, Ingress::Socks, DOMAIN.to_string()),
            (2, Ingress::Platform, DOMAIN.to_string()),
            (3, Ingress::Platform, fake.to_string()),
        ] {
            let payload = format!("geoip routed {number}").into_bytes();
            assert_eq!(
                exchange(&core, ingress, &host, port, &payload)
                    .await
                    .unwrap(),
                payload,
                "no_resolve={no_resolve}: {ingress:?} {host}"
            );
        }
        let to_proxy = proxy
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.target.authority())
            .collect::<Vec<_>>();
        if no_resolve {
            assert_eq!(to_proxy, vec![format!("{DOMAIN}:{port}"); 4]);
            assert!(echo.payloads.lock().unwrap().is_empty());
            assert!(dns.queries.lock().unwrap().is_empty());
        } else {
            assert!(to_proxy.is_empty(), "{to_proxy:?}");
            assert_eq!(echo.payloads.lock().unwrap().len(), 4);
            assert!(dns
                .queries
                .lock()
                .unwrap()
                .contains(&(DOMAIN.into(), RecordType::A)));
        }
        core.close();
    }
}

/// A name the DNS cannot resolve matches no IP rule and goes on to the next.
#[tokio::test]
async fn a_name_that_does_not_resolve_skips_the_ip_rules() {
    let dns = DnsPeer::start(ResponseCode::NXDomain, Ipv4Addr::LOCALHOST).await;
    let proxy = ProxyPeer::start(ProxyKind::Http).await;
    let mut profile = profile(&dns, &proxy, ProxyKind::Http);
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::GeoIp,
            payload: Some("CN"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "sink",
            no_resolve: false,
        },
    ]
    .into();
    profile.geodata.geoip = Some(vec![crate::geodata::GeoIpContent {
        code: "CN".into(),
        cidrs: ["0.0.0.0/0"].into_iter().collect(),
        inverse: false,
    }]);
    let core = NativeCoreDevice::compile(&profile);
    assert_eq!(
        exchange(&core, Ingress::Http, DOMAIN, 443, b"unresolved")
            .await
            .unwrap(),
        b"unresolved"
    );
    assert_eq!(
        proxy.requests.lock().unwrap()[0].target.authority(),
        format!("{DOMAIN}:443")
    );
    assert_eq!(
        *dns.queries.lock().unwrap(),
        vec![(DOMAIN.into(), RecordType::A)]
    );
    core.close();
}

#[tokio::test]
async fn real_ip_with_sni_keeps_its_target_and_writes_sniffed_prefix_once() {
    let dns = DnsPeer::start(ResponseCode::NXDomain, ANSWER).await;
    let proxy = ProxyPeer::start(ProxyKind::Http).await;
    let core = NativeCoreDevice::compile(&profile(&dns, &proxy, ProxyKind::Http));
    let hello = crate::sniff::build_tls_client_hello(Some(DOMAIN));
    assert_eq!(
        exchange(&core, Ingress::Platform, "203.0.113.7", 443, &hello)
            .await
            .unwrap(),
        hello
    );
    let requests = proxy.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target.authority(), "203.0.113.7:443");
    assert_eq!(requests[0].payload, hello);
    assert!(
        dns.queries.lock().unwrap().is_empty(),
        "SNI does not authorize re-resolving a real IP destination"
    );
    core.close();
}

/// An active probe through a proxy hands the node the probe URL's host, so a
/// configured NXDOMAIN cannot fail it.
#[tokio::test]
async fn http_probe_hands_the_node_its_host_and_keeps_the_host_header() {
    let dns = DnsPeer::start(ResponseCode::NXDomain, ANSWER).await;
    let proxy = ProxyPeer::with_response(ProxyKind::Http, SinkResponse::Http204).await;
    let core = NativeCoreDevice::compile(&profile(&dns, &proxy, ProxyKind::Http));
    let probe =
        crate::outbound::probe::parse_probe_url(&format!("http://{DOMAIN}:8080/probe?contract=1"))
            .unwrap();
    timeout(
        DEADLINE,
        crate::runtime::probe_outbound_once(&core.pinned_runtime(), "sink", &probe),
    )
    .await
    .expect("local active probe completes")
    .expect("the proxy tunnel and origin HTTP both succeed");

    let requests = proxy.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target.authority(), format!("{DOMAIN}:8080"));
    let request = std::str::from_utf8(&requests[0].payload).unwrap();
    assert!(request.starts_with("GET /probe?contract=1 HTTP/1.1\r\n"));
    assert!(request
        .lines()
        .any(|line| line == format!("Host: {DOMAIN}:8080")));
    assert!(dns.queries.lock().unwrap().is_empty());
    assert!(core
        .inner
        .sessions
        .group_state
        .health_snapshot("sink")
        .unwrap()
        .ewma_probe_micros
        .is_some());
    core.close();
}
