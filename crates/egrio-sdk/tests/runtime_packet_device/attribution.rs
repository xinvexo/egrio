//! Platform flow attribution through the real Runtime: the host supplies
//! the scanner with the Core start inputs, and both the packet plane and the
//! system-proxy listener use it. Process rules permit DIRECT, while the
//! fallback rejects: a lost identity prevents the real loopback echo rather
//! than merely changing UI text.
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};

use egrio_core::{
    FlowKey, FlowScanner, ProcessInfo, RouteRule, RuleKind, RuntimeProfile,
    TrafficConnectionProtocol,
};
use egrio_runtime::{
    Runtime, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec, RuntimeSpec, SystemProxyEndpoint,
    SystemProxySpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, UdpSocket},
};
use uuid::Uuid;

use super::fragments::Family;
use super::{
    captured_ipv4_tcp_packet, captured_ipv6_tcp_packet, captured_tcp_flags, captured_tcp_payload,
    captured_tcp_sequence_number, dns_query, first_a_answer, first_aaaa_answer, ipv4_udp_packet,
    ipv4_udp_payload, is_dns_answer_to, packet_spec, wait_for_written_packet, FixedCoreConfig,
};

const NAME: &str = "Egrio Attribution Probe";
const PATH: &str =
    "/Applications/Egrio Attribution Probe.app/Contents/MacOS/Egrio Attribution Probe";

#[derive(Clone, Copy)]
enum ProcessRule {
    Name,
    Path,
}
impl ProcessRule {
    /// The rule as the profile writes it, which is how a connection's row
    /// names the rule that routed it.
    fn text(self) -> String {
        match self {
            Self::Name => format!("PROCESS-NAME,{NAME},DIRECT"),
            Self::Path => format!("PROCESS-PATH,{PATH},DIRECT"),
        }
    }
}

fn profile(rule: ProcessRule, fake: bool) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("packet-attribution");
    profile.dns.enabled = fake;
    if fake {
        profile.dns.enhanced_mode = egrio_core::dns::config::DnsMode::FakeIp;
    }
    profile.rules = vec![
        RouteRule {
            kind: match rule {
                ProcessRule::Name => RuleKind::ProcessName,
                ProcessRule::Path => RuleKind::ProcessPath,
            },
            payload: Some(
                match rule {
                    ProcessRule::Name => NAME,
                    ProcessRule::Path => PATH,
                }
                .into(),
            ),
            outbound: "DIRECT",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        },
    ]
    .into();
    profile
}

/// Client source ports owned by the probe process; every other socket is
/// unknown, exactly as a platform scanner reports unowned tuples.
const ATTRIBUTED_PORTS: [u16; 3] = [53011, 54131, 54133];

#[derive(Debug, Default)]
struct ProbeScanner {
    /// Ephemeral client ports a test hands to the probe at run time.
    owned: Mutex<HashSet<u16>>,
}

impl FlowScanner for ProbeScanner {
    fn scan(&self, flows: &[FlowKey], _: Duration, _: &AtomicBool) -> Vec<Option<ProcessInfo>> {
        let owned = self.owned.lock().unwrap();
        flows
            .iter()
            .map(|flow| {
                (ATTRIBUTED_PORTS.contains(&flow.source_port) || owned.contains(&flow.source_port))
                    .then(|| ProcessInfo {
                        name: Some(NAME.into()),
                        path: Some(PATH.into()),
                    })
            })
            .collect()
    }
}

fn emit(platform: &InMemoryPlatform, payload: Vec<u8>) {
    platform.emit_packets(vec![payload]).unwrap();
}

async fn fixture(rule: ProcessRule, fake: bool) -> (EgrioSdk, Arc<Runtime>, Arc<InMemoryPlatform>) {
    start(rule, fake, packet_spec(), Arc::new(ProbeScanner::default())).await
}

async fn start(
    rule: ProcessRule,
    fake: bool,
    spec: RuntimeSpec,
    scanner: Arc<ProbeScanner>,
) -> (EgrioSdk, Arc<Runtime>, Arc<InMemoryPlatform>) {
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .core_config(Arc::new(
            FixedCoreConfig::with_ipv6(profile(rule, fake)).with_flow_scanner(scanner),
        ))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec).await.unwrap();
    runtime.start().await.unwrap();
    (sdk, runtime, platform)
}

/// Only the system-proxy layer: the OS points at the Core listener, no TUN.
fn system_proxy_spec() -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(903)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec {
                http_proxy: Some(SystemProxyEndpoint::CoreListener),
                https_proxy: Some(SystemProxyEndpoint::CoreListener),
                bypass: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

async fn fake_address(platform: &InMemoryPlatform, family: Family, cursor: &mut usize) -> IpAddr {
    // A numeric domain keeps endpoint resolution entirely on loopback and
    // avoids depending on the host resolver or any external DNS service.
    let kind = match family {
        Family::Ipv4 => 1,
        Family::Ipv6 => 28,
    };
    emit(
        platform,
        ipv4_udp_packet(
            Ipv4Addr::new(10, 23, 0, 2),
            Ipv4Addr::new(198, 18, 0, 1),
            53011,
            53,
            &dns_query(0x7351, "127.0.0.1", kind),
        ),
    );
    let packet =
        wait_for_written_packet(platform, cursor, |packet| is_dns_answer_to(packet, 53011)).await;
    let answer = ipv4_udp_payload(&packet);
    match family {
        Family::Ipv4 => first_a_answer(answer).expect("fake A answer").into(),
        Family::Ipv6 => first_aaaa_answer(answer)
            .expect("projected fake AAAA answer")
            .into(),
    }
}

async fn assert_identity(
    runtime: &Runtime,
    source: SocketAddr,
    protocol: TrafficConnectionProtocol,
    rule: ProcessRule,
) {
    let snapshot = runtime.core_traffic_telemetry_snapshot().await;
    let row = snapshot
        .connections
        .iter()
        .find(|row| {
            row.inbound == "tun"
                && row.source.as_deref() == Some(source.to_string().as_str())
                && std::mem::discriminant(&row.protocol) == std::mem::discriminant(&protocol)
        })
        .expect("attributed packet flow belongs to the Runtime Core telemetry");
    assert_eq!(row.process_name.as_deref(), Some(NAME));
    assert_eq!(row.process_path.as_deref(), Some(PATH));
    assert_eq!(&*row.outbound, "DIRECT");
    assert_eq!(
        row.rule.as_deref(),
        Some(rule.text().as_str()),
        "the process rule, rather than a permissive fallback, admitted the echo"
    );
}

fn tcp_packet(
    client: SocketAddr,
    remote: SocketAddr,
    sequence: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    match (client.ip(), remote.ip()) {
        (IpAddr::V4(client_ip), IpAddr::V4(remote_ip)) => captured_ipv4_tcp_packet(
            client_ip,
            remote_ip,
            client.port(),
            remote.port(),
            sequence,
            ack,
            flags,
            payload,
        ),
        (IpAddr::V6(client_ip), IpAddr::V6(remote_ip)) => captured_ipv6_tcp_packet(
            client_ip,
            remote_ip,
            client.port(),
            remote.port(),
            sequence,
            ack,
            flags,
            payload,
        ),
        _ => unreachable!(),
    }
}

fn tcp_to(packet: &[u8], client: SocketAddr) -> bool {
    let header = match packet.first().map(|byte| byte >> 4) {
        Some(4) => 20,
        Some(6) => 40,
        _ => return false,
    };
    packet.len() >= header + 20
        && u16::from_be_bytes([packet[header + 2], packet[header + 3]]) == client.port()
}

async fn tcp_case(family: Family, fake: bool, rule: ProcessRule) {
    const REQUEST: &[u8] = b"attributed TCP request";
    const RESPONSE: &[u8] = b"attributed TCP response";
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = target.local_addr().unwrap();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await.unwrap();
        let _ = wait_release.await;
    });
    let (_sdk, runtime, platform) = fixture(rule, fake).await;
    let mut cursor = 0;
    let remote_ip = if fake {
        fake_address(&platform, family, &mut cursor).await
    } else {
        target_address.ip()
    };
    let client = SocketAddr::new(family.client(), 54131);
    let remote = SocketAddr::new(remote_ip, target_address.port());
    let isn = 1500;
    // The SYN is held until the flow is attributed; the accepted stream
    // keeps that identity for the ACK and data that follow.
    emit(&platform, tcp_packet(client, remote, isn, 0, 0x02, &[]));
    let syn_ack = wait_for_written_packet(&platform, &mut cursor, |packet| {
        tcp_to(packet, client) && captured_tcp_flags(packet) & 0x12 == 0x12
    })
    .await;
    let server_isn = captured_tcp_sequence_number(&syn_ack);
    emit(
        &platform,
        tcp_packet(client, remote, isn + 1, server_isn + 1, 0x10, &[]),
    );
    emit(
        &platform,
        tcp_packet(client, remote, isn + 1, server_isn + 1, 0x18, REQUEST),
    );
    let response = wait_for_written_packet(&platform, &mut cursor, |packet| {
        tcp_to(packet, client) && captured_tcp_payload(packet) == RESPONSE
    })
    .await;
    let source = if response[0] >> 4 == 4 {
        IpAddr::from(<[u8; 4]>::try_from(&response[12..16]).unwrap())
    } else {
        IpAddr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap())
    };
    assert_eq!(source, remote_ip);
    assert_identity(&runtime, client, TrafficConnectionProtocol::Tcp, rule).await;
    release.send(()).ok();
    echo.await.unwrap();
    runtime.stop().await.unwrap();
    assert_eq!(runtime.take_packet_report().unwrap().packets_failed, 0);
}

async fn udp_case(family: Family, fake: bool, rule: ProcessRule) {
    let physical = if fake {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        family.loopback()
    };
    let echo = UdpSocket::bind(SocketAddr::new(physical, 0)).await.unwrap();
    let (_sdk, runtime, platform) = fixture(rule, fake).await;
    let mut cursor = 0;
    let virtual_ip = if fake {
        fake_address(&platform, family, &mut cursor).await
    } else {
        physical
    };
    let remote = SocketAddr::new(virtual_ip, echo.local_addr().unwrap().port());
    let client = SocketAddr::new(family.client(), 54133);
    for (index, payload) in [
        b"attributed fragmented UDP payload with process path".as_slice(),
        b"the next UDP datagram reuses the flow attribution".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let packet = family.packet(client, remote, payload);
        if index == 0 {
            // Attribution runs on the reassembled datagram, so fragments
            // arriving last-first still carry one identity.
            let pieces = family.fragments(&packet, &[24], 0x5432_1000);
            for piece in pieces.into_iter().rev() {
                emit(&platform, piece);
            }
        } else {
            emit(&platform, packet);
        }
        let mut buffer = [0; 256];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(3), echo.recv_from(&mut buffer))
                .await
                .expect("process rule permits real loopback UDP egress")
                .unwrap();
        assert_eq!(&buffer[..length], payload);
        echo.send_to(&buffer[..length], peer).await.unwrap();
        let response = wait_for_written_packet(&platform, &mut cursor, |packet| {
            udp_payload(packet, client) == Some(payload)
        })
        .await;
        let source = if response[0] >> 4 == 4 {
            IpAddr::from(<[u8; 4]>::try_from(&response[12..16]).unwrap())
        } else {
            IpAddr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap())
        };
        assert_eq!(source, virtual_ip);
        assert_identity(&runtime, client, TrafficConnectionProtocol::Udp, rule).await;
    }
    runtime.stop().await.unwrap();
    assert_eq!(runtime.take_packet_report().unwrap().packets_failed, 0);
}

fn udp_payload(packet: &[u8], client: SocketAddr) -> Option<&[u8]> {
    let header = match packet.first()? >> 4 {
        4 => 20,
        6 => 40,
        _ => return None,
    };
    if packet.len() < header + 8
        || u16::from_be_bytes([packet[header + 2], packet[header + 3]]) != client.port()
    {
        return None;
    }
    Some(&packet[header + 8..])
}

#[tokio::test]
async fn attributed_ipv4_tcp_syn_reaches_process_name_rule_and_same_core_telemetry() {
    tcp_case(Family::Ipv4, false, ProcessRule::Name).await;
}
#[tokio::test]
async fn attributed_fake_ipv6_tcp_syn_reaches_process_path_rule_and_same_core_telemetry() {
    tcp_case(Family::Ipv6, true, ProcessRule::Path).await;
}
#[tokio::test]
async fn attributed_ipv6_udp_fragments_reach_process_path_rule_and_same_core_telemetry() {
    udp_case(Family::Ipv6, false, ProcessRule::Path).await;
}
#[tokio::test]
async fn attributed_fake_ipv4_udp_fragments_reach_process_name_rule_and_same_core_telemetry() {
    udp_case(Family::Ipv4, true, ProcessRule::Name).await;
}

/// A flow the scanner cannot attribute falls through to the rejecting rule:
/// the identity, not a permissive default, admits attributed traffic.
#[tokio::test]
async fn unattributed_flow_is_not_admitted_by_the_process_rule() {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (_sdk, runtime, platform) = fixture(ProcessRule::Name, false).await;
    let client = SocketAddr::new(Family::Ipv4.client(), 54199);
    let remote = echo.local_addr().unwrap();
    emit(&platform, Family::Ipv4.packet(client, remote, b"unowned"));
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), echo.recv_from(&mut buffer))
            .await
            .is_err(),
        "an unattributed flow must not match the process rule"
    );
    runtime.stop().await.unwrap();
}

/// The system-proxy layer alone reaches process rules: the Core listener
/// looks up the loopback client with the scanner the host supplied at Core
/// start, while no TUN or packet capture exists.
#[tokio::test]
async fn system_proxy_client_reaches_process_rule_without_a_tun() {
    const REQUEST: &[u8] = b"attributed proxy request";
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        stream.write_all(&request).await.unwrap();
    });
    let scanner = Arc::new(ProbeScanner::default());
    let (_sdk, runtime, _platform) = start(
        ProcessRule::Path,
        false,
        system_proxy_spec(),
        scanner.clone(),
    )
    .await;
    assert!(
        runtime.take_packet_report().is_none(),
        "no packet plane runs"
    );
    let listener: SocketAddr = runtime
        .core_status()
        .listen_addr
        .expect("running Core listener")
        .parse()
        .unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let client_address = socket.local_addr().unwrap();
    scanner.owned.lock().unwrap().insert(client_address.port());
    let mut client = socket.connect(listener).await.unwrap();
    client
        .write_all(format!("CONNECT {target_address} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
        .await
        .expect("the listener answers")
        .unwrap();
    let response = String::from_utf8_lossy(&response[..read]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the process rule admits the attributed client: {response}"
    );
    client.write_all(REQUEST).await.unwrap();
    let mut echoed = vec![0; REQUEST.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, REQUEST);

    let snapshot = runtime.core_traffic_telemetry_snapshot().await;
    let row = snapshot
        .connections
        .iter()
        .find(|row| {
            row.inbound == "http-connect"
                && row.source.as_deref() == Some(client_address.to_string().as_str())
        })
        .expect("the proxied connection belongs to the Runtime Core telemetry");
    assert_eq!(row.process_name.as_deref(), Some(NAME));
    assert_eq!(row.process_path.as_deref(), Some(PATH));
    assert_eq!(row.rule.as_deref(), Some(ProcessRule::Path.text().as_str()));

    drop(client);
    echo.await.unwrap();
    runtime.stop().await.unwrap();
}
