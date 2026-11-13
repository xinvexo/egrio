use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use egrio_core::{
    NativeCoreEgressConfig, PolicyGroup, PolicyGroupKind, RuntimeProfile, TrafficPolicyMode,
};
use egrio_runtime::{
    CheckpointPhase, CheckpointStore, ConnectionHealth, ConnectionHealthFuture, CoreConfigSource,
    PacketCaptureSettings, PacketCaptureSource, PacketDataPlane, PacketDataPlaneFuture,
    PlatformLeaseKey, PlatformLeaseState, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec,
    RuntimeReloadError, RuntimeSpec, RuntimeState,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use uuid::Uuid;

/// The SDK's Runtimes work on the Core's own thread: waits up to two seconds
/// for `condition`, checking it every few milliseconds.
async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    condition()
}

/// Gives the Runtime's thread time to act on an event it must ignore.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[path = "runtime_packet_device/attribution.rs"]
mod attribution;
#[path = "runtime_packet_device/fake_udp.rs"]
mod fake_udp;
#[path = "runtime_packet_device/fragments.rs"]
mod fragments;
#[path = "runtime_packet_device/mtu.rs"]
mod mtu;
#[path = "runtime_packet_device/mtu_contract.rs"]
mod mtu_contract;
#[path = "runtime_packet_device/quiesce.rs"]
mod quiesce;
#[path = "runtime_packet_device/reconfigure.rs"]
mod reconfigure;

/// Serves fresh Core start inputs from a fixed profile id on every load, the
/// in-memory stand-in for the desktop host re-reading its active profile.
#[derive(Debug)]
struct TestCoreConfig(&'static str);

impl CoreConfigSource for TestCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        Ok(egrio_core::CoreStartInputs {
            capture: Default::default(),
            profile: egrio_core::RuntimeProfile::new(self.0),
            egress: egrio_core::NativeCoreEgressConfig::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

#[derive(Debug)]
struct FixedCoreConfig {
    profile: RuntimeProfile,
    egress: NativeCoreEgressConfig,
    capture: egrio_core::NativeCoreCaptureConfig,
    flow_scanner: Option<Arc<dyn egrio_core::FlowScanner>>,
}

impl FixedCoreConfig {
    fn new(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            egress: NativeCoreEgressConfig::default(),
            capture: Default::default(),
            flow_scanner: None,
        }
    }

    fn with_capture(mut self, capture: egrio_core::NativeCoreCaptureConfig) -> Self {
        self.capture = capture;
        self
    }

    fn with_ipv6(profile: RuntimeProfile) -> Self {
        Self {
            egress: NativeCoreEgressConfig {
                ipv6_enabled: true,
                ..NativeCoreEgressConfig::default()
            },
            ..Self::new(profile)
        }
    }

    /// Like a desktop host, hands the Core a platform flow scanner.
    fn with_flow_scanner(mut self, scanner: Arc<dyn egrio_core::FlowScanner>) -> Self {
        self.flow_scanner = Some(scanner);
        self
    }
}

impl CoreConfigSource for FixedCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        Ok(egrio_core::CoreStartInputs {
            capture: self.capture.clone(),
            profile: self.profile.clone(),
            egress: self.egress.clone(),
            egress_socket_guard: None,
            flow_scanner: self.flow_scanner.clone(),
            fake_ip_mappings: None,
        })
    }
}

#[derive(Debug)]
struct RecordingDataPlane {
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[derive(Debug)]
struct ManualConnectionHealth {
    disconnected: tokio::sync::watch::Receiver<bool>,
}

impl ConnectionHealth for ManualConnectionHealth {
    fn wait_disconnected<'a>(&'a self) -> ConnectionHealthFuture<'a> {
        let mut disconnected = self.disconnected.clone();
        Box::pin(async move {
            if *disconnected.borrow() {
                return;
            }
            while disconnected.changed().await.is_ok() {
                if *disconnected.borrow() {
                    return;
                }
            }
        })
    }
}

impl PacketDataPlane for RecordingDataPlane {
    fn run(
        &self,
        _core: egrio_core::NativeCoreDevice,
        queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push("data-plane.ready");
            let _queues = queues;
            stop.cancelled().await;
            events.lock().unwrap().push("data-plane.stop");
            Ok(egrio_core::NativeCoreDeviceRunReport::default())
        })
    }
}

/// Data plane that serves until stopped and then exits with a fatal error
/// recorded on its report: a device failure that coincides with the stop.
#[derive(Debug)]
struct FatalAtTeardownDataPlane;

impl PacketDataPlane for FatalAtTeardownDataPlane {
    fn run(
        &self,
        _core: egrio_core::NativeCoreDevice,
        _queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        Box::pin(async move {
            stop.cancelled().await;
            let mut report = egrio_core::NativeCoreDeviceRunReport {
                packets_received: 42,
                packets_written: 40,
                ..egrio_core::NativeCoreDeviceRunReport::default()
            };
            report.fatal_error = Some("shared packet ring failed: Cancelled".into());
            report.last_error = report.fatal_error.clone();
            Ok(report)
        })
    }
}

fn packet_spec() -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(901)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: true,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn core_only_packet_runtime_spec() -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(901)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec::default(),
    )
    .unwrap()
}

fn packet_and_proxy_spec(port: u16) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(902)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: true,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: Some(egrio_runtime::SystemProxySpec::from_settings(
                egrio_runtime::SystemProxySettings {
                    http_proxy: Some(([127, 0, 0, 1], port).into()),
                    https_proxy: None,
                    bypass: Vec::new(),
                },
            )),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn fake_ip_direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("runtime-packet-fake-ip");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = egrio_core::dns::config::DnsMode::FakeIp;
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("GLOBAL-DIRECT".into());
    profile.groups.push(PolicyGroup {
        id: "global-direct".into(),
        name: "GLOBAL-DIRECT".into(),
        kind: PolicyGroupKind::Select,
        members: vec!["DIRECT".into()],
        interval_seconds: None,
        test_url: None,
        selected: Some("DIRECT".into()),
    });
    profile
}

fn emit_packet(platform: &InMemoryPlatform, _label: &str, payload: Vec<u8>) {
    platform
        .emit_packets(vec![payload])
        .expect("emit captured packet");
}

/// An unfragmented IPv4 UDP packet's (source, destination) ports.
fn ipv4_udp_ports(packet: &[u8]) -> Option<(u16, u16)> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let header = usize::from(packet[0] & 15) * 4;
    Some((
        u16::from_be_bytes([packet[header], packet[header + 1]]),
        u16::from_be_bytes([packet[header + 2], packet[header + 3]]),
    ))
}

/// A captured DNS answer from the virtual resolver to `client_port`.
fn is_dns_answer_to(packet: &[u8], client_port: u16) -> bool {
    ipv4_udp_ports(packet) == Some((53, client_port))
}

async fn wait_for_written_packet(
    platform: &InMemoryPlatform,
    cursor: &mut usize,
    predicate: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let packets = platform.written_packets();
            for packet in packets.iter().skip(*cursor) {
                if predicate(packet) {
                    *cursor = packets.len();
                    return packet.clone();
                }
            }
            *cursor = packets.len();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("expected packet before timeout")
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

fn first_a_answer(message: &[u8]) -> Option<Ipv4Addr> {
    if message.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(message, offset)?.checked_add(4)?;
    }
    for _ in 0..answers {
        offset = skip_dns_name(message, offset)?;
        let header = message.get(offset..offset + 10)?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = message.get(offset + 10..offset + 10 + length)?;
        if record_type == 1 && data.len() == 4 {
            return Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        offset += 10 + length;
    }
    None
}

fn first_aaaa_answer(message: &[u8]) -> Option<Ipv6Addr> {
    if message.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(message, offset)?.checked_add(4)?;
    }
    for _ in 0..answers {
        offset = skip_dns_name(message, offset)?;
        let header = message.get(offset..offset + 10)?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = message.get(offset + 10..offset + 10 + length)?;
        if record_type == 28 && data.len() == 16 {
            return Some(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?));
        }
        offset += 10 + length;
    }
    None
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)?;
        if length & 0xc0 == 0xc0 {
            return message.get(offset + 1).map(|_| offset + 2);
        }
        if length == 0 {
            return Some(offset + 1);
        }
        offset = offset.checked_add(1 + length as usize)?;
    }
}

fn ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let udp_len = 8 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn ipv4_udp_payload(packet: &[u8]) -> &[u8] {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    &packet[header_len + 8..]
}

#[allow(clippy::too_many_arguments)]
fn captured_ipv4_tcp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 40 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let ip_checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence_number.to_be_bytes());
    packet[28..32].copy_from_slice(&acknowledgment_number.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&64_240_u16.to_be_bytes());
    packet[40..].copy_from_slice(payload);
    let checksum = ipv4_tcp_checksum(source_ip, destination_ip, &packet[20..]);
    packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[allow(clippy::too_many_arguments)]
fn captured_ipv6_tcp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut packet = vec![0_u8; 40 + tcp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..48].copy_from_slice(&sequence_number.to_be_bytes());
    packet[48..52].copy_from_slice(&acknowledgment_number.to_be_bytes());
    packet[52] = 5 << 4;
    packet[53] = flags;
    packet[54..56].copy_from_slice(&64_240_u16.to_be_bytes());
    packet[60..].copy_from_slice(payload);
    let checksum = ipv6_tcp_checksum(source_ip, destination_ip, &packet[40..]);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn packet_ip_header_len(packet: &[u8]) -> usize {
    match packet[0] >> 4 {
        4 => ((packet[0] & 0x0f) as usize) * 4,
        6 => 40,
        version => panic!("unexpected IP version {version}"),
    }
}

fn captured_tcp_flags(packet: &[u8]) -> u8 {
    let header_len = packet_ip_header_len(packet);
    packet[header_len + 13]
}

fn captured_tcp_sequence_number(packet: &[u8]) -> u32 {
    let header_len = packet_ip_header_len(packet);
    u32::from_be_bytes(packet[header_len + 4..header_len + 8].try_into().unwrap())
}

fn captured_tcp_acknowledgment_number(packet: &[u8]) -> u32 {
    let header_len = packet_ip_header_len(packet);
    u32::from_be_bytes(packet[header_len + 8..header_len + 12].try_into().unwrap())
}

fn captured_tcp_payload(packet: &[u8]) -> &[u8] {
    let ip_header_len = packet_ip_header_len(packet);
    let tcp_header_len = ((packet[ip_header_len + 12] >> 4) as usize) * 4;
    &packet[ip_header_len + tcp_header_len..]
}

fn ipv4_source(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])
}

fn ipv6_source(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header.iter().copied())
}

fn ipv4_tcp_checksum(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.push(0);
    bytes.push(6);
    bytes.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    bytes.extend_from_slice(segment);
    internet_checksum(bytes)
}

fn ipv6_tcp_checksum(source: Ipv6Addr, destination: Ipv6Addr, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(40 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 6]);
    bytes.extend_from_slice(segment);
    internet_checksum(bytes)
}

fn internet_checksum(bytes: impl IntoIterator<Item = u8>) -> u16 {
    let bytes = bytes.into_iter().collect::<Vec<_>>();
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[tokio::test]
async fn capture_dns_ownership_is_exclusive_while_live_ipv6_keeps_the_packet_task() {
    let platform = Arc::new(InMemoryPlatform::new());
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCoreConfig("capture-dns-ownership")))
        .build()
        .unwrap();
    let mut spec = packet_spec();
    spec.platform.packet_capture.as_mut().unwrap().install_dns = true;
    let runtime = sdk.create_runtime(spec).await.unwrap();
    let start = runtime.start().await.unwrap();
    let unresolved = store.list_unresolved().await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert!(unresolved[0]
        .checkpoint
        .leases
        .contains(&PlatformLeaseKey::system_dns()));
    let dns = sdk
        .create_runtime(
            RuntimeSpec::new(
                RuntimeId::new(),
                RuntimePlatformSpec {
                    dns: Some(egrio_runtime::DnsSettings {
                        servers: Vec::new(),
                        search_domains: Vec::new(),
                    }),
                    ..RuntimePlatformSpec::default()
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        dns.start().await,
        Err(egrio_runtime::RuntimeStartError::LeaseConflict(_))
    ));
    let report = runtime
        .configure(
            egrio_runtime::RuntimeConfigurationChange::Policy(
                egrio_core::CorePolicyUpdate::Ipv6Enabled(true),
            ),
            || Ok(()),
        )
        .await;
    assert_eq!(report.phase, egrio_runtime::ConfigurationPhase::Applied);
    assert_eq!(runtime.status().generation, start.generation);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert!(runtime.take_packet_report().is_none());
    runtime.stop().await.unwrap();
    assert!(store.list_unresolved().await.unwrap().is_empty());
    dns.start().await.unwrap();
    dns.stop().await.unwrap();
}

#[tokio::test]
async fn runtime_owns_packet_device_and_joins_it_before_restore() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let data_plane = Arc::new(RecordingDataPlane {
        events: events.clone(),
    });
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform)
        .packet_data_plane(data_plane)
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();

    runtime.start().await.unwrap();
    runtime.stop().await.unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "capture.prepare",
            "capture.open",
            "data-plane.ready",
            "data-plane.stop",
            "capture.restore",
        ]
    );
}

#[tokio::test]
async fn runtime_start_inputs_capture_policy_reaches_virtual_tcp_dns_on_the_shared_packet_core() {
    let platform = Arc::new(InMemoryPlatform::new());
    let dns_server = Ipv4Addr::new(198, 18, 0, 1);
    let inputs = FixedCoreConfig::new(fake_ip_direct_profile()).with_capture(
        egrio_core::NativeCoreCaptureConfig::with_dns_hijack(
            egrio_core::NativeCoreDnsHijackConfig::capture_udp_port_with_virtual_tcp_targets(
                53,
                [IpAddr::V4(dns_server)],
            ),
        ),
    );
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .core_config(Arc::new(inputs))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();
    let client = Ipv4Addr::new(198, 18, 0, 2);
    let mut cursor = 0;
    // Arbitrary UDP/53 remains intercepted in the combined mode.
    emit_packet(
        &platform,
        "combined-udp",
        ipv4_udp_packet(
            client,
            Ipv4Addr::new(8, 8, 8, 8),
            53123,
            53,
            &dns_query(0x6789, "shared-runtime.test", 1),
        ),
    );
    let udp = wait_for_written_packet(&platform, &mut cursor, |packet| {
        is_dns_answer_to(packet, 53123)
    })
    .await;
    let udp_fake = first_a_answer(ipv4_udp_payload(&udp)).unwrap();
    // Complete a real packet-level TCP handshake to the virtual resolver.
    let port = 53124;
    let isn = 1000;
    emit_packet(
        &platform,
        "combined-syn",
        captured_ipv4_tcp_packet(client, dns_server, port, 53, isn, 0, 0x02, &[]),
    );
    let syn_ack = wait_for_written_packet(&platform, &mut cursor, |packet| {
        captured_tcp_flags(&packet) & 0x12 == 0x12
    })
    .await;
    let server_isn = captured_tcp_sequence_number(&syn_ack);
    assert_eq!(ipv4_source(&syn_ack), dns_server);
    emit_packet(
        &platform,
        "combined-ack",
        captured_ipv4_tcp_packet(
            client,
            dns_server,
            port,
            53,
            isn + 1,
            server_isn + 1,
            0x10,
            &[],
        ),
    );
    let query = dns_query(0x789a, "shared-runtime.test", 1);
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    emit_packet(
        &platform,
        "combined-query",
        captured_ipv4_tcp_packet(
            client,
            dns_server,
            port,
            53,
            isn + 1,
            server_isn + 1,
            0x18,
            &framed,
        ),
    );
    let response = wait_for_written_packet(&platform, &mut cursor, |packet| {
        let bytes = captured_tcp_payload(&packet);
        bytes.len() > 14 && bytes[2..4] == 0x789au16.to_be_bytes()
    })
    .await;
    let payload = captured_tcp_payload(&response);
    assert_eq!(
        usize::from(u16::from_be_bytes([payload[0], payload[1]])),
        payload.len() - 2
    );
    assert_eq!(
        first_a_answer(&payload[2..]),
        Some(udp_fake),
        "UDP and TCP DNS share the same Runtime fake-IP map"
    );
    assert_eq!(runtime.core_state_audit().unwrap().fake_dns_entries, 1);
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().unwrap();
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
    assert_eq!(report.packets_received, 4);
}

#[tokio::test]
async fn runtime_packet_dns_fake_ip_reaches_the_same_core_captured_tcp_path() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = b"fake-ip-runtime-request";
    let response = b"fake-ip-runtime-response";
    let target = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback target");
    let target_addr = target.local_addr().expect("target address");
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("accept captured flow");
        let mut received = vec![0_u8; request.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("read captured request");
        observed_tx.send(received).ok();
        stream
            .write_all(response)
            .await
            .expect("write captured response");
        let _ = release_rx.await;
    });

    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(FixedCoreConfig::new(fake_ip_direct_profile())))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let dns_server = Ipv4Addr::new(1, 1, 1, 1);
    let mut written_cursor = 0;
    emit_packet(
        &platform,
        "dns",
        ipv4_udp_packet(
            client_ip,
            dns_server,
            53_000,
            53,
            &dns_query(0x4567, "127.0.0.1", 1),
        ),
    );
    let dns_response = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        is_dns_answer_to(packet, 53_000)
    })
    .await;
    let dns_payload = ipv4_udp_payload(&dns_response);
    assert_eq!(u16::from_be_bytes([dns_payload[0], dns_payload[1]]), 0x4567);
    let fake_ip = first_a_answer(dns_payload).expect("fake-IP A answer");
    assert_eq!(fake_ip.octets()[0], 198);
    assert!(matches!(fake_ip.octets()[1], 18 | 19));
    assert_eq!(
        runtime
            .core_state_audit()
            .expect("running core audit")
            .fake_dns_entries,
        1
    );

    let client_port = 53_124;
    let client_isn = 1_000_u32;
    emit_packet(
        &platform,
        "tcp-syn",
        captured_ipv4_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn,
            0,
            0x02,
            &[],
        ),
    );
    let syn_ack = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        captured_tcp_flags(&packet) & 0x12 == 0x12
    })
    .await;
    assert_eq!(ipv4_source(&syn_ack), fake_ip);
    assert_eq!(captured_tcp_acknowledgment_number(&syn_ack), client_isn + 1);
    let server_isn = captured_tcp_sequence_number(&syn_ack);

    emit_packet(
        &platform,
        "tcp-ack",
        captured_ipv4_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn + 1,
            server_isn + 1,
            0x10,
            &[],
        ),
    );
    emit_packet(
        &platform,
        "tcp-data",
        captured_ipv4_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn + 1,
            server_isn + 1,
            0x18,
            request,
        ),
    );
    let response_packet = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        captured_tcp_payload(&packet) == response
    })
    .await;
    assert_eq!(ipv4_source(&response_packet), fake_ip);
    assert_eq!(
        observed_rx.await.expect("target observed request"),
        request,
        "the fake-IP reverse map dialed the loopback target"
    );

    let telemetry = runtime
        .traffic_telemetry_snapshot()
        .expect("running packet runtime telemetry");
    let connection = telemetry
        .connections
        .iter()
        .find(|connection| connection.inbound == "tun")
        .expect("captured TCP connection row");
    assert_eq!(&*connection.outbound, "DIRECT");
    assert_eq!(connection.source.as_deref(), Some("10.0.0.2:53124"));
    assert_eq!(
        *connection.destination,
        SocketAddr::new(IpAddr::V4(fake_ip), target_addr.port()).to_string()
    );
    assert_eq!(connection.host.as_deref(), Some("127.0.0.1"));

    release_tx.send(()).ok();
    target_task.await.expect("target task joins");
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().expect("packet run report");
    assert_eq!(report.packets_received, 4);
    assert_eq!(report.packets_action_dns_capture, 1);
    assert_eq!(report.packets_captured_tcp, 3);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}

#[tokio::test]
async fn runtime_packet_dns_fake_ipv6_reaches_the_same_core_captured_tcp_path() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = b"fake-ipv6-runtime-request";
    let response = b"fake-ipv6-runtime-response";
    let target = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback target");
    let target_addr = target.local_addr().expect("target address");
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("accept captured flow");
        let mut received = vec![0_u8; request.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("read captured request");
        observed_tx.send(received).ok();
        stream
            .write_all(response)
            .await
            .expect("write captured response");
        let _ = release_rx.await;
    });

    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(FixedCoreConfig::with_ipv6(
            fake_ip_direct_profile(),
        )))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    let dns_client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let dns_server = Ipv4Addr::new(1, 1, 1, 1);
    let mut written_cursor = 0;
    emit_packet(
        &platform,
        "dns-v6",
        ipv4_udp_packet(
            dns_client_ip,
            dns_server,
            53_001,
            53,
            &dns_query(0x4568, "127.0.0.1", 28),
        ),
    );
    let dns_response = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        is_dns_answer_to(packet, 53_001)
    })
    .await;
    let dns_payload = ipv4_udp_payload(&dns_response);
    assert_eq!(u16::from_be_bytes([dns_payload[0], dns_payload[1]]), 0x4568);
    let fake_ip = first_aaaa_answer(dns_payload).expect("fake-IP AAAA answer");
    assert_eq!(fake_ip.segments()[0], 0xfd11);
    assert_eq!(fake_ip.segments()[1], 0x5ca1);
    assert_eq!(fake_ip.segments()[2], 0xab1e);
    assert_eq!(fake_ip.segments()[3], 1);
    assert_eq!(
        runtime
            .core_state_audit()
            .expect("running core audit")
            .fake_dns_entries,
        1
    );

    let client_ip = Ipv6Addr::new(0xfd11, 0x5ca1, 0xab1e, 0, 0, 0, 0, 2);
    let client_port = 53_125;
    let client_isn = 2_000_u32;
    emit_packet(
        &platform,
        "tcp-v6-syn",
        captured_ipv6_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn,
            0,
            0x02,
            &[],
        ),
    );
    let syn_ack = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        captured_tcp_flags(&packet) & 0x12 == 0x12
    })
    .await;
    assert_eq!(ipv6_source(&syn_ack), fake_ip);
    assert_eq!(captured_tcp_acknowledgment_number(&syn_ack), client_isn + 1);
    let server_isn = captured_tcp_sequence_number(&syn_ack);

    emit_packet(
        &platform,
        "tcp-v6-ack",
        captured_ipv6_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn + 1,
            server_isn + 1,
            0x10,
            &[],
        ),
    );
    emit_packet(
        &platform,
        "tcp-v6-data",
        captured_ipv6_tcp_packet(
            client_ip,
            fake_ip,
            client_port,
            target_addr.port(),
            client_isn + 1,
            server_isn + 1,
            0x18,
            request,
        ),
    );
    let response_packet = wait_for_written_packet(&platform, &mut written_cursor, |packet| {
        captured_tcp_payload(&packet) == response
    })
    .await;
    assert_eq!(ipv6_source(&response_packet), fake_ip);
    assert_eq!(
        observed_rx.await.expect("target observed request"),
        request,
        "the fake-v6 reverse map dialed the loopback target"
    );

    let telemetry = runtime
        .traffic_telemetry_snapshot()
        .expect("running packet runtime telemetry");
    let connection = telemetry
        .connections
        .iter()
        .find(|connection| connection.inbound == "tun")
        .expect("captured IPv6 TCP connection row");
    assert_eq!(&*connection.outbound, "DIRECT");
    assert_eq!(
        connection.source.as_deref(),
        Some(
            SocketAddr::new(IpAddr::V6(client_ip), client_port)
                .to_string()
                .as_str()
        )
    );
    assert_eq!(
        *connection.destination,
        SocketAddr::new(IpAddr::V6(fake_ip), target_addr.port()).to_string()
    );
    assert_eq!(connection.host.as_deref(), Some("127.0.0.1"));

    release_tx.send(()).ok();
    target_task.await.expect("target task joins");
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().expect("packet run report");
    assert_eq!(report.packets_received, 4);
    assert_eq!(report.packets_action_dns_capture, 1);
    assert_eq!(report.packets_captured_tcp, 3);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}

#[tokio::test]
async fn runtime_is_the_live_packet_telemetry_control_surface() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform)
        .packet_data_plane(Arc::new(RecordingDataPlane { events }))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();

    assert!(runtime.traffic_telemetry_snapshot().is_none());
    runtime.start().await.unwrap();

    // Relay one flow through the generation Core's listener: an upstream
    // target, a CONNECT through the bound listener, one byte each way.
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut server, _) = upstream.accept().await.unwrap();
        let mut buffer = [0_u8; 4];
        let read = server.read(&mut buffer).await.unwrap();
        server.write_all(&buffer[..read]).await.unwrap();
    });
    let listener_addr = runtime
        .core_status()
        .listen_addr
        .expect("running Runtime Core listener");
    let mut client = tokio::net::TcpStream::connect(&listener_addr)
        .await
        .unwrap();
    client
        .write_all(format!("CONNECT {upstream_addr} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let read = client.read(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response[..read]).starts_with("HTTP/1.1 200"));
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    upstream_task.await.unwrap();

    // The exit gate: the listener-relayed flow is visible through the packet
    // telemetry surface, because the listener session and the packet data
    // plane share the one generation Core.
    let telemetry = runtime
        .traffic_telemetry_snapshot()
        .expect("running Runtime exposes packet telemetry");
    let relayed = telemetry
        .connections
        .iter()
        .find(|connection| connection.inbound == "http-connect")
        .expect("the listener flow appears in the packet telemetry snapshot");
    let listener_view = runtime.core_traffic_telemetry_snapshot().await;
    assert!(
        listener_view
            .connections
            .iter()
            .any(|connection| connection.id.ends_with(&*relayed.id)),
        "the listener surface serves the same registry row (generation-prefixed)"
    );

    drop(client);
    runtime.stop().await.unwrap();
    assert!(runtime.traffic_telemetry_snapshot().is_none());
}

/// The pump stops only through its cancellation token, which never fails
/// the device; a fatal exit at stop is a genuine data-plane failure. The stop
/// fails — but the run report is still kept for diagnosis.
#[tokio::test]
async fn fatal_exit_at_stop_fails_the_stop_but_keeps_the_report() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(Arc::new(FatalAtTeardownDataPlane))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    let error = runtime
        .stop()
        .await
        .expect_err("a genuine data-plane failure must fail the stop");
    assert!(matches!(
        error,
        egrio_runtime::RuntimeStopError::Capability(_)
    ));

    let report = runtime
        .take_packet_report()
        .expect("the run report survives a failed stop");
    assert_eq!(report.packets_received, 42);
    assert_eq!(
        report.fatal_error.as_deref(),
        Some("shared packet ring failed: Cancelled")
    );
}

#[tokio::test]
async fn failed_reload_does_not_stop_unchanged_packet_capture() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let data_plane = Arc::new(RecordingDataPlane {
        events: events.clone(),
    });
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(data_plane)
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(packet_and_proxy_spec(7890))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    events.lock().unwrap().clear();
    platform.fail_next_apply(egrio_runtime::CapabilityKind::SystemProxy, "reload failure");

    assert!(matches!(
        runtime
            .reload(packet_and_proxy_spec(7891))
            .await
            .unwrap_err(),
        RuntimeReloadError::Capability { .. }
    ));
    assert!(events.lock().unwrap().is_empty());

    runtime.stop().await.unwrap();
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["data-plane.stop", "capture.restore"]
    );
}

fn excluding(mut spec: RuntimeSpec, prefixes: &[&str]) -> RuntimeSpec {
    spec.platform
        .packet_capture
        .as_mut()
        .unwrap()
        .excluded_prefixes = prefixes
        .iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();
    spec
}

#[tokio::test]
async fn the_open_capture_takes_new_exclusions_in_place_and_gives_them_back_on_failure() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(RecordingDataPlane {
            events: events.clone(),
        }))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(packet_and_proxy_spec(7890))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    let excluded = |platform: &InMemoryPlatform| {
        platform
            .packet_capture_settings()
            .unwrap()
            .excluded_prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    events.lock().unwrap().clear();

    let lan = excluding(packet_and_proxy_spec(7890), &["192.168.0.0/16"]);
    assert!(runtime.reload(lan.clone()).await.unwrap().committed);
    assert_eq!(events.lock().unwrap().as_slice(), ["capture.update"]);
    assert_eq!(excluded(&platform), ["192.168.0.0/16"]);

    // A later capability failing hands the capture its previous exclusions.
    events.lock().unwrap().clear();
    platform.fail_next_apply(egrio_runtime::CapabilityKind::SystemProxy, "reload failure");
    let error = runtime
        .reload(excluding(packet_and_proxy_spec(7891), &["10.0.0.0/8"]))
        .await
        .unwrap_err();
    assert!(matches!(error, RuntimeReloadError::Capability { .. }));
    assert_eq!(excluded(&platform), ["192.168.0.0/16"]);
    assert_eq!(runtime.spec(), lan);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["capture.update", "capture.update"]
    );

    // Anything else about an open capture still needs a stop/start.
    let mut redirected = lan.clone();
    redirected
        .platform
        .packet_capture
        .as_mut()
        .unwrap()
        .install_dns = true;
    assert!(matches!(
        runtime.reload(redirected).await.unwrap_err(),
        RuntimeReloadError::UnsupportedSpec(_)
    ));

    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn core_only_runtime_arms_health_only_after_remote_capability_reload() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform)
        .packet_data_plane(Arc::new(RecordingDataPlane { events }))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .connection_health(Arc::new(ManualConnectionHealth {
            disconnected: disconnect_rx,
        }))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(core_only_packet_runtime_spec())
        .await
        .unwrap();
    runtime.start().await.unwrap();

    disconnect_tx.send_replace(true);
    settle().await;
    assert_eq!(runtime.status().state, RuntimeState::Running);

    runtime.reload(packet_spec()).await.unwrap();
    assert!(eventually(|| runtime.status().state == RuntimeState::Degraded).await);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn reload_to_core_only_cancels_the_remote_health_watcher() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform)
        .packet_data_plane(Arc::new(RecordingDataPlane { events }))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .connection_health(Arc::new(ManualConnectionHealth {
            disconnected: disconnect_rx,
        }))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(core_only_packet_runtime_spec())
        .await
        .unwrap();
    runtime.start().await.unwrap();
    runtime.reload(packet_spec()).await.unwrap();
    runtime
        .reload(core_only_packet_runtime_spec())
        .await
        .unwrap();

    disconnect_tx.send_replace(true);
    settle().await;
    assert_eq!(runtime.status().state, RuntimeState::Running);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn disconnect_degrades_once_and_retains_recovery_state() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let data_plane = Arc::new(RecordingDataPlane {
        events: events.clone(),
    });
    let store = Arc::new(InMemoryCheckpointStore::new());
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform)
        .packet_data_plane(data_plane)
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .connection_health(Arc::new(ManualConnectionHealth {
            disconnected: disconnect_rx,
        }))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    // The loss is announced once the degrade is complete, checkpoint
    // included; the state and the data plane's stop come before it.
    let mut losses = runtime.subscribe_session_loss();
    disconnect_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), losses.changed())
        .await
        .expect("the lost session degrades the Runtime")
        .unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(events.lock().unwrap().last(), Some(&"data-plane.stop"));
    assert!(!events.lock().unwrap().contains(&"capture.restore"));
    let unresolved = store.list_unresolved().await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(
        unresolved[0].checkpoint.phase,
        CheckpointPhase::RecoveryRequired
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
        PlatformLeaseState::RecoveryRequired
    );

    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(events.lock().unwrap().last(), Some(&"capture.restore"));
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

/// The system proxy and the Core alone: what a lost platform session leaves
/// of `packet_and_proxy_spec`.
fn proxy_only_spec(port: u16) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(902)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            system_proxy: Some(egrio_runtime::SystemProxySpec::from_settings(
                egrio_runtime::SystemProxySettings {
                    http_proxy: Some(([127, 0, 0, 1], port).into()),
                    https_proxy: None,
                    bypass: Vec::new(),
                },
            )),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

async fn degraded_by_session_loss(
    platform: Arc<InMemoryPlatform>,
    events: Arc<Mutex<Vec<&'static str>>>,
) -> (
    EgrioSdk,
    Arc<egrio_runtime::Runtime>,
    Arc<InMemoryCheckpointStore>,
    tokio::sync::watch::Sender<bool>,
) {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform)
        .packet_data_plane(Arc::new(RecordingDataPlane { events }))
        .core_config(Arc::new(TestCoreConfig("packet-test")))
        .connection_health(Arc::new(ManualConnectionHealth {
            disconnected: disconnect_rx,
        }))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(packet_and_proxy_spec(7890))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    let mut losses = runtime.subscribe_session_loss();
    disconnect_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), losses.changed())
        .await
        .expect("the lost session degrades the Runtime")
        .unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    (sdk, runtime, store, disconnect_tx)
}

/// A lost platform session takes only its own capabilities with it: the
/// degraded reload restores those and keeps the system proxy, its lease and
/// the Core generation; an ordinary reload then adds the session back.
#[tokio::test]
async fn a_lost_platform_session_restores_only_its_capabilities() {
    use egrio_runtime::SystemProxyControl;

    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let (sdk, runtime, store, disconnect_tx) =
        degraded_by_session_loss(platform.clone(), events.clone()).await;
    let core = runtime.core_status();

    runtime.reload(proxy_only_spec(7890)).await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert!(events.lock().unwrap().contains(&"capture.restore"));
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active,
        "the system proxy did not live in the session and stays applied"
    );
    assert_eq!(runtime.core_status().started_at_unix, core.started_at_unix);
    let unresolved = store.list_unresolved().await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].checkpoint.phase, CheckpointPhase::Committed);
    assert_eq!(
        unresolved[0].checkpoint.leases,
        vec![PlatformLeaseKey::system_proxy()]
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
        PlatformLeaseState::Available
    );

    // The platform is back: an ordinary reload adds the session again.
    disconnect_tx.send_replace(false);
    runtime.reload(packet_and_proxy_spec(7890)).await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(runtime.core_status().started_at_unix, core.started_at_unix);
    runtime.stop().await.unwrap();
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

/// Once a transaction has touched the capabilities after the loss, nothing
/// vouches for the system proxy any more: the degraded reload may only
/// shrink to the Core.
#[tokio::test]
async fn a_touched_session_loss_no_longer_keeps_the_system_proxy() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let (_sdk, runtime, _store, _disconnect_tx) =
        degraded_by_session_loss(platform.clone(), events).await;

    platform.fail_next_restore(
        egrio_runtime::CapabilityKind::SystemProxy,
        "restore interrupted",
    );
    runtime.stop().await.unwrap_err();
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    let error = runtime.reload(proxy_only_spec(7890)).await.unwrap_err();
    assert!(
        matches!(error, RuntimeReloadError::UnsupportedSpec(_)),
        "{error}"
    );
    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[derive(Debug, Clone, Copy)]
enum ControlledPacketExit {
    Fatal,
    Error,
    Panic,
    Clean,
}

#[derive(Debug)]
struct ControlledPacketPlane {
    runs: tokio::sync::mpsc::UnboundedSender<tokio::sync::oneshot::Sender<ControlledPacketExit>>,
}

impl PacketDataPlane for ControlledPacketPlane {
    fn run(
        &self,
        _core: egrio_core::NativeCoreDevice,
        _queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        let runs = self.runs.clone();
        Box::pin(async move {
            let (finish, waiting) = tokio::sync::oneshot::channel();
            runs.send(finish).unwrap();
            let exit = tokio::select! {
                biased;
                exit = waiting => exit.unwrap_or(ControlledPacketExit::Clean),
                _ = stop.cancelled() => return Ok(egrio_core::NativeCoreDeviceRunReport { shutdown_requested: true, ..Default::default() }),
            };
            match exit {
                ControlledPacketExit::Fatal => Ok(egrio_core::NativeCoreDeviceRunReport {
                    packets_received: 17,
                    packets_written: 13,
                    fatal_error: Some("packet device failed while running".into()),
                    last_error: Some("packet device failed while running".into()),
                    ..Default::default()
                }),
                ControlledPacketExit::Error => Err("packet worker returned an error".into()),
                ControlledPacketExit::Panic => panic!("packet worker panicked while running"),
                ControlledPacketExit::Clean => Ok(egrio_core::NativeCoreDeviceRunReport::default()),
            }
        })
    }
}

#[tokio::test]
async fn unexpected_packet_completion_degrades_and_preserves_recoverable_ownership() {
    for exit in [
        ControlledPacketExit::Fatal,
        ControlledPacketExit::Error,
        ControlledPacketExit::Panic,
        ControlledPacketExit::Clean,
    ] {
        let platform = Arc::new(InMemoryPlatform::new());
        let store = Arc::new(InMemoryCheckpointStore::new());
        let (runs, mut started) = tokio::sync::mpsc::unbounded_channel();
        let sdk = EgrioSdk::builder()
            .checkpoint_store(store.clone())
            .platform(platform)
            .packet_data_plane(Arc::new(ControlledPacketPlane { runs }))
            .core_config(Arc::new(TestCoreConfig("packet-supervision")))
            .build()
            .unwrap();
        let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
        runtime.start().await.unwrap();
        started.recv().await.unwrap().send(exit).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let unresolved = store.list_unresolved().await.unwrap();
                if runtime.status().state == RuntimeState::Degraded
                    && unresolved[0].checkpoint.phase == CheckpointPhase::RecoveryRequired
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completion actively degrades the Runtime");
        assert!(runtime.status().degradation_error.is_some());
        assert_eq!(
            sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
            PlatformLeaseState::RecoveryRequired
        );
        assert!(runtime.traffic_telemetry_snapshot().is_none());
        let report = runtime
            .take_packet_report()
            .expect("report is available before stop");
        match exit {
            ControlledPacketExit::Fatal => {
                assert_eq!(report.packets_received, 17);
                assert_eq!(report.packets_written, 13);
                assert_eq!(
                    report.fatal_error.as_deref(),
                    Some("packet device failed while running")
                );
            }
            ControlledPacketExit::Error => assert_eq!(
                report.fatal_error.as_deref(),
                Some("packet worker returned an error")
            ),
            ControlledPacketExit::Panic => assert!(report
                .fatal_error
                .as_deref()
                .unwrap()
                .contains("packet worker panicked while running")),
            ControlledPacketExit::Clean => assert!(report.fatal_error.is_none()),
        }
        runtime
            .stop()
            .await
            .expect("an already-ended worker must not prevent OS restoration");
        assert_eq!(runtime.status().state, RuntimeState::Stopped);
        assert!(store.list_unresolved().await.unwrap().is_empty());
        assert!(
            runtime.take_packet_report().is_none(),
            "stop must not republish an already-consumed completion report"
        );
        // A fresh generation has a fresh worker; queued old notifications must
        // not degrade it or carry the old report into it.
        runtime.start().await.unwrap();
        let _running = started.recv().await.unwrap();
        settle().await;
        assert_eq!(runtime.status().state, RuntimeState::Running);
        assert!(runtime.take_packet_report().is_none());
        runtime.stop().await.unwrap();
    }
}

/// A packet data plane ends on its own only when the session behind it did,
/// so its exit reports a lost session like a dropped service connection: the
/// degraded reload keeps the system proxy and the Core generation.
#[tokio::test]
async fn an_unexpected_packet_exit_reports_a_lost_platform_session() {
    use egrio_runtime::SystemProxyControl;

    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let (runs, mut started) = tokio::sync::mpsc::unbounded_channel();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(ControlledPacketPlane { runs }))
        .core_config(Arc::new(TestCoreConfig("packet-session-loss")))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(packet_and_proxy_spec(7890))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    let core = runtime.domain_status().core.unwrap().generation;
    let mut losses = runtime.subscribe_session_loss();

    started
        .recv()
        .await
        .unwrap()
        .send(ControlledPacketExit::Error)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), losses.changed())
        .await
        .expect("the ended data plane reports a lost session")
        .unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Degraded);

    runtime.reload(proxy_only_spec(7890)).await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert!(events.lock().unwrap().contains(&"capture.restore"));
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(runtime.domain_status().core.unwrap().generation, core);

    runtime.reload(packet_and_proxy_spec(7890)).await.unwrap();
    let _running = started.recv().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.domain_status().core.unwrap().generation, core);
    runtime.stop().await.unwrap();
}

#[derive(Debug)]
struct ImmediatePacketFailure;
impl PacketDataPlane for ImmediatePacketFailure {
    fn run(
        &self,
        _: egrio_core::NativeCoreDevice,
        _: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        _: CancellationToken,
    ) -> PacketDataPlaneFuture {
        Box::pin(async {
            Ok(egrio_core::NativeCoreDeviceRunReport {
                packets_received: 3,
                fatal_error: Some("packet startup failed".into()),
                ..Default::default()
            })
        })
    }
}

#[tokio::test]
async fn packet_startup_completion_rolls_back_and_keeps_the_original_report() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(Arc::new(InMemoryPlatform::with_event_log(events.clone())))
        .packet_data_plane(Arc::new(ImmediatePacketFailure))
        .core_config(Arc::new(TestCoreConfig("packet-start-failure")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    let error = runtime.start().await.unwrap_err();
    assert!(error.to_string().contains("packet startup failed"));
    assert_eq!(runtime.status().state, RuntimeState::Created);
    assert!(events.lock().unwrap().contains(&"capture.restore"));
    assert!(store.list_unresolved().await.unwrap().is_empty());
    let report = runtime.take_packet_report().unwrap();
    assert_eq!(report.packets_received, 3);
    assert_eq!(report.fatal_error.as_deref(), Some("packet startup failed"));
}

#[derive(Debug, Default)]
struct CommitBarrierStore {
    inner: InMemoryCheckpointStore,
    committing: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl CheckpointStore for CommitBarrierStore {
    fn create<'a>(
        &'a self,
        checkpoint: egrio_runtime::RecoveryCheckpoint,
    ) -> egrio_runtime::CheckpointFuture<'a, egrio_runtime::StoredCheckpoint> {
        self.inner.create(checkpoint)
    }
    fn get<'a>(
        &'a self,
        id: egrio_runtime::CheckpointId,
    ) -> egrio_runtime::CheckpointFuture<'a, Option<egrio_runtime::StoredCheckpoint>> {
        self.inner.get(id)
    }
    fn replace<'a>(
        &'a self,
        expected: egrio_runtime::CheckpointRevision,
        checkpoint: egrio_runtime::RecoveryCheckpoint,
    ) -> egrio_runtime::CheckpointFuture<'a, egrio_runtime::StoredCheckpoint> {
        Box::pin(async move {
            if checkpoint.phase == CheckpointPhase::Committed {
                self.committing.notify_one();
                self.release.notified().await;
            }
            self.inner.replace(expected, checkpoint).await
        })
    }
    fn list_unresolved<'a>(
        &'a self,
    ) -> egrio_runtime::CheckpointFuture<'a, Vec<egrio_runtime::StoredCheckpoint>> {
        self.inner.list_unresolved()
    }
    fn delete<'a>(
        &'a self,
        id: egrio_runtime::CheckpointId,
        expected: egrio_runtime::CheckpointRevision,
    ) -> egrio_runtime::CheckpointFuture<'a, ()> {
        self.inner.delete(id, expected)
    }
}

#[tokio::test]
async fn packet_exit_during_start_commit_uses_the_same_rollback_as_apply_failure() {
    let store = Arc::new(CommitBarrierStore::default());
    let (runs, mut started) = tokio::sync::mpsc::unbounded_channel();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(Arc::new(ControlledPacketPlane { runs }))
        .core_config(Arc::new(TestCoreConfig("packet-commit-failure")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    let starting = runtime.clone();
    let start = tokio::spawn(async move { starting.start().await });
    store.committing.notified().await;
    started
        .recv()
        .await
        .unwrap()
        .send(ControlledPacketExit::Fatal)
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(report) = runtime.take_packet_report() {
                break report;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker completion is visible while the commit is held");
    assert_eq!(report.packets_received, 17);
    store.release.notify_one();
    let error = start.await.unwrap().unwrap_err();
    assert!(error
        .to_string()
        .contains("packet device failed while running"));
    assert_eq!(runtime.status().state, RuntimeState::Created);
    assert_eq!(runtime.status().generation.get(), 0);
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
        PlatformLeaseState::Available
    );
    assert!(runtime.take_packet_report().is_none());
}

#[tokio::test]
async fn restart_keeps_the_previous_workers_unconsumed_report() {
    let platform = Arc::new(InMemoryPlatform::new());
    let store = Arc::new(InMemoryCheckpointStore::new());
    let (runs, mut started) = tokio::sync::mpsc::unbounded_channel();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .packet_data_plane(Arc::new(ControlledPacketPlane { runs }))
        .core_config(Arc::new(TestCoreConfig("packet-closed-handle")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();
    started
        .recv()
        .await
        .unwrap()
        .send(ControlledPacketExit::Fatal)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.status().state != RuntimeState::Degraded {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert!(store.list_unresolved().await.unwrap().is_empty());
    runtime.start().await.unwrap();
    let _running = started.recv().await.unwrap();
    assert_eq!(
        runtime.take_packet_report().unwrap().fatal_error.as_deref(),
        Some("packet device failed while running"),
        "a restart must not erase the previous worker's unconsumed report"
    );
    runtime.stop().await.unwrap();
}
