//! Raw fragment regressions through the production Runtime-owned packet plane.
//! The capture device is memory-backed; only the UDP target uses a loopback
//! socket. No platform adapter, route, DNS or firewall setting is touched.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use egrio_core::{RuntimeProfile, TrafficConnectionProtocol, TrafficPolicyMode};
use egrio_runtime::{Runtime, RuntimeState};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use tokio::net::UdpSocket;

use super::{
    core_only_packet_runtime_spec, emit_packet, internet_checksum, ipv4_udp_packet, packet_spec,
    wait_for_written_packet, FixedCoreConfig,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub(super) fn client(self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::new(10, 23, 0, 2).into(),
            Self::Ipv6 => "fd00:23::2".parse().unwrap(),
        }
    }

    pub(super) fn loopback(self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::LOCALHOST.into(),
            Self::Ipv6 => Ipv6Addr::LOCALHOST.into(),
        }
    }

    pub(super) fn packet(self, client: SocketAddr, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        match (self, client.ip(), target.ip()) {
            (Self::Ipv4, IpAddr::V4(source), IpAddr::V4(destination)) => {
                ipv4_udp_packet(source, destination, client.port(), target.port(), payload)
            }
            (Self::Ipv6, IpAddr::V6(source), IpAddr::V6(destination)) => {
                let udp_len = 8 + payload.len();
                let mut packet = vec![0_u8; 40 + udp_len];
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                packet[6] = 17;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&source.octets());
                packet[24..40].copy_from_slice(&destination.octets());
                packet[40..42].copy_from_slice(&client.port().to_be_bytes());
                packet[42..44].copy_from_slice(&target.port().to_be_bytes());
                packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
                packet[48..].copy_from_slice(payload);
                let checksum = udp6_checksum(source, destination, &packet[40..]);
                packet[46..48]
                    .copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
                packet
            }
            _ => unreachable!("fragment fixture uses one address family"),
        }
    }

    /// Split at transport-relative byte offsets. Every non-final fragment is
    /// 8-byte aligned and the first fragment contains the entire UDP header.
    pub(super) fn fragments(self, packet: &[u8], cuts: &[usize], id: u32) -> Vec<Vec<u8>> {
        let header_len = match self {
            Self::Ipv4 => 20,
            Self::Ipv6 => 40,
        };
        let transport = &packet[header_len..];
        let mut offsets = vec![0];
        offsets.extend_from_slice(cuts);
        offsets.push(transport.len());
        offsets
            .windows(2)
            .enumerate()
            .map(|(index, range)| {
                let offset = range[0];
                let bytes = &transport[offset..range[1]];
                let more = index + 2 < offsets.len();
                assert_eq!(offset % 8, 0);
                assert!(!more || bytes.len() % 8 == 0);
                match self {
                    Self::Ipv4 => {
                        let mut fragment = packet[..20].to_vec();
                        fragment[2..4].copy_from_slice(&((20 + bytes.len()) as u16).to_be_bytes());
                        fragment[4..6].copy_from_slice(&(id as u16).to_be_bytes());
                        let flags_offset = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
                        fragment[6..8].copy_from_slice(&flags_offset.to_be_bytes());
                        fragment[10..12].fill(0);
                        let checksum = internet_checksum(fragment.iter().copied());
                        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
                        assert_eq!(internet_checksum(fragment.iter().copied()), 0);
                        fragment.extend_from_slice(bytes);
                        fragment
                    }
                    Self::Ipv6 => {
                        let mut fragment = packet[..40].to_vec();
                        fragment[4..6].copy_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
                        fragment[6] = 44; // RFC 8200 Fragment extension header.
                        fragment.extend_from_slice(&[17, 0]);
                        fragment
                            .extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
                        fragment.extend_from_slice(&id.to_be_bytes());
                        fragment.extend_from_slice(bytes);
                        fragment
                    }
                }
            })
            .collect()
    }
}

pub(super) fn udp6_checksum(source: Ipv6Addr, destination: Ipv6Addr, datagram: &[u8]) -> u16 {
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(datagram.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 17]);
    pseudo_header.extend_from_slice(datagram);
    internet_checksum(pseudo_header)
}

struct Fixture {
    _sdk: EgrioSdk,
    runtime: Arc<Runtime>,
    platform: Arc<InMemoryPlatform>,
    echo: UdpSocket,
    client: SocketAddr,
    target: SocketAddr,
    family: Family,
    cursor: usize,
}

impl Fixture {
    async fn new(family: Family) -> Self {
        let echo = UdpSocket::bind(SocketAddr::new(family.loopback(), 0))
            .await
            .unwrap();
        let target = echo.local_addr().unwrap();
        let platform = Arc::new(InMemoryPlatform::new());
        let mut profile = RuntimeProfile::new("runtime-fragment-loopback");
        profile.traffic_policy_mode = TrafficPolicyMode::Direct;
        let sdk = EgrioSdk::builder()
            .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
            .platform(platform.clone())
            .core_config(Arc::new(FixedCoreConfig::with_ipv6(profile)))
            .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
            .build()
            .unwrap();
        let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
        runtime.start().await.unwrap();
        Self {
            _sdk: sdk,
            runtime,
            platform,
            echo,
            client: SocketAddr::new(family.client(), 54_321),
            target,
            family,
            cursor: 0,
        }
    }

    fn emit(&self, id: &str, packet: Vec<u8>) {
        emit_packet(&self.platform, id, packet);
    }

    fn emit_whole(&self, id: &str, payload: &[u8]) {
        self.emit(id, self.family.packet(self.client, self.target, payload));
    }

    async fn assert_no_upstream_datagram(&self) {
        let mut buffer = [0_u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(40), self.echo.recv_from(&mut buffer))
                .await
                .is_err(),
            "incomplete fragments must not reach UDP egress"
        );
    }

    async fn receive_and_echo(&mut self, expected: &[u8]) {
        let mut buffer = [0_u8; 512];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(3), self.echo.recv_from(&mut buffer))
                .await
                .expect("reassembled datagram reaches the loopback UDP target")
                .unwrap();
        assert_eq!(&buffer[..length], expected);
        assert_eq!(
            self.echo.send_to(&buffer[..length], peer).await.unwrap(),
            expected.len()
        );
        let reply = wait_for_written_packet(&self.platform, &mut self.cursor, |packet| {
            response_payload(&packet, self.target, self.client) == Some(expected)
        })
        .await;
        validate_response(&reply, self.target, self.client, expected);
        assert_eq!(self.runtime.status().state, RuntimeState::Running);
    }

    async fn assert_same_core_telemetry(&self, payload_len: usize) {
        let telemetry = self.runtime.core_traffic_telemetry_snapshot().await;
        let connection = telemetry
            .connections
            .iter()
            .find(|connection| {
                connection.inbound == "tun"
                    && matches!(connection.protocol, TrafficConnectionProtocol::Udp)
                    && *connection.destination == self.target.to_string()
            })
            .expect("reassembled TUN UDP flow is visible on the Runtime generation Core");
        assert_eq!(&*connection.outbound, "DIRECT");
        assert_eq!(
            connection.source.as_deref(),
            Some(self.client.to_string().as_str())
        );
        assert!(connection.upload_bytes >= payload_len as u64);
        assert!(connection.download_bytes >= payload_len as u64);
    }
}

fn response_payload<'a>(
    packet: &'a [u8],
    source: SocketAddr,
    destination: SocketAddr,
) -> Option<&'a [u8]> {
    let header = match packet.first()? >> 4 {
        4 if packet.len() >= 28 && packet[9] == 17 => {
            if IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?) != source.ip()
                || IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?) != destination.ip()
            {
                return None;
            }
            usize::from(packet[0] & 0x0f) * 4
        }
        6 if packet.len() >= 48 && packet[6] == 17 => {
            if IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?) != source.ip()
                || IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?) != destination.ip()
            {
                return None;
            }
            40
        }
        _ => return None,
    };
    let udp = packet.get(header..)?;
    if udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != source.port()
        || u16::from_be_bytes([udp[2], udp[3]]) != destination.port()
    {
        return None;
    }
    udp.get(8..)
}

fn validate_response(packet: &[u8], source: SocketAddr, destination: SocketAddr, expected: &[u8]) {
    assert_eq!(
        response_payload(packet, source, destination),
        Some(expected)
    );
    let header = match packet[0] >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            assert_eq!(
                u16::from_be_bytes([packet[2], packet[3]]) as usize,
                packet.len()
            );
            assert_eq!(u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff, 0);
            assert_eq!(internet_checksum(packet[..header].iter().copied()), 0);
            header
        }
        6 => {
            assert_eq!(
                u16::from_be_bytes([packet[4], packet[5]]) as usize,
                packet.len() - 40
            );
            if let (IpAddr::V6(source), IpAddr::V6(destination)) = (source.ip(), destination.ip()) {
                assert_ne!(&packet[46..48], &[0, 0], "IPv6 UDP checksum is mandatory");
                assert_eq!(udp6_checksum(source, destination, &packet[40..]), 0);
            } else {
                panic!("response address family changed");
            }
            40
        }
        _ => unreachable!(),
    };
    assert_eq!(
        u16::from_be_bytes([packet[header + 4], packet[header + 5]]) as usize,
        8 + expected.len()
    );
}

async fn out_of_order_echo(family: Family) {
    let mut fixture = Fixture::new(family).await;
    let payload = (0..73).map(|value| (value * 7) as u8).collect::<Vec<_>>();
    let whole = fixture
        .family
        .packet(fixture.client, fixture.target, &payload);
    let fragments = fixture.family.fragments(&whole, &[24, 48], 0x1234_5678);
    fixture.emit("last-fragment-first", fragments[2].clone());
    fixture.emit("first-fragment-second", fragments[0].clone());
    fixture.assert_no_upstream_datagram().await;
    fixture.emit("middle-fragment-last", fragments[1].clone());
    fixture.receive_and_echo(&payload).await;
    fixture.assert_same_core_telemetry(payload.len()).await;
    fixture.assert_no_upstream_datagram().await;
    fixture.runtime.stop().await.unwrap();
    let report = fixture.runtime.take_packet_report().unwrap();
    assert_eq!(report.packets_received, 3);
    assert_eq!(report.packets_action_direct_udp, 1);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}

async fn stop_discards_partial_fragments(family: Family, retain_core: bool) {
    let mut fixture = Fixture::new(family).await;
    let payload =
        b"one logical UDP datagram must never combine fragments across two Runtime generations";
    let whole = fixture
        .family
        .packet(fixture.client, fixture.target, payload);
    let fragments = fixture.family.fragments(&whole, &[24], 0x5678_1234);
    let first_generation = fixture.runtime.status().generation;
    let first_core = fixture.runtime.domain_status().core.unwrap().generation;
    fixture.emit("old-first-fragment", fragments[0].clone());
    // This complete datagram is a FIFO barrier: seeing it at egress proves
    // the pump consumed the preceding partial fragment before stop.
    fixture.emit_whole("old-generation-barrier", b"old-generation-barrier");
    fixture.receive_and_echo(b"old-generation-barrier").await;
    if retain_core {
        fixture
            .runtime
            .reload(core_only_packet_runtime_spec())
            .await
            .unwrap();
        assert_eq!(
            fixture.runtime.domain_status().core.unwrap().generation,
            first_core
        );
    } else {
        fixture.runtime.stop().await.unwrap();
    }
    let first_report = fixture.runtime.take_packet_report().unwrap();
    assert_eq!(first_report.packets_received, 2);
    assert_eq!(first_report.packets_failed, 0);

    if retain_core {
        fixture.runtime.reload(packet_spec()).await.unwrap();
        assert_eq!(
            fixture.runtime.domain_status().core.unwrap().generation,
            first_core
        );
    } else {
        fixture.runtime.start().await.unwrap();
        assert_ne!(
            fixture.runtime.domain_status().core.unwrap().generation,
            first_core
        );
    }
    assert_ne!(fixture.runtime.status().generation, first_generation);
    fixture.cursor = fixture.platform.written_packets().len();
    fixture.emit("new-last-fragment", fragments[1].clone());
    fixture.emit_whole("new-generation-barrier", b"new-generation-barrier");
    fixture.receive_and_echo(b"new-generation-barrier").await;
    fixture.assert_no_upstream_datagram().await;
    // The tail can complete only after a fresh head arrives in this run.
    fixture.emit("new-first-fragment", fragments[0].clone());
    fixture.receive_and_echo(payload).await;
    fixture.assert_no_upstream_datagram().await;
    fixture.runtime.stop().await.unwrap();
    let second_report = fixture.runtime.take_packet_report().unwrap();
    assert_eq!(second_report.packets_received, 3);
    assert_eq!(second_report.packets_action_direct_udp, 2);
    assert_eq!(second_report.packets_failed, 0);
    assert_eq!(second_report.fatal_error, None);
}

#[tokio::test]
async fn ipv4_fragments_out_of_order_reach_runtime_udp_echo() {
    out_of_order_echo(Family::Ipv4).await;
}

#[tokio::test]
async fn ipv6_fragments_out_of_order_reach_runtime_udp_echo() {
    out_of_order_echo(Family::Ipv6).await;
}

#[tokio::test]
async fn ipv4_pending_fragments_do_not_cross_runtime_generations() {
    stop_discards_partial_fragments(Family::Ipv4, false).await;
}

#[tokio::test]
async fn ipv6_pending_fragments_do_not_cross_runtime_generations() {
    stop_discards_partial_fragments(Family::Ipv6, false).await;
}

#[tokio::test]
async fn ipv4_pending_fragments_do_not_cross_packet_reloads_with_the_same_core() {
    stop_discards_partial_fragments(Family::Ipv4, true).await;
}

#[tokio::test]
async fn ipv6_pending_fragments_do_not_cross_packet_reloads_with_the_same_core() {
    stop_discards_partial_fragments(Family::Ipv6, true).await;
}
