//! Production SDK/Runtime packet plane with memory-backed TUN I/O and real
//! loopback UDP egress. No platform routes, DNS, firewall or interfaces change.
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use egrio_core::{NativeCoreCaptureConfig, RuntimeProfile, TrafficPolicyMode};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use tokio::net::UdpSocket;

use super::fragments::{udp6_checksum, Family};
use super::{emit_packet, internet_checksum, packet_spec, FixedCoreConfig};

fn host_udp_payload_limit() -> usize {
    const COMMON_IP_MAX: usize = 65_507;
    #[cfg(target_os = "macos")]
    {
        // XNU udp_usrreq.c maps maxdgram to udp_sendspace and reserves that
        // budget on new sockets. Read the host's default; never change sysctl
        // or enlarge Core's private sockets just to make this test pass.
        let output = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "net.inet.udp.maxdgram"])
            .output()
            .expect("read-only macOS default UDP send budget");
        assert!(output.status.success());
        let maximum: usize = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .expect("numeric macOS UDP send budget");
        assert!(
            maximum >= 8192,
            "this host cannot exercise the required 8 KiB UDP case"
        );
        return maximum.min(COMMON_IP_MAX);
    }
    #[cfg(not(target_os = "macos"))]
    COMMON_IP_MAX
}

struct ReplyFragments {
    pieces: BTreeMap<usize, Vec<u8>>,
    fragment_id: Option<u32>,
    end: Option<usize>,
    raw_lengths: Vec<usize>,
}

impl ReplyFragments {
    fn new() -> Self {
        Self {
            pieces: BTreeMap::new(),
            fragment_id: None,
            end: None,
            raw_lengths: Vec::new(),
        }
    }

    fn push(
        &mut self,
        bytes: &[u8],
        mtu: usize,
        source: SocketAddr,
        client: SocketAddr,
        udp_len: usize,
    ) {
        assert!(
            bytes.len() <= mtu,
            "raw TUN response {} exceeds MTU {mtu}",
            bytes.len()
        );
        self.raw_lengths.push(bytes.len());
        let (offset, more, fragment_id, transport) = match (bytes[0] >> 4, source.ip(), client.ip())
        {
            (4, IpAddr::V4(source_ip), IpAddr::V4(client_ip)) => {
                assert!(bytes.len() >= 20);
                let header_len = usize::from(bytes[0] & 0x0f) * 4;
                assert!((20..=60).contains(&header_len));
                assert!(bytes.len() > header_len);
                assert_eq!(&bytes[12..16], &source_ip.octets());
                assert_eq!(&bytes[16..20], &client_ip.octets());
                assert_eq!(bytes[9], 17, "response must retain UDP protocol");
                assert_ne!(bytes[8], 0, "IPv4 TTL must remain valid");
                assert_eq!(
                    usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
                    bytes.len()
                );
                assert_eq!(internet_checksum(bytes[..header_len].iter().copied()), 0);
                let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
                assert_eq!(
                    flags & 0xc000,
                    0,
                    "generated fragments cannot carry reserved/DF flags"
                );
                (
                    usize::from(flags & 0x1fff) * 8,
                    flags & 0x2000 != 0,
                    Some(u32::from(u16::from_be_bytes([bytes[4], bytes[5]]))),
                    &bytes[header_len..],
                )
            }
            (6, IpAddr::V6(source_ip), IpAddr::V6(client_ip)) => {
                assert!(bytes.len() >= 40);
                assert_eq!(&bytes[8..24], &source_ip.octets());
                assert_eq!(&bytes[24..40], &client_ip.octets());
                assert_ne!(bytes[7], 0, "IPv6 hop limit must remain valid");
                assert_eq!(
                    usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                    bytes.len() - 40
                );
                if bytes[6] == 44 {
                    assert!(bytes.len() > 48);
                    assert_eq!(bytes[40], 17, "fragment header must point to UDP");
                    assert_eq!(bytes[41], 0, "fragment reserved byte must be zero");
                    let flags = u16::from_be_bytes([bytes[42], bytes[43]]);
                    assert_eq!(flags & 6, 0, "fragment reserved flag bits must be zero");
                    (
                        usize::from(flags & 0xfff8),
                        flags & 1 != 0,
                        Some(u32::from_be_bytes(bytes[44..48].try_into().unwrap())),
                        &bytes[48..],
                    )
                } else {
                    assert_eq!(bytes[6], 17, "unfragmented IPv6 reply must be UDP");
                    (0, false, None, &bytes[40..])
                }
            }
            _ => panic!("response address family differs from the original client/target"),
        };
        assert_eq!(offset % 8, 0);
        assert!(!transport.is_empty());
        assert!(
            offset + transport.len() <= udp_len,
            "fragment runs beyond the expected UDP datagram"
        );
        if more {
            assert_eq!(
                transport.len() % 8,
                0,
                "non-final fragment must be eight-byte aligned"
            );
        } else {
            assert_eq!(offset + transport.len(), udp_len);
            assert!(
                self.end.replace(offset + transport.len()).is_none(),
                "more than one final fragment"
            );
        }
        if let Some(id) = fragment_id {
            if let Some(first) = self.fragment_id {
                assert_eq!(
                    id, first,
                    "one reply datagram must use one fragment identification"
                );
            } else {
                self.fragment_id = Some(id);
            }
        }
        if let Some((previous_offset, previous)) = self.pieces.range(..offset).next_back() {
            assert!(
                *previous_offset + previous.len() <= offset,
                "overlapping response fragments"
            );
        }
        if let Some((next_offset, _)) = self.pieces.range(offset..).next() {
            assert!(
                offset + transport.len() <= *next_offset,
                "overlapping response fragments"
            );
        }
        assert!(
            self.pieces.insert(offset, transport.to_vec()).is_none(),
            "duplicate response fragment"
        );
    }

    fn complete(&self) -> Option<Vec<u8>> {
        let end = self.end?;
        let mut joined = Vec::with_capacity(end);
        for (offset, bytes) in &self.pieces {
            if *offset != joined.len() {
                return None;
            }
            joined.extend_from_slice(bytes);
        }
        (joined.len() == end).then_some(joined)
    }
}

async fn assert_response(
    platform: &InMemoryPlatform,
    mtu: usize,
    source: SocketAddr,
    client: SocketAddr,
    expected: &[u8],
) -> usize {
    let mut fragments = ReplyFragments::new();
    let mut cursor = 0;
    let datagram = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let written = platform.written_packets();
            for packet in written.iter().skip(cursor) {
                fragments.push(packet, mtu, source, client, expected.len() + 8);
            }
            cursor = written.len();
            if let Some(datagram) = fragments.complete() {
                break datagram;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("MTU-sized packet responses reassemble before timeout");
    assert!(
        fragments.raw_lengths.len() > 1,
        "large UDP reply must be fragmented at the configured MTU"
    );
    assert_eq!(
        u16::from_be_bytes([datagram[0], datagram[1]]),
        source.port()
    );
    assert_eq!(
        u16::from_be_bytes([datagram[2], datagram[3]]),
        client.port()
    );
    assert_eq!(
        usize::from(u16::from_be_bytes([datagram[4], datagram[5]])),
        expected.len() + 8
    );
    assert_eq!(
        &datagram[8..],
        expected,
        "fragment join must preserve every application byte"
    );
    match (source.ip(), client.ip()) {
        (IpAddr::V6(source), IpAddr::V6(client)) => {
            assert_ne!(&datagram[6..8], &[0, 0], "IPv6 UDP checksum is mandatory");
            assert_eq!(udp6_checksum(source, client, &datagram), 0);
        }
        (IpAddr::V4(source), IpAddr::V4(client)) if datagram[6..8] != [0, 0] => {
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&client.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(&datagram);
            assert_eq!(internet_checksum(pseudo), 0);
        }
        (IpAddr::V4(_), IpAddr::V4(_)) => {} // RFC 768 permits no IPv4 UDP checksum.
        _ => unreachable!(),
    }
    fragments.raw_lengths.len()
}

async fn exchange(family: Family, mtu: u32, payload_len: usize) {
    let echo = UdpSocket::bind(SocketAddr::new(family.loopback(), 0))
        .await
        .unwrap();
    let target = echo.local_addr().unwrap();
    let client = SocketAddr::new(family.client(), 54_177);
    let payload = (0..payload_len)
        .map(|index| (index * 31 + 17) as u8)
        .collect::<Vec<_>>();
    let mut profile = RuntimeProfile::new(format!("runtime-mtu-{family:?}-{mtu}-{payload_len}"));
    profile.traffic_policy_mode = TrafficPolicyMode::Direct;
    let mut config = FixedCoreConfig::with_ipv6(profile);
    config.capture = NativeCoreCaptureConfig::default().with_mtu(mtu).unwrap();
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .core_config(Arc::new(config))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let mut spec = packet_spec();
    spec.platform.packet_capture.as_mut().unwrap().mtu = mtu;
    let runtime = sdk.create_runtime(spec).await.unwrap();
    runtime.start().await.unwrap();
    let whole = family.packet(client, target, &payload);
    let header_len = match family {
        Family::Ipv4 => 20,
        Family::Ipv6 => 40,
    };
    let fragment_header = match family {
        Family::Ipv4 => 20,
        Family::Ipv6 => 48,
    };
    let per_fragment = (mtu as usize - fragment_header) & !7;
    let transport_len = whole.len() - header_len;
    let cuts = (per_fragment..transport_len)
        .step_by(per_fragment)
        .collect::<Vec<_>>();
    let requests = family.fragments(&whole, &cuts, 0x7182_93a4);
    let received_count = requests.len();
    for (index, packet) in requests.into_iter().enumerate().rev() {
        assert!(
            packet.len() <= mtu as usize,
            "input packet must also fit the simulated TUN MTU"
        );
        emit_packet(&platform, &format!("mtu-request-{index}"), packet);
    }
    let mut received = vec![0_u8; 65_536];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(5), echo.recv_from(&mut received))
            .await
            .expect("reassembled packet reaches real loopback UDP target")
            .unwrap();
    assert_eq!(&received[..length], &payload);
    assert_eq!(
        echo.send_to(&received[..length], peer).await.unwrap(),
        payload.len()
    );
    let response_count = assert_response(&platform, mtu as usize, target, client, &payload).await;
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().unwrap();
    assert_eq!(report.packets_received, received_count as u64);
    assert_eq!(report.packets_written, response_count as u64);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}

macro_rules! mtu_case {
    ($name:ident, $family:ident, $mtu:expr, $size:expr) => {
        #[tokio::test]
        async fn $name() {
            exchange(Family::$family, $mtu, $size).await;
        }
    };
}
mtu_case!(ipv4_mtu_1280_8k, Ipv4, 1280, 8192);
mtu_case!(ipv4_mtu_1420_8k, Ipv4, 1420, 8192);
mtu_case!(ipv4_mtu_1500_8k, Ipv4, 1500, 8192);
mtu_case!(ipv6_mtu_1280_8k, Ipv6, 1280, 8192);
mtu_case!(ipv6_mtu_1420_8k, Ipv6, 1420, 8192);
mtu_case!(ipv6_mtu_1500_8k, Ipv6, 1500, 8192);
mtu_case!(ipv4_mtu_1280_host_max, Ipv4, 1280, host_udp_payload_limit());
mtu_case!(ipv4_mtu_1420_host_max, Ipv4, 1420, host_udp_payload_limit());
mtu_case!(ipv4_mtu_1500_host_max, Ipv4, 1500, host_udp_payload_limit());
mtu_case!(ipv6_mtu_1280_host_max, Ipv6, 1280, host_udp_payload_limit());
mtu_case!(ipv6_mtu_1420_host_max, Ipv6, 1420, host_udp_payload_limit());
mtu_case!(ipv6_mtu_1500_host_max, Ipv6, 1500, host_udp_payload_limit());
