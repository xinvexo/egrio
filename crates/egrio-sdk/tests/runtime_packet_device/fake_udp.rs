//! Fake DNS -> packet UDP -> physical DNS -> real loopback echo. Assertions
//! preserve the client-visible endpoint, including its original virtual IP.
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use egrio_core::dns::config::{DnsNameServerPolicy, DnsRoute, DnsTransport, DnsUpstream};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use tokio::{net::UdpSocket, task::JoinHandle};

use super::fragments::{udp6_checksum, Family};
use super::{
    dns_query, emit_packet, fake_ip_direct_profile, first_a_answer, first_aaaa_answer,
    internet_checksum, ipv4_udp_packet, ipv4_udp_payload, packet_spec, wait_for_written_packet,
    FixedCoreConfig,
};

struct DnsStub {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}

impl DnsStub {
    async fn new(domain: &'static str, answer: IpAddr) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let observed = queries.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = &buffer[..length];
                let (name, qtype, end) = question(request);
                observed.lock().unwrap().push((name.clone(), qtype));
                assert_eq!(
                    name, domain,
                    "nameserver-policy must retain the original domain"
                );
                let record = match (qtype, answer) {
                    (1, IpAddr::V4(ip)) => Some(ip.octets().to_vec()),
                    (28, IpAddr::V6(ip)) => Some(ip.octets().to_vec()),
                    _ => None,
                };
                let mut response = vec![0_u8; 12];
                response[..2].copy_from_slice(&request[..2]);
                response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                response[4..6].copy_from_slice(&1_u16.to_be_bytes());
                response[6..8].copy_from_slice(&u16::from(record.is_some()).to_be_bytes());
                response.extend_from_slice(&request[12..end]);
                if let Some(record) = record {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&qtype.to_be_bytes());
                    response.extend_from_slice(&1_u16.to_be_bytes());
                    response.extend_from_slice(&60_u32.to_be_bytes());
                    response.extend_from_slice(&(record.len() as u16).to_be_bytes());
                    response.extend_from_slice(&record);
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        Self {
            address,
            queries,
            task,
        }
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
}

impl Drop for DnsStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn question(packet: &[u8]) -> (String, u16, usize) {
    assert!(packet.len() >= 12);
    let mut offset = 12;
    let mut labels = Vec::new();
    while packet[offset] != 0 {
        let length = usize::from(packet[offset]);
        assert!(length <= 63);
        offset += 1;
        labels.push(std::str::from_utf8(&packet[offset..offset + length]).unwrap());
        offset += length;
    }
    offset += 1;
    (
        labels.join("."),
        u16::from_be_bytes([packet[offset], packet[offset + 1]]),
        offset + 4,
    )
}

fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some((
            IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
            IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?),
        )),
        6 if packet.len() >= 40 => Some((
            IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
            IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
        )),
        _ => None,
    }
}

/// Accept both a single response and MTU-sized response fragments. Validate
/// the alias on *every* raw IP packet before joining the UDP transport.
async fn expect_virtual_response(
    platform: &InMemoryPlatform,
    cursor: &mut usize,
    remote: SocketAddr,
    client: SocketAddr,
    payload: &[u8],
) {
    let mut pieces = BTreeMap::<usize, Vec<u8>>::new();
    let mut end = None;
    let datagram = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let packets = platform.written_packets();
            for packet in packets.iter().skip(*cursor) {
                if super::is_dns_answer_to(packet, 53_101) { continue; }
                let bytes = packet;
                let Some((source, destination)) = addresses(bytes) else { continue; };
                if destination != client.ip() { continue; }
                assert_eq!(source, remote.ip(), "connected packet UDP replies must retain the original FakeIP, not the resolved loopback IP");
                let (offset, more, transport) = match bytes[0] >> 4 {
                    4 => {
                        let header = usize::from(bytes[0] & 15) * 4;
                        assert_eq!(bytes[9], 17);
                        assert_eq!(internet_checksum(bytes[..header].iter().copied()), 0);
                        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]) as usize, bytes.len());
                        let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
                        (usize::from(flags & 0x1fff) * 8, flags & 0x2000 != 0, &bytes[header..])
                    }
                    6 if bytes[6] == 44 => {
                        assert_eq!(bytes[40], 17);
                        let flags = u16::from_be_bytes([bytes[42], bytes[43]]);
                        (usize::from(flags & 0xfff8), flags & 1 != 0, &bytes[48..])
                    }
                    6 => { assert_eq!(bytes[6], 17); (0, false, &bytes[40..]) }
                    _ => unreachable!(),
                };
                if more { assert_eq!(transport.len() % 8, 0); } else { end = Some(offset + transport.len()); }
                assert!(pieces.insert(offset, transport.to_vec()).is_none(), "unexpected duplicate reply fragment");
            }
            *cursor = packets.len();
            if let Some(end) = end {
                let mut next = 0;
                let mut joined = Vec::new();
                for (offset, bytes) in &pieces {
                    if *offset != next { break; }
                    joined.extend_from_slice(bytes);
                    next += bytes.len();
                }
                if next == end { break joined; }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }).await.expect("packet UDP response before timeout");
    assert!(datagram.len() >= 8);
    assert_eq!(
        u16::from_be_bytes([datagram[0], datagram[1]]),
        remote.port()
    );
    assert_eq!(
        u16::from_be_bytes([datagram[2], datagram[3]]),
        client.port()
    );
    assert_eq!(
        u16::from_be_bytes([datagram[4], datagram[5]]) as usize,
        payload.len() + 8
    );
    assert_eq!(&datagram[8..], payload);
    if let (IpAddr::V6(source), IpAddr::V6(destination)) = (remote.ip(), client.ip()) {
        assert_ne!(&datagram[6..8], &[0, 0]);
        assert_eq!(udp6_checksum(source, destination, &datagram), 0);
    }
}

async fn exchange(family: Family, payload: Vec<u8>, fragmented: bool) {
    let domain = match family {
        Family::Ipv4 => "fake-udp-v4.packet.invalid",
        Family::Ipv6 => "fake-udp-v6.packet.invalid",
    };
    let dns = DnsStub::new(domain, family.loopback()).await;
    let echo = UdpSocket::bind(SocketAddr::new(family.loopback(), 0))
        .await
        .unwrap();
    let echo_address = echo.local_addr().unwrap();
    let mut profile = fake_ip_direct_profile();
    profile.dns.policies.push(DnsNameServerPolicy {
        pattern: domain.parse().unwrap(),
        nameservers: vec![dns.upstream()],
    });
    let mut config = FixedCoreConfig::with_ipv6(profile);
    config.egress.dns_servers = vec![dns.address];
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .core_config(Arc::new(config))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();
    let qtype = match family {
        Family::Ipv4 => 1,
        Family::Ipv6 => 28,
    };
    emit_packet(
        &platform,
        "allocate-udp-fake-ip",
        ipv4_udp_packet(
            Ipv4Addr::new(10, 23, 0, 2),
            Ipv4Addr::new(198, 18, 0, 1),
            53_101,
            53,
            &dns_query(0x891a, domain, qtype),
        ),
    );
    let mut cursor = 0;
    let answer = wait_for_written_packet(&platform, &mut cursor, |packet| {
        super::is_dns_answer_to(packet, 53_101)
    })
    .await;
    let answer = ipv4_udp_payload(&answer);
    let fake = match family {
        Family::Ipv4 => IpAddr::V4(first_a_answer(answer).expect("Fake IPv4 DNS answer")),
        Family::Ipv6 => {
            IpAddr::V6(first_aaaa_answer(answer).expect("projected Fake IPv6 DNS answer"))
        }
    };
    assert_ne!(fake, family.loopback());
    assert_eq!(runtime.core_state_audit().unwrap().fake_dns_entries, 1);
    let client = SocketAddr::new(family.client(), 54_123);
    let virtual_remote = SocketAddr::new(fake, echo_address.port());
    let packet = family.packet(client, virtual_remote, &payload);
    let packets = if fragmented {
        family.fragments(&packet, &[1024, 2048, 3072], 0x9876_5432)
    } else {
        vec![packet]
    };
    let packet_count = packets.len() as u64;
    for (index, packet) in packets.into_iter().enumerate().rev() {
        emit_packet(&platform, &format!("fake-udp-{index}"), packet);
    }
    let mut received = vec![0_u8; 65_535];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(3), echo.recv_from(&mut received))
            .await
            .expect("FakeIP routes through configured loopback DNS to real UDP echo")
            .unwrap();
    assert_eq!(&received[..length], payload.as_slice());
    assert_eq!(
        echo.send_to(&received[..length], peer).await.unwrap(),
        payload.len()
    );
    let observed = dns.queries.lock().unwrap().clone();
    assert!(
        observed
            .iter()
            .any(|(name, kind)| name == domain && *kind == qtype),
        "physical endpoint resolution must use nameserver-policy DNS fixture: {observed:?}"
    );
    expect_virtual_response(&platform, &mut cursor, virtual_remote, client, &payload).await;
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().unwrap();
    assert_eq!(report.packets_received, packet_count + 1);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}

#[tokio::test]
async fn fake_ipv4_udp_reply_keeps_virtual_source_for_empty_payload() {
    exchange(Family::Ipv4, Vec::new(), false).await;
}
#[tokio::test]
async fn fake_ipv4_udp_reply_keeps_virtual_source_for_regular_payload() {
    exchange(
        Family::Ipv4,
        b"connected UDP must see its original fake destination".to_vec(),
        false,
    )
    .await;
}
#[tokio::test]
async fn fake_ipv4_udp_reply_keeps_virtual_source_for_fragmented_payload() {
    exchange(
        Family::Ipv4,
        (0..4096).map(|value| (value * 11) as u8).collect(),
        true,
    )
    .await;
}
#[tokio::test]
async fn fake_ipv6_udp_reply_keeps_virtual_source_for_empty_payload() {
    exchange(Family::Ipv6, Vec::new(), false).await;
}
#[tokio::test]
async fn fake_ipv6_udp_reply_keeps_virtual_source_for_regular_payload() {
    exchange(
        Family::Ipv6,
        b"connected IPv6 UDP must see its projected fake destination".to_vec(),
        false,
    )
    .await;
}
#[tokio::test]
async fn fake_ipv6_udp_reply_keeps_virtual_source_for_fragmented_payload() {
    exchange(
        Family::Ipv6,
        (0..4096).map(|value| (value * 13) as u8).collect(),
        true,
    )
    .await;
}
