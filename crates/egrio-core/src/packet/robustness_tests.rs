//! Malformed captured packets: whatever bytes a program, or a device a
//! gateway capture forwards, puts on the capture interface, the parsers, the
//! reassembler, the pump's classification and the TCP engine take them
//! without panicking. Valid packets of each kind the pump handles are mutated
//! at random, biased to the length and header fields the parsers read.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::rr::RecordType;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::frame::{
    attribution_flow, build_icmp_packet, build_udp_packet, ipv4_header_checksum, parse_packet_flow,
    parse_transport, parse_udp_datagram, split_udp_train, udp_endpoints, udp_train_header,
    CapturedPacket,
};
use super::icmp::{echo_message, EchoRequest};
use super::pipeline::process_captured_packet;
use super::reassembly::PacketReassembler;
use super::tcp::TcpEngine;
use crate::attribution::ClientOwner;
use crate::dns::config::DnsMode;
use crate::profile::{RouteRule, RuleKind};
use crate::runtime::NativeCoreRuntime;
use crate::RuntimeProfile;

const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const FAKE_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 5);
const REMOTE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// Offsets of the fields the parsers read: the IPv4 version and header
/// length, total length, flags and fragment offset, protocol; the IPv6
/// payload length and next header; the transport ports, UDP length, TCP data
/// offset and flags behind either header, and the first extension or option
/// bytes.
const FIELDS: [usize; 22] = [
    0, 2, 3, 4, 5, 6, 7, 9, 20, 22, 24, 25, 32, 33, 40, 41, 44, 45, 46, 52, 53, 60,
];

fn ip_packet(ipv6: bool, protocol: u8, transport: &[u8]) -> Vec<u8> {
    let mut packet = if ipv6 {
        let mut header = vec![0_u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        header[6] = protocol;
        header[7] = 64;
        header[8..24].copy_from_slice(&CLIENT_V6.octets());
        header[24..40].copy_from_slice(&REMOTE_V6.octets());
        header
    } else {
        let mut header = vec![0_u8; 20];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        header[6] = 0x40;
        header[8] = 64;
        header[9] = protocol;
        header[12..16].copy_from_slice(&CLIENT_V4.octets());
        header[16..20].copy_from_slice(&FAKE_V4.octets());
        let checksum = ipv4_header_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        header
    };
    packet.extend_from_slice(transport);
    packet
}

fn tcp_packet(ipv6: bool, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_len = 20 + options.len();
    let mut tcp = vec![0_u8; header_len];
    tcp[0..2].copy_from_slice(&53_123_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&1000_u32.to_be_bytes());
    tcp[8..12].copy_from_slice(&2000_u32.to_be_bytes());
    tcp[12] = ((header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&512_u16.to_be_bytes());
    tcp[20..].copy_from_slice(options);
    tcp.extend_from_slice(payload);
    ip_packet(ipv6, 6, &tcp)
}

/// IPv4 fragment `offset` of datagram `id`, carrying `data` of a UDP
/// datagram.
fn v4_fragment(id: u16, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
    let mut packet = ip_packet(false, 17, data);
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&flags.to_be_bytes());
    packet[10..12].fill(0);
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// IPv6 fragment `offset` of datagram `id` behind a hop-by-hop header.
fn v6_fragment(id: u32, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
    let mut extensions = vec![44, 0, 1, 4, 0, 0, 0, 0];
    extensions.extend_from_slice(&[17, 0]);
    extensions.extend_from_slice(&(offset as u16 | u16::from(more)).to_be_bytes());
    extensions.extend_from_slice(&id.to_be_bytes());
    extensions.extend_from_slice(data);
    ip_packet(true, 0, &extensions)
}

fn seeds() -> Vec<Vec<u8>> {
    let syn_options = [2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 1, 1];
    let sack_options = [
        1, 1, 5, 18, 0, 0, 0x13, 0x88, 0, 0, 0x17, 0x70, 0, 0, 0x1b, 0x58, 0, 0, 0x1f, 0x40,
    ];
    let query = crate::dns::wire::query("example.com", RecordType::A).unwrap();
    let query = crate::dns::wire::encode(&query).unwrap();
    let client_v4 = IpAddr::V4(CLIENT_V4);
    let client_v6 = IpAddr::V6(CLIENT_V6);
    let udp_v4 = build_udp_packet(client_v4, IpAddr::V4(FAKE_V4), 53_123, 53, &query).unwrap();
    let udp_data = &udp_v4[20..];
    let mut train = udp_train_header(
        SocketAddr::new(client_v4, 53_124),
        SocketAddr::new(IpAddr::V4(FAKE_V4), 443),
        3 * 1200,
    )
    .unwrap();
    train.extend(std::iter::repeat_n(0x33, 3 * 1200));
    vec![
        tcp_packet(false, 0x02, &syn_options, &[]),
        tcp_packet(false, 0x18, &sack_options, &[0x16; 100]),
        tcp_packet(true, 0x02, &syn_options, &[]),
        tcp_packet(true, 0x11, &[], &[0x17; 40]),
        udp_v4.clone(),
        build_udp_packet(client_v6, IpAddr::V6(REMOTE_V6), 53_125, 443, &[0x40; 1200]).unwrap(),
        build_icmp_packet(
            client_v4,
            IpAddr::V4(FAKE_V4),
            &echo_message(false, false, 7, 1, b"ping"),
        )
        .unwrap(),
        build_icmp_packet(
            client_v6,
            IpAddr::V6(REMOTE_V6),
            &echo_message(true, false, 7, 1, b"ping"),
        )
        .unwrap(),
        v4_fragment(9, 0, true, &udp_data[..16]),
        v4_fragment(9, 16, false, &udp_data[16..]),
        v6_fragment(11, 0, true, &udp_data[..16]),
        v6_fragment(11, 16, false, &udp_data[16..]),
        train,
    ]
}

fn mutate(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    let mut packet = seed.to_vec();
    for _ in 0..rng.random_range(1..=4) {
        let len = packet.len();
        match rng.random_range(0..7) {
            0 if len > 0 => packet[rng.random_range(0..len)] = rng.random(),
            1 if len > 0 => packet[rng.random_range(0..len)] ^= 1 << rng.random_range(0..8),
            2 => {
                let field = FIELDS[rng.random_range(0..FIELDS.len())];
                if field < len {
                    const BYTES: [u8; 10] = [0, 1, 0x0f, 0x40, 0x45, 0x4f, 0x60, 0x7f, 0x80, 0xff];
                    packet[field] = BYTES[rng.random_range(0..BYTES.len())];
                }
            }
            3 => {
                // A 16-bit field set to a length at a boundary.
                let field = FIELDS[rng.random_range(0..FIELDS.len())];
                if field + 1 < len {
                    let value = match rng.random_range(0..6) {
                        0 => 0,
                        1 => 8,
                        2 => len,
                        3 => len - 1,
                        4 => len + 1,
                        _ => usize::from(u16::MAX),
                    };
                    packet[field..field + 2].copy_from_slice(&(value as u16).to_be_bytes());
                }
            }
            4 => packet.truncate(rng.random_range(0..=len)),
            5 => packet.extend((0..rng.random_range(1..64)).map(|_| rng.random::<u8>())),
            _ => fix_ipv4_header(&mut packet),
        }
    }
    packet
}

/// Makes an IPv4 header's total length and checksum agree with the packet
/// again, so the mutations behind it reach the transport parsers.
fn fix_ipv4_header(packet: &mut [u8]) {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return;
    }
    let total = packet.len().min(usize::from(u16::MAX)) as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[10..12].fill(0);
    let checksum = ipv4_header_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("robustness");
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    fn rule<'a>(kind: RuleKind, payload: Option<&'a str>, outbound: &'a str) -> RouteRule<'a> {
        RouteRule {
            kind,
            payload,
            outbound,
            no_resolve: false,
        }
    }
    profile.rules = vec![
        rule(RuleKind::DomainSuffix, Some("example.com"), "DIRECT"),
        rule(RuleKind::IpCidr, Some("1.1.1.0/24"), "REJECT"),
        rule(RuleKind::IpCidr6, Some("2001:db8::/32"), "DIRECT"),
        rule(RuleKind::DstPort, Some("8443"), "REJECT"),
        rule(RuleKind::Match, None, "DIRECT"),
    ]
    .into();
    profile
}

/// Runs one packet through every stateless parser and the classification,
/// checking that the ranges they hand back lie in the packet.
fn parse_everything(runtime: &NativeCoreRuntime, packet: &[u8], segment: usize) {
    let _ = attribution_flow(packet);
    let _ = parse_packet_flow(packet);
    let _ = parse_udp_datagram(packet);
    if let Ok(view) = parse_transport(packet) {
        assert!(packet.get(view.transport).is_some(), "transport range");
    }
    if let Some((_, _, payload)) = udp_endpoints(packet) {
        assert!(packet.get(payload).is_some(), "UDP payload range");
    }
    if let Some(echo) = EchoRequest::parse(packet) {
        let _ = echo.reply();
    }
    let _ = split_udp_train(packet, segment, |_| {});
    let _ = process_captured_packet(runtime, &CapturedPacket::from_bytes(packet.to_vec()));
}

#[test]
fn malformed_packets_never_panic_the_pump_path() {
    let runtime = NativeCoreRuntime::compile_with_egress(&profile(), Default::default());
    let seeds = seeds();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let mut reassembler = PacketReassembler::default();
    let (accept, _accepted) = tokio::sync::mpsc::unbounded_channel();
    let active = Arc::new(AtomicUsize::new(0));
    let mut engine = TcpEngine::new(65_535, accept, Arc::clone(&active), None);
    let mut now = Instant::now();
    for round in 0..40_000 {
        let seed = &seeds[round % seeds.len()];
        let packet = if rng.random_bool(0.05) {
            seed.clone()
        } else {
            mutate(&mut rng, seed)
        };
        parse_everything(&runtime, &packet, rng.random_range(0..2_000));
        engine.on_packet(
            Bytes::from(packet.clone()),
            ClientOwner::Known(None),
            None,
            now,
        );
        if let Ok(Some(whole)) = reassembler.push_at(packet, now) {
            // What the reassembler hands on goes through the same path.
            parse_everything(&runtime, &whole, 1200);
            engine.on_packet(Bytes::from(whole), ClientOwner::Known(None), None, now);
        }
        if round % 64 == 0 {
            now += Duration::from_millis(rng.random_range(0..3_000));
            engine.on_timers(now);
            engine.attend(now);
            engine.emit(now, usize::MAX, &mut |segment| {
                let packet: Vec<u8> = segment.parts().flatten().copied().collect();
                assert!(
                    parse_transport(&packet).is_ok(),
                    "the engine writes valid packets"
                );
            });
            reassembler.expire_at(now);
        }
    }
    assert_eq!(active.load(Ordering::Relaxed), engine.flow_count());
}
