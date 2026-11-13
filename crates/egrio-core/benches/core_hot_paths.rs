//! Hot-path baselines for the native core.
//!
//! These benches gate kernel performance changes (see `bench/README.md`):
//! measure before changing the hot path, and reject changes that do not move
//! these numbers or that regress them.
//!
//! Covered paths:
//! - rule-engine route decision cost vs. rule-set size (linear-scan baseline);
//! - the packet fallback DNS loop: raw IPv4/UDP parse -> DNS policy ->
//!   fake-IP answer -> response packet build (the per-packet TUN DNS cost);
//! - per-packet allocation shape via a large-payload UDP parse/route pass.

use std::net::Ipv4Addr;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use egrio_core::bench_internals::BenchPacketClassifier;
use egrio_core::{
    ProxyNode, ProxyProtocol, RouteMatchInput, RouteRule, RouteRules, RuleEngine, RuleKind,
    RuntimeProfile,
};
use serde_json::json;

fn proxy_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("bench-profile");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = egrio_core::dns::config::DnsMode::FakeIp;
    profile.proxies.push(ProxyNode {
        id: "proxy-1".into(),
        name: "Proxy".into(),
        protocol: ProxyProtocol::Http,
        server: Some("192.0.2.10".into()),
        port: Some(8080),
        options: json!({}),
    });
    profile
}

fn profile_with_suffix_rules(rule_count: usize) -> RuntimeProfile {
    let mut profile = proxy_profile();
    let mut rules = RouteRules::builder();
    for index in 0..rule_count {
        rules
            .push(RouteRule {
                kind: RuleKind::DomainSuffix,
                payload: Some(&format!("suffix-{index}.bench.example")),
                outbound: "Proxy",
                no_resolve: false,
            })
            .expect("a benchmark's rules fit a block");
    }
    rules
        .push(RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        })
        .expect("a benchmark's rules fit a block");
    profile.rules = rules.finish();
    profile
}

fn host_input(host: &str) -> RouteMatchInput {
    RouteMatchInput {
        host: Some(host.into()),
        ..Default::default()
    }
}

fn bench_route_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_match");
    for rule_count in [10_usize, 1_000, 10_000] {
        let engine = RuleEngine::compile(&profile_with_suffix_rules(rule_count));
        let first_hit = host_input("www.suffix-0.bench.example");
        let last_hit = host_input(&format!("www.suffix-{}.bench.example", rule_count - 1));
        let fallback_miss = host_input("no-rule-matches.test");

        assert_eq!(engine.route(&first_hit).outbound, "Proxy");
        assert_eq!(engine.route(&last_hit).outbound, "Proxy");
        assert_eq!(engine.route(&fallback_miss).outbound, "DIRECT");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("first_rule_hit", rule_count),
            &first_hit,
            |b, input| b.iter(|| engine.route(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("last_rule_hit", rule_count),
            &last_hit,
            |b, input| b.iter(|| engine.route(input)),
        );
        group.bench_with_input(
            BenchmarkId::new("fallback_miss", rule_count),
            &fallback_miss,
            |b, input| b.iter(|| engine.route(input)),
        );
    }
    group.finish();
}

fn bench_packet_dns_fake_ip_answer(c: &mut Criterion) {
    let mut profile = proxy_profile();
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::Domain,
            payload: Some("bench.example"),
            outbound: "Proxy",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        },
    ]
    .into();
    let core = BenchPacketClassifier::compile(&profile);
    let query = dns_a_query_payload(0x1234, "bench.example");
    let packet = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        53_000,
        53,
        &query,
    );

    let action = core
        .classify(&packet)
        .expect("DNS query packet is processed");
    assert_eq!(action, "DnsCapture");

    let mut group = c.benchmark_group("packet_dns_fake_ip_answer");
    group.throughput(Throughput::Elements(1));
    group.bench_function("udp53_a_query_answer", |b| {
        b.iter(|| core.classify(&packet).expect("packet processed"))
    });
    group.finish();
}

fn bench_packet_udp_parse_route(c: &mut Criterion) {
    // A non-DNS UDP packet toward a REJECT rule measures parse + route +
    // decision cost (including the per-packet allocation shape) without
    // touching sockets or accumulating session state across iterations.
    let mut profile = proxy_profile();
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "REJECT",
        no_resolve: false,
    }]
    .into();
    let core = BenchPacketClassifier::compile(&profile);
    let payload = vec![0xa5_u8; 1_200];
    let packet = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(203, 0, 113, 9),
        50_000,
        4_500,
        &payload,
    );

    let action = core.classify(&packet).expect("UDP packet is processed");
    assert_eq!(action, "Reject");

    let mut group = c.benchmark_group("packet_udp_parse_route");
    group.throughput(Throughput::Bytes(packet.len() as u64));
    group.bench_function("mtu_udp_reject_decision", |b| {
        b.iter(|| core.classify(&packet).expect("packet processed"))
    });
    group.finish();
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

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
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

fn dns_a_query_payload(id: u16, domain: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + domain.len() + 2);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&0x0100_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload
}

criterion_group!(
    benches,
    bench_route_match,
    bench_packet_dns_fake_ip_answer,
    bench_packet_udp_parse_route
);
criterion_main!(benches);
