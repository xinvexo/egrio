//! Outbound protocol crypto hot-path baselines — the gate instrument for
//! UDP/stream crypto changes: outbound and Trojan hot-path changes cite
//! before/after numbers from this bench.
//!
//! Run: cargo bench -p egrio-core --bench outbound_hot_paths --features bench-internals
//!
//! Covered (each over `bench-internals` wrappers that mirror the production
//! call sequence, no sockets):
//! - Shadowsocks per-datagram UDP crypto: the connector's seal/open of
//!   `salt || AEAD(socks_address || payload)` — the per-salt subkey
//!   derivation + cipher setup is the protocol-mandated floor, and
//!   master-key derivation alone bounds what deriving it per
//!   datagram would add (the hypothesis the bench falsified);
//! - Shadowsocks steady-state stream crypto: one relay chunk sealed/opened
//!   exactly as `ShadowsocksStream` frames it (sealed length record + sealed
//!   payload record, paired ciphers advancing in nonce lockstep);
//! - Trojan dial path: the per-profile SHA-224 credential hash and the
//!   per-dial `hash CRLF CMD target CRLF` preamble encode that precedes the
//!   first payload byte of every flow;
//! - Hysteria2 UDP datagram framing: the per-datagram message
//!   build+serialize handed to quinn and the peer's parse back into frame
//!   fields.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use egrio_core::bench_internals::{
    BenchHysteria2UdpFrame, BenchShadowsocksStreamCodec, BenchShadowsocksUdpCodec,
    BenchTrojanPreamble, SHADOWSOCKS_MAX_TCP_CHUNK,
};

/// The cipher the doc's baseline rows were recorded with.
const SHADOWSOCKS_CIPHER: &str = "aes-128-gcm";
const PASSWORD: &str = "bench-pre-shared-key";
/// Datagram payload sizes: a small query and an MTU-scale payload, the two
/// points the doc's baseline table records.
const UDP_PAYLOAD_SIZES: [usize; 2] = [64, 1200];

fn bench_shadowsocks_udp_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("shadowsocks_udp_crypto");
    let codec = BenchShadowsocksUdpCodec::new(SHADOWSOCKS_CIPHER, PASSWORD);

    group.throughput(Throughput::Elements(1));
    group.bench_function("master_key_derivation", |b| {
        b.iter(|| codec.master_key(PASSWORD))
    });

    for size in UDP_PAYLOAD_SIZES {
        let payload = vec![0xa5_u8; size];
        let packet = codec.seal(&payload);
        assert_eq!(codec.open(&packet), payload);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("seal_only", size),
            &payload,
            |b, payload| b.iter(|| codec.seal(payload)),
        );
        // Each datagram is independently keyed, so opening the same packet
        // repeatedly is the exact downlink sequence.
        group.bench_with_input(BenchmarkId::new("open_only", size), &packet, |b, packet| {
            b.iter(|| codec.open(packet))
        });
        group.bench_with_input(
            BenchmarkId::new("roundtrip", size),
            &payload,
            |b, payload| b.iter(|| codec.open(&codec.seal(payload))),
        );
    }
    group.finish();
}

fn bench_shadowsocks_stream_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("shadowsocks_stream_crypto");
    // A typical MTU-scale write and a full relay chunk (the 0x3fff cap one
    // 16 KiB relay read seals as).
    for size in [1_200_usize, SHADOWSOCKS_MAX_TCP_CHUNK] {
        let payload = vec![0xa5_u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Seal-only advances just the encryptor, so it gets its own codec.
        let mut seal_codec = BenchShadowsocksStreamCodec::new(SHADOWSOCKS_CIPHER, PASSWORD);
        group.bench_with_input(
            BenchmarkId::new("seal_chunk", size),
            &payload,
            |b, payload| b.iter(|| seal_codec.seal_chunk(payload)),
        );

        let mut roundtrip_codec = BenchShadowsocksStreamCodec::new(SHADOWSOCKS_CIPHER, PASSWORD);
        assert_eq!(roundtrip_codec.roundtrip_chunk(&payload), size);
        group.bench_with_input(
            BenchmarkId::new("roundtrip", size),
            &payload,
            |b, payload| b.iter(|| roundtrip_codec.roundtrip_chunk(payload)),
        );
    }
    group.finish();
}

fn bench_trojan_preamble(c: &mut Criterion) {
    let mut group = c.benchmark_group("trojan_preamble");
    group.throughput(Throughput::Elements(1));

    group.bench_function("password_hash", |b| {
        b.iter(|| BenchTrojanPreamble::password_hash(PASSWORD))
    });

    let preamble = BenchTrojanPreamble::new(PASSWORD, "www.bench.example", 443);
    // hash(56) + CRLF + CMD + domain SOCKS address (1 + 1 + 17 + 2) + CRLF.
    assert_eq!(preamble.encode_connect_preamble().len(), 82);
    group.bench_function("encode_connect_request", |b| {
        b.iter(|| preamble.encode_connect_preamble())
    });
    group.finish();
}

fn bench_hysteria2_udp_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("hysteria2_udp_frame");
    let frame = BenchHysteria2UdpFrame::new("bench.example:53");
    for size in UDP_PAYLOAD_SIZES {
        let payload = vec![0xa5_u8; size];
        let datagram = frame.seal(&payload);
        assert_eq!(frame.parse(&datagram), payload);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), &payload, |b, payload| {
            b.iter(|| frame.seal(payload))
        });
        group.bench_with_input(BenchmarkId::new("parse", size), &datagram, |b, datagram| {
            b.iter(|| frame.parse(datagram))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_shadowsocks_udp_crypto,
    bench_shadowsocks_stream_crypto,
    bench_trojan_preamble,
    bench_hysteria2_udp_frame
);
criterion_main!(benches);
