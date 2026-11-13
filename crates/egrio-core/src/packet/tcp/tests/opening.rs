//! Flows the engine opens (a tunnel's connections), against the engine
//! accepting them: the handshake, refusals and timeouts, and transfers both
//! ways over an impaired link with every byte checked.

use std::net::{IpAddr, Ipv4Addr};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;

const OPENER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2));
const SERVER: &str = "10.8.0.1:80";

/// What `engine` sends, as packets.
fn emitted(engine: &mut TcpEngine, now: Instant) -> Vec<Vec<u8>> {
    engine.attend(now);
    engine.on_timers(now);
    let mut out = Vec::new();
    engine.emit(now, usize::MAX, &mut |segment| out.push(segment.to_vec()));
    out
}

/// Carries packets between two engines until neither sends more.
fn exchange(a: &mut TcpEngine, b: &mut TcpEngine, now: Instant) {
    for _ in 0..32 {
        let from_a = emitted(a, now);
        let from_b = emitted(b, now);
        if from_a.is_empty() && from_b.is_empty() {
            return;
        }
        for packet in from_a {
            b.on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now);
        }
        for packet in from_b {
            a.on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now);
        }
    }
}

fn accepting(mtu: u32) -> (TcpEngine, mpsc::UnboundedReceiver<CapturedTcpStream>) {
    let (accept_tx, accept) = mpsc::unbounded_channel();
    let engine = TcpEngine::new(mtu, accept_tx, Arc::new(AtomicUsize::new(0)), None);
    (engine, accept)
}

#[tokio::test]
async fn an_opened_flow_completes_its_handshake_and_carries_bytes_both_ways() {
    let now = Instant::now();
    let mut opener = TcpEngine::opening(1400);
    let (mut acceptor, mut accept) = accepting(1500);
    let mut client = opener
        .connect(OPENER, SERVER.parse().unwrap(), now)
        .expect("a free port");
    let first = emitted(&mut opener, now);
    let syn = segment::parse(&first[0]).expect("a SYN");
    assert!(syn.has(SYN) && !syn.has(ACK));
    assert_eq!(syn.client, client.client_addr());
    assert_eq!(syn.options.mss, Some(1360), "the MSS fits the engine's MTU");
    assert_eq!(syn.options.window_scale, Some(TUNNEL_WINDOWS.shift));
    assert!(syn.options.sack_permitted);
    acceptor.on_packet(
        Bytes::from(first[0].clone()),
        ClientOwner::Known(None),
        None,
        now,
    );
    exchange(&mut opener, &mut acceptor, now);
    client.established().await.expect("established");
    let mut server = accept.try_recv().expect("the acceptor took the flow");

    let mut cx = context();
    let mut chunk = Some(Bytes::from_static(b"request"));
    assert!(client.poll_write_chunk(&mut cx, &mut chunk).is_ready());
    exchange(&mut opener, &mut acceptor, now);
    assert_eq!(read_available(&mut server).0, b"request");
    let mut chunk = Some(Bytes::from_static(b"response"));
    assert!(server.poll_write_chunk(&mut cx, &mut chunk).is_ready());
    exchange(&mut opener, &mut acceptor, now);
    assert_eq!(read_available(&mut client).0, b"response");

    client.poll_shutdown_for_tests();
    server.poll_shutdown_for_tests();
    exchange(&mut opener, &mut acceptor, now);
    assert_eq!(
        read_available(&mut server).1.map(|end| end.is_ok()),
        Some(true)
    );
    assert_eq!(
        read_available(&mut client).1.map(|end| end.is_ok()),
        Some(true)
    );
    drop((client, server));
    exchange(&mut opener, &mut acceptor, now + Duration::from_secs(5));
    assert_eq!(opener.flow_count(), 0);
    assert_eq!(acceptor.flow_count(), 0);
}

#[test]
fn an_opened_flow_offers_a_window_that_covers_a_long_fat_path() {
    let now = Instant::now();
    let mut opener = TcpEngine::opening(1400);
    let (mut acceptor, _accept) = accepting(1500);
    let _client = opener
        .connect(OPENER, SERVER.parse().unwrap(), now)
        .unwrap();
    let syn = emitted(&mut opener, now);
    acceptor.on_packet(
        Bytes::from(syn[0].clone()),
        ClientOwner::Known(None),
        None,
        now,
    );
    let syn_ack = emitted(&mut acceptor, now);
    opener.on_packet(
        Bytes::from(syn_ack[0].clone()),
        ClientOwner::Known(None),
        None,
        now,
    );
    let ack = emitted(&mut opener, now);
    let ack = segment::parse(&ack[0]).expect("the handshake's ACK");
    // A download's bytes in flight sit in the network, not in a capture
    // device's queues: the whole 8 MiB at once, where a young captured flow
    // gets 256 KiB.
    assert_eq!(
        usize::from(ack.window) << TUNNEL_WINDOWS.shift,
        8 * 1024 * 1024
    );
}

#[tokio::test]
async fn a_peer_that_accepts_nothing_refuses_the_flow() {
    let now = Instant::now();
    let mut opener = TcpEngine::opening(1400);
    // An engine that only opens flows answers every SYN with RST.
    let mut peer = TcpEngine::opening(1400);
    let client = opener
        .connect(OPENER, SERVER.parse().unwrap(), now)
        .unwrap();
    exchange(&mut opener, &mut peer, now);
    let refused = client.established().await.expect_err("refused");
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    exchange(&mut opener, &mut peer, now);
    assert_eq!(opener.flow_count(), 0);
}

#[tokio::test]
async fn an_unanswered_syn_is_retried_and_then_given_up() {
    let mut now = Instant::now();
    let mut opener = TcpEngine::opening(1400);
    let client = opener
        .connect(OPENER, SERVER.parse().unwrap(), now)
        .unwrap();
    let mut syns = 0;
    for _ in 0..200 {
        syns += emitted(&mut opener, now).len();
        if opener.flow_count() == 0 {
            break;
        }
        now = opener
            .next_deadline()
            .unwrap_or(now + Duration::from_secs(1));
    }
    assert_eq!(syns, 6, "the SYN and five retransmissions");
    let failed = client.established().await.expect_err("never answered");
    assert_eq!(failed.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn an_unreachable_destination_ends_the_opening_flow_at_once() {
    let now = Instant::now();
    let mut opener = TcpEngine::opening(1400);
    let client = opener
        .connect(OPENER, SERVER.parse().unwrap(), now)
        .unwrap();
    emitted(&mut opener, now);
    opener.unreachable(client.client_addr(), SERVER.parse().unwrap(), now);
    assert!(client.established().await.is_err());
    emitted(&mut opener, now);
    assert_eq!(opener.flow_count(), 0);
}

#[test]
fn syns_for_an_opening_engine_draw_resets() {
    let now = Instant::now();
    let mut engine = TcpEngine::opening(1400);
    let syn = Outgoing {
        local: SERVER.parse().unwrap(),
        client: SocketAddr::new(OPENER, 50000),
        seq: Seq(77),
        ack: Seq(0),
        flags: SYN,
        window: 65535,
        mss: None,
        window_scale: None,
        sack_permitted: false,
        sack: SackBlocks::default(),
    };
    let mut header = segment::write_header(&syn, 0);
    header.finish_checksum(std::iter::empty());
    engine.on_packet(
        Bytes::from(header.as_slice().to_vec()),
        ClientOwner::Known(None),
        None,
        now,
    );
    let replies = emitted(&mut engine, now);
    let reset = segment::parse(&replies[0]).unwrap();
    assert!(reset.has(RST) && reset.has(ACK));
    assert_eq!(reset.ack, Seq(78));
    assert_eq!(engine.flow_count(), 0);
}

/// Per side of one flow.
#[derive(Default)]
struct Side {
    sent: usize,
    received: usize,
    eof: bool,
    shutdown: bool,
    pending: Option<Bytes>,
}

impl Side {
    /// Reads and checks what arrived, writes what fits of `total`, and shuts
    /// down once it is all written and the other side's EOF came.
    fn drive(
        &mut self,
        stream: &mut CapturedTcpStream,
        flow: usize,
        total: usize,
        mask: u8,
        rng: &mut StdRng,
        seed: u64,
    ) {
        let mut cx = context();
        while !self.eof {
            match stream.poll_read_chunk(&mut cx, rng.random_range(1..=70_000)) {
                Poll::Ready(Ok(Some(chunk))) => {
                    for (i, byte) in chunk.iter().enumerate() {
                        assert_eq!(
                            *byte,
                            pattern(flow, self.received + i) ^ (mask ^ 0xa5),
                            "flow {flow} byte {} (seed {seed})",
                            self.received + i
                        );
                    }
                    self.received += chunk.len();
                }
                Poll::Ready(Ok(None)) => self.eof = true,
                Poll::Ready(Err(error)) => panic!("flow {flow} read failed: {error} (seed {seed})"),
                Poll::Pending => break,
            }
        }
        loop {
            if self.pending.is_none() && self.sent < total {
                let n = rng.random_range(1..=48_000).min(total - self.sent);
                let bytes: Vec<u8> = (self.sent..self.sent + n)
                    .map(|i| pattern(flow, i) ^ mask)
                    .collect();
                self.sent += n;
                self.pending = Some(Bytes::from(bytes));
            }
            if self.pending.is_none() {
                break;
            }
            match stream.poll_write_chunk(&mut cx, &mut self.pending) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    panic!("flow {flow} write failed: {error} (seed {seed})")
                }
                Poll::Pending => break,
            }
        }
        if self.sent == total && self.pending.is_none() && !self.shutdown {
            stream.poll_shutdown_for_tests();
            self.shutdown = true;
        }
    }
}

/// `flows` flows the opener connects, each moving `upload` bytes to the
/// acceptor and `download` back over one link that loses, duplicates and
/// delays `loss` of its packets each way.
fn transfer(seed: u64, mtu: u32, flows: usize, upload: usize, download: usize, loss: f64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let start = Instant::now();
    let mut now = start;
    let mut opener = TcpEngine::opening(mtu);
    let (mut acceptor, mut accept) = accepting(mtu);
    let mut clients: Vec<(CapturedTcpStream, Side)> = (0..flows)
        .map(|_| {
            let stream = opener
                .connect(OPENER, SERVER.parse().unwrap(), now)
                .expect("a free port");
            (stream, Side::default())
        })
        .collect();
    let mut servers: Vec<Option<(CapturedTcpStream, Side)>> = (0..flows).map(|_| None).collect();
    let mut to_acceptor = Impairment::new(seed ^ 1, loss);
    let mut to_opener = Impairment::new(seed ^ 2, loss);
    for _round in 0..400_000 {
        let mut wire = Vec::new();
        for packet in emitted(&mut opener, now) {
            assert!(packet.len() <= mtu as usize, "segments fit the MTU");
            to_acceptor.pass(packet, &mut wire);
        }
        to_acceptor.release(&mut wire);
        let moved = !wire.is_empty();
        for packet in wire {
            acceptor.on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now);
        }
        while let Ok(stream) = accept.try_recv() {
            let port = stream.client_addr().port();
            let flow = clients
                .iter()
                .position(|(client, _)| client.client_addr().port() == port)
                .expect("a flow the opener opened");
            servers[flow] = Some((stream, Side::default()));
        }
        let mut wire = Vec::new();
        for packet in emitted(&mut acceptor, now) {
            to_opener.pass(packet, &mut wire);
        }
        to_opener.release(&mut wire);
        let moved = moved || !wire.is_empty();
        for packet in wire {
            opener.on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now);
        }
        for (flow, (stream, side)) in clients.iter_mut().enumerate() {
            side.drive(stream, flow, upload, 0x00, &mut rng, seed);
        }
        for (flow, server) in servers.iter_mut().enumerate() {
            if let Some((stream, side)) = server {
                side.drive(stream, flow, download, 0xa5, &mut rng, seed);
            }
        }
        let done = clients
            .iter()
            .all(|(_, side)| side.eof && side.shutdown && side.received == download)
            && servers.iter().all(|server| {
                server
                    .as_ref()
                    .is_some_and(|(_, side)| side.eof && side.shutdown && side.received == upload)
            });
        if done {
            return;
        }
        let step = if moved {
            Duration::from_micros(100)
        } else {
            [opener.next_deadline(), acceptor.next_deadline()]
                .into_iter()
                .flatten()
                .min()
                .map_or(Duration::from_millis(10), |due| {
                    due.saturating_duration_since(now)
                })
                .clamp(Duration::from_micros(100), Duration::from_millis(250))
        };
        now += step;
    }
    let states: Vec<String> = clients
        .iter()
        .zip(&servers)
        .enumerate()
        .map(|(flow, ((_, client), server))| {
            let server = server
                .as_ref()
                .map(|(_, side)| (side.received, side.sent, side.eof));
            format!(
                "flow {flow}: client sent {} got {} eof {}; server {server:?}",
                client.sent, client.received, client.eof
            )
        })
        .collect();
    panic!("transfer did not finish (seed {seed}): {states:#?}");
}

#[test]
fn opened_flows_move_every_byte_on_clean_and_impaired_links() {
    for seed in 0..3 {
        transfer(seed, 1400, 1, 300_000, 700_000, 0.0);
        transfer(seed + 100, 1400, 4, 150_000, 300_000, 0.0);
        transfer(seed + 200, 1400, 1, 200_000, 400_000, 0.04);
        transfer(seed + 300, 9000, 3, 100_000, 200_000, 0.08);
    }
}
