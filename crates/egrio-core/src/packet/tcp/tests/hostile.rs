//! Segments no well-behaved client sends: arbitrary sequence and
//! acknowledgment numbers, flag mixes, windows, options and lengths, from a
//! buggy program or a device a gateway capture forwards, mixed with relay
//! writes, reads, closes and resets and with time passing. The engine must
//! not panic, must send only well-formed segments, and must count its live
//! flows exactly.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;

const PORTS: u16 = 4;
const FIRST_PORT: u16 = 40_000;

struct Fuzz {
    harness: Harness,
    rng: StdRng,
    /// Per client port: the client's next sequence number as the engine
    /// last acknowledged it, and the engine's next one.
    anchors: Vec<(u32, u32)>,
    streams: Vec<CapturedTcpStream>,
}

impl Fuzz {
    fn new(seed: u64) -> Self {
        Self {
            harness: Harness::new(),
            rng: StdRng::seed_from_u64(seed),
            anchors: vec![(1000, 0); usize::from(PORTS)],
            streams: Vec::new(),
        }
    }

    /// Near an anchor most of the time, so segments reach the windows, and
    /// anywhere otherwise.
    fn near(&mut self, anchor: u32) -> u32 {
        match self.rng.random_range(0..4) {
            0 => anchor,
            1 => anchor.wrapping_add(self.rng.random_range(0..70_000)),
            2 => anchor.wrapping_sub(self.rng.random_range(0..70_000)),
            _ => self.rng.random(),
        }
    }

    /// A segment from the client: half of them where a client would send
    /// next, so flows open, carry data both ways and close, and half
    /// anywhere, with any flags.
    fn send_segment(&mut self) {
        let port = self.rng.random_range(0..PORTS);
        let (client_next, engine_next) = self.anchors[usize::from(port)];
        let (seq, ack, flags) = if self.rng.random_bool(0.5) {
            let flags = match self.rng.random_range(0..10) {
                0 => SYN,
                1 => ACK | FIN,
                2..=4 => ACK | PSH,
                _ => ACK,
            };
            (client_next, engine_next, flags)
        } else {
            let seq = self.near(client_next);
            let ack = self.near(engine_next);
            (seq, ack, self.rng.random())
        };
        let window = match self.rng.random_range(0..4) {
            0 => 0,
            1 => u16::MAX,
            _ => self.rng.random(),
        };
        let mut segment = self.harness.segment(seq, ack, flags, window);
        segment.local = SocketAddr::new(self.harness.client.ip(), FIRST_PORT + port);
        if self.rng.random_bool(0.3) {
            segment.mss = Some(match self.rng.random_range(0..3) {
                0 => 0,
                1 => 1,
                _ => self.rng.random(),
            });
        }
        if self.rng.random_bool(0.3) {
            segment.window_scale = Some(self.rng.random());
        }
        segment.sack_permitted = self.rng.random_bool(0.3);
        for _ in 0..self.rng.random_range(0..=4) {
            // Each block takes eight bytes, the first four more; all options
            // fit in 40.
            let added = if segment.sack.is_empty() { 12 } else { 8 };
            if segment.options_len() + added > 40 {
                break;
            }
            let left = self.near(engine_next);
            let right = left.wrapping_add(self.rng.random_range(0..20_000));
            segment.sack.push(Seq(left), Seq(right));
        }
        let length = match self.rng.random_range(0..10) {
            0..=4 => 0,
            5..=8 => self.rng.random_range(1..2_000),
            _ => self.rng.random_range(2_000..60_000),
        };
        self.harness.send(&segment, &vec![0xa5; length]);
    }

    fn relay(&mut self) {
        if self.streams.is_empty() {
            return;
        }
        let index = self.rng.random_range(0..self.streams.len());
        let mut cx = context();
        match self.rng.random_range(0..6) {
            0 | 1 => {
                let length = self.rng.random_range(1..100_000);
                let mut chunk = Some(Bytes::from(vec![0x5a; length]));
                let _ = self.streams[index].poll_write_chunk(&mut cx, &mut chunk);
            }
            2 | 3 => {
                let limit = self.rng.random_range(1..200_000);
                let _ = self.streams[index].poll_read_chunk(&mut cx, limit);
            }
            4 => self.streams[index].poll_shutdown_for_tests(),
            _ => {
                let stream = self.streams.swap_remove(index);
                if self.rng.random_bool(0.5) {
                    stream.reset_handle().reset();
                }
            }
        }
    }

    /// Takes what the engine sends, learning where each flow stands.
    fn emit(&mut self) {
        self.harness.engine.attend(self.harness.now);
        let room = self.rng.random_range(1..64);
        let mut out = Vec::new();
        self.harness
            .engine
            .emit(self.harness.now, room, &mut |segment: OutSegment| {
                out.push(segment.to_vec())
            });
        for packet in out {
            let seg = segment::parse(&packet).expect("the engine sends valid segments");
            assert_eq!(seg.client, self.harness.target, "sent from the target");
            assert_eq!(seg.target.ip(), self.harness.client.ip());
            let port = seg.target.port().wrapping_sub(FIRST_PORT);
            assert!(port < PORTS, "sent to a port that sent to it");
            if seg.has(RST) {
                continue;
            }
            let anchor = &mut self.anchors[usize::from(port)];
            anchor.1 = seg.seq.0.wrapping_add(seg.seq_len() as u32);
            if seg.has(ACK) {
                anchor.0 = seg.ack.0;
            }
        }
        while let Ok(stream) = self.harness.accept.try_recv() {
            self.streams.push(stream);
        }
    }

    fn step(&mut self) {
        match self.rng.random_range(0..10) {
            0..=4 => self.send_segment(),
            5 | 6 => self.relay(),
            7 => {
                let by = match self.rng.random_range(0..4) {
                    0 => Duration::from_secs(self.rng.random_range(1..90)),
                    _ => Duration::from_millis(self.rng.random_range(0..1_500)),
                };
                self.harness.advance(by);
            }
            _ => self.emit(),
        }
        assert_eq!(
            self.harness.active.load(Ordering::Relaxed),
            self.harness.engine.flow_count(),
            "the live-flow count matches the flows"
        );
    }
}

#[test]
fn hostile_segments_never_break_the_engine() {
    for seed in 0..48 {
        let mut fuzz = Fuzz::new(seed);
        for _ in 0..3_000 {
            fuzz.step();
        }
        fuzz.emit();
        fuzz.harness.engine.shutdown();
        assert_eq!(fuzz.harness.engine.flow_count(), 0);
        assert_eq!(
            fuzz.harness.active.load(Ordering::Relaxed),
            0,
            "seed {seed}"
        );
    }
}
