//! The sender's congestion behavior over a simulated path, in virtual time:
//! flows the opening engine sends cross a bottleneck of fixed rate with a
//! drop-tail queue and a fixed propagation delay to the accepting engine,
//! whose ACKs return after the same delay. Each scenario measures what the
//! byte-checking transfers elsewhere cannot: how much of the bottleneck the
//! flows use, how long packets wait in its queue, how much is sent twice, how
//! fast a short transfer completes and how evenly flows share the link.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;

const SENDER: &str = "10.8.0.2";
const RECEIVER: &str = "10.8.0.1:80";
/// The tunnel engine's MTU, and the payload of its full segments.
const PATH_MTU: u32 = 1400;
const SEGMENT: u32 = 1360;

/// The path one way: the bottleneck the data crosses and the delay both ways.
#[derive(Clone)]
struct Path {
    /// Bottleneck rate in bytes per second.
    rate: f64,
    /// One-way propagation delay; the round trip is twice this plus queueing.
    delay: Duration,
    /// Bottleneck buffer in bytes, the packet in service included.
    buffer: usize,
    /// Probability that a data packet is lost before the bottleneck.
    loss: f64,
}

impl Path {
    /// `mbps` megabits a second, a round trip of `rtt_ms`, and a buffer of
    /// `bdps` bandwidth-delay products.
    fn new(mbps: f64, rtt_ms: u64, bdps: f64) -> Self {
        let rate = mbps * 1e6 / 8.0;
        let delay = Duration::from_millis(rtt_ms / 2);
        Self {
            rate,
            delay,
            buffer: (rate * 2.0 * delay.as_secs_f64() * bdps) as usize,
            loss: 0.0,
        }
    }

    /// How long a full buffer takes to drain, in milliseconds.
    fn drain_ms(&self) -> f64 {
        self.buffer as f64 / self.rate * 1000.0
    }
}

/// A packet on its way, ordered by arrival and then by when it was sent.
struct InFlight {
    at: Instant,
    order: u64,
    to_receiver: bool,
    packet: Vec<u8>,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.order) == (other.at, other.order)
    }
}
impl Eq for InFlight {}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.at, self.order).cmp(&(other.at, other.order))
    }
}

/// What a run measured.
#[derive(Debug, Default)]
struct Report {
    /// Bytes each flow's receiver read inside the measured interval.
    goodput: Vec<usize>,
    /// The measured interval.
    interval: Duration,
    /// Each data packet's wait in the bottleneck queue, in seconds.
    queueing: Vec<f64>,
    /// Payload bytes sent again, and all payload bytes sent.
    retransmitted: usize,
    sent: usize,
    /// Data packets the bottleneck dropped for a full buffer.
    overflowed: usize,
    /// Payload bytes that reached the receiver again after it had them:
    /// retransmissions the loss did not call for.
    duplicated: usize,
    /// When each flow's receiver had read everything, from the start.
    completed: Vec<Option<Duration>>,
}

impl Report {
    /// The bottleneck's share the flows used together.
    fn utilization(&self, path: &Path) -> f64 {
        let bytes: usize = self.goodput.iter().sum();
        bytes as f64 / (path.rate * self.interval.as_secs_f64())
    }

    /// Jain's fairness index of the flows' goodput: 1 when equal.
    fn fairness(&self) -> f64 {
        let sum: f64 = self.goodput.iter().map(|&bytes| bytes as f64).sum();
        let squares: f64 = self
            .goodput
            .iter()
            .map(|&bytes| (bytes as f64).powi(2))
            .sum();
        sum * sum / (self.goodput.len() as f64 * squares)
    }

    /// The `share` quantile of the queueing delay, in milliseconds.
    fn queueing_ms(&self, share: f64) -> f64 {
        let mut waits = self.queueing.clone();
        waits.sort_by(f64::total_cmp);
        let index = ((waits.len() as f64 - 1.0) * share).round() as usize;
        waits.get(index).map_or(0.0, |wait| wait * 1000.0)
    }

    fn retransmitted_share(&self) -> f64 {
        self.retransmitted as f64 / self.sent.max(1) as f64
    }

    fn duplicated_share(&self) -> f64 {
        self.duplicated as f64 / self.sent.max(1) as f64
    }

    fn print(&self, name: &str, path: &Path) {
        eprintln!(
            "{name}: utilization {:.3}, fairness {:.3}, queueing p50 {:.1} ms p95 {:.1} ms, \
             retransmitted {:.2}%, duplicated {:.2}%, overflowed {}, completed {:?}",
            self.utilization(path),
            self.fairness(),
            self.queueing_ms(0.5),
            self.queueing_ms(0.95),
            self.retransmitted_share() * 100.0,
            self.duplicated_share() * 100.0,
            self.overflowed,
            self.completed,
        );
    }
}

/// What the path does to one data packet beyond its rate and buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Pass,
    Drop,
    /// Arrives this much later than the queue order would have it.
    Delay(Duration),
}

/// One run: `flows` flows each sending `bytes` (or without end, `None`)
/// over `path` for `duration`, goodput measured after `warmup`. `fate`
/// decides each data packet's fate from its flow and its sequence number
/// relative to the flow's first.
struct Run<'a> {
    path: Path,
    flows: usize,
    bytes: Option<usize>,
    duration: Duration,
    warmup: Duration,
    seed: u64,
    fate: &'a mut dyn FnMut(usize, u32) -> Fate,
}

impl Run<'_> {
    fn go(self) -> Report {
        let Run {
            path,
            flows,
            bytes,
            duration,
            warmup,
            seed,
            fate,
        } = self;
        let mut rng = StdRng::seed_from_u64(seed);
        let start = Instant::now();
        let mut now = start;
        let mut sender = TcpEngine::opening(PATH_MTU);
        let (accept_tx, mut accept) = mpsc::unbounded_channel();
        // The receiver is a server across the path: it holds what a whole
        // window brings after a loss.
        let mut receiver = TcpEngine::new(PATH_MTU, accept_tx, Arc::new(AtomicUsize::new(0)), None)
            .with_windows(TUNNEL_WINDOWS);
        let local: std::net::IpAddr = SENDER.parse().unwrap();
        let mut writers: Vec<Writer> = (0..flows)
            .map(|_| Writer {
                stream: sender
                    .connect(local, RECEIVER.parse().unwrap(), now)
                    .expect("a free port"),
                written: 0,
                total: bytes,
                pending: None,
            })
            .collect();
        let ports: Vec<u16> = writers
            .iter()
            .map(|writer| writer.stream.client_addr().port())
            .collect();
        let mut readers: Vec<Option<CapturedTcpStream>> = (0..flows).map(|_| None).collect();
        let mut report = Report {
            goodput: vec![0; flows],
            interval: duration - warmup,
            completed: vec![None; flows],
            ..Report::default()
        };
        let mut read = vec![0usize; flows];
        // Per flow: the first sequence number of its data and the furthest
        // byte sent, to tell retransmissions apart.
        let mut first_seq: Vec<Option<Seq>> = vec![None; flows];
        let mut furthest: Vec<u32> = vec![0; flows];

        // Per flow: the relative sequence numbers of the segments the
        // receiver got, to count the ones it got twice.
        let mut arrived: Vec<std::collections::HashSet<u32>> = vec![Default::default(); flows];
        let mut wire: BinaryHeap<Reverse<InFlight>> = BinaryHeap::new();
        let mut order = 0u64;
        // When the bottleneck finishes sending each queued packet.
        let mut queue: VecDeque<(Instant, usize)> = VecDeque::new();
        let mut busy_until = start;
        let end = start + duration;

        while now < end {
            for packet in emit(&mut sender, now) {
                let seg = segment::parse(&packet).expect("a TCP segment");
                let flow = ports
                    .iter()
                    .position(|port| *port == seg.client.port())
                    .expect("a flow of the run");
                let length = seg.payload_len();
                let mut extra = Duration::ZERO;
                if length > 0 {
                    let first = *first_seq[flow].get_or_insert(seg.seq);
                    let relative = seg.seq.offset_from(first) as u32;
                    let packet_end = relative + length as u32;
                    report.sent += length;
                    if packet_end <= furthest[flow] {
                        report.retransmitted += length;
                    } else {
                        report.retransmitted += furthest[flow].saturating_sub(relative) as usize;
                        furthest[flow] = packet_end;
                    }
                    match fate(flow, relative) {
                        Fate::Drop => continue,
                        Fate::Delay(by) => extra = by,
                        Fate::Pass => {}
                    }
                    if rng.random_bool(path.loss) {
                        continue;
                    }
                }
                // The bottleneck: a FIFO of `buffer` bytes drained at `rate`.
                while queue.front().is_some_and(|(done, _)| *done <= now) {
                    queue.pop_front();
                }
                let queued: usize = queue.iter().map(|(_, size)| size).sum();
                if queued + packet.len() > path.buffer {
                    report.overflowed += 1;
                    continue;
                }
                let begin = busy_until.max(now);
                if length > 0 {
                    report.queueing.push((begin - now).as_secs_f64());
                }
                let done = begin + Duration::from_secs_f64(packet.len() as f64 / path.rate);
                busy_until = done;
                queue.push_back((done, packet.len()));
                order += 1;
                wire.push(Reverse(InFlight {
                    at: done + path.delay + extra,
                    order,
                    to_receiver: true,
                    packet,
                }));
            }
            for packet in emit(&mut receiver, now) {
                order += 1;
                wire.push(Reverse(InFlight {
                    at: now + path.delay,
                    order,
                    to_receiver: false,
                    packet,
                }));
            }
            while let Ok(stream) = accept.try_recv() {
                let flow = ports
                    .iter()
                    .position(|port| *port == stream.client_addr().port())
                    .expect("a flow of the run");
                readers[flow] = Some(stream);
            }
            let mut cx = context();
            for (flow, writer) in writers.iter_mut().enumerate() {
                writer.write(&mut cx, flow);
            }
            for (flow, reader) in readers.iter_mut().enumerate() {
                let Some(stream) = reader else { continue };
                let (chunk, _) = read_available(stream);
                for (i, byte) in chunk.iter().enumerate() {
                    assert_eq!(*byte, pattern(flow, read[flow] + i), "flow {flow} byte");
                }
                read[flow] += chunk.len();
                if now >= start + warmup {
                    report.goodput[flow] += chunk.len();
                }
                if bytes.is_some_and(|total| read[flow] == total)
                    && report.completed[flow].is_none()
                {
                    report.completed[flow] = Some(now - start);
                }
            }
            if bytes.is_some() && report.completed.iter().all(Option::is_some) {
                break;
            }
            // The next event: an arrival or either engine's timer.
            let next = [
                wire.peek().map(|Reverse(next)| next.at),
                sender.next_deadline(),
                receiver.next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(end);
            now = next.max(now).min(end);
            while wire.peek().is_some_and(|Reverse(next)| next.at <= now) {
                let Reverse(arrival) = wire.pop().unwrap();
                if arrival.to_receiver {
                    let seg = segment::parse(&arrival.packet).unwrap();
                    let flow = ports
                        .iter()
                        .position(|port| *port == seg.client.port())
                        .unwrap();
                    if seg.payload_len() > 0 {
                        let relative = seg.seq.offset_from(first_seq[flow].unwrap()) as u32;
                        if !arrived[flow].insert(relative) {
                            report.duplicated += seg.payload_len();
                        }
                    }
                }
                let target = if arrival.to_receiver {
                    &mut receiver
                } else {
                    &mut sender
                };
                target.on_packet(
                    Bytes::from(arrival.packet),
                    ClientOwner::Known(None),
                    None,
                    now,
                );
            }
        }
        report
    }
}

/// The application writing a flow's data: `total` bytes, or without end.
struct Writer {
    stream: CapturedTcpStream,
    written: usize,
    total: Option<usize>,
    pending: Option<Bytes>,
}

impl Writer {
    fn write(&mut self, cx: &mut Context<'_>, flow: usize) {
        loop {
            if self.pending.is_none() {
                let room = self.total.map_or(64 * 1024, |total| total - self.written);
                let n = room.min(64 * 1024);
                if n == 0 {
                    return;
                }
                let bytes: Vec<u8> = (self.written..self.written + n)
                    .map(|i| pattern(flow, i))
                    .collect();
                self.written += n;
                self.pending = Some(Bytes::from(bytes));
            }
            match self.stream.poll_write_chunk(cx, &mut self.pending) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => panic!("flow {flow} write failed: {error}"),
                Poll::Pending => return,
            }
        }
    }
}

fn emit(engine: &mut TcpEngine, now: Instant) -> Vec<Vec<u8>> {
    engine.attend(now);
    engine.on_timers(now);
    let mut out = Vec::new();
    engine.emit(now, usize::MAX, &mut |segment| out.push(segment.to_vec()));
    out
}

fn pass(_: usize, _: u32) -> Fate {
    Fate::Pass
}

/// Drops each of `segments` (relative sequence numbers) the first time it
/// goes out.
fn drop_once(segments: Vec<u32>) -> impl FnMut(usize, u32) -> Fate {
    let mut dropped = vec![false; segments.len()];
    move |_, seq| match segments.iter().position(|&hole| hole == seq) {
        Some(index) if !dropped[index] => {
            dropped[index] = true;
            Fate::Drop
        }
        _ => Fate::Pass,
    }
}

#[test]
fn a_bulk_flow_fills_the_bottleneck_without_a_standing_overflow() {
    let path = Path::new(20.0, 40, 1.0);
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(12),
        warmup: Duration::from_secs(2),
        seed: 1,
        fate: &mut pass,
    }
    .go();
    report.print("bulk", &path);
    assert!(report.utilization(&path) > 0.95, "uses the link");
    assert!(report.retransmitted_share() < 0.01, "sends little twice");
    assert!(report.queueing_ms(0.95) <= path.drain_ms() + 1.0);
}

#[test]
fn a_shallow_buffer_still_carries_a_paced_flow() {
    // A quarter of the bandwidth-delay product: an unpaced window's bursts
    // overflow it.
    let path = Path::new(20.0, 40, 0.25);
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(15),
        warmup: Duration::from_secs(3),
        seed: 6,
        fate: &mut pass,
    }
    .go();
    report.print("shallow buffer", &path);
    assert!(report.utilization(&path) > 0.85);
    assert!(report.retransmitted_share() < 0.02);
}

#[test]
fn a_long_fat_path_with_light_loss_stays_full() {
    // 50 Mbit/s at 100 ms with a loss every 33 000 packets: Reno's steady
    // state is half the link, CUBIC's above it.
    let path = Path {
        loss: 0.00003,
        ..Path::new(50.0, 100, 0.5)
    };
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(30),
        warmup: Duration::from_secs(5),
        seed: 7,
        fate: &mut pass,
    }
    .go();
    report.print("long fat path", &path);
    assert!(report.utilization(&path) > 0.75);
    // The receiver holds what follows a loss, so nothing is sent again for
    // it to drop.
    assert!(report.duplicated_share() < 0.001);
}

#[test]
fn a_flow_fills_a_path_whose_window_is_many_megabytes() {
    // 400 Mbit/s at 200 ms: a bandwidth-delay product of 10 MB, past what
    // a fixed 8 MiB window or 4 MiB send buffer carries.
    let path = Path::new(400.0, 200, 0.5);
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(20),
        warmup: Duration::from_secs(6),
        seed: 11,
        fate: &mut pass,
    }
    .go();
    report.print("ten-megabyte window", &path);
    assert!(report.utilization(&path) > 0.9, "uses the link");
    // CUBIC probes into the bottleneck's buffer, as it does on any path its
    // window does not cap, and no further.
    assert!(report.retransmitted_share() < 0.02);
    assert!(report.queueing_ms(0.95) <= path.drain_ms() + 1.0);
}

#[test]
fn random_loss_costs_no_more_than_renos_share() {
    let path = Path {
        loss: 0.01,
        ..Path::new(20.0, 40, 1.0)
    };
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(20),
        warmup: Duration::from_secs(2),
        seed: 2,
        fate: &mut pass,
    }
    .go();
    report.print("random loss", &path);
    // Reno's steady state at 1% loss: MSS / RTT × 1.22 / √p, a sixth of the
    // link here.
    let reno = f64::from(SEGMENT) / 0.04 * 1.22 / 0.1;
    assert!(report.utilization(&path) > 0.9 * reno / path.rate);
}

#[test]
fn losses_in_one_window_are_repaired_together() {
    let path = Path::new(20.0, 40, 1.0);
    // Five segments of one window, once the flow is in full swing.
    let first = 4_000_000 / SEGMENT * SEGMENT;
    let mut fate = drop_once((0..5).map(|k| first + k * 3 * SEGMENT).collect());
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: Some(6_000_000),
        duration: Duration::from_secs(20),
        warmup: Duration::ZERO,
        seed: 3,
        fate: &mut fate,
    }
    .go();
    report.print("five losses", &path);
    // 6 MB take 2.4 s at the link's rate.
    let completed = report.completed[0].expect("the transfer completes");
    assert!(completed < Duration::from_millis(3200), "{completed:?}");
}

#[test]
fn a_lost_tail_is_probed_before_the_retransmission_timeout() {
    let path = Path::new(20.0, 40, 1.0);
    let size = 20_000;
    let segments = (size as u32).div_ceil(SEGMENT);
    let run = |fate: &mut dyn FnMut(usize, u32) -> Fate| {
        Run {
            path: path.clone(),
            flows: 1,
            bytes: Some(size),
            duration: Duration::from_secs(10),
            warmup: Duration::ZERO,
            seed: 4,
            fate,
        }
        .go()
    };
    // The last three segments of a short transfer.
    let report = run(&mut drop_once(
        (segments - 3..segments).map(|k| k * SEGMENT).collect(),
    ));
    report.print("lost tail", &path);
    let clean = run(&mut pass);
    clean.print("whole tail", &path);
    let clean = clean.completed[0].unwrap();
    // The probe goes out two round trips after the last ACK; its SACK
    // reveals the rest, repaired a round trip later.
    let lost = report.completed[0].unwrap();
    assert!(
        lost < clean + Duration::from_millis(200),
        "{lost:?} against {clean:?}"
    );
}

#[test]
fn reordering_within_a_quarter_round_trip_is_not_taken_for_loss() {
    let path = Path::new(20.0, 40, 1.0);
    // Every hundredth packet arrives 6 ms late, behind the next ones.
    let mut late = |_: usize, seq: u32| {
        if (seq / SEGMENT) % 100 == 50 {
            Fate::Delay(Duration::from_millis(6))
        } else {
            Fate::Pass
        }
    };
    let report = Run {
        path: path.clone(),
        flows: 1,
        bytes: None,
        duration: Duration::from_secs(10),
        warmup: Duration::from_secs(2),
        seed: 8,
        fate: &mut late,
    }
    .go();
    report.print("reordering", &path);
    assert!(report.utilization(&path) > 0.9);
    // The first late packet shows the reordering; later ones wait out the
    // reordering window instead of going out again.
    assert!(report.retransmitted_share() < 0.005);
}

#[test]
fn flows_share_the_bottleneck_evenly() {
    let path = Path::new(40.0, 40, 1.0);
    let report = Run {
        path: path.clone(),
        flows: 4,
        bytes: None,
        duration: Duration::from_secs(20),
        warmup: Duration::from_secs(4),
        seed: 5,
        fate: &mut pass,
    }
    .go();
    report.print("four flows", &path);
    assert!(report.utilization(&path) > 0.95);
    assert!(report.fairness() > 0.95, "{:?}", report.goodput);
}
