//! Engine tests: scripted segments for each behavior the Core architecture
//! document lists, and a randomized transfer against smoltcp as the client
//! over a lossy, reordering, duplicating link.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;

use super::budget::{CAPTURE_WINDOWS, TUNNEL_WINDOWS};
use super::connection::{KEEPALIVE_GRID, MAX_OFFERED_MSS};
use super::engine::{FlowHolders, QueueShare, TcpEngine, MAX_FLOWS};
use super::segment::{self, Outgoing, Received, SackBlocks, ACK, FIN, PSH, RST, SYN};
use super::seq::Seq;
use super::stream::CapturedTcpStream;
use super::OutSegment;
use crate::attribution::ClientOwner;

const MTU: u32 = 65535;
const CLIENT: &str = "10.0.0.2:53123";
const TARGET: &str = "93.184.216.34:443";

/// A segment the engine sent, with its payload.
#[derive(Debug)]
struct Sent {
    seg: Received,
    payload: Vec<u8>,
}

struct Harness {
    engine: TcpEngine,
    accept: mpsc::UnboundedReceiver<CapturedTcpStream>,
    /// The live flows the engine counts.
    active: Arc<AtomicUsize>,
    now: Instant,
    client: SocketAddr,
    target: SocketAddr,
}

impl Harness {
    fn new() -> Self {
        let (accept_tx, accept) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        Self {
            engine: TcpEngine::new(MTU, accept_tx, Arc::clone(&active), None),
            accept,
            active,
            now: Instant::now(),
            client: CLIENT.parse().unwrap(),
            target: TARGET.parse().unwrap(),
        }
    }

    /// The engine of capture queue `queue` among several sharing `holders`.
    fn on_queue(queue: usize, holders: &Arc<FlowHolders>) -> Self {
        let mut harness = Self::new();
        let (accept_tx, accept) = mpsc::unbounded_channel();
        let share = QueueShare {
            queue,
            holders: Arc::clone(holders),
        };
        harness.engine = TcpEngine::new(MTU, accept_tx, Arc::clone(&harness.active), Some(share));
        harness.accept = accept;
        holders.open(queue);
        harness
    }

    /// A SYN from the client's address with source port `port`.
    fn syn_from(&self, port: u16) -> Outgoing {
        let mut syn = self.segment(1000, 0, SYN, 65535);
        syn.local = SocketAddr::new(self.client.ip(), port);
        syn
    }

    /// A client segment with no options.
    fn segment(&self, seq: u32, ack: u32, flags: u8, window: u16) -> Outgoing {
        Outgoing {
            local: self.client,
            client: self.target,
            seq: Seq(seq),
            ack: Seq(ack),
            flags,
            window,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: SackBlocks::default(),
        }
    }

    fn send(&mut self, segment: &Outgoing, payload: &[u8]) {
        let mut header = segment::write_header(segment, payload.len());
        header.finish_checksum(std::iter::once(payload));
        let mut packet = header.as_slice().to_vec();
        packet.extend_from_slice(payload);
        self.engine.on_packet(
            Bytes::from(packet),
            ClientOwner::Known(None),
            None,
            self.now,
        );
    }

    /// Lets the engine attend to relay events and collects what it sends.
    fn sent(&mut self) -> Vec<Sent> {
        self.engine.attend(self.now);
        let mut out = Vec::new();
        self.engine
            .emit(self.now, usize::MAX, &mut |segment: OutSegment| {
                out.push(segment)
            });
        out.into_iter()
            .map(|segment| {
                let packet = segment.to_vec();
                let seg = segment::parse(&packet).expect("the engine sends valid segments");
                assert_eq!(
                    seg.client, self.target,
                    "sent from the captured destination"
                );
                assert_eq!(seg.target, self.client);
                let payload = packet[seg.payload.clone()].to_vec();
                Sent { seg, payload }
            })
            .collect()
    }

    /// Discards whatever the engine has to send.
    fn drain(&mut self) {
        self.engine.attend(self.now);
        self.engine.emit(self.now, usize::MAX, &mut |_| {});
    }

    /// Sends `total` client bytes from `seq` in segments that fit an IP
    /// packet; returns the sequence number after them.
    fn send_bulk(&mut self, mut seq: u32, server: u32, total: usize, byte: u8) -> u32 {
        let mut left = total;
        while left > 0 {
            let length = left.min(60_000);
            self.send(&self.segment(seq, server, ACK, 512), &vec![byte; length]);
            seq = seq.wrapping_add(length as u32);
            left -= length;
        }
        seq
    }

    /// Fills the flow's window and lets the relay drain it until the window
    /// reaches `target`, which a flow earns by filling the windows before it
    /// (`Windows::start` and [`Connection::grow_window`]). Returns the next
    /// client sequence number.
    fn grow_window_to(
        &mut self,
        server: u32,
        mut seq: u32,
        target: usize,
        stream: &mut CapturedTcpStream,
    ) -> (u32, usize) {
        for _ in 0..64 {
            let _ = read_available(stream);
            let (ack, window) = self
                .sent()
                .last()
                .map(|out| {
                    (
                        out.seg.ack.0,
                        usize::from(out.seg.window) << self.engine.budget.windows.shift,
                    )
                })
                .unwrap_or((seq, self.engine.budget.windows.start));
            if window >= target {
                return (ack, window);
            }
            seq = self.send_bulk(ack, server, window.max(1), 1);
        }
        panic!("the window never reached {target}");
    }

    /// Sends until the flow's window closes, growing it on the way; returns
    /// the next client sequence number and how many bytes went in.
    fn close_window(&mut self, server: u32, from: u32) -> (u32, usize) {
        let mut seq = from;
        for _ in 0..64 {
            let window = self
                .sent()
                .last()
                .map(|out| usize::from(out.seg.window) << CAPTURE_WINDOWS.shift)
                .unwrap_or(CAPTURE_WINDOWS.start);
            if window == 0 {
                return (seq, seq.wrapping_sub(from) as usize);
            }
            seq = self.send_bulk(seq, server, window, 1);
        }
        panic!("the window never closed");
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        self.engine.on_timers(self.now);
    }

    /// SYN with MSS 1460, window scale 7 and SACK; returns the SYN|ACK and
    /// the accepted stream.
    fn open(&mut self) -> (Received, CapturedTcpStream) {
        let mut syn = self.segment(1000, 0, SYN, 65535);
        syn.mss = Some(1460);
        syn.window_scale = Some(7);
        syn.sack_permitted = true;
        self.send(&syn, &[]);
        let sent = self.sent();
        assert_eq!(sent.len(), 1);
        let syn_ack = sent.into_iter().next().unwrap().seg;
        let stream = self.accept.try_recv().expect("the SYN surfaces a stream");
        (syn_ack, stream)
    }

    /// Completes the handshake; returns the server's next sequence number.
    fn establish(&mut self) -> (u32, CapturedTcpStream) {
        let (syn_ack, stream) = self.open();
        let server = syn_ack.seq.0.wrapping_add(1);
        // The client's window: 65535 scaled by 7.
        self.send(&self.segment(1001, server, ACK, 512), &[]);
        assert_eq!(
            usize::from(syn_ack.window),
            CAPTURE_WINDOWS.start,
            "a flow starts with the window it has not had to earn"
        );
        assert!(
            self.sent().is_empty(),
            "the starting window went out with the SYN|ACK, so nothing follows it"
        );
        (server, stream)
    }

    /// The relay closes first: FIN-WAIT-1, then the client's ACK and FIN,
    /// whose ACK puts the flow in TIME-WAIT. Returns the server's next
    /// sequence number; the client's is 1002.
    fn time_wait(&mut self) -> u32 {
        let (server, mut stream) = self.establish();
        stream.poll_shutdown_for_tests();
        let fin = self.sent();
        assert!(fin[0].seg.has(FIN));
        self.send(&self.segment(1001, server + 1, ACK, 512), &[]);
        self.send(&self.segment(1001, server + 1, FIN | ACK, 512), &[]);
        let ack = self.sent();
        assert_eq!(ack.len(), 1);
        assert_eq!(ack[0].seg.ack, Seq(1002));
        let (_, end) = read_available(&mut stream);
        assert!(matches!(end, Some(Ok(()))), "the relay sees a clean close");
        server + 1
    }
}

fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

fn read_available(stream: &mut CapturedTcpStream) -> (Vec<u8>, Option<std::io::Result<()>>) {
    let mut cx = context();
    let mut read = Vec::new();
    loop {
        match stream.poll_read_chunk(&mut cx, usize::MAX) {
            Poll::Ready(Ok(Some(chunk))) => read.extend_from_slice(&chunk),
            Poll::Ready(Ok(None)) => return (read, Some(Ok(()))),
            Poll::Ready(Err(error)) => return (read, Some(Err(error))),
            Poll::Pending => return (read, None),
        }
    }
}

fn write(stream: &mut CapturedTcpStream, data: &[u8]) {
    let mut chunk = Some(Bytes::copy_from_slice(data));
    match stream.poll_write_chunk(&mut context(), &mut chunk) {
        Poll::Ready(Ok(())) => {}
        other => panic!("write did not complete: {other:?}"),
    }
}

/// A capture that ends mid-transfer leaves the engine holding nothing: no
/// flow, no window promised against the budget, no timer, and every relay
/// learns by a reset rather than waiting for its own timeout.
#[test]
fn an_abrupt_shutdown_leaves_the_engine_holding_nothing() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // Bytes queued both ways, so the flow holds a window and a timer.
    let (_, queued) = harness.close_window(server, 1001);
    assert!(queued > 0, "the client's bytes are queued");
    write(&mut stream, &vec![7u8; 128 * 1024]);
    harness.drain();
    // Flows that never finished their handshake hold slots too.
    let mut half_open = Vec::new();
    for port in 0..8u16 {
        let mut syn = harness.segment(5000, 0, SYN, 65535);
        syn.local = SocketAddr::new(harness.client.ip(), 20000 + port);
        syn.window_scale = Some(7);
        harness.send(&syn, &[]);
        half_open.push(harness.accept.try_recv().expect("a stream per SYN"));
    }
    harness.drain();
    assert_eq!(harness.engine.flow_count(), 9);
    assert!(
        harness.engine.budget.promised > 0,
        "the flows promised windows"
    );

    harness.engine.shutdown();

    assert_eq!(harness.engine.flow_count(), 0, "no flow is left");
    assert_eq!(
        harness.engine.budget.promised, 0,
        "no window is left promised against the budget"
    );
    assert_eq!(harness.engine.next_deadline(), None, "no timer is left");
    assert!(
        !harness.engine.has_output(),
        "a shutdown writes nothing; reset_all is what leaves resets"
    );
    let (_, ended) = read_available(&mut stream);
    assert!(
        matches!(ended, Some(Err(_))),
        "the relay of an established flow sees a reset: {ended:?}"
    );
    for (index, mut stream) in half_open.into_iter().enumerate() {
        let (_, ended) = read_available(&mut stream);
        assert!(
            matches!(ended, Some(Err(_))),
            "the relay of half-open flow {index} sees a reset: {ended:?}"
        );
    }
}

/// A deadline a flow puts off is the subtlest of the three ways an entry in
/// the timer heap goes stale: arming only pushes a deadline that is earlier
/// than the one queued, so the entry that was due sooner stays and the
/// engine wakes for it with nothing to do. Re-timing it has to leave the
/// later deadline queued -- dropping the entry alone would take the flow's
/// timer away for good.
#[test]
fn the_engine_waits_for_the_keep_alive_a_flow_put_off_and_still_fires_it() {
    let mut harness = Harness::new();
    let (server, _stream) = harness.establish();
    let first = harness
        .engine
        .next_queued_timer()
        .expect("the flow armed its keep-alive");

    harness.advance(KEEPALIVE_GRID);
    harness.send(&harness.segment(1001, server, ACK, 512), &[]);

    let put_off = harness
        .engine
        .next_queued_timer()
        .expect("the flow still waits for a keep-alive");
    assert_eq!(
        put_off,
        first + KEEPALIVE_GRID,
        "the client's segment moved the keep-alive a grid on"
    );
    assert_eq!(
        harness.engine.queued_timers(),
        1,
        "and left nothing behind to wake for"
    );

    harness.advance(put_off - harness.now);
    assert_eq!(
        harness.sent().len(),
        1,
        "the keep-alive probe of the deadline it was re-timed for went out"
    );
}

/// Earning a large window creates no work after the peer goes quiet. Once
/// its receive budget is released, only the ordinary keep-alive remains;
/// neither window growth nor a drained send buffer may keep waking the pump.
#[test]
fn large_windows_leave_no_periodic_work_after_the_flow_goes_quiet() {
    for (windows, target) in [
        (CAPTURE_WINDOWS, 1024 * 1024),
        (TUNNEL_WINDOWS, 32 * 1024 * 1024),
    ] {
        let mut harness = Harness::new();
        harness.engine = harness.engine.with_windows(windows);
        let (syn_ack, mut stream) = harness.open();
        let server = syn_ack.seq.0.wrapping_add(1);
        harness.send(&harness.segment(1001, server, ACK, 512), &[]);
        let (seq, window) = harness.grow_window_to(server, 1001, target, &mut stream);
        assert!(window >= target);
        write(&mut stream, &[1; 4096]);
        harness.drain();
        harness.send(&harness.segment(seq, server + 4096, ACK, 512), &[]);
        harness.drain();
        let _ = read_available(&mut stream);
        harness.drain();
        harness.advance(Duration::from_secs(2));
        harness.drain();
        assert_eq!(harness.engine.budget.granted, 0);
        assert_eq!(harness.engine.budget.promised, 0);
        assert!(!harness.engine.has_output());
        let keepalive = harness.engine.next_queued_timer().unwrap();
        assert!(keepalive > harness.now + Duration::from_secs(10));
        assert_eq!(harness.engine.next_deadline(), Some(keepalive));
        // Polling the driver without new traffic must preserve that wait.
        for _ in 0..100 {
            harness.advance(Duration::from_millis(10));
            assert!(harness.sent().is_empty());
            assert_eq!(harness.engine.next_deadline(), Some(keepalive));
        }
    }
}

/// The second way: a flow that arms an earlier deadline leaves the entry it
/// had, and that one is still in the heap when the earlier timer has been
/// served. The engine must drop it instead of waking for it.
#[test]
fn a_timer_an_earlier_one_superseded_is_dropped_rather_than_waited_for() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    let keep_alive = harness
        .engine
        .next_queued_timer()
        .expect("the flow armed its keep-alive");

    // Bytes for the client arm a retransmission, due far sooner.
    write(&mut stream, b"to the client");
    harness.drain();
    let retransmit = harness
        .engine
        .next_queued_timer()
        .expect("the flow waits for its retransmission");
    assert!(retransmit < keep_alive, "which is the sooner of the two");
    assert_eq!(
        harness.engine.queued_timers(),
        2,
        "the keep-alive's entry is still in the heap behind it"
    );

    // The client takes the bytes a grid later: the retransmission is done
    // with and the keep-alive it hid has moved on.
    harness.advance(KEEPALIVE_GRID);
    harness.send(
        &harness.segment(1001, server.wrapping_add(13), ACK, 512),
        &[],
    );

    assert_eq!(
        harness.engine.next_queued_timer(),
        Some(keep_alive + KEEPALIVE_GRID),
        "the engine waits for the keep-alive the flow has, not the one it had"
    );
    assert_eq!(harness.engine.queued_timers(), 1, "and for nothing else");
}

/// The third way: the flow an entry belongs to is gone. Its slot is empty,
/// so nothing can be served at that instant, and the pump woke for it all
/// the same.
#[test]
fn a_flow_the_engine_removed_leaves_no_timer_to_wake_for() {
    let mut harness = Harness::new();
    let (server, _stream) = harness.establish();
    // Past the pace of the handshake, so the keep-alive is what the flow
    // waits for and the entry outlives it by a long way.
    harness.advance(KEEPALIVE_GRID);
    assert_eq!(
        harness.engine.queued_timers(),
        1,
        "the flow waits for its keep-alive"
    );

    harness.send(&harness.segment(1001, server, RST, 512), &[]);
    assert_eq!(harness.engine.flow_count(), 0, "the reset ended the flow");

    // A grid on, the receiving sweep has stopped as well, so the gone
    // flow's entry is all that is left to report.
    harness.advance(KEEPALIVE_GRID);
    assert_eq!(
        harness.engine.next_deadline(),
        None,
        "nothing is waited for"
    );
    assert_eq!(harness.engine.queued_timers(), 0, "and the heap is empty");
}

/// What the flows hold of the send budget stays inside it. A floor under
/// every flow's share promises more than the budget as soon as enough flows
/// reach it -- the receive side's did, and the send side had no budget at
/// all, which is how a thousand clients that stop reading came to a gigabyte.
#[test]
fn the_send_buffers_of_every_flow_count_fit_the_budget() {
    let mut harness = Harness::new();
    let mut streams = Vec::new();
    for port in 0..64u16 {
        let mut syn = harness.segment(1000, 0, SYN, 65535);
        syn.local = SocketAddr::new(harness.client.ip(), 20000 + port);
        syn.window_scale = Some(7);
        harness.send(&syn, &[]);
        streams.push(harness.accept.try_recv().expect("a stream per SYN"));
    }
    harness.drain();
    // Every relay writes, so every flow sizes a send buffer.
    for stream in &mut streams {
        write(stream, &[1_u8; 4096]);
    }
    harness.drain();
    assert!(
        harness.engine.budget.granted <= CAPTURE_WINDOWS.send_budget,
        "64 flows hold {} bytes against the {} the budget allows",
        harness.engine.budget.granted,
        CAPTURE_WINDOWS.send_budget
    );
    assert!(
        harness.engine.budget.granted > 0,
        "the flows do hold send buffers"
    );
}

/// Forty connections that moved a little and went quiet hold none of the
/// send budget, so a flow that opens after them buffers ahead of its
/// client's acknowledgements. While every open flow held its 1 MiB floor,
/// 32 quiet connections took the whole budget, and each later flow wrote one
/// chunk and then waited for the client to acknowledge all of it.
#[test]
fn quiet_flows_hold_none_of_the_send_budget() {
    let mut harness = Harness::new();
    let mut quiet = Vec::new();
    for port in 0..40u16 {
        harness.client.set_port(20000 + port);
        let (server, mut stream) = harness.establish();
        write(&mut stream, &[1_u8; 4096]);
        harness.drain();
        harness.send(&harness.segment(1001, server + 4096, ACK, 512), &[]);
        harness.drain();
        quiet.push(stream);
    }
    assert_eq!(
        harness.engine.budget.granted, 0,
        "no quiet flow holds a buffer"
    );
    harness.client.set_port(20040);
    let (_, mut stream) = harness.establish();
    write(&mut stream, &[2_u8; 64 * 1024]);
    harness.drain();
    // The engine took the first chunk and sized the buffer, so the next one
    // goes in before the client has acknowledged anything.
    write(&mut stream, &[2_u8; 64 * 1024]);
}

#[test]
fn the_syn_ack_answers_the_clients_options() {
    let mut harness = Harness::new();
    let (syn_ack, _stream) = harness.open();
    assert_eq!(syn_ack.flags, SYN | ACK);
    assert_eq!(syn_ack.ack, Seq(1001));
    // The device carries MTU, the flow offers at most MAX_OFFERED_MSS.
    assert_eq!(syn_ack.options.mss, Some(MAX_OFFERED_MSS as u16));
    assert_eq!(syn_ack.options.window_scale, Some(CAPTURE_WINDOWS.shift));
    assert!(syn_ack.options.sack_permitted);
    // A flow starts with the window it has not had to earn, and a SYN's
    // window is unscaled.
    assert_eq!(usize::from(syn_ack.window), CAPTURE_WINDOWS.start);

    // The same SYN again: our SYN|ACK went missing, send it again.
    let mut syn = harness.segment(1000, 0, SYN, 65535);
    syn.window_scale = Some(7);
    harness.send(&syn, &[]);
    let again = harness.sent();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].seg.seq, syn_ack.seq);
    assert_eq!(again[0].seg.flags, SYN | ACK);
}

#[test]
fn an_unscaled_window_draws_no_stream_of_updates() {
    let mut harness = Harness::new();
    // No window scaling: every window ends at 65 535 bytes.
    let mut syn = harness.segment(1000, 0, SYN, 64240);
    syn.mss = Some(1460);
    harness.send(&syn, &[]);
    let syn_ack = harness.sent().remove(0).seg;
    let mut stream = harness.accept.try_recv().unwrap();
    let server = syn_ack.seq.0.wrapping_add(1);
    harness.send(&harness.segment(1001, server, ACK, 64240), &[]);
    assert!(
        harness.sent().is_empty(),
        "the SYN|ACK already offered the largest window"
    );
    harness.send(&harness.segment(1001, server, PSH | ACK, 64240), b"request");
    assert_eq!(harness.sent().len(), 1, "the data is acknowledged");
    assert_eq!(read_available(&mut stream).0, b"request");
    // Reading cannot move an edge the window field already holds at its end.
    assert!(harness.sent().is_empty());
    assert!(harness.sent().is_empty());
}

#[test]
fn bytes_cross_both_ways_and_the_flow_closes_gracefully() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();

    harness.send(&harness.segment(1001, server, PSH | ACK, 512), b"hello");
    let acks = harness.sent();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].seg.ack, Seq(1006));
    assert!(acks[0].payload.is_empty());
    assert_eq!(read_available(&mut stream).0, b"hello");

    write(&mut stream, b"world");
    let data = harness.sent();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].payload, b"world");
    assert_eq!(data[0].seg.seq, Seq(server));
    assert_eq!(
        data[0].seg.flags,
        PSH | ACK,
        "the segment draining the queue pushes"
    );
    harness.send(&harness.segment(1006, server + 5, ACK, 512), &[]);
    assert!(harness.sent().is_empty());

    // The client closes; the relay sees EOF, then closes its side.
    harness.send(&harness.segment(1006, server + 5, FIN | ACK, 512), &[]);
    let fin_ack = harness.sent();
    assert_eq!(fin_ack.len(), 1);
    assert_eq!(fin_ack[0].seg.ack, Seq(1007));
    let (rest, end) = read_available(&mut stream);
    assert!(rest.is_empty());
    assert!(matches!(end, Some(Ok(()))), "EOF after the client's FIN");

    drop(stream);
    let fin = harness.sent();
    assert_eq!(fin.len(), 1);
    assert_eq!(fin[0].seg.flags, FIN | ACK);
    assert_eq!(fin[0].seg.seq, Seq(server + 5));
    harness.send(&harness.segment(1007, server + 6, ACK, 512), &[]);
    assert_eq!(
        harness.engine.flow_count(),
        0,
        "LAST-ACK ends with the ACK of our FIN"
    );
}

#[test]
fn out_of_order_data_is_sacked_and_delivered_once_the_gap_fills() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();

    harness.send(&harness.segment(1004, server, ACK, 512), b"def");
    let dup = harness.sent();
    assert_eq!(dup.len(), 1, "out-of-order data is acknowledged at once");
    assert_eq!(dup[0].seg.ack, Seq(1001));
    assert_eq!(
        dup[0].seg.options.sack.as_slice(),
        &[(Seq(1004), Seq(1007))]
    );
    assert!(read_available(&mut stream).0.is_empty());

    harness.send(&harness.segment(1010, server, ACK, 512), b"jkl");
    let dup = harness.sent();
    assert_eq!(
        dup[0].seg.options.sack.as_slice(),
        &[(Seq(1010), Seq(1013)), (Seq(1004), Seq(1007))],
        "the block with the latest arrival comes first"
    );

    // Overlapping the held data: only the gap is kept.
    harness.send(&harness.segment(1001, server, ACK, 512), b"abcdefghi");
    let ack = harness.sent();
    assert_eq!(ack[0].seg.ack, Seq(1013));
    assert!(ack[0].seg.options.sack.is_empty());
    assert_eq!(read_available(&mut stream).0, b"abcdefghijkl");
}

/// Four uploads earn the largest window and then go quiet with their
/// connections open: the windows they advertised still add up to the whole
/// budget, but their clients send nothing into the capture device. A new
/// flow's SYN|ACK offers its starting window and its first bytes go through
/// at once; while every open flow's promise counted, it offered none, and the
/// client's ClientHello waited for a zero-window probe.
#[test]
fn flows_that_went_quiet_leave_the_budget_to_the_next_flow() {
    let mut harness = Harness::new();
    let mut quiet = Vec::new();
    let mut promised = 0;
    for port in 20000..20004 {
        harness.client.set_port(port);
        let (server, mut stream) = harness.establish();
        let (_, window) = harness.grow_window_to(server, 1001, 1024 * 1024, &mut stream);
        promised += window;
        harness.advance(Duration::from_secs(2));
        harness.drain();
        quiet.push(stream);
    }
    assert!(
        promised >= CAPTURE_WINDOWS.budget,
        "the quiet flows promised the whole budget"
    );
    harness.client.set_port(20004);
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK | PSH, 512), &[1; 1500]);
    assert_eq!(
        read_available(&mut stream).0.len(),
        1500,
        "the first bytes go through"
    );
    assert_eq!(harness.sent().last().unwrap().seg.ack, Seq(2501));
}

/// Four flows still receiving hold the whole budget in promises; a flow that
/// opens then is held back to its starting window, not to none.
#[test]
fn a_new_flow_keeps_its_starting_window_whatever_the_others_promised() {
    let mut harness = Harness::new();
    let mut receiving = Vec::new();
    for port in 20000..20004 {
        harness.client.set_port(port);
        let (server, mut stream) = harness.establish();
        harness.grow_window_to(server, 1001, 1024 * 1024, &mut stream);
        receiving.push(stream);
    }
    assert_eq!(harness.engine.budget.promised, CAPTURE_WINDOWS.budget);
    harness.client.set_port(20004);
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK | PSH, 512), &[1; 1500]);
    assert_eq!(
        read_available(&mut stream).0.len(),
        1500,
        "the first bytes go through"
    );
}

/// A connection of small requests keeps its starting window however many it
/// sends, since none fills a window in time; while every byte counted, these
/// 800 KiB of requests grew it to 512 KiB. A client that sends a whole window
/// at once earns the next one.
#[test]
fn only_a_client_that_fills_its_window_in_time_grows_it() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    let window = |harness: &mut Harness, seq: u32| {
        let sent = harness.sent();
        let ack = &sent.last().expect("the bytes are acknowledged").seg;
        assert_eq!(ack.ack, Seq(seq));
        usize::from(ack.window) << CAPTURE_WINDOWS.shift
    };
    let mut seq = 1001_u32;
    for _ in 0..200 {
        harness.advance(Duration::from_millis(100));
        harness.send(&harness.segment(seq, server, ACK | PSH, 512), &[7; 4096]);
        seq = seq.wrapping_add(4096);
        assert_eq!(read_available(&mut stream).0.len(), 4096);
        assert_eq!(window(&mut harness, seq), CAPTURE_WINDOWS.start);
    }
    let burst = vec![7; CAPTURE_WINDOWS.start];
    harness.send(&harness.segment(seq, server, ACK | PSH, 512), &burst);
    seq = seq.wrapping_add(burst.len() as u32);
    assert_eq!(read_available(&mut stream).0.len(), burst.len());
    assert_eq!(window(&mut harness, seq), 2 * CAPTURE_WINDOWS.start);
}

/// A quiet flow that sends again puts what its client may still send back
/// against the budget.
#[test]
fn a_quiet_flow_counts_its_promise_again_once_it_sends() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    let (seq, window) = harness.grow_window_to(server, 1001, 256 * 1024, &mut stream);
    assert_eq!(harness.engine.budget.promised, window);
    harness.advance(Duration::from_secs(2));
    assert_eq!(
        harness.engine.budget.promised, 0,
        "the quiet flow's promise leaves the sum"
    );
    harness.send(&harness.segment(seq, server, ACK | PSH, 512), b"again");
    assert_eq!(read_available(&mut stream).0, b"again");
    let ack = harness.sent();
    let ack = &ack.last().expect("the bytes are acknowledged").seg;
    assert_eq!(ack.ack, Seq(seq.wrapping_add(5)));
    assert_eq!(
        harness.engine.budget.promised,
        usize::from(ack.window) << CAPTURE_WINDOWS.shift,
        "its promise counts again"
    );
}

#[test]
fn an_advertised_edge_holds_when_the_window_budget_shrinks() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // The flow earns a 256 KiB window first.
    let (start, window) = harness.grow_window_to(server, 1001, 256 * 1024, &mut stream);
    let edge = start as usize + window;
    // Thirty-one more flows open: the 4 MiB budget now gives each 128 KiB.
    let mut others = Vec::new();
    for port in 0..31u16 {
        let mut syn = harness.segment(7000, 0, SYN, 65535);
        syn.local = SocketAddr::new(harness.client.ip(), 20000 + port);
        syn.window_scale = Some(7);
        harness.send(&syn, &[]);
        others.push(harness.accept.try_recv().unwrap());
    }
    harness.drain();
    harness.send(&harness.segment(start, server, ACK, 512), b"0123456789");
    let ack = harness.sent();
    assert_eq!(ack.len(), 1);
    let advertised =
        ack[0].seg.ack.0 as usize + (usize::from(ack[0].seg.window) << CAPTURE_WINDOWS.shift);
    assert!(advertised >= edge, "the right edge does not move left");
    // The client may send up to the edge it was given.
    let after = start.wrapping_add(10);
    let end = harness.send_bulk(after, server, edge - after as usize, 9);
    assert_eq!(end as usize, edge);
    let ack = harness.sent();
    assert_eq!(ack.last().unwrap().seg.ack, Seq(edge as u32));
    assert_eq!(read_available(&mut stream).0.len(), window);
}

#[test]
fn a_closed_window_reopens_after_the_budget_shrank_under_it() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // The flow earns a window larger than the share 32 flows leave, then
    // fills it.
    let (filled, _) = harness.grow_window_to(server, 1001, 256 * 1024, &mut stream);
    let (seq, queued) = harness.close_window(server, filled);
    assert!(
        queued > 128 * 1024,
        "the queue holds more than the new share"
    );
    // Thirty-one more flows open: the budget now gives each flow 128 KiB, so
    // the read the relay was asked to report no longer reopens enough.
    let mut others = Vec::new();
    for port in 0..31u16 {
        let mut syn = harness.segment(7000, 0, SYN, 65535);
        syn.local = SocketAddr::new(harness.client.ip(), 20000 + port);
        syn.window_scale = Some(7);
        harness.send(&syn, &[]);
        others.push(harness.accept.try_recv().unwrap());
    }
    harness.drain();
    let mut cx = context();
    let mut read = 0;
    while read < 100 * 1024 {
        match stream.poll_read_chunk(&mut cx, 64 * 1024) {
            Poll::Ready(Ok(Some(chunk))) => read += chunk.len(),
            other => panic!("queued bytes read: {other:?}"),
        }
    }
    assert!(harness.sent().is_empty(), "not yet worth an update");
    // Reading the rest frees the whole 128 KiB.
    let (rest, _) = read_available(&mut stream);
    assert_eq!(read + rest.len(), queued);
    let update = harness.sent();
    assert_eq!(update.len(), 1, "the drained queue reopens the window");
    assert_eq!(update[0].seg.ack, Seq(seq));
    assert!(usize::from(update[0].seg.window) << CAPTURE_WINDOWS.shift >= 64 * 1024);
}

#[test]
fn the_window_reopens_once_the_relay_reads_enough() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // The flow earns a 256 KiB window first.
    let (seq, window) = harness.close_window(server, 1001);
    assert!(window > 0, "the client filled the window it had");
    // Reading a little is not worth an update; reading most of it is.
    let mut cx = context();
    let _ = stream.poll_read_chunk(&mut cx, 1000);
    assert!(harness.sent().is_empty());
    let (read, _) = read_available(&mut stream);
    assert_eq!(read.len() + 1000, window);
    let update = harness.sent();
    assert_eq!(update.len(), 1);
    assert!(update[0].seg.window > 0);
    assert_eq!(update[0].seg.ack, Seq(seq));
}

#[test]
fn unacknowledged_data_is_retransmitted_after_the_timeout() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    write(&mut stream, b"lost?");
    assert_eq!(harness.sent()[0].payload, b"lost?");
    harness.advance(Duration::from_millis(100));
    assert!(harness.sent().is_empty(), "not before the timeout");
    harness.advance(Duration::from_secs(1));
    let again = harness.sent();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].seg.seq, Seq(server));
    assert_eq!(again[0].payload, b"lost?");
    harness.send(&harness.segment(1001, server + 5, ACK, 512), &[]);
    harness.advance(Duration::from_secs(10));
    assert!(harness.sent().is_empty(), "acknowledged data is not resent");
}

#[test]
fn three_duplicate_acks_retransmit_the_first_unacknowledged_segment() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK, u16::MAX), &[]);
    write(&mut stream, &vec![3u8; 20 * 1460]);
    assert_eq!(harness.sent().len(), 10);
    harness.send(&harness.segment(1001, server + 1460, ACK, u16::MAX), &[]);
    assert_eq!(harness.sent().len(), 2);
    // The segment after the first is lost: three duplicates of its ACK.
    for _ in 0..3 {
        harness.send(&harness.segment(1001, server + 1460, ACK, u16::MAX), &[]);
    }
    let retransmitted = harness.sent();
    assert_eq!(retransmitted[0].seg.seq, Seq(server + 1460));
    assert_eq!(retransmitted[0].payload.len(), 1460);
    // A partial acknowledgement retransmits the next hole at once (RFC 6582).
    harness.send(
        &harness.segment(1001, server + 2 * 1460, ACK, u16::MAX),
        &[],
    );
    let next = harness.sent();
    assert_eq!(next[0].seg.seq, Seq(server + 2 * 1460));
}

#[test]
fn the_initial_window_then_slow_start_pace_a_burst() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK, u16::MAX), &[]);
    write(&mut stream, &vec![3u8; 20 * 1460]);
    // RFC 6928: ten segments for a 1460-byte MSS.
    let first = harness.sent();
    assert_eq!(first.len(), 10);
    assert!(first.iter().all(|segment| segment.payload.len() == 1460));
    // Each acknowledged segment opens room for two more.
    harness.send(&harness.segment(1001, server + 1460, ACK, u16::MAX), &[]);
    assert_eq!(harness.sent().len(), 2);
}

/// A client whose window holds no more than one segment (Windows behind a
/// 65535-byte MTU: a 65 495-byte MSS and a 64 KiB window) gets segments of
/// half its largest window, so two are in flight and it acknowledges the
/// second at once instead of holding a lone one for its delayed-ACK timer.
#[test]
fn segments_take_half_the_largest_window_offered() {
    let mut harness = Harness::new();
    let mut syn = harness.segment(1000, 0, SYN, 65535);
    syn.mss = Some(65495);
    syn.window_scale = Some(8);
    syn.sack_permitted = true;
    harness.send(&syn, &[]);
    let server = harness.sent()[0].seg.seq.0.wrapping_add(1);
    let mut stream = harness
        .accept
        .try_recv()
        .expect("the SYN surfaces a stream");
    // 255 units of 256 bytes, the window a Windows client offered.
    let window = 255 * 256;
    harness.send(&harness.segment(1001, server, ACK, 255), &[]);
    harness.drain();
    write(&mut stream, &vec![7u8; 256 * 1024]);
    let first = harness.sent();
    assert_eq!(first.len(), 2, "two segments share the window");
    assert!(first
        .iter()
        .all(|segment| segment.payload.len() == window / 2));
    // Acknowledging both opens the window for two more.
    harness.send(
        &harness.segment(1001, server + window as u32, ACK, 255),
        &[],
    );
    let next = harness.sent();
    assert_eq!(next.len(), 2);
    assert!(next
        .iter()
        .all(|segment| segment.payload.len() == window / 2));
}

#[test]
fn a_handshake_that_resent_its_syn_ack_starts_with_one_segment() {
    let mut harness = Harness::new();
    let (syn_ack, mut stream) = harness.open();
    harness.advance(Duration::from_millis(1100));
    let again = harness.sent();
    assert_eq!(again.len(), 1);
    assert!(again[0].seg.has(SYN | ACK), "the SYN|ACK again");
    let server = syn_ack.seq.0.wrapping_add(1);
    harness.send(&harness.segment(1001, server, ACK, u16::MAX), &[]);
    harness.drain();
    write(&mut stream, &vec![3u8; 20 * 1460]);
    assert_eq!(harness.sent().len(), 1, "RFC 6928 section 2");
}

#[test]
fn a_retransmission_timeout_shrinks_the_window_to_one_segment() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK, u16::MAX), &[]);
    write(&mut stream, &vec![3u8; 20 * 1460]);
    assert_eq!(harness.sent().len(), 10);
    // A loss probe goes first: new data, past the congestion window (RFC
    // 8985 section 7.3).
    harness.advance(Duration::from_millis(10));
    let probe = harness.sent();
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].seg.seq, Seq(server + 10 * 1460));
    // Unanswered, the retransmission timeout follows.
    harness.advance(Duration::from_millis(1100));
    let resent = harness.sent();
    assert_eq!(resent.len(), 1, "the loss window is one segment");
    assert_eq!(resent[0].seg.seq, Seq(server));
}

#[test]
fn a_small_window_takes_held_data_after_the_override_timeout() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // A 20 KiB window (scale 7: 160 units) against 30 KiB of data.
    harness.send(&harness.segment(1001, server, ACK, 160), &[]);
    write(&mut stream, &vec![5u8; 30 * 1024]);
    let sent: usize = harness
        .sent()
        .iter()
        .map(|segment| segment.payload.len())
        .sum();
    assert!(sent <= 20 * 1024);
    // The client takes it all but leaves one 128-byte unit of window: a
    // segment that small waits for more window (RFC 9293 section 3.8.6.2.1).
    harness.send(&harness.segment(1001, server + sent as u32, ACK, 1), &[]);
    assert!(
        harness.sent().is_empty(),
        "sender SWS avoidance holds a tiny segment"
    );
    // Without more window, the override timeout sends it anyway.
    harness.advance(Duration::from_millis(250));
    let late = harness.sent();
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].payload.len(), 128);
}

/// The override timeout that lets a held small segment go does not stay
/// due while the output is full: the engine's next deadline moves on, and
/// the segment goes out once the output takes it.
#[test]
fn an_elapsed_sws_override_waits_for_output_room_off_the_timers() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK, 160), &[]);
    write(&mut stream, &vec![5u8; 30 * 1024]);
    let sent: usize = harness
        .sent()
        .iter()
        .map(|segment| segment.payload.len())
        .sum();
    harness.send(&harness.segment(1001, server + sent as u32, ACK, 1), &[]);
    assert!(harness.sent().is_empty(), "the tiny segment is held");
    // The override runs out while the output is full: nothing is emitted.
    for _ in 0..3 {
        harness.advance(Duration::from_millis(250));
        assert!(
            harness
                .engine
                .next_deadline()
                .is_none_or(|deadline| deadline > harness.now),
            "an elapsed override does not wake the pump again"
        );
    }
    let late = harness.sent();
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].payload.len(), 128);
}

#[test]
fn an_rst_inside_the_window_draws_a_challenge_ack() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1101, server, RST | ACK, 0), &[]);
    let challenge = harness.sent();
    assert_eq!(challenge.len(), 1, "RFC 5961 section 3.2");
    assert_eq!(challenge[0].seg.ack, Seq(1001));
    assert_eq!(harness.engine.flow_count(), 1);
    harness.send(&harness.segment(1001, server, RST | ACK, 0), &[]);
    assert_eq!(harness.engine.flow_count(), 0);
    assert!(read_available(&mut stream).1.unwrap().is_err());
}

#[test]
fn a_zero_window_is_probed_until_it_opens() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, ACK, 0), &[]);
    write(&mut stream, b"waiting");
    assert!(harness.sent().is_empty(), "nothing fits a zero window");
    harness.advance(Duration::from_secs(1));
    let probe = harness.sent();
    assert_eq!(probe.len(), 1);
    assert_eq!(
        probe[0].seg.seq,
        Seq(server - 1),
        "a probe repeats an acknowledged byte"
    );
    assert!(probe[0].payload.is_empty());
    harness.send(&harness.segment(1001, server, ACK, 512), &[]);
    let data = harness.sent();
    assert_eq!(data[0].payload, b"waiting");
}

#[test]
fn resets_end_flows_either_way() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.send(&harness.segment(1001, server, RST | ACK, 0), &[]);
    let (_, end) = read_available(&mut stream);
    assert_eq!(
        end.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert_eq!(harness.engine.flow_count(), 0);

    let (_, stream) = harness.open();
    stream.reset_handle().reset();
    let rst = harness.sent();
    assert_eq!(rst.len(), 1);
    assert!(rst[0].seg.has(RST));
    assert_eq!(harness.engine.flow_count(), 0);
}

#[test]
fn an_ending_capture_resets_each_flow_where_its_client_takes_it() {
    // Data in flight: a reset at SND.UNA for XNU, at SND.NXT for Linux.
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    write(&mut stream, b"unacknowledged");
    assert_eq!(harness.sent()[0].payload, b"unacknowledged");
    harness.engine.reset_all();
    let resets = harness.sent();
    let seqs = resets.iter().map(|reset| reset.seg.seq).collect::<Vec<_>>();
    assert_eq!(seqs, [Seq(server), Seq(server.wrapping_add(14))]);
    for reset in &resets {
        assert_eq!(reset.seg.flags, RST | ACK);
        assert_eq!(reset.seg.ack, Seq(1001));
    }
    let (_, end) = read_available(&mut stream);
    assert_eq!(
        end.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset,
        "the relay fails, so its upstream connection ends too"
    );
    assert_eq!(harness.engine.flow_count(), 0);
    assert!(!harness.engine.has_output());

    // Nothing in flight: one reset.
    let mut harness = Harness::new();
    let (server, _stream) = harness.establish();
    harness.engine.reset_all();
    let resets = harness.sent();
    assert_eq!(resets.len(), 1);
    assert_eq!(resets[0].seg.seq, Seq(server));
}

#[test]
fn segments_for_no_flow_draw_resets() {
    let mut harness = Harness::new();
    harness.send(&harness.segment(5000, 777, ACK, 512), b"stray");
    let rst = harness.sent();
    assert_eq!(rst.len(), 1);
    assert_eq!(rst[0].seg.flags, RST);
    assert_eq!(rst[0].seg.seq, Seq(777));

    harness.send(&harness.segment(5000, 0, FIN, 512), &[]);
    let rst = harness.sent();
    assert_eq!(rst[0].seg.flags, RST | ACK);
    assert_eq!(rst[0].seg.ack, Seq(5001));
}

#[test]
fn client_data_after_the_relay_left_draws_a_reset() {
    let mut harness = Harness::new();
    let (server, stream) = harness.establish();
    drop(stream);
    let fin = harness.sent();
    assert!(fin[0].seg.has(FIN));
    harness.send(&harness.segment(1001, server + 1, ACK, 512), b"late");
    let rst = harness.sent();
    assert!(rst.iter().any(|segment| segment.seg.has(RST)));
    assert_eq!(harness.engine.flow_count(), 0);
}

#[test]
fn flows_beyond_the_cap_are_refused() {
    let (accept_tx, _accept) = mpsc::unbounded_channel();
    let active = Arc::new(AtomicUsize::new(MAX_FLOWS));
    let mut engine = TcpEngine::new(MTU, accept_tx, active, None);
    let harness = Harness::new();
    let syn = harness.segment(1000, 0, SYN, 65535);
    let header = segment::write_header(&syn, 0);
    engine.on_packet(
        Bytes::copy_from_slice(header.as_slice()),
        ClientOwner::Known(None),
        None,
        harness.now,
    );
    let mut out = Vec::new();
    engine.emit(harness.now, 8, &mut |segment| out.push(segment));
    assert_eq!(out.len(), 1);
    let rst = segment::parse(&out[0].to_vec()).unwrap();
    assert_eq!(rst.flags, RST | ACK);
    assert_eq!(engine.flow_count(), 0);
}

#[test]
fn segments_of_a_flow_another_queue_holds_go_to_that_queue() {
    let holders = Arc::new(FlowHolders::new(2));
    let mut holder = Harness::on_queue(0, &holders);
    let mut other = Harness::on_queue(1, &holders);
    let (server, mut stream) = holder.establish();

    // Data, and a repeated SYN, that land on the other queue: no reset and no
    // second flow there; they go to the holder.
    other.send(&other.segment(1001, server, ACK | PSH, 512), b"hello");
    other.send(&other.segment(1000, 0, SYN, 65535), &[]);
    assert!(other.sent().is_empty(), "no reset for a held flow");
    assert!(other.accept.try_recv().is_err(), "no second flow");
    let foreign = other.engine.take_foreign();
    assert_eq!(foreign.len(), 2);
    for segment in foreign {
        assert_eq!(segment.queue, 0);
        holder
            .engine
            .on_packet(segment.packet, segment.process, None, holder.now);
    }
    assert_eq!(read_available(&mut stream).0, b"hello");

    // Once the holder's flow ends the tuple is nobody's: a stray segment
    // draws a reset wherever it lands.
    holder.send(&holder.segment(1006, server, RST, 0), &[]);
    holder.drain();
    other.send(&other.segment(1006, server, ACK, 512), &[]);
    let reset = other.sent();
    assert_eq!(reset.len(), 1);
    assert!(reset[0].seg.has(RST));
    assert!(other.engine.take_foreign().is_empty());

    // A new SYN for the tuple belongs to the queue it lands on.
    other.send(&other.segment(5000, 0, SYN, 65535), &[]);
    assert!(other.accept.try_recv().is_ok());
    holder.send(&holder.segment(5001, 1, ACK, 512), &[]);
    assert!(holder.sent().is_empty());
    assert_eq!(holder.engine.take_foreign()[0].queue, 1);
}

#[test]
fn new_flows_go_to_the_queue_holding_the_fewest() {
    let holders = Arc::new(FlowHolders::new(2));
    let mut first = Harness::on_queue(0, &holders);
    let mut second = Harness::on_queue(1, &holders);
    let emitted = |harness: &mut Harness| {
        harness.engine.attend(harness.now);
        let mut segments = 0;
        harness
            .engine
            .emit(harness.now, usize::MAX, &mut |_| segments += 1);
        segments
    };

    // Three flows whose SYNs all land on queue 0: the first stays, the second
    // goes to queue 1, which then answers it, and the third stays again.
    first.send(&first.syn_from(40_001), &[]);
    assert!(first.accept.try_recv().is_ok());
    assert!(first.engine.take_foreign().is_empty());
    first.send(&first.syn_from(40_002), &[]);
    assert!(first.accept.try_recv().is_err());
    let foreign = first.engine.take_foreign();
    assert_eq!(foreign.len(), 1);
    assert_eq!(foreign[0].queue, 1);
    for segment in foreign {
        second
            .engine
            .on_packet(segment.packet, segment.process, None, second.now);
    }
    assert!(second.accept.try_recv().is_ok());
    assert_eq!(emitted(&mut second), 1, "queue 1 writes the SYN|ACK");
    first.send(&first.syn_from(40_003), &[]);
    assert!(first.accept.try_recv().is_ok());
    assert_eq!(emitted(&mut first), 2);
}

#[test]
fn a_queue_takes_no_new_flow_until_its_engine_is_up() {
    let holders = Arc::new(FlowHolders::new(2));
    let mut first = Harness::on_queue(0, &holders);

    // Queue 1 holds no flow but has no engine to answer one: queue 0 keeps
    // both.
    first.send(&first.syn_from(40_001), &[]);
    first.send(&first.syn_from(40_002), &[]);
    assert!(first.accept.try_recv().is_ok());
    assert!(first.accept.try_recv().is_ok());
    assert!(first.engine.take_foreign().is_empty());

    // Once it is up, it takes the next.
    let _second = Harness::on_queue(1, &holders);
    first.send(&first.syn_from(40_003), &[]);
    assert!(first.accept.try_recv().is_err());
    assert_eq!(first.engine.take_foreign()[0].queue, 1);
}

#[test]
fn a_preferred_queue_takes_a_new_flow_whatever_it_holds() {
    let holders = Arc::new(FlowHolders::new(2));
    let mut first = Harness::on_queue(0, &holders);
    // Queue 0 holds one flow and queue 1 none, but the SYN prefers queue 0.
    first.open();
    let mut syn = first.segment(1000, 0, SYN, 65535);
    syn.local = SocketAddr::new(first.client.ip(), 40_010);
    let mut header = segment::write_header(&syn, 0);
    header.finish_checksum(std::iter::empty());
    first.engine.on_packet(
        Bytes::copy_from_slice(header.as_slice()),
        ClientOwner::Known(None),
        Some(0),
        first.now,
    );
    assert!(first.engine.take_foreign().is_empty());
    assert!(first.accept.try_recv().is_ok());
}

#[test]
fn time_wait_lets_a_newer_syn_reopen_the_tuple() {
    let mut harness = Harness::new();
    harness.time_wait();
    let mut old = harness.segment(900, 0, SYN, 65535);
    old.mss = Some(1460);
    harness.send(&old, &[]);
    let ack = harness.sent();
    assert_eq!(ack[0].seg.flags, ACK, "an old SYN is only acknowledged");
    assert_eq!(harness.engine.time_wait_count(), 1);
    let mut syn = harness.segment(90_000, 0, SYN, 65535);
    syn.mss = Some(1460);
    harness.send(&syn, &[]);
    let syn_ack = harness.sent();
    assert_eq!(syn_ack[0].seg.flags, SYN | ACK);
    assert_eq!(syn_ack[0].seg.ack, Seq(90_001));
    assert_eq!(harness.engine.time_wait_count(), 0);
    harness.advance(Duration::from_secs(3));
    assert_eq!(
        harness.engine.flow_count(),
        1,
        "the new incarnation lives on"
    );
}

impl CapturedTcpStream {
    fn poll_shutdown_for_tests(&mut self) {
        use tokio::io::AsyncWrite;
        let _ = std::pin::Pin::new(self).poll_shutdown(&mut context());
    }
}

#[test]
fn idle_flows_are_probed_and_dead_clients_aborted() {
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    harness.advance(Duration::from_secs(27));
    assert!(harness.sent().is_empty());
    harness.advance(Duration::from_secs(5));
    let probe = harness.sent();
    assert_eq!(probe.len(), 1, "a keep-alive after 28 to 32 idle seconds");
    assert_eq!(probe[0].seg.seq, Seq(server - 1));
    // The client answers; the flow lives on.
    harness.send(&harness.segment(1001, server, ACK, 512), &[]);
    harness.advance(Duration::from_secs(60));
    let _ = harness.sent();
    assert_eq!(harness.engine.flow_count(), 1);
    // Silence for the keep-alive time plus the timeout ends it.
    for _ in 0..10 {
        harness.advance(Duration::from_secs(10));
        let _ = harness.sent();
    }
    assert_eq!(harness.engine.flow_count(), 0);
    let (_, end) = read_available(&mut stream);
    assert!(end.unwrap().is_err(), "the relay sees the abort");
}

#[test]
fn time_wait_frees_the_flow_and_restarts_for_a_repeated_fin() {
    let mut harness = Harness::new();
    let start = harness.now;
    let server = harness.time_wait();
    assert_eq!(harness.engine.flow_count(), 0);
    assert_eq!(harness.active.load(Ordering::Relaxed), 0, "no longer live");
    assert_eq!(harness.engine.time_wait_count(), 1);
    harness.send(&harness.segment(1002, server, ACK, 512), &[]);
    assert!(
        harness.sent().is_empty(),
        "an ACK in sequence needs no answer"
    );

    harness.advance(Duration::from_secs(1));
    assert_eq!(
        harness.engine.next_deadline(),
        Some(start + Duration::from_secs(2)),
        "the engine wakes for the end of the wait"
    );
    harness.send(&harness.segment(1001, server, FIN | ACK, 512), &[]);
    let ack = harness.sent();
    assert_eq!(ack.len(), 1, "the client did not hear the ACK of its FIN");
    assert_eq!((ack[0].seg.seq, ack[0].seg.ack), (Seq(server), Seq(1002)));
    assert_eq!(ack[0].seg.flags, ACK);
    harness.advance(Duration::from_millis(1500));
    assert_eq!(harness.engine.time_wait_count(), 1, "the wait restarted");
    harness.advance(Duration::from_secs(1));
    assert_eq!(harness.engine.time_wait_count(), 0);
    assert_eq!(harness.engine.next_deadline(), None);
    harness.send(&harness.segment(1001, server, FIN | ACK, 512), &[]);
    assert_eq!(harness.sent()[0].seg.flags, RST, "the wait is over");
}

#[test]
fn only_an_exact_rst_ends_time_wait() {
    let mut harness = Harness::new();
    harness.time_wait();
    harness.send(&harness.segment(1500, 0, RST, 0), &[]);
    let challenge = harness.sent();
    assert_eq!(challenge.len(), 1, "RFC 5961 section 3.2");
    assert_eq!(challenge[0].seg.ack, Seq(1002));
    assert_eq!(harness.engine.time_wait_count(), 1);
    harness.send(&harness.segment(1002, 0, RST, 0), &[]);
    assert!(harness.sent().is_empty());
    assert_eq!(harness.engine.time_wait_count(), 0);
}

#[test]
fn the_oldest_time_wait_gives_way_past_the_cap() {
    let mut harness = Harness::new();
    harness.engine.set_max_time_waits(1);
    let first = harness.client;
    let first_server = harness.time_wait();
    harness.advance(Duration::from_millis(100));
    harness.client = "10.0.0.2:53124".parse().unwrap();
    let second_server = harness.time_wait();
    assert_eq!(harness.engine.time_wait_count(), 1);

    harness.send(&harness.segment(1001, second_server, FIN | ACK, 512), &[]);
    assert_eq!(harness.sent()[0].seg.flags, ACK, "the newer record stays");
    harness.client = first;
    harness.send(&harness.segment(1001, first_server, FIN | ACK, 512), &[]);
    assert_eq!(harness.sent()[0].seg.flags, RST, "the older one gave way");
}

#[test]
fn a_relay_gone_during_the_handshake_closes_after_it() {
    let mut harness = Harness::new();
    let (syn_ack, stream) = harness.open();
    drop(stream);
    assert!(
        harness.sent().is_empty(),
        "no FIN before the handshake completes"
    );
    let server = syn_ack.seq.0.wrapping_add(1);
    harness.send(&harness.segment(1001, server, ACK, 512), &[]);
    let fin = harness.sent();
    assert!(fin.iter().any(|segment| segment.seg.has(FIN)));
}

#[test]
fn a_writer_holding_a_large_chunk_wakes_when_it_fits() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Flag(AtomicBool);
    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let mut harness = Harness::new();
    let (server, mut stream) = harness.establish();
    // Open the client's window wide (65535 scaled by 7).
    harness.send(&harness.segment(1001, server, ACK, u16::MAX), &[]);
    write(&mut stream, &vec![1u8; 600 * 1024]);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    let mut chunk = Some(Bytes::from(vec![2u8; 512 * 1024]));
    assert!(stream.poll_write_chunk(&mut cx, &mut chunk).is_pending());
    // The chunk fits once 88 KiB of the first write are acknowledged: the
    // client acknowledges what arrives until then.
    let mut acked = 0u32;
    while acked < 88 * 1024 {
        assert!(!flag.0.load(Ordering::SeqCst), "not woken before it fits");
        let sent: usize = harness
            .sent()
            .iter()
            .map(|segment| segment.payload.len())
            .sum();
        assert!(sent > 0);
        acked += sent as u32;
        harness.send(&harness.segment(1001, server + acked, ACK, u16::MAX), &[]);
    }
    assert!(flag.0.load(Ordering::SeqCst), "the writer is woken");
    assert!(stream.poll_write_chunk(&mut cx, &mut chunk).is_ready());
}

/// Drops, duplicates and delays packets.
struct Impairment {
    rng: rand::rngs::StdRng,
    loss: f64,
    held: Vec<(u32, Vec<u8>)>,
}

impl Impairment {
    fn new(seed: u64, loss: f64) -> Self {
        use rand::SeedableRng;
        Self {
            rng: rand::rngs::StdRng::seed_from_u64(seed),
            loss,
            held: Vec::new(),
        }
    }

    fn pass(&mut self, packet: Vec<u8>, out: &mut Vec<Vec<u8>>) {
        use rand::Rng;
        if self.rng.random_bool(self.loss) {
            return;
        }
        if self.rng.random_bool(self.loss / 2.0) {
            out.push(packet.clone());
        }
        if self.rng.random_bool(self.loss) {
            let rounds = self.rng.random_range(1..6);
            self.held.push((rounds, packet));
        } else {
            out.push(packet);
        }
    }

    fn release(&mut self, out: &mut Vec<Vec<u8>>) {
        let mut kept = Vec::new();
        for (rounds, packet) in self.held.drain(..) {
            if rounds <= 1 {
                out.push(packet);
            } else {
                kept.push((rounds - 1, packet));
            }
        }
        self.held = kept;
    }
}

/// The byte at `index` of flow `flow`'s data.
fn pattern(flow: usize, index: usize) -> u8 {
    (index.wrapping_mul(31) ^ (index >> 9) ^ flow.wrapping_mul(97)) as u8
}

mod congestion;
mod hostile;
mod opening;

// Randomized transfers against smoltcp.

mod random {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant as SmolInstant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};

    struct Link {
        rx: VecDeque<Vec<u8>>,
        tx: Vec<Vec<u8>>,
        mtu: usize,
    }

    struct Rx(Vec<u8>);
    struct Tx<'a>(&'a mut Vec<Vec<u8>>);

    impl RxToken for Rx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }

    impl TxToken for Tx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut packet = vec![0; len];
            let result = f(&mut packet);
            self.0.push(packet);
            result
        }
    }

    impl Device for Link {
        type RxToken<'a> = Rx;
        type TxToken<'a> = Tx<'a>;

        fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
            let packet = self.rx.pop_front()?;
            Some((Rx(packet), Tx(&mut self.tx)))
        }

        fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
            Some(Tx(&mut self.tx))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.mtu;
            caps
        }
    }

    struct Flow {
        handle: SocketHandle,
        port: u16,
        client_sent: usize,
        client_received: usize,
        client_closed: bool,
        stream: Option<CapturedTcpStream>,
        relay_received: usize,
        relay_sent: usize,
        relay_eof: bool,
        relay_shutdown: bool,
        pending: Option<Bytes>,
        /// The longest stretch this flow had data to send and sent none: how
        /// long the engine left it without a window while others had one.
        starved: Duration,
        stretch: Duration,
        progress: usize,
        /// How long after every flow started sending this one's upload was
        /// through: what one flow's share of a shared link came to.
        upload_done: Option<Duration>,
    }

    impl Flow {
        fn done(&self, upload: usize, download: usize, sockets: &mut SocketSet<'_>) -> bool {
            self.relay_shutdown
                && self.relay_received == upload
                && self.client_received == download
                && !sockets.get_mut::<tcp::Socket>(self.handle).is_open()
        }
    }

    struct Plan {
        seed: u64,
        ipv6: bool,
        mtu: usize,
        flows: usize,
        upload: usize,
        download: usize,
        loss: f64,
        /// The smoltcp client's buffer per direction.
        client_buffer: usize,
        /// The capture device's queue in bytes. A packet that does not fit is
        /// dropped, as the device drops it. `None` leaves the queue unbounded.
        device_queue: Option<usize>,
        /// Bytes the engine takes out of the device per round, modelling a
        /// pump that cannot keep up with every flow's burst at once.
        device_read: Option<usize>,
        /// Bytes the relay takes from each flow per round, modelling a relay
        /// its upstream has backed up.
        relay_drain: Option<usize>,
        /// Bytes per millisecond the relay takes from all the flows
        /// together, modelling the one saturated uplink their upstream
        /// sockets share: capacity accrues as the clock moves and the flows
        /// take turns spending it, so the harness divides the link evenly
        /// and any unfairness left is the engine's.
        relay_drain_shared: Option<usize>,
        /// The most the slowest upload may take over the median, as a
        /// multiple: what the engine's metering comes to when the link below
        /// it is shared and saturated.
        upload_spread: Option<f64>,
        /// How long the first flow's relay takes nothing at all once the
        /// flows start sending, modelling an upstream socket that stops
        /// accepting bytes mid-transfer. That flow is left out of the
        /// fairness measures; the question it asks is what it costs the
        /// others.
        stall_first: Option<Duration>,
        /// The least of the shared link's capacity the other flows must use
        /// while [`Plan::stall_first`] holds, as a fraction: what the flow
        /// the engine is holding bytes and a shut window for costs the rest.
        link_share: Option<f64>,
        /// The longest a flow may go without the engine moving one of its
        /// bytes while the others are moving: what the budget's fairness
        /// comes to in the end.
        starve_limit: Option<Duration>,
        /// Opens one flow every this many rounds and holds every client's
        /// data until all of them are established, so the flows that opened
        /// first advertised their window while few were receiving and all of
        /// them then send at once.
        stagger: Option<usize>,
    }

    /// Moves `upload` bytes client→relay and `download` relay→client on each
    /// flow sharing one impaired link, then closes both ways; checks every
    /// byte.
    fn transfer(plan: Plan) {
        let Plan {
            seed,
            ipv6,
            mtu,
            flows,
            upload,
            download,
            loss,
            client_buffer,
            device_queue,
            device_read,
            relay_drain,
            relay_drain_shared,
            upload_spread,
            stall_first,
            link_share,
            stagger,
            starve_limit,
        } = plan;
        let mut rng = StdRng::seed_from_u64(seed);
        let (accept_tx, mut accept) = mpsc::unbounded_channel();
        let mut engine = TcpEngine::new(mtu as u32, accept_tx, Arc::new(AtomicUsize::new(0)), None);
        let mut link = Link {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu,
        };
        let (client_ip, target_ip) = if ipv6 {
            (
                IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                IpAddress::v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            )
        } else {
            (IpAddress::v4(10, 0, 0, 2), IpAddress::v4(93, 184, 216, 34))
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut link, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(client_ip, if ipv6 { 64 } else { 24 }))
                .unwrap();
        });
        if ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                    0xfd00, 0, 0, 0, 0, 0, 0, 1,
                ))
                .unwrap();
        } else {
            iface
                .routes_mut()
                .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
                .unwrap();
        }
        let mut sockets = SocketSet::new(vec![]);
        let mut all = Vec::new();
        for index in 0..flows {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; client_buffer]),
                tcp::SocketBuffer::new(vec![0; client_buffer]),
            );
            socket.set_nagle_enabled(false);
            let handle = sockets.add(socket);
            let port = 40000 + index as u16;
            if stagger.is_none() {
                sockets
                    .get_mut::<tcp::Socket>(handle)
                    .connect(
                        iface.context(),
                        (target_ip, 443),
                        IpListenEndpoint {
                            addr: Some(client_ip),
                            port,
                        },
                    )
                    .unwrap();
            }
            all.push(Flow {
                handle,
                port,
                client_sent: 0,
                client_received: 0,
                client_closed: false,
                stream: None,
                relay_received: 0,
                relay_sent: 0,
                relay_eof: false,
                relay_shutdown: false,
                pending: None,
                starved: Duration::ZERO,
                stretch: Duration::ZERO,
                progress: 0,
                upload_done: None,
            });
        }

        let mut to_engine = Impairment::new(seed ^ 1, loss);
        let mut to_client = Impairment::new(seed ^ 2, loss);
        let start = Instant::now();
        let mut now = start;
        let mut cx = context();
        // The longest stretch the link sat idle mid-transfer: on a clean link
        // something always moves, so a long one is a stall.
        let mut idle_stretch = Duration::ZERO;
        let mut longest_idle = Duration::ZERO;
        // When every flow had opened and they all started sending.
        let mut sending_since: Option<Instant> = None;
        // The shared link's unspent capacity, and the step it accrues over.
        let mut shared_credit = 0usize;
        let mut last_step = Duration::ZERO;
        // What the link offered and what the flows took while one upstream
        // was stalled: the cost the stalled one put on the rest.
        let mut offered_in_stall = 0usize;
        let mut used_in_stall = 0usize;
        // The capture device between the clients and the engine.
        let mut device: VecDeque<Vec<u8>> = VecDeque::new();
        let mut device_bytes = 0usize;
        let mut device_dropped = 0usize;

        let mut opened = if stagger.is_some() { 0 } else { flows };
        for round in 0..600_000 {
            let smol_now = SmolInstant::from_micros(now.duration_since(start).as_micros() as i64);
            if let Some(every) = stagger {
                if opened < flows && round % every == 0 {
                    let flow = &all[opened];
                    sockets
                        .get_mut::<tcp::Socket>(flow.handle)
                        .connect(
                            iface.context(),
                            (target_ip, 443),
                            IpListenEndpoint {
                                addr: Some(client_ip),
                                port: flow.port,
                            },
                        )
                        .unwrap();
                    opened += 1;
                }
            }
            // Every client sends at once, once all of them are established.
            let may_send = opened == flows && all.iter().all(|flow| flow.stream.is_some());
            iface.poll(smol_now, &mut link, &mut sockets);
            for (index, flow) in all.iter_mut().enumerate() {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                while may_send && flow.client_sent < upload && socket.can_send() {
                    let sent = socket
                        .send(|buffer| {
                            let n = buffer.len().min(upload - flow.client_sent);
                            for (i, byte) in buffer[..n].iter_mut().enumerate() {
                                *byte = pattern(index, flow.client_sent + i);
                            }
                            (n, n)
                        })
                        .unwrap();
                    flow.client_sent += sent;
                    if sent == 0 {
                        break;
                    }
                }
                while socket.can_recv() {
                    let received = socket
                        .recv(|buffer| {
                            for (i, byte) in buffer.iter().enumerate() {
                                assert_eq!(
                                    *byte,
                                    pattern(index, flow.client_received + i) ^ 0xa5,
                                    "flow {index} download byte {} (seed {seed})",
                                    flow.client_received + i
                                );
                            }
                            (buffer.len(), buffer.len())
                        })
                        .unwrap();
                    flow.client_received += received;
                }
                if flow.client_sent == upload && !flow.client_closed {
                    socket.close();
                    flow.client_closed = true;
                }
            }
            iface.poll(smol_now, &mut link, &mut sockets);

            let mut wire = Vec::new();
            for packet in link.tx.drain(..) {
                to_engine.pass(packet, &mut wire);
            }
            to_engine.release(&mut wire);
            for packet in wire {
                match device_queue {
                    Some(limit) if device_bytes + packet.len() > limit => {
                        device_dropped += 1;
                    }
                    _ => {
                        device_bytes += packet.len();
                        device.push_back(packet);
                    }
                }
            }
            let mut taken = 0usize;
            while let Some(packet) = device.pop_front() {
                device_bytes -= packet.len();
                taken += packet.len();
                engine.on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now);
                if device_read.is_some_and(|room| taken >= room) {
                    break;
                }
            }

            while let Ok(stream) = accept.try_recv() {
                let port = stream.client_addr().port();
                let flow = all
                    .iter_mut()
                    .find(|flow| flow.port == port)
                    .expect("a known flow");
                assert!(flow.stream.is_none(), "one stream per flow");
                flow.stream = Some(stream);
            }
            // A shared link accrues capacity as the clock moves, and the
            // flows spend it from a rotating start, so the harness divides
            // it evenly and the unfairness left is the engine's. It carries
            // a few milliseconds over, as a socket buffer does.
            // Nothing drains the first flow while its upstream is stalled.
            let in_stall = stall_first.is_some_and(|hold| {
                sending_since.is_some_and(|since| now.duration_since(since) < hold)
            });
            // The link's capacity only counts against the engine while a
            // flow that is not stalled still has bytes to move.
            let demanding = in_stall && all.iter().skip(1).any(|flow| flow.relay_received < upload);
            if let Some(rate) = relay_drain_shared {
                let accrued = rate * last_step.as_micros() as usize / 1_000;
                shared_credit = (shared_credit + accrued).min(rate * 4);
                if demanding {
                    // Offered, whether or not a flow comes for it.
                    offered_in_stall += accrued;
                }
            }
            let first = if relay_drain_shared.is_some() {
                round
            } else {
                0
            };
            let mut shared = relay_drain_shared.map(|_| shared_credit);
            for turn in 0..all.len() {
                let index = (turn + first) % all.len();
                let flow = &mut all[index];
                let Some(relay) = flow.stream.as_mut() else {
                    continue;
                };
                let stalled = index == 0 && in_stall;
                let mut drained = 0usize;
                while !flow.relay_eof && !stalled {
                    let room = match relay_drain {
                        Some(room) if drained >= room => break,
                        Some(room) => (room - drained).min(70_000),
                        None => rng.random_range(1..=70_000),
                    };
                    let room = match shared {
                        Some(0) => break,
                        Some(left) => room.min(left),
                        None => room,
                    };
                    match relay.poll_read_chunk(&mut cx, room) {
                        Poll::Ready(Ok(Some(chunk))) => {
                            for (i, byte) in chunk.iter().enumerate() {
                                assert_eq!(
                                    *byte,
                                    pattern(index, flow.relay_received + i),
                                    "flow {index} upload byte {} (seed {seed})",
                                    flow.relay_received + i
                                );
                            }
                            flow.relay_received += chunk.len();
                            drained += chunk.len();
                            if let Some(left) = shared.as_mut() {
                                *left -= chunk.len();
                                shared_credit -= chunk.len();
                                if demanding {
                                    used_in_stall += chunk.len();
                                }
                            }
                        }
                        Poll::Ready(Ok(None)) => flow.relay_eof = true,
                        Poll::Ready(Err(error)) => {
                            panic!("flow {index} relay read failed: {error} (seed {seed})")
                        }
                        Poll::Pending => break,
                    }
                }
                loop {
                    if flow.pending.is_none() && flow.relay_sent < download {
                        let n = rng.random_range(1..=48_000).min(download - flow.relay_sent);
                        let bytes: Vec<u8> = (flow.relay_sent..flow.relay_sent + n)
                            .map(|i| pattern(index, i) ^ 0xa5)
                            .collect();
                        flow.relay_sent += n;
                        flow.pending = Some(Bytes::from(bytes));
                    }
                    if flow.pending.is_none() {
                        break;
                    }
                    match relay.poll_write_chunk(&mut cx, &mut flow.pending) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => {
                            panic!("flow {index} relay write failed: {error} (seed {seed})")
                        }
                        Poll::Pending => break,
                    }
                }
                if flow.relay_sent == download
                    && flow.pending.is_none()
                    && flow.relay_eof
                    && !flow.relay_shutdown
                {
                    relay.poll_shutdown_for_tests();
                    flow.relay_shutdown = true;
                }
            }

            engine.attend(now);
            engine.on_timers(now);
            let mut segments = Vec::new();
            engine.emit(now, usize::MAX, &mut |segment| {
                segments.push(segment.to_vec())
            });
            let mut wire = Vec::new();
            for packet in segments {
                assert!(packet.len() <= mtu, "segments fit the MTU");
                to_client.pass(packet, &mut wire);
            }
            to_client.release(&mut wire);
            link.rx.extend(wire);

            if all
                .iter()
                .all(|flow| flow.done(upload, download, &mut sockets))
                && engine.flow_count() == 0
            {
                assert_eq!(
                    device_dropped, 0,
                    "the windows together overflowed the capture device {device_dropped} times \
                     (seed {seed})"
                );
                assert_eq!(
                    engine.budget.promised, 0,
                    "every flow ended, so no window stays promised (seed {seed})"
                );
                // A flow whose upstream the plan stalled is left out: what
                // it waited is the plan's, not the engine's.
                let measured = usize::from(stall_first.is_some());
                if let Some(limit) = starve_limit {
                    let (worst, at) = all
                        .iter()
                        .enumerate()
                        .skip(measured)
                        .map(|(index, flow)| (flow.starved, index))
                        .max()
                        .expect("a flow");
                    assert!(
                        worst <= limit,
                        "flow {at} went {worst:?} without one of its bytes moving, over {limit:?} \
                         (seed {seed})"
                    );
                }
                if let Some(spread) = upload_spread {
                    let mut took: Vec<Duration> = all
                        .iter()
                        .skip(measured)
                        .map(|flow| flow.upload_done.expect("every upload finished"))
                        .collect();
                    took.sort_unstable();
                    let median = took[took.len() / 2];
                    let worst = *took.last().expect("a flow");
                    assert!(
                        worst.as_secs_f64() <= median.as_secs_f64() * spread,
                        "the slowest upload took {worst:?} against a median of {median:?}, more \
                         than {spread} times as long (seed {seed})"
                    );
                }
                if let Some(least) = link_share {
                    let used = used_in_stall as f64 / offered_in_stall.max(1) as f64;
                    assert!(
                        used >= least,
                        "the flows took {used:.3} of the link while one upstream was stalled, \
                         under {least} (seed {seed})"
                    );
                }
                if loss == 0.0 {
                    assert!(
                        longest_idle < Duration::from_millis(100),
                        "a clean link stalled for {longest_idle:?} (seed {seed})"
                    );
                }
                return;
            }
            let idle = link.rx.is_empty()
                && link.tx.is_empty()
                && device.is_empty()
                && to_client.held.is_empty()
                && to_engine.held.is_empty();
            // Waiting on a saturated shared link is not a stall: the bytes
            // are the harness's to hand over, and the clock only has to
            // reach the link's next capacity.
            let link_bound =
                relay_drain_shared.is_some() && all.iter().any(|flow| flow.relay_received < upload);
            let step = if idle && link_bound {
                Duration::from_micros(500)
            } else if idle {
                engine
                    .next_deadline()
                    .map_or(Duration::from_millis(10), |due| {
                        due.saturating_duration_since(now)
                    })
                    .clamp(Duration::from_micros(50), Duration::from_millis(250))
            } else {
                Duration::from_micros(50)
            };
            last_step = step;
            if idle && !link_bound && may_send && !all.iter().all(|flow| flow.client_closed) {
                idle_stretch += step;
                longest_idle = longest_idle.max(idle_stretch);
            } else {
                idle_stretch = Duration::ZERO;
            }
            if may_send {
                let since = *sending_since.get_or_insert(now);
                for flow in all.iter_mut() {
                    if flow.relay_received == upload {
                        flow.stretch = Duration::ZERO;
                        flow.upload_done.get_or_insert(now.duration_since(since));
                        continue;
                    }
                    if flow.relay_received == flow.progress {
                        flow.stretch += step;
                        flow.starved = flow.starved.max(flow.stretch);
                    } else {
                        flow.progress = flow.relay_received;
                        flow.stretch = Duration::ZERO;
                    }
                }
            }
            now += step;
        }
        let states: Vec<String> = all
            .iter()
            .map(|flow| {
                format!(
                    "port {} sent {}/{upload} relay got {} relay sent {}/{download} got {} state {:?}",
                    flow.port,
                    flow.client_sent,
                    flow.relay_received,
                    flow.relay_sent,
                    flow.client_received,
                    sockets.get_mut::<tcp::Socket>(flow.handle).state()
                )
            })
            .collect();
        panic!(
            "transfer did not finish (seed {seed}, flows left {}): {states:#?}",
            engine.flow_count()
        );
    }

    fn plan(
        seed: u64,
        ipv6: bool,
        mtu: usize,
        flows: usize,
        upload: usize,
        download: usize,
        loss: f64,
    ) -> Plan {
        Plan {
            seed,
            ipv6,
            mtu,
            flows,
            upload,
            download,
            loss,
            client_buffer: 256 * 1024,
            device_queue: None,
            device_read: None,
            relay_drain: None,
            relay_drain_shared: None,
            upload_spread: None,
            stall_first: None,
            link_share: None,
            stagger: None,
            starve_limit: None,
        }
    }

    /// The capture device holds a client's bytes until the engine reads them
    /// and drops what does not fit, and a client may have its whole window
    /// outstanding. The windows together therefore have to fit the device,
    /// however slowly the engine reads and the relay drains. The queue here
    /// is [`CAPTURE_WINDOWS`]'s budget, with room for the headers and the
    /// clients' acknowledgements the budget does not count.
    #[test]
    fn the_windows_together_fit_the_capture_device() {
        transfer(Plan {
            device_queue: Some(CAPTURE_WINDOWS.budget + 128 * 1024),
            device_read: Some(128 * 1024),
            relay_drain: Some(16 * 1024),
            starve_limit: Some(Duration::from_millis(200)),
            ..plan(7000, false, 65535, 64, 256 * 1024, 0, 0.0)
        });
    }

    /// The flows that open first advertise their window while few are
    /// receiving, and an advertised right edge never moves left (RFC 9293
    /// section 3.8.6). When the rest have opened and all of them send at
    /// once, those early promises are still outstanding, so the windows
    /// together have to fit the capture device even then.
    #[test]
    fn windows_promised_early_still_fit_the_capture_device() {
        for seed in 0..3 {
            for (flows, stagger) in [(64, 1), (64, 4), (128, 1), (256, 1)] {
                transfer(Plan {
                    device_queue: Some(CAPTURE_WINDOWS.budget + 128 * 1024),
                    device_read: Some(64 * 1024),
                    relay_drain: Some(16 * 1024),
                    stagger: Some(stagger),
                    starve_limit: Some(Duration::from_millis(200)),
                    ..plan(7100 + seed, false, 65535, flows, 64 * 1024, 0, 0.0)
                });
            }
        }
    }

    /// Forty-eight flows uploading at once over one saturated uplink: the
    /// relay drains them all from a single budget, as the link's capacity
    /// divides between the upstream sockets. The harness divides that budget
    /// evenly, so what is left is the engine's own metering -- the windows it
    /// grants out of one budget and the send buffers it sizes. No flow may
    /// then take much longer than the rest.
    #[test]
    fn a_shared_saturated_uplink_divides_between_the_flows() {
        for seed in 0..2 {
            transfer(Plan {
                device_queue: Some(CAPTURE_WINDOWS.budget + 128 * 1024),
                device_read: Some(128 * 1024),
                relay_drain_shared: Some(16 * 1024),
                upload_spread: Some(1.2),
                starve_limit: Some(Duration::from_millis(200)),
                ..plan(7200 + seed, false, 65535, 48, 256 * 1024, 0, 0.0)
            });
        }
    }

    /// One flow's upstream stops accepting bytes halfway through -- the shape
    /// a node that stalls a single connection has -- while the other
    /// forty-seven upload over the shared link. The engine holds that flow's
    /// queue full and its window shut for the whole stretch, so whatever
    /// budget it keeps must not cost the rest their share of the link.
    #[test]
    fn one_stalled_upstream_costs_the_other_flows_nothing() {
        // The same twelve mebibytes over the link each time, so the stall
        // always falls inside the transfer.
        for flows in [2, 8, 48] {
            transfer(Plan {
                device_queue: Some(CAPTURE_WINDOWS.budget + 128 * 1024),
                device_read: Some(128 * 1024),
                relay_drain_shared: Some(16 * 1024),
                stall_first: Some(Duration::from_millis(200)),
                link_share: Some(0.9),
                upload_spread: Some(1.2),
                starve_limit: Some(Duration::from_millis(200)),
                ..plan(7300, false, 65535, flows, 12 * 1024 * 1024 / flows, 0, 0.0)
            });
        }
    }

    #[test]
    fn small_client_windows_never_stall() {
        for seed in 0..6 {
            for (mtu, buffer) in [(1500, 16 * 1024), (1500, 40 * 1024), (65535, 100 * 1024)] {
                transfer(Plan {
                    client_buffer: buffer,
                    ..plan(seed + 6000, false, mtu, 8, 50_000, 2_000_000, 0.0)
                });
            }
        }
    }

    #[test]
    fn clean_links_move_every_byte() {
        for seed in 0..4 {
            transfer(plan(seed, false, 1500, 1, 300_000, 700_000, 0.0));
            transfer(plan(seed + 100, false, 65535, 1, 2_000_000, 3_000_000, 0.0));
            transfer(plan(seed + 200, true, 1500, 1, 300_000, 700_000, 0.0));
        }
    }

    #[test]
    fn impaired_links_move_every_byte() {
        for seed in 0..12 {
            transfer(plan(seed, false, 1500, 1, 200_000, 400_000, 0.03));
            transfer(plan(seed + 1000, false, 9000, 1, 400_000, 800_000, 0.05));
            transfer(plan(seed + 2000, true, 4064, 1, 200_000, 400_000, 0.05));
        }
    }

    #[test]
    fn concurrent_flows_share_one_link() {
        for seed in 0..3 {
            transfer(plan(seed + 3000, false, 9000, 24, 150_000, 300_000, 0.0));
            transfer(plan(seed + 4000, true, 1500, 12, 100_000, 200_000, 0.04));
        }
    }

    #[test]
    fn heavily_impaired_links_still_finish() {
        for seed in 0..4 {
            transfer(plan(seed + 5000, false, 1500, 2, 100_000, 200_000, 0.15));
        }
    }
}
