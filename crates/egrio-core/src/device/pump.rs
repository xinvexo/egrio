//! The packet-device pump split off `NativeCoreDevice`: the loop that moves
//! whole IP packets between one queue of a platform capture ([`PacketDevice`])
//! and the Core. A capture with several queues gets a pump per queue, each
//! on its own executor with the tasks it starts.
//!
//! Inbound packets are reassembled, attributed, then either handed to the TCP
//! engine (TCP) or executed (UDP relay, DNS capture, ICMP). The pump drives
//! the engine inline: relay events, timers and its segments. Outbound packets
//! — TCP segments, DNS answers, UDP replies — pass one MTU-enforcing output
//! queue. The loop never polls: when there is nothing to do it parks on device
//! readiness, TCP engine wakeups and timers, UDP/DNS wakeups, attribution
//! completion, reassembly expiry, or cancellation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::attribution::{AttributionGate, ClientOwner, FlowKey, FlowProtocol};
use crate::packet::tcp::{OutSegment, MAX_PIECES};
use crate::packet::{
    attribution_flow, reassembly::PacketReassembler, source_fragment::packetize_local_udp,
    split_udp_train, Answer, AnswerSink, PacketCoreAction, PacketDevice, PacketInterest,
    PacketQueue, PacketSend, ReceivedPacket,
};
use crate::udp::{PumpSend, PumpUdpSend, UdpTrain};

/// Packets read, executed or drained per turn before the other direction
/// gets a turn.
const PUMP_BATCH: usize = 64;
/// Datagrams one turn reads, when the platform hands them over glued
/// together: a read is one of [`PUMP_BATCH`] but carries as many datagrams
/// as it carries, and each one costs the pipeline the work of a packet.
/// Eight batches' worth leaves a turn of ordinary packets untouched and
/// still lets a turn of Linux GRO reads take several of them, while bounding
/// what the TCP engine and the output wait behind.
pub(super) const PUMP_DATAGRAM_BATCH: usize = 8 * PUMP_BATCH;
const _: () = assert!(
    PUMP_DATAGRAM_BATCH >= PUMP_BATCH,
    "a turn of ordinary packets must not stop on the datagram bound"
);
/// Busy turns in a row after which the pump yields although it handed no
/// task work. After a turn that did (client bytes or a wakeup for a relay, a
/// datagram for a UDP session, a DNS query bound for an upstream) it yields
/// at once, so those tasks, which share its executor's one thread, run before
/// it goes on. After the turns of a download, which only send the relays'
/// bytes and take acknowledgements, it goes straight on: a yielded task runs
/// again only after its worker has polled the I/O driver with a zero timeout,
/// one more system call per turn. Bounded busy turns amortize that cost
/// while keeping other tasks runnable.
const BUSY_TURNS_PER_YIELD: u32 = 8;
/// Output packets held for a backpressured device; the queue never exceeds
/// it. Every producer takes work only while its worst-case output still
/// fits: inbound reads (at most one direct reply each), TCP segments (one
/// packet each) and Core UDP (one datagram, up to
/// [`PacketOutput::datagram_slots`] fragments). While full, the pump stops
/// reading and draining, so the device's pace reaches every producer.
const OUTPUT_QUEUE: usize = 256;
/// How long an ending capture waits for the device to take the resets of
/// its TCP flows: a utun or TUN takes them at once, and a device that stays
/// full past this leaves the rest of its clients to their timeouts.
const RESET_FLUSH: std::time::Duration = std::time::Duration::from_millis(200);
/// Captured UDP flows the pump sends for itself. Past this many it forgets
/// the least recently used [`PUMP_UDP_FLOWS_FORGOTTEN`] of them, which the
/// next datagram of each relearns. Forgetting them all instead -- which is
/// what it used to do -- cost every other application on the machine its
/// fast path whenever one client minted flows fast enough to fill the map:
/// a BitTorrent peer sweep does it every few seconds, and each forgotten
/// flow's next datagram pays an owner lookup, a routing pass and a session
/// table walk again.
const PUMP_UDP_FLOWS: usize = 4096;
/// Queue places the TCP engine leaves for the replies a read may produce.
/// The pump admits a read only while the queue could hold that packet's
/// reply -- a DNS answer never generated beats one dropped, since either way
/// the client waits out its own timeout -- so with the engine free to fill
/// the queue, a download stopped the pump reading anything at all: the
/// client's ACKs, which are what let that download go on, and every other
/// flow's upload with them. Eight is a trickle rather than a batch, on
/// purpose: only a DNS query or an ICMP echo answers from the read path, a
/// turn is microseconds, and taking a whole batch's worth off the engine
/// cost 2-3% of an eight-flow download for room nothing asks for.
const OUTPUT_REPLY_RESERVE: usize = 8;
/// Flows one eviction forgets, so the pass behind it is paid once for a
/// batch of new flows instead of for each one (the same shape of batch as
/// the UDP session table's reclaim).
const PUMP_UDP_FLOWS_FORGOTTEN: usize = PUMP_UDP_FLOWS / 8;

/// One flow the pump sends for itself, with the mark of its last datagram.
struct LearnedUdpFlow {
    send: PumpUdpSend,
    used: u64,
}

/// Forgets the [`PUMP_UDP_FLOWS_FORGOTTEN`] least recently used flows. Marks
/// are unique, so this drops exactly that many, and it costs one pass over
/// the map per batch rather than per new flow.
fn forget_least_used<K: Eq + std::hash::Hash, V>(
    flows: &mut HashMap<K, V>,
    mark: impl Fn(&V) -> u64,
) {
    let mut marks: Vec<u64> = flows.values().map(&mark).collect();
    let Some(last) = marks.len().checked_sub(1) else {
        return;
    };
    let cut = PUMP_UDP_FLOWS_FORGOTTEN.saturating_sub(1).min(last);
    let (_, &mut oldest_kept, _) = marks.select_nth_unstable(cut);
    // The batch is counted as well as compared: marks the pump assigns are
    // unique, but nothing in the type says so, and under ties a comparison
    // alone would take the whole map -- which is the behaviour this replaced.
    let mut forgotten = 0;
    flows.retain(|_, flow| {
        if mark(flow) > oldest_kept || forgotten >= PUMP_UDP_FLOWS_FORGOTTEN {
            return true;
        }
        forgotten += 1;
        false
    });
}

/// The attribution key of the UDP flow from `source` to `destination`.
fn udp_flow(source: SocketAddr, destination: SocketAddr) -> FlowKey {
    FlowKey {
        protocol: FlowProtocol::Udp,
        source_ip: source.ip(),
        source_port: source.port(),
        destination_ip: destination.ip(),
        destination_port: destination.port(),
    }
}

/// The datagrams in a train of UDP payload `segment` bytes each, the last one
/// fewer; one when the packet is not a train the Core can read.
fn udp_train_datagrams(packet: &[u8], segment: usize) -> u64 {
    crate::packet::udp_endpoints(packet)
        .filter(|_| segment > 0)
        .map_or(1, |(_, _, payload)| {
            payload.len().div_ceil(segment).max(1) as u64
        })
}

impl NativeCoreDevice {
    /// Serves each queue of a capture on the executor paired with it until
    /// `cancel` fires or a queue's device fails, which stops the others. A
    /// queue's pump runs there with the tasks it starts: the relays of the
    /// TCP flows that arrive on it and the sessions of the UDP flows it
    /// opens. Returns the queues' reports added up.
    pub async fn run_packet_queues(
        &self,
        queues: Vec<(Box<dyn PacketDevice>, tokio::runtime::Handle)>,
        cancel: CancellationToken,
    ) -> NativeCoreDeviceRunReport {
        let count = queues.len();
        if count == 0 {
            let mut report = NativeCoreDeviceRunReport::default();
            report.record_fatal("the packet capture opened no queues".into());
            return report;
        }
        let stop = cancel.child_token();
        // Dropping this future stops the queues too.
        let _stop_queues = stop.clone().drop_guard();
        let runs = queues
            .into_iter()
            .enumerate()
            .map(|(index, (mut device, executor))| {
                let core = self.clone();
                let stop = stop.clone();
                executor.spawn(async move {
                    let queue = PacketQueue { index, count };
                    let report = core
                        .run_packet_queue(queue, device.as_mut(), stop.clone())
                        .await;
                    if report.fatal_error.is_some() {
                        stop.cancel();
                    }
                    report
                })
            })
            .collect::<Vec<_>>();
        let mut reports = Vec::with_capacity(count);
        let mut panic = None;
        for run in runs {
            match run.await {
                Ok(report) => reports.push(report),
                Err(error) => {
                    stop.cancel();
                    match error.try_into_panic() {
                        Ok(payload) => panic = panic.or(Some(payload)),
                        Err(error) => {
                            let mut report = NativeCoreDeviceRunReport::default();
                            report.record_fatal(format!("a capture queue's pump ended: {error}"));
                            reports.push(report);
                        }
                    }
                }
            }
        }
        if let Some(payload) = panic {
            std::panic::resume_unwind(payload);
        }
        NativeCoreDeviceRunReport::sum(reports)
    }

    /// Drives `device`, queue `queue` of the capture, until `cancel` fires or
    /// the device fails. The report survives every exit: a fatal device error
    /// lands in `report.fatal_error`, so counters accumulated before it stay
    /// readable. Captured flows are attributed by the Core's own scanner
    /// worker.
    pub async fn run_packet_queue(
        &self,
        queue: PacketQueue,
        device: &mut dyn PacketDevice,
        cancel: CancellationToken,
    ) -> NativeCoreDeviceRunReport {
        let mtu = self.capture_mtu();
        let mut report = NativeCoreDeviceRunReport::default();
        if let Err(error) = NativeCoreCaptureConfig::validate_mtu(mtu) {
            report.record_fatal(error);
            return report;
        }
        if queue.index >= queue.count {
            report.record_fatal(format!(
                "capture queue {} of {} does not exist",
                queue.index, queue.count
            ));
            return report;
        }
        self.start();
        if let Ok(executor) = tokio::runtime::Handle::try_current() {
            self.inner
                .sessions
                .pump_runtimes
                .register(queue, executor.id());
        }
        self.inner
            .sessions
            .udp_sessions
            .note_capture_queues(queue.count);
        // The capture serve owns the active health-probe scheduler; spawning
        // is idempotent per device and the loop exits on close.
        drop(self.spawn_health_probe_loop());
        if self.ensure_packet_tcp(queue).is_none() {
            report.record_fatal("native core device is closed".into());
            return report;
        }
        // Reassembly and the attribution gate belong to this run: stopping or
        // replacing the pump releases incomplete datagrams and held packets.
        let mut reassembly = PacketReassembler::default();
        let mut gate = AttributionGate::new(self.attribution());
        let (answers, mut answers_back) = AnswerSink::channel();
        let udp_replies = self
            .inner
            .sessions
            .udp_sessions
            .pump_notify_handle(queue.index);
        let mut output = PacketOutput::new(mtu, device.completes_tcp_checksums());
        // A device that takes UDP trains gets the datagrams a socket read
        // together as one frame.
        let udp_train_mtu = device.sends_udp_trains().then_some(mtu as usize);
        let mut incoming = Vec::new();
        // The flows of the datagrams in `incoming`, which a later train of
        // the same flow must not overtake.
        let mut incoming_udp = HashSet::new();
        let mut admitted = Vec::new();
        let mut tcp_batch = Vec::new();
        // The engine's next deadline. The sleep stays registered across turns
        // and is reset only when the deadline changes: a fresh timer per wait
        // that ends before the time driver's next wakeup makes Tokio wake the
        // driver's thread.
        let mut tcp_timer = pin!(tokio::time::sleep_until(TokioInstant::now()));
        let mut tcp_timer_at = None;
        let mut busy_turns = 0;
        let mut handoffs = 0;
        // Established flows whose association the pump can drive (a DIRECT
        // socket, a Hysteria2 session): the pump sends their datagrams on its
        // transport itself, without routing or the session actor.
        let udp_table = self.inner.sessions.udp_sessions.clone();
        let mut pump_flows: HashMap<(SocketAddr, SocketAddr), LearnedUdpFlow> = HashMap::new();
        // Counts every learn and every send on a learned flow, so an eviction
        // can tell which flows are still in use. One per datagram, so no two
        // flows ever hold the same mark.
        let mut pump_flow_mark = 0_u64;

        'serve: loop {
            if cancel.is_cancelled() {
                report.shutdown_requested = true;
                break;
            }
            // Registered before draining, so a reply landing in between
            // leaves this wakeup armed.
            let mut udp_ready = pin!(udp_replies.notified());
            udp_ready.as_mut().enable();
            let mut progressed = output.flush(device, &mut report);
            // Whether this turn handed tasks work they should do before the
            // next.
            let mut handed_off = false;

            // Packets read before a device failure are still handled; the
            // failure ends the run afterwards.
            let mut device_failure = None;
            // New flows wait for their owner only while a routing rule reads
            // the process; queries to the tunnel's own resolver then need no
            // owner at all.
            let policy = self.inner.snapshot.load_full();
            let routes_by_process = policy
                .rule_engine
                .routes_by_process_for(policy.traffic_policy_mode);
            gate.set_holding(routes_by_process);
            // An inbound packet emits at most one direct reply (ICMP echo);
            // UDP and TCP output flow through their own bounded producers.
            // Reads are what the device and that reply room are counted in,
            // and datagrams are what the pipeline's work is: a read the
            // platform coalesced carries as many as it carries (a Linux GRO
            // read of small ones carries dozens), each costing a whole
            // packet's route, session and send. Counting reads alone let a
            // turn do that work thousands of times over while the TCP
            // engine and the output waited behind it; the second bound is
            // loose enough that a turn of ordinary packets never reaches it
            // and a turn of trains still reads several.
            let mut datagrams_read = 0;
            for _ in 0..PUMP_BATCH.min(output.free()) {
                if datagrams_read >= PUMP_DATAGRAM_BATCH {
                    break;
                }
                let received = match device.try_recv() {
                    Ok(Some(received)) => received,
                    Ok(None) => break,
                    Err(error) => {
                        device_failure = Some(error);
                        break;
                    }
                };
                progressed = true;
                let ReceivedPacket { bytes, udp_segment } = received;
                datagrams_read +=
                    udp_segment.map_or(1, |segment| udp_train_datagrams(&bytes, segment) as usize);
                let Some(segment) = udp_segment else {
                    report.packets_received += 1;
                    if let Some((source, destination, _)) = crate::packet::udp_endpoints(&bytes) {
                        incoming_udp.insert((source, destination));
                    }
                    incoming.push(bytes);
                    continue;
                };
                let datagrams = udp_train_datagrams(&bytes, segment);
                report.packets_received += datagrams;
                // A learned flow's train goes out whole on its association,
                // in one send where the platform segments UDP: its route is
                // pinned, so it needs no owner, whether or not routing reads
                // the process. Datagrams of the flow that came before it and
                // still wait (for their owner, or in this batch) must not be
                // overtaken, so then its datagrams queue behind them.
                let endpoints = crate::packet::udp_endpoints(&bytes);
                if let Some((source, destination, payload)) = &endpoints {
                    let (source, destination) = (*source, *destination);
                    if let Some(flow) = pump_flows.get_mut(&(source, destination)).filter(|_| {
                        !incoming_udp.contains(&(source, destination))
                            && !gate.holds(&udp_flow(source, destination))
                    }) {
                        pump_flow_mark += 1;
                        flow.used = pump_flow_mark;
                        match flow
                            .send
                            .send_train(&udp_table, &bytes[payload.clone()], segment)
                        {
                            PumpSend::Sent | PumpSend::Dropped => {
                                if flow.send.is_direct() {
                                    report.packets_action_direct_udp += datagrams;
                                } else {
                                    report.packets_action_proxy_udp += datagrams;
                                }
                                continue;
                            }
                            PumpSend::Stale => {
                                pump_flows.remove(&(source, destination));
                            }
                        }
                    }
                }
                if let Some((source, destination, _)) = endpoints {
                    incoming_udp.insert((source, destination));
                }
                if let Err(error) =
                    split_udp_train(&bytes, segment, |datagram| incoming.push(datagram))
                {
                    report.record_failure(error);
                }
            }
            incoming_udp.clear();
            for bytes in incoming.drain(..) {
                match reassembly.push(bytes) {
                    Ok(Some(packet)) => {
                        let flow = attribution_flow(&packet).filter(|(flow, _)| {
                            if flow.protocol != FlowProtocol::Udp {
                                return true;
                            }
                            // The pump sends a learned flow's datagrams itself:
                            // its route is pinned and its owner recorded
                            // already. Only behind earlier datagrams still
                            // waiting for their owner does one wait too.
                            if pump_flows.contains_key(&(
                                SocketAddr::new(flow.source_ip, flow.source_port),
                                SocketAddr::new(flow.destination_ip, flow.destination_port),
                            )) && !gate.holds(flow)
                            {
                                return false;
                            }
                            routes_by_process
                                || !policy.capture.dns_hijack.captures_udp_destination(
                                    flow.destination_ip,
                                    Some(flow.destination_port),
                                )
                        });
                        gate.admit(packet, flow, &mut admitted);
                    }
                    Ok(None) => {}
                    Err(error) => report.record_failure(error),
                }
            }
            drop(policy);
            gate.release_ready(&mut admitted);
            for attributed in admitted.drain(..) {
                progressed = true;
                let packet = CapturedPacket {
                    bytes: attributed.bytes,
                    process: attributed.process,
                };
                if is_tcp_packet(&packet.bytes) {
                    report.packets_captured_tcp += 1;
                    let prefer = if queue.count > 1 {
                        self.carrier_queue(&packet)
                    } else {
                        None
                    };
                    tcp_batch.push((packet, prefer));
                    continue;
                }
                let udp = crate::packet::udp_endpoints(&packet.bytes);
                if let Some((source, destination, payload)) = &udp {
                    if let Some(flow) = pump_flows.get_mut(&(*source, *destination)) {
                        pump_flow_mark += 1;
                        flow.used = pump_flow_mark;
                        match flow.send.send(&udp_table, &packet.bytes[payload.clone()]) {
                            PumpSend::Sent | PumpSend::Dropped => {
                                if flow.send.is_direct() {
                                    report.packets_action_direct_udp += 1;
                                } else {
                                    report.packets_action_proxy_udp += 1;
                                }
                                continue;
                            }
                            PumpSend::Stale => {
                                pump_flows.remove(&(*source, *destination));
                            }
                        }
                    }
                }
                let inbound = self
                    .handle_inbound(queue.index, packet, &answers, &mut output, &mut report)
                    .await;
                handed_off |= inbound.handed_off;
                if let (true, Some((source, destination, _))) = (inbound.udp_session, udp) {
                    if let Some(send) = self.pump_udp_send(source, destination) {
                        if pump_flows.len() >= PUMP_UDP_FLOWS {
                            forget_least_used(&mut pump_flows, |flow| flow.used);
                        }
                        pump_flow_mark += 1;
                        pump_flows.insert(
                            (source, destination),
                            LearnedUdpFlow {
                                send,
                                used: pump_flow_mark,
                            },
                        );
                    }
                }
            }
            // One engine lookup and lock for the batch's TCP packets.
            if !tcp_batch.is_empty() {
                self.inject_captured_tcp_packets(queue, tcp_batch.drain(..));
            }
            if let Some(error) = device_failure {
                report.record_fatal(error);
                break 'serve;
            }

            let tcp = self.current_packet_tcp(queue);
            if let Some(tcp) = tcp.as_ref() {
                progressed |= self.drive_tcp(queue, tcp, &mut output, &mut report);
                let handed = tcp.wake.handoffs();
                handed_off |= handed != handoffs;
                handoffs = handed;
            }
            if output.has_datagram_room() {
                while output.has_datagram_room() {
                    let Ok(answer) = answers_back.try_recv() else {
                        break;
                    };
                    progressed = true;
                    output.push_answer(answer, &mut report);
                }
                // A pull takes only as many replies as would fit if each were
                // a maximal datagram, but most fill one packet: pull again
                // while the room for a maximal one remains.
                while output.has_datagram_room() {
                    match self
                        .drain_pending_udp_packets(
                            queue.index,
                            output.datagram_capacity(),
                            udp_train_mtu,
                        )
                        .await
                    {
                        Ok(replies) if !replies.is_empty() => {
                            progressed = true;
                            report.pending_drain_attempts += 1;
                            for reply in replies.packets {
                                output.push_local_udp(reply, &mut report);
                            }
                            for train in replies.trains {
                                output.push_udp_train(train, &mut report);
                            }
                        }
                        Ok(_) => break,
                        Err(error) => {
                            report.record_fatal(error);
                            break 'serve;
                        }
                    }
                }
            }

            if progressed {
                busy_turns += 1;
                if handed_off || busy_turns >= BUSY_TURNS_PER_YIELD {
                    busy_turns = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }
            busy_turns = 0;

            let room = output.free() > 0;
            let datagram_room = output.has_datagram_room();
            // A full queue stops reads: wait for writability, not readability.
            let interest = PacketInterest {
                read: room,
                write: !output.is_empty(),
            };
            let tcp_wake = tcp.as_ref().map(|tcp| Arc::clone(&tcp.wake));
            let tcp_deadline = tcp
                .as_ref()
                .and_then(|tcp| tcp.engine().next_deadline())
                .map(TokioInstant::from_std);
            drop(tcp);
            if let Some(deadline) = tcp_deadline {
                if tcp_timer_at != Some(deadline) {
                    tcp_timer.as_mut().reset(deadline);
                    tcp_timer_at = Some(deadline);
                }
            }
            let held_deadline = gate.next_deadline().map(TokioInstant::from_std);
            let reassembly_deadline = reassembly.next_expiry().map(TokioInstant::from_std);
            let attribution_completed = gate.completed();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    report.shutdown_requested = true;
                    break 'serve;
                }
                ready = device.ready(interest) => {
                    if let Err(error) = ready {
                        report.record_fatal(error);
                        break 'serve;
                    }
                }
                () = tcp_woken(tcp_wake.as_deref()), if room => {}
                () = &mut tcp_timer, if tcp_deadline.is_some() => {
                    // An elapsed sleep stays ready: rearm it next turn.
                    tcp_timer_at = None;
                }
                answer = answers_back.recv(), if datagram_room => {
                    if let Some(answer) = answer {
                        output.push_answer(answer, &mut report);
                    }
                }
                () = &mut udp_ready, if datagram_room => {}
                () = sleep_until_deadline(held_deadline), if held_deadline.is_some() => {}
                () = wait_attribution(attribution_completed), if held_deadline.is_some() => {}
                () = sleep_until_deadline(reassembly_deadline), if reassembly_deadline.is_some() => {
                    reassembly.expire();
                }
            }
        }

        // Final sweep so a download's last segments and pending replies still
        // reach the device before the pump returns; a capture that ends then
        // resets its flows.
        if let Some(tcp) = self.current_packet_tcp(queue) {
            self.drive_tcp(queue, &tcp, &mut output, &mut report);
            if report.shutdown_requested {
                self.reset_captured_tcp(queue, &tcp, device, &mut output, &mut report)
                    .await;
            }
        }
        output.flush(device, &mut report);
        report
    }

    /// Resets the queue's captured flows toward their clients and writes the
    /// resets while the device is still there, waiting for room up to
    /// [`RESET_FLUSH`]. A client then learns at once that its connection
    /// ended, as when a capture starts and the engine resets the segments of
    /// connections it never saw, and can reconnect over the network: a
    /// socket on the address of a tunnel that is gone stays established
    /// until its own retransmissions or timeouts fail it.
    async fn reset_captured_tcp(
        &self,
        queue: PacketQueue,
        tcp: &Arc<PacketTcp>,
        device: &mut dyn PacketDevice,
        output: &mut PacketOutput,
        report: &mut NativeCoreDeviceRunReport,
    ) {
        tcp.engine().reset_all();
        let deadline = TokioInstant::now() + RESET_FLUSH;
        loop {
            self.drive_tcp(queue, tcp, output, report);
            output.flush(device, report);
            // An engine a cutover replaced meanwhile writes nothing more.
            if output.is_empty()
                && (!tcp.engine().has_output() || !self.packet_tcp_is_current(queue, tcp))
            {
                return;
            }
            let writable = PacketInterest {
                read: false,
                write: true,
            };
            tokio::select! {
                ready = device.ready(writable) => {
                    if ready.is_err() {
                        return;
                    }
                }
                () = tokio::time::sleep_until(deadline) => return,
            }
        }
    }

    /// Runs the TCP engine's segments from other queues, relay events and due
    /// timers, then takes the segments that fit the output queue. Returns
    /// whether it took any.
    fn drive_tcp(
        &self,
        queue: PacketQueue,
        tcp: &Arc<PacketTcp>,
        output: &mut PacketOutput,
        report: &mut NativeCoreDeviceRunReport,
    ) -> bool {
        let now = std::time::Instant::now();
        let mut engine = tcp.engine();
        let (forwarded, dropped) = tcp
            .forwarded
            .lock()
            .expect("captured TCP forwarded segments")
            .take();
        // Segments another queue read for this engine that did not fit its
        // hold: dropped as the device drops, and the client resends them.
        report.packets_forwarded_dropped += dropped;
        for (packet, process) in forwarded {
            engine.on_packet(packet, process, None, now);
        }
        engine.attend(now);
        engine.on_timers(now);
        let room = output.segment_room();
        // An engine a cutover replaced must not write into the new policy's
        // flows.
        let emitted = room > 0
            && self.packet_tcp_is_current(queue, tcp)
            && engine.emit(now, room, &mut |segment| output.push_segment(segment)) > 0;
        // A forwarded segment whose flow moved on meanwhile.
        let foreign = engine.take_foreign();
        drop(engine);
        self.forward_tcp(foreign);
        emitted
    }

    /// UDP, DNS and ICMP; TCP goes to the engine in batches.
    async fn handle_inbound(
        &self,
        queue: usize,
        packet: CapturedPacket,
        answers: &AnswerSink,
        output: &mut PacketOutput,
        report: &mut NativeCoreDeviceRunReport,
    ) -> Inbound {
        match self.execute_packet(queue, &packet, answers).await {
            Ok(outcome) => {
                record_packet_action(&outcome.pipeline.action, report);
                let dns = outcome.pipeline.action == PacketCoreAction::DnsCapture;
                let udp_session = matches!(
                    outcome.pipeline.action,
                    PacketCoreAction::DirectUdp | PacketCoreAction::ProxyUdp
                );
                let handed_off = match outcome.pipeline.action {
                    PacketCoreAction::DirectUdp
                    | PacketCoreAction::ProxyUdp
                    | PacketCoreAction::IcmpEchoRelay => true,
                    PacketCoreAction::DnsCapture => outcome.emitted_packets.is_empty(),
                    _ => false,
                };
                for packet in outcome.emitted_packets {
                    if dns {
                        // A DNS answer is Core-originated UDP, packetized to
                        // the MTU like the answers that come back later.
                        output.push_local_udp(packet, report);
                    } else {
                        // Locally answered ICMP is already a whole MTU-sized
                        // packet.
                        output.push_packetized(packet, report);
                    }
                }
                Inbound {
                    handed_off,
                    udp_session,
                }
            }
            Err(error) => {
                report.record_failure(error);
                Inbound {
                    handed_off: false,
                    udp_session: false,
                }
            }
        }
    }

    /// The pump's own send for a captured flow, once its association is up
    /// and its transport is one the pump drives.
    fn pump_udp_send(&self, source: SocketAddr, destination: SocketAddr) -> Option<PumpUdpSend> {
        let runtime = self.pinned_runtime();
        self.inner
            .sessions
            .udp_sessions
            .pump_send(&runtime, source, destination)
    }

    /// For a new flow's SYN, the queue whose pump runs where the flow's
    /// outbound carrier does: when the route the flow will take is known
    /// before it opens (from its destination, a fake IP's name, and its owner
    /// if already found) and leads through a connection every flow of that
    /// outbound shares, so the flow, its relay and the carrier share a thread.
    fn carrier_queue(&self, packet: &CapturedPacket) -> Option<usize> {
        let (flow, true) = attribution_flow(&packet.bytes)? else {
            return None;
        };
        if flow.protocol != FlowProtocol::Tcp {
            return None;
        }
        let runtime = self.pinned_runtime();
        let target = ConnectTarget {
            host: runtime
                .fake_dns_domain_for_ip(flow.destination_ip)
                .unwrap_or_else(|| flow.destination_ip.to_string()),
            port: flow.destination_port,
        };
        let mut input = crate::runtime::tcp_route_match_input(&target, None);
        if let ClientOwner::Known(Some(process)) = &packet.process {
            input.process_name = process.name.clone();
            input.process_path = process.path.clone();
        }
        let route = runtime.route(&input);
        if crate::rule_engine::is_reject_outbound(&route.outbound) {
            return None;
        }
        let carrier = runtime
            .resolve_outbound(&route.outbound, &target)?
            .connector
            .carrier_runtime()?;
        self.inner.sessions.pump_runtimes.queue_of(carrier)
    }

    /// The queue's engine, if the capture it was made for is still the one
    /// running. The lock and currency check keep an engine replaced by a
    /// cutover from writing into the new policy's flows. The pump takes this
    /// lock for lookup, batch injection and the check inside `drive_tcp`;
    /// benchmark changes here with `e2e_packet_throughput`.
    fn current_packet_tcp(&self, queue: PacketQueue) -> Option<Arc<PacketTcp>> {
        self.inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines")
            .get(queue)
    }

    fn packet_tcp_is_current(&self, queue: PacketQueue, tcp: &Arc<PacketTcp>) -> bool {
        self.current_packet_tcp(queue)
            .is_some_and(|current| Arc::ptr_eq(&current, tcp))
    }
}

/// What handling one inbound packet did.
struct Inbound {
    /// It handed work to another task (a datagram for a UDP session, a DNS
    /// query bound for an upstream), which should run before the next turn.
    handed_off: bool,
    /// It was a datagram for a UDP session, DIRECT or through a proxy.
    udp_session: bool,
}

async fn tcp_woken(wake: Option<&crate::packet::tcp::EngineWake>) {
    match wake {
        Some(wake) => wake.notify.notified().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_deadline(deadline: Option<TokioInstant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn wait_attribution(completed: Option<impl std::future::Future<Output = ()>>) {
    match completed {
        Some(completed) => completed.await,
        None => std::future::pending().await,
    }
}

/// Packets bound for the device, in order, never more than [`OUTPUT_QUEUE`].
/// Everything entering is already within the link MTU: Core-originated UDP is
/// source-packetized here, and other packets (TCP segments, ICMP replies) must
/// already respect the MTU.
#[derive(Debug)]
struct PacketOutput {
    mtu: u32,
    /// The device's OS finishes TCP checksums; see
    /// [`PacketDevice::completes_tcp_checksums`].
    tcp_checksums_offloaded: bool,
    datagram_slots: usize,
    queue: VecDeque<OutPacket>,
    /// Places the queue's packets take, by [`Self::places`].
    charged: usize,
}

enum OutPacket {
    Whole(Vec<u8>),
    /// A TCP segment: its header and slices of the relay's buffers, written
    /// with one gathering send.
    Segment(OutSegment),
    /// Datagrams one socket read together, for a device that takes them as
    /// one frame.
    UdpTrain(UdpTrain),
}

impl std::fmt::Debug for OutPacket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Whole(packet) => formatter.debug_tuple("Whole").field(&packet.len()).finish(),
            Self::Segment(segment) => formatter.debug_tuple("Segment").field(segment).finish(),
            Self::UdpTrain(train) => formatter
                .debug_struct("UdpTrain")
                .field("bytes", &train.payload.len())
                .field("segment", &train.segment)
                .finish(),
        }
    }
}

impl PacketOutput {
    fn new(mtu: u32, tcp_checksums_offloaded: bool) -> Self {
        let datagram_slots = Self::datagram_slots(mtu);
        debug_assert!(datagram_slots <= OUTPUT_QUEUE);
        Self {
            mtu,
            tcp_checksums_offloaded,
            datagram_slots,
            queue: VecDeque::with_capacity(OUTPUT_QUEUE),
            charged: 0,
        }
    }

    fn datagram_slots(mtu: u32) -> usize {
        crate::packet::datagram_frames(mtu as usize)
    }

    fn free(&self) -> usize {
        OUTPUT_QUEUE - self.charged
    }

    /// Queues `packet` and charges it its places.
    fn push(&mut self, packet: OutPacket) {
        self.charged += self.places(&packet);
        self.queue.push_back(packet);
    }

    /// The places a queued packet takes: one MTU-sized frame each, which is
    /// what the queue's places are. A train is the exception -- the device
    /// writes it as one frame and its OS cuts it into datagrams -- so it is
    /// worth as many places as the datagrams it carries. Counting it as one
    /// left the queue bounded in places but not in bytes: 256 maximal trains
    /// are 16 MiB, against the 384 KiB a 1500-byte link's 256 places mean.
    fn places(&self, packet: &OutPacket) -> usize {
        match packet {
            OutPacket::UdpTrain(train) => train
                .payload
                .len()
                .div_ceil((self.mtu as usize).max(1))
                .max(1),
            _ => 1,
        }
    }

    fn has_datagram_room(&self) -> bool {
        self.free() >= self.datagram_slots
    }

    /// Room for the TCP engine's segments: the queue minus what one datagram
    /// may need and minus the replies one read batch may produce. The engine
    /// runs before the DNS answers and the UDP replies in a turn, and both
    /// are skipped -- their wakeups included, so the pump does not even come
    /// back for them -- while `has_datagram_room` is false. Handed the whole
    /// queue the engine filled it for as long as a download had segments
    /// ready, and an answered DNS query or a game's replies waited behind it
    /// the whole time.
    ///
    /// It also leaves [`OUTPUT_REPLY_RESERVE`] places, which is what keeps
    /// the pump reading while the engine has segments ready.
    fn segment_room(&self) -> usize {
        self.free()
            .saturating_sub(self.datagram_slots + OUTPUT_REPLY_RESERVE)
    }

    /// Datagrams that fit even if each fragments maximally. A drain returns
    /// what it reads, which can be more datagrams than this -- one read can
    /// be a train of many -- and still fits: a train carries at most
    /// [`Self::datagram_slots`] of them (see `read_pump_io`), and a batch
    /// stops at the first reply past the limit, so the worst batch is the
    /// limit's small replies plus one maximal reply, which is what
    /// [`Self::has_datagram_room`] keeps the room for.
    ///
    /// Asking in frames instead (`free()`, so one drain could fill the
    /// queue) is slower, not faster: the drain takes one reply per socket
    /// per pass, so a larger limit means more passes and more awaits per
    /// call. Use `e2e_udp_throughput` to compare limits under load.
    fn datagram_capacity(&self) -> usize {
        self.free() / self.datagram_slots
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn push_packetized(&mut self, packet: Vec<u8>, report: &mut NativeCoreDeviceRunReport) {
        if packet.len() > self.mtu as usize {
            report.record_failure(format!(
                "Core packet output has {} bytes, exceeds link MTU {}; TCP/non-UDP must be packetized by its transport",
                packet.len(),
                self.mtu
            ));
            return;
        }
        if self.free() == 0 {
            report.record_failure("Core packet output queue is full; dropped a packet".into());
            return;
        }
        self.push(OutPacket::Whole(packet));
    }

    /// The TCP engine sizes segments to the MTU and takes only the room the
    /// queue has.
    fn push_segment(&mut self, mut segment: OutSegment) {
        debug_assert!(segment.len() <= self.mtu as usize);
        debug_assert!(self.free() > 0);
        if !self.tcp_checksums_offloaded {
            segment.finish_checksum();
        }
        self.push(OutPacket::Segment(segment));
    }

    fn push_answer(&mut self, answer: Answer, report: &mut NativeCoreDeviceRunReport) {
        match answer {
            Answer::Dns(packet) => self.push_local_udp(packet, report),
            Answer::Echo(packet) => self.push_packetized(packet, report),
        }
    }

    fn push_local_udp(&mut self, packet: Vec<u8>, report: &mut NativeCoreDeviceRunReport) {
        match packetize_local_udp(packet, self.mtu) {
            // A datagram is admitted whole or not at all.
            Ok(packets) if packets.len() <= self.free() => packets
                .into_iter()
                .for_each(|packet| self.push(OutPacket::Whole(packet))),
            Ok(_) => report
                .record_failure("Core packet output queue is full; dropped a UDP datagram".into()),
            Err(error) => report.record_failure(error),
        }
    }

    /// A train is written as one frame but takes the places of the datagrams
    /// it carries, so the queue stays bounded in bytes as well.
    fn push_udp_train(&mut self, train: UdpTrain, report: &mut NativeCoreDeviceRunReport) {
        let packet = OutPacket::UdpTrain(train);
        if self.places(&packet) > self.free() {
            report.record_failure("Core packet output queue is full; dropped a UDP train".into());
            return;
        }
        self.push(packet);
    }

    /// Hands queued packets to the device until it reports `Full`. A send
    /// error is scoped to its packet; a dead device surfaces through reads.
    fn flush(
        &mut self,
        device: &mut dyn PacketDevice,
        report: &mut NativeCoreDeviceRunReport,
    ) -> bool {
        let mut progressed = false;
        while let Some(packet) = self.queue.front() {
            let sent = match packet {
                OutPacket::Whole(packet) => device.try_send(packet),
                OutPacket::Segment(segment) => {
                    let mut parts: [&[u8]; MAX_PIECES + 1] = [&[]; MAX_PIECES + 1];
                    let mut count = 0;
                    for part in segment.parts() {
                        parts[count] = part;
                        count += 1;
                    }
                    device.try_send_parts(&parts[..count])
                }
                OutPacket::UdpTrain(train) => {
                    device.try_send_udp_train(&train.header, &train.payload, train.segment)
                }
            };
            match sent {
                Ok(PacketSend::Sent) => report.packets_written += 1,
                Ok(PacketSend::Full) => break,
                Err(error) => report.record_failure(error),
            }
            if let Some(packet) = self.queue.pop_front() {
                self.charged -= self.places(&packet);
            }
            progressed = true;
        }
        progressed
    }
}

fn record_packet_action(action: &PacketCoreAction, report: &mut NativeCoreDeviceRunReport) {
    match action {
        PacketCoreAction::DnsCapture => report.packets_action_dns_capture += 1,
        PacketCoreAction::DirectUdp => report.packets_action_direct_udp += 1,
        PacketCoreAction::ProxyUdp => report.packets_action_proxy_udp += 1,
        PacketCoreAction::IcmpEchoReply => report.packets_action_icmp_echo_reply += 1,
        PacketCoreAction::IcmpEchoRelay => report.packets_action_icmp_echo_relay += 1,
        PacketCoreAction::IcmpDrop => report.packets_action_icmp_drop += 1,
        PacketCoreAction::MulticastDrop => report.packets_action_multicast_drop += 1,
        // TCP routes per flow at the engine's accept, never per packet here.
        PacketCoreAction::DirectTcp
        | PacketCoreAction::ProxyTcp
        | PacketCoreAction::Reject
        | PacketCoreAction::Unsupported => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ipv4_header_checksum, ipv4_tcp_checksum, PacketReady};

    /// A train is one frame to the device and as many datagrams to the link,
    /// so it takes the places of what it carries: the queue is bounded in
    /// bytes and not only in frames.
    #[test]
    fn a_udp_train_takes_the_places_of_its_datagrams() {
        let mut output = PacketOutput::new(1500, false);
        let mut report = NativeCoreDeviceRunReport::default();
        let free = output.free();
        let train = UdpTrain {
            header: vec![0; 28],
            payload: vec![0; 1500 * 8],
            segment: 1500,
        };

        output.push_udp_train(train, &mut report);

        assert_eq!(output.queue.len(), 1, "one frame for the device");
        assert_eq!(output.free(), free - 8, "eight places for the link");
        assert_eq!(report.packets_failed, 0);

        // A train that does not fit is dropped whole, not queued.
        let huge = UdpTrain {
            header: vec![0; 28],
            payload: vec![0; 1500 * OUTPUT_QUEUE],
            segment: 1500,
        };
        output.push_udp_train(huge, &mut report);
        assert_eq!(output.queue.len(), 1, "it did not fit");
        assert_eq!(
            report.packets_failed, 1,
            "the train that did not fit was dropped"
        );
    }

    /// A full map of learned flows loses its oldest batch, not all of it: one
    /// client minting flows must not cost the rest of the machine its fast
    /// path.
    #[test]
    fn a_full_map_of_learned_flows_forgets_its_least_used_batch() {
        let mut flows: HashMap<u32, u64> = (0..PUMP_UDP_FLOWS as u32)
            .map(|index| (index, u64::from(index) + 1))
            .collect();

        forget_least_used(&mut flows, |mark| *mark);

        assert_eq!(flows.len(), PUMP_UDP_FLOWS - PUMP_UDP_FLOWS_FORGOTTEN);
        assert!(
            flows
                .values()
                .all(|mark| *mark > PUMP_UDP_FLOWS_FORGOTTEN as u64),
            "the flows kept are the ones used most recently"
        );
    }

    /// The marks a pump assigns are unique, but nothing in the map's type says
    /// so; ties must not take the whole map with them.
    #[test]
    fn forgetting_flows_that_share_a_mark_keeps_the_rest() {
        let mut flows: HashMap<u32, u64> =
            (0..PUMP_UDP_FLOWS as u32).map(|index| (index, 7)).collect();

        forget_least_used(&mut flows, |mark| *mark);

        assert_eq!(
            flows.len(),
            PUMP_UDP_FLOWS - PUMP_UDP_FLOWS_FORGOTTEN,
            "one batch went, however old the rest looked"
        );
    }

    #[derive(Debug, Default)]
    struct RecordingDevice(Vec<Vec<u8>>);
    impl PacketDevice for RecordingDevice {
        fn name(&self) -> &str {
            "output-boundary-test"
        }
        fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
            Ok(None)
        }
        fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
            self.0.push(packet.to_vec());
            Ok(PacketSend::Sent)
        }
        fn ready(&mut self, _: PacketInterest) -> PacketReady<'_> {
            Box::pin(std::future::pending())
        }
    }

    fn tcp_packet(payload: usize) -> Vec<u8> {
        let source = "203.0.113.1".parse().unwrap();
        let destination = "10.23.0.2".parse().unwrap();
        let mut bytes = vec![0_u8; 40 + payload];
        bytes[0] = 0x45;
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&std::net::Ipv4Addr::octets(&source));
        bytes[16..20].copy_from_slice(&std::net::Ipv4Addr::octets(&destination));
        let checksum = ipv4_header_checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes[20..22].copy_from_slice(&443_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&54321_u16.to_be_bytes());
        bytes[32] = 5 << 4;
        bytes[33] = 0x18;
        let checksum = ipv4_tcp_checksum(source, destination, &bytes[20..]);
        bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    #[test]
    fn output_queue_admits_datagrams_whole_and_never_exceeds_its_capacity() {
        let mut report = NativeCoreDeviceRunReport::default();
        let mut output = PacketOutput::new(1280, false);
        assert_eq!(PacketOutput::datagram_slots(1280), 54);
        assert!(PacketOutput::datagram_slots(1280) <= OUTPUT_QUEUE);
        for _ in 0..OUTPUT_QUEUE + 3 {
            output.push_packetized(tcp_packet(0), &mut report);
        }
        assert_eq!(output.queue.len(), OUTPUT_QUEUE);
        assert_eq!(report.packets_failed, 3);
        assert!(!output.has_datagram_room());
        assert_eq!(output.datagram_capacity(), 0);
    }

    /// The device stays unwritable while the pump is fed far more ICMP echo
    /// requests than the output queue holds: reads stop at the queue's
    /// capacity instead of queueing a reply per request, and every request is
    /// answered once the device drains.
    #[tokio::test]
    async fn blocked_device_bounds_direct_replies_and_resumes_when_writable() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Mutex;

        #[derive(Debug, Default)]
        struct Shared {
            inbound: Mutex<VecDeque<Vec<u8>>>,
            writable: AtomicBool,
            received: AtomicUsize,
            written: AtomicUsize,
            changed: tokio::sync::Notify,
        }
        #[derive(Debug)]
        struct BlockedDevice(Arc<Shared>);
        impl PacketDevice for BlockedDevice {
            fn name(&self) -> &str {
                "blocked-output-test"
            }
            fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
                let packet = self.0.inbound.lock().unwrap().pop_front();
                if packet.is_some() {
                    self.0.received.fetch_add(1, Ordering::SeqCst);
                }
                Ok(packet.map(Into::into))
            }
            fn try_send(&mut self, _: &[u8]) -> Result<PacketSend, String> {
                if !self.0.writable.load(Ordering::SeqCst) {
                    return Ok(PacketSend::Full);
                }
                self.0.written.fetch_add(1, Ordering::SeqCst);
                Ok(PacketSend::Sent)
            }
            fn ready(&mut self, interest: PacketInterest) -> PacketReady<'_> {
                let shared = Arc::clone(&self.0);
                Box::pin(async move {
                    loop {
                        let changed = shared.changed.notified();
                        let readable = interest.read && !shared.inbound.lock().unwrap().is_empty();
                        let writable = interest.write && shared.writable.load(Ordering::SeqCst);
                        if readable || writable {
                            return Ok(());
                        }
                        changed.await;
                    }
                })
            }
        }

        fn echo_request(sequence: u16) -> Vec<u8> {
            let mut bytes = vec![0_u8; 28];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&28_u16.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 1;
            bytes[12..16].copy_from_slice(&[10, 255, 255, 1]);
            bytes[16..20].copy_from_slice(&[198, 18, 0, 9]);
            let checksum = ipv4_header_checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            bytes[20] = 8;
            bytes[24..26].copy_from_slice(&7_u16.to_be_bytes());
            bytes[26..28].copy_from_slice(&sequence.to_be_bytes());
            let checksum = ipv4_header_checksum(&bytes[20..]);
            bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
            bytes
        }

        const REQUESTS: usize = 4096;
        let mut profile = crate::RuntimeProfile::new("blocked-output");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        let core = NativeCoreDevice::compile(&profile);
        let shared = Arc::new(Shared::default());
        shared
            .inbound
            .lock()
            .unwrap()
            .extend((0..REQUESTS).map(|sequence| echo_request(sequence as u16)));
        let cancel = CancellationToken::new();
        let pump = tokio::spawn({
            let core = core.clone();
            let cancel = cancel.clone();
            let mut device = BlockedDevice(Arc::clone(&shared));
            async move {
                core.run_packet_queue(PacketQueue::ONLY, &mut device, cancel)
                    .await
            }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            while shared.received.load(Ordering::SeqCst) < OUTPUT_QUEUE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the pump reads until the output queue fills");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            shared.received.load(Ordering::SeqCst),
            OUTPUT_QUEUE,
            "a blocked device must stop the pump from reading more requests"
        );
        assert_eq!(shared.written.load(Ordering::SeqCst), 0);

        shared.writable.store(true, Ordering::SeqCst);
        shared.changed.notify_waiters();
        tokio::time::timeout(Duration::from_secs(10), async {
            while shared.written.load(Ordering::SeqCst) < REQUESTS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every request is answered once the device drains");
        cancel.cancel();
        let report = pump.await.unwrap();
        assert_eq!(report.packets_received, REQUESTS as u64);
        assert_eq!(report.packets_action_icmp_echo_reply, REQUESTS as u64);
        assert_eq!(report.packets_written, REQUESTS as u64);
        assert_eq!(report.packets_failed, 0, "{:?}", report.last_error);
        core.close();
    }

    /// A device that always has a packet keeps every turn busy without
    /// handing any task work: stray ACKs for no connection draw RSTs. The
    /// pump still yields, so the other tasks on its thread run.
    #[test]
    fn an_always_busy_pump_lets_the_other_tasks_on_its_thread_run() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct FloodDevice(Arc<AtomicUsize>);
        impl PacketDevice for FloodDevice {
            fn name(&self) -> &str {
                "flood-test"
            }
            fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
                Ok(Some(tcp_packet(0).into()))
            }
            fn try_send(&mut self, _: &[u8]) -> Result<PacketSend, String> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(PacketSend::Sent)
            }
            fn ready(&mut self, _: PacketInterest) -> PacketReady<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        // The runtime runs on its own thread so a pump that never yields
        // fails the test instead of hanging it.
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let core = NativeCoreDevice::compile(&crate::RuntimeProfile::new("busy-pump"));
                let resets = Arc::new(AtomicUsize::new(0));
                let cancel = CancellationToken::new();
                let pump = tokio::spawn({
                    let core = core.clone();
                    let cancel = cancel.clone();
                    let mut device = FloodDevice(Arc::clone(&resets));
                    async move {
                        core.run_packet_queue(PacketQueue::ONLY, &mut device, cancel)
                            .await
                    }
                });
                // This task shares the pump's thread: each of its turns waits
                // for the pump to yield.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                assert!(resets.load(Ordering::Relaxed) > 0, "the pump answered");
                cancel.cancel();
                let report = pump.await.expect("pump task");
                assert!(report.shutdown_requested);
                core.close();
            });
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("tasks beside a busy pump run");
    }

    #[test]
    fn oversized_tcp_never_reaches_the_device_and_does_not_stop_other_frames() {
        let mut device = RecordingDevice::default();
        let mut report = NativeCoreDeviceRunReport::default();
        let mut output = PacketOutput::new(1500, false);
        output.push_packetized(tcp_packet(1461), &mut report);
        output.push_packetized(tcp_packet(0), &mut report);
        output.flush(&mut device, &mut report);
        assert_eq!(device.0.len(), 1);
        assert_eq!(device.0[0].len(), 40);
        assert_eq!(report.packets_written, 1);
        assert_eq!(report.packets_failed, 1);
        assert!(report.last_error.unwrap().contains("exceeds link MTU 1500"));
        assert_eq!(report.fatal_error, None);
    }
    /// The engine runs before the DNS answers and the UDP replies in a turn,
    /// and both are skipped while the queue has no datagram room, so the
    /// engine must not be handed the whole queue: a download with segments
    /// ready for every slot would otherwise keep an answered query waiting
    /// for as long as it ran.
    #[test]
    fn the_engine_leaves_the_queue_room_for_a_datagram() {
        for mtu in [1500, 65535] {
            let mut output = PacketOutput::new(mtu, false);
            let room = output.segment_room();
            assert!(room > 0, "mtu {mtu}: the engine has room of its own");
            assert!(
                room < OUTPUT_QUEUE,
                "mtu {mtu}: the engine is not handed the whole queue"
            );
            let mut report = NativeCoreDeviceRunReport::default();
            for _ in 0..room {
                output.push_packetized(vec![0; 40], &mut report);
            }
            assert_eq!(output.segment_room(), 0, "mtu {mtu}: the engine is full");
            assert!(
                output.has_datagram_room(),
                "mtu {mtu}: a datagram still fits behind it"
            );
            assert!(
                output.free() >= OUTPUT_REPLY_RESERVE,
                "mtu {mtu}: a read's reply still fits, so the pump keeps reading"
            );
        }
    }
}
