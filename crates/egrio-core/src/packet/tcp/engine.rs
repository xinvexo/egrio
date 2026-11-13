//! The engine: every captured TCP connection of one Core generation, driven
//! by the packet pump. It finds a segment's connection by its four-tuple,
//! keeps the timers in a heap, takes the relays' wakeups from a list, and
//! sends for the connections with something to send in turn. A connection in
//! TIME-WAIT gives way to a record of its own.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

#[cfg(test)]
use super::budget::Windows;
use super::budget::{Budget, CAPTURE_WINDOWS, TUNNEL_WINDOWS};
use super::connection::{Connection, State};
use super::segment::{self, Outgoing, Received, SackBlocks, ACK, RST, SYN};
use super::seq::Seq;
use super::stream::{CapturedTcpStream, EngineWake, FlowShared};
use super::time_wait::{TimeWait, Verdict};
use super::{OutSegment, Payload};
use crate::attribution::ClientOwner;

/// Live captured flows across the device; a SYN beyond it draws an RST.
/// TIME-WAIT records have their own bound and do not prevent new live flows.
pub(crate) const MAX_FLOWS: usize = 1024;
/// TIME-WAIT records an engine keeps. Past this many the oldest ends early: a client repeats its FIN within a few of its
/// retransmission timeouts, so the oldest record is the least likely to be
/// needed, and a FIN that finds none draws an RST, which ends the client's
/// LAST-ACK all the same.
///
/// It is per engine where [`MAX_FLOWS`] is per device, and stays that way.
/// Records expire after a bounded lifetime, so ordinary occupancy follows
/// the close rate. Keeping the cap per engine avoids a shared counter on
/// every close and lets each queue absorb a local burst.
const MAX_TIME_WAITS: usize = 16 * 1024;
/// Segments a connection sends per turn before the next one's turn.
const SEGMENTS_PER_TURN: usize = 16;
/// The local ports of the flows the engine opens (RFC 6335 section 6).
const FIRST_EPHEMERAL: u16 = 49152;
const EPHEMERAL_PORTS: u16 = 16384;

/// Which capture queue's engine holds each captured flow, for a capture with
/// several queues, and how many each holds. A new flow goes to the queue
/// holding the fewest among those whose engines are up: its engine writes the
/// flow's first reply on that queue, and the kernel keeps a flow on the queue
/// that last wrote a packet with its hash (drivers/net/tun.c,
/// `tun_flow_update`). A flow whose hash
/// collides with another's can still be moved to that one's queue, and a
/// flow idle past the kernel's record arrives on the queue its hash picks;
/// segments that land on a queue that does not hold their flow go to the
/// engine that does instead of drawing a reset.
#[derive(Debug)]
pub(crate) struct FlowHolders(Mutex<Holders>);

#[derive(Debug)]
struct Holders {
    flows: HashMap<(SocketAddr, SocketAddr), usize>,
    /// Flows each queue holds; `None` until the queue's engine is up, since a
    /// flow sent to a queue without one would be lost.
    held: Vec<Option<usize>>,
}

impl FlowHolders {
    pub(crate) fn new(queues: usize) -> Self {
        Self(Mutex::new(Holders {
            flows: HashMap::new(),
            held: vec![None; queues],
        }))
    }

    /// Lets queue `queue`, whose engine is now up, take new flows.
    pub(crate) fn open(&self, queue: usize) {
        if let Some(held @ None) = self.holders().held.get_mut(queue) {
            *held = Some(0);
        }
    }

    fn holders(&self) -> std::sync::MutexGuard<'_, Holders> {
        self.0.lock().expect("captured TCP flow holders")
    }

    /// The queue that takes a new flow whose SYN arrived on `arrival`: the
    /// one holding it already, else `prefer` if its engine is up, else the
    /// one holding the fewest flows, `arrival` among equals, which then holds
    /// it.
    fn place(&self, key: (SocketAddr, SocketAddr), arrival: usize, prefer: Option<usize>) -> usize {
        let mut holders = self.holders();
        if let Some(&holder) = holders.flows.get(&key) {
            return holder;
        }
        let held = |queue: usize| holders.held.get(queue).copied().flatten();
        let fewest = holders.held.iter().flatten().min().copied();
        let queue = match prefer.filter(|&queue| held(queue).is_some()) {
            Some(queue) => queue,
            None if held(arrival) == fewest => arrival,
            None => holders
                .held
                .iter()
                .position(|&held| held.is_some() && held == fewest)
                .unwrap_or(arrival),
        };
        holders.flows.insert(key, queue);
        if let Some(Some(held)) = holders.held.get_mut(queue) {
            *held += 1;
        }
        queue
    }

    fn holder(&self, key: &(SocketAddr, SocketAddr)) -> Option<usize> {
        self.holders().flows.get(key).copied()
    }

    fn release(&self, key: &(SocketAddr, SocketAddr), queue: usize) {
        let mut holders = self.holders();
        if holders.flows.get(key) == Some(&queue) {
            holders.flows.remove(key);
            if let Some(Some(held)) = holders.held.get_mut(queue) {
                *held = held.saturating_sub(1);
            }
        }
    }
}

/// An engine's capture queue among several, and the record they share.
#[derive(Debug)]
pub(crate) struct QueueShare {
    pub(crate) queue: usize,
    pub(crate) holders: Arc<FlowHolders>,
}

/// A segment of a flow another queue's engine holds, for that engine.
#[derive(Debug)]
pub(crate) struct ForeignSegment {
    pub(crate) queue: usize,
    pub(crate) packet: Bytes,
    pub(crate) process: ClientOwner,
}

pub(crate) struct TcpEngine {
    mtu: usize,
    /// What the flows hold together of the capture device and the engine's
    /// memory.
    pub(super) budget: Budget,
    flows: HashMap<(SocketAddr, SocketAddr), usize>,
    /// A flow's state by slot, and the slots no flow holds. An engine keeps
    /// the room of its own busiest moment and reuses empty slots. Live flows
    /// are counted across engines; retained room follows each engine's peak.
    slots: Vec<Option<Connection>>,
    free: Vec<usize>,
    wake: Arc<EngineWake>,
    /// Where accepted flows go; `None` for an engine that only opens flows,
    /// which refuses every SYN.
    accept: Option<mpsc::UnboundedSender<CapturedTcpStream>>,
    /// Live flows across the device, shared with other engines it creates.
    active: Arc<AtomicUsize>,
    /// Connections with something to send, in turn order.
    ready: VecDeque<usize>,
    timers: BinaryHeap<Reverse<(Instant, usize)>>,
    /// Resets for segments no connection takes.
    control: VecDeque<OutSegment>,
    attention: Vec<usize>,
    time_waits: HashMap<(SocketAddr, SocketAddr), TimeWait>,
    /// TIME-WAIT tuples with the end of their wait, in the order the waits
    /// began or restarted; an entry whose wait restarted or ended since is
    /// stale.
    time_wait_order: VecDeque<((SocketAddr, SocketAddr), Instant)>,
    max_time_waits: usize,
    /// Set when the capture has several queues.
    share: Option<QueueShare>,
    /// Segments for flows other queues' engines hold, until the driver
    /// takes them.
    foreign: Vec<ForeignSegment>,
}

impl TcpEngine {
    /// An engine for the flows this host opens through a tunnel, with
    /// segments of at most `mtu` bytes; it accepts none.
    pub(crate) fn opening(mtu: u32) -> Self {
        let (accept, _) = mpsc::unbounded_channel();
        let mut engine = Self::new(mtu, accept, Arc::default(), None);
        engine.accept = None;
        engine.budget = Budget::new(TUNNEL_WINDOWS);
        engine
    }

    /// An accepting engine with `windows`: a test's peer that receives like
    /// a server across a network rather than a capture's client.
    #[cfg(test)]
    pub(super) fn with_windows(mut self, windows: Windows) -> Self {
        self.budget = Budget::new(windows);
        self
    }

    pub(crate) fn new(
        mtu: u32,
        accept: mpsc::UnboundedSender<CapturedTcpStream>,
        active: Arc<AtomicUsize>,
        share: Option<QueueShare>,
    ) -> Self {
        Self {
            mtu: mtu as usize,
            budget: Budget::new(CAPTURE_WINDOWS),
            flows: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            wake: Arc::new(EngineWake::default()),
            accept: Some(accept),
            active,
            ready: VecDeque::new(),
            timers: BinaryHeap::new(),
            control: VecDeque::new(),
            attention: Vec::new(),
            time_waits: HashMap::new(),
            time_wait_order: VecDeque::new(),
            max_time_waits: MAX_TIME_WAITS,
            share,
            foreign: Vec::new(),
        }
    }

    /// The segments that arrived for flows other queues' engines hold.
    pub(crate) fn take_foreign(&mut self) -> Vec<ForeignSegment> {
        std::mem::take(&mut self.foreign)
    }

    /// The other queue holding the flow, if one does.
    fn held_elsewhere(&self, key: &(SocketAddr, SocketAddr)) -> Option<usize> {
        let share = self.share.as_ref()?;
        share
            .holders
            .holder(key)
            .filter(|&queue| queue != share.queue)
    }

    /// The wakeup relays raise when a flow needs the engine; the driver
    /// waits on its `notify` and then calls [`Self::attend`].
    pub(crate) fn wake(&self) -> Arc<EngineWake> {
        Arc::clone(&self.wake)
    }

    /// Connections the engine holds, TIME-WAIT records aside.
    pub(crate) fn flow_count(&self) -> usize {
        self.flows.len()
    }

    #[cfg(test)]
    pub(crate) fn time_wait_count(&self) -> usize {
        self.time_waits.len()
    }

    #[cfg(test)]
    pub(crate) fn set_max_time_waits(&mut self, max: usize) {
        self.max_time_waits = max;
    }

    /// Processes one captured TCP packet. `process` is the owner the
    /// attribution gate found, or is still finding, for a SYN; `prefer` is
    /// the queue a new flow should go to, if one is better for it than the
    /// one holding the fewest flows.
    pub(crate) fn on_packet(
        &mut self,
        packet: Bytes,
        process: ClientOwner,
        prefer: Option<usize>,
        now: Instant,
    ) {
        let Some(seg) = segment::parse(&packet) else {
            return;
        };
        let key = (seg.client, seg.target);
        if let Some(&slot) = self.flows.get(&key) {
            let cap = self
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .map_or(0, |conn| self.budget.window_cap(conn));
            let conn = self.slots[slot]
                .as_mut()
                .expect("a mapped flow has a connection");
            let fresh_syn = seg.has(SYN) && !seg.has(ACK);
            if fresh_syn && (conn.may_reopen_with(&seg) || conn.is_new_syn(&seg)) {
                // A new incarnation of the tuple: TIME-WAIT accepts a SYN
                // beyond the old sequence space (RFC 9293 section 3.10.7.4),
                // and a half-open connection yields to a different SYN.
                let reset = conn.state != State::TimeWait;
                conn.close(reset);
                self.remove(slot);
            } else {
                conn.on_segment(&seg, &packet, cap, now);
                if let Some(conn) = self.slots[slot].as_mut() {
                    self.budget.note_delivery(conn, now);
                }
                self.after_event(slot, now);
                return;
            }
        } else if let Some(queue) = self.held_elsewhere(&key) {
            self.foreign.push(ForeignSegment {
                queue,
                packet,
                process,
            });
            return;
        } else if let Some(wait) = self.time_waits.get_mut(&key) {
            let until = wait.until;
            match wait.on_segment(&seg, now) {
                Verdict::Ignore => return,
                Verdict::Acknowledge => {
                    if wait.until != until {
                        self.time_wait_order.push_back((key, wait.until));
                    }
                    self.control.push_back(wait.ack(&seg));
                    return;
                }
                Verdict::End => {
                    self.time_waits.remove(&key);
                    return;
                }
                Verdict::Reopen => {
                    self.time_waits.remove(&key);
                }
            }
        }
        if seg.has(RST) {
            return;
        }
        if seg.has(SYN) && !seg.has(ACK) && self.accept.is_some() {
            // A new flow goes to the queue holding the fewest; this one if
            // it is among them, or if it took the flow already (the SYN was
            // forwarded here).
            if let Some(share) = &self.share {
                let queue = share.holders.place(key, share.queue, prefer);
                if queue != share.queue {
                    self.foreign.push(ForeignSegment {
                        queue,
                        packet,
                        process,
                    });
                    return;
                }
            }
            if self.active.load(Ordering::Relaxed) >= MAX_FLOWS {
                if let Some(share) = &self.share {
                    share.holders.release(&key, share.queue);
                }
                self.reply_reset(&seg);
                return;
            }
            self.open(&seg, process, now);
            return;
        }
        self.reply_reset(&seg);
    }

    fn open(&mut self, syn: &Received, process: ClientOwner, now: Instant) {
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        let shared = Arc::new(FlowShared::new(slot, Arc::clone(&self.wake)));
        let iss = Seq(rand::random());
        let conn = Connection::accept(
            syn,
            Arc::clone(&shared),
            self.mtu,
            self.budget.windows,
            iss,
            now,
        );
        self.slots[slot] = Some(conn);
        self.flows.insert((syn.client, syn.target), slot);
        self.active.fetch_add(1, Ordering::Relaxed);
        self.budget.open(now);
        // A closed accept queue means the device is going away; the dropped
        // stream makes the connection close after its handshake.
        if let Some(accept) = &self.accept {
            let _ = accept.send(CapturedTcpStream::new(
                syn.client, syn.target, process, shared,
            ));
        }
        self.after_event(slot, now);
    }

    /// Opens a flow from `local_ip` to `peer` on a free local port; the
    /// stream is usable once [`CapturedTcpStream::established`] says so.
    pub(crate) fn connect(
        &mut self,
        local_ip: IpAddr,
        peer: SocketAddr,
        now: Instant,
    ) -> io::Result<CapturedTcpStream> {
        if self.active.load(Ordering::Relaxed) >= MAX_FLOWS {
            return Err(io::Error::other("too many TCP connections"));
        }
        let start = rand::random::<u16>() % EPHEMERAL_PORTS;
        let local = (0..EPHEMERAL_PORTS)
            .map(|step| {
                let port = FIRST_EPHEMERAL + (start + step) % EPHEMERAL_PORTS;
                SocketAddr::new(local_ip, port)
            })
            .find(|local| {
                let key = (peer, *local);
                !self.flows.contains_key(&key) && !self.time_waits.contains_key(&key)
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))?;
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        let shared = Arc::new(FlowShared::opening(slot, Arc::clone(&self.wake)));
        let iss = Seq(rand::random());
        let conn = Connection::connect(
            local,
            peer,
            Arc::clone(&shared),
            self.mtu,
            self.budget.windows,
            iss,
            now,
        );
        self.slots[slot] = Some(conn);
        self.flows.insert((peer, local), slot);
        self.active.fetch_add(1, Ordering::Relaxed);
        self.budget.open(now);
        self.after_event(slot, now);
        Ok(CapturedTcpStream::new(
            local,
            peer,
            ClientOwner::Known(None),
            shared,
        ))
    }

    /// An ICMP destination-unreachable for the flow from `local` to `peer`
    /// ends it if it is still opening.
    pub(crate) fn unreachable(&mut self, local: SocketAddr, peer: SocketAddr, now: Instant) {
        if let Some(&slot) = self.flows.get(&(peer, local)) {
            if let Some(conn) = self.slots[slot].as_mut() {
                conn.unreachable();
            }
            self.after_event(slot, now);
        }
    }

    /// Keeps a flow's TIME-WAIT as a record; past `max_time_waits` the
    /// oldest records end early.
    fn enter_time_wait(&mut self, key: (SocketAddr, SocketAddr), wait: TimeWait) {
        self.time_wait_order.push_back((key, wait.until));
        self.time_waits.insert(key, wait);
        while self.time_waits.len() > self.max_time_waits {
            let Some((oldest, until)) = self.time_wait_order.pop_front() else {
                break;
            };
            self.end_time_wait(oldest, until);
        }
    }

    /// Ends the TIME-WAIT records due by `now`.
    fn expire_time_waits(&mut self, now: Instant) {
        while let Some(&(key, until)) = self.time_wait_order.front() {
            if until > now {
                break;
            }
            self.time_wait_order.pop_front();
            self.end_time_wait(key, until);
        }
    }

    /// Removes the record for `key` if its wait still ends at `until`.
    fn end_time_wait(&mut self, key: (SocketAddr, SocketAddr), until: Instant) {
        if self
            .time_waits
            .get(&key)
            .is_some_and(|wait| wait.until == until)
        {
            self.time_waits.remove(&key);
        }
    }

    /// RFC 9293 section 3.10.7.1: a segment for no connection gets
    /// `<SEQ=SEG.ACK><CTL=RST>` if it acknowledges something, else
    /// `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`.
    fn reply_reset(&mut self, seg: &Received) {
        let (seq, ack, flags) = if seg.has(ACK) {
            (seg.ack, Seq::default(), RST)
        } else {
            (Seq(0), seg.seq.add(seg.seq_len()), RST | ACK)
        };
        let outgoing = Outgoing {
            local: seg.target,
            client: seg.client,
            seq,
            ack,
            flags,
            window: 0,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: SackBlocks::default(),
        };
        self.control.push_back(OutSegment {
            header: segment::write_header(&outgoing, 0),
            payload: Payload::default(),
        });
    }

    /// Takes the flows relays woke the engine for: written bytes, consumed
    /// bytes that reopen a window, shutdowns, drops and refusals.
    pub(crate) fn attend(&mut self, now: Instant) {
        let mut attention = std::mem::take(&mut self.attention);
        self.wake.take_pending(&mut attention);
        for slot in attention.drain(..) {
            let cap = self
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .map_or(0, |conn| self.budget.window_cap(conn));
            let Some(conn) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
                continue;
            };
            conn.service(cap);
            self.after_event(slot, now);
        }
        self.attention = attention;
    }

    /// Runs every timer due by `now`, each connection once.
    pub(crate) fn on_timers(&mut self, now: Instant) {
        let mut due = std::mem::take(&mut self.attention);
        while let Some(&Reverse((at, slot))) = self.timers.peek() {
            if at > now {
                break;
            }
            self.timers.pop();
            if let Some(conn) = self.slots.get_mut(slot).and_then(Option::as_mut) {
                if conn.timer_queued == Some(at) {
                    conn.timer_queued = None;
                }
                due.push(slot);
            }
        }
        due.sort_unstable();
        due.dedup();
        for slot in due.drain(..) {
            let Some(conn) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
                continue;
            };
            if conn.next_timer().is_some_and(|at| at <= now) {
                conn.on_timer(now);
            }
            self.after_event(slot, now);
        }
        self.attention = due;
        self.budget.sweep(self.slots.iter_mut().flatten(), now);
        self.expire_time_waits(now);
    }

    /// Drops the heap entries no connection is waiting on any more and
    /// re-times the ones a connection has put off, so the top is an instant
    /// something is due at.
    ///
    /// The heap has no removal, so an entry goes stale three ways: a
    /// connection that armed an earlier timer left the entry it had, a
    /// removed connection left its entry behind, and a connection whose
    /// next timer moved later kept the entry that was due sooner (arming
    /// only pushes an earlier one). Removing or re-timing them prevents the
    /// pump from waking when no connection needs work.
    ///
    /// Re-timing is where the care is: popping an entry has to leave the
    /// connection either queued for the deadline it now wants or queued for
    /// none, so clearing `timer_queued` without pushing the later deadline
    /// would lose that timer for good.
    fn settle_timers(&mut self) {
        while let Some(&Reverse((at, slot))) = self.timers.peek() {
            let Some(conn) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
                self.timers.pop();
                continue;
            };
            if conn.timer_queued != Some(at) {
                self.timers.pop();
                continue;
            }
            match conn.next_timer() {
                Some(due) if due > at => {
                    self.timers.pop();
                    conn.timer_queued = Some(due);
                    self.timers.push(Reverse((due, slot)));
                }
                Some(_) => break,
                None => {
                    self.timers.pop();
                    conn.timer_queued = None;
                }
            }
        }
    }

    /// When the engine next needs [`Self::on_timers`].
    pub(crate) fn next_deadline(&mut self) -> Option<Instant> {
        self.settle_timers();
        let timer = self.timers.peek().map(|Reverse((at, _))| *at);
        let time_wait = self.time_wait_order.front().map(|&(_, until)| until);
        [timer, self.budget.next_sweep(), time_wait]
            .into_iter()
            .flatten()
            .min()
    }

    /// What the settled heap alone asks for, apart from the sweep and the
    /// time waits [`Self::next_deadline`] also answers for.
    #[cfg(test)]
    pub(super) fn next_queued_timer(&mut self) -> Option<Instant> {
        self.settle_timers();
        self.timers.peek().map(|Reverse((at, _))| *at)
    }

    /// How many entries the timer heap holds.
    #[cfg(test)]
    pub(super) fn queued_timers(&self) -> usize {
        self.timers.len()
    }

    /// Hands up to `room` segments to `out`, connections taking turns.
    /// Returns how many it handed.
    pub(crate) fn emit(
        &mut self,
        now: Instant,
        room: usize,
        out: &mut dyn FnMut(OutSegment),
    ) -> usize {
        let mut sent = 0;
        while sent < room {
            let Some(segment) = self.control.pop_front() else {
                break;
            };
            out(segment);
            sent += 1;
        }
        while sent < room && !self.ready.is_empty() {
            let mut progressed = false;
            for _ in 0..self.ready.len() {
                if sent >= room {
                    break;
                }
                let Some(slot) = self.ready.pop_front() else {
                    break;
                };
                let cap = self
                    .slots
                    .get(slot)
                    .and_then(Option::as_ref)
                    .map_or(0, |conn| self.budget.window_cap(conn));
                let Some(conn) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
                    continue;
                };
                conn.in_tx_queue = false;
                let budget = (room - sent).min(SEGMENTS_PER_TURN);
                let transmitted = conn.poll_transmit(now, cap, budget, out);
                sent += transmitted.segments;
                progressed |= transmitted.segments > 0;
                if transmitted.more {
                    conn.in_tx_queue = true;
                    self.ready.push_back(slot);
                }
                self.after_transmit(slot, now);
            }
            if !progressed {
                break;
            }
        }
        sent
    }

    /// Closes every flow, failing their relays: the Core generation ends.
    pub(crate) fn shutdown(&mut self) {
        for slot in 0..self.slots.len() {
            if let Some(conn) = self.slots[slot].as_mut() {
                conn.close(true);
                self.remove(slot);
            }
        }
        self.ready.clear();
        self.timers.clear();
        self.control.clear();
        self.time_waits.clear();
        self.time_wait_order.clear();
        self.budget.end();
    }

    /// Closes every flow like [`Self::shutdown`] and leaves a reset for each
    /// one's client in the control queue for [`Self::emit`]: the capture
    /// ends, and a client socket left on a tunnel address that is gone would
    /// otherwise learn only when its own retransmissions or timeouts fail.
    pub(crate) fn reset_all(&mut self) {
        let resets: Vec<OutSegment> = self
            .slots
            .iter()
            .flatten()
            .flat_map(Connection::resets)
            .collect();
        self.shutdown();
        self.control.extend(resets);
    }

    /// Whether segments wait for [`Self::emit`].
    pub(crate) fn has_output(&self) -> bool {
        !self.control.is_empty() || !self.ready.is_empty()
    }

    /// After a connection changed: queue it to send if it has something, keep
    /// its earliest timer in the heap, and remove it once closed or in
    /// TIME-WAIT.
    fn after_event(&mut self, slot: usize, now: Instant) {
        let Some(conn) = self.slots[slot].as_mut() else {
            return;
        };
        if conn.wants_transmit() && !conn.in_tx_queue {
            conn.in_tx_queue = true;
            self.ready.push_back(slot);
        }
        self.after_transmit(slot, now);
    }

    fn after_transmit(&mut self, slot: usize, _now: Instant) {
        let Some(conn) = self.slots[slot].as_mut() else {
            return;
        };
        self.budget.resync(conn);
        if conn.state == State::Closed && !conn.wants_transmit() {
            self.remove(slot);
            return;
        }
        if let Some(wait) = conn.time_wait() {
            // Both directions have ended, so the relay sees a clean close.
            conn.close(false);
            let key = (conn.client, conn.local);
            self.remove(slot);
            self.enter_time_wait(key, wait);
            return;
        }
        if let Some(due) = conn.next_timer() {
            if conn.timer_queued.is_none_or(|queued| due < queued) {
                conn.timer_queued = Some(due);
                self.timers.push(Reverse((due, slot)));
            }
        }
    }

    fn remove(&mut self, slot: usize) {
        let Some(conn) = self.slots[slot].take() else {
            return;
        };
        let key = (conn.client, conn.local);
        self.flows.remove(&key);
        if let Some(share) = &self.share {
            share.holders.release(&key, share.queue);
        }
        self.budget.remove(&conn);
        self.active.fetch_sub(1, Ordering::Relaxed);
        if conn.state != State::Closed {
            conn.shared.close(true);
        }
        self.free.push(slot);
    }
}

impl std::fmt::Debug for TcpEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpEngine")
            .field("flows", &self.flows.len())
            .field("time_waits", &self.time_waits.len())
            .field("receiving", &self.budget.receiving())
            .finish_non_exhaustive()
    }
}

impl Drop for TcpEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}
