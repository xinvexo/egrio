//! One TCP connection of the engine: RFC 9293's state machine, with the
//! receive window, SACK, retransmission, congestion control and RFC 5961
//! checks `docs/architecture/core.md` (Captured TCP) lists. A captured flow
//! opens passively, the engine answering the client's SYN; a connection a
//! tunnel carries opens actively, the engine sending the SYN. Either way the
//! other end is `client`, the peer.
//!
//! This file holds the connection's state, how it is made and what the relay
//! asks of it; `receive` takes arriving segments, `timers` runs what times
//! out, and `transmit` builds what goes out.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::budget::Windows;
use super::cubic::{Acked, Cubic};
use super::rack::{Rack, Window, DUPTHRESH};
use super::scoreboard::{Scoreboard, Sent};
use super::segment::{self, Outgoing, Received, SackBlocks, ACK, FIN, PSH, RST, SYN};
use super::seq::Seq;
use super::stream::{FlowShared, MIN_SEND_BUFFER};
use super::time_wait::TimeWait;
use super::{OutSegment, Payload, MAX_PIECES};

mod receive;
mod timers;
mod transmit;

/// RFC 6298 section 2.1.
const INITIAL_RTO: Duration = Duration::from_secs(1);
/// The retransmission timeout's floor, below RFC 6298's second as common
/// stacks set it: RACK-TLP finds most losses before, and the floor still
/// outlasts a peer's delayed ACK.
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(60);
/// RFC 6298 section 2's clock granularity term.
const CLOCK_GRANULARITY: Duration = Duration::from_millis(1);
/// Retransmissions of our SYN or SYN|ACK before the handshake is given up.
const HANDSHAKE_RETRIES: u32 = 5;
/// Idle time before a keep-alive probe, and between probes; each deadline is
/// rounded up to the [`KEEPALIVE_GRID`].
const KEEPALIVE_IDLE: Duration = Duration::from_secs(28);
/// Keep-alive deadlines fall on this grid, so the probes of idle flows that
/// came due within a few seconds of each other go out in one engine wakeup
/// instead of one each.
pub(super) const KEEPALIVE_GRID: Duration = Duration::from_secs(4);
/// How long a client may leave retransmissions or probes unanswered.
const TIMEOUT: Duration = Duration::from_secs(60);
/// TIME-WAIT after an active close. The client is local, so a retransmitted
/// FIN arrives within a few retransmission timeouts.
pub(super) const TIME_WAIT: Duration = Duration::from_secs(2);
/// How long sender SWS avoidance may hold data a small window would take
/// (RFC 9293 section 3.8.6.2.1, "override timeout", 0.1 to 1 second).
const SWS_OVERRIDE: Duration = Duration::from_millis(200);
/// RFC 9293 section 3.7.1 default send MSS when the client sends none.
const DEFAULT_MSS_V4: usize = 536;
const DEFAULT_MSS_V6: usize = 1220;
/// The largest segment an engine offers a client. A capture device carries
/// far more than a link does -- the macOS utun 65 535 bytes, so a segment
/// would be 64 KiB -- while the receiving flows share one budget
/// ([`Windows`]): offering all of it leaves a busy flow a window one or two
/// segments deep, and SWS avoidance then withholds a window update until
/// half of it frees (RFC 9293 section 3.8.6.2.2, `min(MSS, window/2)`),
/// which starves a flow whose window closed. At this size a window holds
/// four segments even where 64 flows share the capture budget, so the
/// withheld update costs at most a quarter of it. What the engine sends is
/// bounded by the device instead, so a download keeps the device's segment.
pub(super) const MAX_OFFERED_MSS: usize = 16 * 1024;
/// How soon a client has to send a whole window to earn the next one
/// ([`Connection::grow_window`]), at the least. A sender held back by its
/// window fills it each round trip, and the capture's round trips are
/// microseconds, a few milliseconds when the Core's worker is saturated;
/// this leaves that room many times over, so only a client sending slower
/// than its window per fifty milliseconds keeps the one it has. A tunnel's
/// peer is a network away, and has a round trip and a half of its own.
const WINDOW_FILL_TIME: Duration = Duration::from_millis(50);

/// The keep-alive deadline after activity at `now`: [`KEEPALIVE_IDLE`]
/// later, rounded up to the [`KEEPALIVE_GRID`].
fn keepalive_deadline(now: Instant) -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    let grid = KEEPALIVE_GRID.as_nanos();
    let offset = (now + KEEPALIVE_IDLE)
        .saturating_duration_since(epoch)
        .as_nanos();
    epoch + Duration::from_nanos((offset.div_ceil(grid) * grid) as u64)
}

/// How far ahead of its pace a flow may send: a millisecond of the pace,
/// since the pump's timers resolve to about that, but no less than
/// `PACING_BURST` segments. RFC 6928 takes ten segments back to back as
/// what a path absorbs, and pacing a slow flow a segment or two at a time
/// wakes the pump for each.
const PACING_SLACK: Duration = Duration::from_millis(1);
const PACING_BURST: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl State {
    fn receives_data(self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }
}

/// Where loss recovery stands (RFC 6675 section 5, RFC 8985).
#[derive(Clone, Copy, Debug)]
enum Recovery {
    Open,
    /// Fast recovery until `point` is cumulatively acknowledged, the window
    /// following Proportional Rate Reduction (RFC 6937): the bytes
    /// delivered and sent since it began, and the flight it began with.
    Fast {
        point: Seq,
        delivered: usize,
        sent: usize,
        flight: usize,
    },
    /// After a retransmission timeout until `point` is acknowledged; no fast
    /// recovery begins before (RFC 6675 section 5.1).
    Timeout {
        point: Seq,
    },
}

/// What a transmission pass produced.
pub(super) struct Transmitted {
    pub(super) segments: usize,
    /// The connection stopped for the segment budget and has more to send.
    pub(super) more: bool,
}

pub(super) struct Connection {
    pub(super) client: SocketAddr,
    pub(super) local: SocketAddr,
    pub(super) state: State,
    pub(super) shared: Arc<FlowShared>,

    // Receive side.
    irs: Seq,
    rcv_nxt: Seq,
    /// The furthest right edge advertised; data up to it is accepted.
    rcv_edge: Seq,
    rcv_shift: u8,
    /// Stream offset of `rcv_nxt`: client bytes delivered in order.
    rcv_offset: u64,
    /// Out-of-order payload by stream offset, at most `max_out_of_order`
    /// segments of it.
    out_of_order: BTreeMap<u64, Bytes>,
    max_out_of_order: usize,
    /// Stream offset of the most recently arrived out-of-order segment.
    last_out_of_order: Option<u64>,
    /// Stream offset of a FIN that arrived ahead of missing data.
    fin_offset: Option<u64>,
    sack_ok: bool,
    /// The segment advertised to clients as their largest.
    our_mss: usize,
    /// The largest segment the capture device carries, which bounds what the
    /// engine sends however small a segment it offered.
    path_mss: usize,
    /// The window this flow has earned: it starts at the engine's starting
    /// window and doubles each time the client sends a whole one in time
    /// ([`Self::grow_window`]), so a flow holds no more of the budget than it
    /// has shown it needs.
    pub(super) allowance: usize,
    /// RCV.NXT and the time the bytes that may earn the next doubling began
    /// to count from.
    window_grown: Option<(Seq, Instant)>,
    /// The most the engine lets this flow hold unacknowledged, its share of
    /// [`Windows::send_budget`]. Starts at the ceiling, so a flow the engine
    /// has not granted yet behaves as it always did.
    send_cap: usize,
    /// The ceiling its send buffer grows to ([`Windows::send_max`]).
    send_max: usize,
    /// The engine's record of [`Self::send_granted`], kept so it can hold
    /// the sum over its flows without walking them.
    pub(super) send_recorded: usize,
    /// The engine's record of [`Self::outstanding_window`], kept so it can
    /// hold the sum over its receiving flows without walking them.
    pub(super) promised: usize,
    /// The next transmission pass sends an ACK, alone or on data: data or a
    /// FIN arrived, the window opened, or a segment needs an answer.
    ack_pending: bool,
    /// Payload was delivered since the engine last asked.
    delivered: bool,

    // Send side.
    iss: Seq,
    snd_una: Seq,
    /// The next new sequence number; retransmissions go out of the
    /// scoreboard and never move it back.
    snd_nxt: Seq,
    snd_wnd: usize,
    snd_wl1: Seq,
    snd_wl2: Seq,
    snd_shift: u8,
    max_snd_wnd: usize,
    send_mss: usize,
    /// The congestion window outside fast recovery: CUBIC with HyStart++
    /// (`cubic.rs`). Segments to a hotspot device cross a real link after
    /// the capture interface, so loss means congestion there.
    cc: Cubic,
    /// What is in flight (`scoreboard.rs`), and RACK-TLP's loss detection
    /// over it (`rack.rs`).
    board: Scoreboard,
    rack: Rack,
    recovery: Recovery,
    /// Whether the congestion window limited sending in the window of data
    /// in flight, the largest flight since that window began, and where it
    /// ends: an application-limited flow does not grow its window (RFC
    /// 9438 section 5.8).
    cwnd_limited: bool,
    max_pipe: usize,
    cwnd_usage_end: Seq,
    /// When the next data segment may go out at the pacing rate, how far
    /// ahead of that the flow may send, and whether the pace is what
    /// stopped sending.
    pace_next: Instant,
    pace_slack: Duration,
    paced: bool,
    /// The send buffer limit last given to the relay.
    send_limit: usize,
    /// When data last went out, for the restart window after idle.
    last_send: Instant,
    /// Relay bytes from `snd_una` on: unacknowledged, then unsent.
    sendq: VecDeque<Bytes>,
    sendq_len: usize,
    /// Where the last segment built from `sendq` ended, so the next one
    /// starts there without walking the bytes in flight.
    cursor: SendCursor,
    fin_queued: bool,
    /// A FIN is in flight right after the last queued byte.
    fin_sent: bool,

    // Timing.
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    /// The handshake's RTT sample: our SYN or SYN|ACK, sent once.
    rtt_sample: Option<(Seq, Instant)>,
    /// The retransmission timeout, the tail loss probe and RACK's
    /// reordering timer (RFC 8985 section 8).
    retransmit_at: Option<Instant>,
    probe_at: Option<Instant>,
    reorder_at: Option<Instant>,
    /// A tail loss probe is due.
    loss_probe_due: bool,
    retransmits: u32,
    last_progress: Instant,
    /// Duplicate ACKs from a peer without SACK, which show a loss once
    /// there are DUPTHRESH (RFC 5681 section 3.2).
    dupacks: u32,
    /// The peer has sent SACK blocks: RACK finds its losses. Until then,
    /// duplicate and partial acknowledgements show them.
    sacks_seen: bool,
    persist_at: Option<Instant>,
    /// When data held back by sender SWS avoidance goes out anyway.
    sws_override_at: Option<Instant>,
    /// The override ran out: the held data goes out once the output takes
    /// it. Off the timers, so a full output does not wake the pump for it
    /// again and again.
    sws_override_due: bool,
    persist_backoff: u32,
    probe_due: bool,
    last_rx: Instant,
    next_keepalive: Instant,
    time_wait_until: Option<Instant>,
    /// The window field of the last segment sent.
    last_window: u16,

    /// Our SYN (opening) or SYN|ACK (accepting) is due.
    handshake_due: bool,
    /// Send RST|ACK from `snd_nxt` and close.
    reset_due: bool,
    /// Answer an unacceptable ACK in SYN-RECEIVED with `<SEQ=ack><CTL=RST>`.
    reply_reset: Option<Seq>,
    /// The relay is gone: client data now draws an RST.
    relay_gone: bool,

    // Engine bookkeeping.
    pub(super) opened: Instant,
    pub(super) last_data: Instant,
    pub(super) receiving: bool,
    pub(super) in_tx_queue: bool,
    pub(super) timer_queued: Option<Instant>,
}

/// A position in the send queue: `offset` bytes past `snd_una`, `skip` bytes
/// into chunk `chunk`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SendCursor {
    offset: usize,
    chunk: usize,
    skip: usize,
}

impl SendCursor {
    /// Follows an acknowledgement of `acked` bytes that dropped `popped`
    /// chunks and cut `trimmed` bytes off the new front chunk. A cursor the
    /// acknowledgement passed goes stale and is sought again on next use.
    fn rebase(&mut self, acked: usize, popped: usize, trimmed: usize) {
        if self.is_stale() || self.offset < acked || self.chunk < popped {
            self.offset = usize::MAX;
            return;
        }
        self.offset -= acked;
        self.chunk -= popped;
        if self.chunk == 0 {
            self.skip -= trimmed;
        }
    }

    fn is_stale(&self) -> bool {
        self.offset == usize::MAX
    }
}

impl Connection {
    /// A connection for a client's SYN, in SYN-RECEIVED with its SYN|ACK due;
    /// `windows` gives our window scale if the client offers scaling.
    pub(super) fn accept(
        syn: &Received,
        shared: Arc<FlowShared>,
        mtu: usize,
        windows: Windows,
        iss: Seq,
        now: Instant,
    ) -> Self {
        let local = syn.target;
        let base = segment::base_header_len(&local);
        let path_mss = mtu
            .saturating_sub(base)
            .clamp(DEFAULT_MSS_V4, usize::from(u16::MAX));
        let our_mss = path_mss.min(MAX_OFFERED_MSS);
        let default_peer_mss = if local.is_ipv4() {
            DEFAULT_MSS_V4
        } else {
            DEFAULT_MSS_V6
        };
        let peer_mss = syn.options.mss.map_or(default_peer_mss, usize::from);
        let send_mss = peer_mss.min(path_mss).max(DEFAULT_MSS_V4 / 2);
        let scaled = syn.options.window_scale.is_some();
        let window = usize::from(syn.window);
        Self {
            client: syn.client,
            local,
            state: State::SynReceived,
            shared,
            irs: syn.seq,
            rcv_nxt: syn.seq.add(1),
            rcv_edge: syn.seq.add(1),
            rcv_shift: if scaled { windows.shift } else { 0 },
            rcv_offset: 0,
            out_of_order: BTreeMap::new(),
            max_out_of_order: windows.out_of_order,
            last_out_of_order: None,
            fin_offset: None,
            sack_ok: syn.options.sack_permitted,
            our_mss,
            path_mss,
            allowance: windows.start,
            window_grown: None,
            send_cap: windows.send_max,
            send_max: windows.send_max,
            send_recorded: 0,
            promised: 0,
            ack_pending: false,
            delivered: false,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: window,
            snd_wl1: syn.seq,
            snd_wl2: iss,
            snd_shift: syn.options.window_scale.unwrap_or(0),
            max_snd_wnd: window,
            send_mss,
            cc: Cubic::new(send_mss, iss),
            board: Scoreboard::default(),
            rack: Rack::new(iss),
            recovery: Recovery::Open,
            cwnd_limited: false,
            max_pipe: 0,
            cwnd_usage_end: iss,
            pace_next: now,
            pace_slack: PACING_SLACK,
            paced: false,
            send_limit: MIN_SEND_BUFFER,
            last_send: now,
            sendq: VecDeque::new(),
            sendq_len: 0,
            cursor: SendCursor::default(),
            fin_queued: false,
            fin_sent: false,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            rtt_sample: None,
            retransmit_at: None,
            probe_at: None,
            reorder_at: None,
            loss_probe_due: false,
            retransmits: 0,
            last_progress: now,
            dupacks: 0,
            sacks_seen: false,
            persist_at: None,
            sws_override_at: None,
            sws_override_due: false,
            persist_backoff: 0,
            probe_due: false,
            last_rx: now,
            next_keepalive: keepalive_deadline(now),
            time_wait_until: None,
            last_window: 0,
            handshake_due: true,
            reset_due: false,
            reply_reset: None,
            relay_gone: false,
            opened: now,
            last_data: now,
            receiving: true,
            in_tx_queue: false,
            timer_queued: None,
        }
    }

    /// A connection this host opens to `peer`, in SYN-SENT with its SYN due.
    /// The SYN offers window scaling as `windows` gives it and SACK; the
    /// peer's SYN|ACK settles what is used (RFC 7323 section 1.3, RFC 2018
    /// section 2).
    pub(super) fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        shared: Arc<FlowShared>,
        mtu: usize,
        windows: Windows,
        iss: Seq,
        now: Instant,
    ) -> Self {
        let base = segment::base_header_len(&local);
        let path_mss = mtu
            .saturating_sub(base)
            .clamp(DEFAULT_MSS_V4, usize::from(u16::MAX));
        let our_mss = path_mss.min(MAX_OFFERED_MSS);
        Self {
            client: peer,
            local,
            state: State::SynSent,
            shared,
            irs: Seq(0),
            rcv_nxt: Seq(0),
            rcv_edge: Seq(0),
            rcv_shift: windows.shift,
            rcv_offset: 0,
            out_of_order: BTreeMap::new(),
            max_out_of_order: windows.out_of_order,
            last_out_of_order: None,
            fin_offset: None,
            sack_ok: false,
            our_mss,
            path_mss,
            allowance: windows.start,
            window_grown: None,
            send_cap: windows.send_max,
            send_max: windows.send_max,
            send_recorded: 0,
            promised: 0,
            ack_pending: false,
            delivered: false,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: Seq(0),
            snd_wl2: iss,
            snd_shift: 0,
            max_snd_wnd: 0,
            send_mss: path_mss,
            cc: Cubic::new(path_mss, iss),
            board: Scoreboard::default(),
            rack: Rack::new(iss),
            recovery: Recovery::Open,
            cwnd_limited: false,
            max_pipe: 0,
            cwnd_usage_end: iss,
            pace_next: now,
            pace_slack: PACING_SLACK,
            paced: false,
            send_limit: MIN_SEND_BUFFER,
            last_send: now,
            sendq: VecDeque::new(),
            sendq_len: 0,
            cursor: SendCursor::default(),
            fin_queued: false,
            fin_sent: false,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            rtt_sample: None,
            retransmit_at: None,
            probe_at: None,
            reorder_at: None,
            loss_probe_due: false,
            retransmits: 0,
            last_progress: now,
            dupacks: 0,
            sacks_seen: false,
            persist_at: None,
            sws_override_at: None,
            sws_override_due: false,
            persist_backoff: 0,
            probe_due: false,
            last_rx: now,
            next_keepalive: keepalive_deadline(now),
            time_wait_until: None,
            last_window: 0,
            handshake_due: true,
            reset_due: false,
            reply_reset: None,
            relay_gone: false,
            opened: now,
            last_data: now,
            receiving: true,
            in_tx_queue: false,
            timer_queued: None,
        }
    }

    /// Whether payload was delivered since the last call.
    pub(super) fn take_delivered(&mut self) -> bool {
        std::mem::take(&mut self.delivered)
    }

    /// The connection's TIME-WAIT as a record, once the ACK of the client's
    /// FIN went out.
    pub(super) fn time_wait(&self) -> Option<TimeWait> {
        if self.state != State::TimeWait || self.wants_transmit() {
            return None;
        }
        Some(TimeWait {
            snd_nxt: self.snd_nxt,
            rcv_nxt: self.rcv_nxt,
            rcv_edge: self.rcv_edge,
            window: self.last_window,
            until: self.time_wait_until?,
        })
    }

    /// The client's ISN, which a SYN in TIME-WAIT must exceed to reopen.
    pub(super) fn may_reopen_with(&self, syn: &Received) -> bool {
        self.state == State::TimeWait && syn.seq.is_after(self.rcv_nxt)
    }

    /// A SYN for this tuple that is not this connection's retransmitted one.
    pub(super) fn is_new_syn(&self, syn: &Received) -> bool {
        self.state == State::SynReceived && syn.seq != self.irs
    }

    // Relay events.

    /// Takes what the relay wrote and the flags it set.
    pub(super) fn service(&mut self, cap: usize) {
        self.shared.unschedule();
        if self.state == State::Closed {
            return;
        }
        if self.shared.is_reset_requested() {
            self.reset_due = true;
            return;
        }
        let before = self.sendq.len();
        let shutdown = self.shared.take_written(&mut self.sendq);
        for chunk in self.sendq.range(before..) {
            self.sendq_len += chunk.len();
        }
        if self.shared.is_dropped() {
            self.relay_gone = true;
            self.fin_queued = true;
        } else if shutdown {
            self.fin_queued = true;
        }
        if self.window_update_worthwhile(cap) {
            self.ack_pending = true;
        } else if self.state.receives_data() {
            // The budget may have shrunk since the relay was asked to call
            // back: ask again for what reopening the window takes now.
            self.arm_window_wake(cap);
        }
    }

    /// Doubles the window, up to `ceiling`, once the client has sent a whole
    /// one within a round trip and a half, and [`WINDOW_FILL_TIME`] at the
    /// least. A flow earns its room by filling what it has at the rate a
    /// larger window would speed up: a bulk sender fills a window each round
    /// trip, while a long-lived connection of small requests, which grew to
    /// the largest window when every byte it ever sent counted, never fills
    /// one in time. Linux sizes the receive buffer by what the reader took in
    /// a round trip the same way, at twice it (`tcp_rcv_space_adjust` in
    /// `net/ipv4/tcp_input.c`). An edge
    /// the client reached ahead of the engine's newest acknowledgement says
    /// nothing here: the engine has moved the edge on before the client's
    /// last segment of a window arrives, so testing for it held uploads back
    /// by a fifth.
    pub(super) fn grow_window(&mut self, ceiling: usize, now: Instant) {
        let Some((from, since)) = self.window_grown else {
            self.window_grown = Some((self.rcv_nxt, now));
            return;
        };
        let filled = self.rcv_nxt.since(from) >= self.allowance as i64;
        let fill_time = self.srtt.map_or(WINDOW_FILL_TIME, |srtt| {
            (srtt + srtt / 2).max(WINDOW_FILL_TIME)
        });
        let in_time = now.duration_since(since) <= fill_time;
        if filled && in_time {
            self.allowance = self.allowance.saturating_mul(2).min(ceiling.max(1));
        }
        if filled || !in_time {
            self.window_grown = Some((self.rcv_nxt, now));
        }
    }

    /// The window this flow has advertised and the client has not used yet:
    /// bytes it may put in the capture device at any moment. The engine sums
    /// these to keep the budget whole, because an advertised right edge never
    /// moves left (RFC 9293 section 3.8.6).
    pub(super) fn outstanding_window(&self) -> usize {
        // A FIN takes a sequence number past the data the window covered.
        self.rcv_edge.since(self.rcv_nxt).max(0) as usize
    }

    /// Whether the flow holds client bytes the relay has not taken. Such a
    /// flow still counts against the window budget: what it holds left the
    /// capture device, but the window it already advertised has not.
    pub(super) fn holds_client_bytes(&self) -> bool {
        self.shared.recv_queued() > 0
    }

    /// RFC 9293 section 3.8.6.2.2: advertise more window only once the edge
    /// would move by min(MSS, half the buffer).
    fn window_update_worthwhile(&self, cap: usize) -> bool {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return false;
        }
        let cap = self.window_limit(cap);
        let open = cap.saturating_sub(self.shared.recv_queued());
        let potential = self.rcv_nxt.add(open);
        potential.since(self.rcv_edge) >= (cap / 2).min(self.our_mss) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tcp::cubic::MAX_WINDOW;
    use crate::packet::tcp::stream::EngineWake;

    #[test]
    fn keepalive_deadlines_share_a_grid_point() {
        let now = Instant::now();
        let due = keepalive_deadline(now);
        assert!(due >= now + KEEPALIVE_IDLE);
        assert!(due < now + KEEPALIVE_IDLE + KEEPALIVE_GRID);
        // Activity later in the same grid cell probes at the same time.
        assert_eq!(keepalive_deadline(due - KEEPALIVE_IDLE), due);
        let earlier = (due - KEEPALIVE_IDLE - KEEPALIVE_GRID) + Duration::from_millis(1);
        assert_eq!(keepalive_deadline(earlier), due);
        assert_eq!(
            keepalive_deadline(now + KEEPALIVE_GRID),
            due + KEEPALIVE_GRID
        );
    }

    fn connection(now: Instant) -> Connection {
        let syn = Received {
            client: "10.0.0.2:40000".parse().unwrap(),
            target: "93.184.216.34:443".parse().unwrap(),
            seq: Seq(1000),
            ack: Seq(0),
            flags: SYN,
            window: u16::MAX,
            options: segment::ReceivedOptions {
                mss: Some(65495),
                window_scale: Some(14),
                sack_permitted: false,
                sack: SackBlocks::default(),
            },
            payload: 0..0,
        };
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let mut conn = Connection::accept(
            &syn,
            shared,
            65535,
            crate::packet::tcp::budget::CAPTURE_WINDOWS,
            Seq(u32::MAX - 100),
            now,
        );
        conn.state = State::Established;
        conn.snd_una = conn.iss.add(1);
        conn.snd_nxt = conn.snd_una;
        conn.snd_wnd = MAX_WINDOW;
        conn
    }

    #[test]
    fn the_send_buffer_follows_what_may_be_in_flight() {
        let now = Instant::now();
        let mut conn = connection(now);
        conn.cc.set_cwnd(MAX_WINDOW);
        conn.snd_wnd = 64 * 1024;
        conn.size_send_buffer();
        assert_eq!(conn.send_limit, 0, "a flow holding nothing holds no buffer");
        conn.sendq.push_back(Bytes::from_static(b"queued"));
        conn.sendq_len = 6;
        conn.size_send_buffer();
        assert_eq!(
            conn.send_limit, MIN_SEND_BUFFER,
            "a small window keeps the floor"
        );
        conn.snd_wnd = 1536 * 1024;
        conn.size_send_buffer();
        assert_eq!(conn.send_limit, 3 * 1024 * 1024);
        conn.snd_wnd = 13 * 1024 * 1024;
        conn.size_send_buffer();
        assert_eq!(conn.send_limit, conn.send_max);
        conn.cc.set_cwnd(conn.send_mss);
        conn.size_send_buffer();
        assert_eq!(
            conn.send_limit, MIN_SEND_BUFFER,
            "a collapsed congestion window shrinks it"
        );
    }
}
