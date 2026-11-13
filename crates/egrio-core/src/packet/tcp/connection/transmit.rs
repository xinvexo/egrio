//! Transmission: what a pass may send -- the handshake, a probe, lost
//! segments before new data, a bare acknowledgement -- within the client's
//! window, the congestion window and the pace.

use super::*;

impl Connection {
    /// Whether anything is ready to go out apart from window-limited data.
    pub(in crate::packet::tcp) fn wants_transmit(&self) -> bool {
        self.reset_due
            || self.reply_reset.is_some()
            || self.handshake_due
            || self.ack_pending
            || self.probe_due
            || self.loss_probe_due
            || (!self.paced && (self.has_sendable() || self.board.has_waiting()))
    }

    fn has_sendable(&self) -> bool {
        if matches!(
            self.state,
            State::SynSent | State::SynReceived | State::Closed
        ) {
            return false;
        }
        let offset = self.snd_nxt.offset_from(self.snd_una);
        offset < self.sendq_len || (self.fin_queued && !self.fin_sent && offset == self.sendq_len)
    }

    /// Writes up to `budget` segments through `out`.
    pub(in crate::packet::tcp) fn poll_transmit(
        &mut self,
        now: Instant,
        cap: usize,
        budget: usize,
        out: &mut dyn FnMut(OutSegment),
    ) -> Transmitted {
        let mut segments = 0;
        if let Some(seq) = self.reply_reset.take() {
            out(self.control(seq, None, RST, 0));
            segments += 1;
        }
        if self.reset_due {
            self.reset_due = false;
            out(self.control(self.snd_nxt, Some(self.rcv_nxt), RST | ACK, 0));
            self.close(true);
            return Transmitted {
                segments: segments + 1,
                more: false,
            };
        }
        match self.state {
            State::Closed => {
                return Transmitted {
                    segments,
                    more: false,
                }
            }
            State::SynSent | State::SynReceived => {
                if self.handshake_due && segments < budget {
                    out(if self.state == State::SynSent {
                        self.syn(cap, now)
                    } else {
                        self.syn_ack(cap, now)
                    });
                    segments += 1;
                }
                return Transmitted {
                    segments,
                    more: false,
                };
            }
            _ => {}
        }
        if self.loss_probe_due && segments < budget {
            self.loss_probe_due = false;
            if let Some(segment) = self.loss_probe(cap, now) {
                out(segment);
                segments += 1;
            }
        }
        let new_from = self.snd_nxt;
        let mut blocked = false;
        while segments < budget {
            match self.next_segment(cap, now, &mut blocked) {
                Some(segment) => {
                    out(segment);
                    segments += 1;
                }
                None => break,
            }
        }
        if self.snd_nxt != new_from {
            // New data restarts the probe timer; a probe does not.
            self.schedule_probe(now);
        }
        self.validate_cwnd(blocked);
        if segments >= budget && !self.paced && (self.has_sendable() || self.board.has_waiting()) {
            return Transmitted {
                segments,
                more: true,
            };
        }
        if (self.ack_pending || self.probe_due) && segments < budget {
            // A probe asks the client for its window with a byte it already
            // acknowledged (RFC 9293 sections 3.8.4 and 3.8.6.1); any other
            // segment carries the ACK by itself.
            let seq = if self.probe_due {
                self.snd_una.sub(1)
            } else {
                self.snd_nxt
            };
            self.probe_due = false;
            let window = self.advertise(cap);
            let segment = self.segment(seq, ACK, window, Payload::default());
            out(segment);
            segments += 1;
        }
        Transmitted {
            segments,
            more: false,
        }
    }

    fn syn_ack(&mut self, cap: usize, now: Instant) -> OutSegment {
        self.handshake_due = false;
        // The window of a SYN is never scaled (RFC 7323 section 2.2).
        let window = cap.min(usize::from(u16::MAX));
        self.rcv_edge = self.rcv_nxt.add(window);
        let outgoing = Outgoing {
            local: self.local,
            client: self.client,
            seq: self.iss,
            ack: self.rcv_nxt,
            flags: SYN | ACK,
            window: window as u16,
            mss: Some(self.our_mss as u16),
            window_scale: (self.rcv_shift > 0).then_some(self.rcv_shift),
            sack_permitted: self.sack_ok,
            sack: SackBlocks::default(),
        };
        self.snd_nxt = self.iss.add(1);
        if self.retransmits == 0 {
            self.rtt_sample = Some((self.iss, now));
        }
        self.retransmit_at = Some(now + self.rto);
        OutSegment {
            header: segment::write_header(&outgoing, 0),
            payload: Payload::default(),
        }
    }

    fn syn(&mut self, cap: usize, now: Instant) -> OutSegment {
        self.handshake_due = false;
        // The window of a SYN is never scaled (RFC 7323 section 2.2).
        let window = cap.min(usize::from(u16::MAX)) as u16;
        self.last_window = window;
        let outgoing = Outgoing {
            local: self.local,
            client: self.client,
            seq: self.iss,
            ack: Seq(0),
            flags: SYN,
            window,
            mss: Some(self.our_mss as u16),
            window_scale: Some(self.rcv_shift),
            sack_permitted: true,
            sack: SackBlocks::default(),
        };
        self.snd_nxt = self.iss.add(1);
        if self.retransmits == 0 {
            self.rtt_sample = Some((self.iss, now));
        }
        self.retransmit_at = Some(now + self.rto);
        OutSegment {
            header: segment::write_header(&outgoing, 0),
            payload: Payload::default(),
        }
    }

    /// An ICMP destination-unreachable for a connection still opening ends
    /// it at once (RFC 1122 section 4.2.3.9 leaves this to the stack for
    /// codes other than "fragmentation needed").
    pub(in crate::packet::tcp) fn unreachable(&mut self) {
        if self.state == State::SynSent {
            self.close(true);
        }
    }

    pub(super) fn control(&self, seq: Seq, ack: Option<Seq>, flags: u8, window: u16) -> OutSegment {
        let outgoing = Outgoing {
            local: self.local,
            client: self.client,
            seq,
            ack: ack.unwrap_or_default(),
            flags,
            window,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: SackBlocks::default(),
        };
        OutSegment {
            header: segment::write_header(&outgoing, 0),
            payload: Payload::default(),
        }
    }

    /// The largest payload a segment can carry with the SACK blocks it
    /// would include now.
    fn max_payload(&self) -> usize {
        self.send_mss
            - self.sack_blocks().as_slice().len().min(4) * 8
            - usize::from(!self.sack_blocks().is_empty()) * 4
    }

    /// The largest payload a new data segment takes: [`Self::max_payload`]
    /// within half the largest window the peer has offered. A receiver
    /// acknowledges every second full-sized segment at once and holds a
    /// lone one for its delayed-ACK timer (RFC 1122 section 4.2.3.2), so a
    /// segment that fills the whole window waits that timer out each time.
    /// A window of a default segment or less is not split.
    fn new_data_payload(&self) -> usize {
        let max_payload = self.max_payload();
        if self.max_snd_wnd <= DEFAULT_MSS_V4 {
            return max_payload;
        }
        max_payload.min(self.max_snd_wnd / 2)
    }

    /// The next data segment the windows and the pace allow: a segment found
    /// lost goes out again before new data (RFC 6675's NextSeg, rules 1 and
    /// 2). Sets `blocked` when the congestion window held data back.
    fn next_segment(&mut self, cap: usize, now: Instant, blocked: &mut bool) -> Option<OutSegment> {
        let lost = self
            .board
            .next_lost()
            .map(|segment| (segment.start, segment.end, segment.fin));
        if lost.is_none() && !self.has_sendable() {
            return None;
        }
        if self.board.is_empty() && now.duration_since(self.last_send) > self.rto {
            // The restart window after an idle period (RFC 5681 section 4.1).
            self.cc.restart_after_idle();
        }
        if self.board.pipe() >= self.cc.cwnd() {
            *blocked = true;
            return None;
        }
        if !self.pace_allows(now) {
            return None;
        }
        match lost {
            Some((start, end, fin)) => Some(self.retransmit(start, end, fin, cap, now)),
            None => self.next_data_segment(cap, now),
        }
    }

    /// Whether the pace lets a data segment out now. The pace spreads the
    /// window over the round trip, instead of sending it as a burst the
    /// bottleneck's queue has to absorb.
    fn pace_allows(&mut self, now: Instant) -> bool {
        if self.pace_next <= now + self.pace_slack {
            self.paced = false;
            return true;
        }
        self.paced = true;
        false
    }

    /// Bytes went out: PRR counts them, and the pace moves on by their time
    /// at the pacing rate, with no credit for time the flow sat idle.
    fn sent_now(&mut self, bytes: usize, now: Instant) {
        self.last_send = now;
        if let Recovery::Fast { sent, .. } = &mut self.recovery {
            *sent += bytes;
        }
        let Some(rate) = self.srtt.and_then(|srtt| self.cc.pacing_rate(srtt)) else {
            return;
        };
        let nanos_per_byte = 1e9 / rate;
        let start = self.pace_next.max(now);
        self.pace_next = start + Duration::from_nanos((bytes as f64 * nanos_per_byte) as u64);
        let burst = (PACING_BURST * self.send_mss) as f64 * nanos_per_byte;
        self.pace_slack = Duration::from_nanos(burst as u64).max(PACING_SLACK);
    }

    /// A segment of the scoreboard again, as it first went out; one that
    /// would not fit with the SACK blocks now goes without them.
    fn retransmit(
        &mut self,
        start: Seq,
        end: Seq,
        fin: bool,
        cap: usize,
        now: Instant,
    ) -> OutSegment {
        let offset = start.offset_from(self.snd_una);
        let length = end.offset_from(start) - usize::from(fin);
        let (payload, taken) = self.payload(offset, length);
        debug_assert_eq!(taken, length, "a segment is resent as it went out");
        let mut flags = ACK;
        if offset + taken == self.sendq_len {
            flags |= PSH;
        }
        if fin {
            flags |= FIN;
        }
        let window = self.advertise(cap);
        let segment = if taken > self.max_payload() {
            self.segment_with(start, flags, window, payload, SackBlocks::default())
        } else {
            self.segment(start, flags, window, payload)
        };
        self.board.resent(start, now);
        self.sent_now(end.offset_from(start), now);
        segment
    }

    /// A tail loss probe (RFC 8985 section 7.3): new data if there is some
    /// and the peer's window takes it, whatever the congestion window and
    /// the pace, else the last segment again.
    fn loss_probe(&mut self, cap: usize, now: Instant) -> Option<OutSegment> {
        if !self.rack.may_probe() || self.board.is_empty() {
            return None;
        }
        let offset = self.snd_nxt.offset_from(self.snd_una);
        if offset < self.sendq_len && self.snd_wnd > offset {
            if let Some(segment) = self.next_data_segment(cap, now) {
                self.rack.probed(self.snd_nxt, false);
                return Some(segment);
            }
        }
        let (start, end, fin) = self
            .board
            .last()
            .map(|last| (last.start, last.end, last.fin))?;
        let segment = self.retransmit(start, end, fin, cap, now);
        self.rack.probed(end, true);
        Some(segment)
    }

    /// Starts or restarts the loss probe timer after new data went out or
    /// new data was acknowledged: with SACK, outside recovery, with nothing
    /// SACKed and RACK's reordering timer off (RFC 8985 section 7.2).
    pub(super) fn schedule_probe(&mut self, now: Instant) {
        if !self.sack_ok
            || !matches!(self.recovery, Recovery::Open)
            || self.board.sacked() > 0
            || self.reorder_at.is_some()
            || self.board.is_empty()
        {
            self.probe_at = None;
            return;
        }
        let rto_at = self.retransmit_at.unwrap_or(now + self.rto);
        let one_segment = self
            .board
            .first()
            .is_some_and(|first| first.end == self.snd_nxt);
        self.probe_at = Some(self.rack.probe_at(self.srtt, one_segment, now, rto_at));
    }

    /// Whether the congestion window limited this window of data (RFC 9438
    /// section 5.8): kept until the data sent while it was the limit is
    /// acknowledged, with the largest flight since.
    fn validate_cwnd(&mut self, blocked: bool) {
        let pipe = self.board.pipe();
        let limited = blocked || pipe >= self.cc.cwnd();
        if !self.snd_una.is_before(self.cwnd_usage_end)
            || limited
            || (!self.cwnd_limited && pipe > self.max_pipe)
        {
            self.cwnd_limited = limited;
            self.max_pipe = pipe;
            self.cwnd_usage_end = self.snd_nxt;
        }
    }

    /// Whether an ACK may grow the window: the window was the limit, or in
    /// slow start the flight reached half of it.
    pub(super) fn is_cwnd_limited(&self) -> bool {
        self.cwnd_limited || (self.cc.in_slow_start() && self.cc.cwnd() < 2 * self.max_pipe)
    }

    /// The next segment of new data the peer's window takes; the congestion
    /// window and the pace are the caller's to check.
    fn next_data_segment(&mut self, cap: usize, now: Instant) -> Option<OutSegment> {
        let offset = self.snd_nxt.offset_from(self.snd_una);
        if offset > self.sendq_len {
            return None;
        }
        let available = self.sendq_len - offset;
        // Byte counts, not sequence arithmetic: the peer's window is at most
        // 2^30 bytes (RFC 7323 section 2.3), and in flight is at most it.
        let usable = self.snd_wnd.saturating_sub(offset);
        let fin_pending = self.fin_queued && !self.fin_sent;
        if available == 0 {
            if fin_pending && usable > 0 {
                let window = self.advertise(cap);
                let segment = self.segment(self.snd_nxt, ACK | FIN, window, Payload::default());
                self.advance(0, true, now);
                return Some(segment);
            }
            if fin_pending {
                self.arm_persist(now);
            }
            return None;
        }
        if usable == 0 {
            // A zero receive window is probed.
            self.arm_persist(now);
            return None;
        }
        let max_payload = self.new_data_payload();
        let length = available.min(usable).min(max_payload);
        // Sender SWS avoidance (RFC 9293 section 3.8.6.2.1): hold a small
        // segment while more data waits for window, up to the override
        // timeout.
        if length < max_payload
            && length < available
            && length < self.max_snd_wnd / 2
            && !self.sws_override_due
        {
            match self.sws_override_at {
                Some(at) if now >= at => {}
                Some(_) => return None,
                None => {
                    self.sws_override_at = Some(now + SWS_OVERRIDE);
                    return None;
                }
            }
        }
        let (payload, length) = self.payload(offset, length);
        let fin = fin_pending && length == available && usable > length;
        let mut flags = ACK;
        if offset + length == self.sendq_len {
            flags |= PSH;
        }
        if fin {
            flags |= FIN;
        }
        let window = self.advertise(cap);
        let segment = self.segment(self.snd_nxt, flags, window, payload);
        self.advance(length, fin, now);
        Some(segment)
    }

    /// Moves `snd_nxt` past a new segment just built and records it.
    fn advance(&mut self, length: usize, fin: bool, now: Instant) {
        let start = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.add(length + usize::from(fin));
        self.board.sent(start, self.snd_nxt, fin, now);
        self.sent_now(length + usize::from(fin), now);
        if fin {
            self.fin_sent = true;
            match self.state {
                State::Established => self.state = State::FinWait1,
                State::CloseWait => self.state = State::LastAck,
                _ => {}
            }
        }
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
        self.persist_at = None;
        self.persist_backoff = 0;
        self.sws_override_at = None;
        self.sws_override_due = false;
    }

    fn arm_persist(&mut self, now: Instant) {
        if self.persist_at.is_none() && self.board.is_empty() {
            self.persist_at = Some(now + self.backoff(self.persist_backoff));
        }
    }

    /// The queued bytes at `[offset, offset + length)` as at most
    /// `MAX_PIECES` pieces; the length shrinks to what fits. Starts from
    /// where the previous segment ended when it ends at `offset`, which is
    /// every new segment; only a retransmission walks from the front.
    fn payload(&mut self, offset: usize, length: usize) -> (Payload, usize) {
        if self.cursor.offset != offset {
            self.cursor = self.seek(offset);
        }
        let SendCursor {
            mut chunk,
            mut skip,
            ..
        } = self.cursor;
        let mut payload = Payload::default();
        let mut remaining = length;
        while remaining > 0 && payload.len() < MAX_PIECES && chunk < self.sendq.len() {
            let bytes = &self.sendq[chunk];
            let take = (bytes.len() - skip).min(remaining);
            payload.push(bytes.slice(skip..skip + take));
            remaining -= take;
            skip += take;
            if skip == bytes.len() {
                chunk += 1;
                skip = 0;
            }
        }
        let taken = length - remaining;
        self.cursor = SendCursor {
            offset: offset + taken,
            chunk,
            skip,
        };
        (payload, taken)
    }

    /// The cursor at `offset` bytes past `snd_una`, found from the front.
    pub(super) fn seek(&self, offset: usize) -> SendCursor {
        let mut chunk = 0;
        let mut skip = offset;
        while chunk < self.sendq.len() && skip >= self.sendq[chunk].len() {
            skip -= self.sendq[chunk].len();
            chunk += 1;
        }
        SendCursor {
            offset,
            chunk,
            skip,
        }
    }

    /// A segment of this connection; every one carries the ACK.
    fn segment(&mut self, seq: Seq, flags: u8, window: u16, payload: Payload) -> OutSegment {
        let sack = self.sack_blocks();
        self.segment_with(seq, flags, window, payload, sack)
    }

    fn segment_with(
        &mut self,
        seq: Seq,
        flags: u8,
        window: u16,
        payload: Payload,
        sack: SackBlocks,
    ) -> OutSegment {
        let outgoing = Outgoing {
            local: self.local,
            client: self.client,
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack,
        };
        self.ack_pending = false;
        self.last_window = window;
        let header = segment::write_header(&outgoing, payload.total_len());
        OutSegment { header, payload }
    }

    /// The window field for a segment going out now. The advertised right
    /// edge never moves left (RFC 9293 section 3.8.6): the scaled window is
    /// rounded up, and an edge already advertised stays.
    fn advertise(&mut self, cap: usize) -> u16 {
        let cap = self.window_limit(cap);
        let queued = self.shared.recv_queued();
        let open = cap.saturating_sub(queued);
        let wanted = self.rcv_nxt.add(open);
        let edge = self.rcv_edge.max(wanted);
        let span = edge.offset_from(self.rcv_nxt);
        let unit = 1usize << self.rcv_shift;
        let field = (span.div_ceil(unit)).min(usize::from(u16::MAX));
        let advertised = self.rcv_nxt.add(field << self.rcv_shift);
        self.rcv_edge = self.rcv_edge.max(advertised);
        self.arm_window_wake(cap);
        field as u16
    }

    /// The receive window budget as far as the window field can express it:
    /// without scaling a window ends at 65 535 bytes (RFC 7323 section 2.2),
    /// and an update cannot move the edge beyond that.
    pub(super) fn window_limit(&self, cap: usize) -> usize {
        cap.min(usize::from(u16::MAX) << self.rcv_shift)
    }

    /// Below half open, asks the relay to call back once its reads leave
    /// little enough queued for the right edge to move by the update
    /// threshold; otherwise asks for nothing. Below half open the span and
    /// the threshold leave room under the cap, so the level is positive and
    /// an empty queue always reaches it.
    pub(super) fn arm_window_wake(&self, cap: usize) {
        let cap = self.window_limit(cap);
        let advertised_span = self.rcv_edge.offset_from(self.rcv_nxt);
        let level = (advertised_span < cap / 2).then(|| {
            let threshold = (cap / 2).min(self.our_mss);
            cap - advertised_span - threshold
        });
        self.shared.wake_when_queued_at_most(level);
    }

    /// SACK blocks for the out-of-order data held: the block holding the
    /// latest arrival first (RFC 2018 section 4), then the others in order.
    fn sack_blocks(&self) -> SackBlocks {
        let mut blocks = SackBlocks::default();
        if !self.sack_ok || self.out_of_order.is_empty() {
            return blocks;
        }
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for (offset, held) in &self.out_of_order {
            let end = *offset + held.len() as u64;
            match ranges.last_mut() {
                Some(last) if last.1 >= *offset => last.1 = last.1.max(end),
                _ => ranges.push((*offset, end)),
            }
        }
        let to_seq = |offset: u64| self.rcv_nxt.add((offset - self.rcv_offset) as usize);
        let latest = self.last_out_of_order;
        if let Some(position) = latest.and_then(|at| {
            ranges
                .iter()
                .position(|(start, end)| *start <= at && at < *end)
        }) {
            let (start, end) = ranges.remove(position);
            blocks.push(to_seq(start), to_seq(end));
        }
        for (start, end) in ranges {
            if !blocks.push(to_seq(start), to_seq(end)) {
                break;
            }
        }
        blocks
    }
}
