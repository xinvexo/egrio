//! Arriving segments (RFC 9293 section 3.10.7.4): the handshake's replies,
//! acceptability and the RFC 5961 checks, what an acknowledgement says about
//! the data in flight, the payload and the FIN a segment carries, and the
//! ends of a connection.

use super::*;

impl Connection {
    pub(in crate::packet::tcp) fn on_segment(
        &mut self,
        seg: &Received,
        packet: &Bytes,
        cap: usize,
        now: Instant,
    ) {
        match self.state {
            State::Closed => {}
            State::SynSent => self.on_segment_syn_sent(seg, now),
            State::SynReceived => self.on_segment_syn_received(seg, packet, cap, now),
            _ => self.on_segment_synchronized(seg, packet, now),
        }
    }

    /// RFC 9293 section 3.10.7.3. A SYN without an ACK (a simultaneous open)
    /// is not taken; neither is data on the SYN|ACK, which only TCP Fast Open
    /// sends.
    fn on_segment_syn_sent(&mut self, seg: &Received, now: Instant) {
        let acceptable =
            seg.has(ACK) && seg.ack.is_after(self.iss) && !seg.ack.is_after(self.snd_nxt);
        if seg.has(ACK) && !acceptable {
            if !seg.has(RST) {
                self.reply_reset = Some(seg.ack);
            }
            return;
        }
        if seg.has(RST) {
            // The peer refused the connection.
            if acceptable {
                self.close(true);
            }
            return;
        }
        if !seg.has(SYN) || !seg.has(ACK) {
            return;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.add(1);
        // The SYN offered its window unscaled.
        self.rcv_edge = self.rcv_nxt.add(usize::from(self.last_window));
        match seg.options.window_scale {
            Some(shift) => self.snd_shift = shift,
            None => self.rcv_shift = 0,
        }
        self.sack_ok = seg.options.sack_permitted;
        let default_peer_mss = if self.local.is_ipv4() {
            DEFAULT_MSS_V4
        } else {
            DEFAULT_MSS_V6
        };
        self.send_mss = seg
            .options
            .mss
            .map_or(default_peer_mss, usize::from)
            .min(self.path_mss)
            .max(DEFAULT_MSS_V4 / 2);
        self.cc.start(self.send_mss, self.retransmits > 0);
        self.state = State::Established;
        self.snd_una = seg.ack;
        self.handshake_due = false;
        self.sample_rtt(seg.ack, now);
        self.retransmits = 0;
        self.rto = self.computed_rto();
        self.retransmit_at = None;
        self.last_progress = now;
        self.last_rx = now;
        self.next_keepalive = keepalive_deadline(now);
        // The window of a SYN is never scaled (RFC 7323 section 2.2).
        self.snd_wnd = usize::from(seg.window);
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.max_snd_wnd = self.snd_wnd;
        self.size_send_buffer();
        self.ack_pending = true;
        self.shared.establish();
    }

    fn on_segment_syn_received(
        &mut self,
        seg: &Received,
        packet: &Bytes,
        cap: usize,
        now: Instant,
    ) {
        if seg.has(RST) {
            if seg.acceptable(self.rcv_nxt, self.rcv_edge) {
                self.close(true);
            }
            return;
        }
        if seg.has(SYN) {
            // The client's SYN again: our SYN|ACK went missing.
            if seg.seq == self.irs && !seg.has(ACK) {
                self.handshake_due = true;
            }
            return;
        }
        if !seg.has(ACK) {
            return;
        }
        if seg.ack != self.iss.add(1) {
            self.reply_reset = Some(seg.ack);
            return;
        }
        self.cc.start(self.send_mss, self.retransmits > 0);
        self.state = State::Established;
        self.snd_una = seg.ack;
        if self.snd_nxt.is_before(seg.ack) {
            self.snd_nxt = seg.ack;
        }
        self.handshake_due = false;
        self.sample_rtt(seg.ack, now);
        self.retransmits = 0;
        self.rto = self.computed_rto();
        self.retransmit_at = None;
        self.last_progress = now;
        self.snd_wnd = usize::from(seg.window) << self.snd_shift;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.max_snd_wnd = self.snd_wnd;
        // The SYN|ACK offered at most 65 535 unscaled bytes; offer the scaled
        // window at once so an upload need not wait for the first ACK.
        if self.window_update_worthwhile(cap) {
            self.ack_pending = true;
        }
        // The handshake's ACK may carry data or a FIN.
        self.on_segment_synchronized(seg, packet, now);
    }

    fn on_segment_synchronized(&mut self, seg: &Received, packet: &Bytes, now: Instant) {
        if !seg.acceptable(self.rcv_nxt, self.rcv_edge) {
            if !seg.has(RST) {
                self.ack_pending = true;
                if self.state == State::TimeWait && seg.has(FIN) {
                    // The client did not hear our ACK of its FIN.
                    self.time_wait_until = Some(now + TIME_WAIT);
                }
            }
            return;
        }
        self.last_rx = now;
        self.next_keepalive = keepalive_deadline(now);
        if seg.has(RST) {
            // RFC 5961 section 3.2: only an RST at exactly RCV.NXT resets;
            // one elsewhere in the window draws a challenge ACK, which a
            // client that really reset answers with an exact RST.
            if seg.seq == self.rcv_nxt {
                self.close(true);
            } else {
                self.ack_pending = true;
            }
            return;
        }
        if seg.has(SYN) {
            // A SYN in a synchronized state draws a challenge ACK (RFC 5961
            // section 4.2); a client that lost the connection answers it with
            // an RST and then retries.
            self.ack_pending = true;
            return;
        }
        if !seg.has(ACK) {
            return;
        }
        if !self.on_ack(seg, now) || self.state == State::Closed {
            return;
        }
        if seg.payload_len() > 0 && self.state.receives_data() {
            if self.relay_gone {
                // RFC 1122 section 4.2.2.13: data after the application
                // closed is lost; say so.
                self.reset_due = true;
                return;
            }
            self.receive_payload(seg, packet, now);
        }
        if seg.has(FIN) && self.state.receives_data() {
            self.receive_fin(seg, now);
        }
    }

    /// Returns false when the segment must go no further.
    fn on_ack(&mut self, seg: &Received, now: Instant) -> bool {
        let ack = seg.ack;
        // RFC 5961 section 5.2: an ACK beyond what was sent, or older than
        // the largest window the client ever offered, is dropped and answered.
        if ack.is_after(self.snd_nxt) || ack.is_before(self.snd_una.sub(self.max_snd_wnd)) {
            self.ack_pending = true;
            return false;
        }
        let window = usize::from(seg.window) << self.snd_shift;
        let previous_window = self.snd_wnd;
        if !ack.is_before(self.snd_una)
            && (self.snd_wl1.is_before(seg.seq)
                || (self.snd_wl1 == seg.seq && !self.snd_wl2.is_after(ack)))
        {
            let reopened = self.snd_wnd == 0 && window > 0;
            self.snd_wnd = window;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
            self.max_snd_wnd = self.max_snd_wnd.max(window);
            if reopened {
                self.persist_at = None;
                self.persist_backoff = 0;
            }
        }
        // A duplicate ACK (RFC 5681 section 2).
        let duplicate = ack == self.snd_una
            && !self.board.is_empty()
            && seg.payload_len() == 0
            && !seg.has(SYN | FIN)
            && window == previous_window;
        self.take_acknowledgement(seg, duplicate, now);
        self.size_send_buffer();
        true
    }

    /// Sizes the relay's send buffer from what may be in flight: twice the
    /// smaller of the client's window and the congestion window, so the next
    /// window's bytes wait queued while the current window's are being
    /// acknowledged (send-buffer autotuning). Coarse steps keep it from
    /// moving on every ACK.
    ///
    /// A flow holding none of the relay's bytes holds none of the budget:
    /// its relay may still write one chunk, as any relay with nothing held
    /// may, and the buffer is sized again once the engine takes it. While
    /// every open flow held its floor, 32 quiet connections took the whole
    /// budget, and each flow after them wrote one chunk and then waited for
    /// the client to acknowledge all of it before the next.
    pub(super) fn size_send_buffer(&mut self) {
        const STEP: usize = 256 * 1024;
        let limit = if self.sendq_len == 0 {
            0
        } else {
            let in_flight = self.snd_wnd.min(self.cc.cwnd());
            // The floor applies within the engine's grant and not past it: a
            // floor under every flow's share promises more than the budget as
            // soon as enough flows reach it, as the receive side's did.
            ((2 * in_flight).div_ceil(STEP) * STEP)
                .clamp(MIN_SEND_BUFFER, self.send_max)
                .min(self.send_cap)
        };
        if limit != self.send_limit {
            self.send_limit = limit;
            self.shared.set_send_limit(limit);
        }
        // The scoreboard's records follow the same demand: what the limit
        // needs now is what it keeps room for.
        self.board.trim(limit.div_ceil(self.send_mss.max(1)));
    }

    /// Takes the engine's grant and resizes the send buffer under it. The
    /// relay's bytes arriving in an empty queue resize it as well, since an
    /// empty flow holds none; acknowledgements resize it as they arrive.
    pub(in crate::packet::tcp) fn grant_send(&mut self, cap: usize) {
        if cap == self.send_cap && (self.sendq_len == 0) == (self.send_limit == 0) {
            return;
        }
        self.send_cap = cap;
        self.size_send_buffer();
    }

    /// What this flow holds of the engine's send budget.
    pub(in crate::packet::tcp) fn send_granted(&self) -> usize {
        self.send_limit
    }

    /// What an ACK says about the data in flight (RFC 6675 section 5, RFC
    /// 8985 section 6.2): the cumulative point and the SACK blocks mark
    /// segments delivered, RACK finds the ones lost, recovery begins or
    /// ends, and the congestion window follows.
    fn take_acknowledgement(&mut self, seg: &Received, duplicate: bool, now: Instant) {
        let ack = seg.ack;
        let prior_una = self.snd_una;
        let prior_sacked = self.board.sacked();
        let mut rtt = None;
        let rack = &mut self.rack;
        let mut delivered_segment = |segment: &Sent| {
            if let Some(sample) = rack.delivered(segment, now) {
                rtt = Some(sample);
            }
        };
        if ack.is_after(self.snd_una) {
            self.board.acknowledge(ack, &mut delivered_segment);
        }
        let (dsack, blocks) = if self.sack_ok {
            Self::split_dsack(seg.options.sack.as_slice(), ack)
        } else {
            (None, &[][..])
        };
        self.board.select(blocks, &mut delivered_segment);
        if let Some(sample) = rtt {
            self.measure_rtt(sample);
        }
        if ack.is_after(self.snd_una) {
            self.acknowledge(ack, now);
        }
        let mut delivered = (self.snd_una.offset_from(prior_una) + self.board.sacked())
            .saturating_sub(prior_sacked);
        if duplicate && seg.options.sack.is_empty() {
            // Without SACK a duplicate ACK stands for a segment that left the
            // network (RFC 6937 section 2).
            delivered += self.send_mss;
        }
        let mut recovery_ended = false;
        if let Recovery::Fast { point, .. } | Recovery::Timeout { point } = self.recovery {
            if !self.snd_una.is_before(point) {
                if matches!(self.recovery, Recovery::Fast { .. }) {
                    self.cc.end_recovery();
                }
                self.recovery = Recovery::Open;
                recovery_ended = true;
            }
        }
        let mut newly_lost = false;
        if self.sack_ok {
            let reo_wnd = self.rack.reo_wnd(&Window {
                recovering: !matches!(self.recovery, Recovery::Open),
                sacked: self.board.sacked_segments(self.send_mss),
                dsack: dsack.is_some(),
                recovery_ended,
                snd_una: self.snd_una,
                snd_nxt: self.snd_nxt,
                srtt: self.srtt,
            });
            let (marked, reorder_at) = self.rack.detect(&mut self.board, reo_wnd, now);
            self.reorder_at = reorder_at;
            newly_lost = marked;
        }
        // From a peer that sends no SACK blocks, duplicates and partial
        // acknowledgements show losses (RFC 5681 section 3.2, RFC 6582
        // section 3.2).
        self.sacks_seen |= !seg.options.sack.is_empty();
        if !self.sacks_seen {
            if duplicate {
                self.dupacks += 1;
                if self.dupacks == DUPTHRESH as u32 {
                    newly_lost |= self.board.mark_first_lost();
                }
            } else if self.snd_una.is_after(prior_una)
                && matches!(self.recovery, Recovery::Fast { .. })
            {
                newly_lost |= self.board.mark_first_lost();
            }
        }
        let dupack_without_sack = duplicate && seg.options.sack.is_empty();
        if self.rack.probe_repaired(ack, dsack, dupack_without_sack)
            && matches!(self.recovery, Recovery::Open)
        {
            // A probe repaired the only loss of the flight: the window answers
            // it as fast recovery would (RFC 8985 section 7.4.2).
            self.cc.on_congestion();
            self.cc.end_recovery();
        }
        self.after_losses(newly_lost, delivered);
        if !matches!(self.recovery, Recovery::Fast { .. }) && delivered > 0 {
            let cwnd_limited = self.is_cwnd_limited();
            self.cc.on_ack(&Acked {
                bytes: delivered,
                ack,
                snd_nxt: self.snd_nxt,
                rtt,
                srtt: self.srtt,
                cwnd_limited,
                now,
            });
        }
        self.arm_after_ack(prior_una, now);
    }

    /// The SACK blocks of an ACK apart from a first block that reports a
    /// duplicate (DSACK, RFC 2883 section 4): below the cumulative
    /// acknowledgement, or inside the second block.
    fn split_dsack(blocks: &[(Seq, Seq)], ack: Seq) -> (Option<(Seq, Seq)>, &[(Seq, Seq)]) {
        let Some(&(left, right)) = blocks.first() else {
            return (None, blocks);
        };
        let below = !right.is_after(ack);
        let inside = blocks.get(1).is_some_and(|&(outer_left, outer_right)| {
            !left.is_before(outer_left) && !right.is_after(outer_right)
        });
        if below || inside {
            (Some((left, right)), &blocks[1..])
        } else {
            (None, blocks)
        }
    }

    /// Moves SND.UNA to `ack`: the relay's bytes it covers leave the send
    /// queue, and a FIN it covers moves the state.
    fn acknowledge(&mut self, ack: Seq, now: Instant) {
        let acked = ack.offset_from(self.snd_una);
        let fin_acked = self.fin_sent && ack == self.snd_una.add(self.sendq_len).add(1);
        let data = acked.min(self.sendq_len);
        self.drop_acknowledged(data);
        self.shared.acknowledged(data);
        self.snd_una = ack;
        self.retransmits = 0;
        self.rto = self.computed_rto();
        self.last_progress = now;
        self.dupacks = 0;
        if fin_acked {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
                State::Closing => self.enter_time_wait(now),
                State::LastAck => self.close(false),
                _ => {}
            }
        }
    }

    /// The response to losses an ACK or the reordering timer found: fast
    /// recovery begins if no recovery is under way, the window reducing,
    /// and during fast recovery the window follows Proportional Rate
    /// Reduction with the slow start reduction bound (RFC 6937 section 3).
    pub(super) fn after_losses(&mut self, newly_lost: bool, delivered: usize) {
        if newly_lost && matches!(self.recovery, Recovery::Open) {
            self.cc.on_congestion();
            self.rack.reset_probe();
            self.probe_at = None;
            self.loss_probe_due = false;
            self.recovery = Recovery::Fast {
                point: self.snd_nxt,
                delivered: 0,
                sent: 0,
                flight: self.snd_nxt.offset_from(self.snd_una),
            };
        }
        let pipe = self.board.pipe();
        let ssthresh = self.cc.ssthresh();
        let mss = self.send_mss;
        let Recovery::Fast {
            delivered: total,
            sent,
            flight,
            ..
        } = &mut self.recovery
        else {
            return;
        };
        *total += delivered;
        let sndcnt = if pipe > ssthresh {
            let share = (*total as u128 * ssthresh as u128).div_ceil((*flight).max(1) as u128);
            (share as usize).saturating_sub(*sent)
        } else {
            let limit = total.saturating_sub(*sent).max(delivered) + mss;
            (ssthresh - pipe).min(limit)
        };
        // A loss just found may always go out again.
        let sndcnt = if newly_lost { sndcnt.max(mss) } else { sndcnt };
        self.cc.set_cwnd(pipe + sndcnt);
    }

    /// The loss timers after an ACK: none with nothing in flight; else the
    /// retransmission timeout restarts when the ACK acknowledged new data
    /// (RFC 6298 section 5.3), and so does the loss probe where it may run.
    fn arm_after_ack(&mut self, prior_una: Seq, now: Instant) {
        if self.board.is_empty() {
            self.retransmit_at = None;
            self.probe_at = None;
            self.reorder_at = None;
            return;
        }
        if self.snd_una.is_after(prior_una) || self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
            self.schedule_probe(now);
        } else if self.board.sacked() > 0 || self.reorder_at.is_some() {
            // SACKed data and RACK's reordering timer take over from the
            // probe (RFC 8985 section 7.2).
            self.probe_at = None;
        }
    }

    fn drop_acknowledged(&mut self, bytes: usize) {
        self.sendq_len -= bytes;
        let mut left = bytes;
        let mut popped = 0;
        let mut trimmed = 0;
        while left > 0 {
            let front = self
                .sendq
                .front_mut()
                .expect("acknowledged bytes are queued");
            if front.len() <= left {
                left -= front.len();
                self.sendq.pop_front();
                popped += 1;
            } else {
                let _ = front.split_to(left);
                trimmed = left;
                left = 0;
            }
        }
        self.cursor.rebase(bytes, popped, trimmed);
        debug_assert!(self.cursor.is_stale() || self.cursor == self.seek(self.cursor.offset));
    }

    fn receive_payload(&mut self, seg: &Received, packet: &Bytes, now: Instant) {
        let mut start = seg.seq;
        let mut data = packet.slice(seg.payload.clone());
        let behind = self.rcv_nxt.since(start);
        if behind > 0 {
            let behind = behind as usize;
            if behind >= data.len() {
                self.ack_pending = true;
                return;
            }
            data = data.slice(behind..);
            start = self.rcv_nxt;
        }
        let room = self.rcv_edge.since(start);
        if room <= 0 {
            self.ack_pending = true;
            return;
        }
        if data.len() > room as usize {
            data.truncate(room as usize);
        }
        self.last_data = now;
        // Every flow with new data is acknowledged once the pump has handled
        // the batch of packets carrying it.
        if start == self.rcv_nxt {
            self.deliver(data);
            self.merge_out_of_order();
            self.ack_pending = true;
        } else {
            let offset = self.rcv_offset + start.offset_from(self.rcv_nxt) as u64;
            self.insert_out_of_order(offset, data);
            self.ack_pending = true;
        }
        if self.fin_offset == Some(self.rcv_offset) {
            self.consume_fin(now);
        }
    }

    fn deliver(&mut self, data: Bytes) {
        let length = data.len();
        if length == 0 {
            return;
        }
        self.shared.deliver(data);
        self.rcv_nxt = self.rcv_nxt.add(length);
        self.rcv_offset += length as u64;
        self.delivered = true;
    }

    /// Keeps the parts of `data` (at stream offset `start`) not already held.
    fn insert_out_of_order(&mut self, start: u64, data: Bytes) {
        let end = start + data.len() as u64;
        self.last_out_of_order = Some(start);
        let mut cursor = start;
        let mut gaps = Vec::new();
        let first = self
            .out_of_order
            .range(..=start)
            .next_back()
            .map(|(offset, held)| (*offset, *offset + held.len() as u64));
        if let Some((_, held_end)) = first {
            cursor = cursor.max(held_end);
        }
        for (offset, held) in self.out_of_order.range(start..end) {
            if cursor >= end {
                break;
            }
            if *offset > cursor {
                gaps.push((cursor, *offset));
            }
            cursor = cursor.max(*offset + held.len() as u64);
        }
        if cursor < end {
            gaps.push((cursor, end));
        }
        for (gap_start, gap_end) in gaps {
            if self.out_of_order.len() >= self.max_out_of_order {
                break;
            }
            let from = (gap_start - start) as usize;
            let to = (gap_end - start) as usize;
            self.out_of_order.insert(gap_start, data.slice(from..to));
        }
    }

    fn merge_out_of_order(&mut self) {
        while let Some(entry) = self.out_of_order.first_entry() {
            let offset = *entry.key();
            if offset > self.rcv_offset {
                break;
            }
            let held = entry.remove();
            let end = offset + held.len() as u64;
            if end > self.rcv_offset {
                let skip = (self.rcv_offset - offset) as usize;
                self.deliver(held.slice(skip..));
            }
        }
        if self.out_of_order.is_empty() {
            self.last_out_of_order = None;
        }
    }

    fn receive_fin(&mut self, seg: &Received, now: Instant) {
        let fin = seg.seq.add(seg.payload_len());
        if fin == self.rcv_nxt {
            self.consume_fin(now);
        } else if fin.is_after(self.rcv_nxt) && !fin.is_after(self.rcv_edge) {
            self.fin_offset = Some(self.rcv_offset + fin.offset_from(self.rcv_nxt) as u64);
            self.ack_pending = true;
        }
    }

    fn consume_fin(&mut self, now: Instant) {
        self.rcv_nxt = self.rcv_nxt.add(1);
        self.fin_offset = None;
        self.shared.finish_recv();
        self.ack_pending = true;
        match self.state {
            State::Established => self.state = State::CloseWait,
            State::FinWait1 => self.state = State::Closing,
            State::FinWait2 => self.enter_time_wait(now),
            _ => {}
        }
    }

    fn enter_time_wait(&mut self, now: Instant) {
        self.state = State::TimeWait;
        self.time_wait_until = Some(now + TIME_WAIT);
        self.retransmit_at = None;
        self.persist_at = None;
    }

    /// The resets that end this connection for its client when the capture
    /// ends: RST|ACK at SND.UNA, then at SND.NXT when sent data or a FIN is
    /// still unacknowledged. A client stack takes a reset only at one number
    /// and answers others in its window with a challenge ACK (RFC 5961
    /// section 3.2): XNU at the last acknowledgement it sent (`last_ack_sent`,
    /// bsd/netinet/tcp_input.c), SND.UNA here once its acknowledgements
    /// arrived; Linux at RCV.NXT (`tcp_validate_incoming`), SND.NXT here once
    /// the segments sent arrived. The two differ while the client holds back
    /// a delayed acknowledgement.
    pub(in crate::packet::tcp) fn resets(&self) -> Vec<OutSegment> {
        if matches!(self.state, State::SynSent | State::TimeWait | State::Closed) {
            return Vec::new();
        }
        let mut resets = vec![self.control(self.snd_una, Some(self.rcv_nxt), RST | ACK, 0)];
        if self.snd_nxt != self.snd_una {
            resets.push(self.control(self.snd_nxt, Some(self.rcv_nxt), RST | ACK, 0));
        }
        resets
    }

    /// Ends the connection; a reset fails the relay's reads and writes.
    pub(in crate::packet::tcp) fn close(&mut self, reset: bool) {
        self.state = State::Closed;
        self.retransmit_at = None;
        self.persist_at = None;
        self.time_wait_until = None;
        self.ack_pending = false;
        self.probe_due = false;
        self.loss_probe_due = false;
        self.probe_at = None;
        self.reorder_at = None;
        self.handshake_due = false;
        self.shared.close(reset);
    }
}
