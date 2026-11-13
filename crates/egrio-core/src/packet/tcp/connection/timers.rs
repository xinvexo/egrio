//! The connection's timers: which is next, and what each does when it runs
//! out -- retransmission, the loss probe and RACK's reordering timer, the
//! persist and keep-alive probes, TIME-WAIT.

use super::*;

impl Connection {
    /// The earliest timer. Every deadline lies past the run of
    /// `on_timer` that handles it, so a timer never fires twice at once.
    pub(in crate::packet::tcp) fn next_timer(&self) -> Option<Instant> {
        if self.state == State::Closed || self.reset_due {
            return None;
        }
        let paced = self.paced.then(|| {
            self.pace_next
                .checked_sub(self.pace_slack)
                .unwrap_or(self.pace_next)
        });
        let mut next = [
            self.retransmit_at,
            self.probe_at,
            self.reorder_at,
            paced,
            self.persist_at,
            self.time_wait_until,
            self.sws_override_at,
        ]
        .into_iter()
        .flatten()
        .min();
        if !matches!(
            self.state,
            State::SynSent | State::SynReceived | State::TimeWait
        ) {
            // Unacknowledged data leaves liveness to the retransmission
            // timer; an idle flow is probed and, unanswered, aborted.
            let dead = self.last_rx + KEEPALIVE_IDLE + TIMEOUT;
            let keepalive = if !self.board.is_empty() {
                dead
            } else {
                self.next_keepalive.min(dead)
            };
            next = Some(next.map_or(keepalive, |at| at.min(keepalive)));
        }
        next
    }

    pub(in crate::packet::tcp) fn on_timer(&mut self, now: Instant) {
        if let Some(until) = self.time_wait_until {
            if now >= until {
                self.close(false);
            }
            return;
        }
        if self.reorder_at.is_some_and(|at| now >= at) {
            self.reorder_at = None;
            self.on_reorder_timeout(now);
        }
        if self.probe_at.is_some_and(|at| now >= at) {
            // A probe goes out on the next pass; the retransmission timeout
            // stays the last resort (RFC 8985 section 7.3).
            self.probe_at = None;
            self.loss_probe_due = true;
            self.retransmit_at = Some(now + self.rto);
        }
        if self.retransmit_at.is_some_and(|at| now >= at) {
            self.on_retransmit_timeout(now);
            if self.state == State::Closed || self.reset_due {
                return;
            }
        }
        if self.paced && now + self.pace_slack >= self.pace_next {
            self.paced = false;
        }
        if self.sws_override_at.is_some_and(|at| now >= at) {
            self.sws_override_at = None;
            self.sws_override_due = true;
        }
        if self.persist_at.is_some_and(|at| now >= at) {
            self.probe_due = true;
            self.persist_backoff = (self.persist_backoff + 1).min(16);
            self.persist_at = Some(now + self.backoff(self.persist_backoff));
        }
        if !matches!(
            self.state,
            State::SynSent | State::SynReceived | State::Closed
        ) {
            if now.duration_since(self.last_rx) >= KEEPALIVE_IDLE + TIMEOUT {
                self.reset_due = true;
                return;
            }
            if now >= self.next_keepalive && self.board.is_empty() {
                self.probe_due = true;
                self.next_keepalive = keepalive_deadline(now);
            }
        }
    }

    fn on_retransmit_timeout(&mut self, now: Instant) {
        self.retransmit_at = None;
        self.rtt_sample = None;
        if matches!(self.state, State::SynSent | State::SynReceived) {
            if self.retransmits >= HANDSHAKE_RETRIES {
                self.close(true);
                return;
            }
            self.retransmits += 1;
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.handshake_due = true;
            return;
        }
        if self.board.is_empty() {
            return;
        }
        if now.duration_since(self.last_progress) >= TIMEOUT {
            self.reset_due = true;
            return;
        }
        // The first segment, and every one sent a round trip and a
        // reordering window ago, is lost (RFC 8985 section 6.3).
        let reo_wnd = self.rack.reo_wnd(&Window {
            recovering: true,
            sacked: 0,
            dsack: false,
            recovery_ended: false,
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            srtt: self.srtt,
        });
        let rack = &self.rack;
        self.board
            .on_timeout(|segment| rack.expired(segment, reo_wnd, now));
        self.cc.on_timeout(self.retransmits == 0);
        self.recovery = Recovery::Timeout {
            point: self.snd_nxt,
        };
        self.rack.reset_probe();
        self.probe_at = None;
        self.reorder_at = None;
        self.loss_probe_due = false;
        self.dupacks = 0;
        self.pace_next = now;
        self.paced = false;
        self.size_send_buffer();
        self.retransmits += 1;
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.retransmit_at = Some(now + self.rto);
    }

    /// RACK's reordering timer: the segments that waited out the window are
    /// lost, whether or not another ACK came (RFC 8985 section 6.2).
    fn on_reorder_timeout(&mut self, now: Instant) {
        if self.board.is_empty() || !self.sack_ok {
            return;
        }
        let reo_wnd = self.rack.reo_wnd(&Window {
            recovering: !matches!(self.recovery, Recovery::Open),
            sacked: self.board.sacked_segments(self.send_mss),
            dsack: false,
            recovery_ended: false,
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            srtt: self.srtt,
        });
        let (marked, reorder_at) = self.rack.detect(&mut self.board, reo_wnd, now);
        self.reorder_at = reorder_at;
        self.after_losses(marked, 0);
    }

    pub(super) fn backoff(&self, exponent: u32) -> Duration {
        self.rto
            .checked_mul(1 << exponent.min(16))
            .unwrap_or(MAX_RTO)
            .min(MAX_RTO)
    }

    /// The handshake's RTT sample, from our SYN or SYN|ACK sent once.
    pub(super) fn sample_rtt(&mut self, ack: Seq, now: Instant) {
        let Some((seq, sent)) = self.rtt_sample else {
            return;
        };
        if !ack.is_after(seq) {
            return;
        }
        self.rtt_sample = None;
        let rtt = now.duration_since(sent);
        self.rack.handshake(rtt, now);
        self.measure_rtt(rtt);
    }

    /// RFC 6298 sections 2.2 and 2.3.
    pub(super) fn measure_rtt(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + delta) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    pub(super) fn computed_rto(&self) -> Duration {
        match self.srtt {
            None => INITIAL_RTO,
            Some(srtt) => (srtt + (self.rttvar * 4).max(CLOCK_GRANULARITY)).clamp(MIN_RTO, MAX_RTO),
        }
    }
}
