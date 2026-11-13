//! RACK-TLP (RFC 8985): loss detection by time. A segment is lost once a
//! segment sent after it has been delivered and a reordering window has
//! passed, so every delivery, a retransmission's included, can reveal the
//! losses before it, however many there are; a tail loss probe draws the
//! feedback that finds a lost tail when no ACK would come before the
//! retransmission timeout.

use std::time::{Duration, Instant};

use super::scoreboard::{Scoreboard, Sent, Verdict};
use super::seq::Seq;

/// RFC 6675's DupThresh, in segments: until reordering is seen, this many
/// SACKed segments start recovery without waiting for the reordering window.
pub(super) const DUPTHRESH: usize = 3;
/// How long a minimum RTT sample stands before a larger one may replace it:
/// a path that grew longer for good is learned within this time.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(300);
/// Loss recoveries a widened reordering window outlasts (RFC 8985 section
/// 6.2, step 4).
const REO_WND_PERSIST: u32 = 16;
/// TLP.max_ack_delay: a receiver may hold the ACK of a lone segment this
/// long; common stacks hold it at most 200 ms (RFC 1122 section 4.2.3.2
/// allows up to 500).
const MAX_ACK_DELAY: Duration = Duration::from_millis(200);
/// The probe timeout without an SRTT (RFC 8985 section 7.2).
const INITIAL_PTO: Duration = Duration::from_secs(1);
/// What a probe waits beyond two round trips for a flight of more than one
/// segment: the pump's timers and the peer's ACK take up to a couple of
/// milliseconds, so on a sub-millisecond path two round trips alone would
/// probe before an ACK could come back.
const PTO_FLOOR: Duration = Duration::from_millis(2);

/// RACK_sent_after: whether `(t1, seq1)` went out after `(t2, seq2)`,
/// sequence numbers breaking ties of equal times.
fn sent_after(t1: Instant, seq1: Seq, t2: Instant, seq2: Seq) -> bool {
    t1 > t2 || (t1 == t2 && seq1.is_after(seq2))
}

#[derive(Debug)]
pub(super) struct Rack {
    /// RACK.xmit_ts and RACK.end_seq: the most recently sent segment that
    /// has been delivered.
    xmit: Option<Instant>,
    end: Seq,
    /// RACK.rtt, of the most recently delivered segment.
    rtt: Duration,
    /// RACK.min_RTT and when it was sampled.
    min_rtt: Option<(Duration, Instant)>,
    /// RACK.fack: the highest sequence number delivered.
    fack: Seq,
    reordering_seen: bool,
    reo_wnd_mult: u32,
    reo_wnd_persist: u32,
    dsack_round: Option<Seq>,
    /// TLP.end_seq and TLP.is_retrans: the probe in flight.
    probe_end: Option<Seq>,
    probe_retransmitted: bool,
    /// An RTT sample came since the last probe (RFC 8985 section 7.3).
    sampled: bool,
}

/// What the reordering window depends on, from the ACK at hand.
pub(super) struct Window {
    pub(super) recovering: bool,
    /// Segments the scoreboard holds SACKed.
    pub(super) sacked: usize,
    pub(super) dsack: bool,
    pub(super) recovery_ended: bool,
    pub(super) snd_una: Seq,
    pub(super) snd_nxt: Seq,
    pub(super) srtt: Option<Duration>,
}

impl Rack {
    pub(super) fn new(iss: Seq) -> Self {
        Self {
            xmit: None,
            end: iss,
            rtt: Duration::ZERO,
            min_rtt: None,
            fack: iss,
            reordering_seen: false,
            reo_wnd_mult: 1,
            reo_wnd_persist: 0,
            dsack_round: None,
            probe_end: None,
            probe_retransmitted: false,
            sampled: true,
        }
    }

    fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.map(|(rtt, _)| rtt)
    }

    /// The handshake's RTT: the first minimum, and the lowest one, from
    /// segments smaller than any data segment, which a short retransmission
    /// would otherwise beat.
    pub(super) fn handshake(&mut self, rtt: Duration, now: Instant) {
        if self.min_rtt.is_none_or(|(min, _)| rtt < min) {
            self.min_rtt = Some((rtt, now));
        }
    }

    /// A segment newly delivered, cumulatively or selectively (RFC 8985
    /// section 6.2, steps 1 to 3). Returns the RTT sample the
    /// retransmission timer may take: only from a segment never
    /// retransmitted (RFC 6298 section 3).
    pub(super) fn delivered(&mut self, segment: &Sent, now: Instant) -> Option<Duration> {
        if segment.end.is_after(self.fack) {
            self.fack = segment.end;
        } else if segment.end.is_before(self.fack) && !segment.retransmitted {
            self.reordering_seen = true;
        }
        let rtt = now.saturating_duration_since(segment.xmit);
        if segment.retransmitted && self.min_rtt().is_some_and(|min| rtt < min) {
            // Acknowledged sooner than any round trip after it went out
            // again: the original arrived, late, so the path reorders, and
            // the time says nothing about the round trip.
            self.reordering_seen = true;
            return None;
        }
        self.rtt = rtt;
        self.sampled = true;
        if self.min_rtt.is_none_or(|(min, at)| {
            rtt <= min || now.saturating_duration_since(at) >= MIN_RTT_WINDOW
        }) {
            self.min_rtt = Some((rtt, now));
        }
        if self
            .xmit
            .is_none_or(|xmit| sent_after(segment.xmit, segment.end, xmit, self.end))
        {
            self.xmit = Some(segment.xmit);
            self.end = segment.end;
        }
        (!segment.retransmitted).then_some(rtt)
    }

    /// RACK.reo_wnd for this ACK (RFC 8985 section 6.2, step 4): zero while
    /// no reordering was seen and recovery is under way or enough is SACKed,
    /// else a quarter of the minimum RTT, widened each round trip that
    /// brought a DSACK, never past SRTT.
    pub(super) fn reo_wnd(&mut self, window: &Window) -> Duration {
        if self
            .dsack_round
            .is_some_and(|round| !window.snd_una.is_before(round))
        {
            self.dsack_round = None;
        }
        if self.dsack_round.is_none() && window.dsack {
            self.dsack_round = Some(window.snd_nxt);
            self.reo_wnd_mult += 1;
            self.reo_wnd_persist = REO_WND_PERSIST;
        } else if window.recovery_ended {
            self.reo_wnd_persist = self.reo_wnd_persist.saturating_sub(1);
            if self.reo_wnd_persist == 0 {
                self.reo_wnd_mult = 1;
            }
        }
        if !self.reordering_seen && (window.recovering || window.sacked >= DUPTHRESH) {
            return Duration::ZERO;
        }
        let quarter = self.min_rtt().unwrap_or_default() / 4;
        let widened = quarter * self.reo_wnd_mult;
        window.srtt.map_or(widened, |srtt| widened.min(srtt))
    }

    /// Marks lost what was sent before the most recently delivered segment
    /// and has waited a round trip and the reordering window (RFC 8985
    /// section 6.2, step 5). Returns whether it marked any, and when the
    /// reordering timer should run again.
    pub(super) fn detect(
        &self,
        board: &mut Scoreboard,
        reo_wnd: Duration,
        now: Instant,
    ) -> (bool, Option<Instant>) {
        let Some(rack_xmit) = self.xmit else {
            return (false, None);
        };
        let rack_end = self.end;
        let wait = self.rtt + reo_wnd;
        board.detect(|segment| {
            if !sent_after(rack_xmit, rack_end, segment.xmit, segment.end) {
                return Verdict::Fine;
            }
            let deadline = segment.xmit + wait;
            if deadline <= now {
                Verdict::Lost
            } else {
                Verdict::LostAt(deadline)
            }
        })
    }

    /// Whether a segment has waited out a round trip and the reordering
    /// window: on a retransmission timeout it counts as lost (RFC 8985
    /// section 6.3).
    pub(super) fn expired(&self, segment: &Sent, reo_wnd: Duration, now: Instant) -> bool {
        segment.xmit + self.rtt + reo_wnd <= now
    }

    /// When a loss probe is due (RFC 8985 section 7.2): two SRTTs, plus the
    /// delayed-ACK allowance for a lone segment or the floor for more,
    /// never later than the retransmission timeout.
    pub(super) fn probe_at(
        &self,
        srtt: Option<Duration>,
        one_segment: bool,
        now: Instant,
        rto_at: Instant,
    ) -> Instant {
        let pto = match srtt {
            Some(srtt) if one_segment => 2 * srtt + MAX_ACK_DELAY,
            Some(srtt) => 2 * srtt + PTO_FLOOR,
            None => INITIAL_PTO,
        };
        (now + pto).min(rto_at)
    }

    /// Whether a probe may go out: none is in flight, and an RTT sample
    /// came since the last one (RFC 8985 section 7.3).
    pub(super) fn may_probe(&self) -> bool {
        self.probe_end.is_none() && self.sampled
    }

    pub(super) fn probed(&mut self, end: Seq, retransmitted: bool) {
        self.probe_end = Some(end);
        self.probe_retransmitted = retransmitted;
        self.sampled = false;
    }

    /// Recovery or a timeout began: no probe episode is under way.
    pub(super) fn reset_probe(&mut self) {
        self.probe_end = None;
        self.probe_retransmitted = false;
    }

    /// Whether this ACK shows that a probe retransmission repaired the only
    /// loss of the flight, which the congestion window must still answer
    /// (RFC 8985 section 7.4.2): the probe's range is acknowledged with
    /// more after it, and no DSACK or duplicate ACK said both copies came.
    pub(super) fn probe_repaired(
        &mut self,
        ack: Seq,
        dsack: Option<(Seq, Seq)>,
        dupack_without_sack: bool,
    ) -> bool {
        let Some(end) = self.probe_end else {
            return false;
        };
        let dsack_of_probe = dsack.is_some_and(|(_, right)| right == end);
        if ack.is_before(end) {
            return false;
        }
        if !self.probe_retransmitted || dsack_of_probe {
            self.probe_end = None;
            return false;
        }
        if ack.is_after(end) {
            self.probe_end = None;
            return true;
        }
        if dupack_without_sack {
            self.probe_end = None;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(sacked: usize) -> Window {
        Window {
            recovering: false,
            sacked,
            dsack: false,
            recovery_ended: false,
            snd_una: Seq(0),
            snd_nxt: Seq(1000),
            srtt: Some(Duration::from_millis(100)),
        }
    }

    /// Ten segments of 100 bytes, sent 1 ms apart from `start`.
    fn sent(start: Instant) -> Scoreboard {
        let mut board = Scoreboard::default();
        for k in 0..10u32 {
            board.sent(
                Seq(k * 100),
                Seq(k * 100 + 100),
                false,
                start + Duration::from_millis(u64::from(k)),
            );
        }
        board
    }

    #[test]
    fn a_later_delivery_marks_what_went_before_it_once_the_window_passed() {
        let start = Instant::now();
        let mut board = sent(start);
        let mut rack = Rack::new(Seq(0));
        // Segments 5..10 arrive, SACKed 100 ms after they went out.
        let now = start + Duration::from_millis(109);
        board.select(&[(Seq(500), Seq(1000))], |segment| {
            rack.delivered(segment, now);
        });
        let reo_wnd = rack.reo_wnd(&window(board.sacked_segments(100)));
        assert_eq!(
            reo_wnd,
            Duration::ZERO,
            "no reordering seen and enough SACKed"
        );
        let (marked, timer) = rack.detect(&mut board, reo_wnd, now);
        assert!(marked && timer.is_none());
        assert_eq!(
            board.pipe(),
            0,
            "segments 0..5 are lost at once, not one a round trip"
        );
    }

    #[test]
    fn reordering_widens_the_window_and_the_timer_waits_it_out() {
        let start = Instant::now();
        let mut board = sent(start);
        let mut rack = Rack::new(Seq(0));
        let now = start + Duration::from_millis(100);
        // Segment 1 arrives before segment 0: a never-retransmitted segment
        // below the highest delivered one shows reordering.
        board.select(&[(Seq(100), Seq(200))], |segment| {
            rack.delivered(segment, now);
        });
        board.acknowledge(Seq(200), |segment| {
            rack.delivered(segment, now);
        });
        assert!(rack.reordering_seen);
        // Segment 9 is SACKed: 2..9 were sent before it, but the window
        // (a quarter of the 99 ms minimum RTT) has not passed for them.
        let later = start + Duration::from_millis(108);
        board.select(&[(Seq(900), Seq(1000))], |segment| {
            rack.delivered(segment, later);
        });
        let reo_wnd = rack.reo_wnd(&window(board.sacked_segments(100)));
        assert_eq!(reo_wnd, Duration::from_micros(24_750));
        let (marked, timer) = rack.detect(&mut board, reo_wnd, later);
        assert!(!marked);
        // Segment 2 went out at 2 ms: lost at 2 + 99 + 24.75 ms.
        assert_eq!(timer, Some(start + Duration::from_micros(125_750)));
    }

    #[test]
    fn a_dsack_widens_the_window_for_sixteen_recoveries() {
        let mut rack = Rack::new(Seq(0));
        rack.reordering_seen = true;
        rack.min_rtt = Some((Duration::from_millis(80), Instant::now()));
        let base = rack.reo_wnd(&window(0));
        assert_eq!(base, Duration::from_millis(20));
        let widened = rack.reo_wnd(&Window {
            dsack: true,
            ..window(0)
        });
        assert_eq!(widened, Duration::from_millis(40));
        for _ in 0..15 {
            rack.reo_wnd(&Window {
                recovery_ended: true,
                snd_una: Seq(2000),
                ..window(0)
            });
            assert_eq!(rack.reo_wnd_mult, 2);
        }
        rack.reo_wnd(&Window {
            recovery_ended: true,
            snd_una: Seq(2000),
            ..window(0)
        });
        assert_eq!(rack.reo_wnd_mult, 1);
    }

    #[test]
    fn a_probe_that_repaired_the_tail_calls_for_a_congestion_response() {
        let mut rack = Rack::new(Seq(0));
        assert!(rack.may_probe());
        rack.probed(Seq(1000), true);
        assert!(!rack.may_probe(), "one probe in flight at a time");
        assert!(
            !rack.probe_repaired(Seq(1000), None, false),
            "not yet past the probe"
        );
        assert!(rack.probe_repaired(Seq(1500), None, false));
        // Both copies arrived: a DSACK says so, no response.
        rack.sampled = true;
        rack.probed(Seq(2000), true);
        assert!(!rack.probe_repaired(Seq(2000), Some((Seq(1900), Seq(2000))), false));
        assert!(rack.probe_end.is_none());
        assert!(
            !rack.may_probe(),
            "not before an RTT sample since the probe"
        );
    }

    #[test]
    fn the_probe_timeout_is_two_round_trips_capped_by_the_retransmission_timeout() {
        let rack = Rack::new(Seq(0));
        let now = Instant::now();
        let srtt = Some(Duration::from_millis(50));
        let rto_at = now + Duration::from_secs(1);
        assert_eq!(
            rack.probe_at(srtt, false, now, rto_at),
            now + Duration::from_millis(102)
        );
        assert_eq!(
            rack.probe_at(srtt, true, now, rto_at),
            now + Duration::from_millis(300)
        );
        assert_eq!(rack.probe_at(None, false, now, rto_at), rto_at);
        assert_eq!(
            rack.probe_at(srtt, true, now, now + Duration::from_millis(250)),
            now + Duration::from_millis(250)
        );
    }
}
