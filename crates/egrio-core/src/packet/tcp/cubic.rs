//! The congestion window of the engine's flows and the pacing rate it
//! implies: CUBIC (RFC 9438) in congestion avoidance, HyStart++ (RFC 9406)
//! in the first slow start, the multiplicative decrease on a congestion
//! event and the loss window after a retransmission timeout. Loss detection
//! decides when a congestion event happens, and during fast recovery the
//! window follows Proportional Rate Reduction (`connection/receive.rs`); this
//! module decides the window outside recovery and the threshold recovery
//! reduces to.

use std::time::{Duration, Instant};

use super::seq::Seq;

/// β_cubic (RFC 9438 section 4.6).
const BETA: f64 = 0.7;
/// C, in segments per second cubed (RFC 9438 section 5).
const C: f64 = 0.4;
/// α_cubic until W_est reaches cwnd_prior (RFC 9438 section 4.3).
const ALPHA: f64 = 3.0 * (1.0 - BETA) / (1.0 + BETA);
/// The window the flow may keep through a congestion event never falls
/// below two segments (RFC 9438 figure 5).
const MIN_SEGMENTS: usize = 2;

// HyStart++ (RFC 9406 section 4.3).
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);
const MAX_RTT_THRESH: Duration = Duration::from_millis(16);
const MIN_RTT_DIVISOR: u32 = 8;
const N_RTT_SAMPLE: u32 = 8;
const CSS_GROWTH_DIVISOR: usize = 4;
const CSS_ROUNDS: u32 = 5;

/// Pacing above cwnd/SRTT: in slow start the window doubles each round
/// trip, so the pace leaves room for that; in congestion avoidance a little
/// headroom keeps the pace from holding the window back.
const SLOW_START_PACING: f64 = 2.0;
const AVOIDANCE_PACING: f64 = 1.2;
/// The cap on the window: TCP cannot advertise more (RFC 7323 section 2.3),
/// and more than half the sequence space would wrap sequence arithmetic.
pub(super) const MAX_WINDOW: usize = 1 << 30;

/// RFC 6928's initial window for a sender MSS: ten segments of up to 1460
/// bytes, fewer larger ones. A request of up to ten segments goes out in
/// the first round trip, where RFC 5681's three or four took two or three.
pub(super) fn initial_window(mss: usize) -> usize {
    (10 * mss).min((2 * mss).max(14_600))
}

#[derive(Debug)]
pub(super) struct Cubic {
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    /// W_max and cwnd_prior, in bytes (RFC 9438 section 4.1.2).
    w_max: f64,
    cwnd_prior: f64,
    /// The congestion avoidance stage under way.
    epoch: Option<Epoch>,
    /// The next stage begins without a W_max to return to (after a
    /// timeout, or after HyStart++ left slow start without a loss): K is 0
    /// and W_max is the window the stage begins with (RFC 9438 sections 4.8
    /// and 4.10).
    no_w_max: bool,
    /// HyStart++ while the first slow start lasts.
    hystart: Option<HyStart>,
}

#[derive(Debug)]
struct Epoch {
    /// t_epoch, moved forward over application-limited stretches so they do
    /// not count (RFC 9438 section 5.8).
    start: Instant,
    /// When the stage last took an acknowledgement.
    last: Instant,
    /// K, in seconds.
    k: f64,
    /// W_est, in bytes.
    w_est: f64,
}

#[derive(Debug)]
struct HyStart {
    /// The round ends when this sequence number is acknowledged.
    window_end: Seq,
    last_round_min: Option<Duration>,
    current_round_min: Option<Duration>,
    samples: u32,
    /// In Conservative Slow Start: the baseline RTT and the rounds run.
    css: Option<(Duration, u32)>,
}

/// What an acknowledgement outside recovery tells the controller.
pub(super) struct Acked {
    /// Bytes newly acknowledged, cumulatively or selectively.
    pub(super) bytes: usize,
    /// The cumulative acknowledgement and the next sequence number to send,
    /// which bound HyStart++'s rounds.
    pub(super) ack: Seq,
    pub(super) snd_nxt: Seq,
    /// This acknowledgement's RTT sample, if it gave one.
    pub(super) rtt: Option<Duration>,
    pub(super) srtt: Option<Duration>,
    /// Whether the window limited what was sent (RFC 9438 section 5.8):
    /// an application-limited flow does not grow its window.
    pub(super) cwnd_limited: bool,
    pub(super) now: Instant,
}

impl Cubic {
    pub(super) fn new(mss: usize, snd_nxt: Seq) -> Self {
        Self {
            mss,
            cwnd: initial_window(mss),
            ssthresh: usize::MAX,
            w_max: 0.0,
            cwnd_prior: 0.0,
            epoch: None,
            no_w_max: true,
            hystart: Some(HyStart {
                window_end: snd_nxt,
                last_round_min: None,
                current_round_min: None,
                samples: 0,
                css: None,
            }),
        }
    }

    pub(super) fn cwnd(&self) -> usize {
        self.cwnd
    }

    pub(super) fn ssthresh(&self) -> usize {
        self.ssthresh
    }

    pub(super) fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// The send MSS the handshake settled, with the initial window for it:
    /// one segment when the handshake had to send its SYN or SYN|ACK again
    /// (RFC 6928 section 2).
    pub(super) fn start(&mut self, mss: usize, handshake_resent: bool) {
        self.mss = mss;
        self.cwnd = if handshake_resent {
            mss
        } else {
            initial_window(mss)
        };
    }

    /// The window during fast recovery, which recovery decides.
    pub(super) fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd.clamp(1, MAX_WINDOW);
    }

    /// The restart window after an idle period (RFC 5681 section 4.1).
    pub(super) fn restart_after_idle(&mut self) {
        self.cwnd = self.cwnd.min(initial_window(self.mss));
        self.epoch = None;
    }

    /// An acknowledgement of new data outside fast recovery.
    pub(super) fn on_ack(&mut self, acked: &Acked) {
        if acked.bytes == 0 {
            return;
        }
        if self.in_slow_start() {
            self.slow_start(acked);
        } else {
            self.avoid(acked);
        }
        self.cwnd = self.cwnd.min(MAX_WINDOW);
    }

    fn slow_start(&mut self, acked: &Acked) {
        if !acked.cwnd_limited {
            return;
        }
        let Some(hystart) = self.hystart.as_mut() else {
            // Slow start after a timeout: RFC 5681 section 3.1, counting
            // acknowledged bytes up to two segments an ACK (RFC 3465).
            self.cwnd += acked.bytes.min(2 * self.mss);
            return;
        };
        if !acked.ack.is_before(hystart.window_end) {
            // A round ended (RFC 9406 section 4.2).
            hystart.window_end = acked.snd_nxt;
            hystart.last_round_min = hystart.current_round_min.take();
            hystart.samples = 0;
            if let Some((_, rounds)) = hystart.css.as_mut() {
                *rounds += 1;
                if *rounds >= CSS_ROUNDS {
                    self.leave_slow_start();
                    return;
                }
            }
        }
        if let Some(rtt) = acked.rtt {
            hystart.current_round_min =
                Some(hystart.current_round_min.map_or(rtt, |min| min.min(rtt)));
            hystart.samples += 1;
        }
        // Paced, so no limit on the bytes one ACK applies (L is infinity).
        match hystart.css {
            Some(_) => self.cwnd += acked.bytes / CSS_GROWTH_DIVISOR,
            None => self.cwnd += acked.bytes,
        }
        let (Some(current), Some(last)) = (hystart.current_round_min, hystart.last_round_min)
        else {
            return;
        };
        if hystart.samples < N_RTT_SAMPLE {
            return;
        }
        match hystart.css {
            None => {
                let threshold = (last / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESH, MAX_RTT_THRESH);
                if current >= last + threshold {
                    // The queue is building: slow start becomes conservative.
                    hystart.css = Some((current, 0));
                }
            }
            Some((baseline, _)) if current < baseline => {
                // The delay rise was spurious: back to slow start.
                hystart.css = None;
            }
            Some(_) => {}
        }
    }

    /// HyStart++ ends slow start without a loss: congestion avoidance from
    /// here, with no W_max to return to.
    fn leave_slow_start(&mut self) {
        self.ssthresh = self.cwnd;
        self.cwnd_prior = self.cwnd as f64;
        self.no_w_max = true;
        self.epoch = None;
        self.hystart = None;
    }

    /// RFC 9438 sections 4.2 to 4.5.
    fn avoid(&mut self, acked: &Acked) {
        let mss = self.mss as f64;
        let cwnd = self.cwnd as f64;
        let now = acked.now;
        let (w_max, no_w_max) = (&mut self.w_max, &mut self.no_w_max);
        let epoch = self.epoch.get_or_insert_with(|| {
            let k = if *no_w_max || *w_max <= cwnd {
                *w_max = cwnd;
                0.0
            } else {
                ((*w_max - cwnd) / mss / C).cbrt()
            };
            *no_w_max = false;
            Epoch {
                start: now,
                last: now,
                k,
                w_est: cwnd,
            }
        });
        if !acked.cwnd_limited {
            // Time the application held the flow back does not count.
            epoch.start += now.saturating_duration_since(epoch.last);
            epoch.last = now;
            return;
        }
        epoch.last = now;
        let w_max = self.w_max;
        let k = epoch.k;
        let w_cubic = |t: f64| C * (t - k).powi(3) * mss + w_max;
        let t = now.saturating_duration_since(epoch.start).as_secs_f64();
        let alpha = if epoch.w_est >= self.cwnd_prior {
            1.0
        } else {
            ALPHA
        };
        epoch.w_est += alpha * mss * acked.bytes as f64 / cwnd;
        if w_cubic(t) < epoch.w_est {
            // The Reno-friendly region (section 4.3).
            self.cwnd = self.cwnd.max(epoch.w_est as usize);
            return;
        }
        let rtt = acked.srtt.unwrap_or_default().as_secs_f64();
        let target = w_cubic(t + rtt).clamp(cwnd, 1.5 * cwnd);
        self.cwnd += ((target - cwnd) * acked.bytes as f64 / cwnd) as usize;
    }

    /// A congestion event detected by loss: W_max with fast convergence
    /// (section 4.7) and the threshold the window reduces to (section 4.6).
    /// The window itself follows recovery from here.
    pub(super) fn on_congestion(&mut self) {
        let cwnd = self.cwnd as f64;
        self.w_max = if cwnd < self.w_max && !self.no_w_max {
            cwnd * (1.0 + BETA) / 2.0
        } else {
            cwnd
        };
        self.no_w_max = false;
        self.cwnd_prior = cwnd;
        self.ssthresh = ((cwnd * BETA).round() as usize).max(MIN_SEGMENTS * self.mss);
        self.epoch = None;
        self.hystart = None;
    }

    /// Fast recovery ended: the window is the threshold it reduced to.
    pub(super) fn end_recovery(&mut self) {
        self.cwnd = self.ssthresh;
        self.epoch = None;
    }

    /// A retransmission timeout: one segment, the threshold from β_cubic
    /// (section 4.8) on the first timeout of an episode only.
    pub(super) fn on_timeout(&mut self, first: bool) {
        if first {
            self.cwnd_prior = self.cwnd as f64;
            self.ssthresh =
                ((self.cwnd as f64 * BETA).round() as usize).max(MIN_SEGMENTS * self.mss);
        }
        self.cwnd = self.mss;
        self.no_w_max = true;
        self.epoch = None;
        self.hystart = None;
    }

    /// The pace at which the window goes out over one SRTT, bytes a second.
    pub(super) fn pacing_rate(&self, srtt: Duration) -> Option<f64> {
        let seconds = srtt.as_secs_f64();
        if seconds <= 0.0 {
            return None;
        }
        let gain = if self.in_slow_start() {
            SLOW_START_PACING
        } else {
            AVOIDANCE_PACING
        };
        Some(gain * self.cwnd as f64 / seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: usize = 1000;

    fn acked(bytes: usize, at: Instant) -> Acked {
        Acked {
            bytes,
            ack: Seq(0),
            snd_nxt: Seq(1),
            rtt: None,
            srtt: Some(Duration::from_millis(100)),
            cwnd_limited: true,
            now: at,
        }
    }

    /// A controller in congestion avoidance after a loss at `cwnd` bytes.
    fn after_loss(cwnd: usize) -> Cubic {
        let mut cubic = Cubic::new(MSS, Seq(0));
        cubic.hystart = None;
        cubic.no_w_max = false;
        cubic.cwnd = cwnd;
        cubic.on_congestion();
        cubic.end_recovery();
        cubic
    }

    #[test]
    fn slow_start_without_loss_stops_at_the_largest_window() {
        let mut cubic = Cubic::new(MSS, Seq(0));
        cubic.cwnd = MAX_WINDOW - MSS;
        cubic.on_ack(&acked(131 * MSS, Instant::now()));
        assert_eq!(cubic.cwnd(), MAX_WINDOW);
    }

    #[test]
    fn a_loss_keeps_seven_tenths_and_regrows_to_the_old_window_in_k() {
        let mut cubic = after_loss(100 * MSS);
        assert_eq!(cubic.ssthresh(), 70 * MSS);
        assert_eq!(cubic.cwnd(), 70 * MSS);
        // K = cbrt(30 segments / 0.4) = 4.22 s.
        let start = Instant::now();
        let mut now = start;
        while now < start + Duration::from_millis(4200) {
            let bytes = cubic.cwnd() / 10;
            cubic.on_ack(&acked(bytes, now));
            now += Duration::from_millis(10);
        }
        let near = cubic.cwnd() as f64 / (100 * MSS) as f64;
        assert!((0.97..1.03).contains(&near), "back at W_max by K: {near}");
        // Past K, the convex region probes beyond W_max.
        while now < start + Duration::from_secs(8) {
            let bytes = cubic.cwnd() / 10;
            cubic.on_ack(&acked(bytes, now));
            now += Duration::from_millis(10);
        }
        assert!(cubic.cwnd() > 110 * MSS, "{}", cubic.cwnd());
    }

    #[test]
    fn a_second_loss_below_w_max_lowers_it_further() {
        let mut cubic = after_loss(100 * MSS);
        cubic.cwnd = 80 * MSS;
        cubic.on_congestion();
        // Fast convergence: 80 × (1 + 0.7) / 2.
        assert_eq!(cubic.w_max as usize, 68 * MSS);
        assert_eq!(cubic.ssthresh(), 56 * MSS);
    }

    #[test]
    fn a_small_window_grows_at_least_as_reno_would() {
        // Short RTT, small window: W_cubic barely moves, W_est leads.
        let mut cubic = after_loss(10 * MSS);
        let start = Instant::now();
        let mut now = start;
        for _ in 0..100 {
            // One round trip of 1 ms: a window's worth acknowledged.
            let bytes = cubic.cwnd();
            cubic.on_ack(&Acked {
                srtt: Some(Duration::from_millis(1)),
                ..acked(bytes, now)
            });
            now += Duration::from_millis(1);
        }
        // Reno would add a segment a round trip: 7 + 100 × α (0.53)
        // until W_est passes cwnd_prior, then 1 a round.
        assert!(cubic.cwnd() >= 50 * MSS, "{}", cubic.cwnd());
    }

    #[test]
    fn an_application_limited_flow_neither_grows_nor_ages_its_stage() {
        let mut cubic = after_loss(100 * MSS);
        let start = Instant::now();
        cubic.on_ack(&acked(MSS, start));
        let cwnd = cubic.cwnd();
        // Ten seconds of acknowledgements while the application sends less
        // than the window allows.
        for step in 1..=1000 {
            cubic.on_ack(&Acked {
                cwnd_limited: false,
                ..acked(MSS, start + Duration::from_millis(10 * step))
            });
        }
        assert_eq!(cubic.cwnd(), cwnd);
        let epoch = cubic.epoch.as_ref().unwrap();
        assert!(
            epoch.start >= start + Duration::from_millis(9_990),
            "t did not run"
        );
    }

    #[test]
    fn a_timeout_restarts_from_one_segment_with_k_zero() {
        let mut cubic = after_loss(100 * MSS);
        cubic.cwnd = 90 * MSS;
        cubic.on_timeout(true);
        assert_eq!(cubic.cwnd(), MSS);
        assert_eq!(cubic.ssthresh(), 63 * MSS);
        // A backed-off timeout keeps the threshold.
        cubic.on_timeout(false);
        assert_eq!(cubic.ssthresh(), 63 * MSS);
        assert!(cubic.in_slow_start());
        // Slow start counts two segments an ACK at most.
        cubic.on_ack(&acked(5 * MSS, Instant::now()));
        assert_eq!(cubic.cwnd(), 3 * MSS);
    }

    #[test]
    fn hystart_turns_conservative_when_the_delay_rises_and_ends_slow_start() {
        let mut cubic = Cubic::new(MSS, Seq(0));
        let now = Instant::now();
        let mut snd_nxt = Seq(0);
        let mut ack = Seq(0);
        let round = |cubic: &mut Cubic, ack: &mut Seq, snd_nxt: &mut Seq, rtt: u64| {
            // One round: the window acknowledged in ten ACKs, each with an
            // RTT sample, then the round ends.
            let window = cubic.cwnd();
            *snd_nxt = snd_nxt.add(2 * window);
            for _ in 0..10 {
                *ack = ack.add(window / 10);
                cubic.on_ack(&Acked {
                    bytes: window / 10,
                    ack: *ack,
                    snd_nxt: *snd_nxt,
                    rtt: Some(Duration::from_millis(rtt)),
                    srtt: Some(Duration::from_millis(rtt)),
                    cwnd_limited: true,
                    now,
                });
            }
            *ack = *snd_nxt;
        };
        round(&mut cubic, &mut ack, &mut snd_nxt, 50);
        round(&mut cubic, &mut ack, &mut snd_nxt, 50);
        assert!(cubic.hystart.as_ref().unwrap().css.is_none());
        let before = cubic.cwnd();
        // The minimum RTT rises by more than 50/8 ms: conservative growth.
        round(&mut cubic, &mut ack, &mut snd_nxt, 60);
        assert!(cubic.hystart.as_ref().unwrap().css.is_some());
        assert!(cubic.cwnd() < 2 * before);
        for _ in 0..CSS_ROUNDS {
            round(&mut cubic, &mut ack, &mut snd_nxt, 60);
        }
        assert!(cubic.hystart.is_none(), "slow start ended without a loss");
        assert!(!cubic.in_slow_start());
    }

    #[test]
    fn the_pace_is_the_window_over_the_round_trip_with_headroom() {
        let mut cubic = Cubic::new(MSS, Seq(0));
        let rate = cubic.pacing_rate(Duration::from_millis(100)).unwrap();
        assert_eq!(rate as usize, 2 * initial_window(MSS) * 10);
        cubic.on_congestion();
        cubic.end_recovery();
        let rate = cubic.pacing_rate(Duration::from_millis(100)).unwrap();
        assert_eq!(
            rate.round() as usize,
            (1.2 * cubic.cwnd() as f64 * 10.0).round() as usize
        );
        assert!(cubic.pacing_rate(Duration::ZERO).is_none());
    }
}
