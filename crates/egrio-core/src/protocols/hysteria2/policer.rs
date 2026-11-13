//! Finds a token-bucket policer on a congestion-controlled connection's path
//! the way Linux's BBR does (`net/ipv4/tcp_bbr.c`, the "long-term" bandwidth
//! sampling): a policer passes a fixed rate and drops the rest without
//! queueing it, so the delivery rate stays put while loss runs high. quinn
//! paces from the congestion window, at 1.25 times the window per round
//! trip, and BBR's window is twice the bandwidth-delay product; past a queue
//! the window fills and holds the rate, but past a policer the dropped
//! packets leave the window free, and the connection kept sending two and a
//! half times its bandwidth estimate, wasting capacity on repeated loss.
//!
//! Sampling begins at the first loss, once the policer's tokens are spent.
//! An interval lasts at least [`MIN_ROUNDS`] round trips and ends at a loss;
//! if more than a fifth as much was lost as delivered, its delivery rate is a
//! sample. Two consecutive samples within an eighth (or 4 kbit/s) of each
//! other mean a policer: the connection then sends at their mean for
//! [`POLICED_ROUNDS`] round trips, and samples afresh after. An interval
//! past [`MAX_ROUNDS`], or one in which the application ran out of data,
//! starts the sampling over.

use std::time::{Duration, Instant};

/// Round trips an interval lasts at least (`bbr_lt_intvl_min_rtts`).
const MIN_ROUNDS: u32 = 4;
/// Round trips past which an interval starts over (four times the least).
const MAX_ROUNDS: u32 = 4 * MIN_ROUNDS;
/// Lost over delivered, in 256ths, at which an interval is lossy
/// (`bbr_lt_loss_thresh`, about a fifth).
const LOSS_THRESHOLD: u64 = 50;
/// Two intervals' rates are consistent within an eighth of the earlier one
/// (`bbr_lt_bw_ratio`) or within 4 kbit/s (`bbr_lt_bw_diff`).
const RATE_RATIO: u64 = 8;
const RATE_DIFF: u64 = 4_000 / 8;
/// Round trips the policed rate is kept (`bbr_lt_bw_max_rtts`).
const POLICED_ROUNDS: u32 = 48;

#[derive(Clone, Debug)]
pub(super) struct Policer {
    /// Bytes acknowledged and declared lost so far, and when the last
    /// acknowledgement arrived.
    delivered: u64,
    lost: u64,
    delivered_at: Option<Instant>,
    /// The smoothed round trip, which times the rounds.
    srtt: Duration,
    round_started: Option<Instant>,
    /// The interval under way, if sampling.
    interval: Option<Interval>,
    /// The last lossy interval's rate, or the policed rate in use, in bytes
    /// per second.
    rate: u64,
    /// Round trips sent at the policed rate, while it is in use.
    policed_rounds: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
struct Interval {
    delivered: u64,
    lost: u64,
    at: Instant,
    rounds: u32,
}

impl Policer {
    pub(super) fn new() -> Self {
        Self {
            delivered: 0,
            lost: 0,
            delivered_at: None,
            srtt: Duration::ZERO,
            round_started: None,
            interval: None,
            rate: 0,
            policed_rounds: None,
        }
    }

    /// The policed rate in bytes per second while one is in use, else 0.
    pub(super) fn policed_rate(&self) -> u64 {
        if self.policed_rounds.is_some() {
            self.rate
        } else {
            0
        }
    }

    /// `bytes` were acknowledged at `now`.
    pub(super) fn acked(&mut self, now: Instant, bytes: u64, srtt: Duration) {
        self.delivered += bytes;
        self.delivered_at = Some(now);
        self.srtt = srtt;
    }

    /// A batch of acknowledgements ended: counts the round trips, ends the
    /// policed rate's term, and starts over an interval that ran too long or
    /// in which the application ran out of data.
    pub(super) fn end_acks(&mut self, now: Instant, app_limited: bool) {
        let round = match self.round_started {
            Some(started) => now.saturating_duration_since(started) >= self.srtt,
            None => true,
        };
        if round {
            self.round_started = Some(now);
        }
        if let Some(rounds) = &mut self.policed_rounds {
            if round {
                *rounds += 1;
                if *rounds >= POLICED_ROUNDS {
                    self.reset();
                }
            }
            return;
        }
        let Some(interval) = &mut self.interval else {
            return;
        };
        if app_limited {
            self.reset();
            return;
        }
        if round {
            interval.rounds += 1;
            if interval.rounds > MAX_ROUNDS {
                self.reset();
            }
        }
    }

    /// `bytes` were declared lost at `now`: starts sampling at the first
    /// loss, and ends a long enough lossy interval.
    pub(super) fn lost(&mut self, bytes: u64) {
        self.lost += bytes;
        if self.policed_rounds.is_some() {
            return;
        }
        let Some(interval) = self.interval else {
            self.start_interval();
            return;
        };
        if interval.rounds < MIN_ROUNDS {
            return;
        }
        let lost = self.lost - interval.lost;
        let delivered = self.delivered - interval.delivered;
        if delivered == 0 || (lost << 8) < LOSS_THRESHOLD * delivered {
            return;
        }
        let Some(at) = self.delivered_at else {
            return;
        };
        let elapsed = at.saturating_duration_since(interval.at);
        if elapsed < Duration::from_millis(1) {
            return;
        }
        let rate = (delivered as f64 / elapsed.as_secs_f64()) as u64;
        self.interval_done(rate);
    }

    /// An interval measured `rate`: a policer if it matches the one before.
    fn interval_done(&mut self, rate: u64) {
        if self.rate > 0 {
            let diff = rate.abs_diff(self.rate);
            if diff * RATE_RATIO <= self.rate || diff <= RATE_DIFF {
                self.rate = (rate + self.rate) / 2;
                self.policed_rounds = Some(0);
                self.interval = None;
                return;
            }
        }
        self.rate = rate;
        self.start_interval();
    }

    fn start_interval(&mut self) {
        self.interval = Some(Interval {
            delivered: self.delivered,
            lost: self.lost,
            at: self.delivered_at.unwrap_or_else(Instant::now),
            rounds: 0,
        });
    }

    fn reset(&mut self) {
        self.rate = 0;
        self.policed_rounds = None;
        self.interval = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(60);

    /// Runs `rounds` round trips of 10 ACK batches delivering `rate` bytes a
    /// second, with `lost_share` of what was sent lost at the end of each
    /// round trip.
    fn run(policer: &mut Policer, now: &mut Instant, rounds: u32, rate: u64, lost_share: f64) {
        for _ in 0..rounds {
            let per_batch = rate * RTT.as_millis() as u64 / 1000 / 10;
            for _ in 0..10 {
                *now += RTT / 10;
                policer.acked(*now, per_batch, RTT);
                policer.end_acks(*now, false);
            }
            let delivered = per_batch * 10;
            let lost = (delivered as f64 * lost_share / (1.0 - lost_share)) as u64;
            if lost > 0 {
                policer.lost(lost);
            }
        }
    }

    #[test]
    fn a_steady_rate_behind_heavy_loss_is_a_policer() {
        let mut policer = Policer::new();
        let mut now = Instant::now();
        run(&mut policer, &mut now, 3, 5_000_000, 0.0);
        assert_eq!(policer.policed_rate(), 0, "no loss, no sampling");
        // Half of what is sent is lost: two intervals of four round trips
        // measure the same rate.
        run(&mut policer, &mut now, 12, 5_000_000, 0.5);
        let rate = policer.policed_rate();
        assert!(
            (4_900_000..=5_100_000).contains(&rate),
            "policed at the delivered rate: {rate}"
        );
        // The term ends after its round trips.
        run(&mut policer, &mut now, POLICED_ROUNDS, 5_000_000, 0.0);
        assert_eq!(policer.policed_rate(), 0);
    }

    #[test]
    fn light_loss_is_not_a_policer() {
        let mut policer = Policer::new();
        let mut now = Instant::now();
        // A fifth would be lossy; a tenth of what is delivered is not.
        run(&mut policer, &mut now, 40, 5_000_000, 0.09);
        assert_eq!(policer.policed_rate(), 0);
    }

    #[test]
    fn inconsistent_rates_are_not_a_policer() {
        let mut policer = Policer::new();
        let mut now = Instant::now();
        // Each lossy interval delivers half again what the one before did.
        let mut rate = 2_000_000;
        for _ in 0..6 {
            run(&mut policer, &mut now, MIN_ROUNDS, rate, 0.5);
            rate = rate * 3 / 2;
            assert_eq!(policer.policed_rate(), 0, "at {rate}");
        }
    }

    #[test]
    fn running_out_of_data_starts_the_sampling_over() {
        let mut policer = Policer::new();
        let mut now = Instant::now();
        run(&mut policer, &mut now, 6, 5_000_000, 0.5);
        assert!(policer.interval.is_some());
        now += RTT;
        policer.end_acks(now, true);
        assert!(policer.interval.is_none());
        assert_eq!(policer.policed_rate(), 0);
    }
}
