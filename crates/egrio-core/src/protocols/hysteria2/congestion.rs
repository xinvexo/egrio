//! Send-rate control for Hysteria 2 connections ([protocol, Congestion
//! Control](https://github.com/apernet/hysteria/blob/master/PROTOCOL.md#congestion-control)).
//! Authentication tells each side the other's receive rate. A sender with an
//! agreed rate sends at it whatever the loss; without one, or when the peer
//! answers `auto`, it keeps congestion control. Each connection's controller
//! runs BBR until authentication writes its [`SendRate`], so the handshake and
//! the authentication exchange are congestion controlled either way. Under
//! BBR, a policer on the path (`policer.rs`) sets the rate for a while.
//!
//! The rate itself is enforced by the connection's [`PacedSocket`]
//! (`pacer.rs`), not by the window: quinn paces from the window in bursts of
//! about 2 ms of it, which couples the rate to how often the connection
//! wakes. The window instead leaves room:
//! by Little's law the bytes in flight are the send rate times how long a byte
//! stays in flight, measured here from sending to acknowledgement or loss, and
//! the window is twice that so data acknowledged late or lost but not yet
//! declared lost never holds the pacer back.
//!
//! [`PacedSocket`]: super::pacer::PacedSocket

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

use super::policer::Policer;

/// Seconds of acknowledgements and losses the loss share is taken over: long
/// enough to average a burst of loss, short enough to follow a path change.
const DELIVERY_SECONDS: usize = 5;
/// Below this many datagrams' worth of samples a single loss would swing the
/// share by several percent, so the rate is not compensated yet.
const MIN_SAMPLE_DATAGRAMS: u64 = 50;
/// The lowest delivered share compensated for. The agreed rate is exceeded
/// only to replace lost data, and by at most 1.25 times: beyond that, extra
/// sending mostly feeds the congestion that causes the loss.
const MIN_DELIVERED_SHARE: f64 = 0.8;
/// The smallest window quinn can always send through, two datagrams
/// (RFC 9002 section 7.2, `kMinimumWindow`).
const MIN_WINDOW_DATAGRAMS: u64 = 2;
/// The window over the bytes the rate keeps in flight.
const WINDOW_HEADROOM: f64 = 2.0;

/// A connection's agreed send rate and the share of its recent data that
/// arrived. Authentication writes the rate once, the controller keeps the
/// share current, and the socket pacer sends at their quotient; without an
/// agreed rate, at the rate of a policer congestion control found.
#[derive(Debug)]
pub(super) struct SendRate {
    /// Bytes per second; 0 keeps congestion control.
    agreed: AtomicU64,
    /// `f64` bits of the delivered share, between [`MIN_DELIVERED_SHARE`]
    /// and 1.
    share: AtomicU64,
    /// Bytes per second a policer passes, while congestion control sends at
    /// it; else 0.
    policed: AtomicU64,
}

impl Default for SendRate {
    fn default() -> Self {
        Self {
            agreed: AtomicU64::new(0),
            share: AtomicU64::new(1.0_f64.to_bits()),
            policed: AtomicU64::new(0),
        }
    }
}

impl SendRate {
    pub(super) fn set(&self, bytes_per_second: u64) {
        self.agreed.store(bytes_per_second, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.agreed.load(Ordering::Relaxed)
    }

    fn share(&self) -> f64 {
        f64::from_bits(self.share.load(Ordering::Relaxed))
    }

    fn set_share(&self, share: f64) {
        self.share.store(share.to_bits(), Ordering::Relaxed);
    }

    fn set_policed(&self, bytes_per_second: u64) {
        self.policed.store(bytes_per_second, Ordering::Relaxed);
    }

    /// The bytes per second to send: the agreed rate raised to replace lost
    /// data; without one the policed rate, or 0 while congestion control
    /// alone is in charge.
    pub(super) fn pacing(&self) -> u64 {
        match self.get() {
            0 => self.policed.load(Ordering::Relaxed),
            agreed => (agreed as f64 / self.share()) as u64,
        }
    }
}

/// Builds each connection's controller around the [`SendRate`] its
/// authentication writes. One factory, and so one rate, per connection.
pub(super) struct RateControlFactory {
    rate: Arc<SendRate>,
    bbr: Arc<BbrConfig>,
}

impl RateControlFactory {
    pub(super) fn new(rate: Arc<SendRate>) -> Self {
        Self {
            rate,
            bbr: Arc::new(BbrConfig::default()),
        }
    }
}

impl ControllerFactory for RateControlFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(RateControl::new(
            Arc::clone(&self.rate),
            Arc::clone(&self.bbr).build(now, current_mtu),
            now,
            current_mtu,
        ))
    }
}

pub(super) struct RateControl {
    rate: Arc<SendRate>,
    bbr: Box<dyn Controller>,
    policer: Policer,
    delivery: Delivery,
    residence: Residence,
    mtu: u16,
}

impl RateControl {
    fn new(rate: Arc<SendRate>, bbr: Box<dyn Controller>, now: Instant, mtu: u16) -> Self {
        Self {
            rate,
            bbr,
            policer: Policer::new(),
            delivery: Delivery::new(now),
            residence: Residence::default(),
            mtu,
        }
    }

    /// The agreed rate in bytes per second, or 0 while BBR is in charge.
    #[cfg(all(test, feature = "server"))]
    pub(super) fn fixed_rate(&self) -> u64 {
        self.rate.get()
    }

    fn congestion_controlled(&self) -> bool {
        self.rate.get() == 0
    }

    /// Accounts bytes that left flight at `now`, acknowledged or lost, after
    /// being sent at `sent`.
    fn left_flight(&mut self, now: Instant, sent: Instant, acked: u64, lost: u64) {
        self.residence
            .add(acked + lost, now.saturating_duration_since(sent));
        let min_sample = MIN_SAMPLE_DATAGRAMS * u64::from(self.mtu);
        self.delivery.record(now, acked, lost, min_sample);
        self.rate.set_share(self.delivery.share);
    }
}

impl Controller for RateControl {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.congestion_controlled() {
            self.bbr.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.left_flight(now, sent, bytes, 0);
        if self.congestion_controlled() {
            self.policer.acked(now, bytes, rtt.get());
            self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.residence.end_batch();
        if self.congestion_controlled() {
            self.policer.end_acks(now, app_limited);
            self.rate.set_policed(self.policer.policed_rate());
            self.bbr
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // An ECN mark reports no lost bytes and changes nothing here: a fixed
        // rate does not back off for congestion it is told about.
        self.left_flight(now, sent, 0, lost_bytes);
        if self.congestion_controlled() {
            if lost_bytes > 0 {
                self.policer.lost(lost_bytes);
                self.rate.set_policed(self.policer.policed_rate());
            }
            self.bbr
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.bbr.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        match (self.rate.pacing(), self.residence.smoothed) {
            (0, _) | (_, None) => self.bbr.window(),
            (pacing, Some(residence)) => fixed_rate_window(pacing, residence, self.mtu),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            rate: Arc::clone(&self.rate),
            bbr: self.bbr.clone_box(),
            policer: self.policer.clone(),
            delivery: self.delivery.clone(),
            residence: self.residence.clone(),
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// The window for sending at `pacing` bytes per second when each byte stays
/// in flight for `residence`.
fn fixed_rate_window(pacing: u64, residence: Duration, mtu: u16) -> u64 {
    let in_flight = pacing as f64 * residence.as_secs_f64();
    ((in_flight * WINDOW_HEADROOM) as u64).max(MIN_WINDOW_DATAGRAMS * u64::from(mtu))
}

/// How long bytes stay in flight: the byte-weighted mean over each ACK batch,
/// smoothed across batches with the 1/8 gain RFC 9002 section 5.3 gives the
/// smoothed RTT.
#[derive(Clone, Default)]
struct Residence {
    smoothed: Option<Duration>,
    batch_bytes: u64,
    batch_byte_nanos: u128,
}

impl Residence {
    fn add(&mut self, bytes: u64, stayed: Duration) {
        self.batch_bytes += bytes;
        self.batch_byte_nanos += u128::from(bytes) * stayed.as_nanos();
    }

    fn end_batch(&mut self) {
        if self.batch_bytes == 0 {
            return;
        }
        let sample = self.batch_byte_nanos / u128::from(self.batch_bytes);
        let sample = Duration::from_nanos(u64::try_from(sample).unwrap_or(u64::MAX));
        self.smoothed = Some(match self.smoothed {
            None => sample,
            Some(smoothed) => (smoothed * 7 + sample) / 8,
        });
        self.batch_bytes = 0;
        self.batch_byte_nanos = 0;
    }
}

/// Bytes acknowledged and declared lost in each of the last
/// [`DELIVERY_SECONDS`] seconds, and the share of them that arrived.
#[derive(Clone)]
struct Delivery {
    origin: Instant,
    seconds: [Second; DELIVERY_SECONDS],
    share: f64,
}

#[derive(Clone, Copy, Default)]
struct Second {
    index: u64,
    acked: u64,
    lost: u64,
}

impl Delivery {
    fn new(origin: Instant) -> Self {
        Self {
            origin,
            seconds: [Second::default(); DELIVERY_SECONDS],
            share: 1.0,
        }
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64, min_sample: u64) {
        let index = now.saturating_duration_since(self.origin).as_secs();
        let second = &mut self.seconds[index as usize % DELIVERY_SECONDS];
        if second.index != index {
            *second = Second {
                index,
                ..Second::default()
            };
        }
        second.acked += acked;
        second.lost += lost;
        let oldest = index.saturating_sub(DELIVERY_SECONDS as u64 - 1);
        let (acked, lost) = self
            .seconds
            .iter()
            .filter(|second| second.index >= oldest)
            .fold((0, 0), |(acked, lost), second| {
                (acked + second.acked, lost + second.lost)
            });
        self.share = if acked + lost < min_sample {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_DELIVERED_SHARE)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1200;

    #[test]
    fn the_window_holds_twice_what_the_rate_keeps_in_flight() {
        let residence = Duration::from_millis(100);
        assert_eq!(fixed_rate_window(12_500_000, residence, MTU), 2_500_000);
        // A rate too low to fill two datagrams per residence still sends.
        assert_eq!(fixed_rate_window(5_000, residence, MTU), 2_400);
    }

    #[test]
    fn the_pacing_rate_replaces_lost_data_within_the_share_floor() {
        let rate = SendRate::default();
        assert_eq!(rate.pacing(), 0);
        rate.set(10_000_000);
        assert_eq!(rate.pacing(), 10_000_000);
        rate.set_share(MIN_DELIVERED_SHARE);
        assert_eq!(rate.pacing(), 12_500_000);
    }

    #[test]
    fn residence_is_the_byte_weighted_batch_mean_smoothed_over_batches() {
        let mut residence = Residence::default();
        residence.end_batch();
        assert_eq!(residence.smoothed, None, "an empty batch is no sample");
        residence.add(3_000, Duration::from_millis(40));
        residence.add(1_000, Duration::from_millis(80));
        residence.end_batch();
        assert_eq!(residence.smoothed, Some(Duration::from_millis(50)));
        residence.add(1_000, Duration::from_millis(130));
        residence.end_batch();
        assert_eq!(residence.smoothed, Some(Duration::from_millis(60)));
    }

    #[test]
    fn loss_raises_the_rate_by_at_most_a_quarter_once_samples_suffice() {
        let start = Instant::now();
        let mut delivery = Delivery::new(start);
        delivery.record(start, 9_000, 1_000, 60_000);
        assert_eq!(delivery.share, 1.0, "too few samples to judge");
        delivery.record(start, 45_000, 5_000, 60_000);
        assert!((delivery.share - 0.9).abs() < 1e-9);
        delivery.record(start, 0, 100_000, 60_000);
        assert_eq!(delivery.share, MIN_DELIVERED_SHARE);
    }

    #[test]
    fn samples_older_than_the_delivery_seconds_stop_counting() {
        let start = Instant::now();
        let mut delivery = Delivery::new(start);
        delivery.record(start, 50_000, 50_000, 60_000);
        assert_eq!(delivery.share, MIN_DELIVERED_SHARE);
        let later = start + Duration::from_secs(DELIVERY_SECONDS as u64);
        delivery.record(later, 100_000, 0, 60_000);
        assert_eq!(delivery.share, 1.0);
    }

    #[test]
    fn bbr_runs_until_a_rate_is_agreed_and_the_rate_window_after() {
        let now = Instant::now();
        let rate = Arc::new(SendRate::default());
        let bbr = Arc::new(BbrConfig::default()).build(now, MTU);
        let bbr_window = bbr.window();
        let mut controller = RateControl::new(Arc::clone(&rate), bbr, now, MTU);
        rate.set(25_000_000);
        assert_eq!(
            controller.window(),
            bbr_window,
            "nothing has left flight yet"
        );

        rate.set(0);
        controller.left_flight(now + Duration::from_millis(50), now, 1_200, 0);
        controller.residence.end_batch();
        assert_eq!(controller.window(), bbr_window, "no rate yet: BBR decides");

        rate.set(25_000_000);
        assert_eq!(controller.window(), 2_500_000);
        assert_eq!(controller.clone_box().window(), 2_500_000);
    }
}
