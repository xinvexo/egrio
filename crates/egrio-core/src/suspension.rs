//! Notices that the host slept. `Instant`, and with it every Tokio timer,
//! stops while the host sleeps where it reads `CLOCK_UPTIME_RAW` (Apple: "does
//! not increment while the system is asleep") or `CLOCK_MONOTONIC` (Linux:
//! does not count suspended time, clock_gettime(2)); the wall clock keeps
//! counting. The gap between the two therefore grows by the time spent
//! asleep, and whatever should have expired meanwhile looks fresh for that
//! much longer: a QUIC carrier the server dropped during the sleep stays in
//! use until its idle timeout passes in waking time, a DNS answer outlives its
//! TTL by the length of the night. Where the monotonic clock counts the sleep,
//! those timers fire on time and nothing here triggers.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The smallest gap between the clocks taken for a sleep: larger than any
/// step a time synchronization makes while the host is awake.
const SLEEP_MS: i64 = 10_000;

/// Where the wall clock stands against the monotonic clock now, in
/// milliseconds; constant while the host stays awake.
pub(crate) fn mark() -> i64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = *BASE.get_or_init(Instant::now);
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as i64);
    wall - base.elapsed().as_millis() as i64
}

/// Whether the host slept since `earlier` was taken with [`mark`].
pub(crate) fn slept_since(earlier: i64) -> bool {
    mark() - earlier >= SLEEP_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_awake_host_never_slept() {
        let before = mark();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!slept_since(before));
        assert!((mark() - before).abs() < SLEEP_MS);
    }

    #[test]
    fn a_mark_from_before_a_long_gap_reads_as_a_sleep() {
        assert!(slept_since(mark() - SLEEP_MS));
        assert!(!slept_since(mark() - SLEEP_MS + 1_000));
    }
}
