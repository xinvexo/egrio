//! Event-loop watchdog (Envoy's watchdog reduced to one heartbeat). A
//! control-plane task sleeps a fixed tick and measures how
//! late the runtime woke it: sustained oversleeps mean something blocked
//! the async executor — the least reproducible class of client jank. The
//! watchdog only counts and records; hosts read the stats and decide.
//!
//! Spawning is a host decision (like the health-probe loop): the heartbeat
//! is a periodic waker, one wakeup of the Core's thread a second for as long
//! as it runs. No shipped host spawns it, so their idle Core keeps no timer
//! for it; the soak instrument (`examples/soak_churn.rs`) does, to report the
//! stalls of a long run.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

/// Default heartbeat period.
pub(crate) const WATCHDOG_TICK: Duration = Duration::from_secs(1);
/// Scheduling delay above which a tick counts as a stall. Well above timer
/// coalescing noise, well below anything a user would feel.
pub(crate) const WATCHDOG_STALL_THRESHOLD: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub(crate) struct WatchdogState {
    ticks: AtomicU64,
    stalls: AtomicU64,
    max_delay_micros: AtomicU64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct WatchdogStats {
    pub ticks: u64,
    pub stalls: u64,
    pub max_scheduling_delay_micros: u64,
}

impl WatchdogState {
    pub(crate) fn record_tick(&self, delay: Duration, threshold: Duration) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
        if delay >= threshold {
            self.stalls.fetch_add(1, Ordering::Relaxed);
        }
        let micros = u64::try_from(delay.as_micros()).unwrap_or(u64::MAX);
        self.max_delay_micros.fetch_max(micros, Ordering::Relaxed);
    }

    pub(crate) fn stats(&self) -> WatchdogStats {
        WatchdogStats {
            ticks: self.ticks.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            max_scheduling_delay_micros: self.max_delay_micros.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_ticks_stalls_and_max_delay() {
        let state = WatchdogState::default();
        let threshold = Duration::from_millis(20);

        state.record_tick(Duration::from_millis(1), threshold);
        state.record_tick(Duration::from_millis(50), threshold);
        state.record_tick(Duration::from_millis(20), threshold);

        let stats = state.stats();
        assert_eq!(stats.ticks, 3);
        assert_eq!(stats.stalls, 2, "at-threshold and above count as stalls");
        assert_eq!(stats.max_scheduling_delay_micros, 50_000);
    }
}
