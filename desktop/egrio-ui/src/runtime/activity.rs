//! The activity page's reads: the traffic chart's samples, the history's
//! totals and the egress lookup.

use std::time::{Duration, Instant};

use egrio_desktop::models::PublicIpInfo;
use egrio_desktop::operations::{egress, telemetry};

use super::Ui;
use crate::backend::Backend;
use crate::msg::Msg;
use crate::pages::activity;
use crate::state::{Remote, Section};

/// How often the egress lookup repeats while the activity page shows it.
const EGRESS_REFRESH: Duration = Duration::from_secs(120);

impl<B: Backend> Ui<B> {
    /// A point for the traffic chart, while the main window shows.
    pub(super) fn sample_traffic(&mut self) {
        if self.main.is_some() {
            let sample = telemetry::traffic_volume(&self.desktop.runtime);
            let received = self.clock.elapsed().as_secs_f64() * 1000.0;
            self.state.series.append(sample.as_ref(), received);
        }
    }

    pub(super) fn load_activity(&mut self) {
        let totals = telemetry::traffic_totals(&self.desktop.history);
        self.state.totals = Remote::Ready(totals);
        self.refresh_egress_if_needed(false);
    }

    /// Looks the egress up when the activity page shows it and the last read
    /// is old, or at once when `now`.
    pub(super) fn refresh_egress_if_needed(&mut self, now: bool) {
        if self.main.is_none()
            || self.state.section != Section::Activity
            || !activity::egress_useful(&self.state)
        {
            return;
        }
        let stale = self
            .egress_read_at
            .is_none_or(|read| read.elapsed() >= EGRESS_REFRESH);
        if !now && !stale {
            return;
        }
        self.egress_read_at = Some(Instant::now());
        if self.state.public_ip.ready().is_none() {
            self.state.public_ip = Remote::Loading;
        }
        let runtime = self.desktop.runtime.clone();
        self.spawn(async move { Msg::PublicIp(Box::new(egress::public_ip_info(&runtime).await)) });
    }

    pub(super) fn public_ip(&mut self, result: Result<PublicIpInfo, String>) {
        self.state.public_ip = result.into();
    }
}
