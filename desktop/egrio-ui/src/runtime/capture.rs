//! The capture layers, the traffic mode, the active profile and the Core's
//! listener: reading them, switching them, and recording what went wrong.

use egrio_core::TrafficPolicyMode;
use egrio_desktop::models::SavedProfileSummary;
use egrio_desktop::operations::{capture, profiles, telemetry};
use egrio_desktop::profile_configuration::{
    ProfileConfigurationPhase, ProfileConfigurationUpdateReport,
};
use egrio_platform::{CaptureLayer, CaptureLayers};

use super::Ui;
use crate::backend::Backend;
use crate::messages::{Level, Source};
use crate::msg::Msg;
use crate::state::{Change, Remote, Section};

impl<B: Backend> Ui<B> {
    pub(super) fn load_capture(&self) {
        let runtime = self.desktop.runtime.clone();
        self.spawn(async move { Msg::CaptureStatus(capture::capture_status(&runtime).await) });
    }

    pub(super) fn load_core(&mut self) {
        self.state.core = Some(telemetry::native_core_status(&self.desktop.runtime));
        self.announce_listener_fallback();
    }

    pub(super) fn load_active_profile(&self) {
        let runtime = self.desktop.runtime.clone();
        self.spawn_blocking(move || Msg::ActiveProfile(profiles::active_profile(&runtime)));
    }

    pub(super) fn capture_status(&mut self, status: capture::CaptureStatus) {
        self.state.capture = Some(status);
        self.refresh_egress_if_needed(false);
    }

    pub(super) fn active_profile_loaded(
        &mut self,
        result: Result<Option<SavedProfileSummary>, String>,
    ) {
        self.state.active_profile = result.into();
        if self.state.section == Section::Rules {
            self.rules_follow_profile();
        }
        self.nodes_follow_profile();
        self.refresh_egress_if_needed(false);
    }

    /// Records a listener port switch once per switch.
    fn announce_listener_fallback(&mut self) {
        let fallback = self.state.port_fallback();
        if fallback == self.announced_fallback {
            return;
        }
        self.announced_fallback = fallback;
        if let Some(fallback) = fallback {
            let text = self.state.text();
            self.note(
                Level::Warning,
                Source::Listener,
                text.port_fallback(fallback.requested, fallback.actual),
                Some(fallback.detail(text)),
            );
        }
    }

    pub(super) fn toggle_capture(&mut self, layer: CaptureLayer) {
        if self.state.transition_pending() {
            return;
        }
        let on = self.state.layer_on(layer);
        if !on && self.state.needs_profile() {
            return;
        }
        let runtime = self.desktop.runtime.clone();
        self.begin_change(Change::Capture { layer, enabled: !on }, async move {
            Msg::CaptureChanged(capture::set_capture_layer(&runtime, layer, !on).await)
        });
    }

    /// A capture switch ended: its switches show the layers it left at
    /// once, and the status read next confirms them.
    pub(super) fn capture_changed(&mut self, result: Result<capture::CaptureLayersReport, String>) {
        let change = self.state.change.take().map(|running| running.change);
        let Some(Change::Capture { layer, enabled }) = change else {
            self.load_capture();
            return;
        };
        let text = self.state.text();
        let (source, failed) = match (layer, enabled) {
            (CaptureLayer::SystemProxy, true) => {
                (Source::SystemProxy, text.system_proxy_on_failed())
            }
            (CaptureLayer::SystemProxy, false) => {
                (Source::SystemProxy, text.system_proxy_off_failed())
            }
            (CaptureLayer::Tun, true) => (Source::Tun, text.tun_on_failed()),
            (CaptureLayer::Tun, false) => (Source::Tun, text.tun_off_failed()),
        };
        match result {
            Ok(report) => {
                if let Some(status) = &mut self.state.capture {
                    status.layers = report.layers;
                }
                if report.approval_required {
                    self.note(Level::Warning, source, text.tun_approval(), None);
                } else if let Some(error) = report.error {
                    self.note(Level::Error, source, failed, Some(error));
                }
            }
            Err(error) => self.note(Level::Error, source, failed, Some(error)),
        }
        self.load_capture();
        self.load_core();
    }

    /// Turns the layers the user left on when the app last ran back on,
    /// once at launch; their switches show them on meanwhile.
    pub(super) fn restore_capture(&mut self, wanted: CaptureLayers) {
        if !wanted.any() || self.state.transition_pending() {
            return;
        }
        let runtime = self.desktop.runtime.clone();
        self.begin_change(Change::Restore(wanted), async move {
            Msg::CaptureRestored(capture::restore_capture_layers(&runtime, wanted).await)
        });
    }

    /// The launch's restore ended: the switches show the layers it left,
    /// and each remembered layer it could not turn on says why.
    pub(super) fn capture_restored(
        &mut self,
        result: Result<capture::CaptureRestoreReport, String>,
    ) {
        let change = self.state.change.take().map(|running| running.change);
        let Some(Change::Restore(wanted)) = change else {
            self.load_capture();
            return;
        };
        let text = self.state.text();
        let (layers, error) = match result {
            Ok(restore) => {
                if restore.tun_not_ready {
                    self.note(Level::Warning, Source::Tun, text.tun_not_restored(), None);
                }
                (Some(restore.report.layers), restore.report.error)
            }
            Err(error) => (None, Some(error)),
        };
        if let (Some(status), Some(layers)) = (&mut self.state.capture, layers) {
            status.layers = layers;
        }
        if let Some(error) = error {
            let reached = layers.unwrap_or(CaptureLayers::NONE);
            for (layer, source, failed) in [
                (
                    CaptureLayer::SystemProxy,
                    Source::SystemProxy,
                    text.system_proxy_on_failed(),
                ),
                (CaptureLayer::Tun, Source::Tun, text.tun_on_failed()),
            ] {
                if wanted.get(layer) && !reached.get(layer) {
                    self.note(Level::Error, source, failed, Some(error.clone()));
                }
            }
        }
        self.load_capture();
        self.load_core();
    }

    pub(super) fn set_traffic_policy(&mut self, mode: TrafficPolicyMode) {
        if self.state.transition_pending() {
            return;
        }
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        if profile.traffic_policy_mode == mode {
            return;
        }
        let (runtime, profile_id) = (self.desktop.runtime.clone(), profile.id.clone());
        self.begin_change(Change::Mode(mode), async move {
            Msg::PolicyChanged(
                profiles::set_profile_traffic_policy(&runtime, profile_id, mode, None).await,
            )
        });
    }

    /// A change of the traffic mode, the global outbound or a group's
    /// member ended; `failed` names its failure. A saved mode, outbound or
    /// member shows at once, and the profile read next confirms it.
    pub(super) fn policy_changed(
        &mut self,
        result: Result<ProfileConfigurationUpdateReport, String>,
        failed: &str,
    ) {
        let change = self.state.change.take().map(|running| running.change);
        let saved = result
            .as_ref()
            .is_ok_and(|report| report.phase != ProfileConfigurationPhase::Rejected);
        if let (true, Remote::Ready(Some(profile))) = (saved, &mut self.state.active_profile) {
            match change {
                Some(Change::Mode(mode)) => profile.traffic_policy_mode = mode,
                Some(Change::GlobalOutbound(outbound)) => profile.global_outbound = Some(outbound),
                Some(Change::Member { group_id, member }) => {
                    self.state.nodes.set_choice(&profile.id, &group_id, &member)
                }
                _ => {}
            }
        }
        self.configuration_changed(result, failed);
        self.load_active_profile();
        self.load_capture();
        self.load_core();
    }

    /// Records how a profile configuration change ended where the user
    /// cannot see it in place: not yet applied, applied with cleanup still
    /// running, refused or incomplete, or failed with `failed` as its title.
    pub(super) fn configuration_changed(
        &mut self,
        result: Result<ProfileConfigurationUpdateReport, String>,
        failed: &str,
    ) {
        let text = self.state.text();
        match result {
            Ok(report) => {
                let notice = match report.phase {
                    ProfileConfigurationPhase::PendingApply => {
                        Some((Level::Warning, text.configuration_pending()))
                    }
                    ProfileConfigurationPhase::AppliedCleanupPending => {
                        Some((Level::Warning, text.configuration_cleanup_pending()))
                    }
                    ProfileConfigurationPhase::Rejected => {
                        Some((Level::Error, text.configuration_rejected()))
                    }
                    ProfileConfigurationPhase::Degraded => {
                        Some((Level::Error, text.configuration_degraded()))
                    }
                    _ => None,
                };
                if let Some((level, title)) = notice {
                    self.note(level, Source::Configuration, title, report.error);
                }
            }
            Err(error) => self.note(Level::Error, Source::Configuration, failed, Some(error)),
        }
    }
}

impl<T> From<Result<T, String>> for Remote<T> {
    fn from(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Remote::Ready(value),
            Err(error) => Remote::Failed(error),
        }
    }
}
