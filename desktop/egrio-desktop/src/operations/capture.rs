//! The two capture-layer switches, system proxy and TUN mode. They are
//! independent: any combination is valid, and the committed Runtime spec is
//! their only state. With both on, applications that honor the system proxy
//! reach the Core listener through it and TUN captures everything else.

use crate::desktop_behavior;
use crate::runtime::DesktopRuntime;
use crate::tun_environment::{self, TunEnvironment};
use egrio_platform::{capture_support_for_os, CaptureLayer, CaptureLayers, CaptureSupport};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatus {
    /// The layers the running Runtime carries.
    pub layers: CaptureLayers,
    /// The layers this platform implements.
    pub support: CaptureSupport,
    /// TUN mode's one-time environment is installed.
    pub tun_environment_ready: bool,
    /// Why TUN mode stopped working on its own (its platform session ended),
    /// while it is being restored or after it could not be.
    pub tun_interruption: Option<String>,
    /// The Core is downloading required data before opening ordinary ingress.
    pub preparation: Option<crate::runtime::CorePreparation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureLayersReport {
    /// The layers the Runtime carries after the request.
    pub layers: CaptureLayers,
    /// Why the requested layers were not reached.
    pub error: Option<String>,
    /// Set instead of `error` while TUN mode's environment awaits the user's
    /// approval; no layer changed.
    pub approval_required: bool,
    /// Accepted, but ordinary ingress is waiting for required configuration data.
    pub preparation: Option<crate::runtime::CorePreparation>,
}

pub async fn capture_status(runtime: &DesktopRuntime) -> CaptureStatus {
    let layers = runtime.capture_layers();
    CaptureStatus {
        layers,
        support: capture_support(),
        // A running TUN layer proves its environment.
        tun_environment_ready: layers.tun || tun_environment::is_ready().await,
        tun_interruption: runtime.tun_interruption(),
        preparation: runtime.core_preparation(),
    }
}

/// Switches one layer and keeps the other. The request carries an intent,
/// not a cached pair of switches: it resolves against the committed layers
/// under the transition lock, so a concurrent tray switch is never undone.
/// The layers it leaves on are the ones the next launch turns back on.
pub async fn set_capture_layer(
    runtime: &DesktopRuntime,
    layer: CaptureLayer,
    enabled: bool,
) -> Result<CaptureLayersReport, String> {
    let report =
        change_capture_layers(runtime.clone(), move |current| current.with(layer, enabled)).await?;
    remember(runtime.requested_capture_layers()).await;
    Ok(report)
}

pub async fn toggle_capture_layer(
    runtime: &DesktopRuntime,
    layer: CaptureLayer,
) -> Result<CaptureLayersReport, String> {
    let report = change_capture_layers(runtime.clone(), move |current| {
        current.with(layer, !current.get(layer))
    })
    .await?;
    remember(runtime.requested_capture_layers()).await;
    Ok(report)
}

/// Keeps the layers a user's switch left for the next launch; a failure to
/// keep them costs only that.
async fn remember(layers: CaptureLayers) {
    let saved =
        crate::async_runtime::spawn_blocking(move || desktop_behavior::save_capture_layers(layers))
            .await;
    if let Err(error) = saved
        .map_err(|error| error.to_string())
        .and_then(|saved| saved)
    {
        log::warn!("couldn't keep the capture layers for the next launch: {error}");
    }
}

/// The layers the user left on when the app last ran; none when they cannot
/// be read.
pub fn remembered_capture_layers() -> CaptureLayers {
    desktop_behavior::load_capture_layers().unwrap_or_else(|error| {
        log::warn!("couldn't read the capture layers to restore: {error}");
        CaptureLayers::NONE
    })
}

/// How turning the remembered layers back on at launch ended.
#[derive(Debug, Clone)]
pub struct CaptureRestoreReport {
    /// The layers the Runtime carries afterwards, and why the remembered
    /// ones were not reached.
    pub report: CaptureLayersReport,
    /// TUN mode stayed off: its environment is not ready, and a launch
    /// asks the user for nothing.
    pub tun_not_ready: bool,
}

/// Turns `wanted`, the layers the user left on, back on at launch for the
/// active profile, without asking for anything: without a profile nothing
/// turns on, and a TUN environment that is not ready (the service not
/// allowed or not answering) leaves TUN off. Layers already on stay on.
pub async fn restore_capture_layers(
    runtime: &DesktopRuntime,
    wanted: CaptureLayers,
) -> Result<CaptureRestoreReport, String> {
    let has_profile = crate::async_runtime::spawn_blocking(|| {
        crate::profile_service::get_active_profile().map(|profile| profile.is_some())
    })
    .await
    .map_err(|error| format!("read the active profile: {error}"))??;
    let tun_not_ready = has_profile && wanted.tun && !tun_environment::is_ready().await;
    let target = CaptureLayers {
        system_proxy: has_profile && wanted.system_proxy,
        tun: has_profile && wanted.tun && !tun_not_ready,
    };
    if !target.any() {
        return Ok(CaptureRestoreReport {
            report: CaptureLayersReport {
                layers: runtime.capture_layers(),
                error: None,
                approval_required: false,
                preparation: runtime.core_preparation(),
            },
            tun_not_ready,
        });
    }
    let report = change_capture_layers(runtime.clone(), move |current| CaptureLayers {
        system_proxy: current.system_proxy || target.system_proxy,
        tun: current.tun || target.tun,
    })
    .await?;
    Ok(CaptureRestoreReport {
        report,
        tun_not_ready,
    })
}

pub async fn prepare_tun_environment() -> TunEnvironment {
    let _notify = crate::events::notify_on_return();
    tun_environment::ensure().await
}

fn capture_support() -> CaptureSupport {
    capture_support_for_os(std::env::consts::OS)
}

async fn change_capture_layers(
    runtime: DesktopRuntime,
    target: impl FnOnce(CaptureLayers) -> CaptureLayers + Send + 'static,
) -> Result<CaptureLayersReport, String> {
    detached(async move {
        let _notify = crate::events::notify_on_return();
        let _transition = runtime.begin_user_transition().await;
        let current = runtime.capture_layers();
        let target = target(runtime.requested_capture_layers());
        let requested =
            serde_json::json!({ "system_proxy": target.system_proxy, "tun": target.tun });
        log::info!(target: "network", "capture-change-requested {requested}");
        let report = switch_layers(&runtime, current, target).await;
        let finished = serde_json::json!({
            "ok": report.error.is_none() && !report.approval_required && report.preparation.is_none(),
            "preparing": report.preparation.is_some(),
            "system_proxy_active": report.layers.system_proxy,
            "tun_active": report.layers.tun,
            "error": report.error,
        });
        log::info!(target: "network", "capture-change-finished {finished}");
        Ok(report)
    })
    .await
}

async fn switch_layers(
    runtime: &DesktopRuntime,
    current: CaptureLayers,
    target: CaptureLayers,
) -> CaptureLayersReport {
    let unchanged = |error: Option<String>, approval_required: bool| CaptureLayersReport {
        layers: runtime.capture_layers(),
        error,
        approval_required,
        preparation: runtime.core_preparation(),
    };
    if target == current && runtime.core_preparation().is_none() {
        return unchanged(None, false);
    }
    if !capture_support().covers(target) {
        return unchanged(
            Some(format!(
                "{} does not support the requested capture layers",
                std::env::consts::OS
            )),
            false,
        );
    }
    if target.tun && !current.tun {
        match tun_environment::ensure().await {
            TunEnvironment::Ready => {}
            TunEnvironment::ApprovalRequired => return unchanged(None, true),
            TunEnvironment::Blocked { error } => return unchanged(Some(error), false),
        }
    } else if current.tun {
        // Removing or recovering a TUN layer restores its capabilities through
        // the same environment (the Windows service may have stopped since).
        // An environment that cannot be readied must not block turning TUN
        // off: the restore then reports its own error and keeps the checkpoint.
        let _ = tun_environment::ensure().await;
    }
    let error = runtime.apply_capture_layers(target).await.err();
    CaptureLayersReport {
        layers: runtime.capture_layers(),
        error,
        approval_required: false,
        preparation: runtime.core_preparation(),
    }
}

/// Runs a network transition as its own task: a closed window or dropped
/// caller cannot cancel it halfway.
async fn detached<T: Send + 'static>(
    transition: impl std::future::Future<Output = Result<T, String>> + Send + 'static,
) -> Result<T, String> {
    crate::async_runtime::spawn(transition)
        .await
        .map_err(|error| format!("capture-layer transition task failed: {error}"))?
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use super::detached;

    #[tokio::test]
    async fn a_dropped_caller_does_not_cancel_the_network_transition() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_by_transition = completed.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(async move {
            detached(async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                completed_by_transition.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
        });

        started_rx.await.expect("transition started");
        caller.abort();
        let _ = caller.await;
        let _ = release_tx.send(());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !completed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached transition completes after caller cancellation");
    }
}
