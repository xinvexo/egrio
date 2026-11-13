//! Wiring for system-proxy guard events. Windows consumes the Runtime
//! adapter's single event channel; the macOS and Linux adapters emit no guard
//! events, so there is nothing to wire there. A yield removes only the system
//! proxy layer through the same switching path as the user's switches.

use crate::runtime::DesktopRuntime;

/// Installs the guard-event sink into the platform's system-proxy owner.
/// Call once, after the Runtime host exists and before the first capture
/// operation can run.
pub fn init(runtime: &DesktopRuntime) {
    #[cfg(windows)]
    if let Some(mut events) = runtime.take_windows_system_proxy_events() {
        let runtime = runtime.clone();
        crate::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    egrio_platform_windows::WindowsSystemProxyGuardEvent::Reasserted {
                        attempt,
                    } => crate::events::notify_system_proxy_guard(
                        crate::events::SystemProxyGuardNotice::Reasserted,
                        format!(
                            "external overwrite re-asserted (attempt {attempt} in the flap window)"
                        ),
                    ),
                    egrio_platform_windows::WindowsSystemProxyGuardEvent::Yielded { reason } => {
                        let runtime = runtime.clone();
                        // Own the layer switch independently of the event
                        // receiver: a dropped receiver must not cancel it.
                        crate::async_runtime::spawn(async move {
                            match yield_system_proxy_layer(runtime).await {
                                Ok(true) => crate::events::notify_system_proxy_guard(
                                    crate::events::SystemProxyGuardNotice::Yielded,
                                    reason,
                                ),
                                Ok(false) => {}
                                Err(error) => log::warn!(
                                    "failed to remove the yielded system proxy layer: {error}"
                                ),
                            }
                        });
                    }
                }
            }
        });
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let _ = runtime;
}

/// Another program took the system proxy over: drop that layer and keep TUN.
#[cfg(windows)]
async fn yield_system_proxy_layer(runtime: DesktopRuntime) -> Result<bool, String> {
    let _transition = runtime.begin_user_transition().await;
    let layers = runtime.capture_layers();
    if !layers.system_proxy {
        return Ok(false);
    }
    runtime
        .apply_capture_layers(layers.with(egrio_platform::CaptureLayer::SystemProxy, false))
        .await?;
    Ok(true)
}
