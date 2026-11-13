use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use egrio_platform::{
    system_proxy_config_from_listen_addr, SystemProxyApplyReport, SystemProxyBackendKind,
    SystemProxyConfig, SystemProxyRestoreReport, SystemProxySnapshot,
};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, PlatformLeaseKey,
    SystemProxyControl, SystemProxySettings,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

const CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const DEFAULT_WATCH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_FLAP_WINDOW: Duration = Duration::from_secs(10);
const DEFAULT_FLAP_LIMIT: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsSystemProxyGuardEvent {
    Reasserted { attempt: usize },
    Yielded { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WindowsSystemProxyCheckpoint {
    baseline: SystemProxySnapshot,
    expected: SystemProxyConfig,
}

trait Backend: Send + Sync + fmt::Debug {
    fn status(&self) -> Result<SystemProxySnapshot, String>;
    fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxyApplyReport, String>;
    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<SystemProxyRestoreReport, String>;
    fn reassert(&self, config: &SystemProxyConfig) -> Result<(), String>;
}

#[derive(Debug)]
struct NativeBackend;

impl Backend for NativeBackend {
    fn status(&self) -> Result<SystemProxySnapshot, String> {
        super::system_proxy_status()
    }

    fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxyApplyReport, String> {
        super::system_proxy::apply_system_proxy(config)
    }

    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<SystemProxyRestoreReport, String> {
        super::system_proxy::restore_system_proxy(snapshot)
    }

    fn reassert(&self, config: &SystemProxyConfig) -> Result<(), String> {
        super::system_proxy::reassert_system_proxy(config)
    }
}

trait WatchStop: Send + Sync + fmt::Debug {
    fn signal(&self);
}

trait WatchDriver: Send + fmt::Debug {
    fn wait_for_change(&mut self, timeout: Duration) -> Result<WatchOutcome, String>;
}

trait WatchFactory: Send + Sync + fmt::Debug {
    fn open(&self) -> Result<OpenedWatch, String>;
}

// Constructed by the native (windows) driver and the scripted test driver;
// cross-compiled host builds only see the trait signature.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchOutcome {
    Changed,
    Stopped,
    TimedOut,
}

struct OpenedWatch {
    driver: Box<dyn WatchDriver>,
    stop: Arc<dyn WatchStop>,
}

impl fmt::Debug for OpenedWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedWatch")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct NativeWatchFactory;

#[cfg(windows)]
struct NativeWatchDriver(crate::system_proxy_watch::WindowsSystemProxyChangeWatcher);

#[cfg(windows)]
struct NativeWatchStop(crate::system_proxy_watch::WindowsSystemProxyWatchStopHandle);

#[cfg(windows)]
impl fmt::Debug for NativeWatchDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWatchDriver")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl fmt::Debug for NativeWatchStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWatchStop")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl WatchStop for NativeWatchStop {
    fn signal(&self) {
        self.0.signal();
    }
}

#[cfg(windows)]
impl WatchDriver for NativeWatchDriver {
    fn wait_for_change(&mut self, timeout: Duration) -> Result<WatchOutcome, String> {
        self.0
            .wait_for_change(timeout)
            .map(|outcome| match outcome {
                crate::system_proxy_watch::SystemProxyWatchOutcome::Changed => {
                    WatchOutcome::Changed
                }
                crate::system_proxy_watch::SystemProxyWatchOutcome::Stopped => {
                    WatchOutcome::Stopped
                }
                crate::system_proxy_watch::SystemProxyWatchOutcome::TimedOut => {
                    WatchOutcome::TimedOut
                }
            })
    }
}

#[cfg(windows)]
impl WatchFactory for NativeWatchFactory {
    fn open(&self) -> Result<OpenedWatch, String> {
        let watcher = crate::system_proxy_watch::WindowsSystemProxyChangeWatcher::open()?;
        let stop = Arc::new(NativeWatchStop(watcher.stop_handle()));
        Ok(OpenedWatch {
            driver: Box::new(NativeWatchDriver(watcher)),
            stop,
        })
    }
}

#[cfg(not(windows))]
impl WatchFactory for NativeWatchFactory {
    fn open(&self) -> Result<OpenedWatch, String> {
        Err("Windows system proxy watcher is only available on Windows".into())
    }
}

struct LiveWatch {
    stop: Arc<dyn WatchStop>,
    thread: JoinHandle<()>,
}

impl fmt::Debug for LiveWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LiveWatch").finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct AdapterState {
    shutdown: bool,
    expected: Option<SystemProxyConfig>,
    watch: Option<LiveWatch>,
}

pub struct WindowsSystemProxyAdapter {
    backend: Arc<dyn Backend>,
    watches: Arc<dyn WatchFactory>,
    events: Option<mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>>,
    lifecycle: tokio::sync::Mutex<()>,
    state: Mutex<AdapterState>,
    watch_timeout: Duration,
    flap_window: Duration,
    flap_limit: usize,
}

impl WindowsSystemProxyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_native_parts(None)
    }

    #[must_use]
    pub fn with_event_sender(sender: mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>) -> Self {
        Self::with_native_parts(Some(sender))
    }

    fn with_native_parts(
        events: Option<mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>>,
    ) -> Self {
        Self {
            backend: Arc::new(NativeBackend),
            watches: Arc::new(NativeWatchFactory),
            events,
            lifecycle: tokio::sync::Mutex::new(()),
            state: Mutex::new(AdapterState::default()),
            watch_timeout: DEFAULT_WATCH_TIMEOUT,
            flap_window: DEFAULT_FLAP_WINDOW,
            flap_limit: DEFAULT_FLAP_LIMIT,
        }
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let _lifecycle = self.lifecycle.lock().await;
        self.state
            .lock()
            .map_err(|_| "Windows system proxy adapter state mutex poisoned".to_string())?
            .shutdown = true;
        self.stop_watch()
    }

    fn ensure_running(&self) -> Result<(), CapabilityError> {
        if self
            .state
            .lock()
            .map_err(|_| apply_error("Windows system proxy adapter state mutex poisoned".into()))?
            .shutdown
        {
            Err(apply_error(
                "Windows system proxy adapter has been shut down".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn stop_watch(&self) -> Result<(), String> {
        let live = self
            .state
            .lock()
            .map_err(|_| "Windows system proxy adapter state mutex poisoned".to_string())?
            .watch
            .take();
        let Some(live) = live else {
            return Ok(());
        };
        live.stop.signal();
        live.thread
            .join()
            .map_err(|_| "Windows system proxy watch thread panicked".to_string())
    }

    fn start_watch(&self, expected: SystemProxyConfig) -> Result<(), String> {
        let opened = self.watches.open()?;
        let stop = opened.stop.clone();
        let backend = self.backend.clone();
        let events = self.events.clone();
        let watch_timeout = self.watch_timeout;
        let flap_window = self.flap_window;
        let flap_limit = self.flap_limit;
        let thread_expected = expected.clone();
        let thread = std::thread::Builder::new()
            .name("egrio-system-proxy-watch".into())
            .spawn(move || {
                run_watch_loop(
                    opened.driver,
                    backend,
                    thread_expected,
                    events,
                    watch_timeout,
                    flap_window,
                    flap_limit,
                );
            })
            .map_err(|error| format!("failed to spawn Windows system proxy watch: {error}"))?;

        let mut state = self
            .state
            .lock()
            .map_err(|_| "Windows system proxy adapter state mutex poisoned".to_string())?;
        if state.shutdown {
            stop.signal();
            drop(state);
            let _ = thread.join();
            return Err("Windows system proxy adapter has been shut down".into());
        }
        if state.watch.is_some() {
            stop.signal();
            drop(state);
            let _ = thread.join();
            return Err("Windows system proxy watch is already active".into());
        }
        state.expected = Some(expected);
        state.watch = Some(LiveWatch { stop, thread });
        Ok(())
    }

    #[cfg(test)]
    fn with_parts(
        backend: Arc<dyn Backend>,
        watches: Arc<dyn WatchFactory>,
        events: Option<mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>>,
        watch_timeout: Duration,
        flap_window: Duration,
        flap_limit: usize,
    ) -> Self {
        Self {
            backend,
            watches,
            events,
            lifecycle: tokio::sync::Mutex::new(()),
            state: Mutex::new(AdapterState::default()),
            watch_timeout,
            flap_window,
            flap_limit,
        }
    }
}

impl Default for WindowsSystemProxyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WindowsSystemProxyAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().ok();
        formatter
            .debug_struct("WindowsSystemProxyAdapter")
            .field(
                "shutdown",
                &state.as_ref().is_some_and(|state| state.shutdown),
            )
            .field(
                "watch_active",
                &state.as_ref().is_some_and(|state| state.watch.is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for WindowsSystemProxyAdapter {
    fn drop(&mut self) {
        let live = self
            .state
            .get_mut()
            .ok()
            .and_then(|state| state.watch.take());
        if let Some(live) = live {
            live.stop.signal();
            let _ = live.thread.join();
        }
    }
}

impl SystemProxyControl for WindowsSystemProxyAdapter {
    fn support(&self) -> CapabilitySupport {
        if cfg!(windows) {
            CapabilitySupport::Supported
        } else {
            CapabilitySupport::Unsupported {
                reason: "Windows system proxy control is only available on Windows".into(),
            }
        }
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.lifecycle.lock().await;
            self.ensure_running()?;
            let expected = config_from_settings(settings)?;
            let baseline = self.backend.status().map_err(observe_error)?;
            let payload = WindowsSystemProxyCheckpoint { baseline, expected };
            Ok(CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                payload: serde_json::to_value(payload).map_err(|error| {
                    CapabilityError::new(
                        CapabilityKind::SystemProxy,
                        CapabilityErrorCode::ObserveFailed,
                        error.to_string(),
                    )
                })?,
                rollback_payload: None,
            })
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.lifecycle.lock().await;
            self.ensure_running()?;
            self.stop_watch().map_err(apply_error)?;
            let config = config_from_settings(settings)?;
            let report = self.backend.apply(&config).map_err(apply_error)?;
            if !report.applied {
                return Err(apply_error(
                    "Windows system proxy backend did not apply the requested listener".into(),
                ));
            }
            let live = self.backend.status().map_err(apply_error)?;
            if !snapshot_matches_listener(&live, &config.proxy_server) {
                return Err(apply_error(
                    "Windows system proxy observation did not match the requested listener".into(),
                ));
            }
            self.state
                .lock()
                .map_err(|_| {
                    apply_error("Windows system proxy adapter state mutex poisoned".into())
                })?
                .expected = Some(config.clone());
            self.start_watch(config).map_err(apply_error)?;
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed: true,
                verified: true,
            })
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            let _lifecycle = self.lifecycle.lock().await;
            let expected = self
                .state
                .lock()
                .map_err(|_| {
                    observe_error("Windows system proxy adapter state mutex poisoned".into())
                })?
                .expected
                .clone();
            let live = self.backend.status().map_err(observe_error)?;
            Ok(CapabilityObservation {
                capability: CapabilityKind::SystemProxy,
                active: expected
                    .as_ref()
                    .is_some_and(|config| snapshot_matches_listener(&live, &config.proxy_server)),
                verified: live.backend == SystemProxyBackendKind::WindowsWinInet,
            })
        })
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.lifecycle.lock().await;
            let payload = decode_checkpoint(checkpoint)?;
            self.stop_watch().map_err(restore_error)?;
            let expected = self
                .state
                .lock()
                .map_err(|_| {
                    restore_error("Windows system proxy adapter state mutex poisoned".into())
                })?
                .expected
                .clone()
                .unwrap_or_else(|| payload.expected.clone());
            // Ownership must be observable before restore. Treating an
            // observation failure as "no live state" would blindly overwrite
            // a possible foreign takeover with the checkpoint baseline.
            let live = self.backend.status().map_err(restore_error)?;

            let changed = if !snapshot_matches_listener(&live, &expected.proxy_server) {
                false
            } else {
                let report = self
                    .backend
                    .restore(&payload.baseline)
                    .map_err(restore_error)?;
                if !report.restored {
                    return Err(restore_error(
                        "Windows system proxy backend did not restore the checkpoint baseline"
                            .into(),
                    ));
                }
                true
            };

            let final_snapshot = self.backend.status().map_err(restore_error)?;
            let verified = if changed {
                snapshots_have_same_effective_settings(&final_snapshot, &payload.baseline)
            } else {
                !snapshot_matches_listener(&final_snapshot, &expected.proxy_server)
            };
            if !verified {
                return Err(restore_error(
                    "Windows system proxy restore verification failed".into(),
                ));
            }
            self.state
                .lock()
                .map_err(|_| {
                    restore_error("Windows system proxy adapter state mutex poisoned".into())
                })?
                .expected = None;
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed,
                verified: true,
            })
        })
    }
}

fn decode_checkpoint(
    checkpoint: &CapabilityCheckpoint,
) -> Result<WindowsSystemProxyCheckpoint, CapabilityError> {
    if checkpoint.lease_key != PlatformLeaseKey::system_proxy()
        || checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION
    {
        return Err(CapabilityError::new(
            CapabilityKind::SystemProxy,
            CapabilityErrorCode::InvalidRequest,
            "checkpoint does not match the Windows system proxy contract",
        ));
    }
    let mut payload = decode_checkpoint_payload(checkpoint.payload.clone())?;
    if let Some(rollback_payload) = checkpoint.rollback_payload.clone() {
        payload.expected = decode_checkpoint_payload(rollback_payload)?.expected;
    }
    Ok(payload)
}

fn decode_checkpoint_payload(
    payload: serde_json::Value,
) -> Result<WindowsSystemProxyCheckpoint, CapabilityError> {
    let payload: WindowsSystemProxyCheckpoint =
        serde_json::from_value(payload).map_err(|error| {
            CapabilityError::new(
                CapabilityKind::SystemProxy,
                CapabilityErrorCode::InvalidRequest,
                error.to_string(),
            )
        })?;
    if payload.baseline.backend != SystemProxyBackendKind::WindowsWinInet {
        return Err(invalid_request(
            "Windows system proxy checkpoint contains a foreign backend baseline",
        ));
    }
    validate_expected_config(&payload.expected)?;
    Ok(payload)
}

fn config_from_settings(
    settings: &SystemProxySettings,
) -> Result<SystemProxyConfig, CapabilityError> {
    let endpoint = settings
        .http_proxy
        .or(settings.https_proxy)
        .ok_or_else(|| {
            invalid_request("Windows system proxy requires an HTTP or HTTPS endpoint")
        })?;
    if settings
        .http_proxy
        .zip(settings.https_proxy)
        .is_some_and(|(http, https)| http != https)
    {
        return Err(invalid_request(
            "the Windows WinINET backend requires one shared HTTP/HTTPS proxy endpoint",
        ));
    }
    if !endpoint.ip().is_loopback() {
        return Err(invalid_request(
            "the Windows system proxy endpoint must be a local Core loopback listener",
        ));
    }
    let mut config =
        system_proxy_config_from_listen_addr(&endpoint.to_string()).map_err(invalid_request)?;
    config.bypass = settings.bypass.clone();
    Ok(config)
}

fn validate_expected_config(config: &SystemProxyConfig) -> Result<(), CapabilityError> {
    let parsed =
        system_proxy_config_from_listen_addr(&config.listen_addr).map_err(invalid_request)?;
    if !parsed
        .host
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
        || parsed.proxy_server != config.proxy_server
        || parsed.host != config.host
        || parsed.port != config.port
    {
        return Err(invalid_request(
            "Windows system proxy checkpoint contains an invalid expected listener",
        ));
    }
    Ok(())
}

fn snapshot_matches_listener(snapshot: &SystemProxySnapshot, expected: &str) -> bool {
    if snapshot.backend != SystemProxyBackendKind::WindowsWinInet
        || setting_value(snapshot, "ProxyEnable") != Some("1")
    {
        return false;
    }
    let endpoints =
        proxy_server_endpoints(setting_value(snapshot, "ProxyServer").unwrap_or_default());
    !endpoints.is_empty()
        && endpoints
            .iter()
            .all(|endpoint| *endpoint == expected && endpoint_is_loopback(endpoint))
}

/// Compares two WinINET snapshots by *effective* proxy state, not raw
/// setting bytes. The per-connection options API cannot delete the inert
/// registry text behind a disabled source: restoring a baseline whose
/// `ProxyServer` was absent leaves the previously applied listener string
/// in the registry next to `ProxyEnable=0`, exactly like the Windows
/// Settings UI keeps the manual-proxy fields populated after the toggle
/// goes off. Values are therefore only compared for the sources that are
/// actually on in either snapshot.
fn snapshots_have_same_effective_settings(
    left: &SystemProxySnapshot,
    right: &SystemProxySnapshot,
) -> bool {
    if left.backend != right.backend {
        return false;
    }
    let enabled = |snapshot| setting_value(snapshot, "ProxyEnable") == Some("1");
    let auto_detect = |snapshot| setting_value(snapshot, "AutoDetect") == Some("1");
    let pac = |snapshot| setting_value(snapshot, "AutoConfigURL").filter(|url| !url.is_empty());

    if enabled(left) != enabled(right)
        || auto_detect(left) != auto_detect(right)
        || pac(left) != pac(right)
    {
        return false;
    }
    if enabled(left)
        && (setting_value(left, "ProxyServer") != setting_value(right, "ProxyServer")
            || setting_value(left, "ProxyOverride") != setting_value(right, "ProxyOverride"))
    {
        return false;
    }
    true
}

fn setting_value<'a>(snapshot: &'a SystemProxySnapshot, name: &str) -> Option<&'a str> {
    snapshot
        .settings
        .iter()
        .find(|setting| setting.name == name)
        .and_then(|setting| setting.value.as_deref())
}

fn proxy_server_endpoints(proxy_server: &str) -> Vec<&str> {
    proxy_server
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty()).then(|| part.split_once('=').map(|(_, value)| value).unwrap_or(part))
        })
        .collect()
}

fn endpoint_is_loopback(endpoint: &str) -> bool {
    let host = proxy_endpoint_host(endpoint);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn proxy_endpoint_host(endpoint: &str) -> &str {
    let endpoint = endpoint.trim();
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match endpoint.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => endpoint,
    }
}

fn run_watch_loop(
    mut driver: Box<dyn WatchDriver>,
    backend: Arc<dyn Backend>,
    expected: SystemProxyConfig,
    events: Option<mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>>,
    watch_timeout: Duration,
    flap_window: Duration,
    flap_limit: usize,
) {
    let mut policy = FlapPolicy::new(flap_window, flap_limit);
    loop {
        match driver.wait_for_change(watch_timeout) {
            Ok(WatchOutcome::Stopped) => break,
            Ok(WatchOutcome::Changed | WatchOutcome::TimedOut) => {
                let live = match backend.status() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        send_event(
                            &events,
                            WindowsSystemProxyGuardEvent::Yielded {
                                reason: format!(
                                    "failed to observe Windows system proxy guard state: {error}"
                                ),
                            },
                        );
                        break;
                    }
                };
                if snapshot_matches_listener(&live, &expected.proxy_server) {
                    continue;
                }
                let attempt = policy.record(Instant::now());
                if attempt <= policy.limit {
                    match backend.reassert(&expected) {
                        Ok(()) => send_event(
                            &events,
                            WindowsSystemProxyGuardEvent::Reasserted { attempt },
                        ),
                        Err(error) => {
                            send_event(
                                &events,
                                WindowsSystemProxyGuardEvent::Yielded {
                                    reason: format!(
                                        "failed to reassert Windows system proxy listener: {error}"
                                    ),
                                },
                            );
                            break;
                        }
                    }
                } else {
                    send_event(
                        &events,
                        WindowsSystemProxyGuardEvent::Yielded {
                            reason: format!(
                                "Windows system proxy was overwritten more than {} times within {}s",
                                policy.limit,
                                policy.window.as_secs()
                            ),
                        },
                    );
                    break;
                }
            }
            Err(error) => {
                send_event(
                    &events,
                    WindowsSystemProxyGuardEvent::Yielded {
                        reason: format!("Windows system proxy watcher failed: {error}"),
                    },
                );
                break;
            }
        }
    }
}

fn send_event(
    sender: &Option<mpsc::UnboundedSender<WindowsSystemProxyGuardEvent>>,
    event: WindowsSystemProxyGuardEvent,
) {
    if let Some(sender) = sender {
        let _ = sender.send(event);
    }
}

struct FlapPolicy {
    window: Duration,
    limit: usize,
    changes: VecDeque<Instant>,
}

impl FlapPolicy {
    fn new(window: Duration, limit: usize) -> Self {
        Self {
            window,
            limit,
            changes: VecDeque::new(),
        }
    }

    fn record(&mut self, now: Instant) -> usize {
        while self
            .changes
            .front()
            .is_some_and(|first| now.duration_since(*first) > self.window)
        {
            self.changes.pop_front();
        }
        self.changes.push_back(now);
        self.changes.len()
    }
}

fn invalid_request(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::InvalidRequest,
        message,
    )
}

fn observe_error(message: String) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::ObserveFailed,
        message,
    )
}

fn apply_error(message: String) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::ApplyFailed,
        message,
    )
}

fn restore_error(message: String) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::RestoreFailed,
        message,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;

    use egrio_platform::{SystemProxySettingKind, SystemProxySettingSnapshot};

    use super::*;

    #[derive(Debug)]
    struct MockBackend {
        state: Mutex<MockBackendState>,
        log: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Debug)]
    struct MockBackendState {
        snapshot: SystemProxySnapshot,
        status_error: Option<String>,
        restore_calls: usize,
        reassert_calls: usize,
    }

    impl MockBackend {
        fn new(snapshot: SystemProxySnapshot, log: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                state: Mutex::new(MockBackendState {
                    snapshot,
                    status_error: None,
                    restore_calls: 0,
                    reassert_calls: 0,
                }),
                log,
            }
        }

        fn set_snapshot(&self, snapshot: SystemProxySnapshot) {
            self.state.lock().unwrap().snapshot = snapshot;
        }

        fn snapshot(&self) -> SystemProxySnapshot {
            self.state.lock().unwrap().snapshot.clone()
        }

        fn set_status_error(&self, error: impl Into<String>) {
            self.state.lock().unwrap().status_error = Some(error.into());
        }

        fn restore_calls(&self) -> usize {
            self.state.lock().unwrap().restore_calls
        }

        fn reassert_calls(&self) -> usize {
            self.state.lock().unwrap().reassert_calls
        }

        fn record(&self, event: &str) {
            self.log.lock().unwrap().push(event.into());
        }
    }

    impl Backend for MockBackend {
        fn status(&self) -> Result<SystemProxySnapshot, String> {
            self.record("status");
            let state = self.state.lock().unwrap();
            match &state.status_error {
                Some(error) => Err(error.clone()),
                None => Ok(state.snapshot.clone()),
            }
        }

        fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxyApplyReport, String> {
            self.record("apply");
            let baseline = self.snapshot();
            self.set_snapshot(active_snapshot(&config.proxy_server));
            Ok(SystemProxyApplyReport {
                applied: true,
                config: config.clone(),
                snapshot: baseline,
                warnings: Vec::new(),
            })
        }

        fn restore(
            &self,
            snapshot: &SystemProxySnapshot,
        ) -> Result<SystemProxyRestoreReport, String> {
            self.record("restore");
            let mut state = self.state.lock().unwrap();
            state.restore_calls += 1;
            state.snapshot = snapshot.clone();
            Ok(SystemProxyRestoreReport {
                restored: true,
                snapshot: snapshot.clone(),
                warnings: Vec::new(),
            })
        }

        fn reassert(&self, config: &SystemProxyConfig) -> Result<(), String> {
            self.record("reassert");
            let mut state = self.state.lock().unwrap();
            state.reassert_calls += 1;
            state.snapshot = active_snapshot(&config.proxy_server);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ScriptedWatch {
        state: Mutex<ScriptedWatchState>,
        changed: Condvar,
        log: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Debug, Default)]
    struct ScriptedWatchState {
        outcomes: VecDeque<Result<WatchOutcome, String>>,
        stopped: bool,
    }

    impl ScriptedWatch {
        fn new(log: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                state: Mutex::new(ScriptedWatchState::default()),
                changed: Condvar::new(),
                log,
            }
        }

        fn push(&self, outcome: WatchOutcome) {
            self.state.lock().unwrap().outcomes.push_back(Ok(outcome));
            self.changed.notify_all();
        }
    }

    #[derive(Debug)]
    struct ScriptedWatchDriver(Arc<ScriptedWatch>);

    impl WatchDriver for ScriptedWatchDriver {
        fn wait_for_change(&mut self, timeout: Duration) -> Result<WatchOutcome, String> {
            let mut state = self.0.state.lock().unwrap();
            loop {
                if state.stopped {
                    self.0.log.lock().unwrap().push("watch.exit".into());
                    return Ok(WatchOutcome::Stopped);
                }
                if let Some(outcome) = state.outcomes.pop_front() {
                    return outcome;
                }
                let (next, wait) = self.0.changed.wait_timeout(state, timeout).unwrap();
                state = next;
                if wait.timed_out() {
                    return Ok(WatchOutcome::TimedOut);
                }
            }
        }
    }

    #[derive(Debug)]
    struct ScriptedWatchStop(Arc<ScriptedWatch>);

    impl WatchStop for ScriptedWatchStop {
        fn signal(&self) {
            self.0.log.lock().unwrap().push("watch.stop".into());
            self.0.state.lock().unwrap().stopped = true;
            self.0.changed.notify_all();
        }
    }

    #[derive(Debug)]
    struct ScriptedWatchFactory(Arc<ScriptedWatch>);

    impl WatchFactory for ScriptedWatchFactory {
        fn open(&self) -> Result<OpenedWatch, String> {
            Ok(OpenedWatch {
                driver: Box::new(ScriptedWatchDriver(self.0.clone())),
                stop: Arc::new(ScriptedWatchStop(self.0.clone())),
            })
        }
    }

    type AdapterParts = (
        WindowsSystemProxyAdapter,
        Arc<MockBackend>,
        Arc<ScriptedWatch>,
        mpsc::UnboundedReceiver<WindowsSystemProxyGuardEvent>,
        Arc<Mutex<Vec<String>>>,
    );

    fn adapter_parts() -> AdapterParts {
        let log = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(MockBackend::new(disabled_snapshot(), log.clone()));
        let watch = Arc::new(ScriptedWatch::new(log.clone()));
        let (events, receiver) = mpsc::unbounded_channel();
        let adapter = WindowsSystemProxyAdapter::with_parts(
            backend.clone(),
            Arc::new(ScriptedWatchFactory(watch.clone())),
            Some(events),
            Duration::from_secs(60),
            Duration::from_secs(10),
            3,
        );
        (adapter, backend, watch, receiver, log)
    }

    fn settings() -> SystemProxySettings {
        SystemProxySettings {
            http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
            https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
            bypass: vec!["localhost".into(), "<local>".into()],
        }
    }

    fn disabled_snapshot() -> SystemProxySnapshot {
        wininet_snapshot("0", None)
    }

    fn active_snapshot(listener: &str) -> SystemProxySnapshot {
        wininet_snapshot("1", Some(listener))
    }

    fn wininet_snapshot(enabled: &str, listener: Option<&str>) -> SystemProxySnapshot {
        SystemProxySnapshot {
            os: "windows".into(),
            backend: SystemProxyBackendKind::WindowsWinInet,
            captured_at_unix: 0,
            settings: vec![
                SystemProxySettingSnapshot {
                    name: "ProxyEnable".into(),
                    kind: SystemProxySettingKind::Dword,
                    value: Some(enabled.into()),
                },
                SystemProxySettingSnapshot {
                    name: "ProxyServer".into(),
                    kind: SystemProxySettingKind::String,
                    value: listener.map(str::to_string),
                },
            ],
            warnings: Vec::new(),
        }
    }

    #[tokio::test]
    async fn runtime_contract_prepares_applies_observes_and_restores() {
        let (adapter, backend, _watch, _events, _log) = adapter_parts();
        let checkpoint = adapter.prepare(&settings()).await.unwrap();
        let payload = decode_checkpoint(&checkpoint).unwrap();
        assert_eq!(payload.baseline, disabled_snapshot());
        assert_eq!(payload.expected.proxy_server, "127.0.0.1:7890");

        assert!(adapter.apply(&settings()).await.unwrap().verified);
        assert!(adapter.observe().await.unwrap().active);

        let restored = adapter.restore(&checkpoint).await.unwrap();
        assert!(restored.changed);
        assert!(restored.verified);
        assert_eq!(backend.snapshot(), disabled_snapshot());
        assert!(!adapter.observe().await.unwrap().active);
    }

    #[tokio::test]
    async fn persisted_reload_ownership_restores_the_original_baseline_after_restart() {
        let (adapter, backend, _watch, _events, log) = adapter_parts();
        let settings_a = settings();
        let settings_b = SystemProxySettings {
            http_proxy: Some("127.0.0.1:7891".parse().unwrap()),
            https_proxy: Some("127.0.0.1:7891".parse().unwrap()),
            bypass: vec!["localhost".into(), "<local>".into()],
        };
        let mut original = adapter.prepare(&settings_a).await.unwrap();
        adapter.apply(&settings_a).await.unwrap();
        let transition = adapter.prepare(&settings_b).await.unwrap();
        adapter.apply(&settings_b).await.unwrap();
        original.rollback_payload = Some(transition.payload);
        assert_eq!(backend.snapshot(), active_snapshot("127.0.0.1:7891"));
        drop(adapter);

        let recovery_watch = Arc::new(ScriptedWatch::new(log));
        let recovery = WindowsSystemProxyAdapter::with_parts(
            backend.clone(),
            Arc::new(ScriptedWatchFactory(recovery_watch)),
            None,
            Duration::from_secs(60),
            Duration::from_secs(10),
            3,
        );
        let restored = recovery.restore(&original).await.unwrap();

        assert!(restored.changed);
        assert!(restored.verified);
        assert_eq!(backend.snapshot(), disabled_snapshot());
    }

    #[tokio::test]
    async fn restore_preserves_a_foreign_takeover() {
        let (adapter, backend, _watch, _events, _log) = adapter_parts();
        let checkpoint = adapter.prepare(&settings()).await.unwrap();
        adapter.apply(&settings()).await.unwrap();
        let foreign = active_snapshot("127.0.0.1:10809");
        backend.set_snapshot(foreign.clone());

        let restored = adapter.restore(&checkpoint).await.unwrap();

        assert!(!restored.changed);
        assert!(restored.verified);
        assert_eq!(backend.restore_calls(), 0);
        assert_eq!(backend.snapshot(), foreign);
    }

    #[tokio::test]
    async fn restore_refuses_to_write_when_ownership_cannot_be_observed() {
        let (adapter, backend, _watch, _events, _log) = adapter_parts();
        let checkpoint = adapter.prepare(&settings()).await.unwrap();
        adapter.apply(&settings()).await.unwrap();
        backend.set_status_error("injected WinINET observation failure");

        let error = adapter.restore(&checkpoint).await.unwrap_err();

        assert_eq!(error.code, CapabilityErrorCode::RestoreFailed);
        assert!(error.message.contains("observation failure"));
        assert_eq!(backend.restore_calls(), 0);
    }

    #[tokio::test]
    async fn watcher_reasserts_three_times_then_yields_non_blockingly() {
        let (adapter, backend, watch, mut events, _log) = adapter_parts();
        adapter.apply(&settings()).await.unwrap();

        for attempt in 1..=3 {
            backend.set_snapshot(active_snapshot("127.0.0.1:10809"));
            watch.push(WatchOutcome::Changed);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), events.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                WindowsSystemProxyGuardEvent::Reasserted { attempt }
            );
        }
        backend.set_snapshot(active_snapshot("127.0.0.1:10809"));
        watch.push(WatchOutcome::Changed);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            WindowsSystemProxyGuardEvent::Yielded { .. }
        ));
        assert_eq!(backend.reassert_calls(), 3);
    }

    #[tokio::test]
    async fn restore_stops_and_joins_the_watcher_before_observe_and_write() {
        let (adapter, _backend, _watch, _events, log) = adapter_parts();
        let checkpoint = adapter.prepare(&settings()).await.unwrap();
        adapter.apply(&settings()).await.unwrap();
        log.lock().unwrap().clear();

        adapter.restore(&checkpoint).await.unwrap();

        let log = log.lock().unwrap().clone();
        let exited = log.iter().position(|event| event == "watch.exit").unwrap();
        let observed = log.iter().position(|event| event == "status").unwrap();
        let restored = log.iter().position(|event| event == "restore").unwrap();
        assert!(exited < observed);
        assert!(observed < restored);
    }

    #[tokio::test]
    async fn shutdown_latch_stops_the_watcher_and_rejects_future_apply() {
        let (adapter, _backend, _watch, _events, log) = adapter_parts();
        adapter.apply(&settings()).await.unwrap();

        adapter.shutdown().await.unwrap();

        let error = adapter.apply(&settings()).await.unwrap_err();
        assert_eq!(error.code, CapabilityErrorCode::ApplyFailed);
        let log = log.lock().unwrap();
        assert!(log.iter().any(|event| event == "watch.stop"));
        assert!(log.iter().any(|event| event == "watch.exit"));
    }

    #[test]
    fn listener_matching_is_exact_and_rejects_non_loopback_endpoints() {
        assert!(snapshot_matches_listener(
            &active_snapshot("127.0.0.1:7890"),
            "127.0.0.1:7890"
        ));
        assert!(!snapshot_matches_listener(
            &active_snapshot("127.0.0.1:10809"),
            "127.0.0.1:7890"
        ));
        assert!(!snapshot_matches_listener(
            &active_snapshot("proxy.example:8080"),
            "proxy.example:8080"
        ));
        assert!(!snapshot_matches_listener(
            &active_snapshot("http=127.0.0.1:7890;https=127.0.0.1:10809"),
            "127.0.0.1:7890"
        ));
    }

    #[test]
    fn effective_settings_ignore_inert_values_behind_disabled_sources() {
        // The real backend cannot delete the applied listener string when it
        // restores a baseline without `ProxyServer`; the text stays inert
        // next to `ProxyEnable=0` and must not fail restore verification.
        assert!(snapshots_have_same_effective_settings(
            &wininet_snapshot("0", Some("127.0.0.1:7890")),
            &disabled_snapshot(),
        ));
        // An empty PAC value is as off as an absent one.
        let mut with_empty_pac = disabled_snapshot();
        with_empty_pac.settings.push(SystemProxySettingSnapshot {
            name: "AutoConfigURL".into(),
            kind: SystemProxySettingKind::String,
            value: Some(String::new()),
        });
        assert!(snapshots_have_same_effective_settings(
            &with_empty_pac,
            &disabled_snapshot(),
        ));

        // Sources that are on still compare by value.
        assert!(!snapshots_have_same_effective_settings(
            &active_snapshot("127.0.0.1:7890"),
            &disabled_snapshot(),
        ));
        assert!(!snapshots_have_same_effective_settings(
            &active_snapshot("127.0.0.1:7890"),
            &active_snapshot("127.0.0.1:10809"),
        ));
        let mut with_pac = disabled_snapshot();
        with_pac.settings.push(SystemProxySettingSnapshot {
            name: "AutoConfigURL".into(),
            kind: SystemProxySettingKind::String,
            value: Some("http://pac.example/proxy.pac".into()),
        });
        assert!(!snapshots_have_same_effective_settings(
            &with_pac,
            &disabled_snapshot(),
        ));
        let mut with_auto_detect = disabled_snapshot();
        with_auto_detect.settings.push(SystemProxySettingSnapshot {
            name: "AutoDetect".into(),
            kind: SystemProxySettingKind::Dword,
            value: Some("1".into()),
        });
        assert!(!snapshots_have_same_effective_settings(
            &with_auto_detect,
            &disabled_snapshot(),
        ));
    }
}
