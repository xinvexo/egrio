use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use egrio_platform::{
    system_proxy_config_from_listen_addr, SystemProxyApplyReport, SystemProxyBackendKind,
    SystemProxyConfig, SystemProxySnapshot,
};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, PlatformLeaseKey,
    SystemProxyControl, SystemProxySettings,
};
use serde::{Deserialize, Serialize};

const CHECKPOINT_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MacosSystemProxyCheckpoint {
    baseline: SystemProxySnapshot,
    expected: SystemProxyConfig,
}

trait Backend: Send + Sync + fmt::Debug {
    fn status(&self) -> Result<SystemProxySnapshot, String>;
    fn apply(
        &self,
        config: &SystemProxyConfig,
        baseline: &SystemProxySnapshot,
    ) -> Result<SystemProxyApplyReport, String>;
    /// Restores the settings `expected` still holds to `baseline`; returns
    /// whether anything changed.
    fn restore_owned(
        &self,
        live: &SystemProxySnapshot,
        baseline: &SystemProxySnapshot,
        expected: &SystemProxyConfig,
        allow_partial: bool,
    ) -> Result<bool, String>;
}

#[derive(Debug)]
struct NativeBackend;

impl Backend for NativeBackend {
    fn status(&self) -> Result<SystemProxySnapshot, String> {
        super::system_proxy_status()
    }

    fn apply(
        &self,
        config: &SystemProxyConfig,
        baseline: &SystemProxySnapshot,
    ) -> Result<SystemProxyApplyReport, String> {
        super::system_proxy::apply_system_proxy_from_baseline(config, baseline)
    }

    fn restore_owned(
        &self,
        live: &SystemProxySnapshot,
        baseline: &SystemProxySnapshot,
        expected: &SystemProxyConfig,
        allow_partial: bool,
    ) -> Result<bool, String> {
        super::system_proxy::restore_owned_system_proxy(live, baseline, expected, allow_partial)
    }
}

/// The system-proxy layer: proxies on every network service. Egrio's tunnel
/// leaves the physical service primary, so they apply with TUN on as well.
#[derive(Clone)]
pub struct MacosSystemProxyAdapter {
    backend: Arc<dyn Backend>,
    state: Arc<Mutex<AdapterState>>,
}

#[derive(Debug, Default)]
struct AdapterState {
    expected: Option<SystemProxyConfig>,
    previous_expected: Option<SystemProxyConfig>,
    prepared: Option<MacosSystemProxyCheckpoint>,
    apply_incomplete: bool,
}

impl MacosSystemProxyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(NativeBackend),
            state: Arc::new(Mutex::new(AdapterState::default())),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            state: Arc::new(Mutex::new(AdapterState::default())),
        }
    }
}

impl Default for MacosSystemProxyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MacosSystemProxyAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSystemProxyAdapter")
            .finish_non_exhaustive()
    }
}

impl SystemProxyControl for MacosSystemProxyAdapter {
    fn support(&self) -> CapabilitySupport {
        if cfg!(target_os = "macos") {
            CapabilitySupport::Supported
        } else {
            CapabilitySupport::Unsupported {
                reason: "macOS system proxy control is only available on macOS".into(),
            }
        }
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let expected = config_from_settings(settings)?;
            let backend = self.backend.clone();
            let baseline = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| observe_error(error.to_string()))?
                .map_err(observe_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&baseline)
                .map_err(observe_error)?;
            if super::system_proxy::snapshot_has_enabled_authenticated_proxy(&baseline) {
                return Err(observe_error(
                    "macOS system proxy takeover refuses an enabled authenticated baseline".into(),
                ));
            }
            let checkpoint = MacosSystemProxyCheckpoint { baseline, expected };
            self.state
                .lock()
                .map_err(|_| observe_error("macOS system proxy state mutex poisoned".into()))?
                .prepared = Some(checkpoint.clone());
            Ok(CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                payload: serde_json::to_value(checkpoint).map_err(|error| {
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
            let config = config_from_settings(settings)?;
            let prepared = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| apply_error("macOS system proxy state mutex poisoned".into()))?;
                if state.apply_incomplete {
                    return Err(apply_error(
                        "macOS system proxy has an incomplete apply that must be restored first"
                            .into(),
                    ));
                }
                let prepared = state.prepared.take().ok_or_else(|| {
                    apply_error(
                        "macOS system proxy apply requires the checkpoint prepared for this transaction"
                            .into(),
                    )
                })?;
                if prepared.expected != config {
                    state.prepared = Some(prepared);
                    return Err(apply_error(
                        "macOS system proxy apply settings do not match the prepared checkpoint"
                            .into(),
                    ));
                }
                state.previous_expected = state.expected.clone();
                state.expected = Some(config.clone());
                state.apply_incomplete = true;
                prepared
            };
            let backend = self.backend.clone();
            let apply_config = config.clone();
            let apply_baseline = prepared.baseline.clone();
            let report =
                tokio::task::spawn_blocking(move || backend.apply(&apply_config, &apply_baseline))
                    .await
                    .map_err(|error| apply_error(error.to_string()))?
                    .map_err(apply_error)?;
            if report.config != config {
                return Err(apply_error(
                    "macOS system proxy backend applied an unexpected listener".into(),
                ));
            }
            if !super::system_proxy::snapshots_have_same_complete_settings(
                &report.snapshot,
                &prepared.baseline,
            ) {
                return Err(apply_error(
                    "macOS system proxy backend did not apply from the prepared baseline".into(),
                ));
            }
            let backend = self.backend.clone();
            let observed = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| apply_error(error.to_string()))?
                .map_err(apply_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&observed).map_err(apply_error)?;
            if !super::system_proxy::snapshot_matches_config(&observed, &report.config) {
                return Err(apply_error(
                    "macOS system proxy observation did not match the requested listener".into(),
                ));
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| apply_error("macOS system proxy state mutex poisoned".into()))?;
            state.previous_expected = None;
            state.apply_incomplete = false;
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed: report.applied,
                verified: report.applied,
            })
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            let backend = self.backend.clone();
            let snapshot = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| observe_error(error.to_string()))?
                .map_err(observe_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&snapshot)
                .map_err(observe_error)?;
            let expected = self
                .state
                .lock()
                .map_err(|_| observe_error("macOS system proxy state mutex poisoned".into()))?
                .expected
                .clone();
            Ok(CapabilityObservation {
                capability: CapabilityKind::SystemProxy,
                active: expected.as_ref().map_or_else(
                    || snapshot_is_active(&snapshot),
                    |config| super::system_proxy::snapshot_matches_config(&snapshot, config),
                ),
                verified: snapshot.backend == SystemProxyBackendKind::MacosNetworkSetup,
            })
        })
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let (baseline, checkpoint_expected) = decode_checkpoint(checkpoint)?;
            let (allow_partial, current_expected) = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| restore_error("macOS system proxy state mutex poisoned".into()))?;
                (state.apply_incomplete, state.expected.clone())
            };
            if current_expected.is_some_and(|current| current != checkpoint_expected) {
                return Err(invalid_checkpoint(
                    "checkpoint expected listener does not match the active adapter transaction",
                ));
            }
            let expected = checkpoint_expected;
            let backend = self.backend.clone();
            let live = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| restore_error(error.to_string()))?
                .map_err(restore_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&live).map_err(restore_error)?;
            let backend = self.backend.clone();
            let restore_baseline = baseline.clone();
            let restore_expected = expected.clone();
            let changed = tokio::task::spawn_blocking(move || {
                backend.restore_owned(&live, &restore_baseline, &restore_expected, allow_partial)
            })
            .await
            .map_err(|error| restore_error(error.to_string()))?
            .map_err(restore_error)?;
            let backend = self.backend.clone();
            let final_snapshot = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| restore_error(error.to_string()))?
                .map_err(restore_error)?;
            if super::system_proxy::snapshot_has_owned_residue(
                &final_snapshot,
                &baseline,
                &expected,
                allow_partial,
            ) {
                return Err(restore_error(
                    "macOS system proxy restore verification failed".into(),
                ));
            }
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| restore_error("macOS system proxy state mutex poisoned".into()))?;
                if allow_partial {
                    state.expected = state.previous_expected.take();
                } else {
                    state.expected = None;
                    state.previous_expected = None;
                }
                state.prepared = None;
                state.apply_incomplete = false;
            }
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed,
                verified: true,
            })
        })
    }
}

/// The baseline a checkpoint restores and the listener whose settings it
/// owns: the rolled-back transaction's when a reload left one, otherwise the
/// checkpoint's own.
fn decode_checkpoint(
    checkpoint: &CapabilityCheckpoint,
) -> Result<(SystemProxySnapshot, SystemProxyConfig), CapabilityError> {
    if checkpoint.lease_key != PlatformLeaseKey::system_proxy() {
        return Err(invalid_checkpoint("checkpoint uses a foreign lease key"));
    }
    if checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION {
        return Err(invalid_checkpoint(
            "checkpoint does not match the macOS system proxy contract",
        ));
    }
    let payload = decode_payload(checkpoint.payload.clone())?;
    let expected = match &checkpoint.rollback_payload {
        Some(rollback) => decode_payload(rollback.clone())?.expected,
        None => payload.expected,
    };
    Ok((payload.baseline, expected))
}

fn decode_payload(
    payload: serde_json::Value,
) -> Result<MacosSystemProxyCheckpoint, CapabilityError> {
    let payload: MacosSystemProxyCheckpoint =
        serde_json::from_value(payload).map_err(|error| invalid_checkpoint(error.to_string()))?;
    validate_expected_config(&payload.expected)?;
    validate_checkpoint_baseline(&payload.baseline)?;
    Ok(payload)
}

fn validate_checkpoint_baseline(baseline: &SystemProxySnapshot) -> Result<(), CapabilityError> {
    super::system_proxy::validate_system_proxy_snapshot(baseline).map_err(invalid_checkpoint)
}

fn validate_expected_config(config: &SystemProxyConfig) -> Result<(), CapabilityError> {
    let parsed =
        system_proxy_config_from_listen_addr(&config.listen_addr).map_err(invalid_checkpoint)?;
    if !parsed
        .host
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
        || parsed.port == 0
        || parsed.host != config.host
        || parsed.port != config.port
        || parsed.proxy_server != config.proxy_server
    {
        return Err(invalid_checkpoint(
            "macOS system proxy checkpoint contains an invalid expected listener",
        ));
    }
    super::system_proxy::validate_bypass_domains(&config.bypass).map_err(invalid_checkpoint)?;
    Ok(())
}

fn invalid_checkpoint(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::InvalidRequest,
        message,
    )
}

fn config_from_settings(
    settings: &SystemProxySettings,
) -> Result<SystemProxyConfig, CapabilityError> {
    let endpoint = settings
        .http_proxy
        .or(settings.https_proxy)
        .ok_or_else(|| {
            CapabilityError::new(
                CapabilityKind::SystemProxy,
                CapabilityErrorCode::InvalidRequest,
                "macOS system proxy settings require an HTTP or HTTPS endpoint",
            )
        })?;
    if settings
        .http_proxy
        .zip(settings.https_proxy)
        .is_some_and(|(http, https)| http != https)
    {
        return Err(CapabilityError::new(
            CapabilityKind::SystemProxy,
            CapabilityErrorCode::InvalidRequest,
            "the current macOS backend requires one shared HTTP/HTTPS proxy endpoint",
        ));
    }
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err(CapabilityError::new(
            CapabilityKind::SystemProxy,
            CapabilityErrorCode::InvalidRequest,
            "the macOS system proxy endpoint must be a non-zero local Core loopback listener",
        ));
    }
    super::system_proxy::validate_bypass_domains(&settings.bypass).map_err(|message| {
        CapabilityError::new(
            CapabilityKind::SystemProxy,
            CapabilityErrorCode::InvalidRequest,
            message,
        )
    })?;
    let host = endpoint.ip().to_string();
    let proxy_server = if host.contains(':') {
        format!("[{host}]:{}", endpoint.port())
    } else {
        format!("{host}:{}", endpoint.port())
    };
    Ok(SystemProxyConfig {
        listen_addr: endpoint.to_string(),
        host,
        port: endpoint.port(),
        proxy_server,
        bypass: settings.bypass.clone(),
    })
}

fn snapshot_is_active(snapshot: &SystemProxySnapshot) -> bool {
    super::system_proxy::snapshot_has_active_proxy(snapshot)
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
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use egrio_platform::{
        system_proxy_config_from_listen_addr, SystemProxySettingKind, SystemProxySettingSnapshot,
    };

    use super::*;
    use crate::system_proxy;

    #[derive(Debug)]
    struct MockBackend {
        snapshot: Mutex<SystemProxySnapshot>,
        applied: Mutex<Vec<SystemProxyConfig>>,
        fail_with_partial_apply: AtomicBool,
    }

    #[derive(Debug)]
    struct RejectMutationBackend {
        snapshot: SystemProxySnapshot,
    }

    #[derive(Debug)]
    struct RejectBackendAccessBackend;

    impl Backend for RejectBackendAccessBackend {
        fn status(&self) -> Result<SystemProxySnapshot, String> {
            panic!("invalid checkpoint must fail before backend observation")
        }

        fn apply(
            &self,
            _config: &SystemProxyConfig,
            _baseline: &SystemProxySnapshot,
        ) -> Result<SystemProxyApplyReport, String> {
            panic!("invalid checkpoint must fail before backend apply")
        }

        fn restore_owned(
            &self,
            _live: &SystemProxySnapshot,
            _baseline: &SystemProxySnapshot,
            _expected: &SystemProxyConfig,
            _allow_partial: bool,
        ) -> Result<bool, String> {
            panic!("invalid checkpoint must fail before selective restore")
        }
    }

    impl Backend for RejectMutationBackend {
        fn status(&self) -> Result<SystemProxySnapshot, String> {
            Ok(self.snapshot.clone())
        }

        fn apply(
            &self,
            _config: &SystemProxyConfig,
            _baseline: &SystemProxySnapshot,
        ) -> Result<SystemProxyApplyReport, String> {
            panic!("unknown checkpoint schema must fail before apply")
        }

        fn restore_owned(
            &self,
            _live: &SystemProxySnapshot,
            _baseline: &SystemProxySnapshot,
            _expected: &SystemProxyConfig,
            _allow_partial: bool,
        ) -> Result<bool, String> {
            panic!("unknown checkpoint schema must fail before selective restore")
        }
    }

    impl Backend for MockBackend {
        fn status(&self) -> Result<SystemProxySnapshot, String> {
            Ok(self.snapshot.lock().unwrap().clone())
        }

        fn apply(
            &self,
            config: &SystemProxyConfig,
            baseline: &SystemProxySnapshot,
        ) -> Result<SystemProxyApplyReport, String> {
            if !system_proxy::snapshots_have_same_complete_settings(&self.status()?, baseline) {
                return Err("system proxy baseline changed after prepare".into());
            }
            self.applied.lock().unwrap().push(config.clone());
            if self.fail_with_partial_apply.load(Ordering::SeqCst) {
                let mut partial = baseline.clone();
                partial
                    .settings
                    .iter_mut()
                    .find(|setting| setting.name.ends_with(":web"))
                    .expect("web setting")
                    .value = Some(format!(
                    "Enabled: Yes\nServer: {}\nPort: {}\nAuthenticated Proxy Enabled: 0\n",
                    config.host, config.port
                ));
                *self.snapshot.lock().unwrap() = partial;
                return Err("injected partial apply failure".into());
            }
            *self.snapshot.lock().unwrap() =
                proxy_snapshot(&config.host, config.port, true, &config.bypass);
            Ok(SystemProxyApplyReport {
                applied: true,
                config: config.clone(),
                snapshot: baseline.clone(),
                warnings: Vec::new(),
            })
        }

        fn restore_owned(
            &self,
            live: &SystemProxySnapshot,
            baseline: &SystemProxySnapshot,
            expected: &SystemProxyConfig,
            allow_partial: bool,
        ) -> Result<bool, String> {
            let (restored, changed) = system_proxy::selectively_restored_snapshot(
                live,
                baseline,
                expected,
                allow_partial,
            );
            *self.snapshot.lock().unwrap() = restored;
            Ok(changed)
        }
    }

    fn snapshot(enabled: bool) -> SystemProxySnapshot {
        proxy_snapshot("10.0.0.1", 8080, enabled, &["baseline.local".into()])
    }

    #[tokio::test]
    async fn runtime_contract_prepares_applies_observes_and_restores() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["localhost".into()],
        };

        let checkpoint = adapter.prepare(&settings).await.unwrap();
        assert_eq!(checkpoint.schema_version, CHECKPOINT_SCHEMA_VERSION);
        assert!(adapter.apply(&settings).await.unwrap().verified);
        assert_eq!(
            backend.applied.lock().unwrap()[0].proxy_server,
            "127.0.0.1:7890"
        );
        assert!(adapter.observe().await.unwrap().active);
        assert!(adapter.restore(&checkpoint).await.unwrap().verified);
        assert!(!adapter.observe().await.unwrap().active);
    }

    #[tokio::test]
    async fn apply_refuses_a_network_service_added_after_prepare() {
        let baseline = snapshot(false);
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(baseline.clone()),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["localhost".into()],
        };
        let checkpoint = adapter.prepare(&settings).await.unwrap();
        let mut changed = baseline.clone();
        changed.settings[0].value = Some("Wi-Fi\nEthernet".into());
        changed.settings.extend(
            baseline
                .settings
                .iter()
                .skip(1)
                .cloned()
                .map(|mut setting| {
                    setting.name = setting.name.replace("macos:Wi-Fi:", "macos:Ethernet:");
                    setting
                }),
        );
        *backend.snapshot.lock().unwrap() = changed.clone();

        let error = adapter.apply(&settings).await.unwrap_err();

        assert_eq!(error.code, CapabilityErrorCode::ApplyFailed);
        assert!(error.message.contains("baseline changed after prepare"));
        assert!(backend.applied.lock().unwrap().is_empty());
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &backend.snapshot.lock().unwrap(),
            &changed
        ));
        assert!(adapter.restore(&checkpoint).await.unwrap().verified);
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &backend.snapshot.lock().unwrap(),
            &changed
        ));
    }

    #[tokio::test]
    async fn apply_refuses_disabled_endpoint_metadata_changed_after_prepare() {
        let baseline = snapshot(false);
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(baseline.clone()),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["localhost".into()],
        };
        let checkpoint = adapter.prepare(&settings).await.unwrap();
        let mut changed = baseline.clone();
        for setting in changed.settings.iter_mut().filter(|setting| {
            setting.name.ends_with(":web")
                || setting.name.ends_with(":secure-web")
                || setting.name.ends_with(":socks")
        }) {
            setting.value = setting
                .value
                .as_ref()
                .map(|value| value.replace("Server: 10.0.0.1", "Server: 10.0.0.2"));
        }
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &baseline, &changed
        ));
        assert!(!system_proxy::snapshots_have_same_complete_settings(
            &baseline, &changed
        ));
        *backend.snapshot.lock().unwrap() = changed.clone();

        let error = adapter.apply(&settings).await.unwrap_err();

        assert_eq!(error.code, CapabilityErrorCode::ApplyFailed);
        assert!(backend.applied.lock().unwrap().is_empty());
        assert!(adapter.restore(&checkpoint).await.unwrap().verified);
        assert!(system_proxy::snapshots_have_same_complete_settings(
            &backend.snapshot.lock().unwrap(),
            &changed
        ));
    }

    #[tokio::test]
    async fn partial_apply_failure_is_recovered_from_the_incomplete_transaction() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(true),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["localhost".into()],
        };
        let checkpoint = adapter.prepare(&settings).await.unwrap();

        assert!(adapter.apply(&settings).await.is_err());
        let restored = adapter.restore(&checkpoint).await.unwrap();

        assert!(restored.changed);
        assert!(restored.verified);
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &backend.snapshot.lock().unwrap(),
            &snapshot(false)
        ));
    }

    #[tokio::test]
    async fn reload_apply_failure_uses_the_new_expected_listener_for_rollback() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings_a = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["a.local".into()],
        };
        let settings_b = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7891))),
            https_proxy: None,
            bypass: vec!["b.local".into()],
        };
        adapter.prepare(&settings_a).await.unwrap();
        adapter.apply(&settings_a).await.unwrap();
        let checkpoint_b = adapter.prepare(&settings_b).await.unwrap();
        backend
            .fail_with_partial_apply
            .store(true, Ordering::SeqCst);

        assert!(adapter.apply(&settings_b).await.is_err());
        let restored = adapter.restore(&checkpoint_b).await.unwrap();

        assert!(restored.changed);
        assert!(restored.verified);
        let expected_a = proxy_snapshot("127.0.0.1", 7890, true, &["a.local".into()]);
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &backend.snapshot.lock().unwrap(),
            &expected_a
        ));
        assert!(adapter.observe().await.unwrap().active);

        *backend.snapshot.lock().unwrap() =
            proxy_snapshot("127.0.0.1", 10809, true, &["foreign.local".into()]);
        assert!(!adapter.observe().await.unwrap().active);
    }

    #[tokio::test]
    async fn incomplete_apply_rejects_a_checkpoint_for_another_listener() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings_a = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["a.local".into()],
        };
        let settings_b = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7891))),
            https_proxy: None,
            bypass: vec!["b.local".into()],
        };
        adapter.prepare(&settings_a).await.unwrap();
        adapter.apply(&settings_a).await.unwrap();
        let checkpoint_b = adapter.prepare(&settings_b).await.unwrap();
        backend
            .fail_with_partial_apply
            .store(true, Ordering::SeqCst);
        assert!(adapter.apply(&settings_b).await.is_err());

        let mut corrupt = checkpoint_b.clone();
        corrupt.payload["expected"] =
            serde_json::to_value(system_proxy_config_from_listen_addr("127.0.0.1:10809").unwrap())
                .unwrap();
        let error = adapter.restore(&corrupt).await.unwrap_err();
        assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);

        assert!(adapter.restore(&checkpoint_b).await.unwrap().verified);
    }

    #[tokio::test]
    async fn persisted_reload_ownership_restores_the_original_baseline_after_restart() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings_a = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: vec!["a.local".into()],
        };
        let settings_b = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7891))),
            https_proxy: None,
            bypass: vec!["b.local".into()],
        };
        let mut original = adapter.prepare(&settings_a).await.unwrap();
        adapter.apply(&settings_a).await.unwrap();
        let transition = adapter.prepare(&settings_b).await.unwrap();
        adapter.apply(&settings_b).await.unwrap();
        original.rollback_payload = Some(transition.payload);

        let recovered = MacosSystemProxyAdapter::with_backend(backend.clone())
            .restore(&original)
            .await
            .unwrap();

        assert!(recovered.changed);
        assert!(recovered.verified);
        assert!(system_proxy::snapshots_have_same_effective_settings(
            &backend.snapshot.lock().unwrap(),
            &snapshot(false)
        ));
    }

    #[tokio::test]
    async fn restore_preserves_a_foreign_takeover() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            bypass: vec!["localhost".into()],
        };
        let checkpoint = adapter.prepare(&settings).await.unwrap();
        adapter.apply(&settings).await.unwrap();
        let foreign = proxy_snapshot("127.0.0.1", 10809, true, &["foreign.local".into()]);
        *backend.snapshot.lock().unwrap() = foreign.clone();

        let restored = adapter.restore(&checkpoint).await.unwrap();

        assert!(!restored.changed);
        assert!(restored.verified);
        assert_eq!(*backend.snapshot.lock().unwrap(), foreign);
    }

    #[tokio::test]
    async fn restore_cleans_owned_protocols_while_preserving_a_partial_takeover() {
        let backend = Arc::new(MockBackend {
            snapshot: Mutex::new(snapshot(false)),
            applied: Mutex::new(Vec::new()),
            fail_with_partial_apply: AtomicBool::new(false),
        });
        let adapter = MacosSystemProxyAdapter::with_backend(backend.clone());
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            bypass: vec!["localhost".into()],
        };
        let checkpoint = adapter.prepare(&settings).await.unwrap();
        adapter.apply(&settings).await.unwrap();
        let mut partial_takeover = backend.snapshot.lock().unwrap().clone();
        partial_takeover
            .settings
            .iter_mut()
            .find(|setting| setting.name.ends_with(":secure-web"))
            .expect("secure-web setting")
            .value = Some(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 10809\nAuthenticated Proxy Enabled: 0\n".into(),
        );
        *backend.snapshot.lock().unwrap() = partial_takeover.clone();

        let restored = adapter.restore(&checkpoint).await.unwrap();
        let final_snapshot = backend.snapshot.lock().unwrap().clone();

        assert!(restored.changed);
        assert!(restored.verified);
        assert_eq!(
            final_snapshot
                .settings
                .iter()
                .find(|setting| setting.name.ends_with(":web"))
                .and_then(|setting| setting.value.clone()),
            snapshot(false)
                .settings
                .iter()
                .find(|setting| setting.name.ends_with(":web"))
                .and_then(|setting| setting.value.clone())
        );
        assert_eq!(
            final_snapshot
                .settings
                .iter()
                .find(|setting| setting.name.ends_with(":secure-web"))
                .and_then(|setting| setting.value.clone()),
            partial_takeover
                .settings
                .iter()
                .find(|setting| setting.name.ends_with(":secure-web"))
                .and_then(|setting| setting.value.clone())
        );
        let mut expected = system_proxy_config_from_listen_addr("127.0.0.1:7890").unwrap();
        expected.bypass = vec!["localhost".into()];
        assert!(!system_proxy::snapshot_has_expected_residue(
            &final_snapshot,
            &snapshot(false),
            &expected
        ));
    }

    #[tokio::test]
    async fn unknown_checkpoint_schemas_fail_before_backend_mutation() {
        let adapter = MacosSystemProxyAdapter::with_backend(Arc::new(RejectMutationBackend {
            snapshot: snapshot(false),
        }));

        for schema_version in [1, 3, u16::MAX] {
            let checkpoint = CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version,
                payload: serde_json::json!({}),
                rollback_payload: None,
            };

            let error = adapter.restore(&checkpoint).await.unwrap_err();
            assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        }
    }

    #[tokio::test]
    async fn malformed_v2_expected_listener_fails_before_backend_access() {
        let adapter = MacosSystemProxyAdapter::with_backend(Arc::new(RejectBackendAccessBackend));
        let valid = system_proxy_config_from_listen_addr("127.0.0.1:7890").unwrap();
        let mut invalid_configs = Vec::new();

        let mut invalid_listen_addr = valid.clone();
        invalid_listen_addr.listen_addr = "not-a-listener".into();
        invalid_configs.push(invalid_listen_addr);

        let mut invalid_host = valid.clone();
        invalid_host.host = "127.0.0.2".into();
        invalid_configs.push(invalid_host);

        let mut invalid_port = valid.clone();
        invalid_port.port = 7891;
        invalid_configs.push(invalid_port);

        let mut invalid_proxy_server = valid.clone();
        invalid_proxy_server.proxy_server = "127.0.0.1:7891".into();
        invalid_configs.push(invalid_proxy_server);

        let mut invalid_bypass = valid;
        invalid_bypass.bypass = vec!["invalid bypass".into()];
        invalid_configs.push(invalid_bypass);

        invalid_configs.push(system_proxy_config_from_listen_addr("192.0.2.1:7890").unwrap());
        invalid_configs.push(system_proxy_config_from_listen_addr("127.0.0.1:0").unwrap());

        for expected in invalid_configs {
            let checkpoint = CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                payload: serde_json::to_value(MacosSystemProxyCheckpoint {
                    baseline: snapshot(false),
                    expected,
                })
                .unwrap(),
                rollback_payload: None,
            };

            let error = adapter.restore(&checkpoint).await.unwrap_err();
            assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        }
    }

    #[tokio::test]
    async fn malformed_checkpoint_baselines_fail_before_backend_access() {
        let adapter = MacosSystemProxyAdapter::with_backend(Arc::new(RejectBackendAccessBackend));
        let expected = system_proxy_config_from_listen_addr("127.0.0.1:7890").unwrap();
        let mut invalid_baselines = Vec::new();

        let mut no_services = snapshot(false);
        no_services.settings[0].value = Some(String::new());
        invalid_baselines.push(no_services);

        let mut missing_protocol = snapshot(false);
        missing_protocol
            .settings
            .retain(|setting| !setting.name.ends_with(":socks"));
        invalid_baselines.push(missing_protocol);

        let mut localized = snapshot(false);
        localized
            .settings
            .iter_mut()
            .find(|setting| setting.name.ends_with(":web"))
            .unwrap()
            .value = Some("Activado: No\nServidor: \nPuerto: 0\nProxy autenticado: 0\n".into());
        invalid_baselines.push(localized);

        for baseline in invalid_baselines {
            let checkpoint = CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                payload: serde_json::to_value(MacosSystemProxyCheckpoint {
                    baseline,
                    expected: expected.clone(),
                })
                .unwrap(),
                rollback_payload: None,
            };

            let error = adapter.restore(&checkpoint).await.unwrap_err();
            assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        }
    }

    #[tokio::test]
    async fn prepare_rejects_non_loopback_zero_port_and_authenticated_baselines() {
        let inaccessible =
            MacosSystemProxyAdapter::with_backend(Arc::new(RejectBackendAccessBackend));
        for endpoint in [
            SocketAddr::from(([192, 0, 2, 1], 7890)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        ] {
            let settings = SystemProxySettings {
                http_proxy: Some(endpoint),
                https_proxy: None,
                bypass: Vec::new(),
            };
            let error = inaccessible.prepare(&settings).await.unwrap_err();
            assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        }
        for bypass in ["invalid bypass", "\u{672a}\u{8bbe}\u{7f6e}\u{57df}"] {
            let settings = SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
                https_proxy: None,
                bypass: vec![bypass.into()],
            };
            let error = inaccessible.prepare(&settings).await.unwrap_err();
            assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        }

        let mut authenticated = snapshot(true);
        for setting in authenticated.settings.iter_mut().filter(|setting| {
            setting.name.ends_with(":web")
                || setting.name.ends_with(":secure-web")
                || setting.name.ends_with(":socks")
        }) {
            setting.value = setting.value.as_ref().map(|value| {
                value.replace(
                    "Authenticated Proxy Enabled: 0",
                    "Authenticated Proxy Enabled: 1\nUsername: user\nPassword: secret",
                )
            });
        }
        let adapter = MacosSystemProxyAdapter::with_backend(Arc::new(RejectMutationBackend {
            snapshot: authenticated,
        }));
        let settings = SystemProxySettings {
            http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
            https_proxy: None,
            bypass: Vec::new(),
        };
        let error = adapter.prepare(&settings).await.unwrap_err();
        assert_eq!(error.code, CapabilityErrorCode::ObserveFailed);
    }

    fn proxy_snapshot(
        host: &str,
        port: u16,
        enabled: bool,
        bypass: &[String],
    ) -> SystemProxySnapshot {
        let service = "Wi-Fi";
        let mut settings = vec![SystemProxySettingSnapshot {
            name: "macos:services".into(),
            kind: SystemProxySettingKind::String,
            value: Some(service.into()),
        }];
        for kind in ["web", "secure-web", "socks"] {
            settings.push(SystemProxySettingSnapshot {
                name: format!("macos:{service}:{kind}"),
                kind: SystemProxySettingKind::String,
                value: Some(format!(
                    "Enabled: {}\nServer: {host}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n",
                    if enabled { "Yes" } else { "No" }
                )),
            });
        }
        settings.push(SystemProxySettingSnapshot {
            name: format!("macos:{service}:bypass"),
            kind: SystemProxySettingKind::String,
            value: Some(bypass.join("\n")),
        });
        SystemProxySnapshot {
            os: "macos".into(),
            backend: SystemProxyBackendKind::MacosNetworkSetup,
            captured_at_unix: 0,
            settings,
            warnings: Vec::new(),
        }
    }
}
