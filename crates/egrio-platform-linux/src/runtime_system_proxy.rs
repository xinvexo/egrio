use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
use tokio::sync::Mutex as AsyncMutex;

const CHECKPOINT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LinuxSystemProxyCheckpoint {
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
    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<SystemProxyRestoreReport, String>;
    fn restore_owned(
        &self,
        live: &SystemProxySnapshot,
        baseline: &SystemProxySnapshot,
        expected: &SystemProxyConfig,
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

    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<SystemProxyRestoreReport, String> {
        super::system_proxy::restore_system_proxy(snapshot)
    }

    fn restore_owned(
        &self,
        live: &SystemProxySnapshot,
        baseline: &SystemProxySnapshot,
        expected: &SystemProxyConfig,
    ) -> Result<bool, String> {
        super::system_proxy::restore_owned_system_proxy(live, baseline, expected, true)
    }
}

#[derive(Clone)]
pub struct LinuxSystemProxyAdapter {
    backend: Arc<dyn Backend>,
    lifecycle: Arc<AsyncMutex<()>>,
    state: Arc<Mutex<AdapterState>>,
}

#[derive(Debug, Default)]
struct AdapterState {
    expected: Option<SystemProxyConfig>,
    previous_expected: Option<SystemProxyConfig>,
    prepared: Option<LinuxSystemProxyCheckpoint>,
    apply_incomplete: bool,
}

impl LinuxSystemProxyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(NativeBackend),
            lifecycle: Arc::new(AsyncMutex::new(())),
            state: Arc::new(Mutex::new(AdapterState::default())),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            lifecycle: Arc::new(AsyncMutex::new(())),
            state: Arc::new(Mutex::new(AdapterState::default())),
        }
    }
}

impl Default for LinuxSystemProxyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LinuxSystemProxyAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxSystemProxyAdapter")
            .finish_non_exhaustive()
    }
}

impl SystemProxyControl for LinuxSystemProxyAdapter {
    fn support(&self) -> CapabilitySupport {
        if cfg!(target_os = "linux") {
            CapabilitySupport::Supported
        } else {
            CapabilitySupport::Unsupported {
                reason: "Linux system proxy control is only available on Linux".into(),
            }
        }
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.lifecycle.lock().await;
            let expected = config_from_settings(settings)?;
            let backend = self.backend.clone();
            let baseline = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| observe_error(error.to_string()))?
                .map_err(observe_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&baseline)
                .map_err(observe_error)?;

            let checkpoint = LinuxSystemProxyCheckpoint { baseline, expected };
            self.state
                .lock()
                .map_err(|_| observe_error("Linux system proxy state mutex poisoned"))?
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
            let _lifecycle = self.lifecycle.lock().await;
            let config = config_from_settings(settings)?;
            let prepared = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| apply_error("Linux system proxy state mutex poisoned"))?;
                if state.apply_incomplete {
                    return Err(apply_error(
                        "Linux system proxy has an incomplete apply that must be restored first",
                    ));
                }
                let prepared = state.prepared.take().ok_or_else(|| {
                    apply_error(
                        "Linux system proxy apply requires the checkpoint prepared for this transaction",
                    )
                })?;
                if prepared.expected != config {
                    state.prepared = Some(prepared);
                    return Err(apply_error(
                        "Linux system proxy apply settings do not match the prepared checkpoint",
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
            if !report.applied || report.config != config {
                return Err(apply_error(
                    "Linux system proxy backend did not apply the requested listener",
                ));
            }
            if !super::system_proxy::snapshots_have_same_complete_settings(
                &report.snapshot,
                &prepared.baseline,
            ) {
                return Err(apply_error(
                    "Linux system proxy backend did not apply from the prepared baseline",
                ));
            }

            let backend = self.backend.clone();
            let observed = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| apply_error(error.to_string()))?
                .map_err(apply_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&observed).map_err(apply_error)?;
            if !super::system_proxy::snapshot_matches_config(&observed, &config) {
                return Err(apply_error(
                    "Linux system proxy observation did not match the requested listener",
                ));
            }

            let mut state = self
                .state
                .lock()
                .map_err(|_| apply_error("Linux system proxy state mutex poisoned"))?;
            state.previous_expected = None;
            state.apply_incomplete = false;
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
                .map_err(|_| observe_error("Linux system proxy state mutex poisoned"))?
                .expected
                .clone();
            Ok(CapabilityObservation {
                capability: CapabilityKind::SystemProxy,
                active: expected.as_ref().map_or_else(
                    || super::system_proxy::snapshot_has_active_proxy(&snapshot),
                    |config| super::system_proxy::snapshot_matches_config(&snapshot, config),
                ),
                verified: snapshot.backend == SystemProxyBackendKind::LinuxDesktopProxy,
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
            let (allow_partial, current_expected) = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| restore_error("Linux system proxy state mutex poisoned"))?;
                (state.apply_incomplete, state.expected.clone())
            };
            if let Some(current) = current_expected.as_ref() {
                if current != &payload.expected {
                    return Err(invalid_checkpoint(
                        "checkpoint expected listener does not match the active adapter transaction",
                    ));
                }
            }
            let expected = current_expected.unwrap_or_else(|| payload.expected.clone());

            let backend = self.backend.clone();
            let live = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| restore_error(error.to_string()))?
                .map_err(restore_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&live).map_err(restore_error)?;
            let already_baseline = super::system_proxy::snapshots_have_same_complete_settings(
                &live,
                &payload.baseline,
            );

            let changed = if already_baseline {
                false
            } else if allow_partial {
                let backend = self.backend.clone();
                let live_snapshot = live.clone();
                let baseline = payload.baseline.clone();
                let expected = expected.clone();
                tokio::task::spawn_blocking(move || {
                    backend.restore_owned(&live_snapshot, &baseline, &expected)
                })
                .await
                .map_err(|error| restore_error(error.to_string()))?
                .map_err(restore_error)?
            } else if super::system_proxy::snapshot_matches_config(&live, &expected) {
                let backend = self.backend.clone();
                let baseline = payload.baseline.clone();
                let report = tokio::task::spawn_blocking(move || backend.restore(&baseline))
                    .await
                    .map_err(|error| restore_error(error.to_string()))?
                    .map_err(restore_error)?;
                if !report.restored {
                    return Err(restore_error(
                        "Linux system proxy backend did not restore the checkpoint baseline",
                    ));
                }
                true
            } else {
                false
            };

            let backend = self.backend.clone();
            let final_snapshot = tokio::task::spawn_blocking(move || backend.status())
                .await
                .map_err(|error| restore_error(error.to_string()))?
                .map_err(restore_error)?;
            super::system_proxy::validate_system_proxy_snapshot(&final_snapshot)
                .map_err(restore_error)?;
            let verified = if allow_partial {
                !super::system_proxy::snapshot_has_owned_residue(
                    &final_snapshot,
                    &payload.baseline,
                    &expected,
                )
            } else if changed || already_baseline {
                super::system_proxy::snapshots_have_same_complete_settings(
                    &final_snapshot,
                    &payload.baseline,
                )
            } else {
                !super::system_proxy::snapshot_matches_config(&final_snapshot, &expected)
            };
            if !verified {
                return Err(restore_error(
                    "Linux system proxy restore verification failed",
                ));
            }

            let mut state = self
                .state
                .lock()
                .map_err(|_| restore_error("Linux system proxy state mutex poisoned"))?;
            if allow_partial {
                state.expected = state.previous_expected.take();
            } else {
                state.expected = None;
                state.previous_expected = None;
            }
            state.prepared = None;
            state.apply_incomplete = false;
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
) -> Result<LinuxSystemProxyCheckpoint, CapabilityError> {
    if checkpoint.lease_key != PlatformLeaseKey::system_proxy()
        || checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION
    {
        return Err(invalid_checkpoint(
            "checkpoint does not match the Linux system proxy contract",
        ));
    }
    let mut payload: LinuxSystemProxyCheckpoint =
        serde_json::from_value(checkpoint.payload.clone())
            .map_err(|error| invalid_checkpoint(error.to_string()))?;
    validate_checkpoint_payload(&payload)?;
    if let Some(rollback_payload) = checkpoint.rollback_payload.clone() {
        let rollback: LinuxSystemProxyCheckpoint = serde_json::from_value(rollback_payload)
            .map_err(|error| invalid_checkpoint(error.to_string()))?;
        validate_checkpoint_payload(&rollback)?;
        payload.expected = rollback.expected;
    }
    Ok(payload)
}

fn validate_checkpoint_payload(
    payload: &LinuxSystemProxyCheckpoint,
) -> Result<(), CapabilityError> {
    super::system_proxy::validate_system_proxy_snapshot(&payload.baseline)
        .map_err(invalid_checkpoint)?;
    validate_expected_config(&payload.expected)
}

fn config_from_settings(
    settings: &SystemProxySettings,
) -> Result<SystemProxyConfig, CapabilityError> {
    let endpoint = settings
        .http_proxy
        .or(settings.https_proxy)
        .ok_or_else(|| invalid_request("Linux system proxy requires an HTTP or HTTPS endpoint"))?;
    if settings
        .http_proxy
        .zip(settings.https_proxy)
        .is_some_and(|(http, https)| http != https)
    {
        return Err(invalid_request(
            "Linux system proxy requires one shared HTTP/HTTPS proxy endpoint",
        ));
    }
    if !endpoint.ip().is_loopback() {
        return Err(invalid_request(
            "Linux system proxy endpoint must be a local Core loopback listener",
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
            "Linux system proxy checkpoint contains an invalid expected listener",
        ));
    }
    Ok(())
}

fn invalid_checkpoint(message: impl Into<String>) -> CapabilityError {
    invalid_request(message)
}

fn invalid_request(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::InvalidRequest,
        message,
    )
}

fn observe_error(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::ObserveFailed,
        message,
    )
}

fn apply_error(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::ApplyFailed,
        message,
    )
}

fn restore_error(message: impl Into<String>) -> CapabilityError {
    CapabilityError::new(
        CapabilityKind::SystemProxy,
        CapabilityErrorCode::RestoreFailed,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use egrio_platform::{
        system_proxy_config_from_listen_addr, SystemProxySettingKind, SystemProxySettingSnapshot,
    };
    use std::collections::BTreeMap;

    #[derive(Debug)]
    struct MockBackend {
        state: Mutex<MockBackendState>,
    }

    #[derive(Debug)]
    struct MockBackendState {
        live: SystemProxySnapshot,
        applied_baselines: Vec<SystemProxySnapshot>,
        restore_calls: usize,
    }

    impl MockBackend {
        fn new(live: SystemProxySnapshot) -> Self {
            Self {
                state: Mutex::new(MockBackendState {
                    live,
                    applied_baselines: Vec::new(),
                    restore_calls: 0,
                }),
            }
        }

        fn live(&self) -> SystemProxySnapshot {
            self.state.lock().expect("mock state").live.clone()
        }
    }

    impl Backend for MockBackend {
        fn status(&self) -> Result<SystemProxySnapshot, String> {
            Ok(self.live())
        }

        fn apply(
            &self,
            config: &SystemProxyConfig,
            baseline: &SystemProxySnapshot,
        ) -> Result<SystemProxyApplyReport, String> {
            let mut state = self.state.lock().expect("mock state");
            if !super::super::system_proxy::snapshots_have_same_complete_settings(
                &state.live,
                baseline,
            ) {
                return Err("mock detected baseline drift".into());
            }
            state.applied_baselines.push(baseline.clone());
            state.live = snapshot_for_config(config);
            Ok(SystemProxyApplyReport {
                applied: true,
                config: config.clone(),
                snapshot: baseline.clone(),
                warnings: Vec::new(),
            })
        }

        fn restore(
            &self,
            snapshot: &SystemProxySnapshot,
        ) -> Result<SystemProxyRestoreReport, String> {
            let mut state = self.state.lock().expect("mock state");
            state.restore_calls += 1;
            state.live = snapshot.clone();
            Ok(SystemProxyRestoreReport {
                restored: true,
                snapshot: snapshot.clone(),
                warnings: Vec::new(),
            })
        }

        fn restore_owned(
            &self,
            live: &SystemProxySnapshot,
            baseline: &SystemProxySnapshot,
            expected: &SystemProxyConfig,
        ) -> Result<bool, String> {
            let (target, changed) = super::super::system_proxy::selectively_restored_snapshot(
                live, baseline, expected,
            )?;
            let mut state = self.state.lock().expect("mock state");
            if changed {
                state.live = target;
            }
            Ok(changed)
        }
    }

    fn snapshot_for_config(config: &SystemProxyConfig) -> SystemProxySnapshot {
        snapshot_from_values(&super::super::system_proxy::expected_setting_values(config))
    }

    fn snapshot_from_values(values: &BTreeMap<String, String>) -> SystemProxySnapshot {
        SystemProxySnapshot {
            os: "linux".into(),
            backend: SystemProxyBackendKind::LinuxDesktopProxy,
            captured_at_unix: 1,
            settings: super::super::system_proxy::GNOME_PROXY_SETTINGS
                .iter()
                .map(|(schema, key)| {
                    let name = format!("{schema}:{key}");
                    SystemProxySettingSnapshot {
                        value: Some(
                            values
                                .get(&name)
                                .cloned()
                                .unwrap_or_else(|| "'baseline'".into()),
                        ),
                        name,
                        kind: SystemProxySettingKind::String,
                    }
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    fn settings() -> SystemProxySettings {
        SystemProxySettings {
            http_proxy: Some("127.0.0.1:51820".parse().expect("endpoint")),
            https_proxy: Some("127.0.0.1:51820".parse().expect("endpoint")),
            bypass: vec!["localhost".into()],
        }
    }

    #[tokio::test]
    async fn prepare_apply_observe_restore_round_trip_uses_one_baseline() {
        let baseline_values =
            BTreeMap::from([("org.gnome.system.proxy:mode".into(), "'none'".into())]);
        let backend = Arc::new(MockBackend::new(snapshot_from_values(&baseline_values)));
        let adapter = LinuxSystemProxyAdapter::with_backend(backend.clone());

        let checkpoint = adapter.prepare(&settings()).await.expect("prepare");
        let report = adapter.apply(&settings()).await.expect("apply");
        assert!(report.verified);
        assert!(adapter.observe().await.expect("observe").active);
        assert_eq!(
            backend.state.lock().expect("mock state").applied_baselines,
            vec![snapshot_from_values(&baseline_values)]
        );

        let restored = adapter.restore(&checkpoint).await.expect("restore");
        assert!(restored.changed);
        assert_eq!(backend.live(), snapshot_from_values(&baseline_values));
    }

    #[tokio::test]
    async fn apply_rejects_settings_that_do_not_match_prepared_checkpoint() {
        let backend = Arc::new(MockBackend::new(snapshot_for_config(
            &system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config"),
        )));
        let adapter = LinuxSystemProxyAdapter::with_backend(backend);
        adapter.prepare(&settings()).await.expect("prepare");
        let changed = SystemProxySettings {
            http_proxy: Some("127.0.0.1:51821".parse().expect("endpoint")),
            https_proxy: Some("127.0.0.1:51821".parse().expect("endpoint")),
            bypass: vec!["localhost".into()],
        };
        let error = adapter.apply(&changed).await.expect_err("mismatched apply");
        assert_eq!(error.code, CapabilityErrorCode::ApplyFailed);
    }

    #[tokio::test]
    async fn restore_does_not_overwrite_a_foreign_takeover() {
        let baseline = snapshot_from_values(&BTreeMap::from([(
            "org.gnome.system.proxy:mode".into(),
            "'none'".into(),
        )]));
        let backend = Arc::new(MockBackend::new(baseline.clone()));
        let adapter = LinuxSystemProxyAdapter::with_backend(backend.clone());
        let checkpoint = adapter.prepare(&settings()).await.expect("prepare");
        adapter.apply(&settings()).await.expect("apply");
        {
            let mut state = backend.state.lock().expect("mock state");
            let mut foreign = state.live.clone();
            foreign.settings[0].value = Some("'auto'".into());
            state.live = foreign;
        }
        let restored = adapter.restore(&checkpoint).await.expect("foreign restore");
        assert!(!restored.changed);
        assert_eq!(backend.live().settings[0].value.as_deref(), Some("'auto'"));
        assert_eq!(backend.state.lock().expect("mock state").restore_calls, 0);
    }
}
