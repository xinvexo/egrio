//! Runtime-owned configuration operations. Product persistence is a callback;
//! this layer neither reads YAML nor permits a live update to restart resources.
use super::*;
use egrio_core::{CorePolicyState, CorePolicyUpdate, RetirementTicket};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

const RETIRE_LIMIT: usize = 16;
const RETIRE_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationClass {
    LiveUpdate,
    ComponentReload,
    RuntimeRestart,
    TopologyChange,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationOperation {
    SelectGroup,
    TrafficPolicy,
    Ipv6,
    AllowLan,
    ReplaceProfile,
    ListenerParameters,
    CaptureTopology,
}
impl ConfigurationOperation {
    pub fn class(self) -> ConfigurationClass {
        match self {
            Self::SelectGroup | Self::TrafficPolicy | Self::Ipv6 => ConfigurationClass::LiveUpdate,
            Self::AllowLan => ConfigurationClass::ComponentReload,
            Self::ReplaceProfile | Self::ListenerParameters => ConfigurationClass::RuntimeRestart,
            Self::CaptureTopology => ConfigurationClass::TopologyChange,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigurationChange {
    Policy(CorePolicyUpdate),
    ListenerScope(SocketAddr),
}
impl RuntimeConfigurationChange {
    pub fn operation(&self) -> ConfigurationOperation {
        match self {
            Self::Policy(CorePolicyUpdate::SelectGroup { .. }) => {
                ConfigurationOperation::SelectGroup
            }
            Self::Policy(CorePolicyUpdate::TrafficPolicy { .. }) => {
                ConfigurationOperation::TrafficPolicy
            }
            Self::Policy(CorePolicyUpdate::Ipv6Enabled(_)) => ConfigurationOperation::Ipv6,
            Self::ListenerScope(_) => ConfigurationOperation::AllowLan,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationPhase {
    NoChange,
    SavedStopped,
    Rejected,
    PendingApply,
    Applied,
    AppliedCleanupPending,
    Degraded,
}
impl ConfigurationPhase {
    pub fn is_applied(self) -> bool {
        matches!(
            self,
            Self::NoChange | Self::Applied | Self::AppliedCleanupPending
        )
    }
    fn blocks_updates(self) -> bool {
        matches!(self, Self::PendingApply | Self::Degraded)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfigurationReport {
    pub operation_id: String,
    pub operation: ConfigurationOperation,
    pub class: ConfigurationClass,
    pub phase: ConfigurationPhase,
    pub generation: RuntimeGeneration,
    pub effective_policy: Option<CorePolicyState>,
    pub effective_listener: Option<SocketAddr>,
    pub error: Option<String>,
}
impl RuntimeConfigurationReport {
    fn fail(mut self, phase: ConfigurationPhase, error: impl ToString) -> Self {
        self.phase = phase;
        self.error = Some(error.to_string());
        self
    }
}
#[derive(Debug, Default)]
pub(super) struct ConfigurationState {
    pub last: Option<RuntimeConfigurationReport>,
    retired: BTreeMap<String, RetirementTicket>,
}
pub(super) struct ConfigurationStopCompletion<'a>(pub(super) &'a Runtime);
impl Drop for ConfigurationStopCompletion<'_> {
    fn drop(&mut self) {
        let error = (self.0.status().state != RuntimeState::Stopped)
            .then(|| "Runtime stop did not finish restoring its resources".to_string());
        // Declared after the operation guard, so this publishes before that
        // guard is released and a later start can establish a new generation.
        self.0.configuration_stopped(error);
    }
}

struct ConfigurationPanicCompletion<'a> {
    runtime: &'a Runtime,
    report: RuntimeConfigurationReport,
}
impl Drop for ConfigurationPanicCompletion<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Publish before the transaction gate unwinds. The caller's
            // JoinError may be delivered after a later stop/start, so it must
            // never mutate the then-current generation's status.
            self.runtime
                .publish_configuration_report(self.report.clone().fail(
                    ConfigurationPhase::Degraded,
                    "configuration task panicked before completing its operation",
                ));
        }
    }
}

impl Runtime {
    /// Called under the operation gate by every path that can mutate the
    /// live Core or its participants. A retained reconciliation candidate
    /// must not race another public mutation entry point.
    pub(super) fn configuration_update_admission(&self) -> Result<(), String> {
        let status = self.status();
        if status.state != RuntimeState::Running {
            return Ok(());
        }
        let state = self.configuration.lock().expect("configuration state");
        if let Some(last) = state
            .last
            .as_ref()
            .filter(|last| last.generation == status.generation && last.phase.blocks_updates())
        {
            return Err(format!(
                "configuration operation {} requires reconciliation: {:?}",
                last.operation_id, last.phase
            ));
        }
        Ok(())
    }
    pub(super) fn configuration_stopped(&self, error: Option<String>) {
        let mut state = self.configuration.lock().expect("configuration state");
        if error.is_none() {
            state.retired.clear();
        }
        if let Some(last) = state.last.as_mut() {
            last.phase = if error.is_some() {
                ConfigurationPhase::Degraded
            } else {
                ConfigurationPhase::SavedStopped
            };
            last.error = error;
            last.effective_policy = None;
            last.effective_listener = None;
            self.configuration_events.send_replace(Some(last.clone()));
        }
    }
    pub fn configuration_status(&self) -> Option<RuntimeConfigurationReport> {
        self.configuration
            .lock()
            .expect("configuration state")
            .last
            .clone()
    }
    pub fn configuration_events(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<RuntimeConfigurationReport>> {
        self.configuration_events.subscribe()
    }
    pub fn effective_core_policy(&self) -> Option<CorePolicyState> {
        if !matches!(
            self.status().state,
            RuntimeState::Preparing | RuntimeState::Running
        ) {
            return None;
        }
        self.core
            .packet_device()
            .map(|device| device.observe_policy())
    }
    fn configuration_report(
        &self,
        change: &RuntimeConfigurationChange,
    ) -> RuntimeConfigurationReport {
        RuntimeConfigurationReport {
            operation_id: Uuid::new_v4().to_string(),
            operation: change.operation(),
            class: change.operation().class(),
            phase: ConfigurationPhase::Rejected,
            generation: self.status().generation,
            effective_policy: self.effective_core_policy(),
            effective_listener: self.core_listener_addr(),
            error: None,
        }
    }
    fn publish_configuration_report(
        &self,
        mut report: RuntimeConfigurationReport,
    ) -> RuntimeConfigurationReport {
        report.effective_policy = self.effective_core_policy();
        report.effective_listener = self.core_listener_addr();
        self.configuration.lock().expect("configuration state").last = Some(report.clone());
        self.configuration_events.send_replace(Some(report.clone()));
        report
    }
    /// Once admitted, the operation belongs to the Runtime even if its caller
    /// closes a window or abandons the response future.
    pub async fn configure<F>(
        self: &Arc<Self>,
        change: RuntimeConfigurationChange,
        persist: F,
    ) -> RuntimeConfigurationReport
    where
        F: FnOnce() -> Result<(), String> + Send + 'static,
    {
        let permit = match self.configuration_admission.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return self.configuration_report(&change).fail(
                    ConfigurationPhase::Rejected,
                    "configuration request queue is full",
                )
            }
        };
        let runtime = Arc::clone(self);
        let expected_generation = self.status().generation;
        let expected_core_generation = self.domain_status().core.map(|core| core.generation);
        let fallback = self.configuration_report(&change);
        let operation_id = fallback.operation_id.clone();
        match self
            .spawn(async move {
                let _permit = permit;
                runtime
                    .configure_transaction(
                        change,
                        persist,
                        expected_generation,
                        expected_core_generation,
                        operation_id,
                    )
                    .await
            })
            .await
        {
            Ok(report) => report,
            Err(error) => fallback.fail(ConfigurationPhase::Degraded, error),
        }
    }
    async fn configure_transaction<F>(
        self: &Arc<Self>,
        change: RuntimeConfigurationChange,
        persist: F,
        expected_generation: RuntimeGeneration,
        expected_core_generation: Option<crate::RuntimeCoreGeneration>,
        operation_id: String,
    ) -> RuntimeConfigurationReport
    where
        F: FnOnce() -> Result<(), String> + Send + 'static,
    {
        let _operation = self.operation.lock().await;
        let mut report = self.configuration_report(&change);
        report.operation_id = operation_id;
        let _panic_completion = ConfigurationPanicCompletion {
            runtime: self,
            report: report.clone(),
        };
        if report.generation != expected_generation
            || self.domain_status().core.map(|core| core.generation) != expected_core_generation
        {
            return report.fail(
                ConfigurationPhase::Rejected,
                "Runtime/Core generation changed while configuration was queued",
            );
        }
        if let Err(error) = self.configuration_update_admission() {
            // Preserve the operation whose uncertainty blocks admission.
            return report.fail(ConfigurationPhase::Rejected, error);
        }
        let backlog_full = {
            let mut state = self.configuration.lock().expect("configuration state");
            state.retired.retain(|_, ticket| !ticket.is_complete());
            state.retired.len() >= RETIRE_LIMIT
        };
        if backlog_full {
            return report.fail(
                ConfigurationPhase::Rejected,
                "configuration cleanup backlog is full",
            );
        }
        match self.core_update_admission() {
            Ok(false) => {
                return self.publish_configuration_report(match persist_blocking(persist).await {
                    Ok(()) => {
                        let mut report = report;
                        report.phase = ConfigurationPhase::SavedStopped;
                        report
                    }
                    Err(error) => report.fail(ConfigurationPhase::Rejected, error),
                })
            }
            Err(error) => {
                return self
                    .publish_configuration_report(report.fail(ConfigurationPhase::Rejected, error))
            }
            Ok(true) => {}
        }
        let Some(device) = self.core.packet_device() else {
            return self.publish_configuration_report(
                report.fail(ConfigurationPhase::Rejected, "running Core is unavailable"),
            );
        };
        match change {
            RuntimeConfigurationChange::ListenerScope(address) => {
                self.configure_listener(address, persist, report).await
            }
            RuntimeConfigurationChange::Policy(update) => {
                let prepared = match device.prepare_policy_update(&[update.clone()]) {
                    Ok(value) => value,
                    Err(error) => {
                        return self.publish_configuration_report(
                            report.fail(ConfigurationPhase::Rejected, error),
                        )
                    }
                };
                if let Err(error) = persist_blocking(persist).await {
                    return self.publish_configuration_report(
                        report.fail(ConfigurationPhase::Rejected, error),
                    );
                }
                if !prepared.is_changed() {
                    let mut report = report;
                    report.phase = ConfigurationPhase::NoChange;
                    return self.publish_configuration_report(report);
                }
                match device.apply_policy_update(prepared) {
                    Ok(value) => self.complete_configuration(report, value.retirement).await,
                    Err(error) => self.publish_configuration_report(
                        report.fail(ConfigurationPhase::PendingApply, error),
                    ),
                }
            }
        }
    }

    async fn complete_configuration(
        self: &Arc<Self>,
        mut report: RuntimeConfigurationReport,
        retirement: RetirementTicket,
    ) -> RuntimeConfigurationReport {
        report.phase = ConfigurationPhase::Applied;
        if !retirement.wait(RETIRE_WAIT).await {
            report.phase = ConfigurationPhase::AppliedCleanupPending;
            report.error =
                Some("configuration applied; previous connections are still draining".into());
            self.retain_retirement(&report.operation_id, retirement);
        }
        self.publish_configuration_report(report)
    }

    fn retain_retirement(self: &Arc<Self>, operation_id: &str, ticket: RetirementTicket) {
        self.configuration
            .lock()
            .expect("configuration state")
            .retired
            .insert(operation_id.to_owned(), ticket.clone());
        let operation_id = operation_id.to_owned();
        let owner = Arc::downgrade(self);
        self.spawn(async move {
            loop {
                let complete = ticket.wait(Duration::from_secs(1)).await;
                let Some(runtime) = owner.upgrade() else {
                    return;
                };
                // The foreground transaction publishes cleanup-pending while
                // still holding this gate. Completion must publish after it,
                // even if the final writer finishes immediately after timeout.
                let _operation = runtime.operation.lock().await;
                if matches!(
                    runtime.status().state,
                    RuntimeState::Created | RuntimeState::Stopped
                ) {
                    return;
                }
                if complete {
                    let mut state = runtime.configuration.lock().expect("configuration state");
                    state.retired.remove(&operation_id);
                    if let Some(last) = state.last.as_mut().filter(|last| {
                        last.operation_id == operation_id
                            && last.phase == ConfigurationPhase::AppliedCleanupPending
                    }) {
                        last.phase = ConfigurationPhase::Applied;
                        last.error = None;
                        runtime
                            .configuration_events
                            .send_replace(Some(last.clone()));
                    }
                    return;
                }
            }
        });
    }
}

impl Runtime {
    /// The spec records the listener address asked for: while a stand-in
    /// port serves, that is the bound scope on the requested port, so a
    /// later start asks for the requested port again.
    fn requested_listener(&self, bound: SocketAddr) -> SocketAddr {
        match self
            .core
            .status()
            .listener_fallback
            .and_then(|fallback| fallback.requested.parse::<SocketAddr>().ok())
        {
            Some(requested) => SocketAddr::new(bound.ip(), requested.port()),
            None => bound,
        }
    }

    async fn configure_listener<F>(
        self: &Arc<Self>,
        address: SocketAddr,
        persist: F,
        mut report: RuntimeConfigurationReport,
    ) -> RuntimeConfigurationReport
    where
        F: FnOnce() -> Result<(), String> + Send + 'static,
    {
        let Some(previous) = self.core_listener_addr() else {
            return self.publish_configuration_report(
                report.fail(ConfigurationPhase::Rejected, "Core listener is unavailable"),
            );
        };
        // While a stand-in port serves for the requested one, a new scope for
        // the requested port means the same scope change on the stand-in.
        let address = match self.core.status().listener_fallback {
            Some(fallback)
                if fallback
                    .requested
                    .parse::<SocketAddr>()
                    .is_ok_and(|requested| requested.port() == address.port()) =>
            {
                SocketAddr::new(address.ip(), previous.port())
            }
            _ => address,
        };
        if previous.port() != address.port() {
            return self.publish_configuration_report(report.fail(
                ConfigurationPhase::Rejected,
                "changing the proxy port requires Runtime restart",
            ));
        }
        if !self.core.listener_scope_cleanup_complete() {
            return self.publish_configuration_report(report.fail(
                ConfigurationPhase::Rejected,
                "previous listener connections are still draining",
            ));
        }
        let spec = self.spec();
        let proxy_update = match spec.platform.system_proxy.as_ref() {
            Some(proxy) => match (proxy.resolve(Some(previous)), proxy.resolve(Some(address))) {
                (Ok(before), Ok(after)) if before != after => Some(after),
                (Ok(_), Ok(_)) => None,
                _ => {
                    return self.publish_configuration_report(report.fail(
                        ConfigurationPhase::Rejected,
                        "system proxy endpoint could not be resolved",
                    ))
                }
            },
            None => None,
        };
        let original = self
            .control
            .lock()
            .expect("runtime control mutex")
            .checkpoint
            .clone();
        let mut prepared_proxy = None;
        if let Some(settings) = proxy_update.as_ref() {
            let Some(adapter) = self.ports.system_proxy.as_ref() else {
                return self.publish_configuration_report(report.fail(
                    ConfigurationPhase::Rejected,
                    "system proxy adapter is unavailable",
                ));
            };
            if original.is_none() {
                return self.publish_configuration_report(report.fail(
                    ConfigurationPhase::Rejected,
                    "system proxy ownership checkpoint is unavailable",
                ));
            }
            match adapter.prepare(settings).await {
                Ok(prepared)
                    if prepared.lease_key == PlatformLeaseKey::system_proxy()
                        && prepared.schema_version != 0 =>
                {
                    prepared_proxy = Some(prepared)
                }
                Ok(_) => {
                    return self.publish_configuration_report(report.fail(
                        ConfigurationPhase::Rejected,
                        "invalid system proxy checkpoint",
                    ))
                }
                Err(error) => {
                    return self.publish_configuration_report(
                        report.fail(ConfigurationPhase::Rejected, error),
                    )
                }
            }
        }
        if let Err(error) = persist_blocking(persist).await {
            return self
                .publish_configuration_report(report.fail(ConfigurationPhase::Rejected, error));
        }
        if previous == address {
            report.phase = ConfigurationPhase::NoChange;
            return self.publish_configuration_report(report);
        }
        let mut ownership = original.clone();
        if let (Some(original), Some(prepared)) = (original.as_ref(), prepared_proxy.as_ref()) {
            let mut checkpoint = original.checkpoint.clone();
            let Some(capability) = checkpoint
                .capabilities
                .iter_mut()
                .find(|v| v.lease_key == PlatformLeaseKey::system_proxy())
            else {
                return self.publish_configuration_report(report.fail(
                    ConfigurationPhase::PendingApply,
                    "system proxy checkpoint does not contain its owned resource",
                ));
            };
            capability.rollback_payload = Some(prepared.payload.clone());
            checkpoint.phase = CheckpointPhase::Applying;
            checkpoint.operation = CheckpointOperation::Reload;
            match self
                .checkpoint_store
                .replace(original.revision, checkpoint)
                .await
            {
                Ok(stored) => {
                    self.control
                        .lock()
                        .expect("runtime control mutex")
                        .checkpoint = Some(stored.clone());
                    ownership = Some(stored);
                }
                Err(error) => {
                    return self.publish_configuration_report(
                        report.fail(ConfigurationPhase::PendingApply, error),
                    )
                }
            }
        }
        let result = match self.core.reconfigure_listener_scope(address).await {
            Ok(value) => value,
            Err(error) => {
                return self.publish_configuration_report(
                    report.fail(ConfigurationPhase::PendingApply, error),
                )
            }
        };
        if let Some(effective) = result.effective_addr {
            let recorded = self.requested_listener(effective);
            if let Some(core) = self
                .control
                .lock()
                .expect("runtime control mutex")
                .spec
                .core
                .as_mut()
            {
                core.listen_addr = Some(recorded);
            }
        }
        if result.effective_addr != Some(address) {
            if result.effective_addr == Some(previous) {
                if let (Some(current), Some(original)) = (ownership.as_ref(), original.as_ref()) {
                    if current.revision != original.revision {
                        match self
                            .checkpoint_store
                            .replace(current.revision, original.checkpoint.clone())
                            .await
                        {
                            Ok(restored) => {
                                self.control
                                    .lock()
                                    .expect("runtime control mutex")
                                    .checkpoint = Some(restored)
                            }
                            Err(error) => {
                                return self.publish_configuration_report(
                                    report.fail(ConfigurationPhase::Degraded, error),
                                )
                            }
                        }
                    }
                }
            }
            let phase = if result.effective_addr.is_some() {
                ConfigurationPhase::PendingApply
            } else {
                ConfigurationPhase::Degraded
            };
            return self.publish_configuration_report(report.fail(
                phase,
                result.error.unwrap_or_else(|| {
                    "listener binding did not reach the requested address".into()
                }),
            ));
        }
        if let Some(settings) = proxy_update {
            let adapter = self
                .ports
                .system_proxy
                .as_ref()
                .expect("validated system proxy adapter");
            let apply = match adapter.apply(&settings).await {
                Ok(applied) if applied.verified => adapter.observe().await.and_then(|observed| {
                    if observed.active && observed.verified {
                        Ok(())
                    } else {
                        Err(CapabilityError::new(
                            CapabilityKind::SystemProxy,
                            crate::CapabilityErrorCode::ObserveFailed,
                            "system proxy did not verify new listener",
                        ))
                    }
                }),
                Ok(_) => Err(CapabilityError::new(
                    CapabilityKind::SystemProxy,
                    crate::CapabilityErrorCode::ApplyFailed,
                    "system proxy update was not verified",
                )),
                Err(error) => Err(error),
            };
            if let Err(error) = apply {
                let restored_proxy = adapter
                    .restore(prepared_proxy.as_ref().unwrap())
                    .await
                    .is_ok_and(|v| v.verified);
                let restored_listener = self
                    .core
                    .reconfigure_listener_scope(previous)
                    .await
                    .is_ok_and(|v| v.effective_addr == Some(previous));
                if restored_listener {
                    let recorded = self.requested_listener(previous);
                    if let Some(core) = self
                        .control
                        .lock()
                        .expect("runtime control mutex")
                        .spec
                        .core
                        .as_mut()
                    {
                        core.listen_addr = Some(recorded);
                    }
                }
                if restored_proxy && restored_listener {
                    if let (Some(current), Some(original)) = (ownership.as_ref(), original.as_ref())
                    {
                        match self
                            .checkpoint_store
                            .replace(current.revision, original.checkpoint.clone())
                            .await
                        {
                            Ok(restored) => {
                                self.control
                                    .lock()
                                    .expect("runtime control mutex")
                                    .checkpoint = Some(restored)
                            }
                            Err(store_error) => {
                                return self.publish_configuration_report(report.fail(
                                    ConfigurationPhase::Degraded,
                                    format!("{error}; checkpoint recovery failed: {store_error}"),
                                ))
                            }
                        }
                    }
                    return self.publish_configuration_report(
                        report.fail(ConfigurationPhase::PendingApply, error),
                    );
                }
                return self.publish_configuration_report(report.fail(
                    ConfigurationPhase::Degraded,
                    format!("{error}; listener/proxy recovery incomplete"),
                ));
            }
            if let Some(current) = ownership {
                let mut checkpoint = current.checkpoint.clone();
                checkpoint.phase = CheckpointPhase::Committed;
                match self
                    .checkpoint_store
                    .replace(current.revision, checkpoint)
                    .await
                {
                    Ok(stored) => {
                        self.control
                            .lock()
                            .expect("runtime control mutex")
                            .checkpoint = Some(stored)
                    }
                    Err(error) => {
                        return self.publish_configuration_report(
                            report.fail(ConfigurationPhase::Degraded, error),
                        )
                    }
                }
            }
        }
        let recorded = self.requested_listener(address);
        if let Some(core) = self
            .control
            .lock()
            .expect("runtime control mutex")
            .spec
            .core
            .as_mut()
        {
            core.listen_addr = Some(recorded);
        }
        report.phase = if result.cleanup_complete {
            ConfigurationPhase::Applied
        } else {
            ConfigurationPhase::AppliedCleanupPending
        };
        report.error = result.error;
        let report = self.publish_configuration_report(report);
        if !result.cleanup_complete {
            let owner = Arc::downgrade(self);
            let operation_id = report.operation_id.clone();
            let generation = report.generation;
            self.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let Some(runtime) = owner.upgrade() else {
                        return;
                    };
                    let _operation = runtime.operation.lock().await;
                    if runtime.status().generation != generation
                        || runtime.status().state != RuntimeState::Running
                    {
                        return;
                    }
                    if runtime.core.listener_scope_cleanup_complete() {
                        let mut state = runtime.configuration.lock().expect("configuration state");
                        if let Some(last) = state.last.as_mut().filter(|last| {
                            last.operation_id == operation_id
                                && last.phase == ConfigurationPhase::AppliedCleanupPending
                        }) {
                            last.phase = ConfigurationPhase::Applied;
                            last.error = None;
                            runtime
                                .configuration_events
                                .send_replace(Some(last.clone()));
                        }
                        return;
                    }
                }
            });
        }
        report
    }
}

/// Runs the host's persistence of a configuration change on the blocking
/// pool: it writes files, and the transaction runs on the thread the Core's
/// traffic runs on.
async fn persist_blocking<F>(persist: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    match tokio::task::spawn_blocking(persist).await {
        Ok(persisted) => persisted,
        // A panic may leave the save half done: it unwinds the transaction,
        // whose panic completion fences later updates.
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(format!("configuration persistence did not finish: {error}")),
    }
}
