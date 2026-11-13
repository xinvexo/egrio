//! The Runtime: its ports and control state. Each transaction and the
//! state it owns live in a child module by responsibility.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod capability_plan;
mod checkpoints;
mod configuration;
mod core_control;
mod health;
mod outcome;
mod packet;
mod reload;
mod start;
mod stop;
mod task;
use capability_plan::*;
pub use configuration::{
    ConfigurationClass, ConfigurationOperation, ConfigurationPhase, RuntimeConfigurationChange,
    RuntimeConfigurationReport,
};
pub use outcome::{
    RuntimeRecoveryError, RuntimeRecoveryReport, RuntimeReloadError, RuntimeReloadReport,
    RuntimeStartError, RuntimeStartReport, RuntimeStopError, RuntimeStopReport,
};
use packet::*;
use task::{Completion, ManagedTask, TaskId};

/// How long `stop` waits for the packet data plane to exit after cancelling
/// it before retaining it for a recovery retry. A healthy pump exits within
/// milliseconds (every wait it parks on selects the stop token); the bound
/// only exists so a wedged data plane cannot hold the operation mutex — and
/// thus every later start/stop/reload — forever.
const PACKET_TASK_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const CORE_CONNECTION_CUTOVER_TIMEOUT: Duration = Duration::from_secs(5);

use crate::{
    CapabilityCheckpoint, CapabilityError, CapabilityKind, CapabilityOperationReport, CheckpointId,
    CheckpointOperation, CheckpointPhase, CheckpointStore, CheckpointStoreError,
    CheckpointStoreErrorCode, ConnectionHealth, CoreConfigSource, DnsControl, DnsSettings,
    FirewallControl, FirewallSettings, LeaseCoordinator, LeaseExpandError, LeaseGrant,
    LeaseReleaseEvidence, LeaseRequestSet, LeaseTransitionError, PacketCapture,
    PacketCaptureSettings, PacketDataPlane, PlatformLeaseConflict, PlatformLeaseKey,
    RecoveryCheckpoint, RecoveryCheckpointError, RouteControl, RouteSettings,
    RuntimeCheckpointStatus, RuntimeCoreDomainStatus, RuntimeDomainReport, RuntimeDomainStatus,
    RuntimeGeneration, RuntimeId, RuntimeResource, RuntimeResourceChange, RuntimeResourceOutcome,
    RuntimeSpec, RuntimeSpecError, RuntimeState, RuntimeStatus, StoredCheckpoint,
    SystemProxyControl, SystemProxySettings,
};
use crate::{RuntimeCore, RuntimeCoreGeneration};
use std::net::SocketAddr;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct RuntimePorts {
    pub packet_capture: Option<Arc<dyn PacketCapture>>,
    pub packet_data_plane: Option<Arc<dyn PacketDataPlane>>,
    pub core_config: Option<Arc<dyn CoreConfigSource>>,
    pub system_proxy: Option<Arc<dyn SystemProxyControl>>,
    pub route: Option<Arc<dyn RouteControl>>,
    pub dns: Option<Arc<dyn DnsControl>>,
    pub firewall: Option<Arc<dyn FirewallControl>>,
    pub connection_health: Option<Arc<dyn ConnectionHealth>>,
}

impl fmt::Debug for RuntimePorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePorts")
            .field("packet_capture", &self.packet_capture.is_some())
            .field("packet_data_plane", &self.packet_data_plane.is_some())
            .field("core_config", &self.core_config.is_some())
            .field("system_proxy", &self.system_proxy.is_some())
            .field("route", &self.route.is_some())
            .field("dns", &self.dns.is_some())
            .field("firewall", &self.firewall.is_some())
            .field("connection_health", &self.connection_health.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAssemblyErrorCode {
    InvalidSpec,
    MissingCapabilityPort,
}

#[derive(Debug)]
pub struct RuntimeAssemblyError {
    pub code: RuntimeAssemblyErrorCode,
    pub message: String,
}

impl fmt::Display for RuntimeAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}
impl Error for RuntimeAssemblyError {}

/// The Core generation a start or reload transaction started, which that
/// transaction stops again if it does not commit.
#[derive(Clone, Copy, Debug)]
struct PreparedRuntimeCore {
    listener: SocketAddr,
    generation: RuntimeCoreGeneration,
}

#[derive(Debug)]
struct RuntimeControlState {
    spec: RuntimeSpec,
    generation: RuntimeGeneration,
    state: RuntimeState,
    lease_grant: Option<LeaseGrant>,
    checkpoint: Option<StoredCheckpoint>,
    /// The Core generation the Runtime's transactions started and stop.
    core: Option<RuntimeCoreGeneration>,
    degradation_error: Option<String>,
    /// Set when the platform session behind packet capture ended while it
    /// was applied, and kept until a transaction touches the capabilities.
    /// Only then may a degraded reload keep the resources that did not live
    /// in that session.
    session_lost: bool,
}

#[derive(Debug)]
pub struct Runtime {
    id: RuntimeId,
    control: Mutex<RuntimeControlState>,
    lease_coordinator: Arc<dyn LeaseCoordinator>,
    checkpoint_store: Arc<dyn CheckpointStore>,
    ports: RuntimePorts,
    core: RuntimeCore,
    operation: AsyncMutex<()>,
    configuration: Mutex<configuration::ConfigurationState>,
    configuration_admission: Arc<tokio::sync::Semaphore>,
    configuration_events: tokio::sync::watch::Sender<Option<RuntimeConfigurationReport>>,
    packet_task: Mutex<Option<ActivePacketTask>>,
    /// Completion report of the latest packet worker, published exactly once
    /// independently of whether its owner has already requested stop.
    packet_report: Mutex<PacketReportState>,
    health_task: Mutex<Option<JoinHandle<()>>>,
    /// Counts platform session losses that degraded this Runtime.
    session_loss: tokio::sync::watch::Sender<u64>,
    /// Where the Runtime's own work and its Core run (see
    /// [`Runtime::with_executors`]); the calling runtime without any.
    executors: Vec<tokio::runtime::Handle>,
    #[cfg(test)]
    core_stop_failure: Mutex<Option<String>>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Ok(task) = self.health_task.get_mut() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
        // A runtime dropped without a completed `stop()` (SDK teardown, a
        // registry drop) must not leave its packet data-plane task pumping the
        // capture device forever: cancel the pump so its device is dropped.
        // `get_mut` needs no await.
        if let Ok(active) = self.packet_task.get_mut() {
            if let Some(active) = active.take() {
                active.worker.request_stop();
                active.stop.cancel();
            }
        }
    }
}

impl Runtime {
    #[doc(hidden)]
    pub fn from_parts(
        spec: RuntimeSpec,
        lease_coordinator: Arc<dyn LeaseCoordinator>,
        checkpoint_store: Arc<dyn CheckpointStore>,
        ports: RuntimePorts,
    ) -> Result<Self, RuntimeAssemblyError> {
        spec.lease_request().map_err(|error| RuntimeAssemblyError {
            code: RuntimeAssemblyErrorCode::InvalidSpec,
            message: error.to_string(),
        })?;
        validate_ports(&spec, &ports)?;
        Ok(Self {
            id: spec.id,
            control: Mutex::new(RuntimeControlState {
                spec,
                generation: RuntimeGeneration::new(0),
                state: RuntimeState::Created,
                lease_grant: None,
                checkpoint: None,
                core: None,
                degradation_error: None,
                session_lost: false,
            }),
            lease_coordinator,
            checkpoint_store,
            ports,
            core: RuntimeCore::default(),
            operation: AsyncMutex::new(()),
            configuration: Mutex::new(configuration::ConfigurationState::default()),
            configuration_admission: Arc::new(tokio::sync::Semaphore::new(16)),
            configuration_events: tokio::sync::watch::channel(None).0,
            packet_task: Mutex::new(None),
            packet_report: Mutex::new(PacketReportState::default()),
            health_task: Mutex::new(None),
            session_loss: tokio::sync::watch::Sender::new(0),
            executors: Vec::new(),
            #[cfg(test)]
            core_stop_failure: Mutex::new(None),
        })
    }

    /// Runs this Runtime's transactions, and with them its Core, on the
    /// first of `executors` instead of the runtime that calls it, and the
    /// packet pumps of a capture's queues each on one of them: tasks the Core
    /// spawns land where the work that spawns them runs. A capture opens at
    /// most as many queues as there are executors.
    #[must_use]
    pub fn with_executors(mut self, executors: Vec<tokio::runtime::Handle>) -> Self {
        self.executors = executors;
        self
    }

    /// The executor of the Runtime's own work.
    fn executor(&self) -> Option<&tokio::runtime::Handle> {
        self.executors.first()
    }

    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.executor() {
            Some(executor) => executor.spawn(future),
            None => tokio::spawn(future),
        }
    }

    #[must_use]
    pub fn id(&self) -> RuntimeId {
        self.id
    }

    #[must_use]
    pub fn spec(&self) -> RuntimeSpec {
        self.control
            .lock()
            .expect("runtime control mutex")
            .spec
            .clone()
    }

    #[must_use]
    pub fn lease_request(&self) -> Option<LeaseRequestSet> {
        self.spec()
            .lease_request()
            .expect("assembled runtime spec remains valid")
    }

    #[must_use]
    pub fn status(&self) -> RuntimeStatus {
        let control = self.control.lock().expect("runtime control mutex");
        RuntimeStatus {
            id: self.id(),
            generation: control.generation,
            state: control.state,
            degradation_error: control.degradation_error.clone(),
        }
    }

    #[must_use]
    pub fn domain_status(&self) -> RuntimeDomainStatus {
        let native_core = self.core.status();
        let control = self.control.lock().expect("runtime control mutex");
        RuntimeDomainStatus {
            runtime: RuntimeStatus {
                id: self.id(),
                generation: control.generation,
                state: control.state,
                degradation_error: control.degradation_error.clone(),
            },
            spec: control.spec.clone(),
            core: control.core.map(|generation| RuntimeCoreDomainStatus {
                generation,
                listen_addr: native_core.listen_addr.clone(),
            }),
            checkpoint: control
                .checkpoint
                .as_ref()
                .map(|stored| RuntimeCheckpointStatus {
                    id: stored.checkpoint.id,
                    operation: stored.checkpoint.operation,
                    phase: stored.checkpoint.phase,
                }),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn assembly_is_complete(&self) -> bool {
        Arc::strong_count(&self.lease_coordinator) > 0
            && Arc::strong_count(&self.checkpoint_store) > 0
            && validate_ports(&self.spec(), &self.ports).is_ok()
    }

    fn set_state(&self, state: RuntimeState) {
        self.control.lock().expect("runtime control mutex").state = state;
    }
}

/// Whether `actual` is the Core's stand-in for an unusable `expected`: the
/// status records `expected` as the address asked for, on the same IP.
fn listener_falls_back_for(
    status: &egrio_core::NativeCoreStatus,
    expected: SocketAddr,
    actual: SocketAddr,
) -> bool {
    expected.ip() == actual.ip()
        && status
            .listener_fallback
            .as_ref()
            .and_then(|fallback| fallback.requested.parse::<SocketAddr>().ok())
            == Some(expected)
}

fn listener_endpoint_matches(expected: SocketAddr, actual: SocketAddr) -> bool {
    if expected.port() == 0 {
        let mut wildcard_port = expected;
        wildcard_port.set_port(actual.port());
        wildcard_port == actual
    } else {
        expected == actual
    }
}

fn validate_ports(spec: &RuntimeSpec, ports: &RuntimePorts) -> Result<(), RuntimeAssemblyError> {
    let requirements = [
        (
            spec.platform.packet_capture.is_some(),
            ports.packet_capture.is_some(),
            "packet-capture",
        ),
        (
            spec.platform.system_proxy.is_some(),
            ports.system_proxy.is_some(),
            "system-proxy",
        ),
        (
            spec.platform.route.is_some(),
            ports.route.is_some(),
            "route",
        ),
        (spec.platform.dns.is_some(), ports.dns.is_some(), "dns"),
        (
            spec.platform.firewall.is_some(),
            ports.firewall.is_some(),
            "firewall",
        ),
    ];
    if let Some((_, _, capability)) = requirements
        .into_iter()
        .find(|(requested, available, _)| *requested && !*available)
    {
        return Err(RuntimeAssemblyError {
            code: RuntimeAssemblyErrorCode::MissingCapabilityPort,
            message: format!("runtime requires the {capability} capability port"),
        });
    }
    if spec.platform.packet_capture.is_some() && ports.packet_data_plane.is_none() {
        return Err(RuntimeAssemblyError {
            code: RuntimeAssemblyErrorCode::MissingCapabilityPort,
            message: "runtime requires a packet data plane".into(),
        });
    }
    if spec.core.is_some() && ports.core_config.is_none() {
        return Err(RuntimeAssemblyError {
            code: RuntimeAssemblyErrorCode::MissingCapabilityPort,
            message: "runtime requires a core config source".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod configuration_tests;
#[cfg(test)]
mod tests;
