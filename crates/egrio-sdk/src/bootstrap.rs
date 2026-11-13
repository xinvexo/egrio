use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use egrio_runtime::{
    CheckpointId, CheckpointStore, CheckpointStoreError, LeaseGrant, PacketDataPlane,
    PlatformLeaseKey, RecoveryCheckpointError, Runtime, RuntimeId, RuntimePorts, RuntimeSpec,
    RuntimeSpecError, RECOVERY_CHECKPOINT_SCHEMA_VERSION,
};
use tokio::sync::OnceCell;

use crate::core_executor::CoreExecutors;
use crate::{PlatformLeaseCoordinator, PlatformLeaseStatus, RecoveryReservationError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBootstrapReport {
    pub checkpoints: Vec<CheckpointId>,
    pub blocked_leases: Vec<PlatformLeaseKey>,
}

struct BootstrapState {
    report: RecoveryBootstrapReport,
    recovery_grants: Mutex<BTreeMap<CheckpointId, LeaseGrant>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkBuildErrorCode {
    MissingCheckpointStore,
    /// The thread the Core runs on could not be started.
    CoreExecutor,
}

#[derive(Debug)]
pub enum RuntimeCreateError {
    InvalidSpec(RuntimeSpecError),
    Assembly(egrio_runtime::RuntimeAssemblyError),
    Bootstrap(RecoveryBootstrapError),
    DuplicateRuntimeId(RuntimeId),
    BoundRuntimeIdMismatch {
        expected: RuntimeId,
        actual: RuntimeId,
    },
}

impl fmt::Display for RuntimeCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(error) => error.fmt(formatter),
            Self::Assembly(error) => error.fmt(formatter),
            Self::Bootstrap(error) => error.fmt(formatter),
            Self::DuplicateRuntimeId(id) => write!(formatter, "runtime {id} already exists"),
            Self::BoundRuntimeIdMismatch { expected, actual } => write!(
                formatter,
                "runtime {actual} does not match the service-bound runtime {expected}"
            ),
        }
    }
}
impl Error for RuntimeCreateError {}

#[derive(Debug)]
pub enum RuntimeRemoveError {
    NotFound(RuntimeId),
    NotStopped {
        runtime_id: RuntimeId,
        state: egrio_runtime::RuntimeState,
    },
}

impl fmt::Display for RuntimeRemoveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(formatter, "runtime {id} is not registered"),
            Self::NotStopped { runtime_id, state } => {
                write!(
                    formatter,
                    "runtime {runtime_id} cannot be removed from {state:?}"
                )
            }
        }
    }
}
impl Error for RuntimeRemoveError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkBuildError {
    pub code: SdkBuildErrorCode,
    pub message: String,
}

impl fmt::Display for SdkBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}
impl Error for SdkBuildError {}

#[derive(Debug)]
pub enum RecoveryBootstrapError {
    Store(CheckpointStoreError),
    UnsupportedSchema {
        checkpoint_id: CheckpointId,
        schema_version: u16,
    },
    InvalidCheckpoint {
        checkpoint_id: CheckpointId,
        error: RecoveryCheckpointError,
    },
    Reservation(RecoveryReservationError),
    MissingRecoveryGrant(CheckpointId),
    BoundRuntimeIdMismatch {
        checkpoint_id: CheckpointId,
        expected: RuntimeId,
        actual: RuntimeId,
    },
    Recovery(egrio_runtime::RuntimeRecoveryError),
}

impl RecoveryBootstrapError {
    #[must_use]
    pub fn store_error(&self) -> Option<&CheckpointStoreError> {
        match self {
            Self::Store(error) => Some(error),
            Self::UnsupportedSchema { .. }
            | Self::InvalidCheckpoint { .. }
            | Self::BoundRuntimeIdMismatch { .. }
            | Self::Reservation(_)
            | Self::MissingRecoveryGrant(_)
            | Self::Recovery(_) => None,
        }
    }
}

impl fmt::Display for RecoveryBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::UnsupportedSchema {
                checkpoint_id,
                schema_version,
            } => write!(
                formatter,
                "checkpoint {} uses unsupported schema version {}",
                checkpoint_id.as_uuid(),
                schema_version
            ),
            Self::InvalidCheckpoint {
                checkpoint_id,
                error,
            } => write!(
                formatter,
                "checkpoint {} is invalid: {}",
                checkpoint_id.as_uuid(),
                error
            ),
            Self::Reservation(error) => error.conflict.fmt(formatter),
            Self::MissingRecoveryGrant(checkpoint_id) => write!(
                formatter,
                "checkpoint {} has no reserved recovery grant",
                checkpoint_id.as_uuid()
            ),
            Self::BoundRuntimeIdMismatch {
                checkpoint_id,
                expected,
                actual,
            } => write!(
                formatter,
                "checkpoint {} belongs to runtime {actual}, not service-bound runtime {expected}",
                checkpoint_id.as_uuid()
            ),
            Self::Recovery(error) => error.fmt(formatter),
        }
    }
}
impl Error for RecoveryBootstrapError {}

#[derive(Default)]
pub struct EgrioSdkBuilder {
    checkpoint_store: Option<Arc<dyn CheckpointStore>>,
    ports: RuntimePorts,
    remote_runtime_id: Option<RuntimeId>,
}

#[cfg(feature = "platform-windows")]
#[derive(Clone, Debug)]
pub struct WindowsServiceConfig {
    pub runtime_id: RuntimeId,
    pub service_name: String,
    pub app_version: String,
    /// Shared with the Core's egress binder: the packet-capture adapter
    /// activates it with the service-held TUN adapter while capture is open.
    #[cfg(windows)]
    pub tun_egress: Arc<egrio_platform_windows::WindowsTunEgress>,
}

/// The Linux root helper at its fixed control socket.
#[cfg(feature = "platform-linux")]
#[derive(Clone, Debug)]
pub struct LinuxServiceConfig {
    pub runtime_id: RuntimeId,
    pub app_version: String,
    /// Shared with the Core's egress guard: the packet-capture adapter
    /// activates it with the TUN's physical resolvers while capture is open.
    #[cfg(target_os = "linux")]
    pub tun_egress: Arc<egrio_platform_linux::LinuxTunEgress>,
}

#[cfg(feature = "platform-macos")]
#[derive(Debug, Clone)]
pub struct MacosServiceConfig {
    pub runtime_id: RuntimeId,
    pub app_version: String,
    /// Shared with the Core's egress binder: the packet-capture adapter
    /// activates it with the physical resolvers while the tunnel is open.
    #[cfg(target_os = "macos")]
    pub tun_egress: Arc<egrio_platform_macos::MacosTunEgress>,
}

impl EgrioSdkBuilder {
    #[must_use]
    pub fn checkpoint_store(mut self, store: Arc<dyn CheckpointStore>) -> Self {
        self.checkpoint_store = Some(store);
        self
    }

    #[must_use]
    pub fn platform<T>(mut self, platform: Arc<T>) -> Self
    where
        T: egrio_runtime::PacketCapture
            + egrio_runtime::SystemProxyControl
            + egrio_runtime::RouteControl
            + egrio_runtime::DnsControl
            + egrio_runtime::FirewallControl
            + 'static,
    {
        self.ports.packet_capture = Some(platform.clone());
        self.ports.system_proxy = Some(platform.clone());
        self.ports.route = Some(platform.clone());
        self.ports.dns = Some(platform.clone());
        self.ports.firewall = Some(platform);
        self
    }

    /// Supplies the platform TUN device; the Runtime owns its packet task.
    #[must_use]
    pub fn packet_capture<T>(mut self, adapter: Arc<T>) -> Self
    where
        T: egrio_runtime::PacketCapture + 'static,
    {
        self.ports.packet_capture = Some(adapter);
        self
    }

    #[must_use]
    pub fn packet_data_plane<T>(mut self, value: Arc<T>) -> Self
    where
        T: PacketDataPlane + 'static,
    {
        self.ports.packet_data_plane = Some(value);
        self
    }

    /// Installs the source the Runtime loads its generation Core inputs from
    /// (profile, egress, socket guard) at the head of every start
    /// transaction. Required by any spec that declares a Runtime-owned Core.
    #[must_use]
    pub fn core_config<T>(mut self, value: Arc<T>) -> Self
    where
        T: egrio_runtime::CoreConfigSource + 'static,
    {
        self.ports.core_config = Some(value);
        self
    }

    #[must_use]
    pub fn connection_health<T>(mut self, value: Arc<T>) -> Self
    where
        T: egrio_runtime::ConnectionHealth + 'static,
    {
        self.ports.connection_health = Some(value);
        self
    }

    /// Runs TUN mode's capabilities through the Windows service.
    #[cfg(all(feature = "platform-windows", windows))]
    #[must_use]
    pub fn windows_service(self, config: WindowsServiceConfig) -> Self {
        let transport = Arc::new(
            egrio_service::windows::WindowsNamedPipeTransport::for_service(&config.service_name),
        );
        self.remote_service(
            transport,
            config.runtime_id,
            config.app_version,
            config.tun_egress,
        )
    }

    /// Runs TUN mode's capabilities through the Linux root helper.
    #[cfg(all(feature = "platform-linux", target_os = "linux"))]
    #[must_use]
    pub fn linux_service(self, config: LinuxServiceConfig) -> Self {
        let transport = Arc::new(egrio_service::unix::UnixSocketTransport::new(
            egrio_platform_linux::LINUX_SERVICE_SOCKET,
        ));
        self.remote_service(
            transport,
            config.runtime_id,
            config.app_version,
            config.tun_egress,
        )
    }

    /// Runs TUN mode through the macOS launchd service, which opens the utun,
    /// routes both halves of each family into it and makes its resolver the
    /// system's default. Its session serves the PacketCapture port; macOS has
    /// no separate Route, DNS or Firewall capability, and the system proxy
    /// layer sets the network services' proxies with TUN on or off.
    #[cfg(all(feature = "platform-macos", target_os = "macos"))]
    #[must_use]
    pub fn macos_service(mut self, config: MacosServiceConfig) -> Self {
        let transport = Arc::new(egrio_service::unix::UnixSocketTransport::new(
            egrio_platform_macos::MACOS_SERVICE_SOCKET,
        ));
        let client = Arc::new(egrio_service::client::ControlClient::deferred(
            transport,
            config.runtime_id,
            config.app_version,
        ));
        let platform = Arc::new(egrio_service::ServicePlatform::new(
            client,
            config.tun_egress,
        ));
        self.ports.packet_capture = Some(platform.clone());
        self.ports.connection_health = Some(platform);
        self.ports.packet_data_plane = Some(Arc::new(crate::NativeCorePacketDataPlane));
        self.ports.system_proxy = Some(Arc::new(
            egrio_platform_macos::MacosSystemProxyAdapter::new(),
        ));
        self.remote_runtime_id = Some(config.runtime_id);
        self
    }

    /// Binds one Runtime identity to the service: its session serves the
    /// PacketCapture, Route, DNS and Firewall ports, and its connection
    /// health degrades the Runtime when the session is lost. The client
    /// connects on the first capability request.
    #[cfg(any(
        all(feature = "platform-windows", windows),
        all(feature = "platform-linux", target_os = "linux")
    ))]
    fn remote_service(
        mut self,
        transport: Arc<dyn egrio_service::transport::ControlTransport>,
        runtime_id: RuntimeId,
        app_version: String,
        tun_egress: Arc<egrio_service::ServiceTunEgress>,
    ) -> Self {
        let client = Arc::new(egrio_service::client::ControlClient::deferred(
            transport,
            runtime_id,
            app_version,
        ));
        let platform = Arc::new(egrio_service::ServicePlatform::new(client, tun_egress));
        self.ports.packet_capture = Some(platform.clone());
        self.ports.route = Some(platform.clone());
        self.ports.dns = Some(platform.clone());
        self.ports.firewall = Some(platform.clone());
        self.ports.connection_health = Some(platform);
        self.ports.packet_data_plane = Some(Arc::new(crate::NativeCorePacketDataPlane));
        self.remote_runtime_id = Some(runtime_id);
        self
    }

    #[must_use]
    pub fn route_control<T>(mut self, adapter: Arc<T>) -> Self
    where
        T: egrio_runtime::RouteControl + 'static,
    {
        self.ports.route = Some(adapter);
        self
    }

    #[must_use]
    pub fn dns_control<T>(mut self, adapter: Arc<T>) -> Self
    where
        T: egrio_runtime::DnsControl + 'static,
    {
        self.ports.dns = Some(adapter);
        self
    }

    #[must_use]
    pub fn firewall_control<T>(mut self, adapter: Arc<T>) -> Self
    where
        T: egrio_runtime::FirewallControl + 'static,
    {
        self.ports.firewall = Some(adapter);
        self
    }

    #[must_use]
    pub fn system_proxy<T>(mut self, adapter: Arc<T>) -> Self
    where
        T: egrio_runtime::SystemProxyControl + 'static,
    {
        self.ports.system_proxy = Some(adapter);
        self
    }

    #[cfg(feature = "platform-windows")]
    #[must_use]
    pub fn windows_system_proxy(self) -> Self {
        self.system_proxy(Arc::new(
            egrio_platform_windows::WindowsSystemProxyAdapter::new(),
        ))
    }

    pub fn build(self) -> Result<EgrioSdk, SdkBuildError> {
        let checkpoint_store = self.checkpoint_store.ok_or_else(|| SdkBuildError {
            code: SdkBuildErrorCode::MissingCheckpointStore,
            message: "EgrioSdk requires an injected CheckpointStore".into(),
        })?;
        let queues = self
            .ports
            .packet_capture
            .as_ref()
            .map_or(1, |capture| capture.queue_limit());
        let core_executors = CoreExecutors::new(queues).map_err(|error| SdkBuildError {
            code: SdkBuildErrorCode::CoreExecutor,
            message: format!("failed to start the Core executors: {error}"),
        })?;
        Ok(EgrioSdk {
            checkpoint_store,
            leases: Arc::new(PlatformLeaseCoordinator::new()),
            bootstrap: OnceCell::new(),
            runtimes: Mutex::new(BTreeMap::new()),
            ports: self.ports,
            remote_runtime_id: self.remote_runtime_id,
            core_executors,
        })
    }
}

pub struct EgrioSdk {
    checkpoint_store: Arc<dyn CheckpointStore>,
    leases: Arc<PlatformLeaseCoordinator>,
    bootstrap: OnceCell<BootstrapState>,
    runtimes: Mutex<BTreeMap<RuntimeId, Arc<Runtime>>>,
    ports: RuntimePorts,
    remote_runtime_id: Option<RuntimeId>,
    /// Where the Runtimes this SDK creates run their Core; they outlive them
    /// as long as the SDK does.
    core_executors: CoreExecutors,
}

impl EgrioSdk {
    #[must_use]
    pub fn builder() -> EgrioSdkBuilder {
        EgrioSdkBuilder::default()
    }

    pub async fn bootstrap_recovery(
        &self,
    ) -> Result<RecoveryBootstrapReport, RecoveryBootstrapError> {
        let state = self
            .bootstrap
            .get_or_try_init(|| async {
                let mut checkpoints = self
                    .checkpoint_store
                    .list_unresolved()
                    .await
                    .map_err(RecoveryBootstrapError::Store)?;
                checkpoints.sort_by_key(|stored| stored.checkpoint.id);
                for stored in &checkpoints {
                    self.validate_bound_checkpoint(stored)?;
                    if stored.checkpoint.schema_version != RECOVERY_CHECKPOINT_SCHEMA_VERSION {
                        return Err(RecoveryBootstrapError::UnsupportedSchema {
                            checkpoint_id: stored.checkpoint.id,
                            schema_version: stored.checkpoint.schema_version,
                        });
                    }
                    stored.checkpoint.validate().map_err(|error| {
                        RecoveryBootstrapError::InvalidCheckpoint {
                            checkpoint_id: stored.checkpoint.id,
                            error,
                        }
                    })?;
                }
                let checkpoint_ids: Vec<CheckpointId> = checkpoints
                    .iter()
                    .map(|stored| stored.checkpoint.id)
                    .collect();
                let mut blocked_leases = checkpoints
                    .iter()
                    .flat_map(|stored| stored.checkpoint.leases.iter().cloned())
                    .collect::<Vec<_>>();
                blocked_leases.sort();
                blocked_leases.dedup();
                let recovery_grants = self
                    .leases
                    .reserve_recovery_batch(&checkpoints)
                    .map_err(RecoveryBootstrapError::Reservation)?;
                let recovery_grants = checkpoint_ids
                    .iter()
                    .copied()
                    .zip(recovery_grants)
                    .collect();
                Ok(BootstrapState {
                    report: RecoveryBootstrapReport {
                        checkpoints: checkpoint_ids,
                        blocked_leases,
                    },
                    recovery_grants: Mutex::new(recovery_grants),
                })
            })
            .await?;
        Ok(state.report.clone())
    }

    pub async fn create_runtime(
        &self,
        spec: RuntimeSpec,
    ) -> Result<Arc<Runtime>, RuntimeCreateError> {
        let uses_remote_ports = spec_uses_remote_ports(&spec);
        let is_bound_runtime = self.remote_runtime_id == Some(spec.id);
        if uses_remote_ports {
            if let Some(expected) = self.remote_runtime_id {
                if spec.id != expected {
                    return Err(RuntimeCreateError::BoundRuntimeIdMismatch {
                        expected,
                        actual: spec.id,
                    });
                }
            }
        }
        let ports = self.ports_for_scope(uses_remote_ports || is_bound_runtime);
        self.bootstrap_recovery()
            .await
            .map_err(RuntimeCreateError::Bootstrap)?;
        let runtime = Arc::new(
            Runtime::from_parts(
                spec,
                self.leases.clone(),
                self.checkpoint_store.clone(),
                ports,
            )
            .map_err(RuntimeCreateError::Assembly)?
            .with_executors(self.core_executors.handles()),
        );
        let mut runtimes = self.runtimes.lock().expect("runtime registry mutex");
        if runtimes.contains_key(&runtime.id()) {
            return Err(RuntimeCreateError::DuplicateRuntimeId(runtime.id()));
        }
        runtimes.insert(runtime.id(), runtime.clone());
        Ok(runtime)
    }

    pub async fn recover_unresolved(
        &self,
    ) -> Result<Vec<egrio_runtime::RuntimeRecoveryReport>, RecoveryBootstrapError> {
        self.bootstrap_recovery().await?;
        let mut checkpoints = self
            .checkpoint_store
            .list_unresolved()
            .await
            .map_err(RecoveryBootstrapError::Store)?;
        checkpoints.sort_by_key(|stored| stored.checkpoint.id);
        let state = self.bootstrap.get().expect("recovery bootstrap state");
        let mut reports = Vec::with_capacity(checkpoints.len());
        for stored in checkpoints {
            self.validate_bound_checkpoint(&stored)?;
            let checkpoint_id = stored.checkpoint.id;
            let grant = state
                .recovery_grants
                .lock()
                .expect("recovery grants mutex")
                .remove(&checkpoint_id)
                .ok_or(RecoveryBootstrapError::MissingRecoveryGrant(checkpoint_id))?;
            let ports = self.ports_for_scope(checkpoint_uses_remote_ports(&stored.checkpoint));
            let result = Runtime::recover_checkpoint(
                ports,
                self.leases.clone(),
                self.checkpoint_store.clone(),
                &grant,
                stored,
            )
            .await;
            match result {
                Ok(report) => reports.push(report),
                Err(error) => {
                    state
                        .recovery_grants
                        .lock()
                        .expect("recovery grants mutex")
                        .insert(checkpoint_id, grant);
                    return Err(RecoveryBootstrapError::Recovery(error));
                }
            }
        }
        Ok(reports)
    }

    fn validate_bound_checkpoint(
        &self,
        stored: &egrio_runtime::StoredCheckpoint,
    ) -> Result<(), RecoveryBootstrapError> {
        if checkpoint_uses_remote_ports(&stored.checkpoint) {
            if let Some(expected) = self.remote_runtime_id {
                if stored.checkpoint.runtime_id != expected {
                    return Err(RecoveryBootstrapError::BoundRuntimeIdMismatch {
                        checkpoint_id: stored.checkpoint.id,
                        expected,
                        actual: stored.checkpoint.runtime_id,
                    });
                }
            }
        }
        Ok(())
    }

    fn ports_for_scope(&self, uses_remote_ports: bool) -> RuntimePorts {
        let mut ports = self.ports.clone();
        if self.remote_runtime_id.is_some() && !uses_remote_ports {
            ports.packet_capture = None;
            ports.route = None;
            ports.dns = None;
            ports.firewall = None;
            ports.connection_health = None;
        }
        ports
    }
}

fn spec_uses_remote_ports(spec: &RuntimeSpec) -> bool {
    spec.platform.packet_capture.is_some()
        || spec.platform.route.is_some()
        || spec.platform.dns.is_some()
        || spec.platform.firewall.is_some()
}

fn checkpoint_uses_remote_ports(checkpoint: &egrio_runtime::RecoveryCheckpoint) -> bool {
    checkpoint.capabilities.iter().any(|capability| {
        let key = &capability.lease_key;
        key == &PlatformLeaseKey::packet_capture()
            || key == &PlatformLeaseKey::default_route()
            || key == &PlatformLeaseKey::system_dns()
            || key == &PlatformLeaseKey::kill_switch()
    })
}

impl EgrioSdk {
    pub async fn remove_runtime(&self, runtime_id: RuntimeId) -> Result<(), RuntimeRemoveError> {
        let mut runtimes = self.runtimes.lock().expect("runtime registry mutex");
        let runtime = runtimes
            .get(&runtime_id)
            .ok_or(RuntimeRemoveError::NotFound(runtime_id))?;
        let state = runtime.status().state;
        if state != egrio_runtime::RuntimeState::Stopped {
            return Err(RuntimeRemoveError::NotStopped { runtime_id, state });
        }
        runtimes.remove(&runtime_id);
        Ok(())
    }

    #[must_use]
    pub fn lease_status(&self, key: &PlatformLeaseKey) -> PlatformLeaseStatus {
        self.leases.status(key)
    }
}

#[cfg(test)]
mod windows_binding_tests {
    use super::*;
    use egrio_runtime::{
        ConnectionHealth, ConnectionHealthFuture, DnsSettings, FirewallSettings,
        PacketCaptureSettings, PacketCaptureSource, PacketDataPlane, PacketDataPlaneFuture,
        RouteSettings, RuntimePlatformSpec, SystemProxySettings, SystemProxySpec,
    };

    #[derive(Debug)]
    struct TestConnectionHealth;

    impl ConnectionHealth for TestConnectionHealth {
        fn wait_disconnected<'a>(&'a self) -> ConnectionHealthFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    #[derive(Debug)]
    struct TestPacketDataPlane;

    impl PacketDataPlane for TestPacketDataPlane {
        fn run(
            &self,
            _core: egrio_core::NativeCoreDevice,
            _queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
            _stop: tokio_util::sync::CancellationToken,
        ) -> PacketDataPlaneFuture {
            panic!("test packet data plane must not run")
        }
    }

    #[derive(Debug)]
    struct TestCoreConfig;

    impl egrio_runtime::CoreConfigSource for TestCoreConfig {
        fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
            Ok(egrio_core::CoreStartInputs {
                flow_scanner: None,
                capture: Default::default(),
                profile: egrio_core::RuntimeProfile::new("bound-runtime-test"),
                egress: egrio_core::NativeCoreEgressConfig::default(),
                egress_socket_guard: None,
                fake_ip_mappings: None,
            })
        }
    }

    fn service_bound_sdk(expected: RuntimeId) -> EgrioSdk {
        let platform = Arc::new(crate::InMemoryPlatform::new());
        EgrioSdkBuilder {
            checkpoint_store: Some(Arc::new(crate::InMemoryCheckpointStore::new())),
            ports: RuntimePorts {
                system_proxy: Some(platform),
                ..RuntimePorts::default()
            },
            remote_runtime_id: Some(expected),
        }
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn service_bound_sdk_runs_a_foreign_pure_system_proxy_runtime() {
        let expected = RuntimeId::new();
        let actual = RuntimeId::new();
        let sdk = service_bound_sdk(expected);
        let platform = RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                bypass: vec!["localhost".into()],
            })),
            ..RuntimePlatformSpec::default()
        };
        let runtime = sdk
            .create_runtime(RuntimeSpec::new(actual, platform).unwrap())
            .await
            .unwrap();

        assert_eq!(runtime.id(), actual);
        assert!(runtime.start().await.unwrap().changed);
        assert!(runtime.stop().await.unwrap().restored);
    }

    #[tokio::test]
    async fn service_bound_sdk_conflicts_two_local_system_proxy_runtimes_before_apply() {
        let sdk = service_bound_sdk(RuntimeId::new());
        let spec = |id| {
            RuntimeSpec::new(
                id,
                RuntimePlatformSpec {
                    system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                        http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                        https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                        bypass: Vec::new(),
                    })),
                    ..RuntimePlatformSpec::default()
                },
            )
            .unwrap()
        };
        let first = sdk.create_runtime(spec(RuntimeId::new())).await.unwrap();
        let second = sdk.create_runtime(spec(RuntimeId::new())).await.unwrap();
        first.start().await.unwrap();

        assert!(matches!(
            second.start().await.unwrap_err(),
            egrio_runtime::RuntimeStartError::LeaseConflict(_)
        ));
        first.stop().await.unwrap();
    }

    #[tokio::test]
    async fn service_bound_sdk_rejects_foreign_remote_runtime_specs() {
        let expected = RuntimeId::new();
        let cases = [
            RuntimePlatformSpec {
                packet_capture: Some(PacketCaptureSettings {
                    mtu: 1500,
                    source: PacketCaptureSource::Tun,
                    install_default_route: false,
                    install_dns: false,
                    excluded_prefixes: Vec::new(),
                    fake_ip_prefixes: Vec::new(),
                }),
                ..RuntimePlatformSpec::default()
            },
            RuntimePlatformSpec {
                route: Some(RouteSettings {
                    default_route: false,
                    excluded_prefixes: Vec::new(),
                }),
                ..RuntimePlatformSpec::default()
            },
            RuntimePlatformSpec {
                dns: Some(DnsSettings {
                    servers: Vec::new(),
                    search_domains: Vec::new(),
                }),
                ..RuntimePlatformSpec::default()
            },
            RuntimePlatformSpec {
                firewall: Some(FirewallSettings {
                    kill_switch: false,
                    allow_lan: true,
                    excluded_prefixes: Vec::new(),
                    fake_ip_prefixes: Vec::new(),
                }),
                ..RuntimePlatformSpec::default()
            },
        ];

        for platform in cases {
            let actual = RuntimeId::new();
            // Packet capture requires the Runtime-owned Core in the spec;
            // the other remote capabilities stay core-less.
            let core = platform
                .packet_capture
                .is_some()
                .then(egrio_runtime::RuntimeCoreSpec::default);
            let error = service_bound_sdk(expected)
                .create_runtime(RuntimeSpec::with_core(actual, core, platform).unwrap())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RuntimeCreateError::BoundRuntimeIdMismatch {
                    expected: value,
                    actual: other,
                } if value == expected && other == actual
            ));
        }
    }

    #[tokio::test]
    async fn service_bound_sdk_allows_foreign_local_recovery_checkpoint() {
        let expected = RuntimeId::new();
        let foreign = RuntimeId::new();
        let store = Arc::new(crate::InMemoryCheckpointStore::new());
        store
            .create(
                egrio_runtime::RecoveryCheckpoint::new(
                    CheckpointId::new(),
                    foreign,
                    egrio_runtime::RuntimeGeneration::new(1),
                    egrio_runtime::CheckpointOperation::Start,
                    egrio_runtime::CheckpointPhase::Committed,
                    vec![egrio_runtime::CapabilityCheckpoint {
                        lease_key: PlatformLeaseKey::system_proxy(),
                        schema_version: 1,
                        payload: serde_json::json!(null),
                        rollback_payload: None,
                    }],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let sdk = EgrioSdkBuilder {
            checkpoint_store: Some(store),
            ports: RuntimePorts::default(),
            remote_runtime_id: Some(expected),
        }
        .build()
        .unwrap();

        let report = sdk.bootstrap_recovery().await.unwrap();
        assert_eq!(report.checkpoints.len(), 1);
    }

    #[tokio::test]
    async fn service_bound_sdk_recovers_a_local_system_proxy_checkpoint() {
        let expected = RuntimeId::new();
        let foreign = RuntimeId::new();
        let store = Arc::new(crate::InMemoryCheckpointStore::new());
        let platform = Arc::new(crate::InMemoryPlatform::new());
        let build = || {
            EgrioSdkBuilder {
                checkpoint_store: Some(store.clone()),
                ports: RuntimePorts {
                    system_proxy: Some(platform.clone()),
                    ..RuntimePorts::default()
                },
                remote_runtime_id: Some(expected),
            }
            .build()
            .unwrap()
        };
        let sdk = build();
        let runtime = sdk
            .create_runtime(
                RuntimeSpec::new(
                    foreign,
                    RuntimePlatformSpec {
                        system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                            http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                            https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                            bypass: Vec::new(),
                        })),
                        ..RuntimePlatformSpec::default()
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        runtime.start().await.unwrap();
        drop(runtime);
        drop(sdk);

        let reports = build().recover_unresolved().await.unwrap();

        assert_eq!(reports.len(), 1);
        assert!(store.list_unresolved().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn service_bound_sdk_rejects_foreign_remote_recovery_checkpoints() {
        let expected = RuntimeId::new();
        for lease_key in [
            PlatformLeaseKey::packet_capture(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::kill_switch(),
        ] {
            let foreign = RuntimeId::new();
            let store = Arc::new(crate::InMemoryCheckpointStore::new());
            store
                .create(
                    egrio_runtime::RecoveryCheckpoint::new(
                        CheckpointId::new(),
                        foreign,
                        egrio_runtime::RuntimeGeneration::new(1),
                        egrio_runtime::CheckpointOperation::Start,
                        egrio_runtime::CheckpointPhase::Committed,
                        vec![egrio_runtime::CapabilityCheckpoint {
                            lease_key,
                            schema_version: 1,
                            payload: serde_json::json!(null),
                            rollback_payload: None,
                        }],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let sdk = EgrioSdkBuilder {
                checkpoint_store: Some(store),
                ports: RuntimePorts::default(),
                remote_runtime_id: Some(expected),
            }
            .build()
            .unwrap();

            assert!(matches!(
                sdk.bootstrap_recovery().await.unwrap_err(),
                RecoveryBootstrapError::BoundRuntimeIdMismatch {
                    expected: value,
                    actual,
                    ..
                } if value == expected && actual == foreign
            ));
        }
    }

    #[tokio::test]
    async fn service_bound_sdk_keeps_remote_ports_for_the_bound_core_only_runtime() {
        let expected = RuntimeId::new();
        let platform = Arc::new(crate::InMemoryPlatform::new());
        let sdk = EgrioSdkBuilder {
            checkpoint_store: Some(Arc::new(crate::InMemoryCheckpointStore::new())),
            ports: RuntimePorts {
                packet_capture: Some(platform.clone()),
                packet_data_plane: Some(Arc::new(TestPacketDataPlane)),
                core_config: Some(Arc::new(TestCoreConfig)),
                system_proxy: Some(platform.clone()),
                route: Some(platform.clone()),
                dns: Some(platform.clone()),
                firewall: Some(platform),
                connection_health: Some(Arc::new(TestConnectionHealth)),
            },
            remote_runtime_id: Some(expected),
        }
        .build()
        .unwrap();

        let local = sdk.ports_for_scope(false);
        assert!(local.packet_capture.is_none());
        assert!(local.route.is_none());
        assert!(local.dns.is_none());
        assert!(local.firewall.is_none());
        assert!(local.connection_health.is_none());
        assert!(local.system_proxy.is_some());
        assert!(local.packet_data_plane.is_some());

        let remote = sdk.ports_for_scope(true);
        assert!(remote.packet_capture.is_some());
        assert!(remote.route.is_some());
        assert!(remote.dns.is_some());
        assert!(remote.firewall.is_some());
        assert!(remote.connection_health.is_some());
        assert!(remote.system_proxy.is_some());
        assert!(remote.packet_data_plane.is_some());

        let core_only = RuntimeSpec::with_core(
            expected,
            Some(egrio_runtime::RuntimeCoreSpec::default()),
            RuntimePlatformSpec::default(),
        )
        .unwrap();
        let runtime = sdk.create_runtime(core_only.clone()).await.unwrap();
        runtime.start().await.unwrap();
        runtime
            .reload(
                RuntimeSpec::with_core(
                    expected,
                    Some(egrio_runtime::RuntimeCoreSpec::default()),
                    RuntimePlatformSpec {
                        dns: Some(DnsSettings {
                            servers: vec!["1.1.1.1".parse().unwrap()],
                            search_domains: Vec::new(),
                        }),
                        ..RuntimePlatformSpec::default()
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        runtime.reload(core_only).await.unwrap();
        runtime.stop().await.unwrap();
    }
}
