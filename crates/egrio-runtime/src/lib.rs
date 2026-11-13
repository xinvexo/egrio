use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

mod capability;
mod checkpoint;
mod core;
mod lease;
mod report;
mod runtime;
mod spec;
mod state;

pub use capability::{
    capture_prefixes, family_capture_prefixes, CapabilityError, CapabilityErrorCode,
    CapabilityFuture, CapabilityKind, CapabilityObservation, CapabilityOperationReport,
    CapabilitySupport, ConnectionHealth, ConnectionHealthFuture, CoreConfigSource, DnsControl,
    DnsSettings, FirewallControl, FirewallSettings, IpPrefix, PacketCapture, PacketCaptureOpen,
    PacketCaptureSettings, PacketCaptureSource, PacketDataPlane, PacketDataPlaneFuture,
    RouteControl, RouteSettings, SystemProxyControl, SystemProxySettings,
    MAX_CAPTURE_ROUTES_PER_FAMILY, MAX_EXCLUDED_PREFIXES,
};
pub use checkpoint::{
    CapabilityCheckpoint, CheckpointFuture, CheckpointId, CheckpointOperation, CheckpointPhase,
    CheckpointRevision, CheckpointStore, CheckpointStoreError, CheckpointStoreErrorCode,
    RecoveryCheckpoint, RecoveryCheckpointError, StoredCheckpoint,
    RECOVERY_CHECKPOINT_SCHEMA_VERSION,
};
pub use core::{RuntimeCore, RuntimeCoreEnsureReport, RuntimeCoreGeneration, TelemetryCursor};
pub use lease::{
    LeaseCoordinator, LeaseExpandError, LeaseGrant, LeaseGrantId, LeaseGrantSecret,
    LeaseReleaseEvidence, LeaseRequestError, LeaseRequestSet, LeaseTransitionError,
    LeaseTransitionErrorCode, ObservedExternalOwner, PlatformLeaseConflict, PlatformLeaseKey,
    PlatformLeaseKeyError, PlatformLeaseState,
};
pub use report::{
    RuntimeDomainReport, RuntimeResource, RuntimeResourceChange, RuntimeResourceOutcome,
};
pub use runtime::{
    ConfigurationClass, ConfigurationOperation, ConfigurationPhase, Runtime, RuntimeAssemblyError,
    RuntimeAssemblyErrorCode, RuntimeConfigurationChange, RuntimeConfigurationReport, RuntimePorts,
    RuntimeRecoveryError, RuntimeRecoveryReport, RuntimeReloadError, RuntimeReloadReport,
    RuntimeStartError, RuntimeStartReport, RuntimeStopError, RuntimeStopReport,
};
pub use spec::{
    RuntimeCoreSpec, RuntimePlatformSpec, RuntimeSpec, RuntimeSpecError, RuntimeSpecErrorCode,
    SystemProxyEndpoint, SystemProxySpec,
};
pub use state::{
    RuntimeCheckpointStatus, RuntimeCoreDomainStatus, RuntimeDomainStatus, RuntimeStatus,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeId(Uuid);

impl RuntimeId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for RuntimeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeGeneration(u64);

impl RuntimeGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeState {
    Created,
    Starting,
    Running,
    Reloading,
    Degraded,
    Stopping,
    Stopped,
}
