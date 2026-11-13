use serde::{Deserialize, Serialize};

use crate::{
    CheckpointId, CheckpointOperation, CheckpointPhase, RuntimeCoreGeneration, RuntimeGeneration,
    RuntimeId, RuntimeSpec, RuntimeState,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub id: RuntimeId,
    pub generation: RuntimeGeneration,
    pub state: RuntimeState,
    pub degradation_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCoreDomainStatus {
    pub generation: RuntimeCoreGeneration,
    pub listen_addr: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCheckpointStatus {
    pub id: CheckpointId,
    pub operation: CheckpointOperation,
    pub phase: CheckpointPhase,
}

/// Stable lifecycle snapshot for host-side projections. It exposes only
/// Runtime-owned facts; product diagnostics, persistence, and UI steps remain
/// host concerns layered on top of this value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDomainStatus {
    pub runtime: RuntimeStatus,
    pub spec: RuntimeSpec,
    pub core: Option<RuntimeCoreDomainStatus>,
    pub checkpoint: Option<RuntimeCheckpointStatus>,
}
