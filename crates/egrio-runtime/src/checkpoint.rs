use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{PlatformLeaseKey, RuntimeGeneration, RuntimeId};

pub const RECOVERY_CHECKPOINT_SCHEMA_VERSION: u16 = 2;
pub type CheckpointFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CheckpointStoreError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointId(Uuid);
impl CheckpointId {
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
impl Default for CheckpointId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointRevision(u64);
impl CheckpointRevision {
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
pub enum CheckpointOperation {
    Start,
    Reload,
    Stop,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointPhase {
    Prepared,
    Applying,
    Committed,
    Restoring,
    RecoveryRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCheckpoint {
    pub lease_key: PlatformLeaseKey,
    /// Adapter-owned payload contract version. Runtime validates that the
    /// value is versioned, while the matching capability port decides which
    /// positive versions it can restore.
    pub schema_version: u16,
    pub payload: Value,
    /// Latest adapter-prepared payload for a changed retained capability.
    /// Runtime keeps `payload` as the ultimate restore baseline and treats
    /// this value as opaque; adapters may use it to recover current ownership
    /// metadata after a committed reload or interrupted process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_payload: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCheckpoint {
    pub schema_version: u16,
    pub id: CheckpointId,
    pub runtime_id: RuntimeId,
    pub generation: RuntimeGeneration,
    pub operation: CheckpointOperation,
    pub phase: CheckpointPhase,
    pub leases: Vec<PlatformLeaseKey>,
    pub capabilities: Vec<CapabilityCheckpoint>,
}
impl RecoveryCheckpoint {
    pub fn new(
        id: CheckpointId,
        runtime_id: RuntimeId,
        generation: RuntimeGeneration,
        operation: CheckpointOperation,
        phase: CheckpointPhase,
        capabilities: Vec<CapabilityCheckpoint>,
    ) -> Result<Self, RecoveryCheckpointError> {
        if capabilities.is_empty() {
            return Err(RecoveryCheckpointError::EmptyCapabilities);
        }
        let mut leases = capabilities
            .iter()
            .map(|entry| entry.lease_key.clone())
            .collect::<Vec<_>>();
        leases.sort();
        leases.dedup();
        let checkpoint = Self {
            schema_version: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
            id,
            runtime_id,
            generation,
            operation,
            phase,
            leases,
            capabilities,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }
    pub fn validate(&self) -> Result<(), RecoveryCheckpointError> {
        if self.schema_version != RECOVERY_CHECKPOINT_SCHEMA_VERSION {
            return Err(RecoveryCheckpointError::UnsupportedCheckpointSchema);
        }
        if self.runtime_id.as_uuid().is_nil() {
            return Err(RecoveryCheckpointError::NilRuntimeId);
        }
        if self.capabilities.is_empty() {
            return Err(RecoveryCheckpointError::EmptyCapabilities);
        }
        let mut capability_leases = BTreeSet::new();
        for capability in &self.capabilities {
            if capability.schema_version == 0 {
                return Err(RecoveryCheckpointError::UnsupportedCapabilitySchema);
            }
            if !capability_leases.insert(capability.lease_key.clone()) {
                return Err(RecoveryCheckpointError::DuplicateCapabilityLease);
            }
        }
        let expected = self
            .capabilities
            .iter()
            .map(|entry| entry.lease_key.clone())
            .collect::<BTreeSet<_>>();
        let actual = self.leases.iter().cloned().collect::<BTreeSet<_>>();
        if actual.len() != self.leases.len() || !expected.is_subset(&actual) {
            return Err(RecoveryCheckpointError::LeaseSetMismatch);
        }
        Ok(())
    }

    pub fn with_leases(
        mut self,
        mut leases: Vec<PlatformLeaseKey>,
    ) -> Result<Self, RecoveryCheckpointError> {
        leases.sort();
        leases.dedup();
        self.leases = leases;
        self.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCheckpointError {
    UnsupportedCheckpointSchema,
    UnsupportedCapabilitySchema,
    DuplicateCapabilityLease,
    NilRuntimeId,
    EmptyCapabilities,
    LeaseSetMismatch,
}
impl fmt::Display for RecoveryCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCheckpointSchema => {
                f.write_str("recovery checkpoint schema version is unsupported")
            }
            Self::UnsupportedCapabilitySchema => {
                f.write_str("capability checkpoint schema version is unsupported")
            }
            Self::DuplicateCapabilityLease => {
                f.write_str("recovery checkpoint contains duplicate capability leases")
            }
            Self::NilRuntimeId => f.write_str("recovery checkpoint runtime id must not be nil"),
            Self::EmptyCapabilities => {
                f.write_str("recovery checkpoint must contain capability entries")
            }
            Self::LeaseSetMismatch => {
                f.write_str("recovery checkpoint leases do not match capability entries")
            }
        }
    }
}
impl Error for RecoveryCheckpointError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredCheckpoint {
    pub checkpoint: RecoveryCheckpoint,
    pub revision: CheckpointRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointStoreErrorCode {
    Unavailable,
    AlreadyExists,
    NotFound,
    RevisionConflict,
    Corrupt,
    UnsupportedSchema,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointStoreError {
    pub code: CheckpointStoreErrorCode,
    pub message: String,
}
impl CheckpointStoreError {
    #[must_use]
    pub fn new(code: CheckpointStoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl fmt::Display for CheckpointStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl Error for CheckpointStoreError {}

pub trait CheckpointStore: Send + Sync + fmt::Debug {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint>;
    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>>;
    fn replace<'a>(
        &'a self,
        expected: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint>;
    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>>;
    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        expected: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()>;
}
