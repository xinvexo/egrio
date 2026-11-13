use std::error::Error;
use std::fmt;

use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::{CheckpointId, RuntimeId};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PlatformLeaseKey {
    capability: String,
    scope: String,
}

impl<'de> Deserialize<'de> for PlatformLeaseKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct LeaseKeyRepr {
            capability: String,
            scope: String,
        }

        let value = LeaseKeyRepr::deserialize(deserializer)?;
        Self::new(value.capability, value.scope).map_err(D::Error::custom)
    }
}

impl PlatformLeaseKey {
    pub fn new(
        capability: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<Self, PlatformLeaseKeyError> {
        let capability = capability.into();
        let scope = scope.into();
        if capability.trim().is_empty() {
            return Err(PlatformLeaseKeyError::new(
                "lease capability must not be empty",
            ));
        }
        if scope.trim().is_empty() {
            return Err(PlatformLeaseKeyError::new("lease scope must not be empty"));
        }
        Ok(Self { capability, scope })
    }

    #[must_use]
    pub fn system_proxy() -> Self {
        Self::new("system-proxy", "global").expect("built-in lease key")
    }
    #[must_use]
    pub fn packet_capture() -> Self {
        Self::new("packet-capture", "global").expect("built-in lease key")
    }
    #[must_use]
    pub fn default_route() -> Self {
        Self::new("route", "default").expect("built-in lease key")
    }
    #[must_use]
    pub fn system_dns() -> Self {
        Self::new("dns", "system").expect("built-in lease key")
    }
    #[must_use]
    pub fn kill_switch() -> Self {
        Self::new("firewall", "kill-switch").expect("built-in lease key")
    }
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformLeaseKeyError {
    message: String,
}
impl PlatformLeaseKeyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
impl fmt::Display for PlatformLeaseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl Error for PlatformLeaseKeyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRequestSet {
    owner: RuntimeId,
    keys: Vec<PlatformLeaseKey>,
}
impl LeaseRequestSet {
    pub fn new(
        owner: RuntimeId,
        keys: impl IntoIterator<Item = PlatformLeaseKey>,
    ) -> Result<Self, LeaseRequestError> {
        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            return Err(LeaseRequestError::Empty);
        }
        Ok(Self { owner, keys })
    }
    #[must_use]
    pub const fn owner(&self) -> RuntimeId {
        self.owner
    }
    #[must_use]
    pub fn keys(&self) -> &[PlatformLeaseKey] {
        &self.keys
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseRequestError {
    Empty,
}
impl fmt::Display for LeaseRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("lease request must contain at least one key")
    }
}
impl Error for LeaseRequestError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseGrantId(Uuid);
impl LeaseGrantId {
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
impl Default for LeaseGrantId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    id: LeaseGrantId,
    owner: RuntimeId,
    keys: Vec<PlatformLeaseKey>,
    secret: LeaseGrantSecret,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct LeaseGrantSecret(Uuid);

impl LeaseGrant {
    #[doc(hidden)]
    #[must_use]
    pub fn issue(owner: RuntimeId, keys: Vec<PlatformLeaseKey>) -> (Self, LeaseGrantSecret) {
        let secret = LeaseGrantSecret(Uuid::new_v4());
        (
            Self {
                id: LeaseGrantId::new(),
                owner,
                keys,
                secret,
            },
            secret,
        )
    }
    #[must_use]
    pub const fn id(&self) -> LeaseGrantId {
        self.id
    }
    #[must_use]
    pub const fn owner(&self) -> RuntimeId {
        self.owner
    }
    #[must_use]
    pub fn keys(&self) -> &[PlatformLeaseKey] {
        &self.keys
    }

    #[doc(hidden)]
    #[must_use]
    pub fn authenticates(&self, secret: LeaseGrantSecret) -> bool {
        self.secret == secret
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum PlatformLeaseState {
    Available,
    Held,
    Releasing,
    RecoveryRequired,
    Recovering,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedExternalOwner {
    pub source: String,
    pub identity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlatformLeaseConflict {
    pub requested: PlatformLeaseKey,
    pub requested_by: RuntimeId,
    pub current_owner: Option<RuntimeId>,
    pub state: PlatformLeaseState,
    pub external_owner: Option<ObservedExternalOwner>,
    pub checkpoint_id: Option<CheckpointId>,
}
impl fmt::Display for PlatformLeaseConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "platform lease {}:{} is unavailable in state {:?}",
            self.requested.capability(),
            self.requested.scope(),
            self.state
        )
    }
}
impl Error for PlatformLeaseConflict {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseExpandError {
    Conflict(PlatformLeaseConflict),
    Transition(LeaseTransitionError),
}

impl fmt::Display for LeaseExpandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(error) => error.fmt(formatter),
            Self::Transition(error) => error.fmt(formatter),
        }
    }
}

impl Error for LeaseExpandError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum LeaseReleaseEvidence {
    NoModification,
    VerifiedRestore,
    VerifiedAdoption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum LeaseTransitionErrorCode {
    UnknownGrant,
    GrantMismatch,
    InvalidState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeaseTransitionError {
    pub code: LeaseTransitionErrorCode,
    pub message: String,
}
impl fmt::Display for LeaseTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl Error for LeaseTransitionError {}

#[doc(hidden)]
pub trait LeaseCoordinator: Send + Sync + fmt::Debug {
    fn acquire_all(&self, request: LeaseRequestSet) -> Result<LeaseGrant, PlatformLeaseConflict>;
    fn expand(
        &self,
        grant: &LeaseGrant,
        request: LeaseRequestSet,
    ) -> Result<LeaseGrant, LeaseExpandError>;
    fn begin_release(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError>;
    fn mark_recovery_required(
        &self,
        grant: &LeaseGrant,
        checkpoint_id: CheckpointId,
    ) -> Result<(), LeaseTransitionError>;
    fn begin_recovery(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError>;
    /// Returns a recovering grant to holding when the recovery restored only
    /// part of its resources, so the owner can shrink it to what it keeps.
    fn resume(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError>;
    fn shrink(
        &self,
        grant: &LeaseGrant,
        retained_keys: Vec<PlatformLeaseKey>,
        evidence: LeaseReleaseEvidence,
    ) -> Result<LeaseGrant, LeaseTransitionError>;
    fn release(
        &self,
        grant: &LeaseGrant,
        evidence: LeaseReleaseEvidence,
    ) -> Result<(), LeaseTransitionError>;
}
