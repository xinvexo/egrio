//! What a start, stop, reload or recovery reports, and how each fails.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStartReport {
    pub generation: RuntimeGeneration,
    pub changed: bool,
    pub checkpoint_id: Option<CheckpointId>,
    pub resources: RuntimeDomainReport,
}

#[derive(Debug)]
pub enum RuntimeStartError {
    InvalidState(RuntimeState),
    UnsupportedSpec(String),
    /// The spec-declared Core failed to compile its inputs, bind its
    /// listener, or resolve spec endpoints. Raised before any lease,
    /// checkpoint, or OS mutation.
    Core(String),
    LeaseConflict(PlatformLeaseConflict),
    Capability(crate::CapabilityError),
    Store(CheckpointStoreError),
    RecoveryRequired(crate::CapabilityError),
    Cleanup(String),
    Task(String),
}

impl fmt::Display for RuntimeStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(state) => write!(formatter, "runtime cannot start from {state:?}"),
            Self::UnsupportedSpec(message) => message.fmt(formatter),
            Self::LeaseConflict(error) => error.fmt(formatter),
            Self::Capability(error) | Self::RecoveryRequired(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Core(message) | Self::Cleanup(message) | Self::Task(message) => {
                message.fmt(formatter)
            }
        }
    }
}
impl Error for RuntimeStartError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStopReport {
    pub generation: RuntimeGeneration,
    pub changed: bool,
    pub restored: bool,
    pub resources: RuntimeDomainReport,
}

#[derive(Debug)]
pub enum RuntimeStopError {
    InvalidState(RuntimeState),
    Capability(crate::CapabilityError),
    Store(CheckpointStoreError),
    Cleanup {
        message: String,
        capabilities_restored: bool,
    },
    Task(String),
}

impl RuntimeStopError {
    /// Whether all platform capabilities were verified restored before a
    /// later checkpoint/lease finalization step failed.
    pub fn capabilities_restored(&self) -> bool {
        matches!(
            self,
            Self::Store(_)
                | Self::Cleanup {
                    capabilities_restored: true,
                    ..
                }
        )
    }
}

impl fmt::Display for RuntimeStopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(state) => write!(formatter, "runtime cannot stop from {state:?}"),
            Self::Capability(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Cleanup { message, .. } | Self::Task(message) => message.fmt(formatter),
        }
    }
}
impl Error for RuntimeStopError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeReloadReport {
    pub generation: RuntimeGeneration,
    pub committed: bool,
    pub recovery_required: bool,
    pub resources: RuntimeDomainReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecoveryReport {
    pub checkpoint_id: CheckpointId,
    pub restored: bool,
    pub resources: RuntimeDomainReport,
}

#[derive(Debug)]
pub enum RuntimeRecoveryError {
    Capability(CapabilityError),
    Store(CheckpointStoreError),
    Cleanup(String),
}

impl fmt::Display for RuntimeRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Cleanup(message) => message.fmt(formatter),
        }
    }
}
impl Error for RuntimeRecoveryError {}

#[derive(Debug)]
pub enum RuntimeReloadError {
    InvalidSpec(crate::RuntimeSpecError),
    Assembly(RuntimeAssemblyError),
    InvalidRuntimeId,
    InvalidState(RuntimeState),
    ConfigurationPending(String),
    UnsupportedSpec(String),
    Core {
        message: String,
        report: RuntimeDomainReport,
    },
    LeaseConflict {
        error: PlatformLeaseConflict,
        report: RuntimeDomainReport,
    },
    Capability {
        error: crate::CapabilityError,
        report: RuntimeDomainReport,
    },
    Store {
        error: CheckpointStoreError,
        report: RuntimeDomainReport,
    },
    LeaseTransition {
        error: LeaseTransitionError,
        report: RuntimeDomainReport,
    },
    RecoveryRequired {
        error: crate::CapabilityError,
        report: RuntimeDomainReport,
    },
    Cleanup {
        message: String,
        report: RuntimeDomainReport,
    },
    Task(String),
}

impl RuntimeReloadError {
    #[must_use]
    pub fn report(&self) -> Option<&RuntimeDomainReport> {
        match self {
            Self::Core { report, .. }
            | Self::LeaseConflict { report, .. }
            | Self::Capability { report, .. }
            | Self::Store { report, .. }
            | Self::LeaseTransition { report, .. }
            | Self::RecoveryRequired { report, .. }
            | Self::Cleanup { report, .. } => Some(report),
            _ => None,
        }
    }
}

impl fmt::Display for RuntimeReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(error) => error.fmt(formatter),
            Self::Assembly(error) => error.fmt(formatter),
            Self::InvalidRuntimeId => formatter.write_str("reload cannot change runtime id"),
            Self::InvalidState(state) => write!(formatter, "runtime cannot reload from {state:?}"),
            Self::UnsupportedSpec(message)
            | Self::ConfigurationPending(message)
            | Self::Task(message) => message.fmt(formatter),
            Self::Core { message, .. } => message.fmt(formatter),
            Self::LeaseConflict { error, .. } => error.fmt(formatter),
            Self::Capability { error, .. } | Self::RecoveryRequired { error, .. } => {
                error.fmt(formatter)
            }
            Self::Store { error, .. } => error.fmt(formatter),
            Self::LeaseTransition { error, .. } => error.fmt(formatter),
            Self::Cleanup { message, .. } => message.fmt(formatter),
        }
    }
}
impl Error for RuntimeReloadError {}
