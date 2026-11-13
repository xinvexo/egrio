use serde::{Deserialize, Serialize};

use crate::CapabilityKind;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "kebab-case")]
pub enum RuntimeResource {
    Core,
    Platform { capability: CapabilityKind },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeResourceOutcome {
    Applied,
    Retained,
    Restored,
    RolledBack,
    RecoveryRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResourceChange {
    pub resource: RuntimeResource,
    pub outcome: RuntimeResourceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl RuntimeResourceChange {
    #[must_use]
    pub fn new(resource: RuntimeResource, outcome: RuntimeResourceOutcome) -> Self {
        Self {
            resource,
            outcome,
            message: None,
        }
    }

    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDomainReport {
    pub resources: Vec<RuntimeResourceChange>,
}

impl RuntimeDomainReport {
    #[must_use]
    pub fn new(resources: Vec<RuntimeResourceChange>) -> Self {
        Self { resources }
    }

    pub(crate) fn push(&mut self, change: RuntimeResourceChange) {
        self.resources.push(change);
    }
}
