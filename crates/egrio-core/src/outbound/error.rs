//! Outbound dial failures, classified where a connector observes them, so
//! health evidence and diagnostics never parse error text.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::egress::{DialError, DialFailureKind};

/// Where establishing an outbound failed. The stage alone says whom the
/// failure is evidence against: the node (its configuration or any hop
/// stage), the destination, or this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundStage {
    /// The node's configuration cannot be used: cipher, credentials, or an
    /// unsupported option.
    Config,
    /// This host refused or could not prepare the dial.
    Local,
    /// The node's address did not resolve.
    HopResolve,
    /// The node did not accept the connection, or its transport failed
    /// before the target request completed.
    HopConnect,
    /// The node rejected the credentials.
    HopAuth,
    /// The node answered outside its protocol.
    HopProtocol,
    /// The destination's address did not resolve.
    TargetResolve,
    /// The destination refused or could not be reached: directly, or as the
    /// node reported it.
    Target,
}

impl OutboundStage {
    /// Whether the failure is evidence against the node itself.
    pub(crate) fn charges_node(self) -> bool {
        matches!(
            self,
            Self::Config | Self::HopResolve | Self::HopConnect | Self::HopAuth | Self::HopProtocol
        )
    }
}

/// Crate-internal: hosts see the stage and message through
/// [`TcpFlowFailure::Outbound`](crate::TcpFlowFailure::Outbound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundError {
    pub(crate) stage: OutboundStage,
    pub(crate) message: String,
}

impl OutboundError {
    pub(crate) fn new(stage: OutboundStage, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }

    /// A dial to the node's own endpoint.
    pub(crate) fn hop_dial(error: DialError) -> Self {
        let stage = match error.kind {
            DialFailureKind::Local => OutboundStage::Local,
            DialFailureKind::Resolve => OutboundStage::HopResolve,
            DialFailureKind::Connect => OutboundStage::HopConnect,
        };
        Self::new(stage, error.message)
    }

    /// A dial straight to the destination (DIRECT).
    pub(crate) fn target_dial(error: DialError) -> Self {
        let stage = match error.kind {
            DialFailureKind::Local => OutboundStage::Local,
            DialFailureKind::Resolve => OutboundStage::TargetResolve,
            DialFailureKind::Connect => OutboundStage::Target,
        };
        Self::new(stage, error.message)
    }
}

impl From<OutboundError> for crate::tcp_flow::TcpFlowFailure {
    fn from(error: OutboundError) -> Self {
        Self::Outbound {
            stage: error.stage,
            message: error.message,
        }
    }
}

impl fmt::Display for OutboundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Classifies a failure at the site that observed it.
pub(crate) trait OutboundResultExt<T> {
    fn at(self, stage: OutboundStage) -> Result<T, OutboundError>;
}

impl<T, E: fmt::Display> OutboundResultExt<T> for Result<T, E> {
    fn at(self, stage: OutboundStage) -> Result<T, OutboundError> {
        self.map_err(|error| OutboundError::new(stage, error.to_string()))
    }
}
