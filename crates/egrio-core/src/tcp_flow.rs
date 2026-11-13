//! Failure information for one TCP pipeline. Socket errors remain typed until
//! the host decides how to report the flow; expected teardown is not inferred
//! from an operating system's error text.

use std::{fmt, io, time::Duration};

use crate::egress::EgressPolicyRejection;
use crate::outbound::OutboundStage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpFlowStage {
    Admission,
    Enrich,
    Route,
    Dial,
    Reply,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpFlowIoSide {
    Client,
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpFlowIoAction {
    Read,
    Write,
    Flush,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpFlowBudget {
    Dial,
    FirstUpstreamByte,
    Idle,
}

#[derive(Debug)]
pub enum TcpFlowFailure {
    Cancelled,
    Io {
        side: TcpFlowIoSide,
        action: TcpFlowIoAction,
        error: io::Error,
    },
    UnattributedIo(io::Error),
    Budget {
        budget: TcpFlowBudget,
        duration: Duration,
    },
    RouteRejected,
    PolicyRejected(EgressPolicyRejection),
    /// The selected outbound failed to establish, at the stage its connector
    /// observed; the stage says whom the failure is evidence against.
    Outbound {
        stage: OutboundStage,
        message: String,
    },
    /// A failure that names no outbound stage, kept as its full message
    /// without guessing an IO endpoint or ErrorKind from it.
    Message(String),
}

impl TcpFlowFailure {
    pub(crate) fn io(side: TcpFlowIoSide, action: TcpFlowIoAction, error: io::Error) -> Self {
        Self::Io {
            side,
            action,
            error,
        }
    }

    pub fn is_expected_close(&self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::RouteRejected | Self::PolicyRejected(_)
        ) || matches!(
            self,
            Self::Io {
                side: TcpFlowIoSide::Client,
                error,
                ..
            } if matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)
        )
    }
}

impl fmt::Display for TcpFlowFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("session cancelled"),
            Self::Io {
                side,
                action,
                error,
            } => write!(
                f,
                "{side:?}/{action:?}: kind={:?} os_code={:?} {error}",
                error.kind(),
                error.raw_os_error()
            ),
            Self::UnattributedIo(error) => write!(
                f,
                "unknown IO origin: kind={:?} os_code={:?} {error}",
                error.kind(),
                error.raw_os_error()
            ),
            Self::Budget { budget, duration } => {
                write!(f, "{budget:?} budget timed out after {duration:?}")
            }
            Self::RouteRejected => f.write_str("TCP flow rejected by route"),
            Self::PolicyRejected(reason) => write!(f, "TCP flow rejected by policy: {reason}"),
            Self::Outbound { stage, message } => write!(f, "outbound {stage:?}: {message}"),
            Self::Message(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TcpFlowFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } | Self::UnattributedIo(error) => Some(error),
            Self::PolicyRejected(reason) => Some(reason),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TcpFlowContext {
    pub session_id: Option<u64>,
    /// The original capture/protocol destination, including fake IPs.
    pub target: String,
    /// The recovered fake-IP mapping or sniffed routing domain.
    pub route_host: Option<String>,
    /// The destination passed to the selected connector after enrichment.
    pub dial_target: Option<String>,
    pub outbound: Option<String>,
    /// The concrete node selected from an outbound group.
    pub resolved_outbound: Option<String>,
    pub matched_rule: Option<String>,
    pub matched_kind: Option<crate::RouteMatchKind>,
    pub matched_payload: Option<String>,
}

#[derive(Debug)]
pub struct NativeTcpFlowError {
    pub stage: TcpFlowStage,
    pub context: TcpFlowContext,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub cause: TcpFlowFailure,
}

impl NativeTcpFlowError {
    pub(crate) fn new(stage: TcpFlowStage, context: TcpFlowContext, cause: TcpFlowFailure) -> Self {
        Self {
            stage,
            context,
            upload_bytes: 0,
            download_bytes: 0,
            cause,
        }
    }

    pub fn is_expected_close(&self) -> bool {
        self.cause.is_expected_close()
    }
}

impl fmt::Display for NativeTcpFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stage={:?} session_id={:?} target={} route_host={:?} dial_target={:?} outbound={:?} resolved_outbound={:?} rule={:?} rule_kind={:?} rule_payload={:?} up={} down={} cause={}",
            self.stage, self.context.session_id, self.context.target, self.context.route_host,
            self.context.dial_target, self.context.outbound, self.context.resolved_outbound,
            self.context.matched_rule, self.context.matched_kind, self.context.matched_payload,
            self.upload_bytes, self.download_bytes, self.cause
        )
    }
}

impl std::error::Error for NativeTcpFlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_identified_client_disconnects_and_explicit_cancellation_are_expected() {
        for side in [TcpFlowIoSide::Client, TcpFlowIoSide::Upstream] {
            for kind in [
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::TimedOut,
                io::ErrorKind::InvalidData,
            ] {
                let failure =
                    TcpFlowFailure::io(side, TcpFlowIoAction::Write, io::Error::new(kind, "test"));
                assert_eq!(
                    failure.is_expected_close(),
                    side == TcpFlowIoSide::Client
                        && matches!(
                            kind,
                            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                        )
                );
            }
        }
        assert!(
            !TcpFlowFailure::Message("Broken pipe: cancelled during dial".into())
                .is_expected_close()
        );
        assert!(!TcpFlowFailure::UnattributedIo(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "unknown side"
        ))
        .is_expected_close());
        assert!(!TcpFlowFailure::Budget {
            budget: TcpFlowBudget::Dial,
            duration: Duration::from_secs(8)
        }
        .is_expected_close());
        assert!(TcpFlowFailure::Cancelled.is_expected_close());
        for reason in [
            EgressPolicyRejection::ScopedTargetRequiresDirect,
            EgressPolicyRejection::UnresolvedIpv6Scope,
        ] {
            assert!(TcpFlowFailure::PolicyRejected(reason).is_expected_close());
        }
    }
}
