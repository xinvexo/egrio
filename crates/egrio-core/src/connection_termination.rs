//! Explicit terminal facts for a connection. Byte counts and the last live
//! phase describe activity; they cannot prove why a session ended.

use serde::{Deserialize, Serialize};

use crate::egress::EgressPolicyRejection;
use crate::outbound::OutboundStage;
use crate::tcp_flow::{
    TcpFlowBudget, TcpFlowFailure, TcpFlowIoAction, TcpFlowIoSide, TcpFlowStage,
};

const MAX_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConnectionTermination {
    Completed,
    Cancelled,
    ClientClosed {
        action: TcpFlowIoAction,
        error_kind: String,
        os_code: Option<i32>,
    },
    RouteRejected,
    PolicyRejected {
        reason: EgressPolicyRejection,
    },
    Failed {
        stage: TcpFlowStage,
        cause: ConnectionFailureCause,
    },
    /// The owner disappeared without reporting a result, or a host missed
    /// the bounded terminal record. This is not evidence of success.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConnectionFailureCause {
    Io {
        side: TcpFlowIoSide,
        action: TcpFlowIoAction,
        error_kind: String,
        os_code: Option<i32>,
        message: String,
    },
    UnattributedIo {
        error_kind: String,
        os_code: Option<i32>,
        message: String,
    },
    Budget {
        budget: TcpFlowBudget,
        duration_ms: u64,
    },
    /// The outbound failed to establish, at the stage its connector observed.
    Outbound {
        stage: OutboundStage,
        message: String,
    },
    Message {
        message: String,
    },
}

impl ConnectionTermination {
    pub(crate) fn from_failure(stage: TcpFlowStage, cause: &TcpFlowFailure) -> Self {
        let failure = match cause {
            TcpFlowFailure::Cancelled => return Self::Cancelled,
            TcpFlowFailure::RouteRejected => return Self::RouteRejected,
            TcpFlowFailure::PolicyRejected(reason) => {
                return Self::PolicyRejected { reason: *reason }
            }
            TcpFlowFailure::Io {
                side: TcpFlowIoSide::Client,
                action,
                error,
            } if cause.is_expected_close() => {
                return Self::ClientClosed {
                    action: *action,
                    error_kind: format!("{:?}", error.kind()),
                    os_code: error.raw_os_error(),
                };
            }
            TcpFlowFailure::Io {
                side,
                action,
                error,
            } => ConnectionFailureCause::Io {
                side: *side,
                action: *action,
                error_kind: format!("{:?}", error.kind()),
                os_code: error.raw_os_error(),
                message: bounded_diagnostic(&error.to_string()),
            },
            TcpFlowFailure::UnattributedIo(error) => ConnectionFailureCause::UnattributedIo {
                error_kind: format!("{:?}", error.kind()),
                os_code: error.raw_os_error(),
                message: bounded_diagnostic(&error.to_string()),
            },
            TcpFlowFailure::Budget { budget, duration } => ConnectionFailureCause::Budget {
                budget: *budget,
                duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            },
            TcpFlowFailure::Outbound { stage, message } => ConnectionFailureCause::Outbound {
                stage: *stage,
                message: bounded_diagnostic(message),
            },
            TcpFlowFailure::Message(message) => ConnectionFailureCause::Message {
                message: bounded_diagnostic(message),
            },
        };
        Self::Failed {
            stage,
            cause: failure,
        }
    }
}

fn bounded_diagnostic(message: &str) -> String {
    if message.len() <= MAX_DIAGNOSTIC_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES - "…".len();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &message[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrafficConnectionState;
    use std::{io, time::Duration};

    #[test]
    fn failure_projection_distinguishes_rejection_cancellation_and_real_faults() {
        for (cause, expected) in [
            (TcpFlowFailure::Cancelled, TrafficConnectionState::Cancelled),
            (
                TcpFlowFailure::RouteRejected,
                TrafficConnectionState::Rejected,
            ),
            (
                TcpFlowFailure::PolicyRejected(EgressPolicyRejection::UnresolvedIpv6Scope),
                TrafficConnectionState::Rejected,
            ),
            (
                TcpFlowFailure::io(
                    TcpFlowIoSide::Client,
                    TcpFlowIoAction::Write,
                    io::Error::from(io::ErrorKind::BrokenPipe),
                ),
                TrafficConnectionState::Cancelled,
            ),
            (
                TcpFlowFailure::io(
                    TcpFlowIoSide::Upstream,
                    TcpFlowIoAction::Read,
                    io::Error::from(io::ErrorKind::ConnectionReset),
                ),
                TrafficConnectionState::Failed,
            ),
            (
                TcpFlowFailure::Budget {
                    budget: TcpFlowBudget::Idle,
                    duration: Duration::from_secs(3),
                },
                TrafficConnectionState::Failed,
            ),
        ] {
            assert_eq!(
                TrafficConnectionState::from(&ConnectionTermination::from_failure(
                    TcpFlowStage::Relay,
                    &cause
                )),
                expected
            );
        }
    }

    #[test]
    fn diagnostics_are_bounded_without_breaking_utf8_and_keep_structured_cause() {
        let cause = TcpFlowFailure::Message("原因".repeat(1024));
        let terminal = ConnectionTermination::from_failure(TcpFlowStage::Dial, &cause);
        let ConnectionTermination::Failed {
            stage,
            cause: ConnectionFailureCause::Message { message },
        } = &terminal
        else {
            panic!("message failure")
        };
        assert_eq!(*stage, TcpFlowStage::Dial);
        assert!(message.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(message.ends_with('…'));
        let encoded = serde_json::to_string(&terminal).unwrap();
        assert_eq!(
            serde_json::from_str::<ConnectionTermination>(&encoded).unwrap(),
            terminal
        );
    }
}
