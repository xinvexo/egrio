//! Why an egress dial failed, before any protocol spoke. The egress layer
//! only says what happened; callers above it decide whom each kind is
//! evidence against (a proxy hop, a destination, or this host).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialFailureKind {
    /// This host refused or could not prepare the socket: an outbound policy,
    /// the open-proxy floor, socket setup, or the socket guard.
    Local,
    /// The name did not resolve, or not within the budget.
    Resolve,
    /// The remote refused or did not answer within the budget.
    Connect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DialError {
    pub(crate) kind: DialFailureKind,
    pub(crate) message: String,
}

impl DialError {
    pub(crate) fn local(message: impl Into<String>) -> Self {
        Self {
            kind: DialFailureKind::Local,
            message: message.into(),
        }
    }

    pub(crate) fn resolve(message: impl Into<String>) -> Self {
        Self {
            kind: DialFailureKind::Resolve,
            message: message.into(),
        }
    }

    pub(crate) fn connect(message: impl Into<String>) -> Self {
        Self {
            kind: DialFailureKind::Connect,
            message: message.into(),
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}
