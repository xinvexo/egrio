use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::protocol::{ControlEnvelope, ControlRequest, ControlResponse};

pub type ControlFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

pub trait ControlTransport: Send + Sync + fmt::Debug {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>>;
}

pub trait ControlConnection: Send + Sync + fmt::Debug {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>>;
    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()>;
    fn close_now(&self);

    /// The oldest descriptor a response carried that no caller took yet.
    #[cfg(unix)]
    fn take_descriptor(&self) -> Option<std::os::fd::OwnedFd> {
        None
    }

    fn close(&self) -> ControlFuture<'_, ()> {
        self.close_now();
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    ConnectFailed,
    PossiblyDelivered,
    Protocol,
    Authentication,
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn possibly_delivered(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::PossiblyDelivered, message)
    }

    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Disconnected, message)
    }

    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for TransportError {}
