use std::collections::BTreeMap;
use std::sync::{mpsc, Mutex};

use egrio_runtime::CapabilityKind;
use egrio_runtime::RuntimeId;
use uuid::Uuid;

use crate::protocol::{
    protocol_version, ControlEnvelope, ControlErrorCode, ControlRequest, ControlResponse,
    SERVICE_PROTOCOL_MAJOR,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceConnectionHealth {
    Disconnected,
    Connecting,
    Authenticating,
    Ready,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlSessionError {
    DuplicateRequest,
    UnknownRequest,
    InvalidProtocol,
    InvalidRuntime,
    InvalidSession,
    Disconnected,
}

type Response = Result<ControlEnvelope<ControlResponse>, ControlSessionError>;

pub trait ControlRequestHandler: Send + Sync + std::fmt::Debug {
    fn handle(
        &self,
        request: ControlRequest,
    ) -> Result<ControlResponse, (ControlErrorCode, String)>;

    fn response_failed(&self, _response: &ControlResponse) {}

    /// A descriptor to send with the response just handled.
    #[cfg(unix)]
    fn take_descriptor(&self) -> Option<std::os::fd::OwnedFd> {
        None
    }
}

#[derive(Debug)]
pub struct ControlServerSession {
    service_version: String,
    capabilities: Vec<CapabilityKind>,
    binding: Mutex<Option<ServerBinding>>,
}

#[derive(Clone, Copy, Debug)]
struct ServerBinding {
    runtime_id: RuntimeId,
    session_id: Uuid,
}

impl ControlServerSession {
    pub fn new(service_version: impl Into<String>, capabilities: Vec<CapabilityKind>) -> Self {
        Self {
            service_version: service_version.into(),
            capabilities,
            binding: Mutex::new(None),
        }
    }

    pub fn handle(
        &self,
        envelope: ControlEnvelope<ControlRequest>,
        handler: &dyn ControlRequestHandler,
    ) -> ControlEnvelope<ControlResponse> {
        if envelope.protocol.major != SERVICE_PROTOCOL_MAJOR {
            return response_error(
                &envelope,
                None,
                ControlErrorCode::IncompatibleVersion,
                "incompatible service protocol major version",
            );
        }
        let mut binding = self.binding.lock().expect("control server binding mutex");
        if binding.is_none() {
            if envelope.session_id.is_some()
                || !matches!(&envelope.body, ControlRequest::Hello { .. })
            {
                return response_error(
                    &envelope,
                    None,
                    ControlErrorCode::InvalidSession,
                    "control session has not completed Hello",
                );
            }
            let session_id = Uuid::new_v4();
            *binding = Some(ServerBinding {
                runtime_id: envelope.runtime_id,
                session_id,
            });
            return ControlEnvelope {
                protocol: protocol_version(),
                request_id: envelope.request_id,
                runtime_id: envelope.runtime_id,
                session_id: Some(session_id),
                body: ControlResponse::Hello {
                    service_version: self.service_version.clone(),
                    session_id,
                    capabilities: self.capabilities.clone(),
                },
            };
        }
        let current = (*binding).expect("control server binding");
        drop(binding);
        if envelope.runtime_id != current.runtime_id
            || envelope.session_id != Some(current.session_id)
            || matches!(&envelope.body, ControlRequest::Hello { .. })
        {
            return response_error(
                &envelope,
                Some(current.session_id),
                ControlErrorCode::InvalidSession,
                "control request does not match the bound session",
            );
        }
        let body = match handler.handle(envelope.body) {
            Ok(response) => response,
            Err((code, message)) => ControlResponse::Error { code, message },
        };
        ControlEnvelope {
            protocol: protocol_version(),
            request_id: envelope.request_id,
            runtime_id: current.runtime_id,
            session_id: Some(current.session_id),
            body,
        }
    }
}

fn response_error(
    request: &ControlEnvelope<ControlRequest>,
    session_id: Option<Uuid>,
    code: ControlErrorCode,
    message: impl Into<String>,
) -> ControlEnvelope<ControlResponse> {
    ControlEnvelope {
        protocol: protocol_version(),
        request_id: request.request_id,
        runtime_id: request.runtime_id,
        session_id,
        body: ControlResponse::Error {
            code,
            message: message.into(),
        },
    }
}

#[derive(Debug)]
pub struct ResponseRouter {
    runtime_id: RuntimeId,
    session_id: Uuid,
    state: Mutex<RouterState>,
    health_tx: tokio::sync::watch::Sender<ServiceConnectionHealth>,
}

#[derive(Debug)]
struct RouterState {
    health: ServiceConnectionHealth,
    pending: BTreeMap<Uuid, mpsc::Sender<Response>>,
}

impl ResponseRouter {
    pub fn new(runtime_id: RuntimeId, session_id: Uuid) -> Self {
        let (health_tx, _) = tokio::sync::watch::channel(ServiceConnectionHealth::Ready);
        Self {
            runtime_id,
            session_id,
            state: Mutex::new(RouterState {
                health: ServiceConnectionHealth::Ready,
                pending: BTreeMap::new(),
            }),
            health_tx,
        }
    }

    pub fn register(
        &self,
        request_id: Uuid,
    ) -> Result<mpsc::Receiver<Response>, ControlSessionError> {
        let mut state = self.state.lock().expect("response router mutex");
        if state.health != ServiceConnectionHealth::Ready {
            return Err(ControlSessionError::Disconnected);
        }
        if state.pending.contains_key(&request_id) {
            return Err(ControlSessionError::DuplicateRequest);
        }
        let (sender, receiver) = mpsc::channel();
        state.pending.insert(request_id, sender);
        Ok(receiver)
    }

    pub fn dispatch(
        &self,
        envelope: ControlEnvelope<ControlResponse>,
    ) -> Result<(), ControlSessionError> {
        let error = if envelope.protocol.major != SERVICE_PROTOCOL_MAJOR {
            Some(ControlSessionError::InvalidProtocol)
        } else if envelope.runtime_id != self.runtime_id {
            Some(ControlSessionError::InvalidRuntime)
        } else if envelope.session_id != Some(self.session_id) {
            Some(ControlSessionError::InvalidSession)
        } else {
            None
        };
        let sender = self
            .state
            .lock()
            .expect("response router mutex")
            .pending
            .remove(&envelope.request_id)
            .ok_or(ControlSessionError::UnknownRequest)?;
        match error {
            Some(error) => {
                let _ = sender.send(Err(error.clone()));
                Err(error)
            }
            None => sender
                .send(Ok(envelope))
                .map_err(|_| ControlSessionError::UnknownRequest),
        }
    }

    pub fn disconnect(&self) {
        self.finish(ServiceConnectionHealth::Disconnected);
    }

    pub fn degrade(&self) {
        self.finish(ServiceConnectionHealth::Degraded);
    }

    fn finish(&self, health: ServiceConnectionHealth) {
        let mut state = self.state.lock().expect("response router mutex");
        if state.health == ServiceConnectionHealth::Disconnected
            && health == ServiceConnectionHealth::Degraded
        {
            return;
        }
        state.health = health;
        for (_, sender) in std::mem::take(&mut state.pending) {
            let _ = sender.send(Err(ControlSessionError::Disconnected));
        }
        self.health_tx.send_replace(health);
    }

    pub fn cancel(&self, request_id: Uuid) {
        self.state
            .lock()
            .expect("response router mutex")
            .pending
            .remove(&request_id);
    }

    pub fn health(&self) -> ServiceConnectionHealth {
        self.state.lock().expect("response router mutex").health
    }

    pub fn subscribe_health(&self) -> tokio::sync::watch::Receiver<ServiceConnectionHealth> {
        self.health_tx.subscribe()
    }
}

impl std::fmt::Display for ControlSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControlSessionError {}
