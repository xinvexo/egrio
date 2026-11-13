use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egrio_runtime::RuntimeId;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::protocol::{
    protocol_version, ControlEnvelope, ControlRequest, ControlResponse, SERVICE_PROTOCOL_MAJOR,
};
use crate::session::{ControlSessionError, ResponseRouter, ServiceConnectionHealth};
use crate::transport::{ControlConnection, ControlTransport, TransportError, TransportErrorKind};

/// How long the service has to answer a Hello, which it does as soon as it
/// has read it.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// How long the service has to answer a request. The slowest is the one that
/// opens the tunnel, where the system may first install the adapter's
/// driver. A service that has not answered by then is taken not to be
/// answering at all, and its session ends: a request -- one of a quit's
/// among them -- otherwise waits for as long as the service stays silent,
/// and so does everything queued behind it.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct ControlClient {
    transport: Arc<dyn ControlTransport>,
    runtime_id: RuntimeId,
    app_version: String,
    hello_deadline: Duration,
    response_deadline: Duration,
    hello_request_id: Mutex<Option<Uuid>>,
    /// The current service session. Once its connection ends (the service
    /// stopped, crashed or was updated), the next request replaces it with a
    /// fresh session, exactly as a restarted app would get one; the service
    /// released the old session's resources with its connection.
    connected: Mutex<Option<Arc<ConnectedClient>>>,
    lifecycle: tokio::sync::Mutex<()>,
    closed: AtomicBool,
}

#[derive(Debug)]
struct ConnectedClient {
    inner: Arc<ClientInner>,
    reader: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

struct CloseConnectionOnDrop(Option<Arc<dyn ControlConnection>>);

impl CloseConnectionOnDrop {
    fn new(connection: Arc<dyn ControlConnection>) -> Self {
        Self(Some(connection))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CloseConnectionOnDrop {
    fn drop(&mut self) {
        if let Some(connection) = self.0.take() {
            connection.close_now();
        }
    }
}

impl ConnectedClient {
    fn abort_reader(&self) {
        if let Some(reader) = self.reader.lock().expect("control reader mutex").take() {
            reader.abort();
        }
    }
}

impl Drop for ConnectedClient {
    fn drop(&mut self) {
        self.inner.router.disconnect();
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.inner.connection.close_now();
        }
        self.abort_reader();
    }
}

#[derive(Debug)]
struct ClientInner {
    runtime_id: RuntimeId,
    session_id: Uuid,
    connection: Arc<dyn ControlConnection>,
    router: Arc<ResponseRouter>,
    writer: tokio::sync::Mutex<()>,
}

impl ControlClient {
    pub fn deferred(
        transport: Arc<dyn ControlTransport>,
        runtime_id: RuntimeId,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            runtime_id,
            app_version: app_version.into(),
            hello_deadline: HELLO_DEADLINE,
            response_deadline: RESPONSE_DEADLINE,
            hello_request_id: Mutex::new(None),
            connected: Mutex::new(None),
            lifecycle: tokio::sync::Mutex::new(()),
            closed: AtomicBool::new(false),
        }
    }

    /// The times the service has to answer a Hello and a request, for a
    /// test that waits them out.
    #[doc(hidden)]
    pub fn with_deadlines(mut self, hello: Duration, response: Duration) -> Self {
        self.hello_deadline = hello;
        self.response_deadline = response;
        self
    }

    pub async fn connect(
        transport: Arc<dyn ControlTransport>,
        runtime_id: RuntimeId,
        app_version: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let client = Self::deferred(transport, runtime_id, app_version);
        client.ensure_connected().await?;
        Ok(client)
    }

    pub async fn connect_with_request_id(
        transport: Arc<dyn ControlTransport>,
        runtime_id: RuntimeId,
        app_version: impl Into<String>,
        request_id: Uuid,
    ) -> Result<Self, TransportError> {
        let client = Self::deferred(transport, runtime_id, app_version);
        *client
            .hello_request_id
            .lock()
            .expect("control hello request id mutex") = Some(request_id);
        client.ensure_connected().await?;
        Ok(client)
    }

    fn current(&self) -> Option<Arc<ConnectedClient>> {
        self.connected
            .lock()
            .expect("control session mutex")
            .clone()
    }

    /// The oldest descriptor a response of the current session carried, for
    /// the request that expected it.
    #[cfg(unix)]
    pub fn take_descriptor(&self) -> Option<std::os::fd::OwnedFd> {
        self.current()?.inner.connection.take_descriptor()
    }

    /// The live session, establishing one when there is none yet or the
    /// previous one's connection ended.
    async fn ensure_connected(&self) -> Result<Arc<ConnectedClient>, TransportError> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::disconnected("control client is closed"));
        }
        if let Some(connected) = self.current() {
            if connected.inner.router.health() == ServiceConnectionHealth::Ready {
                return Ok(connected);
            }
        }
        let ended = self.connected.lock().expect("control session mutex").take();
        drop(ended);
        let request_id = self
            .hello_request_id
            .lock()
            .expect("control hello request id mutex")
            .take()
            .unwrap_or_else(Uuid::new_v4);
        let connected = Arc::new(
            Self::establish(
                self.transport.clone(),
                self.runtime_id,
                self.app_version.clone(),
                request_id,
                self.hello_deadline,
            )
            .await?,
        );
        *self.connected.lock().expect("control session mutex") = Some(connected.clone());
        Ok(connected)
    }

    async fn establish(
        transport: Arc<dyn ControlTransport>,
        runtime_id: RuntimeId,
        app_version: String,
        request_id: Uuid,
        hello_deadline: Duration,
    ) -> Result<ConnectedClient, TransportError> {
        let connection = transport.connect().await?;
        let mut cleanup = CloseConnectionOnDrop::new(connection.clone());
        let hello = ControlEnvelope {
            protocol: protocol_version(),
            request_id,
            runtime_id,
            session_id: None,
            body: ControlRequest::Hello { app_version },
        };
        connection.write_envelope(&hello).await?;
        // A connection can be made to a service that serves nobody: the
        // system takes it for a process that has stopped running its code.
        let response = tokio::time::timeout(hello_deadline, connection.read_envelope())
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportErrorKind::ConnectFailed,
                    format!(
                        "the Egrio service did not answer within {} seconds of the connection",
                        hello_deadline.as_secs()
                    ),
                )
            })??;
        if response.protocol.major != SERVICE_PROTOCOL_MAJOR
            || response.request_id != request_id
            || response.runtime_id != runtime_id
        {
            return Err(TransportError::new(
                TransportErrorKind::Protocol,
                "invalid control hello response identity",
            ));
        }
        let session_id = match response.body {
            ControlResponse::Hello { session_id, .. }
                if response.session_id == Some(session_id) =>
            {
                session_id
            }
            ControlResponse::Error { message, .. } => {
                return Err(TransportError::new(
                    TransportErrorKind::Authentication,
                    message,
                ));
            }
            _ => {
                return Err(TransportError::new(
                    TransportErrorKind::Protocol,
                    "control hello did not establish a session",
                ));
            }
        };
        let router = Arc::new(ResponseRouter::new(runtime_id, session_id));
        let inner = Arc::new(ClientInner {
            runtime_id,
            session_id,
            connection,
            router,
            writer: tokio::sync::Mutex::new(()),
        });
        let reader_inner = inner.clone();
        let reader = tokio::spawn(async move {
            loop {
                match reader_inner.connection.read_envelope().await {
                    Ok(envelope) => {
                        let _ = reader_inner.router.dispatch(envelope);
                    }
                    Err(_) => {
                        reader_inner.router.degrade();
                        break;
                    }
                }
            }
        });
        let connected = ConnectedClient {
            inner,
            reader: Mutex::new(Some(reader)),
            closed: AtomicBool::new(false),
        };
        cleanup.disarm();
        Ok(connected)
    }

    pub fn session_id(&self) -> Option<Uuid> {
        self.current().map(|connected| connected.inner.session_id)
    }

    pub fn health(&self) -> ServiceConnectionHealth {
        self.current()
            .map(|connected| connected.inner.router.health())
            .unwrap_or(ServiceConnectionHealth::Disconnected)
    }

    /// Completes once the current session's connection ends; at once when
    /// there is no live session.
    pub async fn wait_disconnected(&self) {
        let Some(connected) = self.current() else {
            return;
        };
        let mut health = connected.inner.router.subscribe_health();
        if *health.borrow() != ServiceConnectionHealth::Ready {
            return;
        }
        while health.changed().await.is_ok() {
            if *health.borrow() != ServiceConnectionHealth::Ready {
                return;
            }
        }
    }

    pub async fn request(&self, body: ControlRequest) -> Result<ControlResponse, TransportError> {
        let connected = self.ensure_connected().await?;
        let request_id = Uuid::new_v4();
        let receiver = connected
            .inner
            .router
            .register(request_id)
            .map_err(session_error)?;
        let envelope = ControlEnvelope {
            protocol: protocol_version(),
            request_id,
            runtime_id: connected.inner.runtime_id,
            session_id: Some(connected.inner.session_id),
            body,
        };
        let _writer = connected.inner.writer.lock().await;
        if let Err(error) = connected.inner.connection.write_envelope(&envelope).await {
            connected.inner.router.cancel(request_id);
            return Err(error);
        }
        drop(_writer);
        let answer = tokio::task::spawn_blocking(move || receiver.recv());
        let Ok(answer) = tokio::time::timeout(self.response_deadline, answer).await else {
            // The session ends with its connection: the service, if it
            // still runs, releases what the session held, and the requests
            // waiting on it fail with this one. The next opens a new one.
            connected.inner.router.degrade();
            if !connected.closed.swap(true, Ordering::AcqRel) {
                connected.inner.connection.close_now();
            }
            return Err(TransportError::disconnected(format!(
                "the Egrio service did not answer a request within {} seconds",
                self.response_deadline.as_secs()
            )));
        };
        answer
            .map_err(|error| TransportError::disconnected(error.to_string()))?
            .map_err(|error| TransportError::disconnected(error.to_string()))?
            .map(|envelope| envelope.body)
            .map_err(session_error)
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.closed.store(true, Ordering::Release);
        let Some(connected) = self.connected.lock().expect("control session mutex").take() else {
            return Ok(());
        };
        connected.inner.router.disconnect();
        let close_result = if !connected.closed.swap(true, Ordering::AcqRel) {
            connected.inner.connection.close().await
        } else {
            Ok(())
        };
        connected.abort_reader();
        close_result
    }
}

fn session_error(error: ControlSessionError) -> TransportError {
    TransportError::new(TransportErrorKind::Protocol, error.to_string())
}
