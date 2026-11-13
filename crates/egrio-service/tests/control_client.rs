use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use egrio_runtime::{CapabilityKind, RuntimeId};
use egrio_service::client::ControlClient;
use egrio_service::protocol::{protocol_version, ControlEnvelope, ControlRequest, ControlResponse};
use egrio_service::session::ServiceConnectionHealth;
use egrio_service::transport::{
    ControlConnection, ControlFuture, ControlTransport, TransportError, TransportErrorKind,
};
use uuid::Uuid;

#[derive(Debug)]
struct ScriptedConnection {
    reads: Mutex<VecDeque<Result<ControlEnvelope<ControlResponse>, TransportError>>>,
    writes: Mutex<Vec<ControlEnvelope<ControlRequest>>>,
    closed: AtomicBool,
    closes: AtomicUsize,
}

impl ControlConnection for ScriptedConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        Box::pin(async move {
            self.reads
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(TransportError::disconnected("script exhausted")))
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        Box::pin(async move {
            self.writes.lock().unwrap().push(envelope.clone());
            Ok(())
        })
    }

    fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct ScriptedTransport(Arc<ScriptedConnection>);

impl ControlTransport for ScriptedTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        let connection: Arc<dyn ControlConnection> = self.0.clone();
        Box::pin(async move { Ok(connection) })
    }
}

#[derive(Debug)]
struct CountingTransport {
    connects: AtomicUsize,
}

impl ControlTransport for CountingTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(TransportError::disconnected("no scripted connection")) })
    }
}

fn response(
    request_id: Uuid,
    runtime_id: RuntimeId,
    session_id: Uuid,
    body: ControlResponse,
) -> ControlEnvelope<ControlResponse> {
    ControlEnvelope {
        protocol: protocol_version(),
        request_id,
        runtime_id,
        session_id: Some(session_id),
        body,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn client_binds_hello_session_and_degrades_on_disconnect() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let connection = Arc::new(ScriptedConnection {
        reads: Mutex::new(VecDeque::from([
            Ok(response(
                hello_id,
                runtime_id,
                session_id,
                ControlResponse::Hello {
                    service_version: "0.1.0".into(),
                    session_id,
                    capabilities: vec![CapabilityKind::Dns],
                },
            )),
            Err(TransportError::disconnected("pipe closed")),
        ])),
        writes: Mutex::new(Vec::new()),
        closed: AtomicBool::new(false),
        closes: AtomicUsize::new(0),
    });

    let client = ControlClient::connect_with_request_id(
        Arc::new(ScriptedTransport(connection.clone())),
        runtime_id,
        "0.1.0",
        hello_id,
    )
    .await
    .unwrap();
    assert_eq!(client.session_id(), Some(session_id));
    tokio::task::yield_now().await;
    assert_eq!(client.health(), ServiceConnectionHealth::Degraded);

    {
        let writes = connection.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert!(matches!(writes[0].body, ControlRequest::Hello { .. }));
        assert_eq!(writes[0].session_id, None);
    }
    drop(client);
    tokio::task::yield_now().await;
    assert_eq!(connection.closes.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_client_does_not_connect_for_observation_or_close() {
    let transport = Arc::new(CountingTransport {
        connects: AtomicUsize::new(0),
    });
    let client = ControlClient::deferred(transport.clone(), RuntimeId::new(), "0.1.0");

    assert_eq!(client.health(), ServiceConnectionHealth::Disconnected);
    client.wait_disconnected().await;
    client.close().await.unwrap();
    assert!(client
        .request(ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        })
        .await
        .expect_err("a closed deferred client cannot connect")
        .to_string()
        .contains("closed"));

    assert_eq!(transport.connects.load(Ordering::Relaxed), 0);
}

#[derive(Debug)]
struct HangingConnection {
    closed: AtomicBool,
    closes: AtomicUsize,
}

impl ControlConnection for HangingConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        Box::pin(std::future::pending())
    }

    fn write_envelope<'a>(
        &'a self,
        _envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct SingleConnectionTransport {
    connection: Arc<HangingConnection>,
    connects: AtomicUsize,
}

#[derive(Debug)]
struct LiveConnection {
    hello: Mutex<Option<ControlEnvelope<ControlResponse>>>,
    writes: Mutex<Vec<ControlEnvelope<ControlRequest>>>,
    closed: AtomicBool,
    closes: AtomicUsize,
}

impl ControlConnection for LiveConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        Box::pin(async move {
            if let Some(hello) = self.hello.lock().unwrap().take() {
                return Ok(hello);
            }
            std::future::pending().await
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        Box::pin(async move {
            self.writes.lock().unwrap().push(envelope.clone());
            Ok(())
        })
    }

    fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct LiveTransport(Arc<LiveConnection>);

impl ControlTransport for LiveTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        let connection: Arc<dyn ControlConnection> = self.0.clone();
        Box::pin(async move { Ok(connection) })
    }
}

fn live_connection(runtime_id: RuntimeId, hello_id: Uuid, session_id: Uuid) -> Arc<LiveConnection> {
    Arc::new(LiveConnection {
        hello: Mutex::new(Some(response(
            hello_id,
            runtime_id,
            session_id,
            ControlResponse::Hello {
                service_version: "0.1.0".into(),
                session_id,
                capabilities: vec![CapabilityKind::Dns],
            },
        ))),
        writes: Mutex::new(Vec::new()),
        closed: AtomicBool::new(false),
        closes: AtomicUsize::new(0),
    })
}

impl ControlTransport for SingleConnectionTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        let connection: Arc<dyn ControlConnection> = self.connection.clone();
        Box::pin(async move { Ok(connection) })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_hello_closes_the_partially_established_connection() {
    let connection = Arc::new(HangingConnection {
        closed: AtomicBool::new(false),
        closes: AtomicUsize::new(0),
    });
    let transport = Arc::new(SingleConnectionTransport {
        connection: connection.clone(),
        connects: AtomicUsize::new(0),
    });
    let client = Arc::new(ControlClient::deferred(
        transport.clone(),
        RuntimeId::new(),
        "0.1.0",
    ));
    let request_client = client.clone();
    let request = tokio::spawn(async move {
        request_client
            .request(ControlRequest::Observe {
                capability: CapabilityKind::Dns,
            })
            .await
    });
    while transport.connects.load(Ordering::Relaxed) == 0 {
        tokio::task::yield_now().await;
    }

    request.abort();
    let _ = request.await;
    for _ in 0..10 {
        if connection.closes.load(Ordering::Relaxed) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(connection.closes.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_close_then_drop_closes_the_connection_once() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let connection = live_connection(runtime_id, hello_id, session_id);
    let client = ControlClient::connect_with_request_id(
        Arc::new(LiveTransport(connection.clone())),
        runtime_id,
        "0.1.0",
        hello_id,
    )
    .await
    .unwrap();

    client.close().await.unwrap();
    drop(client);

    assert_eq!(connection.closes.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_a_connected_client_without_runtime_closes_synchronously() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let connection = live_connection(runtime_id, hello_id, session_id);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build current-thread runtime");
    let client = runtime
        .block_on(ControlClient::connect_with_request_id(
            Arc::new(LiveTransport(connection.clone())),
            runtime_id,
            "0.1.0",
            hello_id,
        ))
        .unwrap();

    drop(client);

    assert_eq!(connection.closes.load(Ordering::Relaxed), 1);
    drop(runtime);
}

#[test]
fn transport_error_kind_is_structured() {
    assert_eq!(
        TransportError::possibly_delivered("write interrupted").kind(),
        TransportErrorKind::PossiblyDelivered
    );
}

/// A service session that answers every request on its connection: the
/// hello with its own session id, anything else with a scripted refusal.
#[derive(Debug)]
struct AnsweringConnection {
    runtime_id: RuntimeId,
    session_id: Uuid,
    answers: tokio::sync::mpsc::UnboundedSender<ControlEnvelope<ControlResponse>>,
    pending:
        tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<ControlEnvelope<ControlResponse>>>,
}

impl AnsweringConnection {
    fn new(runtime_id: RuntimeId, session_id: Uuid) -> Arc<Self> {
        let (answers, pending) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            runtime_id,
            session_id,
            answers,
            pending: tokio::sync::Mutex::new(pending),
        })
    }
}

impl ControlConnection for AnsweringConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        Box::pin(async move {
            self.pending
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| TransportError::disconnected("service gone"))
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        let body = match envelope.body {
            ControlRequest::Hello { .. } => ControlResponse::Hello {
                service_version: "0.1.0".into(),
                session_id: self.session_id,
                capabilities: vec![CapabilityKind::Dns],
            },
            _ => ControlResponse::Error {
                code: egrio_service::protocol::ControlErrorCode::CapabilityFailed,
                message: format!("answered by {}", self.session_id),
            },
        };
        let _ = self.answers.send(response(
            envelope.request_id,
            self.runtime_id,
            self.session_id,
            body,
        ));
        Box::pin(async { Ok(()) })
    }

    fn close_now(&self) {}
}

/// Hands out one prepared connection per connect, like successive service
/// instances behind the same pipe name.
#[derive(Debug)]
struct SuccessiveTransport {
    connections: Mutex<VecDeque<Arc<dyn ControlConnection>>>,
    connects: AtomicUsize,
}

impl ControlTransport for SuccessiveTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        let next = self.connections.lock().unwrap().pop_front();
        Box::pin(async move { next.ok_or_else(|| TransportError::disconnected("no service")) })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_session_whose_connection_ended_is_replaced_by_the_next_request() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let first_session = Uuid::new_v4();
    let second_session = Uuid::new_v4();
    // The first service instance answers the hello, then goes away.
    let first = Arc::new(ScriptedConnection {
        reads: Mutex::new(VecDeque::from([
            Ok(response(
                hello_id,
                runtime_id,
                first_session,
                ControlResponse::Hello {
                    service_version: "0.1.0".into(),
                    session_id: first_session,
                    capabilities: vec![CapabilityKind::Dns],
                },
            )),
            Err(TransportError::disconnected("service stopped")),
        ])),
        writes: Mutex::new(Vec::new()),
        closed: AtomicBool::new(false),
        closes: AtomicUsize::new(0),
    });
    let transport = Arc::new(SuccessiveTransport {
        connections: Mutex::new(VecDeque::from([
            first.clone() as Arc<dyn ControlConnection>,
            AnsweringConnection::new(runtime_id, second_session),
        ])),
        connects: AtomicUsize::new(0),
    });
    let client =
        ControlClient::connect_with_request_id(transport.clone(), runtime_id, "0.1.0", hello_id)
            .await
            .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(client.health(), ServiceConnectionHealth::Degraded);
    // A degraded session reports its end at once.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.wait_disconnected(),
    )
    .await
    .expect("an ended session does not hold its waiters");

    let answer = client
        .request(ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        })
        .await
        .expect("the next request reaches the restarted service");
    assert!(
        matches!(&answer, ControlResponse::Error { message, .. } if message.contains(&second_session.to_string())),
        "{answer:?}"
    );
    assert_eq!(client.session_id(), Some(second_session));
    assert_eq!(client.health(), ServiceConnectionHealth::Ready);
    assert_eq!(transport.connects.load(Ordering::Relaxed), 2);
    assert_eq!(
        first.closes.load(Ordering::Relaxed),
        1,
        "the ended session is released"
    );
    // Waiters now follow the live session.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.wait_disconnected()
        )
        .await
        .is_err(),
        "a live session keeps its waiters waiting"
    );
}

/// A connection can be made to a service that serves nobody -- the system
/// accepts it for a process that has stopped running its code -- and such a
/// service does not hold its client: the Hello it never answers fails the
/// connection, and the connection is closed.
#[tokio::test(flavor = "current_thread")]
async fn a_hello_the_service_never_answers_fails_the_connection() {
    let connection = Arc::new(HangingConnection {
        closed: AtomicBool::new(false),
        closes: AtomicUsize::new(0),
    });
    let transport = Arc::new(SingleConnectionTransport {
        connection: connection.clone(),
        connects: AtomicUsize::new(0),
    });
    let client = ControlClient::deferred(transport, RuntimeId::new(), "0.1.0").with_deadlines(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_secs(60),
    );

    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.request(ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        }),
    )
    .await
    .expect("the request does not wait for a service that is silent")
    .expect_err("no session was made");
    assert_eq!(error.kind(), TransportErrorKind::ConnectFailed);
    assert_eq!(connection.closes.load(Ordering::Relaxed), 1);
    assert_eq!(client.health(), ServiceConnectionHealth::Disconnected);
}

/// A request the service never answers ends its session instead of keeping
/// its caller -- and everything queued behind it, a quit among them --
/// waiting for as long as the service stays silent: the connection is
/// closed, the session's end is reported to whoever watches it, and the
/// next request opens a new session.
#[tokio::test(flavor = "current_thread")]
async fn a_request_the_service_never_answers_ends_the_session() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let first_session = Uuid::new_v4();
    let second_session = Uuid::new_v4();
    let silent = live_connection(runtime_id, hello_id, first_session);
    let transport = Arc::new(SuccessiveTransport {
        connections: Mutex::new(VecDeque::from([
            silent.clone() as Arc<dyn ControlConnection>,
            AnsweringConnection::new(runtime_id, second_session),
        ])),
        connects: AtomicUsize::new(0),
    });
    let client =
        ControlClient::connect_with_request_id(transport.clone(), runtime_id, "0.1.0", hello_id)
            .await
            .unwrap()
            .with_deadlines(
                std::time::Duration::from_secs(10),
                std::time::Duration::from_millis(80),
            );
    assert_eq!(client.health(), ServiceConnectionHealth::Ready);

    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.request(ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        }),
    )
    .await
    .expect("the request does not wait for a service that is silent")
    .expect_err("the service never answered");
    assert_eq!(error.kind(), TransportErrorKind::Disconnected);
    assert!(error.to_string().contains("did not answer"), "{error}");
    assert_eq!(client.health(), ServiceConnectionHealth::Degraded);
    assert_eq!(silent.closes.load(Ordering::Relaxed), 1);
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.wait_disconnected(),
    )
    .await
    .expect("the session's end is reported");

    client
        .request(ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        })
        .await
        .expect("the next request opens a new session");
    assert_eq!(client.session_id(), Some(second_session));
    assert_eq!(transport.connects.load(Ordering::Relaxed), 2);
    assert_eq!(silent.closes.load(Ordering::Relaxed), 1);
}
