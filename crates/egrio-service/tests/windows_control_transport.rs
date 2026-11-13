//! The control pipe between a real listener and real clients in one
//! process: who a client is, what a connection costs before that is known,
//! and what ends a wait. The pipe is process-local -- no host networking
//! state is touched -- so this runs on any Windows machine.
#![cfg(windows)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use egrio_runtime::{CapabilityKind, RuntimeId};
use egrio_service::client::ControlClient;
use egrio_service::session::ControlServerSession;
use egrio_service::transport::{ControlConnection, ControlTransport, TransportErrorKind};
use egrio_service::windows::{Event, Served, WindowsNamedPipeListener, WindowsNamedPipeTransport};
use egrio_service::{ControlErrorCode, ControlRequest, ControlResponse};
use uuid::Uuid;

const TEST_RUNTIME_ID: RuntimeId = RuntimeId::from_uuid(Uuid::from_u128(0x7465_7374));
const LARGE_CONTROL_PAYLOAD_BYTES: usize = 128 * 1024;

fn test_endpoint(tag: &str) -> String {
    format!(
        r"\\.\pipe\egrio-transport-test-{}-{tag}",
        std::process::id()
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build current-thread runtime")
        .block_on(future)
}

/// A client that has connected and sent nothing. An instance the listener
/// just made takes it at once; one a client has left takes the next only
/// once the listener waits on it again, which a connect allows 1.5 seconds
/// for.
fn silent_client(endpoint: &str) -> Arc<dyn ControlConnection> {
    block_on(WindowsNamedPipeTransport::new(endpoint).connect()).expect("the listener is bound")
}

/// The same from another thread, for a client that connects while the
/// listener is being asked for it.
fn silent_client_soon(endpoint: &str) -> std::thread::JoinHandle<Arc<dyn ControlConnection>> {
    let endpoint = endpoint.to_string();
    std::thread::spawn(move || silent_client(&endpoint))
}

#[derive(Debug)]
struct ObserveHandler;

impl egrio_service::session::ControlRequestHandler for ObserveHandler {
    fn handle(
        &self,
        request: ControlRequest,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        match request {
            ControlRequest::Observe { capability } => Ok(ControlResponse::Observation(
                egrio_runtime::CapabilityObservation {
                    capability,
                    active: false,
                    verified: true,
                },
            )),
            ControlRequest::Prepare {
                capability,
                settings,
            } if capability == CapabilityKind::Route
                && settings
                    .get("padding")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|padding| padding.len() == LARGE_CONTROL_PAYLOAD_BYTES) =>
            {
                Ok(ControlResponse::Observation(
                    egrio_runtime::CapabilityObservation {
                        capability: CapabilityKind::Route,
                        active: false,
                        verified: true,
                    },
                ))
            }
            other => Err((
                ControlErrorCode::UnsupportedMethod,
                format!("test handler cannot serve {other:?}"),
            )),
        }
    }
}

/// Serves `listener`'s next client until its connection ends, and says how
/// it ended.
fn serve_one_client(
    listener: &WindowsNamedPipeListener,
    stop: &Event,
    fault: &Event,
) -> Result<Served, egrio_service::transport::TransportError> {
    let connection = listener
        .accept(stop)?
        .expect("a client came")
        .identify(stop)?;
    let session = ControlServerSession::new("transport-test", vec![CapabilityKind::Route]);
    loop {
        match connection.serve_once(&session, &ObserveHandler, &[stop, fault])? {
            Served::Request => {}
            ended => return Ok(ended),
        }
    }
}

/// The service acts as its client only once it has read from the pipe
/// (`ImpersonateNamedPipeClient` fails with ERROR_CANNOT_IMPERSONATE before
/// that), so the Hello is read first, the client identified by it, and the
/// Hello then served ahead of the pipe.
#[test]
fn a_client_is_identified_by_its_hello_which_is_then_served() {
    let endpoint = test_endpoint("hello");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let stop = Event::new().unwrap();

    let client = std::thread::spawn(move || {
        block_on(async move {
            let transport = Arc::new(WindowsNamedPipeTransport::new(endpoint));
            let client = ControlClient::connect(transport, TEST_RUNTIME_ID, "transport-test")
                .await
                .expect("the Hello is answered");
            let response = client
                .request(ControlRequest::Observe {
                    capability: CapabilityKind::Route,
                })
                .await
                .expect("a request after the Hello is answered");
            assert!(matches!(response, ControlResponse::Observation(_)));
            client.close().await.expect("close");
        })
    });

    let connection = listener
        .accept(&stop)
        .expect("accept")
        .expect("a client came")
        .identify(&stop)
        .expect("the client is this process");
    assert_eq!(connection.client().pid, std::process::id());
    let current_exe = std::env::current_exe()
        .expect("current exe")
        .to_string_lossy()
        .to_ascii_lowercase();
    assert_eq!(
        connection.client().executable_path.to_ascii_lowercase(),
        current_exe
    );

    let session = ControlServerSession::new("transport-test", vec![CapabilityKind::Route]);
    let mut served = 0;
    let ended = loop {
        match connection
            .serve_once(&session, &ObserveHandler, &[&stop])
            .expect("serve")
        {
            Served::Request => served += 1,
            ended => break ended,
        }
    };
    assert_eq!(served, 2, "the Hello and the request");
    assert_eq!(ended, Served::Closed);
    client.join().expect("client thread");
}

#[test]
fn a_client_that_closes_before_its_first_frame_is_not_identified() {
    let endpoint = test_endpoint("eof");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let stop = Event::new().unwrap();

    let client = silent_client(&endpoint);
    let admitted = listener
        .accept(&stop)
        .expect("accept")
        .expect("a client came");
    drop(client);
    let error = admitted
        .identify(&stop)
        .expect_err("a frameless client is nobody");
    assert_eq!(error.kind(), TransportErrorKind::Disconnected);
}

/// A client that came and went before the listener was asked for it is
/// nobody's to serve: the listener waits for the next.
#[test]
fn a_client_gone_before_it_was_accepted_is_passed_over() {
    let endpoint = test_endpoint("gone");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let stop = Event::new().unwrap();
    let fault = Event::new().unwrap();

    drop(silent_client(&endpoint));
    let next = {
        let endpoint = endpoint.clone();
        std::thread::spawn(move || {
            block_on(async move {
                let transport = Arc::new(WindowsNamedPipeTransport::new(endpoint));
                let client = ControlClient::connect(transport, TEST_RUNTIME_ID, "transport-test")
                    .await
                    .expect("the next client is served");
                client.close().await.expect("close");
            })
        })
    };
    assert_eq!(
        serve_one_client(&listener, &stop, &fault).expect("serve"),
        Served::Closed
    );
    next.join().expect("next client");
}

/// The service gives each connection a thread, and a client that sends
/// nothing holds one only until its time is up -- while the listener, which
/// waits for no client's frame, goes on serving the others.
#[test]
fn a_client_that_sends_nothing_holds_nobody_else_up() {
    let endpoint = test_endpoint("silent");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone())
        .expect("bind")
        .with_first_frame_timeout(Duration::from_millis(1_500));
    let stop = Event::new().unwrap();
    let fault = Event::new().unwrap();

    let silent = silent_client(&endpoint);
    let unidentified = listener
        .accept(&stop)
        .expect("accept")
        .expect("the silent client came");

    std::thread::scope(|scope| {
        let waited_out = scope.spawn(|| {
            let started = Instant::now();
            let error = unidentified
                .identify(&stop)
                .expect_err("no frame came in time");
            (started.elapsed(), error)
        });

        // Meanwhile another client connects and is served to its end.
        let other = {
            let endpoint = endpoint.clone();
            scope.spawn(move || {
                block_on(async move {
                    let transport = Arc::new(WindowsNamedPipeTransport::new(endpoint));
                    let client =
                        ControlClient::connect(transport, TEST_RUNTIME_ID, "transport-test")
                            .await
                            .expect("served beside the silent client");
                    client.close().await.expect("close");
                })
            })
        };
        let started = Instant::now();
        assert_eq!(
            serve_one_client(&listener, &stop, &fault).expect("serve"),
            Served::Closed
        );
        assert!(
            started.elapsed() < Duration::from_millis(1_000),
            "the other client did not wait for the silent one's time: {:?}",
            started.elapsed()
        );
        other.join().expect("other client");

        let (waited, error) = waited_out.join().expect("silent client's thread");
        assert_eq!(error.kind(), TransportErrorKind::Disconnected);
        assert!(waited >= Duration::from_millis(1_400), "{waited:?}");
    });
    drop(silent);
}

/// Clients nobody has identified yet hold a bounded number of places; one
/// that finds them all taken is turned away, and a place comes back when
/// its client is done with.
#[test]
fn unidentified_clients_wait_in_bounded_number() {
    const PLACES: usize = 16;
    let endpoint = test_endpoint("places");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let stop = Event::new().unwrap();

    let mut clients = Vec::new();
    let mut waiting = Vec::new();
    for _ in 0..PLACES {
        clients.push(silent_client(&endpoint));
        waiting.push(
            listener
                .accept(&stop)
                .expect("accept")
                .expect("a client came"),
        );
    }
    clients.push(silent_client(&endpoint));
    let refused = listener.accept(&stop).expect_err("every place is taken");
    assert_eq!(refused.kind(), TransportErrorKind::Authentication);

    waiting.pop();
    let next = silent_client_soon(&endpoint);
    listener
        .accept(&stop)
        .expect("a place came back")
        .expect("a client came");
    clients.push(next.join().expect("next client"));
}

/// The pipe's name is the listener's from the moment it is bound: with a
/// client connected and handed on, there is already another instance, so no
/// other process finds the name free to serve it.
#[test]
fn the_name_stays_taken_while_clients_are_served() {
    let endpoint = test_endpoint("taken");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let stop = Event::new().unwrap();

    let first = silent_client(&endpoint);
    let handed_on = listener
        .accept(&stop)
        .expect("accept")
        .expect("a client came");
    let squatter = WindowsNamedPipeListener::bind(endpoint.clone())
        .expect_err("the name is taken while a client is connected");
    assert_eq!(squatter.kind(), TransportErrorKind::ConnectFailed);

    drop(handed_on);
    drop(first);
    WindowsNamedPipeListener::bind(endpoint.clone())
        .expect_err("and after that client's instance is gone");
    // The instance made when the first client was handed on takes the next.
    let second = silent_client(&endpoint);
    listener
        .accept(&stop)
        .expect("accept")
        .expect("the next client came");
    drop(second);
}

/// A session waits for its client's next request, for the service to stop
/// and for its packet session to fault, in one wait: whichever comes first
/// ends it, with no timer in between.
#[test]
fn a_stop_or_a_fault_ends_the_wait_for_a_request() {
    for (index, set_fault) in [(0, false), (1, true)] {
        let endpoint = test_endpoint(if set_fault { "fault" } else { "stop" });
        let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
        let stop = Arc::new(Event::new().unwrap());
        let fault = Arc::new(Event::new().unwrap());
        let (connected_tx, connected_rx) = std::sync::mpsc::channel();

        let client = std::thread::spawn(move || {
            block_on(async move {
                let transport = Arc::new(WindowsNamedPipeTransport::new(endpoint));
                let client = ControlClient::connect(transport, TEST_RUNTIME_ID, "transport-test")
                    .await
                    .expect("connect");
                connected_tx.send(()).unwrap();
                // The session ends under the client: it sees its connection go.
                tokio::time::timeout(Duration::from_secs(10), client.wait_disconnected())
                    .await
                    .expect("the client learns its session ended");
            })
        });
        let setter = {
            let (stop, fault) = (Arc::clone(&stop), Arc::clone(&fault));
            std::thread::spawn(move || {
                connected_rx.recv().unwrap();
                std::thread::sleep(Duration::from_millis(200));
                if set_fault {
                    fault.set();
                } else {
                    stop.set();
                }
            })
        };

        let ended = serve_one_client(&listener, &stop, &fault).expect("serve");
        assert_eq!(ended, Served::Interrupted(index));
        drop(listener);
        setter.join().expect("setter");
        client.join().expect("client");
    }
}

/// The full client loop over the real pipe on a small worker pool: routed
/// requests, a frame larger than the 64-KiB pipe buffer, and dropping the
/// connected client outside a Tokio context must all complete without
/// stranding a blocking pipe worker.
#[test]
fn control_client_large_frames_and_drop_complete_on_a_two_worker_runtime() {
    let endpoint = test_endpoint("client-loop");
    let listener = WindowsNamedPipeListener::bind(endpoint.clone()).expect("bind");
    let (server_done_tx, server_done_rx) = std::sync::mpsc::channel();

    let server_thread = std::thread::spawn(move || {
        let stop = Event::new().unwrap();
        let fault = Event::new().unwrap();
        let ended = serve_one_client(&listener, &stop, &fault);
        server_done_tx.send(ended).ok();
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build two-worker runtime");
    let client = runtime.block_on(async move {
        let transport = Arc::new(WindowsNamedPipeTransport::new(endpoint));
        let client = tokio::time::timeout(
            Duration::from_secs(10),
            ControlClient::connect(transport, TEST_RUNTIME_ID, "transport-test"),
        )
        .await
        .expect("connect must not hang")
        .expect("control client connect");

        for _ in 0..3 {
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                client.request(ControlRequest::Observe {
                    capability: CapabilityKind::Route,
                }),
            )
            .await
            .expect("request must not hang")
            .expect("observe request");
            let ControlResponse::Observation(observation) = response else {
                panic!("expected an observation, got {response:?}");
            };
            assert!(observation.verified);
        }

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client.request(ControlRequest::Prepare {
                capability: CapabilityKind::Route,
                settings: serde_json::json!({
                    "padding": "x".repeat(LARGE_CONTROL_PAYLOAD_BYTES),
                }),
            }),
        )
        .await
        .expect("large request must not hang")
        .expect("large prepare request");
        assert!(matches!(response, ControlResponse::Observation(_)));
        client
    });

    drop(client);
    let server_done = server_done_rx.recv_timeout(Duration::from_secs(5));
    runtime.shutdown_timeout(Duration::from_secs(2));
    let ended = server_done.expect("dropping the client must disconnect the real pipe");
    assert_eq!(ended.expect("serve"), Served::Closed);
    server_thread.join().expect("server thread");
}
