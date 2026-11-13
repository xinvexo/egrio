//! Process attribution of system-proxy clients: the listener looks up a
//! loopback client's socket with the Core's own scanner while the handshake
//! runs, so process rules and the connection table match the TUN path.
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use super::*;
use crate::attribution::{FlowKey, FlowProtocol, FlowScanner, ProcessInfo};
use crate::inbound::CoreSessionManager;

const NAME: &str = "Probe";
const PATH: &str = "/opt/probe/Probe";

/// Owns exactly the client ports a test registers, and records every flow
/// it is asked about.
#[derive(Debug, Default)]
struct PortScanner {
    owned: Mutex<HashSet<u16>>,
    asked: Mutex<Vec<FlowKey>>,
    stall: Option<Arc<AtomicBool>>,
}

impl FlowScanner for PortScanner {
    fn scan(&self, flows: &[FlowKey], _: Duration, stop: &AtomicBool) -> Vec<Option<ProcessInfo>> {
        if let Some(release) = &self.stall {
            while !release.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.asked.lock().unwrap().extend_from_slice(flows);
        let owned = self.owned.lock().unwrap();
        flows
            .iter()
            .map(|flow| {
                owned.contains(&flow.source_port).then(|| ProcessInfo {
                    name: Some(NAME.into()),
                    path: Some(PATH.into()),
                })
            })
            .collect()
    }
}

fn process_rule_profile(fallback: &str) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("listener-attribution");
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::ProcessName,
            payload: Some(NAME),
            outbound: "DIRECT",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: fallback,
            no_resolve: false,
        },
    ]
    .into();
    profile
}

struct Fixture {
    core: NativeCoreDevice,
    manager: CoreSessionManager,
    listener: SocketAddr,
    scanner: Arc<PortScanner>,
}

impl Fixture {
    async fn start(fallback: &str, scanner: PortScanner) -> Self {
        Self::start_with(process_rule_profile(fallback), scanner).await
    }

    async fn start_with(profile: RuntimeProfile, scanner: PortScanner) -> Self {
        let scanner = Arc::new(scanner);
        let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
            profile,
            egress: Default::default(),
            egress_socket_guard: None,
            capture: Default::default(),
            flow_scanner: Some(scanner.clone()),
            fake_ip_mappings: None,
        });
        let manager = CoreSessionManager::default();
        let listener = manager
            .start_on_device(
                core.clone(),
                Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                None,
                false,
            )
            .await
            .unwrap()
            .listen_addr
            .unwrap()
            .parse()
            .unwrap();
        Self {
            core,
            manager,
            listener,
            scanner,
        }
    }

    /// A client socket bound before it dials, so its port can be owned.
    async fn connect(&self, owned: bool) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        if owned {
            let port = socket.local_addr().unwrap().port();
            self.scanner.owned.lock().unwrap().insert(port);
        }
        socket.connect(self.listener).await.unwrap()
    }

    fn stop(self) {
        self.manager.stop();
        self.core.close();
    }
}

/// Sends a CONNECT that also tries to assert another identity in headers,
/// and returns the proxy's status line.
async fn connect_through(client: &mut TcpStream, target: SocketAddr) -> String {
    client
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Egrio-Process-Name: forged\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    // Nothing follows the reply until the client sends through the tunnel.
    let (response, _) = timeout(
        Duration::from_secs(5),
        crate::protocols::http::read_http_header(client),
    )
    .await
    .expect("the proxy answers the CONNECT")
    .unwrap();
    response.lines().next().unwrap_or_default().to_owned()
}

async fn echo(client: &mut TcpStream) {
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
        .await
        .expect("the relayed echo returns")
        .unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn a_loopback_client_s_owner_reaches_process_rules_and_the_connection_table() {
    let (target, echo_task) = spawn_echo_server().await;
    let fixture = Fixture::start("REJECT", PortScanner::default()).await;
    let mut client = fixture.connect(true).await;

    let status = connect_through(&mut client, target).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    echo(&mut client).await;

    let rows = fixture.core.connections_snapshot();
    let row = rows
        .iter()
        .find(|row| row.inbound == "http-connect")
        .expect("the listener connection is in the table");
    assert_eq!(row.process_name.as_deref(), Some(NAME));
    assert_eq!(row.process_path.as_deref(), Some(PATH));
    assert_eq!(
        row.rule.as_deref(),
        Some("PROCESS-NAME,Probe,DIRECT"),
        "the process rule, not the rejecting fallback, admitted the client"
    );
    // The lookup names the client's socket as the client sees it: its own
    // address as the source, the listener address it dialed as destination.
    let client_addr = client.local_addr().unwrap();
    assert!(fixture.scanner.asked.lock().unwrap().contains(&FlowKey {
        protocol: FlowProtocol::Tcp,
        source_ip: client_addr.ip(),
        source_port: client_addr.port(),
        destination_ip: fixture.listener.ip(),
        destination_port: fixture.listener.port(),
    }));

    drop(client);
    fixture.stop();
    echo_task.abort();
}

#[tokio::test]
async fn an_unowned_client_routes_as_no_process_despite_identity_headers() {
    let (target, echo_task) = spawn_echo_server().await;
    let fixture = Fixture::start("REJECT", PortScanner::default()).await;
    let mut client = fixture.connect(false).await;

    let status = connect_through(&mut client, target).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");

    drop(client);
    fixture.stop();
    echo_task.abort();
}

/// Without a process rule nothing waits for the scanner: the client is
/// routed at once, and its connection row takes the owner when the lookup
/// answers.
#[tokio::test]
async fn without_process_rules_a_client_goes_on_and_its_row_takes_the_owner_later() {
    let (target, echo_task) = spawn_echo_server().await;
    let release = Arc::new(AtomicBool::new(false));
    let fixture = Fixture::start_with(
        RuntimeProfile::new("no-process-rules"),
        PortScanner {
            stall: Some(release.clone()),
            ..PortScanner::default()
        },
    )
    .await;
    let mut client = fixture.connect(true).await;

    let started = Instant::now();
    let status = connect_through(&mut client, target).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    echo(&mut client).await;
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "the stalled scanner held the client for {:?}",
        started.elapsed()
    );
    let row_process = || {
        fixture
            .core
            .connections_snapshot()
            .into_iter()
            .find(|row| row.inbound == "http-connect")
            .expect("the listener connection is in the table")
            .process_name
    };
    assert_eq!(row_process(), None, "the lookup has not answered yet");

    release.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(2);
    while row_process().is_none() {
        assert!(Instant::now() < deadline, "the row takes the owner");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(row_process().as_deref(), Some(NAME));

    drop(client);
    fixture.stop();
    echo_task.abort();
}

#[tokio::test]
async fn a_stalled_scanner_holds_a_client_no_longer_than_the_attribution_budget() {
    let (target, echo_task) = spawn_echo_server().await;
    let release = Arc::new(AtomicBool::new(false));
    let fixture = Fixture::start(
        "DIRECT",
        PortScanner {
            stall: Some(release.clone()),
            ..PortScanner::default()
        },
    )
    .await;
    let mut client = fixture.connect(true).await;

    let started = Instant::now();
    let status = connect_through(&mut client, target).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(started.elapsed() < Duration::from_secs(2));
    echo(&mut client).await;
    let rows = fixture.core.connections_snapshot();
    let row = rows
        .iter()
        .find(|row| row.inbound == "http-connect")
        .expect("the listener connection is in the table");
    assert_eq!(row.process_name, None, "an unanswered lookup stays unknown");
    assert_eq!(row.rule.as_deref(), Some("MATCH,DIRECT"));

    release.store(true, Ordering::Release);
    drop(client);
    fixture.stop();
    echo_task.abort();
}
