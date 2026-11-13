use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::accept::acquire_session_permit;
use super::state::{mark_session_accepted, mark_session_task_join_error};
use super::*;
use crate::profile::{RouteRule, RuleKind};
use crate::self_test::{run_connect_client, run_socks5_client, self_test_profile, serve_one_echo};
use crate::ConnectionTermination;

#[tokio::test]
async fn apply_profile_closes_live_tunnels_even_when_the_new_route_is_identical() {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener
            .accept()
            .await
            .map_err(|error| error.to_string())?;
        let mut buffer = vec![0_u8; 8192];
        loop {
            let read = stream
                .read(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            if read == 0 {
                return Ok::<_, String>(());
            }
            stream
                .write_all(&buffer[..read])
                .await
                .map_err(|error| error.to_string())?;
        }
    });

    let manager = CoreSessionManager::default();
    let running = manager
        .start(match_profile("direct-a", "DIRECT"))
        .await
        .expect("manager starts");
    let proxy_addr = running
        .listen_addr
        .as_deref()
        .expect("listen addr")
        .parse::<SocketAddr>()
        .expect("valid listen addr");

    // Establish a SOCKS5 tunnel under the first profile.
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("connect listener");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await.expect("read method");
    assert_eq!(method, [0x05, 0x00]);
    let SocketAddr::V4(target_v4) = target_addr else {
        panic!("IPv4 echo target expected");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_v4.ip().octets());
    request.extend_from_slice(&target_v4.port().to_be_bytes());
    stream.write_all(&request).await.expect("send CONNECT");
    let mut reply = [0_u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read CONNECT reply");
    assert_eq!(reply[1], 0x00);

    stream
        .write_all(b"before")
        .await
        .expect("write before apply");
    let mut echoed = [0; 6];
    stream
        .read_exact(&mut echoed)
        .await
        .expect("echo before apply");
    manager
        .apply_profile(&match_profile("direct-b", "DIRECT"))
        .expect("apply unchanged routing");
    assert_eq!(
        timeout(Duration::from_secs(2), stream.read(&mut echoed))
            .await
            .expect("old tunnel closes")
            .expect("read close"),
        0
    );

    // Sessions accepted after a swap follow the new profile: under
    // MATCH -> REJECT a fresh SOCKS5 CONNECT is refused...
    manager
        .apply_profile(&match_profile("reject-all", "REJECT"))
        .expect("apply reject profile");
    let rejected = run_socks5_client(proxy_addr, target_addr, b"post-swap")
        .await
        .expect_err("new session is rejected by the swapped profile");
    assert!(
        rejected.contains("status 2"),
        "expected SOCKS5 rejection, got: {rejected}"
    );

    wait_for_finished_sessions(&manager, 2).await;
    let status = manager.status();
    assert_eq!(status.completed_sessions, 0);
    assert_eq!(status.failed_sessions, 0);
    assert!(status.last_error.is_none());
    let finished = manager.finished_connections_snapshot();
    assert!(finished
        .iter()
        .any(|flow| flow.termination == Some(ConnectionTermination::Cancelled)));
    assert!(finished
        .iter()
        .any(|flow| flow.termination == Some(ConnectionTermination::RouteRejected)));
    assert_eq!(manager.traffic_telemetry_snapshot().failed_connections, 0);
    assert_eq!(
        manager.traffic_telemetry_snapshot().completed_connections,
        0
    );

    drop(stream);
    echo_task.await.expect("echo join").expect("echo completes");
    manager.stop();
}

async fn wait_for_finished_sessions(manager: &CoreSessionManager, accepted: u64) {
    timeout(Duration::from_secs(2), async {
        while manager.status().accepted_sessions != accepted
            || manager.status().active_sessions != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener accounts for finished sessions");
}

#[tokio::test]
async fn listener_reports_real_dial_failures_for_both_families_with_dns_ipv6_disabled() {
    let manager = CoreSessionManager::default();
    let running = manager
        .start(match_profile("direct", "DIRECT"))
        .await
        .expect("start listener");
    let proxy_addr: SocketAddr = running.listen_addr.unwrap().parse().unwrap();
    // Reserve non-listening loopback ports so both families fail at the
    // actual socket dial, rather than a DNS or address-family policy.
    let reserved_v6 = tokio::net::TcpSocket::new_v6().unwrap();
    reserved_v6.bind((Ipv6Addr::LOCALHOST, 0).into()).unwrap();
    let refused = run_connect_client(proxy_addr, reserved_v6.local_addr().unwrap(), b"").await;
    assert!(refused.is_err());
    wait_for_finished_sessions(&manager, 1).await;
    assert_eq!(manager.status().failed_sessions, 1);
    assert_eq!(manager.status().completed_sessions, 0);
    assert!(manager.status().last_error.is_some());
    assert!(matches!(
        manager.finished_connections_snapshot()[0].termination,
        Some(ConnectionTermination::Failed {
            stage: crate::TcpFlowStage::Dial,
            ..
        })
    ));

    // Binding without listening keeps this loopback port reserved while
    // making connect deterministically fail, with no remote network use.
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let refused = run_socks5_client(proxy_addr, reserved.local_addr().unwrap(), b"").await;
    assert!(refused.is_err());
    wait_for_finished_sessions(&manager, 2).await;
    assert_eq!(manager.status().failed_sessions, 2);
    assert_eq!(manager.status().completed_sessions, 0);
    assert!(manager.status().last_error.is_some());
    let telemetry = manager.traffic_telemetry_snapshot();
    assert_eq!(telemetry.failed_connections, 2);
    assert_eq!(telemetry.completed_connections, 0);
    assert!(manager
        .finished_connections_snapshot()
        .iter()
        .any(|flow| matches!(
            flow.termination,
            Some(ConnectionTermination::Failed {
                stage: crate::TcpFlowStage::Dial,
                ..
            })
        )));
    manager.stop();
}

#[tokio::test]
async fn client_reset_is_expected_but_upstream_reset_remains_a_failure() {
    let manager = CoreSessionManager::default();
    let running = manager
        .start(match_profile("direct", "DIRECT"))
        .await
        .expect("start listener");
    let proxy_addr: SocketAddr = running.listen_addr.unwrap().parse().unwrap();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for (index, client_reset) in [true, false].into_iter().enumerate() {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT {} HTTP/1.1\r\n\r\n", target.local_addr().unwrap()).as_bytes(),
            )
            .await
            .unwrap();
        let (upstream, _) = timeout(Duration::from_secs(2), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut header = Vec::new();
        timeout(Duration::from_secs(2), async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(client.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"HTTP/1.1 200"));
        if client_reset {
            client.set_zero_linger().unwrap();
            drop(client);
            wait_for_finished_sessions(&manager, index as u64 + 1).await;
            drop(upstream);
        } else {
            upstream.set_zero_linger().unwrap();
            drop(upstream);
            wait_for_finished_sessions(&manager, index as u64 + 1).await;
            drop(client);
        }
        assert_eq!(manager.status().failed_sessions, index as u64);
        assert_eq!(manager.status().completed_sessions, 0);
        assert_eq!(
            manager.traffic_telemetry_snapshot().failed_connections,
            index as u64
        );
    }
    let finished = manager.finished_connections_snapshot();
    assert!(finished.iter().any(|flow| matches!(
        flow.termination,
        Some(ConnectionTermination::ClientClosed { .. })
    )));
    assert!(finished.iter().any(|flow| matches!(
        flow.termination,
        Some(ConnectionTermination::Failed {
            stage: crate::TcpFlowStage::Relay,
            ..
        })
    )));
    assert!(manager.status().last_error.is_some());
    manager.stop();
}

#[tokio::test]
async fn routing_cutover_during_inbound_handshake_is_not_a_failure() {
    let manager = CoreSessionManager::default();
    let running = manager
        .start(self_test_profile())
        .await
        .expect("start listener");
    let mut client = TcpStream::connect(running.listen_addr.unwrap())
        .await
        .unwrap();
    client.write_all(b"CONNECT ").await.unwrap();
    timeout(Duration::from_secs(2), async {
        while manager.status().active_sessions != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handshake admitted");
    manager.apply_profile(&self_test_profile()).unwrap();
    wait_for_finished_sessions(&manager, 1).await;
    let status = manager.status();
    assert_eq!(status.failed_sessions, 0);
    assert_eq!(status.completed_sessions, 0);
    assert!(status.last_error.is_none());
    assert!(manager.finished_connections_snapshot().is_empty());
    manager.stop();
}

#[tokio::test]
async fn apply_profile_requires_running_listener() {
    let manager = CoreSessionManager::default();

    let error = manager
        .apply_profile(&match_profile("direct", "DIRECT"))
        .expect_err("apply without start fails");

    assert!(error.contains("not running"));
}

#[test]
fn connections_snapshot_is_empty_when_core_is_not_running() {
    let manager = CoreSessionManager::default();

    assert!(manager.connections_snapshot().is_empty());
}

#[test]
fn traffic_telemetry_snapshot_is_empty_when_core_is_not_running() {
    let manager = CoreSessionManager::default();

    let snapshot = manager.traffic_telemetry_snapshot();

    assert!(snapshot.connections.is_empty());
    assert_eq!(snapshot.active_connections, 0);
}

fn match_profile(rule_id: &str, outbound: &str) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new(rule_id);
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: outbound,
        no_resolve: false,
    }]
    .into();
    profile
}

#[tokio::test]
async fn native_core_manager_starts_and_stops_listener() {
    let manager = CoreSessionManager::default();

    let running = manager
        .start(self_test_profile())
        .await
        .expect("manager starts");
    assert_eq!(running.state, NativeCoreState::Running);
    assert!(running.listen_addr.is_some());
    assert!(running.dns_listen_addr.is_some());
    let listen_addr = running
        .listen_addr
        .as_deref()
        .expect("TCP listen address")
        .parse::<SocketAddr>()
        .expect("valid TCP listen address");
    let dns_listen_addr = running
        .dns_listen_addr
        .as_deref()
        .expect("DNS listen address")
        .parse::<SocketAddr>()
        .expect("valid DNS listen address");

    let stopping = manager.stop();
    assert_eq!(stopping.state, NativeCoreState::Stopping);
    timeout(Duration::from_secs(1), async {
        while manager.status().state != NativeCoreState::Stopped {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener reaches the release barrier");
    assert_eq!(manager.status().state, NativeCoreState::Stopped);
    TcpListener::bind(listen_addr)
        .await
        .expect("Stopped releases the TCP listener port");
    UdpSocket::bind(dns_listen_addr)
        .await
        .expect("Stopped releases the DNS listener port");
}

#[tokio::test]
async fn stale_generation_completion_cannot_stop_a_restarted_listener() {
    let manager = CoreSessionManager::default();
    manager
        .start(self_test_profile())
        .await
        .expect("start first generation");
    let first_generation = manager
        .inner
        .lock()
        .expect("native core manager mutex")
        .generation;

    manager.stop();
    for _ in 0..100 {
        if manager.status().state == NativeCoreState::Stopped {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(manager.status().state, NativeCoreState::Stopped);

    let restarted = manager
        .start(self_test_profile())
        .await
        .expect("start second generation");
    finish_listener_generation(&manager.inner, first_generation);

    assert_eq!(manager.status().state, NativeCoreState::Running);
    let listen_addr = restarted
        .listen_addr
        .as_deref()
        .expect("restarted listen address")
        .parse::<SocketAddr>()
        .expect("valid listen address");
    TcpStream::connect(listen_addr)
        .await
        .expect("restarted listener remains live");
    manager.stop();
}

#[test]
fn abandoned_start_reservation_does_not_advance_the_serving_generation() {
    let manager = CoreSessionManager::default();

    let reservation = manager
        .reserve_listener_start()
        .expect("reserve listener start")
        .expect("start reservation");
    drop(reservation);

    let inner = manager.inner.lock().expect("native core manager mutex");
    assert_eq!(inner.generation, 0);
    assert_eq!(inner.next_generation, 1);
    assert_eq!(inner.starting_generation, None);
}

#[tokio::test]
async fn failed_generation_is_not_relabelled_as_stopped_by_shutdown() {
    let manager = CoreSessionManager::default();
    manager
        .start(self_test_profile())
        .await
        .expect("start listener");
    let generation = manager
        .inner
        .lock()
        .expect("native core manager mutex")
        .generation;

    mark_failed(&manager.inner, generation, "listener failed".into());
    assert_eq!(manager.status().state, NativeCoreState::Stopping);
    finish_listener_generation(&manager.inner, generation);

    let status = manager.status();
    assert_eq!(status.state, NativeCoreState::Failed);
    assert_eq!(status.last_error.as_deref(), Some("listener failed"));
}

#[tokio::test]
async fn stop_waits_for_a_failed_generation_release_barrier() {
    let manager = CoreSessionManager::default();
    manager
        .start(self_test_profile())
        .await
        .expect("start listener");
    let generation = manager
        .inner
        .lock()
        .expect("native core manager mutex")
        .generation;

    mark_failed(&manager.inner, generation, "listener failed".into());
    assert_eq!(manager.stop().state, NativeCoreState::Stopping);

    timeout(Duration::from_secs(1), async {
        while manager.status().state != NativeCoreState::Stopped {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed generation reaches the release barrier");
    assert_eq!(manager.status().state, NativeCoreState::Stopped);
}

#[tokio::test]
async fn native_core_manager_accepts_socks5_connect() {
    let payload = b"socks5-native-core-poc";
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
    let manager = CoreSessionManager::default();
    let running = manager
        .start(self_test_profile())
        .await
        .expect("manager starts");
    let proxy_addr = running
        .listen_addr
        .as_deref()
        .expect("listen addr")
        .parse::<SocketAddr>()
        .expect("valid listen addr");

    let received = run_socks5_client(proxy_addr, target_addr, payload)
        .await
        .expect("SOCKS5 payload tunnels");

    assert_eq!(received, payload);
    echo_task.await.expect("echo join").expect("echo completes");
    manager.stop();
}

#[tokio::test]
async fn native_core_manager_answers_udp_dns_queries() {
    let manager = CoreSessionManager::default();
    let running = manager
        .start(self_test_profile())
        .await
        .expect("manager starts");
    let dns_addr = running
        .dns_listen_addr
        .as_deref()
        .expect("DNS listen addr")
        .parse::<SocketAddr>()
        .expect("valid DNS listen addr");
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind DNS client socket");

    socket
        .send_to(&dns_query(0x1234, "blocked.example", 1), dns_addr)
        .await
        .expect("send DNS query");
    let mut response = [0_u8; 512];
    let (bytes_read, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut response))
        .await
        .expect("DNS response timeout")
        .expect("receive DNS response");
    let response = &response[..bytes_read];

    assert_eq!(response.get(0..2), Some(&0x1234_u16.to_be_bytes()[..]));
    assert_ne!(response[2] & 0x80, 0);
    assert_eq!(response[3] & 0x0f, 3);
    manager.stop();
}

#[tokio::test]
async fn native_core_manager_stop_cancels_active_sessions() {
    let manager = CoreSessionManager::default();
    let running = manager
        .start(self_test_profile())
        .await
        .expect("manager starts");
    let proxy_addr = running
        .listen_addr
        .as_deref()
        .expect("listen addr")
        .parse::<SocketAddr>()
        .expect("valid listen addr");
    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect native core listener");

    for _ in 0..20 {
        if manager.status().active_sessions == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(manager.status().active_sessions, 1);

    manager.stop();
    for _ in 0..20 {
        if manager.status().state == NativeCoreState::Stopped {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let status = manager.status();
    assert_eq!(status.state, NativeCoreState::Stopped);
    assert_eq!(status.active_sessions, 0);
    let mut probe = [0_u8; 1];
    let closed = timeout(Duration::from_secs(1), client.read(&mut probe))
        .await
        .expect("Stopped closes active client sessions");
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn panicked_session_task_does_not_leak_the_active_session_count() {
    let manager = CoreSessionManager::default();
    manager
        .start(self_test_profile())
        .await
        .expect("start listener");
    let generation = manager
        .inner
        .lock()
        .expect("native core manager mutex")
        .generation;
    mark_session_accepted(&manager.inner, generation);

    let error = tokio::spawn(async { panic!("session task panic") })
        .await
        .expect_err("task panics");
    mark_session_task_join_error(&manager.inner, generation, error);

    let status = manager.status();
    assert_eq!(status.active_sessions, 0);
    assert_eq!(status.failed_sessions, 1);
    assert!(status
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("session task failed")));
    manager.stop();
}

#[test]
fn native_core_manager_rejects_sessions_when_limit_is_exhausted() {
    let inner = Arc::new(Mutex::new(CoreSessionManagerInner {
        generation: 7,
        next_generation: 7,
        active_generation: Some(7),
        status: NativeCoreStatus {
            state: NativeCoreState::Running,
            listen_addr: Some("127.0.0.1:7890".into()),
            listener_fallback: None,
            dns_listen_addr: Some("127.0.0.1:5353".into()),
            started_at_unix: Some(now_unix()),
            updated_at_unix: now_unix(),
            active_sessions: 0,
            accepted_sessions: 0,
            completed_sessions: 0,
            failed_sessions: 0,
            last_error: None,
        },
        ..Default::default()
    }));
    let session_limit = Arc::new(Semaphore::new(0));

    let permit = acquire_session_permit(&inner, 7, &session_limit);

    assert!(permit.is_none());
    let status = inner
        .lock()
        .expect("native core manager mutex")
        .status
        .clone();
    assert_eq!(status.active_sessions, 0);
    assert_eq!(status.accepted_sessions, 0);
    assert_eq!(status.failed_sessions, 1);
    assert_eq!(
        status.last_error.as_deref(),
        Some("native core active session limit reached")
    );
}

#[tokio::test]
async fn native_core_manager_starts_with_custom_egress_config() {
    let payload = b"socks5-native-core-custom-egress";
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
    let manager = CoreSessionManager::default();
    let running = manager
        .start_with_egress(self_test_profile(), NativeCoreEgressConfig::default(), None)
        .await
        .expect("manager starts with egress config");
    let proxy_addr = running
        .listen_addr
        .as_deref()
        .expect("listen addr")
        .parse::<SocketAddr>()
        .expect("valid listen addr");

    let received = run_socks5_client(proxy_addr, target_addr, payload)
        .await
        .expect("SOCKS5 payload tunnels through custom egress manager");

    assert_eq!(received, payload);
    echo_task.await.expect("echo join").expect("echo completes");
    manager.stop();
}

#[tokio::test]
async fn native_core_manager_starts_with_requested_listener_addresses() {
    let manager = CoreSessionManager::default();

    let running = manager
        .start_with_config(CoreSessionStartConfig {
            profile: self_test_profile(),
            egress: NativeCoreEgressConfig::default(),
            listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            dns_listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            inbound: CoreInbound::default(),
            hysteria2: None,
            socket_guard: None,
        })
        .await
        .expect("manager starts with requested listener addresses");

    assert!(running
        .listen_addr
        .as_deref()
        .is_some_and(|addr| addr.starts_with("127.0.0.1:")));
    assert!(running
        .dns_listen_addr
        .as_deref()
        .is_some_and(|addr| addr.starts_with("127.0.0.1:")));
    manager.stop();
}

fn dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

#[test]
fn bind_failures_name_the_port_and_the_way_out() {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 7890));
    let reserved = super::bind_failure(
        addr,
        &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    );
    assert!(reserved.starts_with("cannot listen on 127.0.0.1:7890: the system reserves this port"));
    assert!(reserved.contains("choose another port"));
    let taken = super::bind_failure(addr, &std::io::Error::from(std::io::ErrorKind::AddrInUse));
    assert!(taken.contains("another program already uses this port; choose another port"));
    let other = super::bind_failure(
        addr,
        &std::io::Error::from(std::io::ErrorKind::InvalidInput),
    );
    assert!(other.starts_with("cannot listen on 127.0.0.1:7890: ") && !other.contains("choose"));
}
