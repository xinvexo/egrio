//! The Hysteria2 connector↔acceptor loopback gate (TCP path): the in-tree
//! client connector dials the new QUIC/H3
//! server acceptor in-process and a payload rides byte-exact through the
//! unmodified `dispatch_accepted_stream` → Router → DIRECT pipeline. It is the
//! feasibility proof that HTTP/3 auth and Hysteria2's raw proxied-TCP streams
//! coexist on one QUIC connection, and it pins the counted/bounded
//! auth-failure path.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout, Duration};

use super::connector::Hysteria2Connector;
use super::test_server::{self, match_direct_device};
use crate::outbound::OutboundConnector;
use crate::profile::{RouteRule, RuleKind, RuntimeProfile, TrafficPolicyMode};
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;
use crate::udp::{drain_pending_udp_flow_responses, send_udp_flow_datagram, UdpDatagram};

const GATE_AUTH: &str = "s3cr3t-hysteria2-auth";

fn gate_connector(server: SocketAddr, auth: &str) -> Hysteria2Connector {
    Hysteria2Connector::new(
        server.ip().to_string(),
        server.port(),
        &json!({ "password": auth, "skip-cert-verify": true, "sni": test_server::SNI }),
    )
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn hysteria2_connector_and_acceptor_relay_through_the_unmodified_dispatcher() {
    let echo_addr = spawn_tcp_echo().await;
    let acceptor = test_server::acceptor(GATE_AUTH);
    let server_device = match_direct_device();
    let server_addr = test_server::spawn(Arc::clone(&acceptor), server_device.clone()).await;

    let connector = gate_connector(server_addr, GATE_AUTH);
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let client_runtime = match_direct_device().pinned_runtime();
    let mut stream = timeout(
        Duration::from_secs(10),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("hysteria2 dial timeout")
    .expect("hysteria2 dial");

    // Auth (HTTP/3) and this raw proxied-TCP stream shared one QUIC connection.
    let payload = b"ping-through-the-hysteria2-pipeline";
    stream.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&echoed, payload, "payload survived the QUIC/H3 pipeline");

    let mut authenticated_user = None;
    for _ in 0..100 {
        if let Some(snapshot) = server_device
            .pinned_runtime()
            .session_registry()
            .snapshot()
            .into_iter()
            .find(|snapshot| snapshot.inbound == "hysteria2")
        {
            authenticated_user = snapshot.user;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(authenticated_user.as_deref(), Some(test_server::USER));
    assert_eq!(
        acceptor.auth_failures_handle().load(Ordering::Relaxed),
        0,
        "a good handshake never fails auth"
    );
}

#[tokio::test]
async fn a_configured_up_rate_becomes_the_clients_send_rate_and_none_keeps_bbr() {
    let acceptor = test_server::acceptor(GATE_AUTH);
    let server_addr = test_server::spawn(acceptor, match_direct_device()).await;
    let client_runtime = match_direct_device().pinned_runtime();
    for (up, rate) in [(json!("50 Mbps"), 6_250_000), (json!(null), 0)] {
        let connector = Hysteria2Connector::new(
            server_addr.ip().to_string(),
            server_addr.port(),
            &json!({ "password": GATE_AUTH, "skip-cert-verify": true, "sni": test_server::SNI, "up": up }),
        );
        let agreed = timeout(
            Duration::from_secs(10),
            connector.agreed_send_rate(client_runtime.egress()),
        )
        .await
        .expect("hysteria2 dial timeout");
        assert_eq!(agreed, rate, "up {up}");
    }
}

#[tokio::test]
async fn a_profile_switch_closes_old_quic_connections_and_the_listener_accepts_new_ones() {
    let echo_addr = spawn_tcp_echo().await;
    let acceptor = test_server::acceptor(GATE_AUTH);
    let server_device = match_direct_device();
    let server_addr = test_server::spawn(acceptor, server_device.clone()).await;
    let client_runtime = match_direct_device().pinned_runtime();
    let target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let connector = gate_connector(server_addr, GATE_AUTH);
    let mut old = timeout(
        Duration::from_secs(10),
        connector.connect_stream(client_runtime.egress(), &target, b""),
    )
    .await
    .unwrap()
    .unwrap();
    old.write_all(b"before").await.unwrap();
    let mut reply = [0; 6];
    timeout(Duration::from_secs(10), old.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"before");

    let mut next = RuntimeProfile::new("hysteria2-after-switch");
    next.traffic_policy_mode = TrafficPolicyMode::Direct;
    server_device.apply_profile(&next);
    let closed = timeout(Duration::from_secs(3), old.read(&mut reply))
        .await
        .expect("the old QUIC stream closes after a profile switch");
    assert!(matches!(closed, Ok(0) | Err(_)));

    // The same connector replaces its closed carrier and keeps its TLS cache.
    let mut fresh = timeout(
        Duration::from_secs(10),
        connector.connect_stream(client_runtime.egress(), &target, b""),
    )
    .await
    .unwrap()
    .expect("the same listener accepts the new connection generation");
    fresh.write_all(b"after!").await.unwrap();
    timeout(Duration::from_secs(10), fresh.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"after!");
    server_device.close();
}

async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind udp echo");
    let addr = socket.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..read], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// A client runtime with the Hysteria2 proxy compiled from the profile
/// vocabulary and every flow routed to it.
fn hysteria2_client_runtime(server: SocketAddr, auth: &str) -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("hysteria2-udp-client");
    profile.proxies = vec![test_server::proxy_node("Hy2", server, auth)];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Hy2",
        no_resolve: false,
    }]
    .into();
    NativeCoreRuntime::compile(&profile)
}

#[tokio::test]
async fn hysteria2_relays_a_udp_datagram_round_trip() {
    udp_round_trip(b"hysteria2-udp-round-trip").await;
}

/// A datagram larger than one QUIC datagram crosses in Hysteria2 fragments
/// both ways and arrives whole.
#[tokio::test]
async fn hysteria2_relays_a_fragmented_udp_datagram_round_trip() {
    let payload: Vec<u8> = (0..3000).map(|index| (index % 251) as u8).collect();
    udp_round_trip(&payload).await;
}

async fn udp_round_trip(payload: &[u8]) {
    let echo_addr = spawn_udp_echo().await;
    let acceptor = test_server::acceptor(GATE_AUTH);
    let server_addr = test_server::spawn(Arc::clone(&acceptor), match_direct_device()).await;

    // The client sends one UDP datagram; it rides a QUIC datagram to the
    // server's datagram face, relays over DIRECT to the echo, and the response
    // frames back to the same flow.
    let client_runtime = hysteria2_client_runtime(server_addr, GATE_AUTH);
    let flow_id = "hy2-udp-flow";
    let outcome = timeout(
        Duration::from_secs(10),
        send_udp_flow_datagram(
            &client_runtime,
            UdpDatagram {
                flow_id: Some(flow_id.into()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: "127.0.0.1:50000".parse().expect("source addr"),
                target: ConnectTarget {
                    host: echo_addr.ip().to_string(),
                    port: echo_addr.port(),
                },
                payload: payload.to_vec(),
                process_name: None,
                process_path: None,
            },
        ),
    )
    .await
    .expect("udp relay timeout")
    .expect("udp relay");
    assert!(outcome.enqueued);
    let response = drain_pending_udp_flow_responses(&client_runtime, 16, Duration::from_secs(10))
        .await
        .into_iter()
        .find(|response| response.flow_id == flow_id)
        .expect("hysteria2 UDP response");

    // The client profile routes everything to Hy2, so the echo proves the
    // datagram rode the Hysteria2 face.
    assert_eq!(response.payload, payload, "the UDP datagram round-tripped");
}

#[tokio::test]
async fn hysteria2_acceptor_counts_a_wrong_auth_connection() {
    let acceptor = test_server::acceptor(GATE_AUTH);
    let server_addr = test_server::spawn(Arc::clone(&acceptor), match_direct_device()).await;

    // The client presents the wrong auth string: the server answers non-233,
    // so the connector's HTTP/3 auth fails and no tunnel is established.
    let connector = gate_connector(server_addr, "not-the-auth-string");
    let echo_target = ConnectTarget {
        host: "203.0.113.9".into(),
        port: 443,
    };
    let client_runtime = match_direct_device().pinned_runtime();
    let result = timeout(
        Duration::from_secs(10),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("hysteria2 dial timeout");
    assert!(result.is_err(), "wrong-auth dial must fail");

    let auth_failures = acceptor.auth_failures_handle();
    let mut failures = 0;
    for _ in 0..100 {
        failures = auth_failures.load(Ordering::Relaxed);
        if failures >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(failures, 1, "the wrong-auth connection was counted once");
}
