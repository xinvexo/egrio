//! The Trojan connector↔acceptor loopback gate: the real client and server
//! halves dial each other in-process
//! over TLS and the payload rides byte-exact through the unmodified
//! `dispatch_accepted_stream` → Router → DIRECT pipeline. It exercises the
//! shipping `TrojanConnector` and `TrojanAcceptor`, so it runs every commit
//! (behind the `server` feature that terminates TLS).
//!
//! The UDP gate runs the same loop over the associate's framed datagram
//! tunnel: one client associate reaches two echo remotes through the
//! unmodified `dispatch_accepted_datagrams` pump and the user-keyed UDP
//! session table. The auth-failure test pins that contract: a wrong-password
//! client is rejected after a bounded read and the acceptor's counter moves,
//! while a good handshake leaves it untouched.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout, Duration};

use crate::certificate::server_config_from_pem;
use crate::egress::NativeCoreEgressConfig;
use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::inbound::dispatch::{dispatch_accepted_datagrams, dispatch_accepted_stream};
use crate::outbound::OutboundConnector;
use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
use crate::protocols::trojan::acceptor::{TrojanAcceptor, TrojanUserTable};
use crate::protocols::trojan::connector::TrojanConnector;
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;

const GATE_USER: &str = "alice";
pub(crate) const GATE_PASSWORD: &str = "s3cr3t-preshared-key";
pub(crate) const GATE_SNI: &str = "localhost";

pub(crate) fn match_direct_runtime() -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("trojan-gate");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    NativeCoreRuntime::compile_with_egress_and_capture(
        &profile,
        NativeCoreEgressConfig::default(),
        crate::capture::NativeCoreCaptureConfig::default(),
    )
}

/// A throwaway self-signed cert + key (PEM, SAN `localhost`) — the material an
/// operator hands the certificate subsystem.
fn self_signed_pem() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec![GATE_SNI.into()])
        .expect("params")
        .self_signed(&key_pair)
        .expect("self-signed cert");
    (cert.pem(), key_pair.serialize_pem())
}

pub(crate) fn gate_acceptor() -> Arc<TrojanAcceptor> {
    let (cert_pem, key_pem) = self_signed_pem();
    let tls = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), &[])
        .expect("server config builds");
    let users = TrojanUserTable::new().with_user(GATE_USER, GATE_PASSWORD);
    Arc::new(TrojanAcceptor::new(tls, users))
}

fn gate_connector(server: SocketAddr, password: &str) -> TrojanConnector {
    TrojanConnector::new(
        server.ip().to_string(),
        server.port(),
        &json!({ "password": password, "sni": GATE_SNI, "skip-cert-verify": true }),
    )
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
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

async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind udp echo");
    let addr = socket.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 2048];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..read], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

fn udp_target(addr: SocketAddr) -> ConnectTarget {
    ConnectTarget {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

/// The server assembly: accept Trojan connections through the shared acceptor
/// and drive whichever session arm each yields through the unmodified
/// dispatcher — the exact enum match a real listener runs. Auth failures
/// return before dispatch, dropping the connection.
pub(crate) async fn spawn_trojan_server(
    runtime: NativeCoreRuntime,
    acceptor: Arc<TrojanAcceptor>,
) -> SocketAddr {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind trojan server");
    let addr = listener.local_addr().expect("trojan server addr");
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let runtime = runtime.clone();
            let acceptor = Arc::clone(&acceptor);
            let source = client.peer_addr().ok().map(|addr| addr.to_string());
            tokio::spawn(async move {
                match acceptor.accept(Box::new(client)).await {
                    Ok(InboundSession::Stream(accepted)) => {
                        let _ = dispatch_accepted_stream(&runtime, source, accepted).await;
                    }
                    Ok(InboundSession::Datagrams(face)) => {
                        let _ = dispatch_accepted_datagrams(&runtime, face).await;
                    }
                    Err(_) => {}
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn trojan_connector_and_acceptor_relay_through_the_unmodified_dispatcher() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = gate_acceptor();
    let server_addr = spawn_trojan_server(server_runtime.clone(), Arc::clone(&acceptor)).await;

    let connector = gate_connector(server_addr, GATE_PASSWORD);
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    // The client half needs an egress to dial the server; a throwaway runtime
    // supplies one (the client is not the system under test).
    let client_runtime = match_direct_runtime();
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("trojan dial timeout")
    .expect("trojan dial");

    let payload = b"ping-through-the-trojan-pipeline";
    stream.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&echoed, payload, "payload survived the TLS pipeline");

    // The authenticated identity the acceptor proved reached the ledger.
    let mut authenticated_user = None;
    for _ in 0..50 {
        if let Some(snapshot) = server_runtime
            .session_registry()
            .snapshot()
            .into_iter()
            .find(|snapshot| snapshot.inbound == "trojan")
        {
            authenticated_user = snapshot.user;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(authenticated_user.as_deref(), Some(GATE_USER));
    assert_eq!(
        acceptor.auth_failures(),
        0,
        "a good handshake never fails auth"
    );
}

#[tokio::test]
async fn trojan_relays_a_multi_chunk_payload_byte_exact() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = gate_acceptor();
    let server_addr = spawn_trojan_server(server_runtime, Arc::clone(&acceptor)).await;

    let connector = gate_connector(server_addr, GATE_PASSWORD);
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let client_runtime = match_direct_runtime();
    let stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("trojan dial timeout")
    .expect("trojan dial");

    // A payload spanning many TLS records, sent and received concurrently so the
    // relay's chunking and the reader's record assembly are both exercised.
    let payload: Vec<u8> = (0..200_000_u32).map(|byte| byte as u8).collect();
    let expected = payload.clone();
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.expect("write payload");
        write_half.shutdown().await.expect("shutdown write half");
    });

    let mut echoed = vec![0_u8; expected.len()];
    timeout(Duration::from_secs(10), read_half.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    writer.await.expect("writer task");

    assert_eq!(echoed, expected, "multi-chunk payload survived byte-exact");
}

#[tokio::test]
async fn trojan_udp_associate_relays_datagrams_through_the_unmodified_dispatcher() {
    let echo_a = spawn_udp_echo().await;
    let echo_b = spawn_udp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = gate_acceptor();
    let server_addr = spawn_trojan_server(server_runtime.clone(), Arc::clone(&acceptor)).await;

    // The client half opens one associate naming its first target; every frame
    // below still carries its own target (EIM).
    let connector = gate_connector(server_addr, GATE_PASSWORD);
    let client_runtime = match_direct_runtime();
    let transport = timeout(
        Duration::from_secs(5),
        connector.connect_datagram(client_runtime.egress(), &udp_target(echo_a)),
    )
    .await
    .expect("trojan associate timeout")
    .expect("trojan associate");
    let mut receiver = transport.receiver;

    // Two remotes over the single associate: each frame's own target routes
    // it, and each reply comes back tagged with its origin.
    for (echo_addr, payload) in [
        (echo_a, b"trojan-udp-to-a".as_slice()),
        (echo_b, b"trojan-udp-to-b".as_slice()),
    ] {
        let target = udp_target(echo_addr);
        timeout(
            Duration::from_secs(5),
            transport.sender.send(&target, payload),
        )
        .await
        .expect("send timeout")
        .expect("send frame");

        let (origin, echoed) = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("echo timeout")
            .expect("echo frame")
            .expect("one echoed datagram");
        assert_eq!(origin, target, "the reply is tagged with its origin");
        assert_eq!(echoed, payload, "payload survived the framed TLS tunnel");
    }

    // One associate is one authenticated 2-tuple session (EIM): the server's
    // UDP session table carries the acceptor's user on a single flow.
    let sessions = server_runtime.udp_sessions().snapshot_for_test();
    assert_eq!(sessions.len(), 1, "one associate is one EIM session");
    assert_eq!(sessions[0].key.user.as_deref(), Some(GATE_USER));
    assert_eq!(sessions[0].inbound, "udp-associate");
    assert_eq!(
        acceptor.auth_failures(),
        0,
        "a good associate never fails auth"
    );
}

#[tokio::test]
async fn trojan_acceptor_counts_and_bounds_a_wrong_password_request() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = gate_acceptor();
    let server_addr = spawn_trojan_server(server_runtime.clone(), Arc::clone(&acceptor)).await;

    // A client holding the wrong password: its preamble carries a hash no table
    // entry derives, so the map lookup misses and authentication fails.
    let connector = gate_connector(server_addr, "not-the-preshared-key");
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let client_runtime = match_direct_runtime();
    // The dial completes TLS and writes the (unauthenticatable) preamble; Trojan
    // is early-data, so the server rejects it out of band.
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("trojan dial timeout")
    .expect("trojan dial writes the preamble");
    let _ = stream.write_all(b"payload-that-never-arrives").await;

    // The acceptor read a bounded 56-byte hash, failed auth, and counted it —
    // all within the timeout, so the path cannot hang or amplify.
    let mut failures = 0;
    for _ in 0..250 {
        failures = acceptor.auth_failures();
        if failures >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(failures, 1, "the wrong-password request was counted once");
    assert!(
        !authenticated_any(&server_runtime),
        "a rejected request never reaches the dispatcher"
    );
}

fn authenticated_any(runtime: &NativeCoreRuntime) -> bool {
    runtime
        .session_registry()
        .snapshot()
        .iter()
        .any(|snapshot| snapshot.inbound == "trojan")
}

/// The targets the server's sessions were asked for.
async fn targets_seen(runtime: &NativeCoreRuntime) -> Vec<String> {
    for _ in 0..50 {
        let targets: Vec<String> = runtime
            .session_registry()
            .snapshot()
            .into_iter()
            .filter(|snapshot| snapshot.inbound == "trojan")
            .map(|snapshot| snapshot.target.to_string())
            .collect();
        if !targets.is_empty() {
            return targets;
        }
        sleep(Duration::from_millis(20)).await;
    }
    Vec::new()
}

/// A chained node's TLS runs over its dialer-proxy's stream, here another
/// Trojan node's TLS; its UDP associate rides such a carrier too.
#[tokio::test]
async fn a_chained_trojan_node_relays_through_its_dialer_proxy() {
    let echo_addr = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let hop_runtime = match_direct_runtime();
    let hop_addr = spawn_trojan_server(hop_runtime.clone(), gate_acceptor()).await;
    let exit_runtime = match_direct_runtime();
    let exit_addr = spawn_trojan_server(exit_runtime.clone(), gate_acceptor()).await;
    let node = |name: &str, server: SocketAddr, via: Option<&str>| {
        let mut options =
            json!({ "password": GATE_PASSWORD, "sni": GATE_SNI, "skip-cert-verify": true });
        if let Some(via) = via {
            options["dialer-proxy"] = via.into();
        }
        crate::profile::ProxyNode {
            id: name.into(),
            name: name.into(),
            protocol: crate::profile::ProxyProtocol::Trojan,
            server: Some(server.ip().to_string()),
            port: Some(server.port()),
            options,
        }
    };
    let mut profile = RuntimeProfile::new("trojan-chain");
    profile.proxies = vec![
        node("hop", hop_addr, None),
        node("exit", exit_addr, Some("hop")),
    ];
    let client = NativeCoreRuntime::compile(&profile);
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };

    for payload in [
        b"first-through-two-trojan-hops",
        b"again-through-two-trojan-hops",
    ] {
        let (mut stream, _) = timeout(
            Duration::from_secs(5),
            crate::runtime::open_outbound_connection(&client, &echo_target, "exit", b""),
        )
        .await
        .expect("chained dial timeout")
        .expect("chained dial");
        stream.write_all(payload).await.expect("write payload");
        let mut echoed = vec![0_u8; payload.len()];
        timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .expect("echo timeout")
            .expect("echo read");
        assert_eq!(&echoed, payload);
    }
    let hop_targets = targets_seen(&hop_runtime).await;
    assert!(!hop_targets.is_empty());
    assert!(
        hop_targets
            .iter()
            .all(|target| *target == exit_addr.to_string()),
        "{hop_targets:?}"
    );
    assert!(targets_seen(&exit_runtime)
        .await
        .iter()
        .all(|target| *target == echo_addr.to_string()));

    let exit = client
        .resolve_outbound("exit", &udp_target(udp_echo))
        .expect("exit");
    let transport = timeout(
        Duration::from_secs(5),
        exit.connector
            .connect_datagram(client.egress(), &udp_target(udp_echo)),
    )
    .await
    .expect("chained associate timeout")
    .expect("chained associate");
    let mut receiver = transport.receiver;
    transport
        .sender
        .send(&udp_target(udp_echo), b"datagram-through-two-hops")
        .await
        .expect("send frame");
    let (origin, echoed) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("echo timeout")
        .expect("echo frame")
        .expect("one echoed datagram");
    assert_eq!(origin, udp_target(udp_echo));
    assert_eq!(echoed, b"datagram-through-two-hops");
    assert_eq!(exit_runtime.udp_sessions().snapshot_for_test().len(), 1);
    assert!(hop_runtime.udp_sessions().snapshot_for_test().is_empty());
}
