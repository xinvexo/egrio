//! The Shadowsocks connector↔acceptor loopback gate: the real client and
//! server halves dial each other in-process
//! and the payload rides byte-exact through the unmodified
//! `dispatch_accepted_stream` → Router → DIRECT pipeline. Unlike the inbound
//! contract gate — a foreign protocol defined inside a test module — this
//! exercises the shipping `ShadowsocksConnector` and `ShadowsocksAcceptor`,
//! so it runs every commit as their standing gate.
//!
//! The second test pins the auth-failure contract: a wrong-key client is
//! rejected after a bounded read and the acceptor's counter moves, while a
//! good handshake leaves it untouched.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, Duration};

use crate::egress::NativeCoreEgressConfig;
use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::inbound::dispatch::dispatch_accepted_stream;
use crate::outbound::OutboundConnector;
use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
use crate::protocols::shadowsocks::acceptor::{ShadowsocksAcceptor, ShadowsocksUserTable};
use crate::protocols::shadowsocks::codec::parse_cipher;
use crate::protocols::shadowsocks::connector::ShadowsocksConnector;
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;

const GATE_CIPHER: &str = "aes-256-gcm";
const GATE_USER: &str = "alice";
const GATE_PASSWORD: &str = "s3cr3t-preshared-key";

fn match_direct_runtime() -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("shadowsocks-gate");
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

fn gate_user_table() -> Arc<ShadowsocksUserTable> {
    let method = parse_cipher(GATE_CIPHER).expect("known cipher");
    Arc::new(
        ShadowsocksUserTable::new(method)
            .with_user(GATE_USER, GATE_PASSWORD)
            .unwrap(),
    )
}

fn gate_connector(server: SocketAddr, password: &str) -> ShadowsocksConnector {
    ShadowsocksConnector::new(
        server.ip().to_string(),
        server.port(),
        &json!({ "cipher": GATE_CIPHER, "password": password }),
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

/// The server assembly: accept Shadowsocks connections through the shared
/// acceptor and drive each authenticated stream through the unmodified
/// dispatcher. Auth failures return before dispatch, dropping the connection.
async fn spawn_ss_server(
    runtime: NativeCoreRuntime,
    acceptor: Arc<ShadowsocksAcceptor>,
) -> SocketAddr {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ss server");
    let addr = listener.local_addr().expect("ss server addr");
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let runtime = runtime.clone();
            let acceptor = Arc::clone(&acceptor);
            let source = client.peer_addr().ok().map(|addr| addr.to_string());
            tokio::spawn(async move {
                let session = match acceptor.accept(Box::new(client)).await {
                    Ok(session) => session,
                    Err(_) => return,
                };
                let InboundSession::Stream(accepted) = session else {
                    return;
                };
                let _ = dispatch_accepted_stream(&runtime, source, accepted).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn shadowsocks_connector_and_acceptor_relay_through_the_unmodified_dispatcher() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = Arc::new(ShadowsocksAcceptor::new(gate_user_table()));
    let server_addr = spawn_ss_server(server_runtime.clone(), Arc::clone(&acceptor)).await;

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
    .expect("ss dial timeout")
    .expect("ss dial");

    let payload = b"ping-through-the-shadowsocks-pipeline";
    stream.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&echoed, payload, "payload survived the AEAD pipeline");

    // The authenticated identity the acceptor proved reached the ledger.
    let mut authenticated_user = None;
    for _ in 0..50 {
        if let Some(snapshot) = server_runtime
            .session_registry()
            .snapshot()
            .into_iter()
            .find(|snapshot| snapshot.inbound == "shadowsocks")
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
async fn shadowsocks_relays_a_multi_chunk_payload_byte_exact() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = Arc::new(ShadowsocksAcceptor::new(gate_user_table()));
    let server_addr = spawn_ss_server(server_runtime, Arc::clone(&acceptor)).await;

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
    .expect("ss dial timeout")
    .expect("ss dial");

    // A payload spanning many AEAD chunks (> the 0x3fff frame cap), sent and
    // received concurrently so the poll writer's chunking and buffered
    // backpressure and the reader's multi-record assembly are all exercised.
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
async fn shadowsocks_acceptor_counts_and_bounds_a_wrong_key_request() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let acceptor = Arc::new(ShadowsocksAcceptor::new(gate_user_table()));
    let server_addr = spawn_ss_server(server_runtime.clone(), Arc::clone(&acceptor)).await;

    // A client holding the wrong password: its request seals under a key no
    // table entry derives, so no AEAD tag opens and authentication fails.
    let connector = gate_connector(server_addr, "not-the-preshared-key");
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let client_runtime = match_direct_runtime();
    // The dial itself only writes the (unauthenticatable) request — Shadowsocks
    // is early-data, so the server rejects it out of band.
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("ss dial timeout")
    .expect("ss dial writes the request");
    let _ = stream.write_all(b"payload-that-never-arrives").await;

    // The acceptor read a bounded salt + one length record, failed auth, and
    // counted it — all within the timeout, so the path cannot hang or amplify.
    let mut failures = 0;
    for _ in 0..250 {
        failures = acceptor.auth_failures();
        if failures >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(failures, 1, "the wrong-key request was counted once");
    // No session was ever admitted for the rejected connection.
    assert!(
        acceptor.auth_failures() >= 1 && !authenticated_any(&server_runtime),
        "a rejected request never reaches the dispatcher"
    );
}

fn authenticated_any(runtime: &NativeCoreRuntime) -> bool {
    runtime
        .session_registry()
        .snapshot()
        .iter()
        .any(|snapshot| snapshot.inbound == "shadowsocks")
}

/// The targets the server's sessions were asked for.
async fn targets_seen(runtime: &NativeCoreRuntime) -> Vec<String> {
    for _ in 0..50 {
        let targets: Vec<String> = runtime
            .session_registry()
            .snapshot()
            .into_iter()
            .filter(|snapshot| snapshot.inbound == "shadowsocks")
            .map(|snapshot| snapshot.target.to_string())
            .collect();
        if !targets.is_empty() {
            return targets;
        }
        sleep(Duration::from_millis(20)).await;
    }
    Vec::new()
}

/// A chained node's Shadowsocks runs over its dialer-proxy's stream, here
/// another Shadowsocks node's: the hop's server reaches the exit's server,
/// and the exit's server the target.
#[tokio::test]
async fn a_chained_shadowsocks_node_relays_through_its_dialer_proxy() {
    let echo_addr = spawn_tcp_echo().await;
    let hop_runtime = match_direct_runtime();
    let hop_addr = spawn_ss_server(
        hop_runtime.clone(),
        Arc::new(ShadowsocksAcceptor::new(gate_user_table())),
    )
    .await;
    let exit_runtime = match_direct_runtime();
    let exit_addr = spawn_ss_server(
        exit_runtime.clone(),
        Arc::new(ShadowsocksAcceptor::new(gate_user_table())),
    )
    .await;
    let node = |name: &str, server: SocketAddr, options| crate::profile::ProxyNode {
        id: name.into(),
        name: name.into(),
        protocol: crate::profile::ProxyProtocol::Shadowsocks,
        server: Some(server.ip().to_string()),
        port: Some(server.port()),
        options,
    };
    let mut profile = RuntimeProfile::new("shadowsocks-chain");
    profile.proxies = vec![
        node(
            "hop",
            hop_addr,
            json!({ "cipher": GATE_CIPHER, "password": GATE_PASSWORD }),
        ),
        node(
            "exit",
            exit_addr,
            json!({ "cipher": GATE_CIPHER, "password": GATE_PASSWORD, "dialer-proxy": "hop" }),
        ),
    ];
    let client = NativeCoreRuntime::compile(&profile);
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };

    let (mut stream, _) = timeout(
        Duration::from_secs(5),
        crate::runtime::open_outbound_connection(&client, &echo_target, "exit", b""),
    )
    .await
    .expect("chained dial timeout")
    .expect("chained dial");
    let payload = b"ping-through-two-shadowsocks-hops";
    stream.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&echoed, payload);
    assert_eq!(targets_seen(&hop_runtime).await, [exit_addr.to_string()]);
    assert_eq!(targets_seen(&exit_runtime).await, [echo_addr.to_string()]);
}
