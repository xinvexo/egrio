//! The OpenVPN node end to end against the tests' server
//! ([`super::test_server`]): its session, TCP and UDP through the Core's TCP
//! engine and the tunnel, names through the pushed DNS server, a refusal of
//! the credentials, and a server gone silent.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::test_server::{self, Behavior, PASSWORD};
use crate::outbound::OutboundStage;
use crate::profile::{ProxyNode, ProxyProtocol, RuntimeProfile};
use crate::runtime::{open_outbound_connection, NativeCoreRuntime};
use crate::target::ConnectTarget;
use crate::tcp_flow::TcpFlowFailure;

fn runtime(config: &str, password: &str) -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("openvpn");
    profile.proxies = vec![test_server::proxy_node(config, password)];
    NativeCoreRuntime::compile(&profile)
}

/// The node `vpn` with a dialer-proxy.
fn chained(config: &str, hop: &str) -> ProxyNode {
    let mut node = test_server::proxy_node(config, PASSWORD);
    node.options["dialer-proxy"] = hop.into();
    node
}

fn target(host: &str, port: u16) -> ConnectTarget {
    ConnectTarget {
        host: host.into(),
        port,
    }
}

#[tokio::test]
async fn the_node_relays_tcp_and_udp_through_its_session() {
    let server = test_server::start(Behavior::default()).await;
    let runtime = runtime(&server.config, PASSWORD);

    let (mut stream, _) =
        open_outbound_connection(&runtime, &target("10.8.0.1", 7), "vpn", b"early")
            .await
            .expect("a connection through the tunnel");
    stream.write_all(b" and late").await.unwrap();
    let mut echoed = [0_u8; 14];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("the echo")
        .unwrap();
    assert_eq!(&echoed, b"early and late");

    // A name the pushed DNS server knows, on the same session.
    let (mut named, _) =
        open_outbound_connection(&runtime, &target("intranet.test", 7), "vpn", b"")
            .await
            .expect("the name resolves through the tunnel");
    named.write_all(b"by name").await.unwrap();
    let mut echoed = [0_u8; 7];
    tokio::time::timeout(Duration::from_secs(5), named.read_exact(&mut echoed))
        .await
        .expect("the echo")
        .unwrap();
    assert_eq!(&echoed, b"by name");
    let unknown = open_outbound_connection(&runtime, &target("unknown.test", 7), "vpn", b"").await;
    assert!(matches!(
        unknown.err(),
        Some(TcpFlowFailure::Outbound {
            stage: OutboundStage::TargetResolve,
            ..
        })
    ));

    let echo = target("10.8.0.1", 9);
    let connector = runtime.resolve_outbound("vpn", &echo).unwrap().connector;
    let transport = connector
        .connect_datagram(runtime.egress(), &echo)
        .await
        .expect("an association");
    transport.sender.send(&echo, b"datagram").await.unwrap();
    let mut receiver = transport.receiver;
    let (from, payload) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("the echo")
        .unwrap()
        .unwrap();
    assert_eq!((from, payload), (echo, b"datagram".to_vec()));
    assert_eq!(
        server.sessions.load(Ordering::SeqCst),
        1,
        "one session for all"
    );
}

#[tokio::test]
async fn refused_credentials_fail_the_dial_as_the_nodes_authentication() {
    let server = test_server::start(Behavior::default()).await;
    let runtime = runtime(&server.config, "wrong-password");
    let refused = open_outbound_connection(&runtime, &target("10.8.0.1", 7), "vpn", b"").await;
    let Some(TcpFlowFailure::Outbound { stage, message }) = refused.err() else {
        panic!("the dial must fail at the node");
    };
    assert_eq!(stage, OutboundStage::HopAuth);
    assert!(message.contains("refused the credentials"), "{message}");
}

#[tokio::test]
async fn a_dial_that_gives_up_leaves_the_opening_session_to_the_next() {
    let server = test_server::start(Behavior {
        delay: Some(Duration::from_millis(300)),
        ..Behavior::default()
    })
    .await;
    let runtime = runtime(&server.config, PASSWORD);
    let echo = target("10.8.0.1", 7);
    let gave_up = tokio::time::timeout(
        Duration::from_millis(100),
        open_outbound_connection(&runtime, &echo, "vpn", b""),
    )
    .await;
    assert!(
        gave_up.is_err(),
        "the first dial gives up while the session opens"
    );
    assert!(
        open_outbound_connection(&runtime, &echo, "vpn", b"")
            .await
            .is_ok(),
        "the next dial takes the session the first one started"
    );
    assert_eq!(
        server.sessions.load(Ordering::SeqCst),
        1,
        "one session, not one per dial"
    );
}

#[tokio::test]
async fn the_node_reads_its_file_when_a_session_opens() {
    let server = test_server::start(Behavior::default()).await;
    let path = std::env::temp_dir().join(format!("egrio-openvpn-{}.ovpn", rand::random::<u64>()));
    // Compiled before its file exists, the node fails the dial, not the
    // compile.
    let runtime = runtime(&path.to_string_lossy(), PASSWORD);
    let missing = open_outbound_connection(&runtime, &target("10.8.0.1", 7), "vpn", b"").await;
    let Some(TcpFlowFailure::Outbound { stage, message }) = missing.err() else {
        panic!("the dial must fail at the node");
    };
    assert_eq!(stage, OutboundStage::Config);
    assert!(message.contains("cannot read"), "{message}");

    std::fs::copy(&server.config, &path).unwrap();
    let opened = open_outbound_connection(&runtime, &target("10.8.0.1", 7), "vpn", b"").await;
    let _ = std::fs::remove_file(&path);
    assert!(opened.is_ok(), "the next dial reads the file there now");
}

#[tokio::test]
async fn a_server_gone_silent_ends_the_session_and_the_next_dial_opens_another() {
    let server = test_server::start(Behavior {
        ping_restart: Some(1),
        ..Behavior::default()
    })
    .await;
    let runtime = runtime(&server.config, PASSWORD);
    let echo = target("10.8.0.1", 9);
    let connector = runtime.resolve_outbound("vpn", &echo).unwrap().connector;
    let first = connector
        .connect_datagram(runtime.egress(), &echo)
        .await
        .expect("an association");
    assert_eq!(server.sessions.load(Ordering::SeqCst), 1);
    // Nothing comes back from the server for longer than its ping-restart;
    // a loaded machine may run the session's timer late.
    tokio::time::sleep(Duration::from_millis(1600)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while connector.carrier_runtime().is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the session ends");
    drop(first);
    let _second = connector
        .connect_datagram(runtime.egress(), &echo)
        .await
        .expect("a new session");
    assert_eq!(server.sessions.load(Ordering::SeqCst), 2);
}

/// An HTTP CONNECT proxy on loopback that relays each tunnel and records
/// the authority it was asked for.
async fn connect_proxy() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&asked);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = std::sync::Arc::clone(&log);
            tokio::spawn(async move {
                let (header, rest) = crate::protocols::http::read_http_header(&mut client)
                    .await
                    .unwrap();
                let authority = header.split_whitespace().nth(1).unwrap().to_owned();
                log.lock().unwrap().push(authority.clone());
                let mut upstream = tokio::net::TcpStream::connect(&authority).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                upstream.write_all(&rest).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, asked)
}

async fn echo_through(runtime: &NativeCoreRuntime, outbound: &str, payload: &[u8]) {
    let (mut stream, _) = open_outbound_connection(runtime, &target("10.8.0.1", 7), outbound, b"")
        .await
        .expect("a connection");
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("the echo")
        .unwrap();
    assert_eq!(echoed, payload);
}

/// A proxy on the network behind the VPN, as a node whose dialer-proxy is
/// the OpenVPN node.
#[tokio::test]
async fn a_node_chained_through_the_vpn_reaches_the_network_behind_it() {
    let server = test_server::start(Behavior::default()).await;
    let mut profile = RuntimeProfile::new("openvpn");
    profile.proxies = vec![
        test_server::proxy_node(&server.config, PASSWORD),
        ProxyNode {
            id: "corp".into(),
            name: "corp".into(),
            protocol: ProxyProtocol::Http,
            server: Some("10.8.0.1".into()),
            port: Some(3128),
            options: serde_json::json!({ "dialer-proxy": "vpn" }),
        },
    ];
    let runtime = NativeCoreRuntime::compile(&profile);
    echo_through(&runtime, "corp", b"through the corporate proxy").await;
}

/// The VPN's own TCP link through a dialer-proxy's stream.
#[tokio::test]
async fn the_vpn_reaches_its_server_through_a_dialer_proxy() {
    let server = test_server::start(Behavior {
        tcp: true,
        ..Behavior::default()
    })
    .await;
    let (entry, asked) = connect_proxy().await;
    let mut profile = RuntimeProfile::new("openvpn");
    profile.proxies = vec![
        chained(&server.config, "entry"),
        ProxyNode {
            id: "entry".into(),
            name: "entry".into(),
            protocol: ProxyProtocol::Http,
            server: Some("127.0.0.1".into()),
            port: Some(entry),
            options: serde_json::json!({}),
        },
    ];
    let runtime = NativeCoreRuntime::compile(&profile);
    echo_through(&runtime, "vpn", b"over a chained TCP link").await;
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one link for the session: {asked:?}");
    assert!(asked[0].starts_with("127.0.0.1:"), "{asked:?}");
}

/// The VPN's UDP link through a dialer-proxy's datagrams: a Trojan node's
/// UDP associate carries every packet of the session.
#[cfg(feature = "server")]
#[tokio::test]
async fn the_vpn_reaches_its_server_through_a_dialer_proxys_datagrams() {
    use crate::protocols::trojan::gate;

    let server = test_server::start(Behavior::default()).await;
    let trojan =
        gate::spawn_trojan_server(gate::match_direct_runtime(), gate::gate_acceptor()).await;
    let mut profile = RuntimeProfile::new("openvpn");
    profile.proxies = vec![
        chained(&server.config, "entry"),
        ProxyNode {
            id: "entry".into(),
            name: "entry".into(),
            protocol: ProxyProtocol::Trojan,
            server: Some(trojan.ip().to_string()),
            port: Some(trojan.port()),
            options: serde_json::json!({
                "password": gate::GATE_PASSWORD,
                "sni": gate::GATE_SNI,
                "skip-cert-verify": true,
                "udp": true,
            }),
        },
    ];
    let runtime = NativeCoreRuntime::compile(&profile);
    echo_through(&runtime, "vpn", b"over a chained UDP link").await;
    assert_eq!(server.sessions.load(Ordering::SeqCst), 1);
}
