//! UDP through chains, end to end against in-process servers: the datagrams
//! of a Shadowsocks, SOCKS5 or Hysteria2 node to a UDP echo, through a
//! Shadowsocks, Trojan or Hysteria2 hop's datagrams. The hop server's UDP
//! session table shows the datagrams went its way, not from this host.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::inbound::dispatch::dispatch_accepted_stream;
use crate::profile::{ProxyNode, ProxyProtocol, RuntimeProfile};
use crate::protocols::hysteria2::test_server;
use crate::protocols::shadowsocks::acceptor::{ShadowsocksAcceptor, ShadowsocksUserTable};
use crate::protocols::shadowsocks::codec::parse_cipher;
use crate::protocols::shadowsocks::udp::serve_shadowsocks_udp;
use crate::protocols::trojan::gate as trojan;
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;
use crate::NativeCoreDevice;

const SS_CIPHER: &str = "aes-256-gcm";
const SS_PASSWORD: &str = "chain-preshared-key";
const HY2_AUTH: &str = "chain-auth";
const WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Shadowsocks,
    Socks5,
    Trojan,
    Hysteria2,
}

/// A running server and where its relayed UDP sessions show.
enum Server {
    Device(NativeCoreDevice),
    Runtime(NativeCoreRuntime),
    /// The SOCKS5 stub keeps no table.
    Stub,
}

impl Server {
    async fn udp_sessions(&self) -> usize {
        match self {
            Self::Device(device) => {
                device
                    .tracked_session(|runtime| async move {
                        runtime.udp_sessions().snapshot_for_test().len()
                    })
                    .await
            }
            Self::Runtime(runtime) => runtime.udp_sessions().snapshot_for_test().len(),
            Self::Stub => 0,
        }
    }
}

async fn start(kind: Kind) -> (SocketAddr, Server) {
    match kind {
        Kind::Shadowsocks => shadowsocks_server().await,
        Kind::Socks5 => (socks5_udp_server().await, Server::Stub),
        Kind::Trojan => {
            let runtime = trojan::match_direct_runtime();
            let addr = trojan::spawn_trojan_server(runtime.clone(), trojan::gate_acceptor()).await;
            (addr, Server::Runtime(runtime))
        }
        Kind::Hysteria2 => {
            let device = test_server::match_direct_device();
            let addr = test_server::spawn(test_server::acceptor(HY2_AUTH), device.clone()).await;
            (addr, Server::Device(device))
        }
    }
}

/// The node `name` for the server `kind` runs at `addr`, relaying UDP, and
/// chained through `via` when it names one.
fn node(kind: Kind, name: &str, addr: SocketAddr, via: Option<&str>) -> ProxyNode {
    let (protocol, mut options) = match kind {
        Kind::Shadowsocks => (
            ProxyProtocol::Shadowsocks,
            json!({ "cipher": SS_CIPHER, "password": SS_PASSWORD }),
        ),
        Kind::Socks5 => (ProxyProtocol::Socks5, json!({})),
        Kind::Trojan => (
            ProxyProtocol::Trojan,
            json!({
                "password": trojan::GATE_PASSWORD,
                "sni": trojan::GATE_SNI,
                "skip-cert-verify": true,
            }),
        ),
        Kind::Hysteria2 => (
            ProxyProtocol::Hysteria2,
            test_server::proxy_node(name, addr, HY2_AUTH).options,
        ),
    };
    options["udp"] = json!(true);
    if let Some(via) = via {
        options["dialer-proxy"] = json!(via);
    }
    ProxyNode {
        id: name.into(),
        name: name.into(),
        protocol,
        server: Some(addr.ip().to_string()),
        port: Some(addr.port()),
        options,
    }
}

/// A Shadowsocks server on one loopback port for TCP and UDP, as a
/// listener serves it, relaying DIRECT.
async fn shadowsocks_server() -> (SocketAddr, Server) {
    let device = test_server::match_direct_device();
    let table = Arc::new(
        ShadowsocksUserTable::new(parse_cipher(SS_CIPHER).expect("cipher"))
            .with_user("alice", SS_PASSWORD)
            .expect("user"),
    );
    let acceptor = Arc::new(ShadowsocksAcceptor::new(Arc::clone(&table)));
    // The system picks the UDP port, and another test may hold that number
    // for TCP: take another pair until both are free.
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp");
        match TcpListener::bind(udp.local_addr().expect("udp addr")).await {
            Ok(tcp) => break (Arc::new(udp), tcp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("bind tcp on the same port: {error}"),
        }
    };
    let addr = udp.local_addr().expect("udp addr");
    // The UDP face serves until its shutdown sender goes, with the TCP loop.
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(serve_shadowsocks_udp(
        udp,
        device.clone(),
        table,
        acceptor.auth_failures_handle(),
        shutdown_rx,
    ));
    let serving = device.clone();
    tokio::spawn(async move {
        let _shutdown = shutdown;
        while let Ok((client, peer)) = tcp.accept().await {
            let (acceptor, device) = (Arc::clone(&acceptor), serving.clone());
            tokio::spawn(async move {
                if let Ok(InboundSession::Stream(accepted)) =
                    acceptor.accept(Box::new(client)).await
                {
                    device
                        .tracked_session(move |runtime| async move {
                            let _ = dispatch_accepted_stream(
                                &runtime,
                                Some(peer.to_string()),
                                accepted,
                            )
                            .await;
                        })
                        .await;
                }
            });
        }
    });
    (addr, Server::Device(device))
}

/// A SOCKS5 proxy (RFC 1928) that only associates: each association gets a
/// relay socket of its own, announced with a wildcard BND.ADDR so the client
/// sends to the host its control connection reached, and lives as long as
/// that connection.
async fn socks5_udp_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind socks5");
    let addr = listener.local_addr().expect("socks5 addr");
    tokio::spawn(async move {
        while let Ok((control, _)) = listener.accept().await {
            tokio::spawn(associate(control));
        }
    });
    addr
}

async fn associate(mut control: TcpStream) -> std::io::Result<()> {
    let mut greeting = [0_u8; 3];
    control.read_exact(&mut greeting).await?;
    control.write_all(&[0x05, 0x00]).await?;
    // VER CMD=UDP ASSOCIATE RSV, then an IPv4 DST.ADDR and DST.PORT.
    let mut request = [0_u8; 10];
    control.read_exact(&mut request).await?;
    assert_eq!(request[..4], [0x05, 0x03, 0x00, 0x01], "a UDP ASSOCIATE");
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    reply.extend_from_slice(&relay.local_addr()?.port().to_be_bytes());
    control.write_all(&reply).await?;
    let mut client = None;
    let (mut from_client, mut from_remote) = (vec![0_u8; 2048], vec![0_u8; 2048]);
    let mut probe = [0_u8; 1];
    loop {
        tokio::select! {
            closed = control.read(&mut probe) => if matches!(closed, Ok(0) | Err(_)) {
                return Ok(());
            },
            received = relay.recv_from(&mut from_client) => {
                let (read, sender) = received?;
                let datagram = &from_client[..read];
                let (target, consumed) = crate::target::parse_socks_address(&datagram[3..])
                    .expect("a SOCKS address");
                client = Some(sender);
                upstream
                    .send_to(&datagram[3 + consumed..], (target.host.as_str(), target.port))
                    .await?;
            }
            received = upstream.recv_from(&mut from_remote) => {
                let (read, origin) = received?;
                let Some(client) = client else { continue };
                let mut datagram = vec![0x00, 0x00, 0x00];
                datagram.extend(
                    ConnectTarget { host: origin.ip().to_string(), port: origin.port() }
                        .socks_address()
                        .expect("an address"),
                );
                datagram.extend_from_slice(&from_remote[..read]);
                relay.send_to(&datagram, client).await?;
            }
        }
    }
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo");
    let addr = socket.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 2048];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..read], peer).await;
        }
    });
    addr
}

/// `exit`'s datagrams to an echo and back, through `hop`.
async fn round_trip(hop: Kind, exit: Kind) {
    let echo = udp_echo().await;
    let (hop_addr, hop_server) = start(hop).await;
    let (exit_addr, _exit_server) = start(exit).await;
    let mut profile = RuntimeProfile::new("chain-udp");
    profile.proxies = vec![
        node(hop, "hop", hop_addr, None),
        node(exit, "exit", exit_addr, Some("hop")),
    ];
    let runtime = NativeCoreRuntime::compile(&profile);
    let target = ConnectTarget {
        host: echo.ip().to_string(),
        port: echo.port(),
    };
    let connector = runtime
        .resolve_outbound("exit", &target)
        .expect("the exit node")
        .connector;
    assert!(connector.udp_enabled(), "{exit:?} relays UDP when chained");
    let transport = timeout(WAIT, connector.connect_datagram(runtime.egress(), &target))
        .await
        .expect("association in time")
        .unwrap_or_else(|error| panic!("{exit:?} through {hop:?}: {error}"));
    let mut receiver = transport.receiver;
    for payload in [b"first".as_slice(), b"second"] {
        timeout(WAIT, transport.sender.send(&target, payload))
            .await
            .expect("send in time")
            .expect("send");
        let (from, echoed) = timeout(WAIT, receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("{exit:?} through {hop:?}: no echo"))
            .expect("receive")
            .expect("a datagram");
        assert_eq!((from, echoed.as_slice()), (target.clone(), payload));
    }
    assert!(
        hop_server.udp_sessions().await >= 1,
        "{exit:?}'s datagrams went through the {hop:?} hop"
    );
}

#[tokio::test]
async fn shadowsocks_udp_through_a_shadowsocks_hop() {
    round_trip(Kind::Shadowsocks, Kind::Shadowsocks).await;
}

#[tokio::test]
async fn shadowsocks_udp_through_a_trojan_hop() {
    round_trip(Kind::Trojan, Kind::Shadowsocks).await;
}

#[tokio::test]
async fn shadowsocks_udp_through_a_hysteria2_hop() {
    round_trip(Kind::Hysteria2, Kind::Shadowsocks).await;
}

#[tokio::test]
async fn socks5_udp_through_a_shadowsocks_hop() {
    round_trip(Kind::Shadowsocks, Kind::Socks5).await;
}

#[tokio::test]
async fn socks5_udp_through_a_trojan_hop() {
    round_trip(Kind::Trojan, Kind::Socks5).await;
}

#[tokio::test]
async fn socks5_udp_through_a_hysteria2_hop() {
    round_trip(Kind::Hysteria2, Kind::Socks5).await;
}

#[tokio::test]
async fn hysteria2_through_a_shadowsocks_hop() {
    round_trip(Kind::Shadowsocks, Kind::Hysteria2).await;
}

#[tokio::test]
async fn hysteria2_through_a_trojan_hop() {
    round_trip(Kind::Trojan, Kind::Hysteria2).await;
}

#[tokio::test]
async fn hysteria2_through_a_hysteria2_hop() {
    round_trip(Kind::Hysteria2, Kind::Hysteria2).await;
}
