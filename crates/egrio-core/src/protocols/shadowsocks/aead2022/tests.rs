use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use serde_json::json;
use shadowsocks::config::{ServerType, ServerUser, ServerUserManager};
use shadowsocks::context::Context;
use shadowsocks::relay::tcprelay::{ProxyClientStream, ProxyServerStream};
use shadowsocks::relay::udprelay::{
    crypto_io::{
        decrypt_client_payload, decrypt_server_payload, encrypt_client_payload,
        encrypt_server_payload,
    },
    options::UdpSocketControlData,
};
use shadowsocks_crypto::v2::tcp::TcpCipher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use super::*;
use crate::capture::NativeCoreCaptureConfig;
use crate::egress::NativeCoreEgressConfig;
use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::outbound::OutboundConnector;
use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
use crate::protocols::shadowsocks::acceptor::{ShadowsocksAcceptor, ShadowsocksUserTable};
use crate::protocols::shadowsocks::codec::parse_cipher;
use crate::protocols::shadowsocks::connector::ShadowsocksConnector;
use crate::runtime::NativeCoreRuntime;
use crate::NativeCoreDevice;

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const OTHER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
pub(super) const METHODS: [&str; 3] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
const WAIT: Duration = Duration::from_secs(5);

pub(super) fn config(method: &str) -> Arc<Config> {
    Config::new(
        parse_cipher(method).unwrap(),
        if method.contains("128") {
            "AAAAAAAAAAAAAAAAAAAAAA=="
        } else {
            KEY
        },
    )
    .unwrap()
}

pub(super) fn profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("ss2022-test");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn runtime() -> NativeCoreRuntime {
    NativeCoreRuntime::compile_with_egress_and_capture(
        &profile(),
        NativeCoreEgressConfig::default(),
        NativeCoreCaptureConfig::default(),
    )
}

fn target() -> ConnectTarget {
    ConnectTarget {
        host: "example.com".into(),
        port: 443,
    }
}

#[test]
fn keys_are_strict_psks_and_plaintext_ciphers_are_rejected() {
    let method = parse_cipher(METHODS[1]).unwrap();
    for invalid in ["password", "", "YWJj", "!:!", "YWJj:YWJj"] {
        assert!(Config::new(method, invalid).is_err());
    }
    let config = config(METHODS[1]);
    assert_eq!(config.server.key(), &[0; 32]);
    assert!(parse_cipher("none").is_err());
    let identity = Config::new(method, &format!("{OTHER_KEY}:{KEY}")).unwrap();
    assert_eq!(identity.server.identity_keys().len(), 1);
    assert!(ShadowsocksUserTable::new(method)
        .with_user("alice", "invalid")
        .is_err());
    assert!(ShadowsocksUserTable::new(method)
        .with_user("alice", &format!("{OTHER_KEY}:{KEY}"))
        .is_err());
}

#[tokio::test]
async fn all_methods_interoperate_with_official_tcp_server_and_large_early_data() {
    for method in METHODS {
        let config = config(method);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = vec![0x5a; 180_000];
        let expected = payload.clone();
        let server_config = config.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                socket,
                server_config.server.method(),
                server_config.server.key(),
            );
            assert_eq!(from_address(stream.handshake().await.unwrap()), target());
            let mut body = vec![0; expected.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, expected);
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let connector = ShadowsocksConnector::new(
            addr.ip().to_string(),
            addr.port(),
            &json!({"cipher": method, "password": config.server.password()}),
        );
        let runtime = runtime();
        let mut stream = timeout(
            WAIT,
            connector.connect_stream(runtime.egress(), &target(), &payload),
        )
        .await
        .unwrap()
        .unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, payload);
        timeout(WAIT, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn server_first_tcp_works_without_client_payload() {
    let config = config(METHODS[1]);
    let table = ShadowsocksUserTable::new(config.server.method())
        .with_user("alice", KEY)
        .unwrap();
    let acceptor = ShadowsocksAcceptor::new(Arc::new(table));
    let (client_io, server_io) = tokio::io::duplex(4096);
    let target = target();
    let (client, server) = timeout(WAIT, async {
        tokio::join!(
            connect(client_io, &config, &target, b""),
            acceptor.accept(Box::new(server_io))
        )
    })
    .await
    .unwrap();
    let mut client = client.unwrap();
    let InboundSession::Stream(mut accepted) = server.unwrap() else {
        panic!("expected TCP")
    };
    accepted.io.write_all(b"server greeting").await.unwrap();
    let mut greeting = [0; 15];
    timeout(WAIT, client.read_exact(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&greeting, b"server greeting");
}

fn sealed_request(config: &Config, timestamp: u64) -> Vec<u8> {
    let method = config.server.method();
    let salt: Vec<u8> = (0..method.salt_len()).map(|_| rand::random()).collect();
    let mut variable = target().socks_address().unwrap();
    variable.extend_from_slice(&0_u16.to_be_bytes());
    variable.extend_from_slice(b"early");
    let mut fixed = vec![0];
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut cipher = TcpCipher::new(method, config.server.key(), &salt);
    let mut wire = salt;
    for mut chunk in [fixed, variable] {
        chunk.resize(chunk.len() + method.tag_len(), 0);
        cipher.encrypt_packet(&mut chunk);
        wire.extend_from_slice(&chunk);
    }
    wire
}

#[tokio::test]
async fn tcp_rejects_wrong_keys_tampering_stale_headers_and_replayed_salts() {
    for method in METHODS {
        let config = config(method);
        let acceptor = ShadowsocksAcceptor::new(Arc::new(
            ShadowsocksUserTable::new(config.server.method())
                .with_user("alice", config.server.password())
                .unwrap(),
        ));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = sealed_request(&config, now);
        assert!(acceptor
            .accept(Box::new(Cursor::new(valid.clone())))
            .await
            .is_ok());
        assert!(acceptor.accept(Box::new(Cursor::new(valid))).await.is_err());
        for time in [now - 60, now + 60] {
            assert!(acceptor
                .accept(Box::new(Cursor::new(sealed_request(&config, time))))
                .await
                .is_err());
        }
        let mut tampered = sealed_request(&config, now);
        *tampered.last_mut().unwrap() ^= 1;
        assert!(acceptor
            .accept(Box::new(Cursor::new(tampered)))
            .await
            .is_err());
        let other = Config::new(
            config.server.method(),
            if method.contains("128") {
                "AQEBAQEBAQEBAQEBAQEBAQ=="
            } else {
                OTHER_KEY
            },
        )
        .unwrap();
        assert!(acceptor
            .accept(Box::new(Cursor::new(sealed_request(&other, now))))
            .await
            .is_err());
        assert_eq!(
            acceptor.auth_failures(),
            1,
            "authenticated replays and malformed bodies are not bad credentials"
        );
    }
}

/// SIP022 section 3.1.4: a probe of any length is held while the prober
/// waits and closed with a FIN once it closes, never with an RST that would
/// show how many bytes the server read.
#[tokio::test]
async fn tcp_refused_probes_of_any_length_are_held_and_closed_with_a_fin() {
    let config = config(METHODS[1]);
    let acceptor = Arc::new(ShadowsocksAcceptor::new(Arc::new(
        ShadowsocksUserTable::new(config.server.method())
            .with_user("alice", config.server.password())
            .unwrap(),
    )));
    let header = config.server.method().salt_len() + 11 + config.server.method().tag_len();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    for length in [1, header - 1, header, 200, 50_000] {
        let mut prober = tokio::net::TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let acceptor = Arc::clone(&acceptor);
        let refused = tokio::spawn(async move { acceptor.accept(Box::new(server)).await });
        prober.write_all(&vec![0x5A_u8; length]).await.unwrap();
        let mut byte = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(200), prober.read(&mut byte))
                .await
                .is_err(),
            "a {length}-byte probe sees the connection open"
        );
        prober.shutdown().await.unwrap();
        assert!(timeout(WAIT, refused).await.unwrap().unwrap().is_err());
        let read = timeout(WAIT, prober.read(&mut byte)).await.unwrap();
        assert!(
            matches!(read, Ok(0)),
            "a {length}-byte probe ends with a FIN, got {read:?}"
        );
    }
}

#[tokio::test]
async fn tcp_client_rejects_response_bound_to_another_request() {
    for method in METHODS {
        let config = config(method);
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut client = connect(client_io, &config, &target(), b"early")
            .await
            .unwrap();
        let cipher = config.server.method();
        let mut request_salt = vec![0; cipher.salt_len()];
        server_io.read_exact(&mut request_salt).await.unwrap();
        request_salt[0] ^= 1;
        let salt = vec![0x5a; cipher.salt_len()];
        let mut fixed = vec![1];
        fixed.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_be_bytes(),
        );
        fixed.extend_from_slice(&request_salt);
        fixed.extend_from_slice(&3_u16.to_be_bytes());
        let mut encryptor = TcpCipher::new(cipher, config.server.key(), &salt);
        let mut wire = salt;
        for mut chunk in [fixed, b"bad".to_vec()] {
            chunk.resize(chunk.len() + cipher.tag_len(), 0);
            encryptor.encrypt_packet(&mut chunk);
            wire.extend_from_slice(&chunk);
        }
        server_io.write_all(&wire).await.unwrap();
        assert!(timeout(WAIT, client.read(&mut [0; 3]))
            .await
            .unwrap()
            .is_err());
    }
}

#[tokio::test]
async fn official_tcp_client_authenticates_the_correct_inbound_user() {
    for method in METHODS {
        let config = config(method);
        let key = config.server.password();
        let other = if method.contains("128") {
            "AQEBAQEBAQEBAQEBAQEBAQ=="
        } else {
            OTHER_KEY
        };
        let table = ShadowsocksUserTable::new(config.server.method())
            .with_user("alice", other)
            .unwrap()
            .with_user("bob", key)
            .unwrap();
        let acceptor = ShadowsocksAcceptor::new(Arc::new(table));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client = ProxyClientStream::from_stream(
            config.context.clone(),
            client_io,
            &config.server,
            to_address(&target()).unwrap(),
        );
        let (sent, accepted) = timeout(WAIT, async {
            tokio::join!(
                client.write_all(b"early"),
                acceptor.accept(Box::new(server_io))
            )
        })
        .await
        .unwrap();
        sent.unwrap();
        let InboundSession::Stream(mut accepted) = accepted.unwrap() else {
            panic!("expected TCP")
        };
        assert_eq!(accepted.user.as_deref(), Some("bob"));
        assert_eq!(accepted.target, target());
        let mut early = [0; 5];
        accepted.io.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
        accepted.io.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }
}

#[tokio::test]
async fn identity_chain_tcp_interoperates_with_official_multi_user_server() {
    let config = Config::new(
        parse_cipher(METHODS[1]).unwrap(),
        &format!("{OTHER_KEY}:{KEY}"),
    )
    .unwrap();
    let root = Config::new(config.server.method(), OTHER_KEY).unwrap();
    let mut users = ServerUserManager::new();
    users.add_user(ServerUser::new("alice", config.server.key().to_vec()));
    let (client_io, server_io) = tokio::io::duplex(4096);
    let target = target();
    let mut server = ProxyServerStream::from_stream_with_user_manager(
        Context::new_shared(ServerType::Server),
        server_io,
        root.server.method(),
        root.server.key(),
        Some(Arc::new(users)),
    );
    let (client, address) = timeout(WAIT, async {
        tokio::join!(
            connect(client_io, &config, &target, b"early"),
            server.handshake()
        )
    })
    .await
    .unwrap();
    assert_eq!(from_address(address.unwrap()), target);
    assert_eq!(server.user_key().unwrap(), config.server.key());
    let mut early = [0; 5];
    server.read_exact(&mut early).await.unwrap();
    server.write_all(&early).await.unwrap();
    let mut reply = [0; 5];
    client.unwrap().read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, early);
}

#[tokio::test]
async fn udp_client_rejects_wrong_bindings_and_replays_for_all_methods() {
    let mut cases: Vec<_> = METHODS
        .into_iter()
        .map(|method| (method, config(method).server.password().to_string()))
        .collect();
    cases.extend([
        (
            METHODS[0],
            "AQEBAQEBAQEBAQEBAQEBAQ==:AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
        ),
        (METHODS[1], format!("{OTHER_KEY}:{KEY}")),
    ]);
    for (method, password) in cases {
        let config = Config::new(parse_cipher(method).unwrap(), &password).unwrap();
        let mut users = ServerUserManager::new();
        let identity = config.server.identity_keys().first();
        if identity.is_some() {
            users.add_user(ServerUser::new("alice", config.server.key().to_vec()));
        }
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let runtime = runtime();
        let connector = ShadowsocksConnector::new(
            addr.ip().to_string(),
            addr.port(),
            &json!({"cipher": method, "password": password}),
        );
        let mut transport = connector
            .connect_datagram(runtime.egress(), &target())
            .await
            .unwrap();
        transport.sender.send(&target(), b"request").await.unwrap();
        let mut request = vec![0; 65536];
        let (read, client) = timeout(WAIT, server.recv_from(&mut request))
            .await
            .unwrap()
            .unwrap();
        let (size, address, control) = decrypt_client_payload(
            &config.context,
            config.server.method(),
            identity.map_or(config.server.key(), |key| key.as_ref()),
            &mut request[..read],
            identity.map(|_| &users),
        )
        .unwrap();
        assert_eq!(&request[..size], b"request");
        assert_eq!(from_address(address), target());
        let mut control = control.unwrap();
        control.server_session_id = 777;
        let client_id = control.client_session_id;
        // Wrong binding must not poison the valid session's packet-zero bit.
        for (id, packet_id, payload) in [
            (client_id ^ 1, 0, "bad"),
            (client_id, 0, "one"),
            (client_id, 0, "replay"),
            (client_id, 1, "two"),
        ] {
            control.client_session_id = id;
            control.packet_id = packet_id;
            let mut packet = BytesMut::new();
            encrypt_server_payload(
                &config.context,
                config.server.method(),
                config.server.key(),
                &to_address(&target()).unwrap(),
                &control,
                payload.as_bytes(),
                &mut packet,
            );
            server.send_to(&packet, client).await.unwrap();
        }
        assert_eq!(
            timeout(WAIT, transport.receiver.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .1,
            b"one"
        );
        assert_eq!(
            timeout(WAIT, transport.receiver.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .1,
            b"two"
        );
    }
}

#[tokio::test]
async fn udp_inbound_keeps_sessions_across_nat_rebinding_and_rejects_replays() {
    for method in METHODS {
        let config = config(method);
        let table = Arc::new(
            ShadowsocksUserTable::new(config.server.method())
                .with_user("alice", config.server.password())
                .unwrap(),
        );
        let device = NativeCoreDevice::compile_with_egress_and_capture(
            &profile(),
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
        );
        device.start();
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let server_socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let server_addr = server_socket.local_addr().unwrap();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve(
            server_socket,
            device.clone(),
            table,
            Arc::new(AtomicU64::new(0)),
            shutdown,
        ));
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 1234;
        let endpoint = ConnectTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let mut previous_source = None;
        let mut server_id = None;
        for packet_id in 0..2 {
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            control.packet_id = packet_id;
            let mut request = BytesMut::new();
            encrypt_client_payload(
                &config.context,
                config.server.method(),
                config.server.key(),
                &to_address(&endpoint).unwrap(),
                &control,
                &[],
                b"ping",
                &mut request,
            );
            client.send_to(&request, server_addr).await.unwrap();
            let mut packet = vec![0; 65536];
            let (read, source) = timeout(WAIT, echo.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&packet[..read], b"ping");
            if let Some(previous) = previous_source {
                assert_eq!(source, previous);
            }
            previous_source = Some(source);
            echo.send_to(b"pong", source).await.unwrap();
            let (read, _) = timeout(WAIT, client.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
            let (size, _, reply) = decrypt_server_payload(
                &config.context,
                config.server.method(),
                config.server.key(),
                &mut packet[..read],
            )
            .unwrap();
            assert_eq!(&packet[..size], b"pong");
            let reply = reply.unwrap();
            assert_eq!(reply.client_session_id, 1234);
            assert_eq!(reply.packet_id, packet_id);
            if let Some(previous) = server_id {
                assert_eq!(reply.server_session_id, previous);
            }
            server_id = Some(reply.server_session_id);
            client.send_to(&request, server_addr).await.unwrap();
            assert!(
                timeout(Duration::from_millis(75), echo.recv_from(&mut packet))
                    .await
                    .is_err(),
                "replay reached target"
            );
        }
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap();
        device.close();
    }
}

#[tokio::test]
async fn the_pump_seals_and_opens_a_udp_association_like_its_actor() {
    use crate::outbound::{PumpFrom, PumpTo};
    let config = config(METHODS[0]);
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = server.local_addr().unwrap();
    let runtime = runtime();
    let connector = ShadowsocksConnector::new(
        addr.ip().to_string(),
        addr.port(),
        &json!({"cipher": METHODS[0], "password": config.server.password()}),
    );
    let transport = connector
        .connect_datagram(runtime.egress(), &target())
        .await
        .unwrap();
    transport.sender.send(&target(), b"actor").await.unwrap();
    let io = transport
        .receiver
        .pump_datagrams()
        .expect("the pump can drive a Shadowsocks 2022 association");
    io.hand_reads_to(std::task::Waker::noop().clone());
    io.try_send(&PumpTo::Name("example.com:443".into()), b"pump")
        .unwrap();

    // Both sends share the client session; the pump's packet comes second.
    let mut packet_ids = Vec::new();
    let mut client = None;
    for expected in [&b"actor"[..], b"pump"] {
        let mut request = vec![0; 65536];
        let (read, from) = timeout(WAIT, server.recv_from(&mut request))
            .await
            .unwrap()
            .unwrap();
        let (size, address, control) = decrypt_client_payload(
            &config.context,
            config.server.method(),
            config.server.key(),
            &mut request[..read],
            None,
        )
        .unwrap();
        assert_eq!(&request[..size], expected);
        assert_eq!(from_address(address), target());
        let control = control.unwrap();
        packet_ids.push(control.packet_id);
        client = Some((from, control.client_session_id));
    }
    assert_eq!(packet_ids, [0, 1]);

    let (from, client_id) = client.unwrap();
    let mut control = UdpSocketControlData::default();
    control.client_session_id = client_id;
    control.server_session_id = 9;
    let mut reply = BytesMut::new();
    encrypt_server_payload(
        &config.context,
        config.server.method(),
        config.server.key(),
        &to_address(&target()).unwrap(),
        &control,
        b"pong",
        &mut reply,
    );
    server.send_to(&reply, from).await.unwrap();
    let mut buffer = [0_u8; 2048];
    let read = timeout(WAIT, async {
        loop {
            match io.try_recv(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                read => break read.unwrap(),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(&buffer[..read.0], b"pong");
    assert_eq!(read.1, PumpFrom::Name(target()));
}
