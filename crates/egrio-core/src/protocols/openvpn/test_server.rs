//! An OpenVPN server for the tests, over UDP on loopback: tls-crypt, TLS
//! with the client's certificate required, the key exchange with a username
//! and password, a push reply, and the data channel. Behind its address the
//! Core's TCP engine accepts connections and echoes them; UDP datagrams are
//! echoed, and port 53 answers `intranet.test`. The client half was checked
//! against OpenVPN 2.6 and 2.7 servers (see `live.rs`); this one lets every
//! commit run the node end to end. It listens on UDP or, as `proto tcp`
//! servers do, takes one TCP connection's length-prefixed packets; port 3128
//! behind it is an HTTP CONNECT proxy whose tunnels echo, for a node chained
//! through the VPN.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use super::config::DataCipher;
use super::crypt::{StaticKey, TlsCrypt};
use super::data::{DataKeys, Payload};
use super::reliable::Reliable;
use super::wire::{
    key_id, opcode, ControlPlain, Wrap, ACKS_ALONE, ACKS_WITH_MESSAGE, P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_SERVER_V2, P_CONTROL_V1, P_DATA_V1,
    P_DATA_V2,
};
use crate::attribution::ClientOwner;
use crate::packet::tcp::{CapturedTcpStream, TcpEngine};
use crate::packet::{build_udp_packet, udp_endpoints};
use crate::profile::{ProxyNode, ProxyProtocol};

pub(crate) const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
pub(super) const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
pub(super) const USERNAME: &str = "egrio";
pub(crate) const PASSWORD: &str = "test-password";
const PEER_ID: u32 = 7;

/// A running server and the client config that reaches it.
pub(crate) struct TestServer {
    /// The client's `.ovpn` file, removed with the server.
    pub(crate) config: String,
    /// Sessions clients opened so far.
    pub(super) sessions: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.config);
    }
}

/// What the server pushes besides the address and keys, and how it answers.
#[derive(Clone, Default)]
pub(crate) struct Behavior {
    /// Pushed `ping-restart`; the server answers no ping, so a client
    /// following it ends the session after this long without traffic.
    pub(super) ping_restart: Option<u64>,
    /// Answers the push request with `AUTH_FAILED` whatever the credentials.
    pub(super) refuse: bool,
    /// Listens on TCP instead of UDP.
    pub(super) tcp: bool,
    /// Takes this long to answer a new session, as a slow server does.
    pub(super) delay: Option<Duration>,
}

/// What the server reads from its wire.
enum Incoming {
    Packet(Vec<u8>, SocketAddr),
    /// A TCP client connected; packets go back on it.
    Connection(OwnedWriteHalf),
}

/// Where the server writes packets.
enum Wire {
    Udp(Arc<UdpSocket>),
    Tcp(Option<OwnedWriteHalf>),
}

impl Wire {
    async fn send(&mut self, packet: &[u8], to: SocketAddr) {
        match self {
            Self::Udp(socket) => {
                let _ = socket.send_to(packet, to).await;
            }
            Self::Tcp(Some(write)) => {
                let mut framed = (packet.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(packet);
                let _ = write.write_all(&framed).await;
            }
            Self::Tcp(None) => {}
        }
    }
}

/// Reads the wire into `incoming`.
async fn read_wire(wire: WireListener, incoming: mpsc::Sender<Incoming>) {
    match wire {
        WireListener::Udp(socket) => {
            let mut buffer = vec![0_u8; 65536];
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                if incoming
                    .send(Incoming::Packet(buffer[..read].to_vec(), from))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        WireListener::Tcp(listener) => {
            while let Ok((stream, from)) = listener.accept().await {
                let (mut read, write) = stream.into_split();
                if incoming.send(Incoming::Connection(write)).await.is_err() {
                    return;
                }
                let incoming = incoming.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok(length) = read.read_u16().await else {
                            return;
                        };
                        let mut packet = vec![0_u8; usize::from(length)];
                        if read.read_exact(&mut packet).await.is_err() {
                            return;
                        }
                        if incoming.send(Incoming::Packet(packet, from)).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    }
}

enum WireListener {
    Udp(Arc<UdpSocket>),
    Tcp(TcpListener),
}

fn pem_block(tag: &str, pem: &str) -> String {
    format!("<{tag}>\n{pem}</{tag}>\n")
}

/// The node `vpn` reading `config`, with `password`.
pub(crate) fn proxy_node(config: &str, password: &str) -> ProxyNode {
    ProxyNode {
        id: "vpn".into(),
        name: "vpn".into(),
        protocol: ProxyProtocol::OpenVpn,
        server: None,
        port: None,
        options: serde_json::json!({
            "config": config,
            "username": USERNAME,
            "password": password,
        }),
    }
}

pub(crate) async fn start(behavior: Behavior) -> TestServer {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "Egrio test CA");
    let ca = ca.self_signed(&ca_key).unwrap();
    let leaf = |name: &str, usage: rcgen::ExtendedKeyUsagePurpose| {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        (cert, key)
    };
    let (server_cert, server_key) = leaf("server_test", rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) = leaf("client_test", rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let mut static_key = String::from("-----BEGIN OpenVPN Static key V1-----\n");
    for _ in 0..16 {
        let line: [u8; 16] = rand::random();
        static_key.extend(line.iter().map(|byte| format!("{byte:02x}")));
        static_key.push('\n');
    }
    static_key.push_str("-----END OpenVPN Static key V1-----\n");

    let (listener, wire, port) = if behavior.tcp {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (WireListener::Tcp(listener), Wire::Tcp(None), port)
    } else {
        let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let port = socket.local_addr().unwrap().port();
        (
            WireListener::Udp(Arc::clone(&socket)),
            Wire::Udp(socket),
            port,
        )
    };
    let proto = if behavior.tcp { "tcp" } else { "udp" };
    let config = format!(
        "client\ndev tun\nproto {proto}\nremote 127.0.0.1 {port}\nnobind\nremote-cert-tls server\n\
         verify-x509-name server_test name\nauth-user-pass\n{}{}{}{}",
        pem_block("ca", &ca.pem()),
        pem_block("cert", &client_cert.pem()),
        pem_block("key", &client_key.serialize_pem()),
        pem_block("tls-crypt", &static_key),
    );

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        )
        .unwrap();
    let crypt = TlsCrypt::server(&StaticKey::parse(&static_key).unwrap());
    let sessions = Arc::new(AtomicUsize::new(0));
    let (incoming, packets) = mpsc::channel(1024);
    let reader = tokio::spawn(read_wire(listener, incoming));
    let task = tokio::spawn(serve(
        packets,
        wire,
        reader,
        Arc::new(tls),
        crypt,
        behavior,
        Arc::clone(&sessions),
    ));
    let path = std::env::temp_dir().join(format!("egrio-openvpn-{}.ovpn", rand::random::<u64>()));
    std::fs::write(&path, config).unwrap();
    TestServer {
        config: path.to_string_lossy().into_owned(),
        sessions,
        task,
    }
}

struct Session {
    client: SocketAddr,
    peer: [u8; 8],
    reliable: Reliable,
    tls: rustls::ServerConnection,
    plaintext: Vec<u8>,
    got_exchange: bool,
    refused: bool,
    keys: Option<DataKeys>,
}

async fn serve(
    mut packets: mpsc::Receiver<Incoming>,
    mut wire: Wire,
    reader: tokio::task::JoinHandle<()>,
    tls: Arc<rustls::ServerConfig>,
    crypt: TlsCrypt,
    behavior: Behavior,
    sessions: Arc<AtomicUsize>,
) {
    let mut wrap = Wrap::Crypt(crypt);
    let ours: [u8; 8] = rand::random();
    let mut session: Option<Session> = None;
    let (accept_tx, mut accept) = mpsc::unbounded_channel();
    let mut engine = TcpEngine::new(1500, accept_tx, Arc::new(AtomicUsize::new(0)), None);
    let wake = engine.wake();
    // The reader ends with the server.
    let _reader = AbortOnDrop(reader);
    loop {
        let now = Instant::now();
        while let Ok(stream) = accept.try_recv() {
            tokio::spawn(answer_tcp(stream));
        }
        engine.attend(now);
        engine.on_timers(now);
        let mut segments = Vec::new();
        engine.emit(now, usize::MAX, &mut |mut segment| {
            segment.finish_checksum();
            segments.push(segment.parts().flatten().copied().collect::<Vec<u8>>());
        });
        if let Some(state) = session.as_mut() {
            if let Some(keys) = state.keys.as_mut() {
                for packet in segments {
                    let sealed = keys.seal(Some(PEER_ID), &packet).unwrap();
                    wire.send(&sealed, state.client).await;
                }
            }
            for packet in transmit(&mut wrap, &ours, state, now) {
                wire.send(&packet, state.client).await;
            }
        }
        let deadline = engine
            .next_deadline()
            .unwrap_or(now + Duration::from_millis(50))
            .min(now + Duration::from_millis(50));
        let (packet, from) = tokio::select! {
            received = packets.recv() => match received {
                Some(Incoming::Packet(packet, from)) => (packet, from),
                Some(Incoming::Connection(write)) => {
                    wire = Wire::Tcp(Some(write));
                    continue;
                }
                None => return,
            },
            () = wake.notify.notified() => continue,
            () = tokio::time::sleep_until(deadline.into()) => continue,
        };
        let first = packet[0];
        if matches!(opcode(first), P_DATA_V1 | P_DATA_V2) {
            let Some(state) = session.as_mut() else {
                continue;
            };
            let Some(keys) = state.keys.as_mut() else {
                continue;
            };
            let Some(Payload::Ip(ip)) = keys.open(&packet) else {
                continue;
            };
            if behavior.ping_restart.is_some() {
                // A server gone silent: it takes nothing more.
                continue;
            }
            if let Some(reply) = answer_udp(&ip) {
                let sealed = keys.seal(Some(PEER_ID), &reply).unwrap();
                wire.send(&sealed, state.client).await;
            } else {
                engine.on_packet(
                    Bytes::from(ip),
                    ClientOwner::Known(None),
                    None,
                    Instant::now(),
                );
            }
            continue;
        }
        let Some((sender, plain)) = wrap.open(&packet) else {
            continue;
        };
        // A new session from the client replaces the old one.
        if opcode(first) == P_CONTROL_HARD_RESET_CLIENT_V2
            && session.as_ref().is_none_or(|state| state.peer != sender)
        {
            if let Some(delay) = behavior.delay {
                tokio::time::sleep(delay).await;
            }
            sessions.fetch_add(1, Ordering::SeqCst);
            let mut reliable = Reliable::new(Duration::from_secs(2));
            reliable.queue(P_CONTROL_HARD_RESET_SERVER_V2, Vec::new());
            session = Some(Session {
                client: from,
                peer: sender,
                reliable,
                tls: rustls::ServerConnection::new(tls.clone()).unwrap(),
                plaintext: Vec::new(),
                got_exchange: false,
                refused: false,
                keys: None,
            });
        }
        let Some(state) = session.as_mut() else {
            continue;
        };
        if sender != state.peer || key_id(first) != 0 {
            continue;
        }
        state.reliable.acknowledge(&plain.acks);
        let Some(id) = plain.message_id else {
            continue;
        };
        for (opcode, payload) in state.reliable.receive(id, opcode(first), plain.payload) {
            if opcode != P_CONTROL_V1 {
                continue;
            }
            let mut bytes = &payload[..];
            while !bytes.is_empty() {
                state.tls.read_tls(&mut bytes).unwrap();
                state.tls.process_new_packets().unwrap();
            }
            let mut chunk = [0_u8; 4096];
            while let Ok(read) = std::io::Read::read(&mut state.tls.reader(), &mut chunk) {
                if read == 0 {
                    break;
                }
                state.plaintext.extend_from_slice(&chunk[..read]);
            }
            handle_plaintext(state, &behavior);
            flush_tls(state);
        }
    }
}

/// Moves TLS records into control messages.
fn flush_tls(state: &mut Session) {
    let mut out = Vec::new();
    while state.tls.wants_write() {
        state.tls.write_tls(&mut out).unwrap();
    }
    for chunk in out.chunks(1100) {
        state.reliable.queue(P_CONTROL_V1, chunk.to_vec());
    }
}

fn string(bytes: &[u8], at: &mut usize) -> Option<String> {
    let length = usize::from(u16::from_be_bytes(
        bytes.get(*at..*at + 2)?.try_into().ok()?,
    ));
    let text = bytes.get(*at + 2..*at + 2 + length)?;
    *at += 2 + length;
    Some(
        String::from_utf8_lossy(text)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

fn handle_plaintext(state: &mut Session, behavior: &Behavior) {
    if !state.got_exchange {
        // u32 0, method 2, the client's 112 bytes of key source, then options,
        // username, password and peer info.
        let mut at = 4 + 1 + 48 + 32 + 32;
        let Some(_options) = string(&state.plaintext, &mut at) else {
            return;
        };
        let (Some(username), Some(password), Some(_peer_info)) = (
            string(&state.plaintext, &mut at),
            string(&state.plaintext, &mut at),
            string(&state.plaintext, &mut at),
        ) else {
            return;
        };
        state.plaintext.drain(..at);
        state.got_exchange = true;
        let mut exchange = vec![0, 0, 0, 0, 2];
        exchange.extend_from_slice(&rand::random::<[u8; 64]>());
        for text in ["V4,dev-type tun", "", "", ""] {
            if text.is_empty() {
                exchange.extend_from_slice(&[0, 0]);
            } else {
                exchange.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
                exchange.extend_from_slice(text.as_bytes());
                exchange.push(0);
            }
        }
        std::io::Write::write_all(&mut state.tls.writer(), &exchange).unwrap();
        state.refused = behavior.refuse || username != USERNAME || password != PASSWORD;
    }
    while let Some(end) = state.plaintext.iter().position(|&byte| byte == 0) {
        let message: Vec<u8> = state.plaintext.drain(..=end).collect();
        if message.starts_with(b"PUSH_REQUEST") {
            if state.refused {
                std::io::Write::write_all(&mut state.tls.writer(), b"AUTH_FAILED\0").unwrap();
                continue;
            }
            if state.keys.is_some() {
                continue;
            }
            let mut reply = format!(
                "PUSH_REPLY,dhcp-option DNS {SERVER_IP},topology subnet,ping 10,ifconfig {CLIENT_IP} 255.255.255.0,\
                 peer-id {PEER_ID},cipher AES-256-GCM,protocol-flags cc-exit tls-ekm"
            );
            if let Some(restart) = behavior.ping_restart {
                reply.push_str(&format!(",ping-restart {restart}"));
            }
            reply.push('\0');
            std::io::Write::write_all(&mut state.tls.writer(), reply.as_bytes()).unwrap();
            let material = state
                .tls
                .export_keying_material([0_u8; 256], b"EXPORTER-OpenVPN-datakeys", None)
                .unwrap();
            state.keys = Some(DataKeys::server(DataCipher::Aes256Gcm, &material, 0));
        }
    }
}

fn transmit(wrap: &mut Wrap, ours: &[u8; 8], state: &mut Session, now: Instant) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for (id, opcode, payload) in state.reliable.due(now) {
        let acks = state.reliable.take_acks(ACKS_WITH_MESSAGE);
        let plain = ControlPlain {
            acked_session: (!acks.is_empty()).then_some(state.peer),
            acks,
            message_id: Some(id),
            payload,
        };
        packets.push(wrap.seal(opcode, 0, ours, &plain));
    }
    while state.reliable.has_acks() {
        let plain = ControlPlain {
            acks: state.reliable.take_acks(ACKS_ALONE),
            acked_session: Some(state.peer),
            message_id: None,
            payload: Vec::new(),
        };
        packets.push(wrap.seal(P_ACK_V1, 0, ours, &plain));
    }
    packets
}

/// The echo or DNS answer to a UDP packet for the server; `None` for any
/// other packet.
fn answer_udp(ip: &[u8]) -> Option<Vec<u8>> {
    let (from, to, payload) = udp_endpoints(ip)?;
    let payload = &ip[payload];
    let reply = if to.port() == 53 {
        let request = crate::dns::wire::decode(payload).ok()?;
        let mut answer = hickory_proto::op::Message::new();
        answer
            .set_id(request.id())
            .set_message_type(hickory_proto::op::MessageType::Response)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .add_queries(request.queries().to_vec());
        let query = request.queries().first()?;
        if query.name().to_ascii().trim_end_matches('.') == "intranet.test"
            && query.query_type() == hickory_proto::rr::RecordType::A
        {
            answer.add_answer(hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                60,
                hickory_proto::rr::RData::A(SERVER_IP.into()),
            ));
        } else {
            answer.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
        }
        crate::dns::wire::encode(&answer).ok()?
    } else {
        payload.to_vec()
    };
    build_udp_packet(to.ip(), from.ip(), to.port(), from.port(), &reply).ok()
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Port 3128 is an HTTP CONNECT proxy whose tunnels echo; every other port
/// echoes.
async fn answer_tcp(mut stream: CapturedTcpStream) {
    if stream.target_addr().port() == 3128 {
        let Ok((header, rest)) = crate::protocols::http::read_http_header(&mut stream).await else {
            return;
        };
        if !header.starts_with("CONNECT ") {
            return;
        }
        if stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .is_err()
            || stream.write_all(&rest).await.is_err()
        {
            return;
        }
    }
    echo(stream).await;
}

async fn echo(mut stream: CapturedTcpStream) {
    let mut buffer = vec![0_u8; 64 * 1024];
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
    let _ = stream.shutdown().await;
}
