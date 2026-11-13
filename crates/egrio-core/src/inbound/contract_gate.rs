//! The inbound contract's loopback dial-pair gate.
//!
//! An encrypted wire protocol defined entirely in this test module — no
//! dispatcher file can name it — proves inbound-contract symmetry: its
//! `InboundAcceptor` server half and `OutboundConnector` client half dial
//! each other in-process, and the payload rides byte-exact through the
//! unmodified `dispatch_accepted_stream` → Router → DIRECT pipeline. The
//! UDP arm proves the user-keyed flow table isolates two authenticated
//! connections that claim identical `(source, target)` flows.
//!
//! This is the inbound dual of `outbound/mod.rs`'s protocol-vocabulary gate: there a
//! foreign connector rode the unmodified dispatcher; here a foreign
//! acceptor does.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{timeout, Duration};

use crate::attribution::ClientOwner;
use crate::egress::NativeCoreEgressConfig;
use crate::inbound::acceptor::{
    AcceptedDatagramFace, AcceptedStream, BoxedInboundStream, InboundAcceptor, InboundDatagram,
    InboundDatagramReceiver, InboundDatagramResponder, InboundFuture, InboundReplyPlan,
    InboundSession,
};
use crate::inbound::dispatch::{dispatch_accepted_datagrams, dispatch_accepted_stream};
use crate::outbound::{
    write_early_data, BoxedOutboundStream, OutboundConnector, OutboundError, OutboundFuture,
    OutboundResultExt, OutboundStage,
};
use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;

/// Constant-mask stream cipher standing in for a real AEAD: symmetric and
/// position-independent, so the handshake header and the relayed body share
/// one keystream and encode == decode. A real protocol swaps this for its
/// framed AEAD; the contract shape is identical.
const GATE_MASK: u8 = 0x3c;

fn mask(bytes: &mut [u8]) {
    for byte in bytes {
        *byte ^= GATE_MASK;
    }
}

/// A duplex stream that "encrypts" every byte crossing it. The dispatcher
/// relays through this exactly like a plaintext socket — proof that an
/// encrypted acceptor plugs into the unmodified relay stage.
struct GateCipherStream<S> {
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for GateCipherStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let start = before;
            let filled = buf.filled_mut();
            mask(&mut filled[start..]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GateCipherStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut masked = buf.to_vec();
        mask(&mut masked);
        Pin::new(&mut self.get_mut().inner).poll_write(cx, &masked)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---- The foreign encrypted stream protocol: client sends a masked header
// `[user_len][user][host_len][host][port:u16]`, then a ciphered body.

async fn read_masked_byte(io: &mut BoxedInboundStream) -> Result<u8, String> {
    let mut byte = [0_u8; 1];
    io.read_exact(&mut byte)
        .await
        .map_err(|error| error.to_string())?;
    Ok(byte[0] ^ GATE_MASK)
}

async fn read_masked_vec(io: &mut BoxedInboundStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; len];
    io.read_exact(&mut buffer)
        .await
        .map_err(|error| error.to_string())?;
    mask(&mut buffer);
    Ok(buffer)
}

#[derive(Debug)]
struct GateStreamAcceptor;

impl InboundAcceptor for GateStreamAcceptor {
    fn accept(&self, mut io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        Box::pin(async move {
            let user_len = read_masked_byte(&mut io).await? as usize;
            let user = String::from_utf8(read_masked_vec(&mut io, user_len).await?)
                .map_err(|error| error.to_string())?;
            let host_len = read_masked_byte(&mut io).await? as usize;
            let host = String::from_utf8(read_masked_vec(&mut io, host_len).await?)
                .map_err(|error| error.to_string())?;
            let port_hi = read_masked_byte(&mut io).await?;
            let port_lo = read_masked_byte(&mut io).await?;
            let port = u16::from_be_bytes([port_hi, port_lo]);

            Ok(InboundSession::Stream(AcceptedStream {
                inbound: "contract-gate",
                user: Some(Arc::from(user.as_str())),
                process: ClientOwner::Known(None),
                target: ConnectTarget { host, port },
                io: Box::new(GateCipherStream { inner: io }),
                // Encrypted protocol: no plaintext replies, failure is a
                // dropped stream. Every reply-plan field stays empty.
                replies: InboundReplyPlan::default(),
                reset: None,
            }))
        })
    }
}

/// The matching client half: dials the gate server, sends the masked
/// header for `target` under its configured user, and returns the ciphered
/// duplex stream.
#[derive(Debug)]
struct GateStreamConnector {
    server_host: String,
    server_port: u16,
    user: String,
}

impl OutboundConnector for GateStreamConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a crate::egress::EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let mut tcp = egress
                .connect_tcp_host(&self.server_host, self.server_port, "contract gate server")
                .await
                .map_err(OutboundError::hop_dial)?;
            let mut header = Vec::new();
            header.push(self.user.len() as u8);
            header.extend_from_slice(self.user.as_bytes());
            let host = target.host.as_bytes();
            header.push(host.len() as u8);
            header.extend_from_slice(host);
            header.extend_from_slice(&target.port.to_be_bytes());
            mask(&mut header);
            tcp.write_all(&header).await.at(OutboundStage::HopConnect)?;

            let mut stream = GateCipherStream { inner: tcp };
            // Fold any sniffed prefix into the ciphered body, exactly as a
            // real early-data protocol would.
            write_early_data(&mut stream, early_data)
                .await
                .at(OutboundStage::HopConnect)?;
            Ok(Box::new(stream) as BoxedOutboundStream)
        })
    }
}

fn match_direct_runtime() -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("contract-gate");
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

/// The server assembly: accept gate connections, run the foreign acceptor,
/// and drive each accepted stream through the unmodified dispatcher.
async fn spawn_gate_server(runtime: NativeCoreRuntime) -> SocketAddr {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind gate server");
    let addr = listener.local_addr().expect("gate server addr");
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let runtime = runtime.clone();
            let source = client.peer_addr().ok().map(|addr| addr.to_string());
            tokio::spawn(async move {
                let session = match GateStreamAcceptor.accept(Box::new(client)).await {
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
async fn foreign_encrypted_acceptor_relays_stream_through_unmodified_dispatcher() {
    let echo_addr = spawn_tcp_echo().await;
    let server_runtime = match_direct_runtime();
    let server_addr = spawn_gate_server(server_runtime.clone()).await;

    let SocketAddr::V4(server_v4) = server_addr else {
        panic!("IPv4 gate server expected");
    };
    let connector = GateStreamConnector {
        server_host: server_v4.ip().to_string(),
        server_port: server_v4.port(),
        user: "alice".into(),
    };
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };

    // The client half needs an egress to dial the gate server; a throwaway
    // runtime supplies one (the client is not the system under test).
    let client_runtime = match_direct_runtime();
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(client_runtime.egress(), &echo_target, b""),
    )
    .await
    .expect("gate dial timeout")
    .expect("gate dial");

    let payload = b"ping-through-the-inbound-pipeline";
    stream.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&echoed, payload, "payload survived the encrypted pipeline");

    // Metadata{user} reached the ledger: the authenticated identity the
    // acceptor proved is visible on the live session.
    let mut authenticated_user = None;
    for _ in 0..50 {
        if let Some(snapshot) = server_runtime
            .session_registry()
            .snapshot()
            .into_iter()
            .find(|snapshot| snapshot.inbound == "contract-gate")
        {
            authenticated_user = snapshot.user;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(authenticated_user.as_deref(), Some("alice"));
}

// ---- The UDP arm: a scripted datagram face standing in for one
// authenticated connection's deframed flows.

/// Shared log of `(client flow, response payload)` a responder recorded, so
/// the gate can assert each flow's echo came back to the right source.
type ResponderLog = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

struct ScriptedReceiver {
    items: VecDeque<InboundDatagram>,
}

impl InboundDatagramReceiver for ScriptedReceiver {
    fn next(&mut self) -> InboundFuture<'_, Option<InboundDatagram>> {
        match self.items.pop_front() {
            Some(item) => Box::pin(std::future::ready(Ok(Some(item)))),
            // Park after the scripted flows, like a live connection: the
            // no-wait pump's background drain keeps delivering responses, and
            // the gate stops the pump once it has recorded them.
            None => Box::pin(std::future::pending()),
        }
    }
}

struct RecordingResponder {
    seen: ResponderLog,
}

impl InboundDatagramResponder for RecordingResponder {
    fn respond<'a>(
        &'a self,
        source: SocketAddr,
        _from: &'a ConnectTarget,
        payload: &'a [u8],
    ) -> InboundFuture<'a, ()> {
        self.seen
            .lock()
            .expect("responder log")
            .push((source, payload.to_vec()));
        Box::pin(std::future::ready(Ok(())))
    }
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

fn gate_datagram(source: SocketAddr, target: SocketAddr, payload: &[u8]) -> InboundDatagram {
    InboundDatagram {
        source,
        target: ConnectTarget {
            host: target.ip().to_string(),
            port: target.port(),
        },
        payload: payload.to_vec(),
    }
}

/// A datagram-capable acceptor whose `accept` yields the multi-flow face
/// arm of `InboundSession` — the shape a real Shadowsocks acceptor takes.
/// It ignores the carrier IO and replays a
/// scripted flow set, which is all the gate needs to exercise the enum's
/// datagram arm and the user-keyed flow table.
#[derive(Debug)]
struct GateDatagramAcceptor {
    user: String,
    script: Mutex<Option<Vec<InboundDatagram>>>,
    seen: ResponderLog,
}

impl InboundAcceptor for GateDatagramAcceptor {
    fn accept(&self, _io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        let datagrams = self
            .script
            .lock()
            .expect("gate script")
            .take()
            .unwrap_or_default();
        let face = AcceptedDatagramFace {
            user: Some(Arc::from(self.user.as_str())),
            receiver: Box::new(ScriptedReceiver {
                items: datagrams.into(),
            }),
            responder: Box::new(RecordingResponder {
                seen: Arc::clone(&self.seen),
            }),
        };
        Box::pin(std::future::ready(Ok(InboundSession::Datagrams(face))))
    }
}

/// Accepts one connection through the datagram acceptor and drives whatever
/// `InboundSession` arm it produced — the exact enum match a real listener
/// runs. Returns the responder log and the live pump, so the caller decides
/// when the face ends: ending it reclaims the face's UDP sessions, so a caller
/// inspecting the session table must hold the face open until it has looked.
async fn pump_face(
    runtime: &NativeCoreRuntime,
    user: &str,
    datagrams: Vec<InboundDatagram>,
) -> (ResponderLog, LiveFace) {
    let expected = datagrams.len();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let acceptor = GateDatagramAcceptor {
        user: user.into(),
        script: Mutex::new(Some(datagrams)),
        seen: Arc::clone(&seen),
    };
    // A throwaway carrier: the datagram acceptor does not read it.
    let (_client, server) = tokio::io::duplex(64);
    let session = acceptor
        .accept(Box::new(server))
        .await
        .expect("datagram acceptor");
    let InboundSession::Datagrams(face) = session else {
        panic!("datagram acceptor yielded a stream");
    };
    // The no-wait pump enqueues sends and delivers responses through its
    // background drain, and the scripted receiver parks after its flows, so the
    // pump runs for the connection's life. Drive it in the background, wait for
    // the scripted flows' echoes to be recorded, then stop it.
    let pump = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            let _ = dispatch_accepted_datagrams(&runtime, face).await;
        })
    };
    for _ in 0..250 {
        if seen.lock().expect("responder log").len() >= expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (seen, LiveFace(pump))
}

/// A running face pump. Dropping it ends the face, which reclaims that face's
/// UDP sessions.
struct LiveFace(tokio::task::JoinHandle<()>);

impl Drop for LiveFace {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn foreign_datagram_face_isolates_flows_by_user() {
    let echo_addr = spawn_udp_echo().await;
    let runtime = match_direct_runtime();

    // Two client flows behind one address, plus a second target flow, all
    // over the single authenticated "alice" connection.
    let flow_a: SocketAddr = "10.0.0.1:40000".parse().expect("flow a");
    let flow_b: SocketAddr = "10.0.0.2:40000".parse().expect("flow b");
    let (alice_seen, alice_face) = pump_face(
        &runtime,
        "alice",
        vec![
            gate_datagram(flow_a, echo_addr, b"alice-a"),
            gate_datagram(flow_b, echo_addr, b"alice-b"),
        ],
    )
    .await;

    // A second authenticated connection ("bob") reuses alice's flow_a
    // (source, target) exactly — the user key must keep them apart.
    let (bob_seen, bob_face) = pump_face(
        &runtime,
        "bob",
        vec![gate_datagram(flow_a, echo_addr, b"bob-a")],
    )
    .await;

    let alice_seen = alice_seen.lock().expect("alice log").clone();
    assert!(alice_seen.contains(&(flow_a, b"alice-a".to_vec())));
    assert!(alice_seen.contains(&(flow_b, b"alice-b".to_vec())));
    let bob_seen = bob_seen.lock().expect("bob log").clone();
    assert_eq!(bob_seen, vec![(flow_a, b"bob-a".to_vec())]);

    // Three distinct flow sessions: (alice, flow_a), (alice, flow_b),
    // (bob, flow_a). The two flow_a sessions share (source, target) and are
    // told apart only by the user key.
    let sessions = runtime.udp_sessions().snapshot_for_test();
    let echo_target = ConnectTarget {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
    };
    let flow_a_users: Vec<Option<String>> = sessions
        .iter()
        .filter(|session| session.key.source == flow_a && session.target == echo_target)
        .map(|session| session.key.user.as_deref().map(str::to_string))
        .collect();
    assert_eq!(flow_a_users.len(), 2, "user key split the shared flow");
    assert!(flow_a_users.contains(&Some("alice".to_string())));
    assert!(flow_a_users.contains(&Some("bob".to_string())));
    assert_eq!(sessions.len(), 3, "three isolated flow sessions total");

    // Ending a face reclaims exactly its own flows: alice's two go, bob's one
    // stays. Nothing else would reclaim them — flow ids embed a monotonic face
    // id, so a later connection can never drain a dead face's sessions.
    drop(alice_face);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_alice = runtime.udp_sessions().snapshot_for_test();
    assert_eq!(
        after_alice.len(),
        1,
        "alice's flows are reclaimed, bob's survives"
    );
    assert_eq!(after_alice[0].key.user.as_deref(), Some("bob"));

    drop(bob_face);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        runtime.udp_sessions().snapshot_for_test().is_empty(),
        "the last face's flows are reclaimed too"
    );
}
