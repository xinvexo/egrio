//! The Hysteria2 server half: the mirror of the
//! `hysteria2` connector. Hysteria2's transport is a QUIC connection that
//! multiplexes many proxied-TCP streams (and, later, UDP flows), so — unlike a
//! byte-stream protocol — the "acceptor" is not an [`InboundAcceptor`]: it is a
//! QUIC connection server that authenticates once over HTTP/3 and then drives
//! one dispatch pipeline per accepted bidirectional stream.
//!
//! Auth and raw streams coexist on one connection by riding quinn's separate
//! accept queues: HTTP/3's control/QPACK streams are unidirectional and stay
//! with the h3 layer, while Hysteria2's proxied-TCP streams are the
//! bidirectional ones this module takes with `accept_bi` — the exact mirror of
//! how the in-tree client keeps its h3 driver alive alongside raw `open_bi`.
//!
//! Server-only (behind the `server` feature): it terminates TLS with the
//! certificate subsystem, which a client build never links.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::codec::{
    get_varint, put_varint, random_padding, send_udp_message, Hysteria2UdpDefragger,
    Hysteria2UdpMessage, AUTH_OK_STATUS, HYSTERIA2_QUEUED_DATAGRAMS,
    HYSTERIA2_TCP_REQUEST_FRAME_TYPE, MAX_DATAGRAM_FRAME_SIZE, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH, TCP_PADDING_MAX, TCP_PADDING_MIN,
};
use super::turns::{SendTurns, TurnSend};
use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{
    AcceptedDatagramFace, AcceptedStream, InboundDatagram, InboundDatagramReceiver,
    InboundDatagramResponder, InboundFuture, InboundReplyPlan,
};
use crate::inbound::dispatch::{dispatch_accepted_datagrams, dispatch_accepted_stream};
#[cfg(not(test))]
use crate::inbound::listener::INBOUND_HANDSHAKE_TIMEOUT;
use crate::runtime::NativeCoreRuntime;
use crate::target::{parse_connect_authority, ConnectTarget};
use crate::NativeCoreDevice;

/// QUIC idle timeout for a served connection (the client keep-alives well
/// inside it).
const HYSTERIA2_SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-connection auth budget: a peer that opens QUIC but never completes the
/// HTTP/3 auth request is dropped here instead of pinning an accept task.
const HYSTERIA2_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HYSTERIA2_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
/// What a client's connection may have in flight once it is a user's: the
/// window has to cover the bandwidth-delay product of everything that client
/// proxies, since it all rides this one connection (20 MiB is a gigabit at
/// 160 ms), and it mirrors the connector's own.
const HYSTERIA2_CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
/// And what it may have in flight before it has authenticated. The windows
/// are not a promise the handshake makes: quinn buffers what a peer sends
/// whether or not the application has accepted the stream, and nothing here
/// accepts a stream before auth, so the window is simply what an attempt can
/// park on the host -- a public port must not let that be the tunnel's 20
/// MiB apiece. The auth exchange is one HTTP/3 request with no body, so this
/// is a hundred times what it needs; the tunnel's window is granted the
/// moment the credential matches.
const HYSTERIA2_UNAUTHENTICATED_RECEIVE_WINDOW: u32 = 256 * 1024;
/// Proxied-TCP streams one connection may have open at once. Each one is a
/// client TCP connection, and a client multiplexes every flow it proxies onto
/// a single QUIC connection, so this has to cover what one client can hold at
/// once -- a captured client's engine allows a thousand flows. Below that a
/// busy client's stream opens would wait on QUIC flow control; above it one
/// connection could park more tasks than any client can use. Quinn's default
/// is a hundred, which is a throttle, not a bound. What a parked stream costs
/// is bounded by the request budget and the connection's receive window.
const HYSTERIA2_MAX_PROXIED_STREAMS: u32 = 1024;
/// QUIC connections one inbound serves at once. A connection here is a
/// client, not a flow: a client multiplexes every flow it proxies onto one
/// connection, so this bounds the clients a node holds -- and with them the
/// receive windows, datagram buffers and stream credit each one carries.
/// The attempt that finds the inbound full is refused; nothing being served
/// is closed to make room for it.
///
/// It is one number, not a share for attempts and a share for users: every
/// connection is unauthenticated when it needs its place, so holding places
/// back for authenticated users would only shrink what a new user can take,
/// and a connection already served never needs a place again. So a flood of
/// attempts keeps new connections out and leaves the served ones untouched,
/// which is what a public port can promise.
const HYSTERIA2_MAX_CONNECTIONS: usize = 256;
/// How long an admitted attempt has to finish its QUIC handshake before the
/// inbound takes its place back. A client is one round trip away, so this is
/// really the budget for an attempt that stops there -- and a refused dial
/// leaves one behind: a client's dial arrives as more than one Initial
/// packet, and refusing the first statelessly leaves the endpoint no state
/// for the rest, so the next packet of the same dial becomes an attempt of
/// its own. If a place frees in between, that attempt is admitted with no
/// client left to finish it, and without a budget it would hold the place
/// for the whole idle timeout. Tests shrink it, because what it bounds is
/// only visible once it runs out.
#[cfg(not(test))]
const HYSTERIA2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const HYSTERIA2_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
/// The budget one proxied stream's request frame gets. It is the listener's
/// handshake budget: these streams never pass that wrap, so they carry it
/// here. Tests shrink it, because what it bounds is only visible once it runs
/// out.
#[cfg(not(test))]
const HYSTERIA2_TCP_REQUEST_TIMEOUT: Duration = INBOUND_HANDSHAKE_TIMEOUT;
#[cfg(test)]
const HYSTERIA2_TCP_REQUEST_TIMEOUT: Duration = Duration::from_millis(250);

/// The static user table the Hysteria2 acceptor authenticates against: each
/// user is a `(name, auth-string)` the operator
/// pre-shares; the client presents the auth string in the `Hysteria-Auth`
/// HTTP/3 header.
pub(crate) struct Hysteria2UserTable {
    users: Vec<(Arc<str>, String)>,
}

impl Hysteria2UserTable {
    pub(crate) fn new() -> Self {
        Self { users: Vec::new() }
    }

    pub(crate) fn with_user(mut self, name: impl Into<Arc<str>>, auth: &str) -> Self {
        self.users.push((name.into(), auth.to_string()));
        self
    }

    /// The user whose auth string the peer presented, or `None` if none match.
    ///
    /// An empty credential never authenticates, even against a user
    /// misconfigured with an empty auth string: a client that sends no
    /// `Hysteria-Auth` header normalizes to `""`, so matching it would
    /// authenticate everyone. The empty string is not a credential.
    fn authenticate(&self, presented: &str) -> Option<Arc<str>> {
        if presented.is_empty() {
            return None;
        }
        self.users
            .iter()
            .find(|(_, auth)| auth == presented)
            .map(|(name, _)| Arc::clone(name))
    }
}

/// One Hysteria2 QUIC/H3 inbound: a server config, its user table, and the
/// count of connections that reached auth but presented no valid credential.
pub(crate) struct Hysteria2Acceptor {
    server_config: quinn::ServerConfig,
    users: Arc<Hysteria2UserTable>,
    auth_failures: Arc<AtomicU64>,
    max_connections: usize,
}

impl Hysteria2Acceptor {
    pub(crate) fn new(
        tls: Arc<rustls::ServerConfig>,
        users: Hysteria2UserTable,
    ) -> Result<Self, String> {
        let quic_crypto = QuicServerConfig::try_from(tls)
            .map_err(|error| format!("failed to build Hysteria2 QUIC server config: {error}"))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        server_config.transport_config(Arc::new(transport_config()));
        Ok(Self {
            server_config,
            users: Arc::new(users),
            auth_failures: Arc::new(AtomicU64::new(0)),
            max_connections: HYSTERIA2_MAX_CONNECTIONS,
        })
    }

    /// The same acceptor serving at most `connections` at once, for a test
    /// that fills it.
    #[cfg(test)]
    pub(crate) fn serving_at_most(mut self, connections: usize) -> Self {
        self.max_connections = connections;
        self
    }

    /// A shared handle to the auth-failure counter — connections that
    /// authenticated over HTTP/3 with no matching credential. A composing
    /// listener surfaces it on its control surface without holding the whole
    /// acceptor, so a host can alarm on credential probing.
    pub(crate) fn auth_failures_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.auth_failures)
    }

    /// Binds a QUIC server endpoint for this acceptor at `addr`.
    pub(crate) fn bind(&self, addr: std::net::SocketAddr) -> Result<Endpoint, String> {
        let failed = |error: io::Error| format!("failed to bind Hysteria2 QUIC endpoint: {error}");
        let socket = std::net::UdpSocket::bind(addr).map_err(failed)?;
        crate::egress::size_udp_socket_buffers(socket2::SockRef::from(&socket))?;
        Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(self.server_config.clone()),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(failed)
    }

    /// Accepts connections until `endpoint` closes, serving each on its own
    /// task through the unmodified dispatcher. An attempt that arrives with
    /// the inbound full is refused (see [`HYSTERIA2_MAX_CONNECTIONS`]).
    pub(crate) async fn serve(&self, endpoint: Endpoint, device: NativeCoreDevice) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    // Take out what finished first: the count is the live one
                    // only once it is reaped, and this branch can win the
                    // select many times in a row.
                    while connections.try_join_next().is_some() {}
                    if connections.len() >= self.max_connections {
                        // CONNECTION_REFUSED (RFC 9000 section 20.1), so a
                        // client fails now instead of waiting out its own
                        // handshake. The reply is one small Initial packet
                        // against the client's padded one, so refusing a
                        // source that has not proved its address amplifies
                        // nothing.
                        incoming.refuse();
                        continue;
                    }
                    let users = Arc::clone(&self.users);
                    let auth_failures = Arc::clone(&self.auth_failures);
                    connections.spawn(device.tracked_session(move |runtime| async move {
                        let cancel = runtime.connection_cancellation();
                        let handshake = timeout(HYSTERIA2_HANDSHAKE_TIMEOUT, incoming);
                        let connection = tokio::select! {
                            biased;
                            _ = cancel.cancelled() => return,
                            handshaken = handshake => match handshaken {
                                Ok(Ok(connection)) => connection,
                                Ok(Err(_)) | Err(_) => return,
                            },
                        };
                        let _ = serve_connection(connection, users, auth_failures, runtime).await;
                    }));
                }
            }
        }
        while connections.join_next().await.is_some() {}
        endpoint.wait_idle().await;
    }
}

impl fmt::Debug for Hysteria2Acceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2Acceptor")
            .field("users", &self.users.users.len())
            .finish_non_exhaustive()
    }
}

fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(HYSTERIA2_SERVER_IDLE_TIMEOUT).expect("valid idle timeout"),
    ));
    transport.stream_receive_window(VarInt::from_u32(HYSTERIA2_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(HYSTERIA2_UNAUTHENTICATED_RECEIVE_WINDOW));
    transport
        .datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE * HYSTERIA2_QUEUED_DATAGRAMS));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE * HYSTERIA2_QUEUED_DATAGRAMS);
    transport.max_concurrent_bidi_streams(VarInt::from_u32(HYSTERIA2_MAX_PROXIED_STREAMS));
    transport
}

/// Keeps the authenticated connection's HTTP/3 control streams open for its
/// lifetime: dropping the h3 connection would FIN the critical control stream
/// (RFC 9114 §6.2.1) and tear the QUIC connection down under the proxied
/// streams. We never call `accept` on it again, so it does not compete for the
/// bidirectional streams `serve_connection` relays.
struct H3Keepalive {
    _connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
}

async fn serve_connection(
    connection: Connection,
    users: Arc<Hysteria2UserTable>,
    auth_failures: Arc<AtomicU64>,
    runtime: NativeCoreRuntime,
) -> Result<(), String> {
    let cancel = runtime.connection_cancellation();
    let authentication = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            connection.close(VarInt::from_u32(0), b"runtime switched");
            return Err("Hysteria2 connection closed by runtime switch".into());
        },
        result = timeout(HYSTERIA2_AUTH_TIMEOUT, authenticate(&connection, &users)) => result,
    };
    let (user, h3_keepalive) = match authentication {
        Ok(Ok(Some(AuthOutcome::Authenticated { user, keepalive }))) => (user, keepalive),
        Ok(Ok(Some(AuthOutcome::Rejected { keepalive }))) => {
            auth_failures.fetch_add(1, Ordering::Relaxed);
            // The masquerade 404 is written but not yet flushed. Keep the
            // connection and its HTTP/3 control streams alive so it reaches
            // the peer exactly as an ordinary web server's response would,
            // then wind down on the idle timeout. Dropping or `close()`ing
            // now would abandon the buffered response — quinn: "closing the
            // connection immediately abandons efforts to deliver data to the
            // peer" — a truncation an active prober could fingerprint.
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    connection.close(VarInt::from_u32(0), b"runtime switched");
                },
                _ = connection.closed() => {},
            }
            drop(keepalive);
            return Err("hysteria2: no user credential authenticated the connection".into());
        }
        Ok(Ok(None)) => {
            auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err("hysteria2: connection sent no auth request".into());
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err("hysteria2: auth handshake timed out".into()),
    };
    // A user's connection now, so it gets a user's window: the peer is told
    // by MAX_DATA, which goes out before any proxied stream is accepted.
    connection.set_receive_window(VarInt::from_u32(HYSTERIA2_CONNECTION_RECEIVE_WINDOW));
    let source = connection.remote_address().to_string();

    // This connection's UDP flows: one datagram face pumps them all through
    // the UDP dispatcher for the connection's lifetime. It ends when the
    // connection closes and `read_datagram` errors.
    let mut tasks = JoinSet::new();
    {
        let connection = connection.clone();
        let user = Arc::clone(&user);
        let tracker = runtime.task_tracker().clone();
        let runtime = runtime.clone();
        tasks.spawn(tracker.track_future(async move {
            let face = AcceptedDatagramFace {
                user: Some(user),
                receiver: Box::new(Hysteria2DatagramReceiver {
                    connection: connection.clone(),
                    defragger: Hysteria2UdpDefragger::default(),
                }),
                responder: Box::new(Hysteria2DatagramResponder {
                    connection,
                    next_packet_id: AtomicU16::new(0),
                }),
            };
            let _ = dispatch_accepted_datagrams(&runtime, face).await;
        }));
    }

    // Each proxied-TCP request is one bidirectional QUIC stream; the h3
    // keepalive stays in scope so the control streams outlive them all.
    let turns = Arc::new(SendTurns::default());
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let send = turns.stream(send);
                let user = Arc::clone(&user);
                let source = source.clone();
                let tracker = runtime.task_tracker().clone();
                let runtime = runtime.clone();
                tasks.spawn(tracker.track_future(async move {
                    let _ = serve_tcp_stream(send, recv, user, source, &runtime).await;
                }));
            }
        }
    }
    connection.close(VarInt::from_u32(0), b"connection ended");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(h3_keepalive);
    Ok(())
}

/// The outcome of the HTTP/3 auth exchange for a connection that sent a
/// request: a valid credential (proceed to relay) or a rejected one (the
/// masquerade response has already been written). Both carry the keepalive
/// holding the connection's HTTP/3 control streams open — on the reject path so
/// the masquerade flushes exactly as an ordinary web server's response would.
enum AuthOutcome {
    Authenticated {
        user: Arc<str>,
        keepalive: H3Keepalive,
    },
    Rejected {
        keepalive: H3Keepalive,
    },
}

/// Runs the HTTP/3 auth exchange: read the one request and match its
/// `Hysteria-Auth` header against the user table. A match answers 233 with
/// `Hysteria-UDP: true` (the UDP relay this acceptor drives) and
/// `Hysteria-CC-RX: 0`, the protocol's "no receive limit", so a client that
/// configured an upload rate sends at it; a miss answers as
/// an ordinary HTTP/3 web server would — a plain 404 carrying no `Hysteria-*`
/// header — so an active prober cannot fingerprint the server on the failure
/// path. This mirrors the reference server, whose default
/// masquerade is Go's `http.NotFound` (apernet/hysteria `core/server/server.go`:
/// auth failure -> `masqHandler` -> `http.NotFound`). `Ok(None)` is a peer that
/// completed the HTTP/3 setup but sent no request.
async fn authenticate(
    connection: &Connection,
    users: &Hysteria2UserTable,
) -> Result<Option<AuthOutcome>, String> {
    let mut h3_connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|error| format!("hysteria2 HTTP/3 setup failed: {error}"))?;
    let resolver = match h3_connection
        .accept()
        .await
        .map_err(|error| format!("hysteria2 HTTP/3 accept failed: {error}"))?
    {
        Some(resolver) => resolver,
        None => return Ok(None),
    };
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| format!("hysteria2 HTTP/3 request failed: {error}"))?;

    let presented = request
        .headers()
        .get("Hysteria-Auth")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    match users.authenticate(presented) {
        Some(user) => {
            let response = http::Response::builder()
                .status(AUTH_OK_STATUS)
                .header("Hysteria-UDP", "true")
                .header("Hysteria-CC-RX", "0")
                .body(())
                .map_err(|error| format!("hysteria2 auth response build failed: {error}"))?;
            stream
                .send_response(response)
                .await
                .map_err(|error| format!("hysteria2 auth response send failed: {error}"))?;
            stream
                .finish()
                .await
                .map_err(|error| format!("hysteria2 auth response finish failed: {error}"))?;
            Ok(Some(AuthOutcome::Authenticated {
                user,
                keepalive: H3Keepalive {
                    _connection: h3_connection,
                },
            }))
        }
        None => {
            let (response, body) = masquerade_rejection_response()?;
            stream
                .send_response(response)
                .await
                .map_err(|error| format!("hysteria2 masquerade response send failed: {error}"))?;
            stream
                .send_data(body)
                .await
                .map_err(|error| format!("hysteria2 masquerade body send failed: {error}"))?;
            stream
                .finish()
                .await
                .map_err(|error| format!("hysteria2 masquerade response finish failed: {error}"))?;
            Ok(Some(AuthOutcome::Rejected {
                keepalive: H3Keepalive {
                    _connection: h3_connection,
                },
            }))
        }
    }
}

/// The auth-failure masquerade: the ordinary-web-server response the reference
/// hysteria2 server returns by default on a bad/absent credential — Go's
/// `http.NotFound`, i.e. `net/http`'s `Error` (apernet/hysteria
/// `core/server/server.go` -> default `masqHandler`): a 404 with a `text/plain`
/// body, the `nosniff` guard, and — the point — no `Hysteria-*` header, so the
/// failure path is indistinguishable from a plain HTTP/3 site. Returns the
/// response head and its body; h3 sends them in separate calls.
fn masquerade_rejection_response() -> Result<(http::Response<()>, Bytes), String> {
    let body = Bytes::from_static(b"404 page not found\n");
    let response = http::Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(|error| format!("hysteria2 masquerade response build failed: {error}"))?;
    Ok((response, body))
}

async fn serve_tcp_stream(
    mut send: TurnSend,
    mut recv: RecvStream,
    user: Arc<str>,
    source: String,
    runtime: &NativeCoreRuntime,
) -> Result<(), String> {
    // This acceptor's streams never pass the listener's handshake wrap (it
    // serves its own QUIC endpoint), so the request frame carries that budget
    // here: a client that opens a stream and writes nothing would otherwise
    // park a task, a QUIC stream and a place in the connection's stream
    // allowance until it disconnected.
    let (address, leftover) = timeout(HYSTERIA2_TCP_REQUEST_TIMEOUT, read_tcp_request(&mut recv))
        .await
        .map_err(|_| "hysteria2: TCP request frame timed out".to_string())??;
    let target = parse_connect_authority(&address)?;
    // The TCP response is the "tunnel established" signal the client strips
    // before relay bytes; send it eagerly (the reference client reads it even
    // in fast-open mode).
    send.write_all(&encode_tcp_response(true))
        .await
        .map_err(|error| format!("hysteria2 TCP response send failed: {error}"))?;

    let accepted = AcceptedStream {
        inbound: "hysteria2",
        user: Some(user),
        process: ClientOwner::Known(None),
        target,
        io: Box::new(Hysteria2ServerStream::new(send, recv, leftover)),
        // Encrypted transport: the pipeline writes no plaintext replies (the
        // TCP response above is the protocol's own, already sent).
        replies: InboundReplyPlan::default(),
        reset: None,
    };
    dispatch_accepted_stream(runtime, Some(source), accepted)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Reads the proxied-TCP request frame off the QUIC stream, returning the
/// target authority and any relay bytes that trailed it (fast-open payload).
async fn read_tcp_request(recv: &mut RecvStream) -> Result<(String, Vec<u8>), String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        match parse_tcp_request(&buffer) {
            TcpRequestParse::Done { address, consumed } => {
                return Ok((address, buffer[consumed..].to_vec()));
            }
            TcpRequestParse::Invalid => {
                return Err("hysteria2: malformed TCP request frame".into());
            }
            TcpRequestParse::NeedMore => {
                match recv
                    .read(&mut chunk)
                    .await
                    .map_err(|error| format!("hysteria2 TCP request read failed: {error}"))?
                {
                    Some(0) | None => {
                        return Err("hysteria2: stream closed before the TCP request".into());
                    }
                    Some(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            }
        }
    }
}

enum TcpRequestParse {
    NeedMore,
    Done { address: String, consumed: usize },
    Invalid,
}

/// Parses a proxied-TCP request frame (mirror of the connector's
/// `encode_tcp_request`): `varint(0x401) varint(len) address varint(len)
/// padding`.
fn parse_tcp_request(buffer: &[u8]) -> TcpRequestParse {
    let Some((frame_type, mut cursor)) = get_varint(buffer) else {
        return TcpRequestParse::NeedMore;
    };
    if frame_type != HYSTERIA2_TCP_REQUEST_FRAME_TYPE {
        return TcpRequestParse::Invalid;
    }

    let Some((address_length, used)) = buffer.get(cursor..).and_then(get_varint) else {
        return TcpRequestParse::NeedMore;
    };
    if address_length > MAX_MESSAGE_LENGTH {
        return TcpRequestParse::Invalid;
    }
    cursor += used;
    let address_end = cursor + address_length as usize;
    if buffer.len() < address_end {
        return TcpRequestParse::NeedMore;
    }
    let Ok(address) = std::str::from_utf8(&buffer[cursor..address_end]) else {
        return TcpRequestParse::Invalid;
    };
    let address = address.to_string();
    cursor = address_end;

    let Some((padding_length, used)) = buffer.get(cursor..).and_then(get_varint) else {
        return TcpRequestParse::NeedMore;
    };
    if padding_length > MAX_PADDING_LENGTH {
        return TcpRequestParse::Invalid;
    }
    cursor += used + padding_length as usize;
    if buffer.len() < cursor {
        return TcpRequestParse::NeedMore;
    }
    TcpRequestParse::Done {
        address,
        consumed: cursor,
    }
}

/// Encodes the proxied-TCP response the client strips before relay: a status
/// byte (0 = accepted), an empty message, and random padding.
fn encode_tcp_response(ok: bool) -> Vec<u8> {
    let padding = random_padding(TCP_PADDING_MIN, TCP_PADDING_MAX);
    let mut response = BytesMut::with_capacity(8 + padding.len());
    response.put_u8(u8::from(!ok));
    put_varint(&mut response, 0);
    put_varint(&mut response, padding.len() as u64);
    response.put_slice(&padding);
    response.to_vec()
}

/// Bridges Hysteria2's per-flow `session_id` to the datagram face's
/// `SocketAddr` flow key and back — a bijection through an IPv4 encoding, so
/// the UDP session table keys each session id as its own full-cone flow and
/// the responder recovers the id to frame the reply.
fn session_id_to_source(session_id: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(session_id)), 0)
}

fn source_to_session_id(source: SocketAddr) -> u32 {
    match source.ip() {
        IpAddr::V4(address) => u32::from(address),
        IpAddr::V6(_) => 0,
    }
}

/// Yields one deframed inbound datagram per authenticated connection: read a
/// QUIC datagram, reassemble it, and present `(session-derived source, target,
/// payload)`. An undecodable datagram is skipped (UDP loss semantics); a
/// closed connection ends the face.
struct Hysteria2DatagramReceiver {
    connection: Connection,
    defragger: Hysteria2UdpDefragger,
}

impl InboundDatagramReceiver for Hysteria2DatagramReceiver {
    fn next(&mut self) -> InboundFuture<'_, Option<InboundDatagram>> {
        Box::pin(async move {
            loop {
                let datagram = match self.connection.read_datagram().await {
                    Ok(datagram) => datagram,
                    Err(_) => return Ok(None),
                };
                let Some(message) = Hysteria2UdpMessage::parse(&datagram) else {
                    continue;
                };
                let Some(message) = self.defragger.feed(message) else {
                    continue;
                };
                let Ok(target) = parse_connect_authority(&message.addr) else {
                    continue;
                };
                return Ok(Some(InboundDatagram {
                    source: session_id_to_source(message.session_id),
                    target,
                    payload: message.data,
                }));
            }
        })
    }
}

/// Frames a relay response back onto the QUIC connection for the flow the
/// `source` names, recovering that flow's `session_id`.
struct Hysteria2DatagramResponder {
    connection: Connection,
    next_packet_id: AtomicU16,
}

impl InboundDatagramResponder for Hysteria2DatagramResponder {
    fn respond<'a>(
        &'a self,
        source: SocketAddr,
        from: &'a ConnectTarget,
        payload: &'a [u8],
    ) -> InboundFuture<'a, ()> {
        Box::pin(async move {
            let session_id = source_to_session_id(source);
            let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
            send_udp_message(
                &self.connection,
                session_id,
                packet_id,
                &from.authority(),
                payload,
            )
        })
    }
}

/// The proxied byte stream a Hysteria2 bi-stream carries: relay reads drain the
/// fast-open leftover first, then the QUIC recv stream; relay writes go to the
/// QUIC send stream.
struct Hysteria2ServerStream {
    send: TurnSend,
    recv: RecvStream,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl Hysteria2ServerStream {
    fn new(send: TurnSend, recv: RecvStream, leftover: Vec<u8>) -> Self {
        Self {
            send,
            recv,
            leftover,
            leftover_pos: 0,
        }
    }
}

impl AsyncRead for Hysteria2ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = &mut *self;
        if stream.leftover_pos < stream.leftover.len() {
            let remaining = &stream.leftover[stream.leftover_pos..];
            let length = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..length]);
            stream.leftover_pos += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut stream.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Hysteria2ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    //! Acceptor-side tests in two layers. The pure layer pins every decision
    //! function that judges untrusted client bytes — the auth-string table,
    //! the proxied-TCP request parser (fed the exact frame the in-tree client
    //! encodes), the response framing, the auth-failure masquerade, and the
    //! UDP session-id bridge. The loopback layer stands up the real QUIC/H3
    //! endpoint with a raw quinn+h3 client (the connector's transport half,
    //! minus its dialing machinery) to drive the two abuse paths the connector
    //! never produces: a missing `Hysteria-Auth` header — refused with the
    //! ordinary-web-server masquerade, carrying no `Hysteria-*` fingerprint —
    //! and a malformed request frame on an authenticated connection. The full
    //! connector↔acceptor pipeline is `gate.rs`'s standing coverage.

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    use super::*;
    use crate::protocols::hysteria2::test_server::{self, match_direct_device};

    const TEST_AUTH: &str = "unit-hysteria2-auth";
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    // ---- The pure decision functions.

    #[test]
    fn user_table_authenticates_only_the_exact_auth_string() {
        let table = Hysteria2UserTable::new()
            .with_user("alice", "alice-auth")
            .with_user("bob", "bob-auth");

        assert_eq!(table.authenticate("alice-auth").as_deref(), Some("alice"));
        assert_eq!(table.authenticate("bob-auth").as_deref(), Some("bob"));
        assert!(
            table.authenticate("").is_none(),
            "an absent header never authenticates"
        );
        assert!(
            table.authenticate("alice-auth ").is_none(),
            "credentials match exactly, never loosely"
        );
        assert!(
            Hysteria2UserTable::new().authenticate("anything").is_none(),
            "an empty table rejects everyone"
        );
    }

    #[test]
    fn an_empty_credential_never_authenticates_even_against_an_empty_auth_user() {
        // A user misconfigured with an empty auth string, plus a client that
        // sends no `Hysteria-Auth` header (normalized to ""), must not
        // authenticate everyone: an empty presented credential is refused at
        // lookup, so the empty-auth user matches no one.
        let table = Hysteria2UserTable::new()
            .with_user("misconfigured", "")
            .with_user("alice", "alice-auth");

        assert!(
            table.authenticate("").is_none(),
            "an empty credential never authenticates, even against an empty-auth user"
        );
        // A real credential in the same table still authenticates.
        assert_eq!(table.authenticate("alice-auth").as_deref(), Some("alice"));
    }

    #[test]
    fn masquerade_rejection_is_a_plain_web_server_404_with_no_hysteria_headers() {
        let (response, body) = masquerade_rejection_response().expect("masquerade response builds");

        assert_eq!(
            response.status(),
            http::StatusCode::NOT_FOUND,
            "the reference default masquerade is Go's http.NotFound"
        );
        // The point of the masquerade: nothing on the failure path may name
        // Hysteria, or an active prober could positively fingerprint the server.
        for name in response.headers().keys() {
            assert!(
                !name.as_str().to_ascii_lowercase().starts_with("hysteria"),
                "the auth-failure response must carry no Hysteria-* header, found {name}"
            );
        }
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8"),
            "an ordinary web server's 404 is text/plain"
        );
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff"),
            "net/http's Error sets the nosniff guard"
        );
        assert_eq!(
            body.as_ref(),
            b"404 page not found\n",
            "the body is the reference 404 page, byte for byte"
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("19"),
            "content-length matches the 404-page body an ordinary server sends"
        );
    }

    /// The proxied-TCP request frame exactly as the in-tree client encodes it
    /// (`connector::encode_tcp_request` on the shared codec): `varint(0x401)
    /// varint(len) address varint(len) padding` — with caller-fixed padding
    /// so the byte layout is deterministic.
    fn client_tcp_request(address: &str, padding: &[u8]) -> Vec<u8> {
        let mut frame = BytesMut::new();
        put_varint(&mut frame, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
        put_varint(&mut frame, address.len() as u64);
        frame.put_slice(address.as_bytes());
        put_varint(&mut frame, padding.len() as u64);
        frame.put_slice(padding);
        frame.to_vec()
    }

    #[test]
    fn parse_tcp_request_accepts_a_client_frame_and_returns_the_fast_open_leftover() {
        let mut wire = client_tcp_request("example.com:443", &[b'x'; 70]);
        let frame_len = wire.len();
        wire.extend_from_slice(b"fast-open-payload");

        match parse_tcp_request(&wire) {
            TcpRequestParse::Done { address, consumed } => {
                assert_eq!(address, "example.com:443");
                assert_eq!(
                    consumed, frame_len,
                    "padding is consumed, relay bytes are not"
                );
                assert_eq!(&wire[consumed..], b"fast-open-payload");
            }
            TcpRequestParse::NeedMore | TcpRequestParse::Invalid => {
                panic!("a client-encoded frame must parse")
            }
        }
    }

    #[test]
    fn parse_tcp_request_needs_more_on_every_partial_prefix() {
        let wire = client_tcp_request("example.com:443", &[b'x'; 70]);
        for cut in 0..wire.len() {
            match parse_tcp_request(&wire[..cut]) {
                TcpRequestParse::NeedMore => {}
                TcpRequestParse::Done { .. } => panic!("a {cut}-byte prefix parsed early"),
                TcpRequestParse::Invalid => panic!("a {cut}-byte prefix misread as invalid"),
            }
        }
    }

    #[test]
    fn parse_tcp_request_rejects_malformed_frames() {
        // A frame type that is not the proxied-TCP request.
        let mut wrong_type = BytesMut::new();
        put_varint(&mut wrong_type, 0x400);
        assert!(matches!(
            parse_tcp_request(&wrong_type),
            TcpRequestParse::Invalid
        ));

        // An address length above the protocol cap: rejected before any
        // attempt to buffer it (anti-abuse).
        let mut oversized_address = BytesMut::new();
        put_varint(&mut oversized_address, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
        put_varint(&mut oversized_address, MAX_MESSAGE_LENGTH + 1);
        assert!(matches!(
            parse_tcp_request(&oversized_address),
            TcpRequestParse::Invalid
        ));

        // A padding length above the protocol cap.
        let mut oversized_padding = BytesMut::new();
        put_varint(&mut oversized_padding, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
        put_varint(&mut oversized_padding, 1);
        oversized_padding.put_slice(b"a");
        put_varint(&mut oversized_padding, MAX_PADDING_LENGTH + 1);
        assert!(matches!(
            parse_tcp_request(&oversized_padding),
            TcpRequestParse::Invalid
        ));

        // Address bytes that are not UTF-8.
        let mut bad_utf8 = BytesMut::new();
        put_varint(&mut bad_utf8, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
        put_varint(&mut bad_utf8, 2);
        bad_utf8.put_slice(&[0xFF, 0xFE]);
        assert!(matches!(
            parse_tcp_request(&bad_utf8),
            TcpRequestParse::Invalid
        ));
    }

    #[test]
    fn encode_tcp_response_frames_status_empty_message_and_bounded_padding() {
        for (ok, expected_status) in [(true, 0_u8), (false, 1_u8)] {
            let response = encode_tcp_response(ok);
            assert_eq!(response[0], expected_status);
            let (message_length, used) = get_varint(&response[1..]).expect("message length");
            assert_eq!(message_length, 0, "the response carries no message");
            let mut cursor = 1 + used;
            let (padding_length, used) = get_varint(&response[cursor..]).expect("padding length");
            assert!(
                ((TCP_PADDING_MIN as u64)..(TCP_PADDING_MAX as u64)).contains(&padding_length),
                "padding length {padding_length} stays in the anti-fingerprint band"
            );
            cursor += used + padding_length as usize;
            assert_eq!(response.len(), cursor, "nothing trails the padding");
        }
    }

    #[test]
    fn session_id_source_bridge_is_a_bijection_for_ipv4_sources() {
        for session_id in [0_u32, 1, 7, 0xDEAD_BEEF, u32::MAX] {
            let source = session_id_to_source(session_id);
            assert_eq!(source_to_session_id(source), session_id);
        }
        let v6: SocketAddr = "[2001:db8::1]:9".parse().expect("v6 addr");
        assert_eq!(
            source_to_session_id(v6),
            0,
            "non-bridged sources collapse to session 0"
        );
    }

    // ---- The live QUIC/H3 loopback layer.

    /// A raw QUIC client endpoint that accepts the test certificate and
    /// speaks h3 — the connector's transport half without its profile and
    /// dialing machinery, so a test can present hand-built headers and
    /// frames.
    fn quic_client_endpoint() -> Endpoint {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls = crate::tls::client_config(true, &[b"h3".to_vec()]);
        let quic_tls =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client tls");
        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_tls)));
        endpoint
    }

    async fn connect_client(endpoint: &Endpoint, server: SocketAddr) -> Connection {
        timeout(
            TEST_TIMEOUT,
            endpoint
                .connect(server, test_server::SNI)
                .expect("begin quic dial"),
        )
        .await
        .expect("quic dial must not hang")
        .expect("quic dial")
    }

    /// Runs the client half of the HTTP/3 auth exchange, presenting
    /// `auth_header` (`None` sends no `Hysteria-Auth` at all). Returns the
    /// response status and headers (or the transport error), plus the driver
    /// and sender that must stay alive for the connection's lifetime.
    async fn h3_auth(
        connection: &Connection,
        auth_header: Option<&str>,
    ) -> (
        Result<(u16, http::HeaderMap), String>,
        h3::client::Connection<h3_quinn::Connection, Bytes>,
        h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    ) {
        let (driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .expect("h3 client setup");
        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth");
        if let Some(auth) = auth_header {
            request = request.header("Hysteria-Auth", auth);
        }
        let request = request.body(()).expect("auth request");
        let mut stream = sender
            .send_request(request)
            .await
            .expect("send auth request");
        stream.finish().await.expect("finish auth request");
        let outcome = stream
            .recv_response()
            .await
            .map(|response| (response.status().as_u16(), response.headers().clone()))
            .map_err(|error| error.to_string());
        (outcome, driver, sender)
    }

    async fn wait_for_auth_failures(acceptor: &Hysteria2Acceptor, at_least: u64) -> u64 {
        let failures = acceptor.auth_failures_handle();
        let mut seen = 0;
        for _ in 0..250 {
            seen = failures.load(Ordering::Relaxed);
            if seen >= at_least {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        seen
    }

    #[tokio::test]
    async fn a_missing_credential_gets_a_web_server_masquerade_and_is_counted() {
        let acceptor = test_server::acceptor(TEST_AUTH);
        let server_addr = test_server::spawn(Arc::clone(&acceptor), match_direct_device()).await;

        let endpoint = quic_client_endpoint();
        let connection = connect_client(&endpoint, server_addr).await;
        let (outcome, _driver, _sender) = timeout(TEST_TIMEOUT, h3_auth(&connection, None))
            .await
            .expect("auth exchange must not hang");

        // The acceptor keeps the refused connection alive to flush the
        // masquerade, so the client reads it deterministically: a plain 404
        // an active prober cannot tell apart from an ordinary web server, with
        // no `Hysteria-*` header to fingerprint on the failure path.
        let (code, headers) = outcome.expect("the masquerade response is delivered, not truncated");
        assert_eq!(code, 404, "an absent credential gets an ordinary 404");
        assert!(
            headers
                .keys()
                .all(|name| !name.as_str().to_ascii_lowercase().starts_with("hysteria")),
            "the failure path leaks no Hysteria-* header, found {headers:?}"
        );
        assert_eq!(
            wait_for_auth_failures(&acceptor, 1).await,
            1,
            "the credential-less connection was counted once"
        );
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

    /// `Some(consumed)` once `buffer` holds one whole ok-status TCP response
    /// frame (status byte, message, padding).
    fn parse_ok_response_frame(buffer: &[u8]) -> Option<usize> {
        let status = *buffer.first()?;
        assert_eq!(status, 0, "the server accepted the request");
        let (message_length, used) = get_varint(buffer.get(1..)?)?;
        let mut cursor = 1 + used + message_length as usize;
        let (padding_length, used) = get_varint(buffer.get(cursor..)?)?;
        cursor += used + padding_length as usize;
        (buffer.len() >= cursor).then_some(cursor)
    }

    /// Reads and strips the server's TCP response frame from `recv`,
    /// returning any relay bytes that arrived behind it.
    async fn read_ok_tcp_response(recv: &mut RecvStream) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 512];
        loop {
            if let Some(consumed) = parse_ok_response_frame(&buffer) {
                return buffer[consumed..].to_vec();
            }
            let read = recv
                .read(&mut chunk)
                .await
                .expect("response read")
                .expect("response before EOF");
            buffer.extend_from_slice(&chunk[..read]);
        }
    }

    #[tokio::test]
    async fn a_malformed_tcp_request_stream_is_refused_without_killing_the_connection() {
        let echo_addr = spawn_tcp_echo().await;
        let acceptor = test_server::acceptor(TEST_AUTH);
        let server_device = match_direct_device();
        let server_addr = test_server::spawn(Arc::clone(&acceptor), server_device.clone()).await;

        let endpoint = quic_client_endpoint();
        let connection = connect_client(&endpoint, server_addr).await;
        let (outcome, _driver, _sender) =
            timeout(TEST_TIMEOUT, h3_auth(&connection, Some(TEST_AUTH)))
                .await
                .expect("auth exchange must not hang");
        let (code, headers) = outcome.expect("authenticated response");
        assert_eq!(
            code, AUTH_OK_STATUS,
            "the pre-shared credential authenticates"
        );
        assert_eq!(
            headers
                .get("Hysteria-UDP")
                .and_then(|value| value.to_str().ok()),
            Some("true"),
            "auth success advertises the UDP relay the acceptor drives"
        );
        assert_eq!(
            headers
                .get("Hysteria-CC-RX")
                .and_then(|value| value.to_str().ok()),
            Some("0"),
            "auth success states the server's receive rate: no limit"
        );

        // Stream one: a frame type that is not a proxied-TCP request. The
        // server must refuse the stream — no tunnel-established response, no
        // dispatched session — without tearing the connection down.
        let (mut send, mut recv) = connection.open_bi().await.expect("open malformed stream");
        let mut junk = BytesMut::new();
        put_varint(&mut junk, 0x17);
        junk.put_slice(&[0xFF_u8; 16]);
        send.write_all(&junk).await.expect("write junk frame");
        let outcome = timeout(TEST_TIMEOUT, recv.read_to_end(64 * 1024))
            .await
            .expect("the refused stream settles instead of hanging");
        assert!(
            outcome.is_err() || outcome.is_ok_and(|bytes| bytes.is_empty()),
            "a malformed request never receives a tunnel-established response"
        );
        assert!(
            server_device
                .pinned_runtime()
                .session_registry()
                .snapshot()
                .iter()
                .all(|snapshot| snapshot.inbound != "hysteria2"),
            "no session was dispatched for the malformed stream"
        );

        // Stream two, same connection: a well-formed client frame with
        // fast-open payload still relays through the dispatcher to the echo.
        let (mut send, mut recv) = connection.open_bi().await.expect("open good stream");
        let mut wire = client_tcp_request(
            &format!("{}:{}", echo_addr.ip(), echo_addr.port()),
            &[b'x'; 70],
        );
        wire.extend_from_slice(b"fast-open-ping");
        send.write_all(&wire).await.expect("write request");

        let mut echoed = timeout(TEST_TIMEOUT, read_ok_tcp_response(&mut recv))
            .await
            .expect("tcp response must not hang");
        while echoed.len() < b"fast-open-ping".len() {
            let mut chunk = [0_u8; 512];
            let read = timeout(TEST_TIMEOUT, recv.read(&mut chunk))
                .await
                .expect("echo must not hang")
                .expect("echo read")
                .expect("echo before EOF");
            echoed.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(
            &echoed, b"fast-open-ping",
            "the fast-open payload rode the same connection the probe used"
        );
    }

    /// What a connection that has not authenticated can park on the host.
    /// A peer whose credential was refused is kept for the masquerade, and
    /// past the auth request nothing reads its streams -- not the HTTP/3
    /// layer, which is never asked for another request, and not the
    /// dispatcher, which this connection never reaches. Quinn buffers a
    /// stream's bytes whether or not the application takes them, so what is
    /// left between such a peer and the host's memory is the receive window.
    #[tokio::test]
    async fn an_attempt_that_has_not_authenticated_parks_little() {
        let acceptor = test_server::acceptor(TEST_AUTH);
        let server_addr = test_server::spawn(Arc::clone(&acceptor), match_direct_device()).await;

        let endpoint = quic_client_endpoint();
        let connection = connect_client(&endpoint, server_addr).await;
        let (outcome, _driver, _sender) = timeout(TEST_TIMEOUT, h3_auth(&connection, None))
            .await
            .expect("auth exchange must not hang");
        assert_eq!(
            outcome.expect("the masquerade response").0,
            404,
            "no credential, so the connection is only being kept for the masquerade"
        );

        // Push on a stream of its own until the writes stop completing. What
        // reaches the host is what the window allows, however much the
        // client buffers for itself.
        let (mut send, _recv) = connection.open_bi().await.expect("open a stream");
        let chunk = vec![0_u8; 256 * 1024];
        let mut written = 0;
        for _ in 0..128 {
            match timeout(Duration::from_millis(100), send.write_all(&chunk)).await {
                Ok(Ok(())) => written += chunk.len(),
                Ok(Err(error)) => panic!("the stream was held off, not failed: {error}"),
                Err(_) => break,
            }
        }
        let parked = connection.stats().udp_tx.bytes;
        assert!(
            parked < 1024 * 1024,
            "a refused credential put {parked} bytes on the host ({written} written)"
        );
    }

    /// Full means the next attempt is told no -- not that a connection being
    /// served is closed to make room for it. Two places here; the two
    /// clients that take them keep relaying while the third is refused.
    #[tokio::test]
    async fn a_full_inbound_refuses_the_attempt_and_keeps_what_it_serves() {
        let echo_addr = spawn_tcp_echo().await;
        let acceptor = test_server::acceptor_serving_at_most(TEST_AUTH, 2);
        let server_addr = test_server::spawn(Arc::clone(&acceptor), match_direct_device()).await;

        let endpoint = quic_client_endpoint();
        let mut served = Vec::new();
        for _ in 0..2 {
            let connection = connect_client(&endpoint, server_addr).await;
            let (outcome, driver, sender) =
                timeout(TEST_TIMEOUT, h3_auth(&connection, Some(TEST_AUTH)))
                    .await
                    .expect("auth exchange must not hang");
            assert_eq!(
                outcome.expect("authenticated response").0,
                AUTH_OK_STATUS,
                "the inbound has a place for this client"
            );
            served.push((connection, driver, sender));
        }

        // A place comes back when a client leaves: what the inbound counts
        // is what it holds, not what has ever reached it.
        drop(served.pop().expect("a served client leaves"));
        let mut admitted = None;
        for _ in 0..250 {
            match endpoint
                .connect(server_addr, test_server::SNI)
                .expect("begin the dial that takes the freed place")
                .await
            {
                Ok(connection) => {
                    admitted = Some(connection);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(20)).await,
            }
        }
        let connection = admitted.expect("the place the leaving client held is served again");
        let (outcome, driver, sender) =
            timeout(TEST_TIMEOUT, h3_auth(&connection, Some(TEST_AUTH)))
                .await
                .expect("auth exchange must not hang");
        assert_eq!(
            outcome.expect("authenticated response").0,
            AUTH_OK_STATUS,
            "the client that took the freed place is served like any other"
        );
        served.push((connection, driver, sender));

        // Full again, and the next attempt is told so at once -- in the QUIC
        // transport's own words -- instead of waiting out its handshake.
        let refused = timeout(
            TEST_TIMEOUT,
            endpoint
                .connect(server_addr, test_server::SNI)
                .expect("begin the dial that finds no place"),
        )
        .await
        .expect("a refused dial does not hang");
        assert!(
            matches!(
                &refused,
                Err(quinn::ConnectionError::ConnectionClosed(close))
                    if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED
            ),
            "the full inbound refuses the attempt, got {refused:?}"
        );

        // And both connections it holds still relay: nothing was closed to
        // make room for the attempt.
        for (connection, _driver, _sender) in &served {
            let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
            let wire = client_tcp_request(
                &format!("{}:{}", echo_addr.ip(), echo_addr.port()),
                &[b'x'; 70],
            );
            send.write_all(&wire).await.expect("write request");
            timeout(TEST_TIMEOUT, read_ok_tcp_response(&mut recv))
                .await
                .expect("a served connection still relays");
        }
    }

    /// A stream that starts its request frame and stops. Without a budget on
    /// the frame its task parks until the client disconnects, holding a
    /// tracked task, a QUIC stream and a place in the connection's stream
    /// allowance -- and none of it shows in the session registry, which only
    /// sees a stream once its request has parsed. (A stream the client opens
    /// and never writes on does not reach the server at all; QUIC carries the
    /// open with the first bytes.)
    #[tokio::test]
    async fn a_half_sent_request_frame_runs_out_of_its_budget() {
        let echo_addr = spawn_tcp_echo().await;
        let acceptor = test_server::acceptor(TEST_AUTH);
        let server_device = match_direct_device();
        let server_addr = test_server::spawn(Arc::clone(&acceptor), server_device.clone()).await;

        let endpoint = quic_client_endpoint();
        let connection = connect_client(&endpoint, server_addr).await;
        let (outcome, _driver, _sender) =
            timeout(TEST_TIMEOUT, h3_auth(&connection, Some(TEST_AUTH)))
                .await
                .expect("auth exchange must not hang");
        assert_eq!(
            outcome.expect("authenticated response").0,
            AUTH_OK_STATUS,
            "the pre-shared credential authenticates"
        );

        // One byte of the frame type's two-byte varint: enough for the stream
        // to reach the server and park its task, never enough to parse.
        let (mut send, mut recv) = connection.open_bi().await.expect("open silent stream");
        send.write_all(&[0x44])
            .await
            .expect("write a partial varint");
        let outcome = timeout(TEST_TIMEOUT, recv.read_to_end(64 * 1024))
            .await
            .expect("the silent stream settles instead of hanging");
        assert!(
            outcome.is_err() || outcome.is_ok_and(|bytes| bytes.is_empty()),
            "a stream that sent no request never receives a tunnel-established response"
        );

        // The connection still serves: the budget ends one stream, not the
        // client.
        let (mut send, mut recv) = connection.open_bi().await.expect("open good stream");
        let wire = client_tcp_request(
            &format!("{}:{}", echo_addr.ip(), echo_addr.port()),
            &[b'x'; 70],
        );
        send.write_all(&wire).await.expect("write request");
        timeout(TEST_TIMEOUT, read_ok_tcp_response(&mut recv))
            .await
            .expect("tcp response must not hang");
    }
}
