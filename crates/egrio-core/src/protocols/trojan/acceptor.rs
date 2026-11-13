//! The Trojan server half: the `InboundAcceptor` dual of
//! the connector. On an accepted TCP transport it terminates TLS, reads the
//! Trojan preamble, authenticates the 56-byte password hash against a static
//! user table, and hands the plaintext TLS duplex to the unmodified dispatch
//! pipeline as an [`AcceptedStream`] carrying the authenticated `user`.
//!
//! A request whose hash no user table entry matches is an auth failure —
//! bounded (a fixed 56-byte hash is all that was read) and counted (so a host
//! can alarm on it). Unlike stock Trojan there is no fallback to a camouflage
//! web server; the connection is simply dropped, which keeps the failure
//! path from being turned into an amplifier.
//!
//! The loopback gate (`gate.rs`) is this acceptor's exhaustive standing gate;
//! the live constructor is the listener's `CoreInbound::Trojan` arm
//! (`inbound/listener/compose.rs`), which terminates TLS with operator-supplied
//! PEM material and surfaces its auth-failure count on the manager's control
//! surface.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsAcceptor;

use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{
    AcceptedDatagramFace, AcceptedStream, BoxedInboundStream, InboundAcceptor, InboundDatagram,
    InboundDatagramReceiver, InboundDatagramResponder, InboundFuture, InboundReplyPlan,
    InboundSession,
};
use crate::protocols::trojan::codec::{
    encode_udp_frame, password_hash_hex, read_auth_hash, read_request, read_udp_frame, CMD_CONNECT,
    CMD_UDP_ASSOCIATE, TROJAN_HASH_LEN,
};
use crate::target::ConnectTarget;

/// The static user table the acceptor authenticates against. Each user is a
/// `(name, password)` the server
/// pre-shares; the table keys on `hex(SHA224(password))` so authentication is a
/// single map lookup on the hash the client presents.
pub(crate) struct TrojanUserTable {
    users: HashMap<[u8; TROJAN_HASH_LEN], Arc<str>>,
}

impl TrojanUserTable {
    pub(crate) fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Adds a pre-shared user, deriving its auth hash once at table build.
    pub(crate) fn with_user(mut self, name: impl Into<Arc<str>>, password: &str) -> Self {
        self.users.insert(password_hash_hex(password), name.into());
        self
    }

    /// The user whose hash the peer presented, or `None` if none match.
    fn authenticate(&self, hash: &[u8; TROJAN_HASH_LEN]) -> Option<Arc<str>> {
        self.users.get(hash).cloned()
    }
}

/// One Trojan inbound: terminates TLS, authenticates against a shared user
/// table, and counts the requests no user hash matched.
pub(crate) struct TrojanAcceptor {
    tls: TlsAcceptor,
    users: Arc<TrojanUserTable>,
    auth_failures: Arc<AtomicU64>,
}

impl TrojanAcceptor {
    pub(crate) fn new(tls: Arc<ServerConfig>, users: TrojanUserTable) -> Self {
        Self {
            tls: TlsAcceptor::from(tls),
            users: Arc::new(users),
            auth_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Requests that reached the acceptor but no user hash authenticated — the
    /// gate's direct reader (a live listener surfaces the same count through
    /// [`Self::auth_failures_handle`] on its control surface). The gate asserts
    /// it moves on a bad hash and stays put on a good one.
    #[cfg(test)]
    pub(crate) fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    /// A shared handle to the auth-failure counter — so a composing listener can
    /// surface it without holding the whole acceptor.
    pub(crate) fn auth_failures_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.auth_failures)
    }
}

impl fmt::Debug for TrojanAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrojanAcceptor")
            .field("users", &self.users.users.len())
            .finish_non_exhaustive()
    }
}

impl InboundAcceptor for TrojanAcceptor {
    fn accept(&self, io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        Box::pin(async move {
            accept_trojan_session(&self.tls, io, &self.users, &self.auth_failures).await
        })
    }
}

/// Terminates TLS, authenticates the Trojan preamble, and yields the accepted
/// session: a proxied stream for CONNECT, or an authenticated datagram face for
/// UDP associate. The hash is read and checked before anything else, so an
/// unauthenticated peer costs one bounded 56-byte read before the drop.
async fn accept_trojan_session(
    tls: &TlsAcceptor,
    io: BoxedInboundStream,
    users: &TrojanUserTable,
    auth_failures: &AtomicU64,
) -> Result<InboundSession, String> {
    let mut stream = tls
        .accept(io)
        .await
        .map_err(|error| format!("Trojan TLS handshake failed: {error}"))?;

    // The password hash is the credential: one map lookup authenticates the peer
    // and names the user. An unknown hash is bounded (56 bytes) and counted.
    let hash = read_auth_hash(&mut stream).await?;
    let Some(user) = users.authenticate(&hash) else {
        auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("trojan: no user hash authenticated the request".into());
    };

    let (command, target) = read_request(&mut stream).await?;
    match command {
        CMD_CONNECT => Ok(InboundSession::Stream(AcceptedStream {
            inbound: "trojan",
            user: Some(user),
            process: ClientOwner::Known(None),
            target,
            io: Box::new(stream),
            // Encrypted protocol: no plaintext replies, failure is a dropped
            // stream. Every reply-plan field stays empty.
            replies: InboundReplyPlan::default(),
            reset: None,
        })),
        // UDP associate rides the same TLS connection as length-framed datagrams
        // (trojan spec). The request names the client's desired destination,
        // but every datagram carries its own target, which is what the face
        // relays. Split the TLS duplex so the receive
        // half deframes client datagrams while the send half frames responses
        // back — the authenticated datagram face the UDP dispatcher pumps, the
        // Trojan peer of the Hysteria2 QUIC datagram face.
        CMD_UDP_ASSOCIATE => {
            let (read_half, write_half) = tokio::io::split(stream);
            Ok(InboundSession::Datagrams(AcceptedDatagramFace {
                user: Some(user),
                receiver: Box::new(TrojanUdpReceiver {
                    read: Box::new(read_half),
                }),
                responder: Box::new(TrojanUdpResponder {
                    write: AsyncMutex::new(Box::new(write_half)),
                }),
            }))
        }
        other => Err(format!("trojan: unsupported command {other}")),
    }
}

/// One Trojan UDP connection's flow source. Trojan carries no per-flow
/// discriminator — one TLS connection is one client socket — so every datagram
/// on the connection shares this constant source, and the UDP session key
/// separates flows by their (authenticated user, this source, target). Two
/// connections' faces stay apart on their `user` and the dispatcher's per-face
/// flow-id counter.
const TROJAN_UDP_SOURCE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// The receive half of a Trojan datagram face: deframes one client datagram per
/// call off the TLS read half. `Ok(None)` ends the face when the client closes
/// the associate at a frame boundary.
struct TrojanUdpReceiver {
    read: Box<dyn AsyncRead + Send + Unpin>,
}

impl InboundDatagramReceiver for TrojanUdpReceiver {
    fn next(&mut self) -> InboundFuture<'_, Option<InboundDatagram>> {
        Box::pin(async move {
            Ok(read_udp_frame(&mut self.read)
                .await
                .map_err(|error| error.to_string())?
                .map(|(target, payload)| InboundDatagram {
                    source: TROJAN_UDP_SOURCE,
                    target,
                    payload,
                }))
        })
    }
}

/// The send half of a Trojan datagram face: frames one relay response back onto
/// the TLS write half, tagged with the remote it came from. `&self` so a late
/// response frames while the receive half is parked; the write half is behind an
/// async mutex because the response path is the only writer but must not overlap
/// itself.
struct TrojanUdpResponder {
    write: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl InboundDatagramResponder for TrojanUdpResponder {
    fn respond<'a>(
        &'a self,
        _source: SocketAddr,
        from: &'a ConnectTarget,
        payload: &'a [u8],
    ) -> InboundFuture<'a, ()> {
        Box::pin(async move {
            let frame = encode_udp_frame(from, payload)?;
            let mut write = self.write.lock().await;
            write
                .write_all(&frame)
                .await
                .map_err(|error| error.to_string())?;
            write.flush().await.map_err(|error| error.to_string())?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    //! Preamble-parser tests over in-memory TLS: a tokio-rustls client half
    //! handshakes against the acceptor across a `tokio::io::duplex`, so no
    //! sockets are involved. The end-to-end CONNECT relay and the dispatcher
    //! integration are the loopback gate's business (`gate.rs`); these pin
    //! the acceptor's own parsing of untrusted client bytes — every accepted
    //! shape carries the right user and target, every malformed shape errors
    //! (never panics or parks), and the UDP-associate face frames both ways.

    use rustls_pki_types::ServerName;
    use tokio::io::{duplex, DuplexStream};
    use tokio::task::JoinHandle;
    use tokio::time::{timeout, Duration};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::certificate::server_config_from_pem;
    use crate::protocols::trojan::codec::encode_client_preamble;

    const TEST_USER: &str = "alice";
    const TEST_PASSWORD: &str = "s3cr3t-preshared-key";
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    /// A throwaway self-signed cert + key (PEM, SAN `localhost`) — the
    /// material an operator hands the certificate subsystem (same shape the
    /// gate uses).
    fn self_signed_pem() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("self-signed cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn test_acceptor() -> TrojanAcceptor {
        let (cert_pem, key_pem) = self_signed_pem();
        let tls = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), &[])
            .expect("server config builds");
        TrojanAcceptor::new(
            tls,
            TrojanUserTable::new().with_user(TEST_USER, TEST_PASSWORD),
        )
    }

    /// Client-side TLS over the duplex: the skip-verify config (the cert is
    /// a throwaway self-signed) handshaking against the acceptor running
    /// concurrently in the test body.
    async fn tls_client(io: DuplexStream) -> tokio_rustls::client::TlsStream<DuplexStream> {
        let server_name = ServerName::try_from("localhost").expect("server name");
        TlsConnector::from(crate::tls::client_config(true, &[]))
            .connect(server_name, io)
            .await
            .expect("client TLS handshake")
    }

    /// Spawns the peer: handshake TLS, write `bytes` as the plaintext
    /// application data, and keep the session alive until joined.
    fn spawn_tls_client(
        io: DuplexStream,
        bytes: Vec<u8>,
    ) -> JoinHandle<tokio_rustls::client::TlsStream<DuplexStream>> {
        tokio::spawn(async move {
            let mut tls = tls_client(io).await;
            tls.write_all(&bytes).await.expect("write over TLS");
            tls.flush().await.expect("flush over TLS");
            tls
        })
    }

    fn preamble(password: &str, command: u8, target: &ConnectTarget) -> Vec<u8> {
        encode_client_preamble(&password_hash_hex(password), command, target)
            .expect("preamble encodes")
    }

    /// Runs one full authenticated CONNECT handshake and returns what the
    /// acceptor yielded plus its auth-failure count.
    async fn accept_connect(target: &ConnectTarget) -> (AcceptedStream, u64) {
        let acceptor = test_acceptor();
        let (client_io, server_io) = duplex(64 * 1024);
        let client = spawn_tls_client(client_io, preamble(TEST_PASSWORD, CMD_CONNECT, target));

        let session = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server_io)))
            .await
            .expect("accept must not hang")
            .expect("authenticated CONNECT accepted");
        let _client = client.await.expect("client task");
        match session {
            InboundSession::Stream(accepted) => (accepted, acceptor.auth_failures()),
            InboundSession::Datagrams(_) => panic!("CONNECT yields a stream session"),
        }
    }

    /// Runs the acceptor against a client that writes `bytes` over TLS and
    /// returns the accept error. (`expect_err` needs `Debug` on the session,
    /// which it deliberately does not carry.)
    async fn rejected_over_tls(bytes: Vec<u8>, why: &str) -> (String, u64) {
        let acceptor = test_acceptor();
        let (client_io, server_io) = duplex(64 * 1024);
        let client = spawn_tls_client(client_io, bytes);

        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server_io)))
            .await
            .expect("accept must not hang");
        let _client = client.await.expect("client task");
        match outcome {
            Err(error) => (error, acceptor.auth_failures()),
            Ok(_) => panic!("{why}: the request was accepted"),
        }
    }

    #[tokio::test]
    async fn authenticates_a_connect_request_and_yields_the_user_and_target() {
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let (accepted, auth_failures) = accept_connect(&target).await;

        assert_eq!(accepted.inbound, "trojan");
        assert_eq!(accepted.user.as_deref(), Some(TEST_USER));
        assert_eq!(accepted.target, target);
        assert!(
            accepted.replies.success.is_empty(),
            "an encrypted protocol carries no plaintext replies"
        );
        assert_eq!(auth_failures, 0, "a good hash never counts as a failure");
    }

    #[tokio::test]
    async fn parses_an_ipv4_connect_target() {
        let target = ConnectTarget {
            host: "192.0.2.7".into(),
            port: 443,
        };
        let (accepted, _) = accept_connect(&target).await;
        assert_eq!(accepted.target, target);
    }

    #[tokio::test]
    async fn parses_an_ipv6_connect_target() {
        let target = ConnectTarget {
            host: "2001:db8::1".into(),
            port: 53,
        };
        let (accepted, _) = accept_connect(&target).await;
        assert_eq!(accepted.target, target);
    }

    #[tokio::test]
    async fn counts_and_rejects_a_request_with_an_unknown_password_hash() {
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let bytes = preamble("not-the-preshared-key", CMD_CONNECT, &target);
        let (error, auth_failures) = rejected_over_tls(bytes, "wrong password").await;

        assert!(error.contains("no user hash authenticated"), "{error}");
        assert_eq!(auth_failures, 1, "the unknown hash was counted once");
    }

    #[tokio::test]
    async fn rejects_an_authenticated_request_with_an_unsupported_command() {
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let bytes = preamble(TEST_PASSWORD, 0x7f, &target);
        let (error, auth_failures) = rejected_over_tls(bytes, "unknown command").await;

        assert!(error.contains("unsupported command 127"), "{error}");
        assert_eq!(
            auth_failures, 0,
            "the hash authenticated; the command failed"
        );
    }

    #[tokio::test]
    async fn rejects_a_preamble_missing_its_crlf_separator() {
        let mut bytes = password_hash_hex(TEST_PASSWORD).to_vec();
        bytes.extend_from_slice(b"XX");
        let (error, _) = rejected_over_tls(bytes, "missing CRLF").await;
        assert!(error.contains("not CRLF-terminated"), "{error}");
    }

    #[tokio::test]
    async fn rejects_an_unknown_address_type_in_the_request() {
        let mut bytes = password_hash_hex(TEST_PASSWORD).to_vec();
        bytes.extend_from_slice(b"\r\n");
        bytes.push(CMD_CONNECT);
        bytes.push(0x02); // no such SOCKS address type
        let (error, _) = rejected_over_tls(bytes, "unknown address type").await;
        assert!(
            error.contains("unsupported Trojan address type 2"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn errors_instead_of_hanging_on_a_truncated_preamble() {
        let acceptor = test_acceptor();
        let (client_io, server_io) = duplex(64 * 1024);
        // Ten bytes of a 56-byte hash, then a clean TLS close: the exact
        // read must surface EOF as an error, not park forever.
        let client = tokio::spawn(async move {
            let mut tls = tls_client(client_io).await;
            tls.write_all(&password_hash_hex(TEST_PASSWORD)[..10])
                .await
                .expect("write partial hash");
            tls.shutdown().await.expect("close notify");
            tls
        });

        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server_io)))
            .await
            .expect("truncated preamble must not hang");
        assert!(outcome.is_err(), "EOF mid-hash is an error");
        let _client = client.await.expect("client task");
    }

    #[tokio::test]
    async fn fails_the_tls_handshake_on_plaintext_garbage() {
        let acceptor = test_acceptor();
        let (mut client_io, server_io) = duplex(64 * 1024);
        client_io
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("write plaintext garbage");
        drop(client_io);

        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server_io)))
            .await
            .expect("garbage handshake must not hang");
        match outcome {
            Err(error) => assert!(error.contains("Trojan TLS handshake failed"), "{error}"),
            Ok(_) => panic!("plaintext garbage: the request was accepted"),
        }
    }

    #[tokio::test]
    async fn udp_associate_yields_an_authenticated_datagram_face_that_frames_both_ways() {
        let acceptor = test_acceptor();
        let (client_io, server_io) = duplex(64 * 1024);

        // The associate request's own address is a placeholder (trojan
        // spec); every datagram carries its own target.
        let placeholder = ConnectTarget {
            host: "0.0.0.0".into(),
            port: 0,
        };
        let associate = preamble(TEST_PASSWORD, CMD_UDP_ASSOCIATE, &placeholder);
        let query_target = ConnectTarget {
            host: "192.0.2.53".into(),
            port: 53,
        };
        let request_frame =
            encode_udp_frame(&query_target, b"query-bytes").expect("request frame encodes");

        let client = tokio::spawn(async move {
            let mut tls = tls_client(client_io).await;
            tls.write_all(&associate).await.expect("write associate");
            tls.write_all(&request_frame).await.expect("write frame");
            tls.flush().await.expect("flush");
            // Read the framed response the responder writes back, then end
            // the associate cleanly (close_notify -> the receiver's
            // `Ok(None)`).
            let response = read_udp_frame(&mut tls)
                .await
                .expect("read response frame")
                .expect("one response frame");
            tls.shutdown().await.expect("close associate");
            response
        });

        let session = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server_io)))
            .await
            .expect("accept must not hang")
            .expect("authenticated associate accepted");
        let InboundSession::Datagrams(mut face) = session else {
            panic!("UDP associate yields a datagram face");
        };
        assert_eq!(face.user.as_deref(), Some(TEST_USER));

        // The client's frame deframes into a datagram on the connection's
        // constant source.
        let datagram = timeout(HANDSHAKE_TIMEOUT, face.receiver.next())
            .await
            .expect("receive must not hang")
            .expect("deframe ok")
            .expect("one datagram");
        assert_eq!(
            datagram.source, TROJAN_UDP_SOURCE,
            "one connection is one client socket"
        );
        assert_eq!(datagram.target, query_target);
        assert_eq!(datagram.payload, b"query-bytes");

        // A relay response frames back tagged with its origin.
        let origin = ConnectTarget {
            host: "192.0.2.53".into(),
            port: 53,
        };
        timeout(
            HANDSHAKE_TIMEOUT,
            face.responder
                .respond(datagram.source, &origin, b"answer-bytes"),
        )
        .await
        .expect("respond must not hang")
        .expect("response framed");

        let (from, payload) = client.await.expect("client task");
        assert_eq!(from, origin, "the client demuxes replies by origin");
        assert_eq!(payload, b"answer-bytes");

        // The client's close_notify ends the face cleanly at the frame
        // boundary.
        let end = timeout(HANDSHAKE_TIMEOUT, face.receiver.next())
            .await
            .expect("clean end must not hang")
            .expect("clean end");
        assert!(end.is_none(), "a closed associate ends the face");
    }
}
