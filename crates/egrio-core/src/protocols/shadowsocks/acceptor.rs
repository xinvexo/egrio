//! The Shadowsocks server half: the `InboundAcceptor`
//! dual of the connector. On an accepted TCP transport it reads the client
//! salt and the request's first sealed chunk, authenticates the peer by
//! trial-decrypting that chunk against a static user key table, parses the
//! SOCKS target, and hands the plaintext duplex to the unmodified dispatch
//! pipeline as an [`AcceptedStream`] carrying the authenticated `user`.
//!
//! Authentication is the AEAD tag itself: only the user's key opens the first
//! length record, so a valid tag both proves identity and yields the
//! decryptor. A request no key opens is an auth failure — bounded (a fixed
//! salt + one length record is all that was read) and counted (so a host can
//! alarm on it and it can never be turned into an amplifier).
//!
//! A valid tag is necessary but not sufficient: the request salt is a one-time
//! value, so a request whose salt was already seen is a replay of a recorded
//! `salt || length-record || payload-record` prefix, replayed to reopen a
//! session as that user. The acceptor keeps a bounded per-listener window of
//! recently authenticated salts ([`SaltFilter`]) and refuses the second
//! sighting before it opens a session.
//!
//! The loopback gate (`gate.rs`) is this acceptor's exhaustive standing gate;
//! the live constructor is the listener's `CoreInbound::Shadowsocks` arm
//! (`inbound/listener/compose.rs`), which builds one shared acceptor per
//! server deployment and surfaces its auth-failure count on the manager's
//! control surface.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
};
use shadowsocks_crypto::{v1::Cipher, CipherKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::aead2022;
use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{
    AcceptedStream, BoxedInboundStream, InboundAcceptor, InboundFuture, InboundReplyPlan,
    InboundSession,
};
use crate::protocols::shadowsocks::codec::{
    new_encryptor, open_payload, open_udp_packet, random_salt, shadowsocks_key, try_open_length,
    ShadowsocksStream, SHADOWSOCKS_MAX_TCP_CHUNK,
};
use crate::target::{parse_socks_address, ConnectTarget};

/// Recently accepted client salts remembered per listener for replay
/// rejection. Only authenticated handshakes populate the window, so this
/// bounds the freshness state a busy listener keeps — not memory an
/// unauthenticated peer can grow.
const SALT_FILTER_CAPACITY: usize = 8192;

/// A bounded, per-listener window of the client salts recent authenticated
/// requests carried. A Shadowsocks request salt is a one-time random value, so
/// the same salt arriving twice is a replay — a recorded `salt || length-record
/// || payload-record` prefix replayed to reopen an authenticated session as its
/// user. The acceptor records each salt that authenticates
/// and rejects the second sighting.
///
/// Memory is capped at [`SALT_FILTER_CAPACITY`] salts; the oldest is evicted
/// once the window is full. Because only authenticated handshakes record a
/// salt, an unauthenticated peer cannot flood the window to evict a live salt.
/// An aged-out salt is a replay the filter no longer remembers — the reference
/// bloom filter's bounded-window tradeoff, without its false positives.
struct SaltFilter {
    capacity: usize,
    window: Mutex<SaltWindow>,
}

#[derive(Default)]
struct SaltWindow {
    seen: HashSet<Arc<[u8]>>,
    order: VecDeque<Arc<[u8]>>,
}

impl SaltFilter {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            window: Mutex::new(SaltWindow::default()),
        }
    }

    /// Records `salt` and reports whether it was already in the window — a
    /// replay. A fresh salt is inserted, evicting the oldest once the window is
    /// full.
    fn is_replay(&self, salt: &[u8]) -> bool {
        let mut window = self.window.lock().expect("salt filter mutex poisoned");
        if window.seen.contains(salt) {
            return true;
        }
        let salt: Arc<[u8]> = Arc::from(salt);
        window.seen.insert(Arc::clone(&salt));
        window.order.push_back(salt);
        if window.order.len() > self.capacity {
            if let Some(evicted) = window.order.pop_front() {
                window.seen.remove(&evicted);
            }
        }
        false
    }
}

/// One server-side user: a label and the master key its password derives to.
pub(super) struct ShadowsocksUser {
    pub(super) name: Arc<str>,
    pub(super) key: Vec<u8>,
}

/// The static user key table the acceptor authenticates against. One AEAD
/// method per listener; each user is a
/// `(name, password)` the server pre-shares. Trial-decrypting the request's
/// first length record against these keys both authenticates the peer and
/// names the user for the session ledger and UDP flow table.
pub(crate) struct ShadowsocksUserTable {
    method: CipherKind,
    pub(super) users: Vec<ShadowsocksUser>,
    pub(super) context: SharedContext,
}

impl ShadowsocksUserTable {
    pub(crate) fn new(method: CipherKind) -> Self {
        Self {
            method,
            users: Vec::new(),
            context: Context::new_shared(ServerType::Server),
        }
    }

    /// Adds a pre-shared user, deriving its master key once at table build.
    pub(crate) fn with_user(
        mut self,
        name: impl Into<Arc<str>>,
        password: &str,
    ) -> Result<Self, String> {
        let key = if self.method.is_aead_2022() {
            let config = aead2022::Config::new(self.method, password)?;
            if !config.server.identity_keys().is_empty() {
                return Err("Shadowsocks 2022 inbound users require a single PSK; identity chains are outbound-only".into());
            }
            config.server.key().to_vec()
        } else {
            shadowsocks_key(self.method, password)
        };
        let name = name.into();
        if self
            .users
            .iter()
            .any(|user| user.name == name || user.key == key)
        {
            return Err("Shadowsocks inbound users require unique names and keys".into());
        }
        self.users.push(ShadowsocksUser { name, key });
        Ok(self)
    }

    /// The AEAD method every user in this table keys against.
    pub(crate) fn method(&self) -> CipherKind {
        self.method
    }

    /// Trial-decrypts one Shadowsocks UDP packet against every user key: the key
    /// whose AEAD tag opens it authenticates the user and yields the packet's
    /// target and payload. `None` when no user key opens it — an auth failure the
    /// UDP server counts and drops (bounded to one packet, never an
    /// amplifier), the datagram dual of the TCP `try_open_length` probe.
    pub(crate) fn open_udp(&self, packet: &[u8]) -> Option<(Arc<str>, ConnectTarget, Vec<u8>)> {
        self.users.iter().find_map(|user| {
            open_udp_packet(self.method, &user.key, packet)
                .ok()
                .map(|(target, payload)| (Arc::clone(&user.name), target, payload))
        })
    }

    /// Each user's `(name, key)` — the UDP server spawns one response-drain task
    /// per user, sealing that user's replies with the matching key.
    pub(crate) fn user_keys(&self) -> Vec<(Arc<str>, Vec<u8>)> {
        self.users
            .iter()
            .map(|user| (Arc::clone(&user.name), user.key.clone()))
            .collect()
    }
}

/// One Shadowsocks inbound: authenticates against a shared user table and
/// counts the requests no key opened.
pub(crate) struct ShadowsocksAcceptor {
    table: Arc<ShadowsocksUserTable>,
    auth_failures: Arc<AtomicU64>,
    salt_filter: SaltFilter,
}

impl ShadowsocksAcceptor {
    pub(crate) fn new(table: Arc<ShadowsocksUserTable>) -> Self {
        Self {
            table,
            auth_failures: Arc::new(AtomicU64::new(0)),
            salt_filter: SaltFilter::new(SALT_FILTER_CAPACITY),
        }
    }

    /// Requests that reached the acceptor but no user key authenticated (a
    /// host reads the count through [`Self::auth_failures_handle`] to alarm on
    /// credential probing). The gate asserts it moves on a bad key and stays
    /// put on a good one.
    #[cfg(test)]
    pub(crate) fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    /// The shared user table, so a composing listener can stand up the
    /// Shadowsocks UDP inbound (`protocols/shadowsocks/udp.rs`) over the same
    /// pre-shared users this TCP acceptor authenticates against.
    pub(crate) fn user_table(&self) -> Arc<ShadowsocksUserTable> {
        Arc::clone(&self.table)
    }

    /// A shared handle to the auth-failure counter, so the UDP server counts a
    /// probe against the same signal the TCP acceptor does — one Shadowsocks
    /// credential-probing alarm for the port.
    pub(crate) fn auth_failures_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.auth_failures)
    }
}

impl fmt::Debug for ShadowsocksAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowsocksAcceptor")
            .field("users", &self.table.users.len())
            .finish_non_exhaustive()
    }
}

impl InboundAcceptor for ShadowsocksAcceptor {
    fn accept(&self, io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        Box::pin(async move {
            if self.table.method.is_aead_2022() {
                let accepted = aead2022::accept(io, &self.table, &self.auth_failures).await?;
                return Ok(InboundSession::Stream(accepted));
            }
            let accepted =
                accept_shadowsocks_stream(io, &self.table, &self.auth_failures, &self.salt_filter)
                    .await?;
            Ok(InboundSession::Stream(accepted))
        })
    }
}

/// Runs the Shadowsocks server handshake and yields the authenticated proxied
/// stream. Reads are exact and bounded: a salt, one length record, one
/// payload record. A refused connection is discarded until the peer closes
/// it ([`super::discard_until_closed`]).
async fn accept_shadowsocks_stream(
    mut io: BoxedInboundStream,
    table: &ShadowsocksUserTable,
    auth_failures: &AtomicU64,
    salt_filter: &SaltFilter,
) -> Result<AcceptedStream, String> {
    let request = match read_request(&mut io, table, auth_failures, salt_filter).await {
        Ok(request) => request,
        Err(error) => {
            super::discard_until_closed(&mut io).await;
            return Err(error);
        }
    };
    let ShadowsocksRequest {
        user,
        key,
        decryptor,
        target,
        leftover,
    } = request;
    let method = table.method;

    // Answer with the server salt and key the downlink cipher to it, then wrap
    // the transport as the plaintext duplex the dispatcher relays.
    let server_salt = random_salt(method);
    io.write_all(&server_salt)
        .await
        .map_err(|error| error.to_string())?;
    let encryptor = new_encryptor(method, &key, &server_salt);
    let stream = ShadowsocksStream::server(io, method, decryptor, leftover, encryptor);

    Ok(AcceptedStream {
        inbound: "shadowsocks",
        user: Some(user),
        process: ClientOwner::Known(None),
        target,
        io: Box::new(stream),
        // Encrypted protocol: no plaintext replies, failure is a dropped
        // stream. Every reply-plan field stays empty.
        replies: InboundReplyPlan::default(),
        reset: None,
    })
}

/// An authenticated, parsed request: who sent it, their key and the uplink
/// cipher past the first records, the target, and the relay bytes that
/// trailed it.
struct ShadowsocksRequest {
    user: Arc<str>,
    key: Vec<u8>,
    decryptor: Cipher,
    target: ConnectTarget,
    leftover: Vec<u8>,
}

async fn read_request(
    io: &mut BoxedInboundStream,
    table: &ShadowsocksUserTable,
    auth_failures: &AtomicU64,
    salt_filter: &SaltFilter,
) -> Result<ShadowsocksRequest, String> {
    let method = table.method;
    let tag_len = method.tag_len();

    let mut salt = vec![0_u8; method.salt_len()];
    io.read_exact(&mut salt)
        .await
        .map_err(|error| error.to_string())?;

    let mut length_record = vec![0_u8; 2 + tag_len];
    io.read_exact(&mut length_record)
        .await
        .map_err(|error| error.to_string())?;

    // The AEAD tag is the credential: the one user key that opens the length
    // record authenticates the peer and yields the decryptor advanced past it.
    let Some((user, key, mut decryptor, payload_len)) = table.users.iter().find_map(|user| {
        try_open_length(method, &user.key, &salt, &length_record)
            .map(|(cipher, payload_len)| (user.name.clone(), user.key.clone(), cipher, payload_len))
    }) else {
        auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("shadowsocks: no user key authenticated the request".into());
    };

    // The salt is a one-time value, so an authenticated request whose salt was
    // already seen is a replay of a recorded request — the recorded `salt ||
    // length-record || payload-record` prefix replayed to reopen a session as
    // this user. Reject it without counting an auth failure: the peer proved
    // the key, so this is not credential probing.
    if salt_filter.is_replay(&salt) {
        return Err("shadowsocks: replayed request salt".into());
    }

    if payload_len == 0 || payload_len > SHADOWSOCKS_MAX_TCP_CHUNK {
        return Err(format!(
            "shadowsocks: authenticated request length out of range: {payload_len}"
        ));
    }

    let mut payload_record = vec![0_u8; payload_len + tag_len];
    io.read_exact(&mut payload_record)
        .await
        .map_err(|error| error.to_string())?;
    let first_block = open_payload(&mut decryptor, tag_len, payload_record)?;

    // The request's plaintext opens with the SOCKS target; whatever trails it
    // is the first relay bytes and rides into the stream as pending plaintext.
    let (target, address_len) = parse_socks_address(&first_block)?;
    let leftover = first_block[address_len..].to_vec();
    Ok(ShadowsocksRequest {
        user,
        key,
        decryptor,
        target,
        leftover,
    })
}

#[cfg(test)]
mod tests {
    //! Acceptor-face tests over an in-memory duplex: the real in-tree client
    //! codec seals every well-formed handshake (so acceptance proves the two
    //! halves share one wire format), and every malformed or truncated shape
    //! an untrusted peer can send must end in a bounded error — never a
    //! panic, a parked read, or a miscounted auth failure. The loopback gate
    //! (`gate.rs`) owns the full dispatcher pipeline; these pin the handshake
    //! parser and the user-table faces (TCP trial-decrypt, UDP trial-decrypt,
    //! and the direct-drive UDP server composed from them).

    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::{duplex, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout, Duration};

    use super::*;
    use crate::capture::NativeCoreCaptureConfig;
    use crate::egress::NativeCoreEgressConfig;
    use crate::profile::{RouteRule, RuleKind, RuntimeProfile, TrafficPolicyMode};
    use crate::protocols::shadowsocks::codec::{
        connect_client_stream, open_udp_packet, parse_cipher, seal_udp_packet,
    };
    use crate::protocols::shadowsocks::udp::serve_shadowsocks_udp;
    use crate::NativeCoreDevice;

    const TEST_CIPHER: &str = "aes-256-gcm";
    const TEST_USER: &str = "alice";
    const TEST_PASSWORD: &str = "unit-preshared-key";
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    /// Big enough that a whole scripted handshake buffers unread, so the
    /// client and server halves can be driven sequentially over one duplex.
    const DUPLEX_CAPACITY: usize = 256 * 1024;

    fn method() -> CipherKind {
        parse_cipher(TEST_CIPHER).expect("known cipher")
    }

    fn single_user_acceptor() -> ShadowsocksAcceptor {
        ShadowsocksAcceptor::new(Arc::new(
            ShadowsocksUserTable::new(method())
                .with_user(TEST_USER, TEST_PASSWORD)
                .unwrap(),
        ))
    }

    /// Runs the real client half against the acceptor: the client codec seals
    /// `target` + `early_data` as its request over one duplex, and the
    /// acceptor must authenticate and parse it. Returns the client's
    /// plaintext stream (still open, for relay assertions) and the outcome;
    /// the accept future is bounded so a stalled parser fails the test.
    async fn accept_client_handshake(
        acceptor: &ShadowsocksAcceptor,
        password: &str,
        target: &ConnectTarget,
        early_data: &[u8],
    ) -> (
        ShadowsocksStream<DuplexStream>,
        Result<InboundSession, String>,
    ) {
        let (client, server) = duplex(DUPLEX_CAPACITY);
        let key = shadowsocks_key(method(), password);
        let mut request = target.socks_address().expect("encodable target");
        request.extend_from_slice(early_data);
        let client_stream = connect_client_stream(client, method(), &key, &request)
            .await
            .expect("client handshake buffers into the duplex");
        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
            .await
            .expect("shadowsocks accept must not hang");
        (client_stream, outcome)
    }

    /// The client half of [`accept_client_handshake`] for a handshake the
    /// acceptor refuses: a refused connection is held until the peer closes
    /// it (SIP022 section 3.1.4), so the client closes after its request.
    async fn refuse_client_handshake(
        acceptor: &ShadowsocksAcceptor,
        password: &str,
        target: &ConnectTarget,
    ) -> Result<InboundSession, String> {
        let (client, server) = duplex(DUPLEX_CAPACITY);
        let key = shadowsocks_key(method(), password);
        let request = target.socks_address().expect("encodable target");
        let client_stream = connect_client_stream(client, method(), &key, &request)
            .await
            .expect("client handshake buffers into the duplex");
        drop(client_stream);
        timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
            .await
            .expect("a refused handshake ends when the client closes")
    }

    fn accepted_stream(outcome: Result<InboundSession, String>) -> AcceptedStream {
        match outcome.expect("handshake accepted") {
            InboundSession::Stream(stream) => stream,
            InboundSession::Datagrams(_) => panic!("shadowsocks TCP yields a stream session"),
        }
    }

    /// The handshake error, or a panic if the malformed input was accepted.
    fn rejected(outcome: Result<InboundSession, String>, why: &str) -> String {
        match outcome {
            Err(error) => error,
            Ok(_) => panic!("{why}: the handshake was accepted"),
        }
    }

    #[tokio::test]
    async fn accepts_a_real_client_handshake_and_relays_both_directions() {
        let acceptor = single_user_acceptor();
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let (mut client, outcome) =
            accept_client_handshake(&acceptor, TEST_PASSWORD, &target, b"early-flight").await;
        let accepted = accepted_stream(outcome);

        assert_eq!(accepted.inbound, "shadowsocks");
        assert_eq!(accepted.user.as_deref(), Some(TEST_USER));
        assert_eq!(accepted.target, target);
        assert_eq!(acceptor.auth_failures(), 0, "a good handshake never counts");

        // The bytes that trailed the request address surface as the accepted
        // stream's first plaintext (the early-data fold).
        let mut io = accepted.io;
        let mut early = vec![0_u8; b"early-flight".len()];
        timeout(HANDSHAKE_TIMEOUT, io.read_exact(&mut early))
            .await
            .expect("early data must not hang")
            .expect("early data read");
        assert_eq!(&early, b"early-flight");

        // Uplink: a post-handshake client chunk decrypts on the server face.
        client
            .write_all(b"uplink-chunk")
            .await
            .expect("client write");
        let mut uplink = vec![0_u8; b"uplink-chunk".len()];
        timeout(HANDSHAKE_TIMEOUT, io.read_exact(&mut uplink))
            .await
            .expect("uplink must not hang")
            .expect("uplink read");
        assert_eq!(&uplink, b"uplink-chunk");

        // Downlink: the acceptor keyed its reply cipher to the server salt it
        // sent, so the unmodified client codec must open it.
        io.write_all(b"downlink-chunk").await.expect("server write");
        let mut downlink = vec![0_u8; b"downlink-chunk".len()];
        timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut downlink))
            .await
            .expect("downlink must not hang")
            .expect("downlink read");
        assert_eq!(&downlink, b"downlink-chunk");
    }

    #[tokio::test]
    async fn parses_ipv4_and_ipv6_literal_targets() {
        for (host, port) in [("93.184.216.34", 80), ("2001:db8::1", 443)] {
            let acceptor = single_user_acceptor();
            let target = ConnectTarget {
                host: host.into(),
                port,
            };
            let (_client, outcome) =
                accept_client_handshake(&acceptor, TEST_PASSWORD, &target, b"").await;
            assert_eq!(
                accepted_stream(outcome).target,
                target,
                "{host} must round-trip the SOCKS address vocabulary"
            );
        }
    }

    #[tokio::test]
    async fn authenticates_the_matching_user_from_a_multi_user_table() {
        let acceptor = ShadowsocksAcceptor::new(Arc::new(
            ShadowsocksUserTable::new(method())
                .with_user("alice", "alice-key")
                .unwrap()
                .with_user("bob", "bob-key")
                .unwrap(),
        ));
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 80,
        };
        let (_client, outcome) = accept_client_handshake(&acceptor, "bob-key", &target, b"").await;

        assert_eq!(accepted_stream(outcome).user.as_deref(), Some("bob"));
        assert_eq!(acceptor.auth_failures(), 0);
    }

    #[tokio::test]
    async fn rejects_a_wrong_key_client_and_counts_one_auth_failure() {
        let acceptor = single_user_acceptor();
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let outcome = refuse_client_handshake(&acceptor, "not-the-preshared-key", &target).await;

        let error = rejected(outcome, "a wrong key");
        assert!(
            error.contains("no user key authenticated"),
            "auth failure names itself: {error}"
        );
        assert_eq!(acceptor.auth_failures(), 1);

        // The shared acceptor still authenticates a good client afterwards,
        // and the probe's count stays put.
        let (_client, outcome) =
            accept_client_handshake(&acceptor, TEST_PASSWORD, &target, b"").await;
        assert!(outcome.is_ok(), "a good handshake after a probe");
        assert_eq!(acceptor.auth_failures(), 1);
    }

    /// Salt plus one length record announcing `announced`, sealed under the
    /// table's real key — a well-authenticated but protocol-violating first
    /// chunk.
    async fn accept_hand_sealed_length(
        acceptor: &ShadowsocksAcceptor,
        announced: u16,
    ) -> Result<InboundSession, String> {
        let method = method();
        let key = shadowsocks_key(method, TEST_PASSWORD);
        let salt = random_salt(method);
        let mut encryptor = new_encryptor(method, &key, &salt);
        let mut length_record = vec![0_u8; 2 + method.tag_len()];
        length_record[..2].copy_from_slice(&announced.to_be_bytes());
        encryptor.encrypt_packet(&mut length_record);

        let (mut client, server) = duplex(DUPLEX_CAPACITY);
        client.write_all(&salt).await.expect("write salt");
        client
            .write_all(&length_record)
            .await
            .expect("write length record");
        // Refused connections are held until the client closes.
        drop(client);
        timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
            .await
            .expect("shadowsocks accept must not hang")
    }

    #[tokio::test]
    async fn rejects_an_authenticated_out_of_range_length_without_counting_auth() {
        let acceptor = single_user_acceptor();

        let error = rejected(
            accept_hand_sealed_length(&acceptor, 0).await,
            "a zero-length first chunk",
        );
        assert!(error.contains("length out of range"), "got: {error}");

        let error = rejected(
            accept_hand_sealed_length(&acceptor, (SHADOWSOCKS_MAX_TCP_CHUNK + 1) as u16).await,
            "an over-cap first chunk",
        );
        assert!(error.contains("length out of range"), "got: {error}");

        // The peer held the key: a protocol violation is not credential
        // probing, so the alarm counter must not move.
        assert_eq!(acceptor.auth_failures(), 0);
    }

    #[tokio::test]
    async fn rejects_a_corrupted_payload_record_after_a_valid_length_record() {
        let acceptor = single_user_acceptor();
        let method = method();
        let key = shadowsocks_key(method, TEST_PASSWORD);
        let salt = random_salt(method);
        let mut encryptor = new_encryptor(method, &key, &salt);
        let mut length_record = vec![0_u8; 2 + method.tag_len()];
        length_record[..2].copy_from_slice(&5_u16.to_be_bytes());
        encryptor.encrypt_packet(&mut length_record);

        let (mut client, server) = duplex(DUPLEX_CAPACITY);
        client.write_all(&salt).await.expect("write salt");
        client
            .write_all(&length_record)
            .await
            .expect("write length record");
        // The announced 5-byte payload record arrives, but its AEAD tag is
        // wrong: an in-window tamper after a valid authentication.
        client
            .write_all(&vec![0xAA_u8; 5 + method.tag_len()])
            .await
            .expect("write corrupted payload record");
        drop(client);

        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
            .await
            .expect("shadowsocks accept must not hang");

        let error = rejected(outcome, "a corrupted payload record");
        assert!(error.contains("payload auth failed"), "got: {error}");
        assert_eq!(
            acceptor.auth_failures(),
            0,
            "the peer proved the key; a tampered record is not credential probing"
        );
    }

    /// SIP022 section 3.1.4: whatever the length of a probe, the server keeps
    /// the connection while the prober waits and, once the prober closes,
    /// closes with a FIN, never an RST that would show how much it read.
    #[tokio::test]
    async fn a_refused_probe_of_any_length_is_held_and_closed_with_a_fin() {
        let acceptor = Arc::new(single_user_acceptor());
        let method = method();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        for length in [1, method.salt_len() - 1, method.salt_len() + 1, 200, 50_000] {
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
            let outcome = timeout(HANDSHAKE_TIMEOUT, refused).await.unwrap().unwrap();
            assert!(outcome.is_err(), "a {length}-byte probe is refused");
            let read = timeout(HANDSHAKE_TIMEOUT, prober.read(&mut byte))
                .await
                .unwrap();
            assert!(
                matches!(read, Ok(0)),
                "a {length}-byte probe ends with a FIN, got {read:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_a_garbage_handshake_as_one_counted_auth_failure() {
        let acceptor = single_user_acceptor();
        let method = method();
        let (mut client, server) = duplex(DUPLEX_CAPACITY);
        // A fixed pattern shaped like salt + length record: no user key's
        // AEAD tag opens it, deterministically.
        let garbage = vec![0xAA_u8; method.salt_len() + 2 + method.tag_len()];
        client.write_all(&garbage).await.expect("write garbage");
        drop(client);

        let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
            .await
            .expect("shadowsocks accept must not hang");

        let error = rejected(outcome, "a garbage handshake");
        assert!(error.contains("no user key authenticated"), "got: {error}");
        assert_eq!(acceptor.auth_failures(), 1);
    }

    /// The exact bytes a client puts on the wire for one handshake to
    /// `target`: the clear salt, then the sealed length and payload records of
    /// the SOCKS request. This is the `salt || length-record || payload-record`
    /// prefix an attacker captures off the wire to replay.
    fn recorded_handshake(target: &ConnectTarget, password: &str) -> Vec<u8> {
        let method = method();
        let tag_len = method.tag_len();
        let key = shadowsocks_key(method, password);
        let salt = random_salt(method);
        let mut encryptor = new_encryptor(method, &key, &salt);

        let request = target.socks_address().expect("encodable target");
        let mut length_record = vec![0_u8; 2 + tag_len];
        length_record[..2].copy_from_slice(&(request.len() as u16).to_be_bytes());
        encryptor.encrypt_packet(&mut length_record);
        let mut payload_record = vec![0_u8; request.len() + tag_len];
        payload_record[..request.len()].copy_from_slice(&request);
        encryptor.encrypt_packet(&mut payload_record);

        let mut wire = salt;
        wire.extend_from_slice(&length_record);
        wire.extend_from_slice(&payload_record);
        wire
    }

    /// Feeds pre-recorded handshake bytes to the acceptor over a fresh duplex,
    /// bounding the accept so a stalled parser fails the test instead of
    /// hanging it.
    async fn accept_recorded(
        acceptor: &ShadowsocksAcceptor,
        recorded: &[u8],
    ) -> Result<InboundSession, String> {
        let (mut client, server) = duplex(DUPLEX_CAPACITY);
        client
            .write_all(recorded)
            .await
            .expect("write recorded handshake");
        let accept = acceptor.accept(Box::new(server));
        tokio::pin!(accept);
        // An accepted handshake answers while the client is connected; a
        // refused one is held until the client closes.
        if let Ok(outcome) = timeout(Duration::from_millis(300), &mut accept).await {
            return outcome;
        }
        drop(client);
        timeout(HANDSHAKE_TIMEOUT, accept)
            .await
            .expect("a refused handshake ends when the client closes")
    }

    #[tokio::test]
    async fn rejects_a_replayed_handshake_recording_without_counting_auth() {
        let acceptor = single_user_acceptor();
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let recorded = recorded_handshake(&target, TEST_PASSWORD);

        // First sighting: a well-formed handshake authenticates and parses.
        let accepted = accepted_stream(accept_recorded(&acceptor, &recorded).await);
        assert_eq!(accepted.target, target);
        assert_eq!(accepted.user.as_deref(), Some(TEST_USER));

        // The very same bytes again: the salt was already seen, so this is a
        // replay of a recorded request and must be refused — no second session
        // opens for the same salt.
        let error = rejected(
            accept_recorded(&acceptor, &recorded).await,
            "a replayed handshake recording",
        );
        assert!(error.contains("replayed request salt"), "got: {error}");

        // A replay is not credential probing — the peer held the key — so the
        // auth-failure alarm never moves.
        assert_eq!(acceptor.auth_failures(), 0);

        // A fresh handshake (new random salt) still authenticates on the same
        // shared acceptor: the filter rejects replays, not new sessions.
        let fresh = recorded_handshake(&target, TEST_PASSWORD);
        assert!(
            accept_recorded(&acceptor, &fresh).await.is_ok(),
            "a fresh salt still authenticates after a replay is refused"
        );
    }

    #[tokio::test]
    async fn errors_without_hanging_when_the_client_closes_mid_handshake() {
        let method = method();
        let key = shadowsocks_key(method, TEST_PASSWORD);

        let truncated_salt = vec![0x5A_u8; method.salt_len() / 2];
        let truncated_length_record = {
            let mut bytes = random_salt(method);
            bytes.extend_from_slice(&[0x5A_u8; 3]);
            bytes
        };
        // A fully authenticated length record whose payload never arrives.
        let missing_payload_record = {
            let salt = random_salt(method);
            let mut encryptor = new_encryptor(method, &key, &salt);
            let mut length_record = vec![0_u8; 2 + method.tag_len()];
            length_record[..2].copy_from_slice(&5_u16.to_be_bytes());
            encryptor.encrypt_packet(&mut length_record);
            let mut bytes = salt;
            bytes.extend_from_slice(&length_record);
            bytes
        };

        for (name, prefix) in [
            ("a truncated salt", truncated_salt),
            ("a truncated length record", truncated_length_record),
            ("a missing payload record", missing_payload_record),
        ] {
            let acceptor = single_user_acceptor();
            let (mut client, server) = duplex(DUPLEX_CAPACITY);
            client.write_all(&prefix).await.expect("write prefix");
            drop(client); // EOF mid-handshake.

            let outcome = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(Box::new(server)))
                .await
                .unwrap_or_else(|_| panic!("accept hung on {name}"));
            assert!(outcome.is_err(), "{name} must be rejected");
            assert_eq!(
                acceptor.auth_failures(),
                0,
                "{name} is an IO error, not a counted credential probe"
            );
        }
    }

    #[test]
    fn udp_table_opens_a_packet_only_for_the_key_that_sealed_it() {
        let method = method();
        let table = ShadowsocksUserTable::new(method)
            .with_user("alice", "alice-key")
            .unwrap()
            .with_user("bob", "bob-key")
            .unwrap();
        let target = ConnectTarget {
            host: "10.1.2.3".into(),
            port: 53,
        };
        let packet = seal_udp_packet(
            method,
            &shadowsocks_key(method, "bob-key"),
            &target,
            b"query",
        )
        .expect("seal");

        let (user, opened_target, payload) = table.open_udp(&packet).expect("bob's key opens");
        assert_eq!(&*user, "bob");
        assert_eq!(opened_target, target);
        assert_eq!(payload, b"query");

        let foreign = seal_udp_packet(
            method,
            &shadowsocks_key(method, "mallory-key"),
            &target,
            b"query",
        )
        .expect("seal");
        assert!(
            table.open_udp(&foreign).is_none(),
            "unknown keys never open"
        );
        assert!(
            table.open_udp(&[0xAA_u8; 8]).is_none(),
            "short garbage never opens"
        );
        assert!(table.open_udp(&[]).is_none(), "an empty packet never opens");
    }

    fn match_direct_device() -> NativeCoreDevice {
        let mut profile = RuntimeProfile::new("shadowsocks-acceptor-tests");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let device = NativeCoreDevice::compile_with_egress_and_capture(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
        );
        device.start();
        device
    }

    async fn spawn_udp_echo() -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
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

    #[tokio::test]
    async fn udp_face_survives_profile_switch_and_counts_a_garbage_packet() {
        let echo_addr = spawn_udp_echo().await;
        let acceptor = single_user_acceptor();
        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind ss udp server"),
        );
        let server_addr = server_socket.local_addr().expect("ss udp server addr");
        // The direct-drive UDP face composed exactly as a listener would:
        // over the TCP acceptor's shared user table and failure counter.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_device = match_direct_device();
        let serve = tokio::spawn(serve_shadowsocks_udp(
            Arc::clone(&server_socket),
            server_device.clone(),
            acceptor.user_table(),
            acceptor.auth_failures_handle(),
            shutdown_rx,
        ));

        let method = method();
        let key = shadowsocks_key(method, TEST_PASSWORD);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp client");
        client.connect(server_addr).await.expect("connect client");
        let echo_target = ConnectTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let packet =
            seal_udp_packet(method, &key, &echo_target, b"ss-udp-ping").expect("seal request");
        client.send(&packet).await.expect("send datagram");

        // The response comes back sealed under the same user key and names
        // its origin flow.
        let mut buffer = vec![0_u8; 2048];
        let read = timeout(Duration::from_secs(10), client.recv(&mut buffer))
            .await
            .expect("udp response must not hang")
            .expect("udp response");
        let (origin, payload) =
            open_udp_packet(method, &key, &buffer[..read]).expect("client key opens the reply");
        assert_eq!(payload, b"ss-udp-ping");
        assert_eq!(origin, echo_target);

        let mut next = RuntimeProfile::new("shadowsocks-after-switch");
        next.traffic_policy_mode = TrafficPolicyMode::Direct;
        server_device.apply_profile(&next);
        let packet = seal_udp_packet(method, &key, &echo_target, b"after-switch").unwrap();
        client.send(&packet).await.unwrap();
        let read = timeout(Duration::from_secs(10), client.recv(&mut buffer))
            .await
            .expect("the UDP listener admits the new connection generation")
            .unwrap();
        let (origin, payload) = open_udp_packet(method, &key, &buffer[..read]).unwrap();
        assert_eq!(payload, b"after-switch");
        assert_eq!(origin, echo_target);

        // A packet no key opens is counted on the same alarm the TCP face
        // uses, and never answered (no amplification).
        client.send(&[0xAA_u8; 64]).await.expect("send garbage");
        let mut failures = 0;
        for _ in 0..250 {
            failures = acceptor.auth_failures();
            if failures >= 1 {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(failures, 1, "the garbage datagram was counted once");
        shutdown_tx.send(true).expect("signal UDP server shutdown");
        serve.await.expect("UDP server reaches release barrier");
        server_device.close();
        drop(server_socket);
        UdpSocket::bind(server_addr)
            .await
            .expect("completed UDP server releases every socket clone");
    }
}
