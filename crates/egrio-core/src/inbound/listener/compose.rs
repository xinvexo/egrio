//! Inbound composition: which inbound wire protocol a listener terminates,
//! built from its configuration before any socket binds, so a bad cipher, bad
//! certificate material or an empty user table fails the start instead of
//! leaving a bound socket.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::net::TcpStream;

#[cfg(feature = "server")]
use crate::certificate::server_config_from_pem;
use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
use crate::inbound::dispatch::accept_mixed_session;
#[cfg(feature = "server")]
use crate::protocols::hysteria2::{Hysteria2Acceptor, Hysteria2UserTable};
use crate::protocols::shadowsocks::acceptor::{ShadowsocksAcceptor, ShadowsocksUserTable};
use crate::protocols::shadowsocks::codec::parse_cipher;
#[cfg(feature = "server")]
use crate::protocols::trojan::{TrojanAcceptor, TrojanUserTable};

/// A Hysteria2 QUIC/H3 server inbound: where to bind
/// the QUIC endpoint, the operator's PEM certificate chain and private key the
/// certificate subsystem terminates TLS with, and the pre-shared `(name, auth)`
/// users the acceptor authenticates over HTTP/3. Plain data, so it compiles in
/// every build; only actually running it needs the `server` feature.
#[derive(Debug, Clone)]
pub struct Hysteria2Inbound {
    pub listen_addr: SocketAddr,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub users: Vec<(String, String)>,
}

/// Which inbound wire protocol the listener's accept loop terminates: a
/// deployment's role is the acceptors it composes, so this
/// is the assembly's inbound selector, not a mode flag.
#[derive(Debug, Clone, Default)]
pub enum CoreInbound {
    /// SOCKS5 + HTTP CONNECT, chosen per connection by a first-byte peek. No
    /// inbound authentication — the local capture facade and the trusted
    /// compat proxy both use it.
    #[default]
    Mixed,
    /// One Shadowsocks AEAD inbound authenticating against a pre-shared user
    /// table. `cipher` is the Clash method name
    /// (`aes-256-gcm`, `chacha20-ietf-poly1305`, …); `users` are the
    /// `(name, password)` credentials the acceptor trial-decrypts against.
    Shadowsocks {
        cipher: String,
        users: Vec<(String, String)>,
    },
    /// One Trojan-over-TLS inbound authenticating against a pre-shared user
    /// table. `cert_pem`/`key_pem` are the operator's
    /// PEM material the certificate subsystem terminates TLS with; `users` are
    /// the `(name, password)` credentials the acceptor authenticates by their
    /// `hex(SHA224(password))` hash. Like the Hysteria2 inbound it terminates
    /// on the main TCP listener (unlike Hysteria2's own QUIC endpoint), and
    /// running it needs the `server` feature; the plain data compiles anywhere.
    Trojan {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        users: Vec<(String, String)>,
    },
}

/// The composed inbound the accept loop drives. Cheap to clone per accepted
/// connection: an encrypted arm shares one acceptor (and its user table and
/// auth-failure counter) across every session through an `Arc`.
#[derive(Clone)]
pub(super) enum InboundStrategy {
    Mixed,
    Shadowsocks(Arc<ShadowsocksAcceptor>),
    #[cfg(feature = "server")]
    Trojan(Arc<TrojanAcceptor>),
}

impl InboundStrategy {
    /// Runs one connection's protocol handshake and yields the accepted
    /// session. The accept loop bounds this with the inbound handshake timeout
    /// and reads the peer address first.
    pub(super) async fn accept(&self, client: TcpStream) -> Result<InboundSession, String> {
        match self {
            InboundStrategy::Mixed => accept_mixed_session(client).await,
            InboundStrategy::Shadowsocks(acceptor) => acceptor.accept(Box::new(client)).await,
            #[cfg(feature = "server")]
            InboundStrategy::Trojan(acceptor) => acceptor.accept(Box::new(client)).await,
        }
    }
}

/// A stream inbound with what its listener and the control surface need
/// beside the accept loop.
pub(super) struct ComposedInbound {
    pub(super) strategy: InboundStrategy,
    /// Failed authentications of an encrypted inbound.
    pub(super) auth_failures: Option<Arc<AtomicU64>>,
    /// The Shadowsocks users and their auth-failure counter, shared with the
    /// UDP server that rides the same port.
    pub(super) shadowsocks_udp: Option<(Arc<ShadowsocksUserTable>, Arc<AtomicU64>)>,
}

/// Composes the stream inbound, deriving its user keys once. An encrypted
/// inbound with no users could authenticate no one, so it is refused.
pub(super) fn compose_inbound(inbound: CoreInbound) -> Result<ComposedInbound, String> {
    match inbound {
        CoreInbound::Mixed => Ok(ComposedInbound {
            strategy: InboundStrategy::Mixed,
            auth_failures: None,
            shadowsocks_udp: None,
        }),
        CoreInbound::Shadowsocks { cipher, users } => {
            if users.is_empty() {
                return Err("Shadowsocks inbound requires at least one user".into());
            }
            let method = parse_cipher(&cipher)?;
            let mut table = ShadowsocksUserTable::new(method);
            for (name, password) in &users {
                table = table.with_user(name.clone(), password)?;
            }
            let acceptor = Arc::new(ShadowsocksAcceptor::new(Arc::new(table)));
            let auth_failures = acceptor.auth_failures_handle();
            Ok(ComposedInbound {
                auth_failures: Some(Arc::clone(&auth_failures)),
                shadowsocks_udp: Some((acceptor.user_table(), auth_failures)),
                strategy: InboundStrategy::Shadowsocks(acceptor),
            })
        }
        CoreInbound::Trojan {
            cert_pem,
            key_pem,
            users,
        } => compose_trojan(cert_pem, key_pem, users),
    }
}

/// Parses the operator PEM into a TLS server config and derives the user
/// table. Server-only (TLS termination); a non-server build rejects a Trojan
/// inbound rather than silently dropping it.
#[cfg(feature = "server")]
fn compose_trojan(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    users: Vec<(String, String)>,
) -> Result<ComposedInbound, String> {
    if users.is_empty() {
        return Err("Trojan inbound requires at least one user".into());
    }
    // Trojan advertises no ALPN by default (unlike the Hysteria2 `h3` endpoint);
    // an operator who fronts it behind an ALPN-sniffing proxy sets it clientside.
    let tls = server_config_from_pem(&cert_pem, &key_pem, &[])?;
    let mut table = TrojanUserTable::new();
    for (name, password) in &users {
        table = table.with_user(name.clone(), password);
    }
    let acceptor = Arc::new(TrojanAcceptor::new(tls, table));
    Ok(ComposedInbound {
        auth_failures: Some(acceptor.auth_failures_handle()),
        shadowsocks_udp: None,
        strategy: InboundStrategy::Trojan(acceptor),
    })
}

#[cfg(not(feature = "server"))]
fn compose_trojan(
    _cert_pem: Vec<u8>,
    _key_pem: Vec<u8>,
    _users: Vec<(String, String)>,
) -> Result<ComposedInbound, String> {
    Err("Trojan inbound requires the `server` feature to terminate TLS".into())
}

/// Builds and binds a Hysteria2 QUIC/H3 inbound from its config: parses the
/// operator's PEM material into a TLS server config,
/// derives the pre-shared user table, and binds the QUIC endpoint. Fails fast
/// before the manager marks itself running — an empty user table would
/// authenticate no one, and bad cert material or a taken port must surface as
/// a start error, not a half-started listener.
#[cfg(feature = "server")]
pub(super) fn build_hysteria2_inbound(
    inbound: Hysteria2Inbound,
) -> Result<(Arc<Hysteria2Acceptor>, quinn::Endpoint), String> {
    if inbound.users.is_empty() {
        return Err("Hysteria2 inbound requires at least one user".into());
    }
    let tls = server_config_from_pem(&inbound.cert_pem, &inbound.key_pem, &[b"h3"])?;
    let mut users = Hysteria2UserTable::new();
    for (name, auth) in &inbound.users {
        users = users.with_user(name.clone(), auth);
    }
    let acceptor = Arc::new(Hysteria2Acceptor::new(tls, users)?);
    let endpoint = acceptor.bind(inbound.listen_addr)?;
    Ok((acceptor, endpoint))
}
