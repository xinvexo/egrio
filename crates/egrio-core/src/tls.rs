//! Shared client-side TLS: one rustls `ClientConfig` builder the encrypted
//! outbound connectors reuse, so the security-sensitive certificate
//! verification policy — including the dangerous skip-verify path a profile can
//! opt into — is written once rather than per protocol. The aws-lc-rs provider
//! is pinned to match the rest of the core's TLS (`certificate.rs`, the
//! Hysteria2 QUIC stack); the Shadowsocks ciphers link aws-lc already.
//!
//! Server-side TLS has its own home (`certificate.rs`, the PEM loader behind the
//! `server` feature); this is only the client half every proxy hop dials with.
//!
//! A proxy node's TLS settings are read here once ([`TlsClientOptions`]) and a
//! stream hop handshakes through [`TlsClient`], so Trojan, Hysteria2's QUIC and
//! the HTTP and SOCKS5 hops with `tls: true` share one option vocabulary and
//! one refusal of the trust options none of them implements.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::outbound::options::{option_bool, option_string, option_string_list};

/// A proxy node's TLS client settings under Clash's aliases.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TlsClientOptions {
    /// `sni`, `servername` or `server-name`; the hop uses the node's host
    /// when none is given.
    pub(crate) server_name: Option<String>,
    /// `skip-cert-verify` and its aliases: accept any certificate.
    pub(crate) insecure: bool,
    pub(crate) alpn: Vec<Vec<u8>>,
}

impl TlsClientOptions {
    pub(crate) fn from_node(options: &JsonValue) -> Self {
        Self {
            server_name: option_string(options, &["sni", "servername", "server-name"]),
            insecure: option_bool(
                options,
                &[
                    "skip-cert-verify",
                    "skip-cert-verification",
                    "allow-insecure",
                    "insecure",
                ],
            )
            .unwrap_or(false),
            alpn: option_string_list(options, "alpn")
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        }
    }
}

/// Trust options no TLS hop implements, which must fail loudly rather than be
/// dropped: ignoring a certificate pin, a client certificate or an ECH config
/// would connect with weaker guarantees than the profile asked for.
pub(crate) fn unsupported_trust_options(options: &JsonValue) -> Vec<&'static str> {
    let mut unsupported = Vec::new();
    if option_string(options, &["fingerprint"]).is_some() {
        unsupported.push("fingerprint");
    }
    if option_string(options, &["certificate"]).is_some() {
        unsupported.push("certificate");
    }
    if option_string(options, &["private-key", "private_key"]).is_some() {
        unsupported.push("private-key");
    }
    if options
        .get("ech-opts")
        .is_some_and(|value| !value.is_null())
    {
        unsupported.push("ech-opts");
    }
    unsupported
}

/// One stream hop's TLS client: the config built once per node and shared by
/// every dial (so session resumption spans its flows), and the validated
/// server name.
pub(crate) struct TlsClient {
    connector: TlsConnector,
    name: String,
    server_name: ServerName<'static>,
}

impl TlsClient {
    pub(crate) fn new(host: &str, options: &TlsClientOptions) -> Result<Self, String> {
        let name = options
            .server_name
            .clone()
            .unwrap_or_else(|| host.to_string());
        let server_name = ServerName::try_from(name.clone())
            .map_err(|error| format!("invalid TLS server name '{name}': {error}"))?;
        Ok(Self {
            connector: TlsConnector::from(node_client_config(options.insecure, &options.alpn)),
            name,
            server_name,
        })
    }

    /// The server name the handshake presents.
    pub(crate) fn server_name(&self) -> &str {
        &self.name
    }

    #[cfg(test)]
    pub(crate) fn alpn(&self) -> &[Vec<u8>] {
        &self.connector.config().alpn_protocols
    }

    pub(crate) async fn connect<IO>(&self, io: IO) -> io::Result<ClientTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let transport = Transport { io, closed: false };
        let inner = self
            .connector
            .connect(self.server_name.clone(), transport)
            .await?;
        Ok(ClientTlsStream { inner })
    }
}

impl fmt::Debug for TlsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClient")
            .field("server_name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A client TLS stream that reads its node closing the transport without
/// close_notify as the end of the stream. Proxy servers commonly end a tunnel
/// that way once its target closes (Go's crypto/tls, behind most of them,
/// reads it as EOF); rustls reports it as `UnexpectedEof`, which would fail
/// every such flow after its data arrived. Only a clean close of the
/// transport counts: an error from below, such as a lower hop's truncated
/// frame, still fails the read.
pub(crate) struct ClientTlsStream<IO> {
    inner: TlsStream<Transport<IO>>,
}

impl<IO> ClientTlsStream<IO> {
    /// The transport under the TLS session.
    pub(crate) fn transport_mut(&mut self) -> &mut IO {
        &mut self.inner.get_mut().0.io
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientTlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::UnexpectedEof
                    && this.inner.get_ref().0.closed =>
            {
                Poll::Ready(Ok(()))
            }
            read => read,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientTlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The transport under a [`ClientTlsStream`], noting when a read finds it
/// closed.
struct Transport<IO> {
    io: IO,
    closed: bool,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Transport<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let read = Pin::new(&mut this.io).poll_read(cx, buf);
        if matches!(read, Poll::Ready(Ok(())))
            && buf.filled().len() == filled
            && buf.remaining() > 0
        {
            this.closed = true;
        }
        read
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Transport<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Builds a client config trusting the webpki root store — or, when `insecure`,
/// accepting any certificate (the `skip-cert-verify` escape hatch some profiles
/// need) — advertising `alpn`. Pins the aws-lc-rs crypto provider so QUIC and
/// TCP hops share one TLS backend. Its key exchange prefers the X25519MLKEM768
/// hybrid, as browsers now do, whose key share takes the ClientHello over one
/// QUIC Initial datagram: two of them let a server send a first flight up to
/// three times their size before it has validated the client's address (RFC
/// 9000 section 8.1). A certificate chain larger than that allowance can
/// otherwise add a round trip while the server waits for acknowledgement.
///
/// The sessions it keeps to resume are rustls's default, 256 of them for up
/// to 32 servers: a config that reaches several, as the DNS transports and
/// the probes do.
pub(crate) fn client_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    build_client_config(insecure, alpn, None)
}

/// [`client_config`] for a proxy node's hop, which handshakes with that one
/// server: it keeps one server's sessions.
///
/// A profile compiles a config for each of its TLS nodes, used or not, so
/// what a config holds before its first handshake is multiplied by the
/// node count. rustls allocates the session store for its capacity at once
/// (`ClientSessionMemoryCache::new`, a map and a queue for 32 servers).
/// Sharing trust roots and the provider and keeping one server's sessions
/// bounds each node's extra state to what its hop uses.
pub(crate) fn node_client_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    build_client_config(insecure, alpn, Some(ONE_SERVER_SESSIONS))
}

/// The sessions rustls keeps for one server: up to eight TLS 1.3 tickets
/// (`MAX_TLS13_TICKETS_PER_SERVER` in its `client/handy.rs`), and any store
/// of one to eight sessions remembers one server.
const ONE_SERVER_SESSIONS: usize = 8;

fn build_client_config(
    insecure: bool,
    alpn: &[Vec<u8>],
    sessions: Option<usize>,
) -> Arc<ClientConfig> {
    // One provider and one set of trust roots for every config: both are
    // the same for all of them and neither changes.
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    let provider = PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs provider supports the safe default TLS versions");
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let roots = ROOTS
            .get_or_init(|| {
                let mut roots = RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(roots)
            })
            .clone();
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.to_vec();
    // The store is the config's own: a session made by a config that skips
    // verification must not be resumed by one that verifies.
    if let Some(sessions) = sessions {
        config.resumption = rustls::client::Resumption::in_memory_sessions(sessions);
    }
    Arc::new(config)
}

/// The `skip-cert-verify` verifier: accepts any certificate and signature. Only
/// reachable when a profile explicitly opts in (`insecure`); the default path
/// verifies against the webpki roots.
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signed: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signed: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    /// What a config holds for itself is what a profile pays per TLS node:
    /// the provider is one for all of them, and a node's config resumes with
    /// its own sessions, never another config's.
    #[test]
    fn configs_share_the_provider_and_keep_their_own_sessions() {
        let node = node_client_config(false, &[]);
        let insecure_node = node_client_config(true, &[b"h2".to_vec()]);
        let many = client_config(false, &[b"http/1.1".to_vec()]);
        assert!(Arc::ptr_eq(
            node.crypto_provider(),
            insecure_node.crypto_provider()
        ));
        assert!(Arc::ptr_eq(node.crypto_provider(), many.crypto_provider()));
        assert_eq!(insecure_node.alpn_protocols, [b"h2".to_vec()]);
        // Each call builds a config of its own, sessions with it.
        assert!(!Arc::ptr_eq(&node, &node_client_config(false, &[])));
    }

    /// A TLS server at the other end of `io` that sends `reply` and then
    /// closes the transport without close_notify, as Go-based proxy servers
    /// end a tunnel.
    async fn reply_and_close_bare(io: DuplexStream, reply: &'static [u8]) {
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("self-signed cert");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
            )
            .expect("server config");
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(io)
            .await
            .expect("server handshake");
        tls.write_all(reply).await.expect("reply");
        tls.flush().await.expect("flush");
        drop(tls.into_inner().0);
    }

    fn insecure_client() -> TlsClient {
        let options = TlsClientOptions {
            insecure: true,
            ..Default::default()
        };
        TlsClient::new("localhost", &options).expect("client")
    }

    #[tokio::test]
    async fn a_node_closing_without_close_notify_ends_the_stream() {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(reply_and_close_bare(server_io, b"tunnel data"));
        let mut stream = insecure_client()
            .connect(client_io)
            .await
            .expect("handshake");
        let mut received = Vec::new();
        stream
            .read_to_end(&mut received)
            .await
            .expect("a bare close ends the stream");
        assert_eq!(received, b"tunnel data");
        server.await.expect("server");
    }

    /// A transport whose end is an error, as a lower hop reports a
    /// truncated frame.
    struct Truncated(DuplexStream);

    impl AsyncRead for Truncated {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let filled = buf.filled().len();
            std::task::ready!(Pin::new(&mut self.get_mut().0).poll_read(cx, buf))?;
            if buf.filled().len() == filled {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "lower hop frame truncated",
                )));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Truncated {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn an_error_below_the_tls_session_still_fails_the_read() {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(reply_and_close_bare(server_io, b"tunnel data"));
        let mut stream = insecure_client()
            .connect(Truncated(client_io))
            .await
            .expect("handshake");
        let mut received = Vec::new();
        let error = stream
            .read_to_end(&mut received)
            .await
            .expect_err("the transport's error fails the read");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(error.to_string(), "lower hop frame truncated");
        assert_eq!(received, b"tunnel data");
        server.await.expect("server");
    }

    #[test]
    fn node_options_read_every_alias() {
        for key in [
            "skip-cert-verify",
            "skip-cert-verification",
            "allow-insecure",
            "insecure",
        ] {
            assert!(
                TlsClientOptions::from_node(&json!({ key: true })).insecure,
                "{key}"
            );
        }
        for key in ["sni", "servername", "server-name"] {
            let options = TlsClientOptions::from_node(&json!({ key: "front.example" }));
            assert_eq!(
                options.server_name.as_deref(),
                Some("front.example"),
                "{key}"
            );
        }
        assert_eq!(
            TlsClientOptions::from_node(&json!({"alpn": ["h2", "http/1.1"]})).alpn,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn trust_options_no_hop_implements_are_named() {
        let options = json!({"fingerprint": "ab:cd", "ech-opts": {"enable": true}, "sni": "x"});
        assert_eq!(
            unsupported_trust_options(&options),
            ["fingerprint", "ech-opts"]
        );
        assert!(unsupported_trust_options(&json!({"client-fingerprint": "chrome"})).is_empty());
    }
}
