//! The carrier under a stream protocol's framing: the connection to the
//! proxy — TCP from this host, or a stream through the node's dialer-proxy —
//! inside TLS when the node asks for it. Protocols frame their requests over
//! whatever this returns, so a carrier added here (a WebSocket or gRPC
//! transport) serves every stream protocol at once.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde_json::Value as JsonValue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::egress::EgressRuntime;
use crate::outbound::options::option_bool;
use crate::outbound::{BoxedOutboundStream, Dialer, Hop, OutboundError, OutboundStage};
use crate::target::ConnectTarget;
use crate::tls::{unsupported_trust_options, TlsClient, TlsClientOptions};

/// A node's connection to its own server.
pub(crate) enum ServerStream {
    /// TCP from this host.
    Tcp(TcpStream),
    /// A stream through the node's dialer-proxy.
    Chained(BoxedOutboundStream),
}

impl ServerStream {
    /// The server's address, when this host connected to it.
    pub(crate) fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr().ok(),
            Self::Chained(_) => None,
        }
    }
}

/// Dials a node's server at `host:port` the way `dialer` says; `ahead` for a
/// connection that will hold it for long, whose path is dialed as one ahead
/// of need is (see `EgressRuntime::connect_tcp_host_ahead`). `label` names
/// the hop in errors.
pub(crate) async fn dial_server(
    egress: &EgressRuntime,
    dialer: &Dialer,
    host: &str,
    port: u16,
    label: &'static str,
    ahead: bool,
) -> Result<ServerStream, OutboundError> {
    let server = ConnectTarget {
        host: host.to_owned(),
        port,
    };
    let hop = dialer.hop(egress, &server)?;
    dial_server_via(egress, hop.as_ref(), server, label, ahead).await
}

/// [`dial_server`] through `hop`, already resolved, or from this host.
async fn dial_server_via(
    egress: &EgressRuntime,
    hop: Option<&Hop>,
    server: ConnectTarget,
    label: &'static str,
    ahead: bool,
) -> Result<ServerStream, OutboundError> {
    if let Some(hop) = hop {
        return hop.stream(&server).await.map(ServerStream::Chained);
    }
    let tcp = if ahead {
        egress
            .connect_tcp_host_ahead(&server.host, server.port, label)
            .await
    } else {
        egress
            .connect_tcp_host(&server.host, server.port, label)
            .await
    };
    tcp.map(ServerStream::Tcp).map_err(OutboundError::hop_dial)
}

/// Dials the carrier and returns it with the proxy's address when this host
/// connected to it, which a SOCKS5 relay endpoint may name only implicitly.
/// `label` names the hop in errors.
pub(crate) async fn dial_carrier(
    egress: &EgressRuntime,
    dialer: &Dialer,
    host: &str,
    port: u16,
    label: &'static str,
    tls: Option<&TlsClient>,
) -> Result<(BoxedOutboundStream, Option<SocketAddr>), OutboundError> {
    let server = dial_server(egress, dialer, host, port, label, false).await?;
    carrier_over(server, label, tls).await
}

/// [`dial_carrier`] through `hop`, already resolved, or from this host: for
/// a carrier whose association's datagrams take the same hop.
pub(crate) async fn dial_carrier_via(
    egress: &EgressRuntime,
    hop: Option<&Hop>,
    server: ConnectTarget,
    label: &'static str,
    tls: Option<&TlsClient>,
) -> Result<(BoxedOutboundStream, Option<SocketAddr>), OutboundError> {
    let server = dial_server_via(egress, hop, server, label, false).await?;
    carrier_over(server, label, tls).await
}

/// [`dial_carrier`] for a carrier a connection will hold for long.
pub(crate) async fn dial_lasting_carrier(
    egress: &EgressRuntime,
    dialer: &Dialer,
    host: &str,
    port: u16,
    label: &'static str,
    tls: Option<&TlsClient>,
) -> Result<(BoxedOutboundStream, Option<SocketAddr>), OutboundError> {
    let server = dial_server(egress, dialer, host, port, label, true).await?;
    carrier_over(server, label, tls).await
}

async fn carrier_over(
    server: ServerStream,
    label: &'static str,
    tls: Option<&TlsClient>,
) -> Result<(BoxedOutboundStream, Option<SocketAddr>), OutboundError> {
    let peer = server.peer_addr();
    let Some(tls) = tls else {
        return Ok((Box::new(server), peer));
    };
    let stream = tls.connect(server).await.map_err(|error| {
        OutboundError::new(
            OutboundStage::HopConnect,
            format!("{label} TLS handshake failed: {error}"),
        )
    })?;
    Ok((Box::new(stream), peer))
}

impl AsyncRead for ServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Chained(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Chained(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Chained(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(stream) => stream.is_write_vectored(),
            Self::Chained(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Chained(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Chained(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// The TLS layer of an HTTP or SOCKS5 hop, whose plain protocol rides TLS
/// when the node sets `tls: true`. Compiled once per node; settings the hop
/// cannot honor are kept as the configuration error every dial reports.
#[derive(Debug)]
pub(crate) struct ProxyTls(Result<Option<TlsClient>, String>);

impl ProxyTls {
    /// No TLS: the protocol speaks over the bare TCP connection.
    pub(crate) const PLAIN: Self = Self(Ok(None));

    pub(crate) fn from_node(host: &str, options: &JsonValue) -> Self {
        if !requested(options) {
            return Self::PLAIN;
        }
        Self(match Self::unsupported_option(options) {
            Some(issue) => Err(issue),
            None => TlsClient::new(host, &TlsClientOptions::from_node(options)).map(Some),
        })
    }

    /// The TLS option the node asks for that no hop implements, if any.
    pub(crate) fn unsupported_option(options: &JsonValue) -> Option<String> {
        if !requested(options) {
            return None;
        }
        let trust = unsupported_trust_options(options);
        (!trust.is_empty())
            .then(|| format!("TLS options are not supported yet: {}", trust.join(", ")))
    }

    /// The client a dial handshakes through; `None` for a plain hop.
    pub(crate) fn client(&self) -> Result<Option<&TlsClient>, OutboundError> {
        self.0
            .as_ref()
            .map(Option::as_ref)
            .map_err(|error| OutboundError::new(OutboundStage::Config, error.clone()))
    }
}

fn requested(options: &JsonValue) -> bool {
    option_bool(options, &["tls"]) == Some(true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_proxy_hop_is_plain_unless_the_node_asks_for_tls() {
        for options in [json!({}), json!({"tls": false}), json!({"sni": "front"})] {
            assert!(
                ProxyTls::from_node("proxy.example", &options)
                    .client()
                    .expect("valid")
                    .is_none(),
                "{options}"
            );
        }
        let tls = ProxyTls::from_node("proxy.example", &json!({"tls": true, "sni": "front"}));
        let client = tls.client().expect("valid").expect("TLS hop");
        assert_eq!(client.server_name(), "front");
    }

    #[test]
    fn trust_options_and_bad_server_names_fail_every_dial() {
        let pinned = json!({"tls": true, "fingerprint": "ab:cd"});
        assert!(ProxyTls::unsupported_option(&pinned)
            .is_some_and(|issue| issue.contains("fingerprint")));
        let error = ProxyTls::from_node("proxy.example", &pinned)
            .client()
            .expect_err("a pin must not be dropped");
        assert_eq!(error.stage, OutboundStage::Config);
        // A pin on a plain hop pins nothing the hop would weaken.
        assert!(ProxyTls::unsupported_option(&json!({"fingerprint": "ab:cd"})).is_none());

        let error = ProxyTls::from_node("bad name!", &json!({"tls": true}))
            .client()
            .expect_err("an invalid server name");
        assert!(error.to_string().contains("server name"), "{error}");
    }
}
