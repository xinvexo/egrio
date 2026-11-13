use tokio::io::AsyncWriteExt;

use super::codec::read_http_header;
use crate::egress::EgressRuntime;
use crate::outbound::{
    dial_carrier, write_early_data, BoxedOutboundStream, Dialer, OutboundAuth, OutboundConnector,
    OutboundError, OutboundFuture, OutboundResultExt, OutboundStage, ProxyTls,
};
use crate::prefixed::PrefixedStream;
use crate::target::ConnectTarget;

/// HTTP CONNECT proxy hop; an HTTPS proxy when the node sets `tls: true`.
#[derive(Debug)]
pub(crate) struct HttpProxyConnector {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) dialer: Dialer,
    pub(crate) auth: Option<OutboundAuth>,
    pub(crate) tls: ProxyTls,
}

impl OutboundConnector for HttpProxyConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let mut stream = self.connect_tunnel(egress, target).await?;
            // The proxy already reported the target connected; a failure now
            // is the tunnel to the target closing, not the proxy failing.
            write_early_data(&mut stream, early_data)
                .await
                .at(OutboundStage::Target)?;
            Ok(stream)
        })
    }
}

impl HttpProxyConnector {
    async fn connect_tunnel(
        &self,
        egress: &EgressRuntime,
        target: &ConnectTarget,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        let (stream, _) = dial_carrier(
            egress,
            &self.dialer,
            &self.host,
            self.port,
            "HTTP proxy",
            self.tls.client()?,
        )
        .await?;
        connect_over(stream, self.auth.as_ref(), target).await
    }
}

async fn connect_over(
    mut stream: BoxedOutboundStream,
    auth: Option<&OutboundAuth>,
    target: &ConnectTarget,
) -> Result<BoxedOutboundStream, OutboundError> {
    let authority = target.authority();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = auth {
        request.push_str(&format!(
            "Proxy-Authorization: {}\r\n",
            basic_proxy_authorization_header(auth)
        ));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .at(OutboundStage::HopConnect)?;
    stream.flush().await.at(OutboundStage::HopConnect)?;
    let rest = read_connect_response(&mut stream).await?;
    // A server-first target's opening bytes may share the reply's segment.
    if rest.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(PrefixedStream::new(rest, stream)))
    }
}

/// Reads the proxy's answer to CONNECT; returns the tunnel bytes that
/// arrived with it.
async fn read_connect_response(stream: &mut BoxedOutboundStream) -> Result<Vec<u8>, OutboundError> {
    let (header, rest) = read_http_header(stream)
        .await
        .at(OutboundStage::HopConnect)?;
    let status_line = header.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            OutboundError::new(
                OutboundStage::HopProtocol,
                format!("malformed CONNECT response: {status_line:?}"),
            )
        })?;
    match status {
        200 => Ok(rest),
        _ => Err(OutboundError::new(
            connect_status_stage(status),
            format!("CONNECT failed: {status_line}"),
        )),
    }
}

/// Whom a refused CONNECT is evidence against (RFC 9110 §15): the proxy
/// rejecting our credentials, the proxy answering for the target it could
/// not or would not reach, or the proxy failing its own protocol.
fn connect_status_stage(status: u16) -> OutboundStage {
    match status {
        407 => OutboundStage::HopAuth,
        403 | 502..=504 => OutboundStage::Target,
        _ => OutboundStage::HopProtocol,
    }
}

fn basic_proxy_authorization_header(auth: &OutboundAuth) -> String {
    format!(
        "Basic {}",
        base64_encode(format!("{}:{}", auth.username, auth.password).as_bytes())
    )
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);

        encoded.push(TABLE[(first >> 2) as usize] as char);
        encoded.push(TABLE[(((first & 0b0000_0011) << 4) | (second >> 4)) as usize] as char);

        if chunk.len() > 1 {
            encoded.push(TABLE[(((second & 0b0000_1111) << 2) | (third >> 6)) as usize] as char);
        } else {
            encoded.push('=');
        }

        if chunk.len() > 2 {
            encoded.push(TABLE[(third & 0b0011_1111) as usize] as char);
        } else {
            encoded.push('=');
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use std::sync::Arc;

    use serde_json::{json, Value as JsonValue};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::inbound::listener::CoreSessionManager;
    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::self_test::{run_connect_client, serve_one_echo};
    use crate::target::parse_connect_authority;

    #[test]
    fn a_refused_connect_names_whom_it_blames() {
        assert_eq!(connect_status_stage(407), OutboundStage::HopAuth);
        for status in [403, 502, 503, 504] {
            assert_eq!(
                connect_status_stage(status),
                OutboundStage::Target,
                "{status}"
            );
        }
        for status in [400, 405, 500] {
            assert_eq!(
                connect_status_stage(status),
                OutboundStage::HopProtocol,
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn a_proxy_refusal_reaches_the_dial_result_with_its_stage() {
        for (status_line, stage) in [
            (
                "HTTP/1.1 407 Proxy Authentication Required",
                OutboundStage::HopAuth,
            ),
            ("HTTP/1.1 502 Bad Gateway", OutboundStage::Target),
            ("garbage", OutboundStage::HopProtocol),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind refusing proxy");
            let port = listener.local_addr().expect("proxy addr").port();
            let proxy = tokio::spawn(async move {
                let (mut client, _) = listener.accept().await.expect("accept");
                read_http_header(&mut client)
                    .await
                    .expect("CONNECT request");
                client
                    .write_all(format!("{status_line}\r\n\r\n").as_bytes())
                    .await
                    .expect("answer");
            });
            let connector = HttpProxyConnector {
                host: "127.0.0.1".into(),
                port,
                dialer: Dialer::default(),
                auth: None,
                tls: ProxyTls::PLAIN,
            };
            let target = ConnectTarget {
                host: "192.0.2.1".into(),
                port: 443,
            };
            let error = connector
                .connect_stream(&EgressRuntime::default(), &target, b"")
                .await
                .err()
                .expect("the proxy refuses");
            assert_eq!(error.stage, stage, "{error}");
            proxy.await.expect("proxy task");
        }
    }

    #[tokio::test]
    async fn native_core_routes_through_http_proxy_outbound() {
        let payload = b"http-proxy-outbound-poc";
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let target_addr = target_listener.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake HTTP proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let proxy_task = tokio::spawn(async move { serve_one_http_proxy(proxy_listener).await });
        let manager = CoreSessionManager::default();
        let running = manager
            .start(proxy_profile("HttpProxy", ProxyProtocol::Http, proxy_addr))
            .await
            .expect("manager starts");
        let core_addr = running
            .listen_addr
            .as_deref()
            .expect("listen addr")
            .parse::<SocketAddr>()
            .expect("valid listen addr");

        let received = run_connect_client(core_addr, target_addr, payload)
            .await
            .expect("HTTP proxy outbound tunnels");

        assert_eq!(received, payload);
        echo_task.await.expect("echo join").expect("echo completes");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
        manager.stop();
    }

    #[tokio::test]
    async fn native_core_sends_http_proxy_basic_auth() {
        let payload = b"http-proxy-auth-poc";
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let target_addr = target_listener.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake HTTP proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let expected_auth = "Basic dXNlcjpwYXNz".to_string();
        let proxy_task = tokio::spawn(async move {
            serve_one_http_proxy_with_auth(proxy_listener, Some(expected_auth)).await
        });
        let manager = CoreSessionManager::default();
        let running = manager
            .start(proxy_profile_with_options(
                "HttpProxy",
                ProxyProtocol::Http,
                proxy_addr,
                json!({ "username": "user", "password": "pass" }),
            ))
            .await
            .expect("manager starts");
        let core_addr = running
            .listen_addr
            .as_deref()
            .expect("listen addr")
            .parse::<SocketAddr>()
            .expect("valid listen addr");

        let received = run_connect_client(core_addr, target_addr, payload)
            .await
            .expect("HTTP proxy auth outbound tunnels");

        assert_eq!(received, payload);
        echo_task.await.expect("echo join").expect("echo completes");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
        manager.stop();
    }

    #[tokio::test]
    async fn native_core_routes_through_an_https_proxy() {
        let payload = b"https-proxy-outbound";
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let target_addr = target_listener.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake HTTPS proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let acceptor = self_signed_acceptor();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = proxy_listener
                .accept()
                .await
                .map_err(|error| error.to_string())?;
            let client = acceptor
                .accept(client)
                .await
                .map_err(|error| error.to_string())?;
            relay_one_connect(client, None).await
        });
        let manager = CoreSessionManager::default();
        let running = manager
            .start(proxy_profile_with_options(
                "HttpsProxy",
                ProxyProtocol::Http,
                proxy_addr,
                json!({ "tls": true, "skip-cert-verify": true, "sni": "localhost" }),
            ))
            .await
            .expect("manager starts");
        let core_addr = running
            .listen_addr
            .as_deref()
            .expect("listen addr")
            .parse::<SocketAddr>()
            .expect("valid listen addr");

        let received = run_connect_client(core_addr, target_addr, payload)
            .await
            .expect("HTTPS proxy outbound tunnels");

        assert_eq!(received, payload);
        echo_task.await.expect("echo join").expect("echo completes");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
        manager.stop();
    }

    #[tokio::test]
    async fn an_https_proxy_certificate_is_verified_by_default() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind HTTPS proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let acceptor = self_signed_acceptor();
        let proxy = tokio::spawn(async move {
            let (client, _) = listener.accept().await.expect("accept");
            acceptor.accept(client).await.is_err()
        });
        let connector = HttpProxyConnector {
            host: "127.0.0.1".into(),
            port,
            dialer: Dialer::default(),
            auth: None,
            tls: ProxyTls::from_node("127.0.0.1", &json!({ "tls": true, "sni": "localhost" })),
        };
        let target = ConnectTarget {
            host: "192.0.2.1".into(),
            port: 443,
        };
        let error = connector
            .connect_stream(&EgressRuntime::default(), &target, b"")
            .await
            .err()
            .expect("a self-signed certificate is untrusted");
        assert_eq!(error.stage, OutboundStage::HopConnect, "{error}");
        assert!(
            error
                .to_string()
                .contains("HTTP proxy TLS handshake failed"),
            "{error}"
        );
        assert!(proxy.await.expect("proxy task"), "the client aborts");
    }

    fn self_signed_acceptor() -> TlsAcceptor {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der())
                    .into(),
            )
            .expect("server config");
        TlsAcceptor::from(Arc::new(config))
    }

    async fn serve_one_http_proxy(listener: TcpListener) -> Result<(), String> {
        serve_one_http_proxy_with_auth(listener, None).await
    }

    async fn serve_one_http_proxy_with_auth(
        listener: TcpListener,
        expected_auth: Option<String>,
    ) -> Result<(), String> {
        let (client, _) = listener.accept().await.map_err(|error| error.to_string())?;
        relay_one_connect(client, expected_auth).await
    }

    /// Answers one CONNECT on `client` and relays it to the target.
    async fn relay_one_connect(
        mut client: impl AsyncRead + AsyncWrite + Unpin,
        expected_auth: Option<String>,
    ) -> Result<(), String> {
        let (header, tunnel_start) = read_http_header(&mut client).await?;
        if let Some(expected_auth) = expected_auth {
            let expected_header = format!("Proxy-Authorization: {expected_auth}");
            if !header
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&expected_header))
            {
                client
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .map_err(|error| error.to_string())?;
                return Err("HTTP proxy auth header missing or invalid".into());
            }
        }
        let request_line = header
            .lines()
            .next()
            .ok_or_else(|| "HTTP proxy request missing request line".to_string())?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
            return Err(format!("expected proxy CONNECT, got {request_line}"));
        }
        let target = parse_connect_authority(parts[1])?;
        let mut upstream = crate::egress::EgressRuntime::default()
            .connect_target_tcp(&target)
            .await
            .map_err(|error| error.to_string())?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| error.to_string())?;
        upstream
            .write_all(&tunnel_start)
            .await
            .map_err(|error| error.to_string())?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn proxy_profile(
        name: &str,
        protocol: ProxyProtocol,
        proxy_addr: SocketAddr,
    ) -> RuntimeProfile {
        proxy_profile_with_options(name, protocol, proxy_addr, JsonValue::Null)
    }

    fn proxy_profile_with_options(
        name: &str,
        protocol: ProxyProtocol,
        proxy_addr: SocketAddr,
        options: JsonValue,
    ) -> RuntimeProfile {
        RuntimeProfile {
            dns: Default::default(),
            rule_sets: Vec::new(),
            geodata: Default::default(),
            id: "proxy-profile".into(),
            name: "proxy-profile".into(),
            traffic_policy_mode: crate::profile::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: vec![ProxyNode {
                id: format!("proxy-{name}"),
                name: name.into(),
                protocol,
                server: Some(proxy_addr.ip().to_string()),
                port: Some(proxy_addr.port()),
                options,
            }],
            groups: Vec::new(),
            rules: vec![RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: name,
                no_resolve: false,
            }]
            .into(),
        }
    }
}
