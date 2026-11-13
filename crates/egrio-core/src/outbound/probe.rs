//! End-to-end reachability probes over the selected outbound stream.
//! A proxy handshake is not evidence that the probe origin is reachable.

use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::BoxedOutboundStream;
use crate::target::ConnectTarget;

const MAX_RESPONSE_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundProbeRequest {
    pub(crate) target: ConnectTarget,
    pub(crate) tls: bool,
    pub(crate) http_request: Vec<u8>,
}

pub(crate) fn parse_probe_url(url: &str) -> Option<OutboundProbeRequest> {
    // URI parsing also excludes whitespace/control characters in the request.
    if url.contains('#') {
        return None;
    }
    let uri = url.parse::<http::Uri>().ok()?;
    let (tls, default_port) = match uri.scheme_str()? {
        "http" => (false, 80),
        "https" => (true, 443),
        _ => return None,
    };
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().trim_matches(['[', ']']);
    if host.is_empty() || host.contains('%') {
        return None;
    }
    let suffix = authority.as_str().strip_prefix(authority.host())?;
    let port = if suffix.is_empty() {
        default_port
    } else {
        suffix.strip_prefix(':')?.parse::<u16>().ok()?
    };
    if port == 0 {
        return None;
    }
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    Some(OutboundProbeRequest {
        target: ConnectTarget {
            host: host.into(),
            port,
        },
        tls,
        http_request: format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    })
}

pub(crate) async fn verify_response(
    stream: BoxedOutboundStream,
    probe: &OutboundProbeRequest,
) -> Result<(), String> {
    // All probe origins use ordinary certificate verification, independently
    // of any skip-cert-verify option configured on the proxy hop.
    static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    verify_response_with_tls(
        stream,
        probe,
        TLS_CONFIG.get_or_init(|| crate::tls::client_config(false, &[b"http/1.1".to_vec()])),
    )
    .await
}

async fn verify_response_with_tls(
    mut stream: BoxedOutboundStream,
    probe: &OutboundProbeRequest,
    config: &Arc<rustls::ClientConfig>,
) -> Result<(), String> {
    if probe.tls {
        let name = rustls_pki_types::ServerName::try_from(probe.target.host.clone())
            .map_err(|error| format!("invalid probe TLS server name: {error}"))?;
        stream = Box::new(
            tokio_rustls::TlsConnector::from(config.clone())
                .connect(name, stream)
                .await
                .map_err(|error| format!("probe TLS handshake failed: {error}"))?,
        );
    }
    stream
        .write_all(&probe.http_request)
        .await
        .map_err(|error| format!("probe request failed: {error}"))?;
    // tokio-rustls buffers encrypted writes; flush before waiting on the peer.
    stream
        .flush()
        .await
        .map_err(|error| format!("probe request flush failed: {error}"))?;
    read_response_head(&mut stream).await
}

async fn read_response_head(stream: &mut BoxedOutboundStream) -> Result<(), String> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0; 1024];
    let mut total = 0;
    loop {
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            let line_end = head
                .windows(2)
                .position(|window| window == b"\r\n")
                .unwrap();
            let line = &head[..line_end];
            if line.len() < 13
                || !(line.starts_with(b"HTTP/1.1 ") || line.starts_with(b"HTTP/1.0 "))
                || line[12] != b' '
                || !line[9..12].iter().all(u8::is_ascii_digit)
            {
                return Err("probe returned an invalid HTTP status line".into());
            }
            let status = (line[9] - b'0') as u16 * 100
                + (line[10] - b'0') as u16 * 10
                + (line[11] - b'0') as u16;
            if (100..200).contains(&status) && status != 101 {
                head.drain(..end + 4);
                continue;
            }
            return if (200..400).contains(&status) {
                Ok(())
            } else {
                Err(format!("probe returned HTTP status {status}"))
            };
        }
        if total >= MAX_RESPONSE_HEAD {
            return Err("probe HTTP response headers exceeded 16 KiB".into());
        }
        let remaining = buf.len().min(MAX_RESPONSE_HEAD - total);
        let read = stream
            .read(&mut buf[..remaining])
            .await
            .map_err(|error| format!("probe response failed: {error}"))?;
        if read == 0 {
            return Err("probe target closed before a complete HTTP response header".into());
        }
        total += read;
        head.extend_from_slice(&buf[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parses_http_https_ipv6_and_rejects_invalid_urls() {
        for (url, host, port, tls, path) in [
            (
                "http://example.com/check?q=1",
                "example.com",
                80,
                false,
                "/check?q=1",
            ),
            ("https://example.com/", "example.com", 443, true, "/"),
            ("http://[::1]:8080/", "::1", 8080, false, "/"),
        ] {
            let probe = parse_probe_url(url).unwrap();
            assert_eq!(probe.target.host, host);
            assert_eq!(probe.target.port, port);
            assert_eq!(probe.tls, tls);
            assert!(probe
                .http_request
                .starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
        }
        for url in [
            "ftp://example.com",
            "http://",
            "http://user:password@example.com/",
            "http://example.com/\r\nX: y",
            "https://example.com:0/",
            "https://example.com:70000/",
            "https://example.com:bad/",
            "https://example.com:/",
            "https://example.com/#fragment",
        ] {
            assert!(parse_probe_url(url).is_none(), "{url:?}");
        }
    }

    #[tokio::test]
    async fn requires_complete_valid_success_response() {
        for (response, succeeds) in [
            ("HTTP/1.1 204 No Content\r\n\r\n", true),
            (
                "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
                true,
            ),
            ("HTTP/1.1 503 Unavailable\r\n\r\n", false),
            ("HTTP/1.1 101 Switching Protocols\r\n\r\n", false),
            ("HTTP/1.1 204 No Content\r\n", false),
            ("this is not HTTP\r\n\r\n", false),
            ("", false),
        ] {
            let (client, mut peer) = duplex(1024);
            let server = tokio::spawn(async move {
                let mut request = [0; 1024];
                peer.read(&mut request).await.unwrap();
                for byte in response.as_bytes() {
                    peer.write_all(&[*byte]).await.unwrap();
                }
            });
            let result = verify_response(
                Box::new(client),
                &parse_probe_url("http://example.com/").unwrap(),
            )
            .await;
            assert_eq!(result.is_ok(), succeeds, "{response:?}: {result:?}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn bounds_response_header_memory() {
        let (client, mut peer) = duplex(MAX_RESPONSE_HEAD * 2);
        peer.write_all(&vec![b'x'; MAX_RESPONSE_HEAD + 1])
            .await
            .unwrap();
        let result = read_response_head(&mut (Box::new(client) as BoxedOutboundStream)).await;
        assert!(result.unwrap_err().contains("16 KiB"));
    }

    fn tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    #[tokio::test]
    async fn https_requires_origin_tls_and_http_response() {
        let (server_config, client_config) = tls_configs();
        let (client, peer) = duplex(8192);
        let server = tokio::spawn(async move {
            let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(peer)
                .await
                .unwrap();
            let mut request = [0; 1024];
            let n = tls.read(&mut request).await.unwrap();
            assert!(request[..n].starts_with(b"GET /check HTTP/1.1\r\n"));
            tls.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
        });
        verify_response_with_tls(
            Box::new(client),
            &parse_probe_url("https://localhost/check").unwrap(),
            &client_config,
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_rejects_untrusted_origin_certificates() {
        let (server_config, _) = tls_configs();
        let (client, peer) = duplex(8192);
        let server = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server_config)
                .accept(peer)
                .await
        });
        let error = verify_response(
            Box::new(client),
            &parse_probe_url("https://localhost/").unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("TLS handshake failed"), "{error}");
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_transport_without_origin_response_is_not_a_success() {
        let (client, _peer) = duplex(8192);
        let probe = parse_probe_url("https://localhost/").unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(5),
            verify_response(Box::new(client), &probe)
        )
        .await
        .is_err());
    }
}
