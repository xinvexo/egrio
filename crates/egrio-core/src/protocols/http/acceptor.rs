use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{
    AcceptedStream, BoxedInboundStream, InboundAcceptor, InboundFuture, InboundReplyPlan,
    InboundSession,
};
use crate::prefixed::PrefixedStream;
use crate::target::{parse_connect_authority, ConnectTarget};

use super::codec::read_http_header;
use super::forward::ForwardRequest;

/// HTTP proxy server half: the mixed listener's plaintext acceptor. A
/// `CONNECT` request opens a tunnel. Any other method
/// in absolute-form — how clients send plain `http://` requests to the
/// HTTP proxy the system settings name — is forwarded to its origin (see
/// [`super::forward`]). Request headers carry no identity: the process
/// behind a connection comes only from the Core's flow scanner.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpProxyAcceptor;

impl InboundAcceptor for HttpProxyAcceptor {
    fn accept(&self, mut io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        Box::pin(async move {
            let (header, rest) = read_http_header(io.as_mut()).await?;
            // Usually empty: a client waits for the tunnel before sending.
            if !rest.is_empty() {
                io = Box::new(PrefixedStream::new(rest, io));
            }
            let stream = match parse_proxy_request(&header)? {
                ProxyRequest::Connect(target) => AcceptedStream {
                    inbound: "http-connect",
                    user: None,
                    process: ClientOwner::Known(None),
                    target,
                    io,
                    replies: CONNECT_REPLY_PLAN,
                    reset: None,
                },
                ProxyRequest::Forward(request) => AcceptedStream {
                    inbound: "http-forward",
                    user: None,
                    process: ClientOwner::Known(None),
                    target: request.target.clone(),
                    io: Box::new(request.into_stream(io)),
                    replies: FORWARD_REPLY_PLAN,
                    reset: None,
                },
            };
            Ok(InboundSession::Stream(stream))
        })
    }
}

const CONNECT_REPLY_PLAN: InboundReplyPlan = InboundReplyPlan {
    success: b"HTTP/1.1 200 Connection Established\r\n\r\n",
    admission_refused: b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
    route_rejected: b"HTTP/1.1 403 Forbidden\r\n\r\n",
    outbound_unavailable: b"HTTP/1.1 501 Not Implemented\r\n\r\n",
    dial_failed: b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
};

/// A forwarded request's success reply is the origin's own response.
const FORWARD_REPLY_PLAN: InboundReplyPlan = InboundReplyPlan {
    success: b"",
    ..CONNECT_REPLY_PLAN
};

enum ProxyRequest {
    Connect(ConnectTarget),
    Forward(ForwardRequest),
}

fn parse_proxy_request(header: &str) -> Result<ProxyRequest, String> {
    let mut lines = header.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(target), Some(version), None) => (method, target, version),
        _ => return Err(format!("malformed HTTP proxy request line: {request_line}")),
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        parse_connect_authority(target).map(ProxyRequest::Connect)
    } else {
        ForwardRequest::parse(method, target, version, lines).map(ProxyRequest::Forward)
    }
}

#[cfg(test)]
mod tests {
    //! Request-parser tests over an in-memory duplex: the acceptor reads
    //! untrusted client bytes, so malformed requests must error (never
    //! panic or park), the header read must stay byte-capped, and a
    //! forwarded request must reach its origin rewritten for that hop.

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::{timeout, Duration};

    use super::*;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Runs the acceptor against a fully scripted client. The script is
    /// written up front (the duplex buffers it); the accept future is
    /// bounded so a stalled parser fails the test instead of hanging it.
    async fn accept_scripted(script: &[u8]) -> (Result<InboundSession, String>, DuplexStream) {
        let (mut client, server) = duplex(16 * 1024);
        client
            .write_all(script)
            .await
            .expect("script fits the duplex buffer");
        let outcome = timeout(
            HANDSHAKE_TIMEOUT,
            HttpProxyAcceptor.accept(Box::new(server)),
        )
        .await
        .expect("HTTP proxy handshake must not hang");
        (outcome, client)
    }

    fn accepted_stream(outcome: Result<InboundSession, String>) -> AcceptedStream {
        match outcome.expect("request accepted") {
            InboundSession::Stream(stream) => stream,
            InboundSession::Datagrams(_) => panic!("an HTTP proxy yields a stream session"),
        }
    }

    /// The handshake error, or a panic if the malformed input was accepted.
    /// (`expect_err` needs `Debug` on the session, which it deliberately
    /// does not carry.)
    fn rejected(outcome: Result<InboundSession, String>, why: &str) -> String {
        match outcome {
            Err(error) => error,
            Ok(_) => panic!("{why}: the request was accepted"),
        }
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_a_domain_authority() {
        let script = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (outcome, mut client) = accept_scripted(script).await;

        let stream = accepted_stream(outcome);
        assert_eq!(stream.inbound, "http-connect");
        assert_eq!(stream.user, None);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "example.com".into(),
                port: 443,
            }
        );
        assert_eq!(
            stream.replies.success,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );

        // Accept writes nothing itself: the 200 belongs to the dispatcher's
        // reply plan.
        drop(stream);
        let mut written = Vec::new();
        timeout(HANDSHAKE_TIMEOUT, client.read_to_end(&mut written))
            .await
            .expect("client drain must not hang")
            .expect("client drain");
        assert!(written.is_empty(), "no reply is written during accept");
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_an_ipv4_authority() {
        let script = b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\n\r\n";
        let (outcome, _client) = accept_scripted(script).await;

        let stream = accepted_stream(outcome);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "127.0.0.1".into(),
                port: 8080,
            }
        );
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_a_bracketed_ipv6_authority() {
        let script = b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n";
        let (outcome, _client) = accept_scripted(script).await;

        let stream = accepted_stream(outcome);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "2001:db8::1".into(),
                port: 8443,
            }
        );
    }

    #[tokio::test]
    async fn request_headers_never_assert_a_process_identity() {
        // Any local client could forge another app's identity to steer its
        // own routing, so identity-looking headers stay plain headers.
        let script = concat!(
            "CONNECT example.com:443 HTTP/1.1\r\n",
            "X-Egrio-Process-Name: firefox\r\n",
            "X-Egrio-Process-Path: C:\\Programs\\firefox.exe\r\n",
            "\r\n",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;

        assert!(accepted_stream(outcome).process.known().is_none());
    }

    /// What the origin receives: the replayed head, then whatever the
    /// client sent after it, up to `len` bytes.
    async fn origin_bytes(stream: &mut AcceptedStream, len: usize) -> String {
        let mut bytes = vec![0; len];
        timeout(HANDSHAKE_TIMEOUT, stream.io.read_exact(&mut bytes))
            .await
            .expect("the forwarded bytes are readable")
            .expect("forwarded bytes");
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn forwards_an_absolute_form_request_with_a_head_rewritten_for_its_origin() {
        let script = concat!(
            "GET http://example.com/index.html?q=1#top HTTP/1.1\r\n",
            "Host: stale.example\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Proxy-Authorization: Basic c2VjcmV0\r\n",
            "User-Agent: test\r\n",
            "Connection: keep-alive, X-Hop\r\n",
            "X-Hop: 1\r\n",
            "Accept: */*\r\n",
            "\r\n",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;
        let mut stream = accepted_stream(outcome);
        assert_eq!(stream.inbound, "http-forward");
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "example.com".into(),
                port: 80,
            }
        );
        assert!(
            stream.replies.success.is_empty(),
            "the origin's response is the reply"
        );
        let expected = concat!(
            "GET /index.html?q=1 HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "User-Agent: test\r\n",
            "Accept: */*\r\n",
            "Connection: close\r\n",
            "\r\n",
        );
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
    }

    #[tokio::test]
    async fn a_forwarded_body_follows_its_rewritten_head_with_framing_intact() {
        let script = concat!(
            "POST http://[2001:db8::1]:8080?x=1 HTTP/1.0\r\n",
            "Content-Length: 5\r\n",
            "Connection: Content-Length\r\n",
            "\r\n",
            "hello",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;
        let mut stream = accepted_stream(outcome);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "2001:db8::1".into(),
                port: 8080,
            }
        );
        let expected = concat!(
            "POST /?x=1 HTTP/1.0\r\n",
            "Host: [2001:db8::1]:8080\r\n",
            "Content-Length: 5\r\n",
            "Connection: close\r\n",
            "\r\n",
            "hello",
        );
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
    }

    #[tokio::test]
    async fn a_websocket_upgrade_keeps_its_upgrade_fields_and_is_not_bounded() {
        let script = concat!(
            "GET http://example.com/ws HTTP/1.1\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Key: a2V5\r\n",
            "\r\n",
            "frames after the upgrade",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;
        let mut stream = accepted_stream(outcome);
        let expected = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Key: a2V5\r\n",
            "Connection: Upgrade\r\n",
            "\r\n",
            "frames after the upgrade",
        );
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
    }

    /// The next read after the forwarded message.
    async fn after_message(stream: &mut AcceptedStream) -> std::io::Result<usize> {
        let mut rest = [0_u8; 64];
        timeout(HANDSHAKE_TIMEOUT, stream.io.read(&mut rest))
            .await
            .expect("the read after the message must not hang")
    }

    #[tokio::test]
    async fn a_reused_connection_never_carries_a_next_request_to_the_pinned_origin() {
        let script = concat!(
            "POST http://example.com/form HTTP/1.1\r\n",
            "Content-Length: 5\r\n",
            "\r\n",
            "hello",
            "GET http://other.example/ HTTP/1.1\r\n",
            "\r\n",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;
        let mut stream = accepted_stream(outcome);
        let expected = concat!(
            "POST /form HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Content-Length: 5\r\n",
            "Connection: close\r\n",
            "\r\n",
            "hello",
        );
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
        assert_eq!(
            after_message(&mut stream)
                .await
                .expect("the next request ends this message, it does not fail it"),
            0,
            "the next request is not carried to the pinned origin"
        );
    }

    #[tokio::test]
    async fn a_chunked_body_ends_after_its_last_chunk() {
        let script = concat!(
            "PUT http://example.com/upload HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "4\r\nwiki\r\n0\r\n\r\n",
            "GET http://other.example/ HTTP/1.1\r\n\r\n",
        );
        let (outcome, _client) = accept_scripted(script.as_bytes()).await;
        let mut stream = accepted_stream(outcome);
        let expected = concat!(
            "PUT /upload HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Connection: close\r\n",
            "\r\n",
            "4\r\nwiki\r\n0\r\n\r\n",
        );
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
        assert_eq!(
            after_message(&mut stream)
                .await
                .expect("the next request ends this message, it does not fail it"),
            0,
            "the next request is not carried to the pinned origin"
        );
    }

    #[tokio::test]
    async fn stray_crlf_after_a_request_is_not_a_next_request() {
        let (mut client, server) = duplex(16 * 1024);
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let outcome = timeout(
            HANDSHAKE_TIMEOUT,
            HttpProxyAcceptor.accept(Box::new(server)),
        )
        .await
        .expect("HTTP proxy handshake must not hang");
        let mut stream = accepted_stream(outcome);
        let expected = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        assert_eq!(origin_bytes(&mut stream, expected.len()).await, expected);
        assert_eq!(after_message(&mut stream).await.unwrap(), 0, "a clean end");
    }

    #[tokio::test]
    async fn rejects_requests_that_are_not_proxyable_in_the_clear() {
        for (request_line, why) in [
            (
                "GET https://example.com/ HTTP/1.1",
                "expected CONNECT or an absolute http://",
            ),
            (
                "GET /relative HTTP/1.1",
                "expected CONNECT or an absolute http://",
            ),
            (
                "GET http://user@example.com/ HTTP/1.1",
                "invalid http:// authority",
            ),
            ("GET http:///path HTTP/1.1", "invalid http:// authority"),
            (
                "GET http://example.com/ HTTP/2.0",
                "unsupported HTTP proxy request version",
            ),
        ] {
            let script = format!("{request_line}\r\n\r\n");
            let (outcome, _client) = accept_scripted(script.as_bytes()).await;
            let error = rejected(outcome, request_line);
            assert!(error.contains(why), "{request_line}: {error}");
        }
        let folded = b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\r\n 2\r\n\r\n";
        let (outcome, _client) = accept_scripted(folded).await;
        let error = rejected(outcome, "folded header");
        assert!(error.contains("folding"), "{error}");
        let smuggled = concat!(
            "POST http://example.com/ HTTP/1.1\r\n",
            "Content-Length: 4\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
        );
        let (outcome, _client) = accept_scripted(smuggled.as_bytes()).await;
        let error = rejected(outcome, "ambiguous framing");
        assert!(
            error.contains("both Transfer-Encoding and Content-Length"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn rejects_request_lines_with_missing_or_extra_fields() {
        for request_line in [
            "CONNECT",
            "CONNECT example.com:443",
            "CONNECT example.com:443 HTTP/1.1 extra",
        ] {
            let script = format!("{request_line}\r\n\r\n");
            let (outcome, _client) = accept_scripted(script.as_bytes()).await;
            let error = rejected(outcome, "malformed CONNECT request line");
            assert!(
                error.contains("malformed HTTP proxy request line"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_a_connect_authority_without_a_port() {
        let script = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (outcome, _client) = accept_scripted(script).await;
        let error = rejected(outcome, "portless authority");
        assert!(error.contains("missing port"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_header_block_that_is_not_utf8() {
        let mut script = vec![0xff, 0xfe];
        script.extend_from_slice(b"\r\n\r\n");
        let (outcome, _client) = accept_scripted(&script).await;
        let error = rejected(outcome, "non-UTF-8 header");
        assert!(error.contains("utf-8"), "{error}");
    }

    #[tokio::test]
    async fn caps_an_unterminated_header_at_the_read_limit() {
        // A client that never sends the blank line must hit the byte cap,
        // not grow the buffer forever.
        let mut script = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        script.resize(script.len() + 9000, b'a');
        let (outcome, _client) = accept_scripted(&script).await;
        let error = rejected(outcome, "unterminated header");
        assert!(error.contains("8192"), "{error}");
    }

    #[tokio::test]
    async fn errors_instead_of_hanging_when_the_client_truncates_the_request() {
        let (mut client, server) = duplex(16 * 1024);
        client
            .write_all(b"CONNECT exam")
            .await
            .expect("partial request");
        drop(client);

        let outcome = timeout(
            HANDSHAKE_TIMEOUT,
            HttpProxyAcceptor.accept(Box::new(server)),
        )
        .await
        .expect("truncated request must not hang");
        let error = rejected(outcome, "truncated request");
        assert!(error.contains("connection closed"), "{error}");
    }
}
