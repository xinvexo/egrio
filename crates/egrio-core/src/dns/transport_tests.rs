//! Real loopback UDP/TLS/HTTP peers exercise the production DNS transport. The
//! generated test certificate is explicitly trusted; no verifier is bypassed.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{
    rdata::{A, NS, TXT},
    Name, RData, Record, RecordType,
};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::dns::config::RuntimeDnsConfig;
use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
use crate::outbound::{DirectConnector, OutboundConnector, OutboundTable};
use crate::policy_group::GroupStateTable;
use crate::profile::{RuntimeProfile, TrafficPolicyMode};
use crate::rule_engine::RuleEngine;

fn service() -> Arc<DnsService> {
    let profile = RuntimeProfile::new("dns-transport-loopback");
    let direct: Arc<dyn OutboundConnector> = Arc::new(DirectConnector);
    DnsService::new(
        Arc::new(RuntimeDnsConfig::default()),
        EgressRuntime::new(NativeCoreEgressConfig::default()),
        Arc::new(RuleEngine::compile(&profile)),
        Arc::new(OutboundTable::from([("DIRECT".into(), direct)])),
        Arc::new(HashMap::new()),
        GroupStateTable::default(),
        TrafficPolicyMode::Rule,
        "DIRECT".into(),
    )
}

fn tls_configs(alpn: &[&[u8]]) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

fn upstream(address: SocketAddr, transport: DnsTransport) -> (DnsUpstream, ConnectTarget) {
    (
        DnsUpstream {
            transport,
            host: address.ip().to_string(),
            port: address.port(),
            path: "/dns-query".into(),
            server_name: Some("localhost".into()),
            route: None,
        },
        ConnectTarget {
            host: address.ip().to_string(),
            port: address.port(),
        },
    )
}

fn full_answer(request: &Message) -> Message {
    let mut answer = wire::response(request, ResponseCode::NoError);
    answer.add_answer(Record::from_rdata(
        request.queries.first().unwrap().name().clone(),
        60,
        RData::TXT(TXT::new(vec!["complete TXT answer".into()])),
    ));
    answer.add_authority(Record::from_rdata(
        Name::from_ascii("test.").unwrap(),
        40,
        RData::NS(NS(Name::from_ascii("ns.test.").unwrap())),
    ));
    answer.add_additional(Record::from_rdata(
        Name::from_ascii("ns.test.").unwrap(),
        30,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    answer
}

#[tokio::test]
async fn dot_uses_length_framing_with_verified_tls_and_no_http_alpn() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Tls);
    let (server_config, mut client_config) = tls_configs(&[b"dot"]);
    let mut dns = service();
    let production_alpn = dns.tls.alpn_protocols.clone();
    assert!(production_alpn
        .iter()
        .all(|value| value != b"http/1.1" && value != b"h2"));
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = production_alpn;
    Arc::get_mut(&mut dns).unwrap().tls = client_config;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(socket)
            .await
            .unwrap();
        assert_ne!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let length = stream.read_u16().await.unwrap() as usize;
        let mut query = vec![0; length];
        stream.read_exact(&mut query).await.unwrap();
        let request = wire::decode(&query).unwrap();
        let bytes = wire::encode(&full_answer(&request)).unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        // Independent writes ensure the client uses DNS framing, not read boundaries.
        for chunk in bytes.chunks(7) {
            stream.write_all(chunk).await.unwrap();
        }
        stream.flush().await.unwrap();
        let _ = stream.shutdown().await;
    });
    let request = wire::query("answer.test", RecordType::TXT).unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        exchange(
            &dns,
            &request,
            &upstream,
            "DIRECT",
            &endpoint,
            Default::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let expected = full_answer(&request);
    assert_eq!(reply.answers, expected.answers);
    assert_eq!(reply.authorities, expected.authorities);
    assert_eq!(reply.additionals, expected.additionals);
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn doh_negotiates_http1_or_http2_and_applies_age_to_the_complete_message() {
    for protocol in [b"http/1.1".as_slice(), b"h2".as_slice()] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Https);
        let (server_config, mut client_config) = tls_configs(&[protocol]);
        let mut dns = service();
        let production_alpn = dns.https_tls.alpn_protocols.clone();
        assert!(production_alpn.iter().any(|value| value == protocol));
        Arc::get_mut(&mut client_config).unwrap().alpn_protocols = production_alpn;
        Arc::get_mut(&mut dns).unwrap().https_tls = client_config;
        let protocol = protocol.to_vec();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(
                stream.get_ref().1.alpn_protocol(),
                Some(protocol.as_slice())
            );
            let handler = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(request.uri().path(), "/dns-query");
                if request.version() == http::Version::HTTP_2 {
                    assert_eq!(request.uri().scheme_str(), Some("https"));
                    assert!(request.uri().authority().is_some());
                    assert!(
                        !request.headers().contains_key(http::header::HOST),
                        "HTTP/2 authority is carried only by :authority"
                    );
                } else {
                    assert!(request.headers().contains_key(http::header::HOST));
                }
                assert_eq!(
                    request.headers()[http::header::CONTENT_TYPE],
                    "application/dns-message"
                );
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                let query = wire::decode(&bytes).unwrap();
                assert_eq!(
                    query.id, 0,
                    "HTTP correlates requests; DoH IDs do not fragment HTTP caches"
                );
                let bytes = wire::encode(&full_answer(&query)).unwrap();
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .status(http::StatusCode::NON_AUTHORITATIVE_INFORMATION)
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .header(http::header::AGE, "15")
                        .body(Full::new(Bytes::from(bytes)))
                        .unwrap(),
                )
            });
            // The client owns the connection lifetime; trailing TLS EOF is not
            // a DNS assertion.
            if protocol == b"h2" {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            }
        });
        let mut request = wire::query("answer.test", RecordType::TXT).unwrap();
        request.metadata.id = 0x4242;
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(
                &dns,
                &request,
                &upstream,
                "DIRECT",
                &endpoint,
                Default::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = full_answer(&request);
        wire::age_ttls(&mut expected, Duration::from_secs(15));
        assert_eq!(reply.id, 0x4242);
        assert_eq!(reply.answers, expected.answers);
        assert_eq!(reply.authorities, expected.authorities);
        assert_eq!(reply.additionals, expected.additionals);
        // An HTTP/2 connection stays for later queries until the service
        // retires; HTTP/1.1 closed after its one exchange.
        dns.retire();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

/// A DoT connection carries the next query too; once the server has closed
/// it, the query that finds it closed goes out on a new one.
#[tokio::test]
async fn dot_keeps_its_connection_for_the_next_query_until_the_server_closes_it() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Tls);
    let (server_config, mut client_config) = tls_configs(&[]);
    let mut dns = service();
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = dns.tls.alpn_protocols.clone();
    Arc::get_mut(&mut dns).unwrap().tls = client_config;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts = Arc::clone(&accepted);
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                .accept(socket)
                .await
                .unwrap();
            // Two queries per connection, then the server closes it.
            for _ in 0..2 {
                let Ok(length) = stream.read_u16().await else {
                    break;
                };
                let mut query = vec![0; length as usize];
                stream.read_exact(&mut query).await.unwrap();
                let request = wire::decode(&query).unwrap();
                let bytes = wire::encode(&full_answer(&request)).unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.flush().await.unwrap();
            }
            let _ = stream.shutdown().await;
        }
    });
    for (index, connections) in [(1, 1), (2, 1), (3, 2)] {
        let request = wire::query(&format!("answer{index}.test"), RecordType::TXT).unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(
                &dns,
                &request,
                &upstream,
                "DIRECT",
                &endpoint,
                Default::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply.answers, full_answer(&request).answers);
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            connections,
            "query {index}"
        );
    }
    server.abort();
}

/// DoH queries to one server share one HTTP/2 connection, the ones that
/// start together included, until the service retires and closes it.
#[tokio::test]
async fn doh_queries_share_one_http2_connection_until_the_service_retires() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Https);
    let (server_config, mut client_config) = tls_configs(&[b"h2"]);
    let mut dns = service();
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = dns.https_tls.alpn_protocols.clone();
    Arc::get_mut(&mut dns).unwrap().https_tls = client_config;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts = Arc::clone(&accepted);
    let (closed_tx, closed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut closed_tx = Some(closed_tx);
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                .accept(socket)
                .await
                .unwrap();
            let handler = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                let query = wire::decode(&bytes).unwrap();
                let bytes = wire::encode(&full_answer(&query)).unwrap();
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .body(Full::new(Bytes::from(bytes)))
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), handler)
                .await;
            if let Some(closed_tx) = closed_tx.take() {
                let _ = closed_tx.send(());
            }
        }
    });
    let query = |index: usize| {
        let dns = Arc::clone(&dns);
        let upstream = upstream.clone();
        let endpoint = endpoint.clone();
        async move {
            let request = wire::query(&format!("answer{index}.test"), RecordType::TXT).unwrap();
            let reply = tokio::time::timeout(
                Duration::from_secs(3),
                exchange(
                    &dns,
                    &request,
                    &upstream,
                    "DIRECT",
                    &endpoint,
                    Default::default(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply.answers, full_answer(&request).answers);
        }
    };
    tokio::join!(query(1), query(2), query(3));
    query(4).await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    dns.retire();
    tokio::time::timeout(Duration::from_secs(3), closed)
        .await
        .expect("retiring the service closes its connection")
        .unwrap();
    server.abort();
}

/// A DoH server for the keep-alive tests: every connection is served in a
/// task of its own and counted; the first stops reading its connection once
/// `hold` is notified, so its PINGs go unacknowledged; `closed` hears of
/// each connection that ended.
async fn http2_doh_server(
    listener: TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    hold: Arc<tokio::sync::Notify>,
    closed: tokio::sync::mpsc::UnboundedSender<usize>,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let number = accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let server_config = server_config.clone();
            let hold = Arc::clone(&hold);
            let closed = closed.clone();
            tokio::spawn(async move {
                let stream = tokio_rustls::TlsAcceptor::from(server_config)
                    .accept(socket)
                    .await
                    .unwrap();
                let handler =
                    service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let query = wire::decode(&bytes).unwrap();
                        let bytes = wire::encode(&full_answer(&query)).unwrap();
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(http::header::CONTENT_TYPE, "application/dns-message")
                                .body(Full::new(Bytes::from(bytes)))
                                .unwrap(),
                        )
                    });
                let serve = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), handler);
                let mut serve = std::pin::pin!(serve);
                if number == 1 {
                    tokio::select! {
                        _ = serve.as_mut() => {}
                        () = hold.notified() => {
                            // Open, and nobody reads it.
                            std::future::pending::<()>().await;
                        }
                    }
                } else {
                    let _ = serve.await;
                }
                let _ = closed.send(number);
            });
        }
    });
    (accepted, task)
}

/// One TXT question to the DoH server, answered within a second.
async fn doh_query(
    dns: &Arc<DnsService>,
    upstream: &DnsUpstream,
    endpoint: &ConnectTarget,
    name: &str,
) {
    let request = wire::query(name, RecordType::TXT).unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        exchange(
            dns,
            &request,
            upstream,
            "DIRECT",
            endpoint,
            Default::default(),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{name} took more than a second"))
    .unwrap();
    assert_eq!(reply.answers, full_answer(&request).answers);
}

/// A DoH service whose HTTP/2 connections are kept as `keep` says, and the
/// server it asks.
async fn kept_doh(
    keep: Http2Keep,
) -> (
    Arc<DnsService>,
    DnsUpstream,
    ConnectTarget,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<tokio::sync::Notify>,
    tokio::sync::mpsc::UnboundedReceiver<usize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Https);
    let (server_config, mut client_config) = tls_configs(&[b"h2"]);
    let mut dns = service();
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = dns.https_tls.alpn_protocols.clone();
    let service = Arc::get_mut(&mut dns).unwrap();
    service.https_tls = client_config;
    service.connections = DnsConnections::keeping_http2(keep);
    let hold = Arc::new(tokio::sync::Notify::new());
    let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
    let (accepted, server) =
        http2_doh_server(listener, server_config, Arc::clone(&hold), closed_tx).await;
    (dns, upstream, endpoint, accepted, hold, closed, server)
}

/// A DoH connection waits for the next query through a pause, its PINGs
/// answered meanwhile.
#[tokio::test]
async fn a_doh_connection_waits_for_the_next_query_through_a_pause() {
    let keep = Http2Keep {
        ping: Duration::from_millis(50),
        ping_timeout: Duration::from_millis(500),
        idle: Duration::from_secs(10),
    };
    let (dns, upstream, endpoint, accepted, _hold, _closed, server) = kept_doh(keep).await;
    doh_query(&dns, &upstream, &endpoint, "before.test").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    doh_query(&dns, &upstream, &endpoint, "after.test").await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    dns.retire();
    server.abort();
}

/// A DoH connection whose server stopped answering is closed by its first
/// unacknowledged PING: the next query opens a new connection at once
/// rather than wait on the old one.
#[tokio::test]
async fn a_doh_connection_that_stopped_answering_is_not_asked_again() {
    let keep = Http2Keep {
        ping: Duration::from_millis(50),
        ping_timeout: Duration::from_millis(200),
        idle: Duration::from_secs(10),
    };
    let (dns, upstream, endpoint, accepted, hold, _closed, server) = kept_doh(keep).await;
    doh_query(&dns, &upstream, &endpoint, "before.test").await;
    hold.notify_one();
    tokio::time::sleep(Duration::from_millis(600)).await;
    doh_query(&dns, &upstream, &endpoint, "after.test").await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
    dns.retire();
    server.abort();
}

/// A DoH connection no query took for its idle time closes, and the next
/// query opens a new one.
#[tokio::test]
async fn a_doh_connection_closes_after_its_idle_time() {
    let keep = Http2Keep {
        ping: Duration::from_secs(5),
        ping_timeout: Duration::from_secs(5),
        idle: Duration::from_millis(200),
    };
    let (dns, upstream, endpoint, accepted, _hold, mut closed, server) = kept_doh(keep).await;
    doh_query(&dns, &upstream, &endpoint, "before.test").await;
    let ended = tokio::time::timeout(Duration::from_secs(2), closed.recv())
        .await
        .expect("the idle connection closes")
        .unwrap();
    assert_eq!(ended, 1);
    doh_query(&dns, &upstream, &endpoint, "after.test").await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
    dns.retire();
    server.abort();
}

/// A DoH server that takes only HTTP/1.1 answers every query on a
/// connection of the query's own, the ones that come together included.
#[tokio::test]
async fn doh_over_http1_gives_each_query_its_own_connection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Https);
    let (server_config, mut client_config) = tls_configs(&[b"http/1.1"]);
    let mut dns = service();
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = dns.https_tls.alpn_protocols.clone();
    Arc::get_mut(&mut dns).unwrap().https_tls = client_config;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts = Arc::clone(&accepted);
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let server_config = server_config.clone();
            tokio::spawn(async move {
                let stream = tokio_rustls::TlsAcceptor::from(server_config)
                    .accept(socket)
                    .await
                    .unwrap();
                let handler =
                    service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let query = wire::decode(&bytes).unwrap();
                        let bytes = wire::encode(&full_answer(&query)).unwrap();
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(http::header::CONTENT_TYPE, "application/dns-message")
                                .body(Full::new(Bytes::from(bytes)))
                                .unwrap(),
                        )
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            });
        }
    });
    let query = |index: usize| {
        let dns = Arc::clone(&dns);
        let upstream = upstream.clone();
        let endpoint = endpoint.clone();
        async move {
            let request = wire::query(&format!("answer{index}.test"), RecordType::TXT).unwrap();
            let reply = tokio::time::timeout(
                Duration::from_secs(3),
                exchange(
                    &dns,
                    &request,
                    &upstream,
                    "DIRECT",
                    &endpoint,
                    Default::default(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply.answers, full_answer(&request).answers);
        }
    };
    query(1).await;
    query(2).await;
    tokio::join!(query(3), query(4));
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 4);
    server.abort();
}

#[tokio::test]
async fn plain_http_uses_dns_wire_post_and_rejects_wrong_content_type() {
    for content_type in ["application/dns-message", "application/json"] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), DnsTransport::Http);
        let authority = endpoint.authority();
        let mut request = wire::query("answer.test", RecordType::TXT).unwrap();
        request.metadata.id = 0x4242;
        let mut http_query = request.clone();
        http_query.metadata.id = 0;
        let expected_body = wire::encode(&http_query).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let handler = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                let authority = authority.clone();
                let expected_body = expected_body.clone();
                async move {
                    assert_eq!(request.version(), http::Version::HTTP_11);
                    assert_eq!(request.method(), http::Method::POST);
                    assert_eq!(request.uri().path(), "/dns-query");
                    assert!(request.uri().scheme().is_none());
                    assert_eq!(request.headers()[http::header::HOST], authority);
                    assert_eq!(
                        request.headers()[http::header::ACCEPT],
                        "application/dns-message"
                    );
                    assert_eq!(
                        request.headers()[http::header::CONTENT_TYPE],
                        "application/dns-message"
                    );
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(body.as_ref(), expected_body.as_slice());
                    let query = wire::decode(&body).unwrap();
                    let answer = wire::encode(&full_answer(&query)).unwrap();
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .header(http::header::CONTENT_TYPE, content_type)
                            .body(Full::new(Bytes::from(answer)))
                            .unwrap(),
                    )
                }
            });
            // A plain TCP HTTP/1.1 peer cannot accept an accidental TLS handshake.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), handler)
                .await;
        });
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(
                &service(),
                &request,
                &upstream,
                "DIRECT",
                &endpoint,
                Default::default(),
            ),
        )
        .await
        .unwrap();
        if content_type == "application/dns-message" {
            let reply = reply.unwrap();
            let expected = full_answer(&request);
            assert_eq!(reply.id, request.id);
            assert_eq!(reply.answers, expected.answers);
            assert_eq!(reply.authorities, expected.authorities);
            assert_eq!(reply.additionals, expected.additionals);
        } else {
            assert_eq!(
                reply.unwrap_err(),
                "DNS HTTP response has an invalid content type"
            );
        }
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn encrypted_dns_rejects_untrusted_origin_certificates() {
    for transport in [DnsTransport::Tls, DnsTransport::Https] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (upstream, endpoint) = upstream(listener.local_addr().unwrap(), transport);
        let (server_config, _) = tls_configs(&[]);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_rustls::TlsAcceptor::from(server_config)
                .accept(socket)
                .await
                .is_err()
        });
        let request = wire::query("answer.test", RecordType::TXT).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(
                &service(),
                &request,
                &upstream,
                "DIRECT",
                &endpoint,
                Default::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.contains("TLS handshake failed"), "{error}");
        assert!(tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap());
    }
}

#[tokio::test]
async fn udp_ignores_unrelated_same_id_questions_before_accepting_a_matching_reply() {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (upstream, endpoint) = upstream(socket.local_addr().unwrap(), DnsTransport::Udp);
    let server = tokio::spawn(async move {
        let mut bytes = vec![0; u16::MAX as usize];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let query = wire::decode(&bytes[..length]).unwrap();
        let mut wrong_query = wire::query("unrelated.test", RecordType::TXT).unwrap();
        wrong_query.metadata.id = query.id;
        socket
            .send_to(&wire::encode(&full_answer(&wrong_query)).unwrap(), peer)
            .await
            .unwrap();
        socket
            .send_to(&wire::encode(&full_answer(&query)).unwrap(), peer)
            .await
            .unwrap();
    });
    let request = wire::query("answer.test", RecordType::TXT).unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        exchange(
            &service(),
            &request,
            &upstream,
            "DIRECT",
            &endpoint,
            Default::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply.answers, full_answer(&request).answers);
    server.await.unwrap();
}

#[tokio::test]
async fn a_lost_udp_query_goes_out_again_well_within_the_budget() {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (upstream, endpoint) = upstream(socket.local_addr().unwrap(), DnsTransport::Udp);
    let server = tokio::spawn(async move {
        let mut bytes = vec![0; u16::MAX as usize];
        // The first query is lost; the second is answered.
        socket.recv_from(&mut bytes).await.unwrap();
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let query = wire::decode(&bytes[..length]).unwrap();
        socket
            .send_to(&wire::encode(&full_answer(&query)).unwrap(), peer)
            .await
            .unwrap();
    });
    let request = wire::query("answer.test", RecordType::TXT).unwrap();
    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        exchange(
            &service(),
            &request,
            &upstream,
            "DIRECT",
            &endpoint,
            Default::default(),
        ),
    )
    .await
    .expect("answered before the server's budget runs out")
    .unwrap();
    assert_eq!(reply.answers, full_answer(&request).answers);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    server.await.unwrap();
}
