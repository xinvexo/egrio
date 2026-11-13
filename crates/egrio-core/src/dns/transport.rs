//! Standard DNS transports over a chosen physical or proxy connection.

use bytes::Bytes;
use hickory_proto::op::Message;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::config::{DnsTransport, DnsUpstream};
use super::connections::{ConnectionKey, Http2};
#[cfg(test)]
use super::connections::{DnsConnections, Http2Keep};
use super::service::{DnsService, QueryContext};
use super::wire;
use crate::outbound::BoxedOutboundStream;
use crate::target::ConnectTarget;

/// How long a query over UDP waits for its answer before it goes out again,
/// doubling after each send; the caller's deadline for the server bounds the
/// exchange. A resolver answers within tens of milliseconds, so this fires
/// when the query or the answer was lost, which would otherwise cost the
/// whole budget for the server and, with one server, fail the lookup.
const UDP_RETRANSMIT: std::time::Duration = std::time::Duration::from_millis(500);

pub(super) async fn exchange(
    service: &Arc<DnsService>,
    request: &Message,
    upstream: &DnsUpstream,
    outbound: &str,
    endpoint: &ConnectTarget,
    context: QueryContext,
) -> Result<Message, String> {
    if upstream.transport == DnsTransport::Udp {
        let bytes = wire::encode(request)?;
        let reply = if outbound.eq_ignore_ascii_case("direct") {
            let socket = service
                .physical
                .bind_udp_for_host(&endpoint.host, "DNS UDP socket")
                .await
                .map_err(|error| error.to_string())?;
            socket
                .connect(endpoint.authority())
                .await
                .map_err(|error| error.to_string())?;
            socket
                .send(&bytes)
                .await
                .map_err(|error| error.to_string())?;
            let mut response = vec![0; u16::MAX as usize];
            let mut wait = UDP_RETRANSMIT;
            let mut resend = tokio::time::Instant::now() + wait;
            loop {
                let length = tokio::select! {
                    received = socket.recv(&mut response) => {
                        received.map_err(|error| error.to_string())?
                    }
                    () = tokio::time::sleep_until(resend) => {
                        // The same socket takes the answer to either send.
                        socket
                            .send(&bytes)
                            .await
                            .map_err(|error| error.to_string())?;
                        wait *= 2;
                        resend += wait;
                        continue;
                    }
                };
                if let Ok(reply) = wire::decode(&response[..length]) {
                    if wire::validate_response(request, &reply).is_ok() {
                        break reply;
                    }
                }
            }
        } else {
            let mut transport = service
                .connect_datagram(outbound, endpoint, context.clone())
                .await?;
            transport
                .sender
                .send(endpoint, &bytes)
                .await
                .map_err(|error| error.to_string())?;
            let mut wait = UDP_RETRANSMIT;
            let mut resend = tokio::time::Instant::now() + wait;
            loop {
                let received = tokio::select! {
                    received = transport.receiver.recv() => {
                        received.map_err(|error| error.to_string())?
                    }
                    () = tokio::time::sleep_until(resend) => {
                        transport
                            .sender
                            .send(endpoint, &bytes)
                            .await
                            .map_err(|error| error.to_string())?;
                        wait *= 2;
                        resend += wait;
                        continue;
                    }
                };
                let Some((remote, payload)) = received else {
                    return Err("DNS datagram transport closed".into());
                };
                if remote.ip() != endpoint.ip() || remote.port != endpoint.port {
                    continue;
                }
                if let Ok(reply) = wire::decode(&payload) {
                    if wire::validate_response(request, &reply).is_ok() {
                        break reply;
                    }
                }
            }
        };
        if !reply.truncated() {
            return Ok(reply);
        }
        return exchange_framed(
            service,
            request,
            DnsTransport::Tcp,
            upstream,
            outbound,
            endpoint,
            context,
        )
        .await;
    }
    match upstream.transport {
        DnsTransport::Tcp | DnsTransport::Tls => {
            exchange_framed(
                service,
                request,
                upstream.transport,
                upstream,
                outbound,
                endpoint,
                context,
            )
            .await
        }
        DnsTransport::Https => {
            exchange_https(service, request, upstream, outbound, endpoint, context).await
        }
        DnsTransport::Http => {
            let (stream, _) = open_stream(service, upstream, outbound, endpoint, context).await?;
            exchange_http1(stream, request, upstream).await
        }
        _ => Err("unsupported DNS transport".into()),
    }
}

/// A connection to the server over the route, wrapped in TLS for DoT and
/// DoH; with whether the server took HTTP/2.
async fn open_stream(
    service: &Arc<DnsService>,
    upstream: &DnsUpstream,
    outbound: &str,
    endpoint: &ConnectTarget,
    context: QueryContext,
) -> Result<(BoxedOutboundStream, bool), String> {
    let stream = service.connect_stream(outbound, endpoint, context).await?;
    if !matches!(upstream.transport, DnsTransport::Tls | DnsTransport::Https) {
        return Ok((stream, false));
    }
    let name = upstream
        .server_name
        .as_deref()
        .unwrap_or(&upstream.host)
        .to_owned();
    let name = rustls_pki_types::ServerName::try_from(name).map_err(|error| error.to_string())?;
    let tls = if upstream.transport == DnsTransport::Https {
        service.https_tls.clone()
    } else {
        service.tls.clone()
    };
    let secured = tokio_rustls::TlsConnector::from(tls)
        .connect(name, stream)
        .await
        .map_err(|error| format!("DNS TLS handshake failed: {error}"))?;
    let h2 = secured.get_ref().1.alpn_protocol() == Some(b"h2");
    Ok((Box::new(secured), h2))
}

/// A query over TCP (`transport` TCP, also a truncated UDP answer's retry)
/// or DoT, on a connection kept from an earlier query when there is one.
/// A kept connection the server has closed since fails at once; a new one
/// then takes the query, which a DNS server may answer twice.
async fn exchange_framed(
    service: &Arc<DnsService>,
    request: &Message,
    transport: DnsTransport,
    upstream: &DnsUpstream,
    outbound: &str,
    endpoint: &ConnectTarget,
    context: QueryContext,
) -> Result<Message, String> {
    let key = ConnectionKey::new(transport, upstream, outbound, endpoint);
    if let Some(mut stream) = service.connections.take_stream(&key) {
        if let Ok(reply) = exchange_tcp(&mut stream, request).await {
            service.connections.put_stream(key, stream);
            return Ok(reply);
        }
    }
    let (mut stream, _) = open_stream(service, upstream, outbound, endpoint, context).await?;
    let reply = exchange_tcp(&mut stream, request).await?;
    service.connections.put_stream(key, stream);
    Ok(reply)
}

/// A DoH query on the server's HTTP/2 connection, opened by the first query
/// to need it while later ones wait for it. A kept connection that fails a
/// request is replaced once. A server that does not take HTTP/2 answers
/// over HTTP/1.1 on a connection of this query's own.
async fn exchange_https(
    service: &Arc<DnsService>,
    request: &Message,
    upstream: &DnsUpstream,
    outbound: &str,
    endpoint: &ConnectTarget,
    context: QueryContext,
) -> Result<Message, String> {
    let key = ConnectionKey::new(DnsTransport::Https, upstream, outbound, endpoint);
    let slot = service.connections.http2_slot(&key);
    let mut replaced = false;
    loop {
        let mut held = slot.lock().await;
        if let Some((sender, id)) = held.connection.as_mut().and_then(Http2::take_turn) {
            drop(held);
            match exchange_http2(sender, request, upstream).await {
                Err(HttpFailure::Connection(_)) if !replaced => {
                    replaced = true;
                    let mut held = slot.lock().await;
                    if held
                        .connection
                        .as_ref()
                        .is_some_and(|connection| connection.id() == id)
                    {
                        held.connection = None;
                    }
                    continue;
                }
                result => return result.map_err(HttpFailure::into_message),
            }
        }
        // Closed or idle too long: it goes, and this query opens the next,
        // the others waiting for it, unless the server takes only HTTP/1.1
        // and each query has a connection of its own anyway.
        held.connection = None;
        let held = (!held.takes_http1_only()).then_some(held);
        let (stream, h2) =
            open_stream(service, upstream, outbound, endpoint, context.clone()).await?;
        if !h2 {
            if let Some(mut held) = held {
                held.took_http2(false);
            }
            return exchange_http1(stream, request, upstream).await;
        }
        let connection = start_http2(service, stream).await?;
        let sender = connection.sender();
        let mut held = match held {
            Some(held) => held,
            None => slot.lock().await,
        };
        held.took_http2(true);
        // A connection another query opened meanwhile stays; this one then
        // carries only this query.
        let own = if held.connection.is_none() {
            held.connection = Some(connection);
            None
        } else {
            Some(connection)
        };
        drop(held);
        let reply = exchange_http2(sender, request, upstream).await;
        drop(own);
        return reply.map_err(HttpFailure::into_message);
    }
}

/// Starts an HTTP/2 connection on `stream`, driven by a task that runs
/// while queries hold its handle and the service stands: dropping the kept
/// connection, retiring the service or its idle time without a query
/// ends it. While it waits it sends PINGs, and one left unacknowledged
/// closes it (see `dns/connections.rs`).
async fn start_http2(
    service: &Arc<DnsService>,
    stream: BoxedOutboundStream,
) -> Result<Http2, String> {
    let keep = service.connections.http2_keep();
    let (sender, connection) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(keep.ping)
            .keep_alive_timeout(keep.ping_timeout)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|error| http_error("HTTP/2 handshake", &error))?;
    let cancel = service.cancel.clone();
    let used = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let last_use = Arc::clone(&used);
    let driver = tokio::spawn(async move {
        tokio::pin!(connection);
        loop {
            let used = *last_use.lock().expect("HTTP/2 last use");
            let idle_until = tokio::time::Instant::from_std(used) + keep.idle;
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = &mut connection => break,
                () = tokio::time::sleep_until(idle_until) => {
                    if last_use.lock().expect("HTTP/2 last use").elapsed() >= keep.idle {
                        break;
                    }
                }
            }
        }
    })
    .abort_handle();
    Ok(Http2::new(sender, driver, used, keep.idle))
}

/// Why a DoH exchange failed: the connection (another may carry the query)
/// or the server's answer.
enum HttpFailure {
    Connection(String),
    Answer(String),
}

impl HttpFailure {
    fn into_message(self) -> String {
        match self {
            Self::Connection(message) | Self::Answer(message) => message,
        }
    }
}

pub(crate) async fn exchange_tcp(
    stream: &mut BoxedOutboundStream,
    request: &Message,
) -> Result<Message, String> {
    let bytes = wire::encode(request)?;
    let length = u16::try_from(bytes.len()).map_err(|_| "DNS request exceeds TCP frame limit")?;
    stream
        .write_u16(length)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;
    let length = stream.read_u16().await.map_err(|error| error.to_string())? as usize;
    let mut response = vec![0; length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| error.to_string())?;
    let response = wire::decode(&response)?;
    wire::validate_response(request, &response)?;
    if response.truncated() {
        return Err("DNS TCP response is truncated".into());
    }
    Ok(response)
}

/// The DoH request for `request` (RFC 8484 §4.1: a POST of the wire
/// message with ID 0), and that query.
fn http_request(
    request: &Message,
    upstream: &DnsUpstream,
    h2: bool,
) -> Result<(http::Request<Full<Bytes>>, Message), String> {
    let mut http_query = request.clone();
    http_query.set_id(0);
    let authority = ConnectTarget {
        host: upstream.host.clone(),
        port: upstream.port,
    }
    .authority();
    let uri = if h2 {
        format!("https://{authority}{}", upstream.path)
    } else {
        upstream.path.clone()
    };
    let mut http_request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_TYPE, "application/dns-message");
    if !h2 {
        // HTTP/1.1 uses Host. HTTP/2 takes :authority from the absolute URI;
        // keep that as the single authority field on the HTTP/2 wire.
        http_request = http_request.header(http::header::HOST, authority);
    }
    let http_request = http_request
        .body(Full::new(Bytes::from(wire::encode(&http_query)?)))
        .map_err(|error| error.to_string())?;
    Ok((http_request, http_query))
}

/// A DoH query over HTTP/2 on a connection another task drives.
async fn exchange_http2(
    mut sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    request: &Message,
    upstream: &DnsUpstream,
) -> Result<Message, HttpFailure> {
    let (http_request, http_query) =
        http_request(request, upstream, true).map_err(HttpFailure::Answer)?;
    sender
        .ready()
        .await
        .map_err(|error| HttpFailure::Connection(http_error("HTTP/2 connection", &error)))?;
    let reply = sender
        .send_request(http_request)
        .await
        .map_err(|error| HttpFailure::Connection(http_error("HTTP/2 request", &error)))?;
    let mut reply = decode_http(reply, &http_query).await?;
    reply.set_id(request.id());
    Ok(reply)
}

/// A DoH (or plain HTTP) query over HTTP/1.1 on a connection of its own,
/// driven here and closed when the answer is in.
async fn exchange_http1(
    stream: BoxedOutboundStream,
    request: &Message,
    upstream: &DnsUpstream,
) -> Result<Message, String> {
    let (http_request, http_query) = http_request(request, upstream, false)?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| http_error("HTTP/1.1 handshake", &error))?;
    let mut reply = drive_http(connection, async {
        let reply = sender
            .send_request(http_request)
            .await
            .map_err(|error| http_error("HTTP/1.1 request", &error))?;
        decode_http(reply, &http_query)
            .await
            .map_err(HttpFailure::into_message)
    })
    .await?;
    reply.set_id(request.id());
    Ok(reply)
}

async fn decode_http(
    reply: http::Response<hyper::body::Incoming>,
    request: &Message,
) -> Result<Message, HttpFailure> {
    if !reply.status().is_success() {
        return Err(HttpFailure::Answer(format!(
            "DNS HTTP server returned {}",
            reply.status()
        )));
    }
    let content_type = reply
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/dns-message")
    {
        return Err(HttpFailure::Answer(
            "DNS HTTP response has an invalid content type".into(),
        ));
    }
    let age = reply
        .headers()
        .get(http::header::AGE)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| HttpFailure::Answer("invalid DNS HTTP Age header".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let body = Limited::new(reply.into_body(), u16::MAX as usize)
        .collect()
        .await
        .map_err(|error| HttpFailure::Connection(http_error("response body", error.as_ref())))?
        .to_bytes();
    let mut reply = wire::decode(&body).map_err(HttpFailure::Answer)?;
    wire::validate_response(request, &reply).map_err(HttpFailure::Answer)?;
    if reply.truncated() {
        return Err(HttpFailure::Answer("DNS HTTP response is truncated".into()));
    }
    wire::age_ttls(&mut reply, std::time::Duration::from_secs(age));
    Ok(reply)
}

async fn drive_http(
    connection: impl std::future::Future<Output = Result<(), hyper::Error>>,
    exchange: impl std::future::Future<Output = Result<Message, String>>,
) -> Result<Message, String> {
    tokio::pin!(connection);
    tokio::pin!(exchange);
    tokio::select! {
        biased;
        result = &mut exchange => result,
        result = &mut connection => { result.map_err(|error| http_error("HTTP connection", &error))?; exchange.await },
    }
}

fn http_error(stage: &str, error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = format!("DNS HTTP {stage}: {error}");
    let mut source = error.source();
    while let Some(error) = source {
        message.push_str(": ");
        message.push_str(&error.to_string());
        source = error.source();
    }
    message
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
