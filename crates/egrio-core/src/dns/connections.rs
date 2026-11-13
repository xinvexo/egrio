//! Connections to stream DNS servers kept for the queries after the one
//! that opened them. A query over TCP or DoT has a connection to itself and
//! gives it back once its answer is in (RFC 7766 §6.2.1, RFC 7858 §3.4); a
//! DoH server's HTTP/2 connection carries every query to that server at
//! once (RFC 8484 §5). Without them every query that missed the cache paid
//! the TCP and TLS handshakes again, two round trips more, and over a proxy
//! node a new connection to the node as well.
//!
//! A connection serves only queries to the same server over the same route.
//! TCP and DoT connections idle longer than [`STREAM_IDLE`] are not reused:
//! servers close idle connections after some seconds, and a query sent on a
//! closed one would wait for the failure before going out again. An HTTP/2
//! connection is driven by a task of the service's that ends when the
//! service retires or the network changes, the one thing here that outlives
//! the query that opened it.
//!
//! An HTTP/2 connection waits for the next query as long as [`Http2Keep`]
//! says, sending PING frames meanwhile (RFC 9113 §6.7): a server or a path
//! that stopped answering shows as a PING without its acknowledgement, which
//! closes the connection before a query is sent on it, and the PINGs keep the
//! path's NAT state. In fake-IP mode the profile's nameserver is asked only
//! when a new name meets an IP rule, often minutes apart; a connection
//! dropped after a minute idle would make each such lookup pay for new
//! TCP and TLS handshakes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use tokio::task::AbortHandle;

use super::config::{DnsTransport, DnsUpstream};
use crate::outbound::BoxedOutboundStream;
use crate::target::ConnectTarget;

/// How long a TCP or DoT connection may idle and still take a query.
const STREAM_IDLE: Duration = Duration::from_secs(10);
/// Idle TCP or DoT connections kept per server and route; concurrent
/// queries open more, and those past this many close when they finish.
const IDLE_STREAMS: usize = 4;
/// How a DoH server's HTTP/2 connection is kept between queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Http2Keep {
    /// How often a PING goes out while the connection waits.
    pub(super) ping: Duration,
    /// A PING not acknowledged within this closes the connection.
    pub(super) ping_timeout: Duration,
    /// The connection closes after this long without a query.
    pub(super) idle: Duration,
}

impl Default for Http2Keep {
    fn default() -> Self {
        Self {
            ping: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(10),
            idle: Duration::from_secs(600),
        }
    }
}
/// How long a DoH server that took only HTTP/1.1 is believed to: its
/// queries open their own connections at once rather than one after another
/// at the slot.
const HTTP1_MEMORY: Duration = Duration::from_secs(600);

/// A server reached over one route.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct ConnectionKey {
    transport: DnsTransport,
    outbound: String,
    endpoint: String,
    server_name: Option<String>,
}

impl ConnectionKey {
    pub(super) fn new(
        transport: DnsTransport,
        upstream: &DnsUpstream,
        outbound: &str,
        endpoint: &ConnectTarget,
    ) -> Self {
        Self {
            transport,
            outbound: outbound.to_ascii_lowercase(),
            endpoint: endpoint.authority(),
            server_name: upstream.server_name.clone(),
        }
    }
}

/// A DoH server's HTTP/2 connection: the handle requests go through and
/// the task that drives the connection.
pub(super) struct Http2 {
    sender: SendRequest<Full<Bytes>>,
    driver: AbortHandle,
    /// When a query last took the connection, which its driver reads to
    /// close it once it idled [`Http2Keep::idle`].
    used: Arc<Mutex<Instant>>,
    idle: Duration,
}

impl Http2 {
    pub(super) fn new(
        sender: SendRequest<Full<Bytes>>,
        driver: AbortHandle,
        used: Arc<Mutex<Instant>>,
        idle: Duration,
    ) -> Self {
        Self {
            sender,
            driver,
            used,
            idle,
        }
    }

    /// A handle for one more request, unless the connection closed or idled
    /// too long; with it, the connection's identity.
    pub(super) fn take_turn(&mut self) -> Option<(SendRequest<Full<Bytes>>, tokio::task::Id)> {
        let mut used = self.used.lock().expect("HTTP/2 last use");
        if self.sender.is_closed() || used.elapsed() >= self.idle {
            return None;
        }
        *used = Instant::now();
        drop(used);
        Some((self.sender.clone(), self.driver.id()))
    }

    pub(super) fn id(&self) -> tokio::task::Id {
        self.driver.id()
    }

    pub(super) fn sender(&self) -> SendRequest<Full<Bytes>> {
        self.sender.clone()
    }
}

impl Drop for Http2 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// One DoH server's HTTP/2 connection, if any, or that the server takes
/// only HTTP/1.1. Held across the handshake, so queries that come together
/// share one connection.
#[derive(Default)]
pub(super) struct Http2State {
    pub(super) connection: Option<Http2>,
    http1_since: Option<Instant>,
}

impl Http2State {
    /// Whether the server lately answered only over HTTP/1.1.
    pub(super) fn takes_http1_only(&self) -> bool {
        self.http1_since
            .is_some_and(|since| since.elapsed() < HTTP1_MEMORY)
    }

    /// Notes what the server took on the latest connection.
    pub(super) fn took_http2(&mut self, http2: bool) {
        self.http1_since = (!http2).then(Instant::now);
    }
}

pub(super) type Http2Slot = Arc<tokio::sync::Mutex<Http2State>>;

#[derive(Default)]
pub(super) struct DnsConnections {
    streams: Mutex<HashMap<ConnectionKey, Vec<(BoxedOutboundStream, Instant)>>>,
    http2: Mutex<HashMap<ConnectionKey, Http2Slot>>,
    http2_keep: Http2Keep,
}

/// Closes the idle connections of every server that idled too long, so one
/// no query uses any more does not hold a connection (through a proxy node,
/// the node's too) until the network changes.
fn close_stale(streams: &mut HashMap<ConnectionKey, Vec<(BoxedOutboundStream, Instant)>>) {
    streams.retain(|_, idle| {
        idle.retain(|(_, since)| since.elapsed() < STREAM_IDLE);
        !idle.is_empty()
    });
}

impl std::fmt::Debug for DnsConnections {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let streams = self
            .streams
            .lock()
            .map(|streams| streams.values().map(Vec::len).sum::<usize>())
            .unwrap_or_default();
        let http2 = self
            .http2
            .lock()
            .map(|http2| http2.len())
            .unwrap_or_default();
        formatter
            .debug_struct("DnsConnections")
            .field("idle_streams", &streams)
            .field("http2_servers", &http2)
            .finish()
    }
}

impl DnsConnections {
    /// Connections whose HTTP/2 ones are kept as `keep` says.
    #[cfg(test)]
    pub(super) fn keeping_http2(keep: Http2Keep) -> Self {
        Self {
            http2_keep: keep,
            ..Self::default()
        }
    }

    pub(super) fn http2_keep(&self) -> Http2Keep {
        self.http2_keep
    }

    /// The most recently used idle connection to the server, if one idled
    /// less than [`STREAM_IDLE`]; older ones close.
    pub(super) fn take_stream(&self, key: &ConnectionKey) -> Option<BoxedOutboundStream> {
        let mut streams = self.streams.lock().expect("DNS connections mutex");
        close_stale(&mut streams);
        let idle = streams.get_mut(key)?;
        let stream = idle.pop().map(|(stream, _)| stream);
        if idle.is_empty() {
            streams.remove(key);
        }
        stream
    }

    /// Keeps a connection whose exchange completed for the next query.
    pub(super) fn put_stream(&self, key: ConnectionKey, stream: BoxedOutboundStream) {
        let mut streams = self.streams.lock().expect("DNS connections mutex");
        close_stale(&mut streams);
        let idle = streams.entry(key).or_default();
        if idle.len() >= IDLE_STREAMS {
            idle.remove(0);
        }
        idle.push((stream, Instant::now()));
    }

    pub(super) fn http2_slot(&self, key: &ConnectionKey) -> Http2Slot {
        let mut http2 = self.http2.lock().expect("DNS connections mutex");
        Arc::clone(http2.entry(key.clone()).or_default())
    }

    /// Closes every connection: the service retired, or the network they
    /// went out on changed. An HTTP/2 connection in a handshake now is left
    /// to that query and closes with it.
    pub(super) fn clear(&self) {
        self.streams.lock().expect("DNS connections mutex").clear();
        let slots: Vec<Http2Slot> = self
            .http2
            .lock()
            .expect("DNS connections mutex")
            .drain()
            .map(|(_, slot)| slot)
            .collect();
        for slot in slots {
            if let Ok(mut held) = slot.try_lock() {
                held.connection.take();
            }
        }
    }
}
