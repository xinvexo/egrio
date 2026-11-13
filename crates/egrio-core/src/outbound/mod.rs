//! The outbound layer's object contract.
//!
//! Physical outbounds are protocol connectors behind one trait: the
//! dispatcher only ever asks for "one stream / one datagram transport to
//! this target" and relays whatever comes back. Handshake, crypto, and any
//! connection reuse (mux carriers, connection pools, QUIC streams) are
//! implementation details on the connector side: a connector is shared by
//! every session pinning its snapshot (`&self`, `Send + Sync`), so it can
//! hold pooled state internally, and the IO objects it returns are
//! `'static`, so they can carry shared handles into that state. Adding a
//! protocol therefore touches exactly one dispatcher-facing line — the
//! vocabulary match in `RuntimeSnapshot::compile` — which is what the
//! protocol-vocabulary gate ("new protocols change no Dispatcher/Router
//! behavior") pins down.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::egress::EgressRuntime;
use crate::target::ConnectTarget;

mod carrier;
mod datagram;
#[cfg(feature = "bench-internals")]
pub use datagram::udp_buffer_borrows;
mod direct;
mod error;
mod hop;
pub(crate) mod options;
mod warm;
pub(crate) use carrier::{
    dial_carrier, dial_carrier_via, dial_lasting_carrier, dial_server, ProxyTls, ServerStream,
};
pub(crate) use datagram::{
    after_receive_error, is_datagram_event, recv_datagram, DatagramError, DatagramFuture,
    DatagramOperation, DatagramSendCancellation, UDP_DATAGRAM_BUFFERS, UDP_DATAGRAM_CAPACITY,
};
pub use error::OutboundStage;
pub(crate) use error::{OutboundError, OutboundResultExt};
pub(crate) use hop::{
    chain_issue, chained_datagrams, held_until_closed, DatagramCodec, Dialer, Hop, Hops,
};
pub(crate) use warm::{CarrierDial, WarmCarriers};
pub(crate) mod probe;

pub(crate) use direct::DirectConnector;

/// Whole outbound transport establishment: DNS, socket connect, carrier
/// admission and protocol authentication share this ceiling for TCP and UDP.
pub(crate) const OUTBOUND_DIAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Boxed future all connector methods return: keeps the trait
/// object-safe without an async-trait dependency.
pub(crate) type OutboundFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, OutboundError>> + Send + 'a>>;

/// Any duplex byte stream. This is the whole interface the relay stage
/// needs from an outbound protocol; framed/encrypted protocols present
/// their plaintext side as this.
pub(crate) trait OutboundStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> OutboundStream for T {}

pub(crate) type BoxedOutboundStream = Box<dyn OutboundStream>;

/// The compiled snapshot's table of dialable outbounds by name.
pub(crate) type OutboundTable = HashMap<String, Arc<dyn OutboundConnector>>;

/// One physical outbound protocol.
pub(crate) trait OutboundConnector: Send + Sync + fmt::Debug {
    /// Dials one bidirectional byte stream to `target`.
    ///
    /// On success `early_data` (the client prefix the sniff stage consumed)
    /// has been accepted for in-order delivery ahead of relay bytes: protocols
    /// with an early-data slot fold it into their handshake; everything else
    /// writes it right after the handshake
    /// via [`write_early_data`]. The caller accounts it as upload.
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream>;

    /// Dials one datagram transport to `target`. Only called when
    /// [`supports_udp`](Self::supports_udp) returns true.
    fn connect_datagram<'a>(
        &'a self,
        _egress: &'a EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(std::future::ready(Err(OutboundError::new(
            OutboundStage::Config,
            "outbound protocol does not relay UDP",
        ))))
    }

    fn supports_tcp(&self) -> bool {
        true
    }

    fn supports_udp(&self) -> bool {
        false
    }

    /// The profile's `udp` switch: whether rule matching may send a UDP flow
    /// here. A UDP flow skips a rule whose outbound has it off and keeps
    /// matching, so a later rule decides instead of the flow being dropped.
    /// Global mode sends UDP to its outbound regardless, so this is a routing
    /// switch, not a capability; that is `supports_udp`.
    fn udp_enabled(&self) -> bool {
        self.supports_udp()
    }

    /// Whether this outbound dials the origin target itself instead of a
    /// proxy hop. Only then does the Core resolve a TCP target name; a proxy
    /// is handed the name. Also used for target-scope policy checks and the
    /// packet pipeline's direct/proxied action counters, not protocol-name
    /// dispatch.
    fn is_direct(&self) -> bool {
        false
    }

    /// The host's network changed. A connector that keeps a carrier for
    /// later dials moves it onto the network that is there now; `egress` is
    /// the policy to bind its new socket with. The Core ends stranded
    /// per-connection sockets itself.
    fn network_changed(
        &self,
        _change: &crate::egress::NetworkChange,
        _egress: &crate::egress::EgressRuntime,
    ) {
    }

    /// The runtime whose tasks drive the connection every stream of this
    /// outbound shares, while one is up (a Hysteria2 carrier). A flow through
    /// it does least work when it runs there too.
    fn carrier_runtime(&self) -> Option<tokio::runtime::Id> {
        None
    }
}

/// Send half of a datagram transport: frames/encrypts one payload toward
/// `target` per call. `&self` so the UDP session actor can send while the
/// receive half is parked in its background reader; implementations lock
/// internally when their wire form needs it.
///
/// `target` rides every send instead of being fixed at connect: one session
/// keyed by the client 2-tuple (capture-redesign R2) is endpoint-independent
/// (RFC 4787 EIM), so a single transport carries datagrams to every remote
/// the client addresses.
pub(crate) trait OutboundDatagramSender: Send + Sync {
    fn send_cancellation(&self) -> DatagramSendCancellation;

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()>;
}

/// Receive half of a datagram transport: yields decoded response payloads
/// paired with the remote they came from.
///
/// `Ok(Some((remote, payload)))` is one datagram and `Ok(None)` ends the
/// transport. Native socket packet errors preserve its mapping; carrier and
/// protocol failures terminate it. The remote makes filtering endpoint-independent (RFC 4787
/// EIF): a reply from a remote the client never sent to (a hole-punched
/// peer) is still delivered, and the session sources each reply's framing
/// from its real origin. Decode-policy belongs to the implementation:
/// datagram codecs skip a single undecodable packet internally (one corrupt
/// datagram must not tear down the session) while framed stream tunnels end
/// instead — a byte stream cannot resync mid-frame.
pub(crate) trait OutboundDatagramReceiver: Send {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>>;

    /// The transport's datagrams as the packet pump can drive them itself for
    /// a captured flow; `None` for a transport that only the actor can drive.
    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        None
    }

    /// While the packet pump drives the datagrams, resolves when the
    /// transport ends anyway: `Ok` when the carrier that holds it closed (a
    /// SOCKS5 association's control connection), an error when the carrier
    /// failed. Never by default: a transport the pump drives fails through
    /// its sends and reads.
    fn ended(&mut self) -> DatagramFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

/// A datagram transport the packet pump drives itself for a captured flow:
/// sends that never wait, and replies it reads when their readiness wakes it.
pub(crate) trait PumpDatagrams: Send + Sync {
    /// Sends one datagram to `to` without waiting. `WouldBlock` loses it like
    /// any datagram; `NotConnected` means the transport cannot send there
    /// (yet), and the full send path must.
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> std::io::Result<()>;

    /// Sends a train of datagrams to `to`: `segment` payload bytes each, the
    /// last one fewer, without waiting. The number sent; an error only when
    /// none was, with [`Self::try_send`]'s meaning.
    fn try_send_train(
        &self,
        to: &PumpTo,
        payload: &[u8],
        segment: usize,
    ) -> std::io::Result<usize> {
        let mut sent = 0;
        for datagram in payload.chunks(segment) {
            match self.try_send(to, datagram) {
                Ok(()) => sent += 1,
                Err(error) if sent == 0 => return Err(error),
                Err(_) => break,
            }
        }
        Ok(sent)
    }

    /// From now on replies wake `waker`; the receive half is no longer polled.
    fn hand_reads_to(&self, waker: std::task::Waker);

    /// One read without waiting: the bytes (several datagrams of one sender
    /// when the platform coalesces them), their sender, and the size of each
    /// datagram but the last. `WouldBlock` once nothing waits, with the
    /// wakeup registered again.
    fn try_recv(&self, buffer: &mut [u8]) -> std::io::Result<(usize, PumpFrom, usize)>;
}

/// Where the packet pump sends a learned flow's datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PumpTo {
    Addr(std::net::SocketAddr),
    /// A host name the proxy resolves (strict global mode), as `host:port`.
    Name(Arc<str>),
}

impl PumpTo {
    /// Appends where to send as a SOCKS address, the encoding of
    /// [`ConnectTarget::socks_address`], an address without going through
    /// text. A scoped IPv6 address is refused: its zone is node-local and
    /// the encoding has no field for it.
    pub(crate) fn push_socks_address(&self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            PumpTo::Addr(std::net::SocketAddr::V4(remote)) => {
                out.push(0x01);
                out.extend_from_slice(&remote.ip().octets());
                out.extend_from_slice(&remote.port().to_be_bytes());
            }
            PumpTo::Addr(std::net::SocketAddr::V6(remote)) if remote.scope_id() == 0 => {
                out.push(0x04);
                out.extend_from_slice(&remote.ip().octets());
                out.extend_from_slice(&remote.port().to_be_bytes());
            }
            PumpTo::Addr(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "scoped IPv6 targets cannot be encoded for a remote proxy",
                ))
            }
            PumpTo::Name(authority) => out.extend(
                crate::target::parse_connect_authority(authority)
                    .and_then(|target| target.socks_address())
                    .map_err(io::Error::other)?,
            ),
        }
        Ok(())
    }
}

/// Who sent a datagram the packet pump read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PumpFrom {
    Addr(std::net::SocketAddr),
    /// A host name: a proxy may identify the sender of a reply by the name
    /// to which the request was addressed.
    Name(ConnectTarget),
}

impl PumpFrom {
    /// The sender a reply names: an address, or a name it was sent to.
    pub(crate) fn from_target(target: ConnectTarget) -> Self {
        match target.ip() {
            Some(ip) => PumpFrom::Addr(std::net::SocketAddr::new(ip, target.port)),
            None => PumpFrom::Name(target),
        }
    }

    /// The sender a SOCKS address at the front of `bytes` names, and the
    /// address's length; an address is read without going through text.
    pub(crate) fn from_socks_address(bytes: &[u8]) -> Option<(Self, usize)> {
        let port = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        match bytes.first() {
            Some(0x01) if bytes.len() >= 7 => {
                let ip: [u8; 4] = bytes[1..5].try_into().ok()?;
                Some((PumpFrom::Addr((ip, port(5)).into()), 7))
            }
            Some(0x04) if bytes.len() >= 19 => {
                let ip: [u8; 16] = bytes[1..17].try_into().ok()?;
                Some((PumpFrom::Addr((ip, port(17)).into()), 19))
            }
            Some(0x03) => crate::target::parse_socks_address(bytes)
                .ok()
                .map(|(target, length)| (PumpFrom::from_target(target), length)),
            _ => None,
        }
    }
}

/// What a connector hands the UDP session actor: the actor owns
/// queueing, response delivery, idle pruning, and teardown around these
/// halves for every protocol uniformly.
pub(crate) struct OutboundDatagramTransport {
    pub(crate) sender: Box<dyn OutboundDatagramSender>,
    pub(crate) receiver: Box<dyn OutboundDatagramReceiver>,
}

#[derive(Debug, Clone)]
pub(crate) struct OutboundAuth {
    pub(crate) username: String,
    pub(crate) password: String,
}

/// Writes sniffed early data during dial, for protocols without a native
/// early-data slot in their handshake. Flushed: the client may send nothing
/// more until this is answered, and the relay only flushes what it copied
/// itself, so data a TLS carrier buffered here would park both sides. The
/// caller classifies a failure: it knows whether the stream ends at the node
/// or at the destination.
pub(crate) async fn write_early_data(
    stream: &mut (impl AsyncWrite + Unpin),
    early_data: &[u8],
) -> io::Result<()> {
    if early_data.is_empty() {
        return Ok(());
    }
    stream.write_all(early_data).await?;
    stream.flush().await
}

pub(crate) fn proxy_auth(options: &JsonValue) -> Option<OutboundAuth> {
    let username = options::option_string(options, &["username", "user"])?;
    let password = options::option_string(options, &["password", "pass"])?;

    Some(OutboundAuth { username, password })
}

/// The protocol-vocabulary gate: protocols defined inside this test module — which no
/// dispatcher file can name — ride the unmodified dispatcher end to end.
/// The mux connector additionally proves the trait accommodates
/// connection reuse: it pools one carrier connection inside the connector
/// and serves concurrent sessions as substreams, invisibly to the relay.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::OwnedWriteHalf;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::{mpsc, Mutex as AsyncMutex};
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::capture::NativeCoreCaptureConfig;
    use crate::egress::NativeCoreEgressConfig;
    use crate::inbound::dispatch::handle_connect_client;
    use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
    use crate::runtime::{
        open_outbound_connection, NativeCoreRuntime, NativeCoreSessionState, RuntimeSnapshot,
    };
    use crate::self_test::run_socks5_client;
    use crate::udp::{drain_pending_udp_flow_responses, send_udp_flow_datagram, UdpDatagram};

    fn match_profile_to(outbound: &str) -> RuntimeProfile {
        let mut profile = RuntimeProfile::new("vocabulary-gate");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: outbound,
            no_resolve: false,
        }]
        .into();
        profile
    }

    /// Compiles a routable runtime and registers the foreign connector
    /// through the test injection point — the profile vocabulary never
    /// learns the protocol.
    fn runtime_with_connector(
        name: &str,
        connector: Arc<dyn OutboundConnector>,
    ) -> NativeCoreRuntime {
        let mut snapshot = RuntimeSnapshot::compile(
            &match_profile_to(name),
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test(name, connector);
        NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default())
    }

    // ---- A minimal mux wire protocol: `[stream id][u16 len][bytes]`,
    // `len == 0` closes the substream. One TCP carrier multiplexes them all.

    async fn read_frame(
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Option<(u8, Vec<u8>)>, String> {
        let mut header = [0_u8; 3];
        if stream.read_exact(&mut header).await.is_err() {
            return Ok(None);
        }
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;
        let mut data = vec![0_u8; length];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|error| error.to_string())?;
        Ok(Some((header[0], data)))
    }

    async fn write_frame(
        stream: &mut (impl AsyncWrite + Unpin),
        id: u8,
        data: &[u8],
    ) -> Result<(), String> {
        let mut frame = Vec::with_capacity(3 + data.len());
        frame.push(id);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        stream
            .write_all(&frame)
            .await
            .map_err(|error| error.to_string())
    }

    /// Accepts mux carriers, counts them, and echoes every frame back —
    /// data and close alike — so each substream behaves like an echo peer.
    fn spawn_mux_echo_server(listener: TcpListener, accepted: Arc<AtomicUsize>) {
        tokio::spawn(async move {
            loop {
                let Ok((mut carrier, _)) = listener.accept().await else {
                    break;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while let Ok(Some((id, data))) = read_frame(&mut carrier).await {
                        if write_frame(&mut carrier, id, &data).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    type MuxStreamRegistry = Arc<StdMutex<HashMap<u8, mpsc::UnboundedSender<Vec<u8>>>>>;

    /// A mux/pooled protocol the dispatcher has never heard of: substreams
    /// over one lazily dialed, connector-held carrier connection. Early
    /// data folds into the substream's first frame (its handshake slot).
    struct MuxTestConnector {
        server: SocketAddr,
        carrier: AsyncMutex<Option<MuxCarrier>>,
        carriers_opened: AtomicUsize,
        next_stream_id: AtomicU8,
    }

    struct MuxCarrier {
        write: Arc<AsyncMutex<OwnedWriteHalf>>,
        streams: MuxStreamRegistry,
    }

    impl fmt::Debug for MuxTestConnector {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MuxTestConnector")
        }
    }

    impl MuxTestConnector {
        fn new(server: SocketAddr) -> Self {
            Self {
                server,
                carrier: AsyncMutex::new(None),
                carriers_opened: AtomicUsize::new(0),
                next_stream_id: AtomicU8::new(0),
            }
        }

        /// Returns the live carrier, dialing it on first use. The pool
        /// state lives behind `&self`, which is what the trait's shape
        /// must permit for mux/pooled protocols.
        async fn carrier(
            &self,
        ) -> Result<(Arc<AsyncMutex<OwnedWriteHalf>>, MuxStreamRegistry), String> {
            let mut slot = self.carrier.lock().await;
            if slot.is_none() {
                let stream = TcpStream::connect(self.server)
                    .await
                    .map_err(|error| error.to_string())?;
                let (mut read, write) = stream.into_split();
                let streams: MuxStreamRegistry = Arc::default();
                let demux = Arc::clone(&streams);
                tokio::spawn(async move {
                    while let Ok(Some((id, data))) = read_frame(&mut read).await {
                        if data.is_empty() {
                            demux.lock().expect("mux registry").remove(&id);
                        } else {
                            let sender = demux.lock().expect("mux registry").get(&id).cloned();
                            if let Some(sender) = sender {
                                let _ = sender.send(data);
                            }
                        }
                    }
                });
                self.carriers_opened.fetch_add(1, Ordering::SeqCst);
                *slot = Some(MuxCarrier {
                    write: Arc::new(AsyncMutex::new(write)),
                    streams,
                });
            }
            let carrier = slot.as_ref().expect("carrier just ensured");
            Ok((Arc::clone(&carrier.write), Arc::clone(&carrier.streams)))
        }
    }

    impl OutboundConnector for MuxTestConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
            early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(async move {
                let (write, streams) = self.carrier().await.at(OutboundStage::HopConnect)?;
                let id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
                let (from_server_tx, mut from_server_rx) = mpsc::unbounded_channel();
                streams
                    .lock()
                    .expect("mux registry")
                    .insert(id, from_server_tx);
                if !early_data.is_empty() {
                    write_frame(&mut *write.lock().await, id, early_data)
                        .await
                        .at(OutboundStage::HopConnect)?;
                }

                let (local, remote) = tokio::io::duplex(64 * 1024);
                let (mut local_read, mut local_write) = tokio::io::split(local);
                // Uplink: relay bytes → data frames; relay EOF → close frame.
                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 8 * 1024];
                    loop {
                        match local_read.read(&mut buffer).await {
                            Ok(0) | Err(_) => {
                                let _ = write_frame(&mut *write.lock().await, id, &[]).await;
                                break;
                            }
                            Ok(read) => {
                                let framed =
                                    write_frame(&mut *write.lock().await, id, &buffer[..read])
                                        .await;
                                if framed.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                // Downlink: demuxed frames → relay; substream close → EOF.
                tokio::spawn(async move {
                    while let Some(data) = from_server_rx.recv().await {
                        if local_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    let _ = local_write.shutdown().await;
                });

                Ok(Box::new(remote) as BoxedOutboundStream)
            })
        }
    }

    #[tokio::test]
    async fn foreign_mux_protocol_relays_concurrent_sessions_over_one_pooled_carrier() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mux server");
        let server_addr = listener.local_addr().expect("mux server addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        spawn_mux_echo_server(listener, Arc::clone(&accepted));

        let connector = Arc::new(MuxTestConnector::new(server_addr));
        let runtime = runtime_with_connector(
            "mux-test",
            Arc::clone(&connector) as Arc<dyn OutboundConnector>,
        );

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind dispatcher listener");
        let proxy_addr = proxy.local_addr().expect("dispatcher addr");
        let accept_runtime = runtime.clone();
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = proxy.accept().await else {
                    break;
                };
                let runtime = accept_runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_connect_client(client, &runtime).await;
                });
            }
        });

        // TEST-NET target: reachable only through the connector, so a
        // dispatcher that tried to dial it itself would fail the test.
        let target: SocketAddr = "192.0.2.10:443".parse().expect("target");
        let first = tokio::spawn(run_socks5_client(
            proxy_addr,
            target,
            b"first-substream-payload",
        ));
        let second = tokio::spawn(run_socks5_client(
            proxy_addr,
            target,
            b"second-substream-payload",
        ));
        let first = timeout(Duration::from_secs(5), first)
            .await
            .expect("first session timeout")
            .expect("first session join")
            .expect("first session tunnels");
        let second = timeout(Duration::from_secs(5), second)
            .await
            .expect("second session timeout")
            .expect("second session join")
            .expect("second session tunnels");

        assert_eq!(first, b"first-substream-payload");
        assert_eq!(second, b"second-substream-payload");
        // Connection reuse stayed a connector detail: two concurrent
        // dispatcher sessions shared exactly one upstream connection.
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(connector.carriers_opened.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connector_receives_early_data_in_its_handshake_slot() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mux server");
        let server_addr = listener.local_addr().expect("mux server addr");
        spawn_mux_echo_server(listener, Arc::new(AtomicUsize::new(0)));
        let runtime = runtime_with_connector(
            "mux-test",
            Arc::new(MuxTestConnector::new(server_addr)) as Arc<dyn OutboundConnector>,
        );

        let target = ConnectTarget {
            host: "192.0.2.11".into(),
            port: 443,
        };
        let (mut stream, _binding) =
            open_outbound_connection(&runtime, &target, "mux-test", b"early-flight")
                .await
                .expect("dial with early data");

        // The dial delivered the sniffed prefix itself (here: folded into
        // the substream's first frame); the echo returns it without the
        // relay stage writing a byte.
        let mut received = vec![0_u8; b"early-flight".len()];
        timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .expect("early data echo timeout")
            .expect("early data echo read");
        assert_eq!(received, b"early-flight");
    }

    // ---- A foreign datagram protocol: XOR "cipher" over UDP to a fixed
    // relay server, decoding proven by an echo of the raw wire bytes.

    const XOR_MASK: u8 = 0x5a;

    fn xor(payload: &[u8]) -> Vec<u8> {
        payload.iter().map(|byte| byte ^ XOR_MASK).collect()
    }

    #[derive(Debug)]
    struct XorDatagramConnector {
        server: SocketAddr,
    }

    impl OutboundConnector for XorDatagramConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
            _early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(std::future::ready(Err(OutboundError::new(
                OutboundStage::Config,
                "gate connector only relays datagrams",
            ))))
        }

        fn connect_datagram<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
        ) -> OutboundFuture<'a, OutboundDatagramTransport> {
            Box::pin(async move {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .at(OutboundStage::Local)?;
                socket.connect(self.server).await.at(OutboundStage::Local)?;
                let socket = Arc::new(socket);
                Ok(OutboundDatagramTransport {
                    sender: Box::new(XorDatagramSender {
                        socket: Arc::clone(&socket),
                    }),
                    receiver: Box::new(XorDatagramReceiver {
                        socket,
                        remote: ConnectTarget {
                            host: self.server.ip().to_string(),
                            port: self.server.port(),
                        },
                        buffer: vec![0_u8; 2048],
                    }),
                })
            })
        }

        fn supports_udp(&self) -> bool {
            true
        }
    }

    struct XorDatagramSender {
        socket: Arc<UdpSocket>,
    }

    impl OutboundDatagramSender for XorDatagramSender {
        fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
            crate::outbound::DatagramSendCancellation::AtomicDatagram
        }

        fn send<'a>(
            &'a self,
            _target: &'a ConnectTarget,
            payload: &'a [u8],
        ) -> DatagramFuture<'a, ()> {
            Box::pin(async move {
                self.socket
                    .send(&xor(payload))
                    .await
                    .map(|_| ())
                    .map_err(DatagramError::NativeSocket)
            })
        }
    }

    struct XorDatagramReceiver {
        socket: Arc<UdpSocket>,
        /// The connected server: this mock dials one endpoint, so every reply
        /// originates there (the connected-socket analog of a real protocol
        /// decoding the reply's source address).
        remote: ConnectTarget,
        buffer: Vec<u8>,
    }

    impl OutboundDatagramReceiver for XorDatagramReceiver {
        fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
            Box::pin(async move {
                match self.socket.recv(&mut self.buffer).await {
                    Ok(read) => Ok(Some((self.remote.clone(), xor(&self.buffer[..read])))),
                    Err(error) => Err(DatagramError::NativeSocket(error)),
                }
            })
        }
    }

    #[tokio::test]
    async fn foreign_datagram_protocol_relays_through_unmodified_udp_dispatcher() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp echo server");
        let server_addr = server.local_addr().expect("udp echo addr");
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            loop {
                let Ok((read, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                // Echo the wire bytes untouched: only the connector's codec
                // can make the roundtrip an identity.
                if server.send_to(&buffer[..read], peer).await.is_err() {
                    break;
                }
            }
        });

        let runtime = runtime_with_connector(
            "xor-udp",
            Arc::new(XorDatagramConnector {
                server: server_addr,
            }) as Arc<dyn OutboundConnector>,
        );

        let source: SocketAddr = "127.0.0.1:53535".parse().expect("source");
        for payload in [
            b"first-foreign-datagram".as_slice(),
            b"second-foreign-datagram".as_slice(),
        ] {
            let flow_id = "foreign-datagram-flow";
            let outcome = send_udp_flow_datagram(
                &runtime,
                UdpDatagram {
                    flow_id: Some(flow_id.into()),
                    pump_queue: None,
                    inbound: "tun",
                    user: None,
                    source,
                    target: ConnectTarget {
                        host: "192.0.2.12".into(),
                        port: 4433,
                    },
                    payload: payload.to_vec(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
            .expect("foreign datagram sends");
            assert!(outcome.enqueued);
            let response = drain_pending_udp_flow_responses(&runtime, 16, Duration::from_secs(5))
                .await
                .into_iter()
                .find(|response| response.flow_id == flow_id)
                .expect("foreign datagram response");
            assert_eq!(response.payload, payload);
            assert!(outcome.enqueued);
            assert_eq!(
                runtime
                    .udp_sessions()
                    .session_for_flow(&flow_id)
                    .unwrap()
                    .outbound,
                "xor-udp"
            );
        }
        // The session actor cached one transport across datagrams: the
        // decision-5 socket-reuse discipline holds for a protocol the UDP
        // dispatcher cannot name.
        assert_eq!(runtime.udp_sessions().session_socket_count(), 1);
    }

    /// The packet pump writes and reads SOCKS addresses without going
    /// through text, with [`ConnectTarget::socks_address`]'s encoding.
    #[test]
    fn pump_addresses_are_socks_addresses() {
        for (to, target) in [
            (
                "192.0.2.9:53",
                ConnectTarget {
                    host: "192.0.2.9".into(),
                    port: 53,
                },
            ),
            (
                "[2001:db8::7]:443",
                ConnectTarget {
                    host: "2001:db8::7".into(),
                    port: 443,
                },
            ),
        ] {
            let remote: SocketAddr = to.parse().unwrap();
            let mut encoded = Vec::new();
            PumpTo::Addr(remote)
                .push_socks_address(&mut encoded)
                .unwrap();
            assert_eq!(encoded, target.socks_address().unwrap());
            encoded.extend_from_slice(b"payload");
            assert_eq!(
                PumpFrom::from_socks_address(&encoded),
                Some((PumpFrom::Addr(remote), encoded.len() - 7))
            );
            assert_eq!(
                PumpFrom::from_socks_address(&encoded[..encoded.len() - 9]),
                None
            );
        }
        let mut named = Vec::new();
        PumpTo::Name("example.com:443".into())
            .push_socks_address(&mut named)
            .unwrap();
        assert_eq!(
            PumpFrom::from_socks_address(&named),
            Some((
                PumpFrom::Name(ConnectTarget {
                    host: "example.com".into(),
                    port: 443
                }),
                named.len()
            ))
        );
        assert_eq!(PumpFrom::from_socks_address(&[0x05, 0, 0]), None);
    }
}
