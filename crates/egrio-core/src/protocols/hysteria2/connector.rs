use crate::outbound::options::{option_bool, option_string};
use crate::outbound::{DatagramError, DatagramFuture};
use crate::tls::{unsupported_trust_options, TlsClientOptions};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, IdleTimeout, Runtime, TokioRuntime,
    VarInt,
};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use super::codec::{
    get_varint, put_varint, random_padding, random_padding_string, send_udp_message,
    Hysteria2UdpDefragger, Hysteria2UdpMessage, AUTH_OK_STATUS, HYSTERIA2_QUEUED_DATAGRAMS,
    HYSTERIA2_TCP_REQUEST_FRAME_TYPE, MAX_DATAGRAM_FRAME_SIZE, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH, TCP_PADDING_MAX, TCP_PADDING_MIN,
};
use super::congestion::{RateControlFactory, SendRate};
use super::hop_socket::{remote_address, HopSocket};
use super::pacer::PacedSocket;
use super::paths;
use super::socket::client_socket;
use super::turns::{SendTurns, TurnSend};
use crate::egress::dial::{race_connections, AttemptError, AttemptFailure, RaceFailure};
use crate::egress::pending::Pending;
use crate::egress::{EgressBinding, EgressRuntime, NetworkChange};
use crate::outbound::{
    write_early_data, BoxedOutboundStream, Dialer, Hop, OutboundConnector,
    OutboundDatagramReceiver, OutboundDatagramSender, OutboundDatagramTransport, OutboundError,
    OutboundFuture, OutboundResultExt, OutboundStage, PumpDatagrams, PumpFrom, PumpTo,
};
use crate::target::{parse_connect_authority, ConnectTarget};

/// Datagrams one UDP session's reader may have waiting. Each entry is one
/// QUIC datagram, so the count bounds the bytes too (a fragment is at most a
/// packet's worth, and defragmenting happens past this channel, one message
/// at a time). It matches the Core's own per-association mailbox, which sits
/// right behind it: a deeper queue here only moves the drop further from the
/// source, and the session's consumer is a task woken per datagram. At 1024 a
/// thousand sessions against a client that stopped reading came to over a
/// gigabyte of datagrams nobody would take.
const HYSTERIA2_UDP_SESSION_CHANNEL: usize = 64;
/// Whole-dial budget (DNS + QUIC handshake + HTTP/3 auth) shared by every
/// resolved address. Without it a black-holed server parks every new
/// connection on this hop behind the connect mutex until QUIC's 30 s idle
/// timeout fires; this fails fast at the same scale as the egress TCP dial
/// budget.
const HYSTERIA2_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Transport flow-control windows. quinn's 1.25 MB default per-stream window
/// caps one proxied TCP connection (one QUIC stream) near 100 Mbps at 100 ms
/// RTT; these mirror hysteria's upstream defaults (8 MB stream / 20 MB
/// connection).
const HYSTERIA2_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const HYSTERIA2_CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const HYSTERIA2_SEND_WINDOW: u64 = 16 * 1024 * 1024;
const AUTH_PADDING_MIN: usize = 256;
const AUTH_PADDING_MAX: usize = 2048;
/// QUIC handshakes a carrier dial starts at once to one address, each from a
/// socket of its own. A network that spreads flows over paths by their ports
/// gives each socket its own path, and the carrier keeps the first to finish
/// its handshake, so a slow path no longer holds every stream for the
/// carrier's life.
const PATH_CANDIDATES: usize = 3;
/// Fresh sockets a carrier's path check probes (see [`paths`]).
const PATH_PROBES: usize = 3;
/// How long a path check waits for its probes' answers.
const PROBE_WAIT: Duration = Duration::from_secs(1);
/// How much shorter a probed path's round trip must be, besides under two
/// thirds of the carrier's, for the carrier to move to it.
const PATH_GAIN: Duration = Duration::from_millis(25);
/// When a carrier's path is first checked, once its round-trip estimate has
/// samples, and how often after.
const PATH_CHECK_AFTER_DIAL: Duration = Duration::from_secs(5);
const PATH_CHECK_EVERY: Duration = Duration::from_secs(300);

/// Hysteria2 proxy hop: QUIC/H3 authentication plus one bidirectional QUIC
/// stream per proxied TCP connection.
pub(crate) struct Hysteria2Connector {
    config: Hysteria2Config,
    quic_config: OnceLock<Result<ClientConfig, String>>,
    client: Arc<StdMutex<Option<(u64, Arc<Hysteria2Client>)>>>,
    /// Every carrier dialed, with its policy. A network change moves the live
    /// ones, cached or not, for the streams that ride them.
    carriers: StdMutex<Vec<(u64, Weak<Hysteria2Client>)>>,
    connect_lock: Mutex<()>,
}

impl Hysteria2Connector {
    pub(crate) fn new(host: String, port: u16, options: &JsonValue) -> Self {
        Self {
            config: Hysteria2Config::from_options(host, port, options),
            quic_config: OnceLock::new(),
            client: Arc::new(StdMutex::new(None)),
            carriers: StdMutex::new(Vec::new()),
            connect_lock: Mutex::new(()),
        }
    }

    /// The fixed send rate the carrier connection agreed at authentication,
    /// 0 when it kept congestion control.
    #[cfg(all(test, feature = "server"))]
    pub(super) async fn agreed_send_rate(&self, egress: &EgressRuntime) -> u64 {
        let client = self.client(egress).await.expect("carrier connects");
        client
            .connection
            .congestion_state()
            .into_any()
            .downcast::<super::congestion::RateControl>()
            .expect("Hysteria2 connections use the rate controller")
            .fixed_rate()
    }

    async fn client(&self, egress: &EgressRuntime) -> Result<Arc<Hysteria2Client>, OutboundError> {
        let retired = || OutboundError::new(OutboundStage::Local, "egress policy retired");
        let cancel = egress.policy_cancel();
        if cancel.is_cancelled() {
            return Err(retired());
        }
        let _connect = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(retired()),
            guard = self.connect_lock.lock() => guard,
        };
        // A carrier from before the host slept is not reused: the server has
        // likely dropped it, and its idle timeout would only notice after as
        // long again in waking time. Nor is one parked without an uplink.
        if let Some((_, client)) = self
            .client
            .lock()
            .expect("Hysteria2 client cache")
            .as_ref()
            .filter(|(policy, client)| {
                *policy == egress.policy_id()
                    && client.is_open()
                    && !client.parked.load(Ordering::Relaxed)
                    && !crate::suspension::slept_since(client.awake)
            })
        {
            egress.record_binding(client.binding().carried());
            return Ok(client.clone());
        }
        let deadline = tokio::time::Instant::now() + HYSTERIA2_CONNECT_TIMEOUT;
        let connected = Arc::new(tokio::select! { biased;
            _ = cancel.cancelled() => return Err(retired()),
            connected = Hysteria2Client::connect(&self.config, &self.quic_config, egress, deadline) => connected?,
        });
        *self.client.lock().expect("Hysteria2 client cache") =
            Some((egress.policy_id(), connected.clone()));
        let mut carriers = self.carriers.lock().expect("Hysteria2 carriers");
        carriers.retain(|(_, carrier)| carrier.strong_count() > 0);
        carriers.push((egress.policy_id(), Arc::downgrade(&connected)));
        drop(carriers);
        let cache = Arc::downgrade(&self.client);
        let weak = Arc::downgrade(&connected);
        let connection = connected.connection.clone();
        let endpoint = connected.endpoint.clone();
        let h3_abort = connected.h3_driver.abort_handle();
        let policy_id = egress.policy_id();
        let cleanup = async move {
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = connection.closed() => {} }
            if let Some(cache) = cache.upgrade() {
                let mut cache = cache.lock().expect("Hysteria2 client cache");
                if cache.as_ref().is_some_and(|(id, entry)| {
                    *id == policy_id && Weak::ptr_eq(&Arc::downgrade(entry), &weak)
                }) {
                    cache.take();
                }
            }
            connection.close(0x100_u32.into(), b"egress policy retired");
            h3_abort.abort();
            endpoint.close(0x100_u32.into(), b"egress policy retired");
            endpoint.wait_idle().await;
        };
        if let Err(error) = egress.spawn_policy_task(cleanup) {
            self.client.lock().expect("Hysteria2 client cache").take();
            connected
                .connection
                .close(0x100_u32.into(), b"egress policy retired");
            connected.h3_driver.abort();
            return Err(OutboundError::new(OutboundStage::Local, error));
        }
        // A keeper that cannot start leaves the carrier on the path it drew;
        // a chained carrier's path is its hop's.
        if !connected.chained {
            let _ = egress.spawn_policy_task(keep_path(Arc::downgrade(&connected), egress.clone()));
        }
        egress.record_binding(connected.binding().carried());
        Ok(connected)
    }
}

impl fmt::Debug for Hysteria2Connector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2Connector")
            .field("server_addr", &self.config.server_addr())
            .field("server_name", &self.config.server_name())
            .field("insecure", &self.config.insecure)
            .finish_non_exhaustive()
    }
}

impl OutboundConnector for Hysteria2Connector {
    fn carrier_runtime(&self) -> Option<tokio::runtime::Id> {
        self.client
            .lock()
            .expect("Hysteria2 client cache")
            .as_ref()
            .filter(|(_, client)| client.is_open())
            .map(|(_, client)| client.runtime)
    }

    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let client = self.client(egress).await?;
            let mut stream = client.tcp_connect(&target.authority()).await?;
            // Without fast-open the server already confirmed the target.
            let stage = if client.fast_open {
                OutboundStage::HopConnect
            } else {
                OutboundStage::Target
            };
            write_early_data(&mut stream, early_data).await.at(stage)?;
            Ok(Box::new(stream) as BoxedOutboundStream)
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async move {
            let client = self.client(egress).await?;
            let session = client.udp_session().at(OutboundStage::HopProtocol)?;
            let io = Arc::new(Hysteria2UdpSessionIo {
                connection: client.connection.clone(),
                session_id: session.id,
                next_packet_id: AtomicU16::new(0),
                receive: StdMutex::new(Hysteria2UdpReceive {
                    receiver: session.receiver,
                    defragger: Hysteria2UdpDefragger::default(),
                    stashed: None,
                }),
                pump: OnceLock::new(),
                manager: Arc::downgrade(
                    client
                        .udp_manager
                        .as_ref()
                        .expect("UDP session only exists when manager exists"),
                ),
                _client: client,
            });
            Ok(OutboundDatagramTransport {
                sender: Box::new(Hysteria2DatagramSender(Arc::clone(&io))),
                receiver: Box::new(Hysteria2DatagramReceiver(io)),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    /// The carriers follow the network (QUIC connection migration, RFC 9000
    /// §9): one whose socket the change stranded, or that is bound off the
    /// uplink new dials take now, moves to a new socket on that uplink, and
    /// the streams and UDP sessions on it carry on. A stranded carrier with
    /// no uplink to move to is parked, out of new dials, until a later change
    /// brings one or its idle timeout closes it. A chained carrier has no
    /// socket of this host to move; its hop follows the network itself.
    fn network_changed(&self, change: &NetworkChange, egress: &EgressRuntime) {
        let carriers: Vec<_> = {
            let mut carriers = self.carriers.lock().expect("Hysteria2 carriers");
            carriers.retain(|(_, carrier)| carrier.strong_count() > 0);
            carriers
                .iter()
                .filter(|(policy, _)| *policy == egress.policy_id())
                .filter_map(|(_, carrier)| carrier.upgrade())
                .filter(|carrier| !carrier.chained)
                .collect()
        };
        for carrier in carriers {
            let binding = carrier.binding();
            let stranded = carrier.parked.load(Ordering::Relaxed) || change.strands(&binding);
            if carrier.is_open() && (stranded || change.moves(&binding)) {
                let policy = egress.clone();
                // A retired policy closes its carriers itself.
                let _ = egress.spawn_policy_task(async move {
                    carrier.move_to_uplink(&policy, stranded).await;
                });
            }
        }
    }
}

/// Options this connector does not implement and must not drop silently.
fn unsupported_features(options: &JsonValue) -> Vec<&'static str> {
    let mut features = Vec::new();
    if option_string(options, &["obfs"])
        .is_some_and(|obfs| !matches!(obfs.to_ascii_lowercase().as_str(), "none" | ""))
    {
        features.push("obfs");
    }
    if option_string(options, &["obfs-password", "obfs_password"]).is_some() {
        features.push("obfs-password");
    }
    features.extend(unsupported_trust_options(options));
    features
}

fn unsupported_features_error(features: &[&str]) -> String {
    format!(
        "hysteria2 options are not supported yet: {}",
        features.join(", ")
    )
}

/// Why a node with these options cannot connect, if it cannot.
pub(crate) fn unsupported_option(options: &JsonValue) -> Option<String> {
    let features = unsupported_features(options);
    (!features.is_empty()).then(|| unsupported_features_error(&features))
}

#[derive(Debug, Clone)]
struct Hysteria2Config {
    host: String,
    port: u16,
    auth: String,
    sni: Option<String>,
    insecure: bool,
    alpn: Vec<Vec<u8>>,
    fast_open: bool,
    /// Client download bandwidth in bytes/second, sent as `Hysteria-CC-RX` so
    /// the server can send at this rate. 0 means "unknown" — the server keeps
    /// congestion control (protocol default).
    recv_bps: u64,
    /// Client upload bandwidth in bytes/second. Bounded by the server's
    /// receive rate, it becomes the connection's fixed send rate after
    /// authentication; 0 keeps congestion control.
    send_bps: u64,
    unsupported_features: Vec<&'static str>,
    /// QUIC handshakes a carrier dial starts at once to an address:
    /// [`PATH_CANDIDATES`]; tests that count sockets start one.
    paths: usize,
    /// How the carrier reaches the server: from this host, or over the
    /// datagrams of the hop the node's `dialer-proxy` names.
    dialer: Dialer,
}

impl Hysteria2Config {
    fn from_options(host: String, port: u16, options: &JsonValue) -> Self {
        let auth = option_string(options, &["password", "auth", "auth-str"]).unwrap_or_default();
        let TlsClientOptions {
            server_name: sni,
            insecure,
            mut alpn,
        } = TlsClientOptions::from_node(options);
        if alpn.is_empty() {
            alpn.push(b"h3".to_vec());
        }
        let fast_open = option_bool(options, &["fast-open", "fast_open"]).unwrap_or(true);
        let recv_bps = option_bandwidth_bps(options, "down");
        let send_bps = option_bandwidth_bps(options, "up");
        let unsupported_features = unsupported_features(options);
        Self {
            host,
            port,
            auth,
            sni,
            insecure,
            alpn,
            fast_open,
            recv_bps,
            send_bps,
            unsupported_features,
            paths: PATH_CANDIDATES,
            dialer: Dialer::from_options(options),
        }
    }

    fn server_addr(&self) -> String {
        crate::target::authority(&self.host, self.port)
    }

    fn server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }
}

struct Hysteria2Client {
    connection: quinn::Connection,
    endpoint: Endpoint,
    /// Where the carrier's socket leaves the host; a move replaces it.
    binding: StdMutex<EgressBinding>,
    /// The agreed send rate, which the pacer of every socket the carrier
    /// moves to reads as well.
    send_rate: Arc<SendRate>,
    /// Stranded, with no uplink to move to.
    parked: AtomicBool,
    /// The server has answered a path probe, so a move probes for its path.
    negotiates: AtomicBool,
    /// One move at a time.
    moving: Mutex<()>,
    /// The suspension mark when the carrier connected.
    awake: i64,
    fast_open: bool,
    udp_manager: Option<Arc<Hysteria2UdpSessionManager>>,
    /// The proxied-TCP streams' turns at the connection's send space.
    turns: Arc<SendTurns>,
    /// Drives the HTTP/3 connection for the tunnel's lifetime and holds the
    /// control/QPACK streams open. Aborted on drop; see
    /// [`authenticate_hysteria2_connection`] for why it must outlive auth.
    h3_driver: JoinHandle<()>,
    /// The runtime the endpoint and connection drivers run on: the one that
    /// dialed the carrier.
    runtime: tokio::runtime::Id,
    /// Over a hop's datagrams, which the carrier keeps until it closes: no
    /// socket of this host to move or to probe paths with.
    chained: bool,
}

impl Hysteria2Client {
    /// Connects to the first of the server's resolved addresses that
    /// completes the QUIC handshake and HTTP/3 authentication by `deadline`,
    /// or, for a chained node, through its hop.
    async fn connect(
        config: &Hysteria2Config,
        quic_config: &OnceLock<Result<ClientConfig, String>>,
        egress: &EgressRuntime,
        deadline: tokio::time::Instant,
    ) -> Result<Self, OutboundError> {
        if config.auth.is_empty() {
            return Err(OutboundError::new(
                OutboundStage::Config,
                "hysteria2 password/auth is required",
            ));
        }
        if !config.unsupported_features.is_empty() {
            return Err(OutboundError::new(
                OutboundStage::Config,
                unsupported_features_error(&config.unsupported_features),
            ));
        }

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let server = ConnectTarget {
            host: config.host.clone(),
            port: config.port,
        };
        let recording = egress.with_binding_recorder();
        if let Some(hop) = config.dialer.hop(&recording, &server)? {
            let chained = Self::connect_via(config, quic_config, egress, &recording, hop, server);
            return tokio::time::timeout_at(deadline, chained)
                .await
                .unwrap_or_else(|_| {
                    Err(OutboundError::new(
                        OutboundStage::HopConnect,
                        "Hysteria2 dial through the dialer-proxy timed out",
                    ))
                });
        }
        let candidates = egress
            .resolve_candidates(
                &config.host,
                config.port,
                crate::dns::service::QueryPurpose::ProxyEndpoint,
            )
            .at(OutboundStage::Local)?;
        Self::connect_candidates(config, quic_config, egress, candidates, deadline).await
    }

    /// Races the candidates with the egress TCP dial's pacing: a staggered
    /// attempt per address, families alternating, all sharing `deadline`. A
    /// bound UDP socket proves nothing about the server, so an attempt counts
    /// only once the server authenticated it; the losers are dropped, which
    /// closes their endpoints.
    async fn connect_candidates(
        config: &Hysteria2Config,
        quic_config: &OnceLock<Result<ClientConfig, String>>,
        egress: &EgressRuntime,
        candidates: Pending<'_, Result<Vec<SocketAddr>, String>>,
        deadline: tokio::time::Instant,
    ) -> Result<Self, OutboundError> {
        race_connections(candidates, deadline, |server_addr| async move {
            Self::connect_addr(config, quic_config, egress, server_addr)
                .await
                .map_err(CarrierAttempt)
        })
        .await
        .map(|(_, client)| client)
        .map_err(|failure| carrier_failure(config, failure))
    }

    async fn connect_addr(
        config: &Hysteria2Config,
        quic_config: &OnceLock<Result<ClientConfig, String>>,
        egress: &EgressRuntime,
        server_addr: SocketAddr,
    ) -> Result<Self, OutboundError> {
        egress
            .check_udp_remote(server_addr)
            .map_err(OutboundError::hop_dial)?;
        let handshaken =
            handshake_on_fastest_path(config, quic_config, egress, server_addr).await?;
        Self::authenticated(config, egress, handshaken, false).await
    }

    /// Connects through `hop`, the outbound the node's dialer-proxy resolved
    /// to: one QUIC handshake over the hop's datagrams to the server, whose
    /// name only the hop resolves. `recording` records where the hop's own
    /// socket leaves this host.
    async fn connect_via(
        config: &Hysteria2Config,
        quic_config: &OnceLock<Result<ClientConfig, String>>,
        egress: &EgressRuntime,
        recording: &EgressRuntime,
        hop: Hop,
        server: ConnectTarget,
    ) -> Result<Self, OutboundError> {
        let datagrams = hop.datagrams(&server).await?;
        let remote = remote_address(&server);
        let send_rate = Arc::new(SendRate::default());
        let socket = Arc::new(PacedSocket::new(
            Arc::new(HopSocket::new(datagrams, server, remote)),
            Arc::clone(&send_rate),
        ));
        let endpoint = quic_endpoint(socket)?;
        let connecting = begin_quic_dial(config, quic_config, &endpoint, remote, &send_rate)?;
        let handshaken = Handshaken {
            connection: finish_quic_dial(connecting).await?,
            endpoint,
            binding: recording.recorded_binding(),
            send_rate,
        };
        Self::authenticated(config, egress, handshaken, true).await
    }

    /// The carrier once the server authenticated its QUIC connection.
    async fn authenticated(
        config: &Hysteria2Config,
        egress: &EgressRuntime,
        handshaken: Handshaken,
        chained: bool,
    ) -> Result<Self, OutboundError> {
        let Handshaken {
            connection,
            endpoint,
            binding,
            send_rate,
        } = handshaken;
        let (auth, h3_driver) =
            authenticate_hysteria2_connection(&connection, config, egress).await?;
        send_rate.set(auth.server_rx.send_rate(config.send_bps));
        let udp_manager = auth
            .udp_enabled
            .then(|| Hysteria2UdpSessionManager::new(connection.clone(), egress))
            .transpose()
            .at(OutboundStage::Local)?;

        Ok(Self {
            connection,
            endpoint,
            binding: StdMutex::new(binding),
            send_rate,
            parked: AtomicBool::new(false),
            negotiates: AtomicBool::new(false),
            moving: Mutex::new(()),
            awake: crate::suspension::mark(),
            fast_open: config.fast_open,
            udp_manager,
            turns: Arc::default(),
            h3_driver,
            runtime: tokio::runtime::Handle::current().id(),
            chained,
        })
    }

    fn is_open(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    fn binding(&self) -> EgressBinding {
        *self.binding.lock().expect("Hysteria2 carrier binding")
    }

    /// Moves the connection to a new socket on the current uplink: of
    /// [`PATH_PROBES`] fresh ones, the first whose probe the server answers
    /// if it has answered probes before, else any. quinn keeps reading the
    /// old socket until the server answers on the new one, and the server
    /// takes the new address as the client's once it has validated the path.
    /// A stranded carrier that cannot move is parked.
    async fn move_to_uplink(&self, egress: &EgressRuntime, stranded: bool) {
        let _moving = self.moving.lock().await;
        let probing = self.negotiates.load(Ordering::Relaxed);
        let mut sockets = self
            .fresh_sockets(egress, if probing { PATH_PROBES } else { 1 })
            .await;
        let chosen = if probing {
            self.fastest(&sockets).await.map_or(0, |(index, _)| index)
        } else {
            0
        };
        let moved = chosen < sockets.len() && {
            let (socket, binding) = sockets.swap_remove(chosen);
            self.rebind(socket, binding)
        };
        if moved {
            self.parked.store(false, Ordering::Relaxed);
        } else if stranded {
            self.parked.store(true, Ordering::Relaxed);
        }
    }

    /// Moves the carrier to a faster path if probing [`PATH_PROBES`] fresh
    /// sockets finds one: its round trip under two thirds of the carrier's
    /// and at least [`PATH_GAIN`] shorter. Whether it moved.
    async fn check_path(&self, egress: &EgressRuntime) -> bool {
        let _moving = self.moving.lock().await;
        let mut sockets = self.fresh_sockets(egress, PATH_PROBES).await;
        let Some((index, rtt)) = self.fastest(&sockets).await else {
            return false;
        };
        let current = self.connection.rtt();
        if rtt.mul_f64(1.5) >= current || current.saturating_sub(rtt) < PATH_GAIN {
            return false;
        }
        let (socket, binding) = sockets.swap_remove(index);
        self.rebind(socket, binding)
    }

    /// Up to `count` sockets for the carrier on the current uplink.
    async fn fresh_sockets(
        &self,
        egress: &EgressRuntime,
        count: usize,
    ) -> Vec<(tokio::net::UdpSocket, EgressBinding)> {
        let server = self.connection.remote_address();
        let mut sockets = Vec::new();
        for _ in 0..count {
            if let Ok(bound) = bind_carrier_socket(egress, server).await {
                sockets.push(bound);
            }
        }
        sockets
    }

    /// The first of `sockets` whose path probe the server answers within
    /// [`PROBE_WAIT`], with its round trip (see [`paths`]).
    async fn fastest(
        &self,
        sockets: &[(tokio::net::UdpSocket, EgressBinding)],
    ) -> Option<(usize, Duration)> {
        let probed: Vec<_> = sockets.iter().map(|(socket, _)| socket).collect();
        let fastest = paths::fastest(&probed, self.connection.remote_address(), PROBE_WAIT).await;
        if fastest.is_some() {
            self.negotiates.store(true, Ordering::Relaxed);
        }
        fastest
    }

    /// Moves the connection onto `socket`; whether it moved.
    fn rebind(&self, socket: tokio::net::UdpSocket, binding: EgressBinding) -> bool {
        let server = self.connection.remote_address();
        let Ok(socket) = quinn_socket(socket, server, &self.send_rate) else {
            return false;
        };
        let binding = binding.at(socket.local_addr());
        if self.endpoint.rebind_abstract(socket).is_err() {
            return false;
        }
        *self.binding.lock().expect("Hysteria2 carrier binding") = binding;
        true
    }

    async fn tcp_connect(
        self: &Arc<Self>,
        address: &str,
    ) -> Result<Hysteria2TcpStream, OutboundError> {
        let carrier = |what: &str, error: &dyn fmt::Display| {
            OutboundError::new(
                OutboundStage::HopConnect,
                format!("failed to {what} Hysteria2 TCP stream: {error}"),
            )
        };
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| carrier("open", &error))?;
        let mut send = self.turns.stream(send);
        send.write_all(&encode_tcp_request(address))
            .await
            .map_err(|error| carrier("send the request on a", &error))?;
        send.flush()
            .await
            .map_err(|error| carrier("flush the request on a", &error))?;
        let mut stream = Hysteria2TcpStream::new(send, recv, Arc::clone(self));
        if !self.fast_open {
            stream.establish().await.map_err(|error| {
                // `poll_establish` marks the server's verdict on the target
                // as refused and a response it cannot parse as invalid data.
                let stage = match error.kind() {
                    io::ErrorKind::ConnectionRefused => OutboundStage::Target,
                    io::ErrorKind::InvalidData => OutboundStage::HopProtocol,
                    _ => OutboundStage::HopConnect,
                };
                OutboundError::new(stage, error.to_string())
            })?;
        }
        Ok(stream)
    }

    fn udp_session(&self) -> Result<Hysteria2UdpSession, String> {
        self.udp_manager
            .as_ref()
            .map(Hysteria2UdpSessionManager::new_session)
            .ok_or_else(|| "Hysteria2 server did not enable UDP relay".into())
    }
}

impl Drop for Hysteria2Client {
    fn drop(&mut self) {
        // Close the QUIC connection first so the driver task's `poll_close`
        // resolves and quinn suppresses the control/QPACK stream FINs, then
        // abort in case it is parked elsewhere.
        self.connection.close(0x100_u32.into(), b"");
        self.h3_driver.abort();
    }
}

/// One Hysteria2 UDP session: what the session actor's halves and the packet
/// pump share. Messages to the session arrive on `receive`, demultiplexed
/// from the connection's datagrams by the session manager.
struct Hysteria2UdpSessionIo {
    connection: quinn::Connection,
    session_id: u32,
    /// Monotonic per-session packet id. Fragments of one datagram share it so
    /// the peer's defragger groups them; a wrapping counter (never a random
    /// draw) keeps consecutive datagrams from colliding on the same id.
    next_packet_id: AtomicU16,
    receive: StdMutex<Hysteria2UdpReceive>,
    /// Set once the packet pump reads the session (see
    /// [`PumpDatagrams::hand_reads_to`]).
    pump: OnceLock<std::task::Waker>,
    manager: Weak<Hysteria2UdpSessionManager>,
    /// Keeps the QUIC connection the session rides alive while it is in use.
    _client: Arc<Hysteria2Client>,
}

struct Hysteria2UdpReceive {
    receiver: mpsc::Receiver<Hysteria2UdpMessage>,
    defragger: Hysteria2UdpDefragger,
    /// A message taken while registering the pump's wakeup, read next.
    stashed: Option<Hysteria2UdpMessage>,
}

impl Hysteria2UdpSessionIo {
    /// The target address rides every message (Hysteria2 UDP carries it in
    /// the datagram header), so one session relays to every remote the client
    /// addresses (EIM). All fragment enqueues are synchronous.
    fn send(&self, target: &str, payload: &[u8]) -> Result<(), String> {
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        send_udp_message(
            &self.connection,
            self.session_id,
            packet_id,
            target,
            payload,
        )
    }
}

impl Drop for Hysteria2UdpSessionIo {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.remove(self.session_id);
        }
    }
}

impl PumpDatagrams for Hysteria2UdpSessionIo {
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> io::Result<()> {
        match to {
            PumpTo::Addr(remote) => {
                // A socket address prints in at most 58 bytes
                // ("[v6%scope]:port"): written on the stack, the send
                // allocates only the buffer quinn takes.
                let mut text = [0_u8; 64];
                let mut cursor = io::Cursor::new(&mut text[..]);
                write!(cursor, "{remote}")?;
                let length = cursor.position() as usize;
                let target = std::str::from_utf8(&text[..length]).map_err(io::Error::other)?;
                self.send(target, payload)
            }
            PumpTo::Name(authority) => self.send(authority, payload),
        }
        .map_err(io::Error::other)
    }

    fn hand_reads_to(&self, waker: std::task::Waker) {
        if self.pump.set(waker.clone()).is_ok() {
            // Whatever already waits is read on the first wakeup.
            waker.wake();
        }
    }

    fn try_recv(&self, buffer: &mut [u8]) -> io::Result<(usize, PumpFrom, usize)> {
        let mut receive = self.receive.lock().expect("Hysteria2 UDP session receive");
        loop {
            let message = match receive.stashed.take() {
                Some(message) => message,
                None => match receive.receiver.try_recv() {
                    Ok(message) => message,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err(io::ErrorKind::ConnectionAborted.into())
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        let Some(waker) = self.pump.get() else {
                            return Err(io::ErrorKind::WouldBlock.into());
                        };
                        match receive.receiver.poll_recv(&mut Context::from_waker(waker)) {
                            Poll::Ready(Some(message)) => message,
                            Poll::Ready(None) => {
                                return Err(io::ErrorKind::ConnectionAborted.into())
                            }
                            Poll::Pending => return Err(io::ErrorKind::WouldBlock.into()),
                        }
                    }
                },
            };
            let Some(message) = receive.defragger.feed(message) else {
                continue;
            };
            // The message's own address is the reply origin (EIF); one that
            // names nothing is skipped.
            let Some(from) = pump_from(&message.addr) else {
                continue;
            };
            let length = message.data.len().min(buffer.len());
            buffer[..length].copy_from_slice(&message.data[..length]);
            return Ok((length, from, length));
        }
    }
}

/// Who a reply message names as its sender: an address, or the host name a
/// server answers a datagram sent to a name with.
fn pump_from(addr: &str) -> Option<PumpFrom> {
    match addr.parse::<SocketAddr>() {
        Ok(remote) => Some(PumpFrom::Addr(remote)),
        Err(_) => parse_connect_authority(addr).ok().map(PumpFrom::Name),
    }
}

struct Hysteria2DatagramSender(Arc<Hysteria2UdpSessionIo>);

impl OutboundDatagramSender for Hysteria2DatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        // All fragment enqueues are synchronous within one poll; this send
        // has no await at which a partially submitted batch can be cancelled.
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            self.0.send(&target.authority(), payload).map_err(|error| {
                DatagramError::Protocol(format!("failed to send Hysteria2 UDP datagram: {error}"))
            })
        })
    }
}

struct Hysteria2DatagramReceiver(Arc<Hysteria2UdpSessionIo>);

impl OutboundDatagramReceiver for Hysteria2DatagramReceiver {
    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        Some(Arc::clone(&self.0) as Arc<dyn PumpDatagrams>)
    }

    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            loop {
                let message = std::future::poll_fn(|cx| {
                    let mut receive = self
                        .0
                        .receive
                        .lock()
                        .expect("Hysteria2 UDP session receive");
                    if let Some(message) = receive.stashed.take() {
                        return Poll::Ready(Some(message));
                    }
                    receive.receiver.poll_recv(cx)
                })
                .await;
                let Some(message) = message else {
                    return Ok(None);
                };
                let full_message = self
                    .0
                    .receive
                    .lock()
                    .expect("Hysteria2 UDP session receive")
                    .defragger
                    .feed(message);
                if let Some(full_message) = full_message {
                    // The message's own address is the reply origin (EIF), the
                    // framing source for the client. A malformed address skips
                    // the datagram rather than tearing down the session.
                    let Ok(remote) = parse_connect_authority(&full_message.addr) else {
                        continue;
                    };
                    return Ok(Some((remote, full_message.data)));
                }
            }
        })
    }
}

struct Hysteria2UdpSession {
    id: u32,
    receiver: mpsc::Receiver<Hysteria2UdpMessage>,
}

struct Hysteria2UdpSessionManager {
    sessions: StdMutex<HashMap<u32, mpsc::Sender<Hysteria2UdpMessage>>>,
    next_id: AtomicU32,
}

impl Hysteria2UdpSessionManager {
    fn new(connection: quinn::Connection, egress: &EgressRuntime) -> Result<Arc<Self>, String> {
        let manager = Arc::new(Self {
            sessions: StdMutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        });
        let weak = Arc::downgrade(&manager);
        let cancel = egress.policy_cancel();
        egress.spawn_policy_task(async move {
            tokio::select! { biased;
                _ = cancel.cancelled() => {},
                _ = receive_hysteria2_udp_messages(connection, weak) => {},
            }
        })?;
        Ok(manager)
    }

    fn new_session(self: &Arc<Self>) -> Hysteria2UdpSession {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(HYSTERIA2_UDP_SESSION_CHANNEL);
        self.sessions
            .lock()
            .expect("hysteria2 UDP session map")
            .insert(id, sender);
        Hysteria2UdpSession { id, receiver }
    }

    fn dispatch(&self, message: Hysteria2UdpMessage) {
        let sessions = self.sessions.lock().expect("hysteria2 UDP session map");
        if let Some(sender) = sessions.get(&message.session_id) {
            let _ = sender.try_send(message);
        }
    }

    fn remove(&self, session_id: u32) {
        self.sessions
            .lock()
            .expect("hysteria2 UDP session map")
            .remove(&session_id);
    }

    /// Drops every session sender so each receiver observes end-of-stream. Used
    /// when the QUIC datagram reader stops (connection dead): otherwise a
    /// receive-only flow would park forever on a channel no one can feed.
    fn clear(&self) {
        self.sessions
            .lock()
            .expect("hysteria2 UDP session map")
            .clear();
    }
}

async fn receive_hysteria2_udp_messages(
    connection: quinn::Connection,
    manager: Weak<Hysteria2UdpSessionManager>,
) {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                if let Some(message) = Hysteria2UdpMessage::parse(&datagram) {
                    let Some(manager) = manager.upgrade() else {
                        return;
                    };
                    manager.dispatch(message);
                }
            }
            // The connection is gone: end every session so receive-only flows
            // stop waiting and the session actor rebuilds on the next datagram.
            Err(_) => {
                if let Some(manager) = manager.upgrade() {
                    manager.clear();
                }
                return;
            }
        }
    }
}

struct Hysteria2TcpStream {
    send: TurnSend,
    recv: quinn::RecvStream,
    response_done: bool,
    scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    /// Keeps the QUIC connection the stream rides alive while it is in use.
    _client: Arc<Hysteria2Client>,
}

impl Hysteria2TcpStream {
    fn new(send: TurnSend, recv: quinn::RecvStream, client: Arc<Hysteria2Client>) -> Self {
        Self {
            send,
            recv,
            response_done: false,
            scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_pos: 0,
            _client: client,
        }
    }

    async fn establish(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_establish(cx)).await
    }

    fn poll_establish(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = &mut *self;
        while !stream.response_done {
            match parse_tcp_response(&stream.scratch) {
                TcpResponseParse::Done { ok, consumed } => {
                    if !ok {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "Hysteria2 server rejected TCP request",
                        )));
                    }
                    stream.leftover = stream.scratch.split_off(consumed);
                    stream.scratch = Vec::new();
                    stream.response_done = true;
                    break;
                }
                TcpResponseParse::Invalid => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Hysteria2 TCP response is malformed",
                    )));
                }
                TcpResponseParse::NeedMore => {
                    let mut temporary = [0_u8; 512];
                    let mut buffer = ReadBuf::new(&mut temporary);
                    match Pin::new(&mut stream.recv).poll_read(cx, &mut buffer) {
                        Poll::Ready(Ok(())) => {
                            let filled = buffer.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Hysteria2 stream closed before TCP response",
                                )));
                            }
                            stream.scratch.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.response_done {
            match self.as_mut().poll_establish(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let stream = &mut *self;
        if stream.leftover_pos < stream.leftover.len() {
            let remaining = &stream.leftover[stream.leftover_pos..];
            let length = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..length]);
            stream.leftover_pos += length;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut stream.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// The connector's QUIC client config. Clones retain the TLS session and QUIC
/// validation-token stores across carrier reconnects, within this compiled
/// connector only.
fn base_client_config(
    config: &Hysteria2Config,
    quic_config: &OnceLock<Result<ClientConfig, String>>,
) -> Result<ClientConfig, OutboundError> {
    quic_config
        .get_or_init(|| {
            let tls = crate::tls::node_client_config(config.insecure, &config.alpn);
            Ok(ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|error| {
                    format!("failed to build Hysteria2 QUIC TLS config: {error}")
                })?,
            )))
        })
        .as_ref()
        .map_err(|error| OutboundError::new(OutboundStage::Config, error.clone()))
        .cloned()
}

/// A QUIC connection whose handshake finished, with its endpoint, where its
/// socket leaves the host, and the send rate its controller and pacer share.
struct Handshaken {
    connection: quinn::Connection,
    endpoint: Endpoint,
    binding: EgressBinding,
    send_rate: Arc<SendRate>,
}

/// Starts `config.paths` QUIC handshakes with `server_addr` at once, each
/// from a socket of its own, and keeps the first to finish; dropping the
/// rest closes them and their endpoints. Every handshake failing fails with
/// the first failure.
async fn handshake_on_fastest_path(
    config: &Hysteria2Config,
    quic_config: &OnceLock<Result<ClientConfig, String>>,
    egress: &EgressRuntime,
    server_addr: SocketAddr,
) -> Result<Handshaken, OutboundError> {
    let mut handshakes = Pending::new();
    let mut failure = None;
    for _ in 0..config.paths.max(1) {
        match start_handshake(config, quic_config, egress, server_addr).await {
            Ok(handshake) => handshakes.push(handshake),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    while let Some(handshake) = handshakes.next().await {
        match handshake {
            Ok(handshaken) => return Ok(handshaken),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    Err(failure.expect("a handshake was tried"))
}

/// Binds an endpoint for `server_addr` and begins a QUIC handshake on it;
/// the future returned finishes it.
async fn start_handshake(
    config: &Hysteria2Config,
    quic_config: &OnceLock<Result<ClientConfig, String>>,
    egress: &EgressRuntime,
    server_addr: SocketAddr,
) -> Result<impl std::future::Future<Output = Result<Handshaken, OutboundError>>, OutboundError> {
    // The connection's controller and its socket's pacer share the send
    // rate authentication settles, so each connection gets its own
    // transport config. The endpoint binds a UDP socket of the candidate's
    // family.
    let send_rate = Arc::new(SendRate::default());
    let (socket, binding) = carrier_socket(egress, server_addr, &send_rate).await?;
    let endpoint = quic_endpoint(socket)?;
    let connecting = begin_quic_dial(config, quic_config, &endpoint, server_addr, &send_rate)?;
    Ok(async move {
        Ok(Handshaken {
            connection: finish_quic_dial(connecting).await?,
            endpoint,
            binding,
            send_rate,
        })
    })
}

/// A carrier's endpoint over `socket`.
fn quic_endpoint(socket: Arc<dyn AsyncUdpSocket>) -> Result<Endpoint, OutboundError> {
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime).map_err(
        |error| {
            OutboundError::new(
                OutboundStage::Local,
                format!("failed to create Hysteria2 QUIC endpoint: {error}"),
            )
        },
    )
}

/// Begins the QUIC handshake with `server_addr` on `endpoint`, with the
/// connection's own transport config: its controller and its socket's pacer
/// share `send_rate`.
fn begin_quic_dial(
    config: &Hysteria2Config,
    quic_config: &OnceLock<Result<ClientConfig, String>>,
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    send_rate: &Arc<SendRate>,
) -> Result<quinn::Connecting, OutboundError> {
    let mut client_config = base_client_config(config, quic_config)?;
    client_config.transport_config(Arc::new(transport_config(send_rate)));
    endpoint
        .connect_with(client_config, server_addr, config.server_name())
        .map_err(|error| {
            OutboundError::new(
                OutboundStage::Config,
                format!("failed to begin Hysteria2 QUIC dial: {error}"),
            )
        })
}

async fn finish_quic_dial(
    connecting: quinn::Connecting,
) -> Result<quinn::Connection, OutboundError> {
    connecting.await.map_err(|error| {
        OutboundError::new(
            OutboundStage::HopConnect,
            format!("failed to connect Hysteria2 QUIC session: {error}"),
        )
    })
}

/// A UDP socket of a carrier to `server`, guarded like every egress socket,
/// with where it leaves the host. The carrier owns that binding: the socket
/// of a losing attempt or of a move must not overwrite the caller's, and
/// later streams report it even when a caller without a per-flow recorder
/// created the carrier. A socket connected to the server keeps the source
/// address it got, so the binding names that address, and a network change
/// that takes it away strands the carrier.
async fn carrier_socket(
    egress: &EgressRuntime,
    server: SocketAddr,
    send_rate: &Arc<SendRate>,
) -> Result<(Arc<dyn AsyncUdpSocket>, EgressBinding), OutboundError> {
    let (socket, binding) = bind_carrier_socket(egress, server).await?;
    let socket = quinn_socket(socket, server, send_rate)?;
    let binding = binding.at(socket.local_addr());
    Ok((socket, binding))
}

/// A guarded UDP socket for a carrier to `server` and the egress the guard
/// reported for it, not yet naming its source address.
async fn bind_carrier_socket(
    egress: &EgressRuntime,
    server: SocketAddr,
) -> Result<(tokio::net::UdpSocket, EgressBinding), OutboundError> {
    let egress = egress.with_binding_recorder();
    let socket = egress
        .bind_udp_for_host(&server.ip().to_string(), "Hysteria2 QUIC UDP socket")
        .await
        .map_err(OutboundError::hop_dial)?;
    Ok((socket, egress.recorded_binding()))
}

/// `socket` as quinn takes it: connected to `server` unless the platform
/// offloads segmentation, and paced at the carrier's send rate.
fn quinn_socket(
    socket: tokio::net::UdpSocket,
    server: SocketAddr,
    send_rate: &Arc<SendRate>,
) -> Result<Arc<dyn AsyncUdpSocket>, OutboundError> {
    let local = |what: &str, error: io::Error| {
        OutboundError::new(
            OutboundStage::Local,
            format!("failed to {what} Hysteria2 UDP socket: {error}"),
        )
    };
    let socket = socket.into_std().map_err(|error| local("convert", error))?;
    let socket = client_socket(socket, server).map_err(|error| local("set up", error))?;
    Ok(Arc::new(PacedSocket::new(socket, Arc::clone(send_rate))))
}

/// Checks a carrier's path [`PATH_CHECK_AFTER_DIAL`] after its dial and
/// every [`PATH_CHECK_EVERY`] after that, until it closes or its policy
/// retires. Its first path is the fastest of a few drawn at once, and a live
/// flow keeps its path, but all of them can have been slow, and routes
/// change.
async fn keep_path(carrier: Weak<Hysteria2Client>, egress: EgressRuntime) {
    let cancel = egress.policy_cancel();
    let mut wait = PATH_CHECK_AFTER_DIAL;
    loop {
        tokio::select! { biased;
            _ = cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
        let Some(carrier) = carrier.upgrade().filter(|carrier| carrier.is_open()) else {
            return;
        };
        carrier.check_path(&egress).await;
        wait = PATH_CHECK_EVERY;
    }
}

fn transport_config(send_rate: &Arc<SendRate>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(Duration::from_secs(30)).expect("valid idle timeout"),
    ));
    transport.initial_rtt(Duration::from_millis(100));
    // Widen the flow-control windows, and send with BBR or the agreed fixed
    // rate, so the high-BDP, lossy links hysteria2 targets are not throttled
    // by quinn's conservative Cubic defaults.
    transport.stream_receive_window(VarInt::from_u32(HYSTERIA2_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(HYSTERIA2_CONNECTION_RECEIVE_WINDOW));
    transport.send_window(HYSTERIA2_SEND_WINDOW);
    transport
        .congestion_controller_factory(Arc::new(RateControlFactory::new(Arc::clone(send_rate))));
    transport
        .datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE * HYSTERIA2_QUEUED_DATAGRAMS));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE * HYSTERIA2_QUEUED_DATAGRAMS);
    transport
}

struct Hysteria2AuthResponse {
    udp_enabled: bool,
    server_rx: ServerReceiveRate,
}

/// The server's `Hysteria-CC-RX` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerReceiveRate {
    /// `auto`: the client must use congestion control.
    Auto,
    /// Bytes per second; 0 means no limit.
    Limit(u64),
}

impl ServerReceiveRate {
    /// Only `auto` asks for congestion control. A missing or malformed value
    /// states no limit, as 0 does, so the client's own rate stands.
    fn from_header(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("auto") => Self::Auto,
            value => Self::Limit(value.and_then(|value| value.parse().ok()).unwrap_or(0)),
        }
    }

    /// The client's fixed send rate for its own `up` rate: the lower of the
    /// two, or 0 (congestion control) when the server asks for it or the
    /// client's rate is unknown.
    fn send_rate(self, up: u64) -> u64 {
        match self {
            Self::Auto => 0,
            Self::Limit(0) => up,
            Self::Limit(limit) => up.min(limit),
        }
    }
}

async fn authenticate_hysteria2_connection(
    connection: &quinn::Connection,
    config: &Hysteria2Config,
    egress: &EgressRuntime,
) -> Result<(Hysteria2AuthResponse, JoinHandle<()>), OutboundError> {
    let carrier = |message: String| OutboundError::new(OutboundStage::HopConnect, message);
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut request_sender) = h3::client::new(h3_connection)
        .await
        .map_err(|error| carrier(format!("failed to start Hysteria2 HTTP/3 client: {error}")))?;
    // `:authority` comes from the URI host; the reference client sends no
    // extra `Host` header, so neither do we. `Hysteria-CC-RX` carries the
    // client's download bandwidth (bytes/s), which the server may use as its
    // send rate.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", &config.auth)
        .header("Hysteria-CC-RX", config.recv_bps.to_string())
        .header(
            "Hysteria-Padding",
            random_padding_string(AUTH_PADDING_MIN, AUTH_PADDING_MAX),
        )
        .body(())
        .map_err(|error| {
            OutboundError::new(
                OutboundStage::Config,
                format!("failed to build Hysteria2 auth request: {error}"),
            )
        })?;

    let mut stream = request_sender
        .send_request(request)
        .await
        .map_err(|error| carrier(format!("failed to send Hysteria2 auth request: {error}")))?;
    stream
        .finish()
        .await
        .map_err(|error| carrier(format!("failed to finish Hysteria2 auth request: {error}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| carrier(format!("failed to read Hysteria2 auth response: {error}")))?;

    let status = response.status().as_u16();
    if status != AUTH_OK_STATUS {
        return Err(OutboundError::new(
            OutboundStage::HopAuth,
            format!("Hysteria2 authentication failed with HTTP/3 status {status}"),
        ));
    }

    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let udp_enabled = header("Hysteria-UDP") == Some("true");
    let server_rx = ServerReceiveRate::from_header(header("Hysteria-CC-RX"));

    // Keep the HTTP/3 driver and request sender alive for the whole tunnel.
    // Dropping them finishes (FIN) the H3 control and QPACK streams, which a
    // strict server treats as H3_CLOSED_CRITICAL_STREAM (RFC 9114 §6.2.1) and
    // tears the connection down. Polling `poll_close`
    // also processes the server control stream (e.g. GOAWAY). The driver never
    // reads QUIC datagrams, so the raw-datagram UDP relay is unaffected.
    let cancel = egress.policy_cancel();
    let driver_task = egress
        .spawn_policy_task(async move {
            let _request_sender = request_sender;
            tokio::select! { biased;
                _ = cancel.cancelled() => {},
                _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => {},
            }
        })
        .at(OutboundStage::Local)?;

    Ok((
        Hysteria2AuthResponse {
            udp_enabled,
            server_rx,
        },
        driver_task,
    ))
}

/// One carrier attempt as the address race sees it. Every candidate is an
/// address of the same server, so only a verdict that holds for all of them
/// (rejected credentials, unusable configuration) ends the race; a
/// connection failure leaves the other addresses worth trying.
struct CarrierAttempt(OutboundError);

impl fmt::Display for CarrierAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl AttemptError for CarrierAttempt {
    fn ends_race(&self) -> bool {
        matches!(self.0.stage, OutboundStage::HopAuth | OutboundStage::Config)
    }
}

/// The carrier failure across every address: the verdict that ended the
/// race, unresolved addresses, or the node failing to accept.
fn carrier_failure(
    config: &Hysteria2Config,
    failure: RaceFailure<CarrierAttempt>,
) -> OutboundError {
    let stage = if let Some((_, CarrierAttempt(error))) = &failure.ended_by {
        error.stage
    } else if failure.launched == 0 {
        OutboundStage::HopResolve
    } else if failure.only_local(|CarrierAttempt(error)| error.stage == OutboundStage::Local) {
        OutboundStage::Local
    } else {
        failure
            .attempts
            .iter()
            .find_map(|(_, attempt)| match attempt {
                AttemptFailure::Failed(CarrierAttempt(error)) if error.stage.charges_node() => {
                    Some(error.stage)
                }
                _ => None,
            })
            .unwrap_or(OutboundStage::HopConnect)
    };
    OutboundError::new(
        stage,
        format!(
            "failed to connect Hysteria2 server {}: {failure}",
            config.server_addr()
        ),
    )
}

fn encode_tcp_request(address: &str) -> Vec<u8> {
    let padding = random_padding(TCP_PADDING_MIN, TCP_PADDING_MAX);
    let mut request = BytesMut::with_capacity(16 + address.len() + padding.len());
    put_varint(&mut request, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
    put_varint(&mut request, address.len() as u64);
    request.put_slice(address.as_bytes());
    put_varint(&mut request, padding.len() as u64);
    request.put_slice(&padding);
    request.to_vec()
}

enum TcpResponseParse {
    NeedMore,
    Done { ok: bool, consumed: usize },
    Invalid,
}

fn parse_tcp_response(buffer: &[u8]) -> TcpResponseParse {
    let mut cursor = 0;
    let Some(status) = buffer.get(cursor) else {
        return TcpResponseParse::NeedMore;
    };
    cursor += 1;

    let Some((message_length, used)) = buffer.get(cursor..).and_then(get_varint) else {
        return TcpResponseParse::NeedMore;
    };
    if message_length > MAX_MESSAGE_LENGTH {
        return TcpResponseParse::Invalid;
    }
    cursor += used + message_length as usize;
    if buffer.len() < cursor {
        return TcpResponseParse::NeedMore;
    }

    let Some((padding_length, used)) = buffer.get(cursor..).and_then(get_varint) else {
        return TcpResponseParse::NeedMore;
    };
    if padding_length > MAX_PADDING_LENGTH {
        return TcpResponseParse::Invalid;
    }
    cursor += used + padding_length as usize;
    if buffer.len() < cursor {
        return TcpResponseParse::NeedMore;
    }

    TcpResponseParse::Done {
        ok: *status == 0,
        consumed: cursor,
    }
}

/// Reads a Clash bandwidth option (`up`/`down`) as bytes per second. Accepts a
/// units string or a bare number.
fn option_bandwidth_bps(options: &JsonValue, key: &str) -> u64 {
    match options.get(key) {
        Some(JsonValue::String(text)) => parse_bandwidth_bps(text),
        // A bare number (no unit) is megabits per second.
        Some(JsonValue::Number(number)) => number
            .as_u64()
            .map(|value| value.saturating_mul(1_000_000) / 8)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Parses a bandwidth string to bytes per second:
/// `<int>[K|M|G|T]?(B|b)ps` where an uppercase `B` is bytes and a lowercase
/// `b` is bits (divided by 8); magnitudes are decimal (×1000). A bare integer
/// is treated as megabits per second. Anything else yields 0 ("unknown").
fn parse_bandwidth_bps(value: &str) -> u64 {
    let text = value.trim();
    if text.is_empty() {
        return 0;
    }
    if let Ok(plain) = text.parse::<u64>() {
        return plain.saturating_mul(1_000_000) / 8;
    }

    let split = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    let Ok(number) = text[..split].parse::<u64>() else {
        return 0;
    };
    let (magnitude, is_bits) = match text[split..].trim() {
        "Bps" => (1, false),
        "bps" => (1, true),
        "KBps" => (1_000, false),
        "Kbps" => (1_000, true),
        "MBps" => (1_000_000, false),
        "Mbps" => (1_000_000, true),
        "GBps" => (1_000_000_000, false),
        "Gbps" => (1_000_000_000, true),
        "TBps" => (1_000_000_000_000, false),
        "Tbps" => (1_000_000_000_000, true),
        _ => return 0,
    };
    let scaled = number.saturating_mul(magnitude);
    if is_bits {
        scaled / 8
    } else {
        scaled
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::egress::{
        EgressNetwork, EgressRuntime, EgressSocketDescriptor, EgressSocketGuard,
        NativeCoreEgressConfig,
    };
    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::runtime::NativeCoreRuntime;

    #[test]
    fn a_reply_names_an_address_or_the_host_it_was_sent_to() {
        assert_eq!(
            pump_from("203.0.113.7:443"),
            Some(PumpFrom::Addr("203.0.113.7:443".parse().unwrap()))
        );
        assert_eq!(
            pump_from("[2001:db8::7]:443"),
            Some(PumpFrom::Addr("[2001:db8::7]:443".parse().unwrap()))
        );
        assert_eq!(
            pump_from("a.example:53"),
            Some(PumpFrom::Name(ConnectTarget {
                host: "a.example".into(),
                port: 53,
            }))
        );
        assert_eq!(pump_from("no port"), None);
    }

    /// Binds the n-th socket it protects to interface 41 + n, and none while
    /// the uplink is down.
    #[derive(Debug, Default)]
    struct RecordingSocketGuard {
        seen: AtomicUsize,
        down: AtomicBool,
    }

    impl EgressSocketGuard for RecordingSocketGuard {
        fn protect_socket(
            &self,
            _descriptor: EgressSocketDescriptor,
            _context: crate::egress::EgressSocketContext,
        ) -> Result<crate::egress::EgressBinding, String> {
            if self.down.load(Ordering::Relaxed) {
                return Err("no physical uplink".into());
            }
            let index = self.seen.fetch_add(1, Ordering::Relaxed) as u32;
            Ok(crate::egress::EgressBinding::bound(41 + index))
        }
    }

    /// The physical network with these interfaces, each holding one IPv4
    /// address, and new IPv4 dials bound to `uplink`.
    fn network(uplink: Option<u32>, interfaces: &[u32]) -> EgressNetwork {
        EgressNetwork {
            ipv4_uplink: uplink,
            ipv6_uplink: None,
            addresses: interfaces
                .iter()
                .map(|index| (*index, Ipv4Addr::new(192, 0, 2, *index as u8).into()))
                .collect(),
        }
    }

    /// Until the server takes the carrier's current socket as the client's
    /// address.
    async fn served_from_current_socket(server: &quinn::Connection, carrier: &Hysteria2Client) {
        let port = carrier.endpoint.local_addr().unwrap().port();
        tokio::time::timeout(Duration::from_secs(3), async {
            while server.remote_address().port() != port {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the server follows the carrier to its new socket");
    }

    #[test]
    fn reads_common_clash_hysteria2_options() {
        let config = Hysteria2Config::from_options(
            "proxy.example.com".into(),
            443,
            &json!({
                "password": "secret",
                "sni": "front.example.com",
                "skip-cert-verify": "true",
                "alpn": ["h3"],
                "fast-open": false,
                "up": "20 Mbps",
                "down": "100 Mbps"
            }),
        );

        assert_eq!(config.auth, "secret");
        assert_eq!(config.server_addr(), "proxy.example.com:443");
        assert_eq!(config.server_name(), "front.example.com");
        assert!(config.insecure);
        assert_eq!(config.alpn, vec![b"h3".to_vec()]);
        assert!(!config.fast_open);
        assert_eq!(config.recv_bps, 12_500_000);
        assert_eq!(config.send_bps, 2_500_000);
    }

    #[test]
    fn the_send_rate_is_the_lower_of_up_and_the_server_receive_rate() {
        use ServerReceiveRate::{Auto, Limit};
        assert_eq!(ServerReceiveRate::from_header(Some("auto")), Auto);
        assert_eq!(
            ServerReceiveRate::from_header(Some("12500000")),
            Limit(12_500_000)
        );
        assert_eq!(ServerReceiveRate::from_header(None), Limit(0));
        assert_eq!(ServerReceiveRate::from_header(Some("fast")), Limit(0));
        assert_eq!(Auto.send_rate(2_500_000), 0);
        assert_eq!(Limit(0).send_rate(2_500_000), 2_500_000);
        assert_eq!(Limit(1_000_000).send_rate(2_500_000), 1_000_000);
        assert_eq!(Limit(12_500_000).send_rate(2_500_000), 2_500_000);
        assert_eq!(Limit(12_500_000).send_rate(0), 0);
    }

    #[test]
    fn records_unsupported_hysteria2_extensions() {
        let config = Hysteria2Config::from_options(
            "proxy.example.com".into(),
            443,
            &json!({
                "password": "secret",
                "obfs": "salamander",
                "obfs-password": "obfs-secret",
                "fingerprint": "ab:cd",
                "certificate": "cert.pem",
                "private-key": "key.pem"
            }),
        );

        assert_eq!(
            config.unsupported_features,
            vec![
                "obfs",
                "obfs-password",
                "fingerprint",
                "certificate",
                "private-key"
            ]
        );
    }

    #[test]
    fn parses_hysteria2_bandwidth_options() {
        assert_eq!(parse_bandwidth_bps("100 Mbps"), 12_500_000);
        assert_eq!(parse_bandwidth_bps("100Mbps"), 12_500_000);
        assert_eq!(parse_bandwidth_bps("1 Gbps"), 125_000_000);
        assert_eq!(parse_bandwidth_bps("100 MBps"), 100_000_000);
        assert_eq!(parse_bandwidth_bps("512 Kbps"), 64_000);
        assert_eq!(parse_bandwidth_bps("8 bps"), 1);
        // A bare number is megabits per second.
        assert_eq!(parse_bandwidth_bps("50"), 6_250_000);
        assert_eq!(parse_bandwidth_bps(""), 0);
        assert_eq!(parse_bandwidth_bps("fast"), 0);
        assert_eq!(parse_bandwidth_bps("100 mbps"), 0);
        // JSON number falls back to the bare-number (megabits) reading.
        assert_eq!(
            option_bandwidth_bps(&json!({ "down": 50 }), "down"),
            6_250_000
        );
    }

    #[test]
    fn encodes_hysteria2_tcp_request_frame() {
        let request = encode_tcp_request("example.com:443");
        let (frame_type, used) = get_varint(&request).expect("frame type");
        assert_eq!(frame_type, HYSTERIA2_TCP_REQUEST_FRAME_TYPE);
        let (address_length, address_length_used) =
            get_varint(&request[used..]).expect("address length");
        let address_start = used + address_length_used;
        let address_end = address_start + address_length as usize;
        assert_eq!(&request[address_start..address_end], b"example.com:443");
        let (padding_length, padding_length_used) =
            get_varint(&request[address_end..]).expect("padding length");
        assert!((TCP_PADDING_MIN..TCP_PADDING_MAX).contains(&(padding_length as usize)));
        assert_eq!(
            request.len(),
            address_end + padding_length_used + padding_length as usize
        );
    }

    #[test]
    fn parses_hysteria2_tcp_response_and_leftover_payload() {
        let mut response = BytesMut::new();
        response.put_u8(0);
        put_varint(&mut response, 2);
        response.put_slice(b"ok");
        put_varint(&mut response, 3);
        response.put_slice(b"pad");
        response.put_slice(b"payload");

        match parse_tcp_response(&response) {
            TcpResponseParse::Done { ok, consumed } => {
                assert!(ok);
                assert_eq!(&response[consumed..], b"payload");
            }
            TcpResponseParse::NeedMore | TcpResponseParse::Invalid => {
                panic!("response should parse")
            }
        }
    }

    #[tokio::test]
    async fn quic_reconnect_reuses_config_and_protects_each_new_socket() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(Arc::clone(&guard) as Arc<dyn EgressSocketGuard>),
        );
        let config = Hysteria2Config::from_options(
            "127.0.0.1".into(),
            443,
            &json!({ "password": "secret" }),
        );

        let quic_config = OnceLock::new();
        let server = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);
        base_client_config(&config, &quic_config).expect("client config builds");
        let send_rate = Arc::new(SendRate::default());
        let (socket, _) = carrier_socket(&egress, server, &send_rate)
            .await
            .expect("socket binds");
        let endpoint = quic_endpoint(socket).expect("endpoint builds");

        let cached = quic_config.get().unwrap().as_ref().unwrap();
        drop(endpoint);
        base_client_config(&config, &quic_config).expect("cached client config");
        let (socket, _) = carrier_socket(&egress, server, &send_rate)
            .await
            .expect("new socket binds");
        let _reconnected = quic_endpoint(socket).expect("new endpoint builds");

        assert!(std::ptr::eq(
            cached,
            quic_config.get().unwrap().as_ref().unwrap()
        ));
        assert_eq!(guard.seen.load(Ordering::Relaxed), 2);
        let fresh =
            Hysteria2Connector::new("127.0.0.1".into(), 443, &json!({ "password": "secret" }));
        assert!(fresh.quic_config.get().is_none());
    }

    /// A QUIC/HTTP/3 server on 127.0.0.1 that authenticates `carriers`
    /// Hysteria2 connections, hands its side of each to the receiver and keeps
    /// it open until the client closes it. Connections that close before
    /// authenticating, a carrier dial's losing handshakes, count for nothing.
    fn serve_hysteria2_auth(
        carriers: usize,
    ) -> (
        SocketAddr,
        JoinHandle<()>,
        mpsc::UnboundedReceiver<quinn::Connection>,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let (connections, accepted) = mpsc::unbounded_channel();
        let peer = tokio::spawn(async move {
            let (closed, mut closings) = mpsc::unbounded_channel();
            let mut ended = 0;
            while ended < carriers {
                tokio::select! {
                    incoming = server.accept() => {
                        let incoming = incoming.expect("the server endpoint stays open");
                        let (connections, closed) = (connections.clone(), closed.clone());
                        tokio::spawn(async move {
                            if authenticate(incoming, &connections).await.is_some() {
                                let _ = closed.send(());
                            }
                        });
                    }
                    Some(()) = closings.recv() => ended += 1,
                }
            }
            server.close(0u32.into(), b"test complete");
        });
        (address, peer, accepted)
    }

    /// Authenticates one Hysteria2 connection, hands it over and returns once
    /// the client closed it; none if it closed first.
    async fn authenticate(
        incoming: quinn::Incoming,
        connections: &mpsc::UnboundedSender<quinn::Connection>,
    ) -> Option<()> {
        let connection = incoming.await.ok()?;
        let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(
            connection.clone(),
        ))
        .await
        .ok()?;
        let request = h3.accept().await.ok()??;
        let (_, mut stream) = request.resolve_request().await.ok()?;
        stream
            .send_response(
                http::Response::builder()
                    .status(AUTH_OK_STATUS)
                    .header("Hysteria-UDP", "true")
                    .body(())
                    .unwrap(),
            )
            .await
            .ok()?;
        stream.finish().await.ok()?;
        let _ = connections.send(connection.clone());
        connection.closed().await;
        drop(h3);
        Some(())
    }

    /// Relays UDP between its clients and `server`, each client through a
    /// socket of its own, holding back both ways by `delay` the packets of
    /// the clients whose order of arrival `slow` lists: a network whose paths
    /// differ by flow.
    async fn uneven_paths(server: SocketAddr, slow: &[usize], delay: Duration) -> SocketAddr {
        let slow = slow.to_vec();
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = front.local_addr().unwrap();
        tokio::spawn(async move {
            let mut flows = HashMap::new();
            let mut buffer = vec![0_u8; 65536];
            loop {
                // Windows reports the ICMP error for a datagram relayed to a
                // client socket already closed (a losing probe's, a carrier's
                // old one) on the next receive; the other flows go on.
                let (length, client) = match front.recv_from(&mut buffer).await {
                    Ok(received) => received,
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(_) => return,
                };
                if !flows.contains_key(&client) {
                    let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    back.connect(server).await.unwrap();
                    let hold = if slow.contains(&flows.len()) {
                        delay
                    } else {
                        Duration::ZERO
                    };
                    let (front, returning) = (Arc::clone(&front), Arc::clone(&back));
                    tokio::spawn(async move {
                        let mut buffer = vec![0_u8; 65536];
                        while let Ok(length) = returning.recv(&mut buffer).await {
                            if hold.is_zero() {
                                let _ = front.send_to(&buffer[..length], client).await;
                                continue;
                            }
                            let (front, packet) = (Arc::clone(&front), buffer[..length].to_vec());
                            tokio::spawn(async move {
                                tokio::time::sleep(hold).await;
                                let _ = front.send_to(&packet, client).await;
                            });
                        }
                    });
                    flows.insert(client, (back, hold));
                }
                let (back, hold) = flows[&client].clone();
                if hold.is_zero() {
                    let _ = back.send(&buffer[..length]).await;
                    continue;
                }
                let packet = buffer[..length].to_vec();
                tokio::spawn(async move {
                    tokio::time::sleep(hold).await;
                    let _ = back.send(&packet).await;
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn a_carrier_keeps_the_fastest_of_its_paths() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, _) = serve_hysteria2_auth(1);
        // Every path but the last a dial starts adds 300 ms a round trip.
        let front = uneven_paths(address, &[0, 1], Duration::from_millis(150)).await;
        let config = Hysteria2Config::from_options(
            front.ip().to_string(),
            front.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        let started = tokio::time::Instant::now();
        let client = Hysteria2Client::connect_addr(
            &config,
            &OnceLock::new(),
            &EgressRuntime::default(),
            front,
        )
        .await
        .expect("a path authenticates");

        assert!(
            started.elapsed() < Duration::from_millis(300),
            "authenticated after {:?}",
            started.elapsed()
        );
        assert!(
            client.connection.rtt() < Duration::from_millis(150),
            "the carrier's round trip is {:?}",
            client.connection.rtt()
        );
        drop(client);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    /// Writes on a stream until the carrier's round-trip estimate drops under
    /// `bound`, or gives up after a while.
    async fn rtt_settles_under(client: &Hysteria2Client, bound: Duration) -> Duration {
        let mut stream = client.connection.open_uni().await.unwrap();
        for _ in 0..100 {
            if client.connection.rtt() < bound {
                break;
            }
            stream.write_all(b"ping").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        client.connection.rtt()
    }

    #[tokio::test]
    async fn a_carrier_on_a_slow_path_moves_to_a_faster_one() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, _) = serve_hysteria2_auth(1);
        // Every path the dial draws adds 300 ms a round trip; the ones the
        // check probes after do not.
        let front = uneven_paths(address, &[0, 1, 2], Duration::from_millis(150)).await;
        let config = Hysteria2Config::from_options(
            front.ip().to_string(),
            front.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        let egress = EgressRuntime::default();
        let client = Hysteria2Client::connect_addr(&config, &OnceLock::new(), &egress, front)
            .await
            .expect("a slow path authenticates");
        assert!(client.connection.rtt() >= Duration::from_millis(250));

        assert!(client.check_path(&egress).await, "a faster path was found");
        let rtt = rtt_settles_under(&client, Duration::from_millis(20)).await;
        assert!(rtt < Duration::from_millis(20), "the round trip is {rtt:?}");
        assert!(client.is_open());
        // Already on the fastest path, the next check stays.
        assert!(!client.check_path(&egress).await);

        drop(client);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_move_takes_the_fastest_path_on_the_new_uplink() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, _) = serve_hysteria2_auth(1);
        // The dial draws three fast paths; the first socket the move binds
        // meets a slow one.
        let front = uneven_paths(address, &[PATH_CANDIDATES], Duration::from_millis(150)).await;
        let config = Hysteria2Config::from_options(
            front.ip().to_string(),
            front.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        let egress = EgressRuntime::default();
        let client = Hysteria2Client::connect_addr(&config, &OnceLock::new(), &egress, front)
            .await
            .expect("a fast path authenticates");
        // The server has answered probes before.
        client.negotiates.store(true, Ordering::Relaxed);

        client.move_to_uplink(&egress, false).await;
        // Taking the first socket would have doubled the round trip by now.
        let mut stream = client.connection.open_uni().await.unwrap();
        for _ in 0..40 {
            stream.write_all(b"ping").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let rtt = client.connection.rtt();
        assert!(
            rtt < Duration::from_millis(100),
            "the round trip is {rtt:?}"
        );
        assert!(client.is_open());

        drop((stream, client));
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_silent_first_address_fails_over_to_the_next_candidate() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, _) = serve_hysteria2_auth(1);
        // Takes the QUIC Initial and never answers, like a blackholed address
        // of a dual-homed server.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let mut config = Hysteria2Config::from_options(
            address.ip().to_string(),
            address.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        config.paths = 1;
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(guard.clone() as Arc<dyn EgressSocketGuard>),
        );
        let mut candidates = Pending::new();
        candidates.push(async move { Ok(vec![silent_addr, address]) });

        let started = tokio::time::Instant::now();
        let client = Hysteria2Client::connect_candidates(
            &config,
            &OnceLock::new(),
            &egress,
            candidates,
            started + HYSTERIA2_CONNECT_TIMEOUT,
        )
        .await
        .expect("the live address authenticates");

        assert_eq!(client.connection.remote_address(), address);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the live address starts after the dial stagger, not after the silent one's budget"
        );
        let mut initial = [0_u8; 1500];
        assert!(
            silent.try_recv(&mut initial).is_ok(),
            "the silent address was tried first"
        );
        // The silent attempt's socket took binding 41; the carrier keeps its own.
        assert_eq!(client.binding().interface_index, Some(42));
        drop(client);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn ipv6_policy_retires_cached_carrier_and_reuses_static_tls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, _) = serve_hysteria2_auth(2);
        let mut connector = Hysteria2Connector::new(
            address.ip().to_string(),
            address.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        connector.config.paths = 1;
        let guard = Arc::new(RecordingSocketGuard::default());
        let old_policy = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(guard.clone()),
        );
        // The first caller deliberately has no recorder, as a configured DNS
        // transport may initialize a carrier before an application flow.
        let first = connector.client(&old_policy).await.unwrap();
        assert_eq!(first.binding().interface_index, Some(41));
        let attempt_a = old_policy.with_binding_recorder();
        let attempt_b = old_policy.with_binding_recorder();
        let (reused_a, reused_b) =
            tokio::join!(connector.client(&attempt_a), connector.client(&attempt_b),);
        assert!(Arc::ptr_eq(&first, &reused_a.unwrap()));
        assert!(Arc::ptr_eq(&first, &reused_b.unwrap()));
        // Streams on a carrier report its interface but no local address: the
        // carrier moves them when the network changes.
        assert_eq!(attempt_a.recorded_binding(), EgressBinding::bound(41));
        assert_eq!(attempt_b.recorded_binding(), EgressBinding::bound(41));
        assert_eq!(guard.seen.load(Ordering::Relaxed), 1);
        let tls_config = connector.quic_config.get().unwrap().as_ref().unwrap() as *const _;
        let retired = old_policy.retire_policy();
        tokio::time::timeout(Duration::from_secs(3), retired.wait())
            .await
            .unwrap();
        assert!(!first.is_open());
        assert!(connector.client.lock().unwrap().is_none());
        assert!(connector.client(&old_policy).await.is_err());
        let new_policy = old_policy.with_ipv6_policy(true);
        let next_attempt = new_policy.with_binding_recorder();
        let second = connector.client(&next_attempt).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.binding().interface_index, Some(42));
        assert_eq!(next_attempt.recorded_binding(), EgressBinding::bound(42));
        assert_eq!(guard.seen.load(Ordering::Relaxed), 2);
        assert_eq!(
            tls_config,
            connector.quic_config.get().unwrap().as_ref().unwrap() as *const _
        );
        let retired = new_policy.retire_policy();
        tokio::time::timeout(Duration::from_secs(3), retired.wait())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn the_carrier_follows_the_uplink_and_keeps_its_connection() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, mut accepted) = serve_hysteria2_auth(1);
        let mut connector = Hysteria2Connector::new(
            address.ip().to_string(),
            address.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        connector.config.paths = 1;
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(guard.clone()),
        );
        let carrier = connector.client(&egress).await.unwrap();
        let server = accepted.recv().await.unwrap();
        assert_eq!(carrier.binding().interface_index, Some(41));

        // A new link that does not take the uplink moves nothing.
        connector.network_changed(
            &NetworkChange::between(&network(Some(41), &[41]), &network(Some(41), &[41, 99])),
            &egress,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(guard.seen.load(Ordering::Relaxed), 1);

        // The uplink moves to the new link: so does the carrier, and the server
        // follows it to the new socket.
        connector.network_changed(
            &NetworkChange::between(&network(Some(41), &[41, 99]), &network(Some(99), &[41, 99])),
            &egress,
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while carrier.binding().interface_index != Some(42) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the carrier moves to a socket on the uplink");
        served_from_current_socket(&server, &carrier).await;
        assert!(carrier.is_open());
        assert!(Arc::ptr_eq(
            &carrier,
            &connector.client(&egress).await.unwrap()
        ));

        drop(carrier);
        drop(connector);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_stranded_carrier_waits_parked_for_an_uplink() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (address, peer, mut accepted) = serve_hysteria2_auth(1);
        let mut connector = Hysteria2Connector::new(
            address.ip().to_string(),
            address.port(),
            &json!({ "password": "test", "sni": "localhost", "skip-cert-verify": true }),
        );
        connector.config.paths = 1;
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(guard.clone()),
        );
        let carrier = connector.client(&egress).await.unwrap();
        let server = accepted.recv().await.unwrap();

        // The carrier's link goes away and no other takes over.
        guard.down.store(true, Ordering::Relaxed);
        connector.network_changed(
            &NetworkChange::between(&network(Some(41), &[41]), &network(None, &[])),
            &egress,
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while !carrier.parked.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the stranded carrier parks");
        assert!(carrier.is_open());
        assert!(
            connector.client(&egress).await.is_err(),
            "new dials do not take the parked carrier"
        );

        // A link comes up: the parked carrier moves onto it.
        guard.down.store(false, Ordering::Relaxed);
        connector.network_changed(
            &NetworkChange::between(&network(None, &[]), &network(Some(99), &[99])),
            &egress,
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while carrier.parked.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the carrier moves once there is an uplink");
        assert_eq!(carrier.binding().interface_index, Some(42));
        served_from_current_socket(&server, &carrier).await;
        assert!(Arc::ptr_eq(
            &carrier,
            &connector.client(&egress).await.unwrap()
        ));

        drop(carrier);
        drop(connector);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn runtime_compiles_hysteria2_proxy_to_outbound() {
        let mut profile = RuntimeProfile::new("hysteria2-runtime");
        profile.proxies = vec![ProxyNode {
            id: "hy2".into(),
            name: "Hy2".into(),
            protocol: ProxyProtocol::Hysteria2,
            server: Some("proxy.example.com".into()),
            port: Some(443),
            options: json!({ "password": "secret" }),
        }];
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "Hy2",
            no_resolve: false,
        }]
        .into();

        let runtime = NativeCoreRuntime::compile(&profile);
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let resolved = runtime
            .resolve_outbound("Hy2", &target)
            .expect("hysteria2 outbound resolves");

        assert!(resolved.connector.supports_tcp());
        assert!(resolved.connector.supports_udp());
    }
}
