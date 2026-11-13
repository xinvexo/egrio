use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use serde::{Deserialize, Serialize};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

pub(crate) mod dial;
mod echo;
mod failure;
mod network;
pub(crate) mod pending;
mod resolver;
pub(crate) use failure::{DialError, DialFailureKind};
pub use network::EgressNetwork;
pub(crate) use network::NetworkChange;

use crate::target::{authority, literal_socket_addr, ConnectTarget};

/// Local routing constraints that reject a target before a connector dials.
/// These do not describe the health of the selected outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressPolicyRejection {
    ScopedTargetRequiresDirect,
    UnresolvedIpv6Scope,
}

impl std::fmt::Display for EgressPolicyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ScopedTargetRequiresDirect => {
                "interface-scoped IPv6 target requires a DIRECT outbound"
            }
            Self::UnresolvedIpv6Scope => {
                "IPv6 interface scope must be normalized before local egress"
            }
        })
    }
}

impl std::error::Error for EgressPolicyRejection {}

/// OS descriptor handed to [`EgressSocketGuard`]: a raw fd on Unix, a raw
/// SOCKET on Windows.
#[cfg(unix)]
pub type EgressSocketDescriptor = std::os::fd::RawFd;
#[cfg(windows)]
pub type EgressSocketDescriptor = std::os::windows::io::RawSocket;

/// Address family of one egress socket, carried to [`EgressSocketGuard`]
/// implementations that need family-specific socket options (Windows
/// `IP_UNICAST_IF` vs `IPV6_UNICAST_IF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAddressFamily {
    Ipv4,
    Ipv6,
}

impl EgressAddressFamily {
    fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

/// What the guard knows about one egress socket at protect time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressSocketContext {
    pub family: EgressAddressFamily,
    /// The single remote the socket will talk to, when known pre-connect;
    /// `None` for multi-destination sockets (UDP NAT sessions). Guards use it
    /// to skip binding loopback-destined sockets and to pick the egress
    /// interface per destination.
    pub remote: Option<IpAddr>,
}

impl EgressSocketContext {
    pub fn for_remote(ip: IpAddr) -> Self {
        Self {
            family: EgressAddressFamily::of(ip),
            remote: Some(ip),
        }
    }

    pub fn multi_destination(family: EgressAddressFamily) -> Self {
        Self {
            family,
            remote: None,
        }
    }
}

/// Pre-connect hook over every physical egress socket the core creates.
///
/// This is the universal loop-protection contract: platform hosts that must
/// exempt egress traffic from their own capture at the socket layer see each
/// socket after creation and before connect. Windows binds the socket to the
/// physical egress interface (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) so a bound socket cannot
/// re-enter the Wintun capture routes regardless of the route table. macOS
/// binds IP_BOUND_IF / IPV6_BOUND_IF to physical interface-scoped routes;
/// Linux assigns the SO_MARK excluded by its TUN policy-routing rules.
///
/// A guard failure fails the dial: an unguarded egress socket would relay
/// captured traffic back into the capture device.
///
/// A desktop Core outlives TUN sessions: the same Core serves the system proxy
/// alone, TUN alone, or both. A guard therefore protects according to whether
/// its platform's TUN layer is active right now, and reports the egress
/// settings that hold only while it is.
pub trait EgressSocketGuard: Send + Sync + std::fmt::Debug {
    fn protect_socket(
        &self,
        descriptor: EgressSocketDescriptor,
        context: EgressSocketContext,
    ) -> Result<EgressBinding, String>;

    /// Egress settings that replace the Core's start configuration while the
    /// platform's TUN layer is active; `None` while it is not.
    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        None
    }

    /// The physical network as the platform observes it, updated on every
    /// change; the Core ends the connections a change strands. `None` from a
    /// guard that does not watch the network.
    fn network(&self) -> Option<tokio::sync::watch::Receiver<EgressNetwork>> {
        None
    }

    /// Whether the guard sends ICMP echo over the physical uplink
    /// ([`echo`](Self::echo)); the Core relays echo routed DIRECT only then.
    fn sends_echo(&self) -> bool {
        false
    }

    /// Sends one ICMP echo request carrying `payload` to `target` over the
    /// physical uplink and waits up to `wait` for its reply: from a ping
    /// socket the guard protects on macOS and Linux, through the IP Helper
    /// API on Windows once the privileged service lets it past the kill
    /// switch. Blocks; the Core calls it off its async threads.
    fn echo(
        &self,
        _target: IpAddr,
        _payload: &[u8],
        _wait: std::time::Duration,
    ) -> Result<(), String> {
        Err("this egress guard sends no ICMP echo".into())
    }

    /// Turns on receive coalescing for the UDP socket `descriptor` where the
    /// platform has it: datagrams from one sender that arrive together are
    /// then read as one buffer by [`recv_coalesced`](Self::recv_coalesced).
    /// Whether it is on; without it the Core reads one datagram at a time.
    fn coalesce_datagrams(&self, _descriptor: EgressSocketDescriptor) -> bool {
        false
    }

    /// Reads, without blocking, one datagram or the datagrams coalesced into
    /// one buffer from a socket [`coalesce_datagrams`](Self::coalesce_datagrams)
    /// turned it on for: the bytes read, their sender, and the size of each
    /// datagram but the last. `WouldBlock` when none is waiting.
    fn recv_coalesced(
        &self,
        _descriptor: EgressSocketDescriptor,
        _buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, usize)> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// Sends `payload` from the UDP socket `descriptor` to `remote` as
    /// datagrams of `segment` bytes each, the last one shorter, in one call
    /// where the platform segments UDP sends: the number of datagrams sent.
    /// `Unsupported` where it does not; the Core then sends them one by one.
    fn send_segmented(
        &self,
        _descriptor: EgressSocketDescriptor,
        _payload: &[u8],
        _segment: usize,
        _remote: SocketAddr,
    ) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Egress settings that hold only while a TUN layer is active. The TUN points
/// the system resolver at Egrio, so Core resolves its own egress through the
/// physical resolvers captured before the TUN applied its DNS; the TUN's IPv6
/// posture can also forbid IPv6 egress the profile would otherwise allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureEgressOverlay {
    pub dns_servers: Vec<SocketAddr>,
    pub ipv6_enabled: bool,
}

/// Where one physical egress socket leaves the host: the interface the guard
/// bound it to, which also names the egress in the connection row, and the
/// local address the socket got. A guard that only exempts the socket, naming
/// no interface, reports none; the dial funnel fills in the address, which a
/// network change may take away (see [`NetworkChange`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressBinding {
    pub interface_index: Option<u32>,
    /// The connected socket's source address; the unspecified address of
    /// its family for an unconnected UDP socket.
    pub local_address: Option<IpAddr>,
}

impl EgressBinding {
    /// A guard that protected the socket without binding it to a named
    /// interface.
    pub fn unbound() -> Self {
        Self::default()
    }

    /// A socket bound to physical egress interface `interface_index`.
    pub fn bound(interface_index: u32) -> Self {
        Self {
            interface_index: Some(interface_index),
            local_address: None,
        }
    }

    pub(crate) fn at(self, local: std::io::Result<SocketAddr>) -> Self {
        Self {
            local_address: local.ok().map(|address| address.ip()),
            ..self
        }
    }

    /// The egress of a connection multiplexed on a carrier that moves itself
    /// to the current uplink: the interface still names it, but no local
    /// address can strand it.
    pub(crate) fn carried(self) -> Self {
        Self {
            local_address: None,
            ..self
        }
    }
}

/// When one operation first had an address to dial: the first address any
/// of its lookups gave (`resolve_candidates`), whether from an answer that
/// came now, from a cache, or a literal. A latency test counts from there,
/// so the lookup of a node's server, which later connections take from the
/// cache, is not part of the node's latency.
#[derive(Debug, Clone, Default)]
pub(crate) struct LookupClock(Arc<std::sync::OnceLock<std::time::Instant>>);

impl LookupClock {
    fn answered(&self) {
        let _ = self.0.set(std::time::Instant::now());
    }

    /// The time since `started`, or since the first address when it came
    /// after `started`.
    pub(crate) fn elapsed_since(&self, started: std::time::Instant) -> Duration {
        self.0
            .get()
            .map_or(started, |answered| (*answered).max(started))
            .elapsed()
    }
}

/// Shared binding telemetry without retaining DNS policy, socket guards or
/// resolver caches. Only the egress socket funnel can write this record.
#[derive(Debug, Clone, Default)]
pub(crate) struct EgressBindingRecorder(Option<Arc<Mutex<EgressBinding>>>);

impl EgressBindingRecorder {
    fn enabled() -> Self {
        Self(Some(Arc::new(Mutex::new(EgressBinding::default()))))
    }

    pub(crate) fn current(&self) -> EgressBinding {
        self.0
            .as_ref()
            .map(|cell| *cell.lock().expect("egress binding recorder mutex"))
            .unwrap_or_default()
    }

    fn record(&self, binding: EgressBinding) {
        if let Some(cell) = &self.0 {
            *cell.lock().expect("egress binding recorder mutex") = binding;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeCoreEgressConfig {
    pub dns_servers: Vec<SocketAddr>,
    /// IPv6 DNS policy. When false — the default — AAAA answers are suppressed
    /// and domain resolution selects only IPv4 addresses. Numeric IPv6 targets
    /// remain dialable, including DIRECT destinations and proxy endpoints.
    #[serde(default)]
    pub ipv6_enabled: bool,
    /// Server-assembly open-proxy safety floor. When
    /// true, egress dials whose resolved destination is loopback, private,
    /// link-local, unique-local, unspecified, or multicast/broadcast are
    /// refused, so a public untrusted inbound cannot pivot into the server's
    /// own host or LAN. The server host sets it (it is built into the server
    /// assembly, not a user knob); clients leave it false — the default — and
    /// reach private targets normally. Applied at the dial funnels, so it
    /// covers literal-IP targets and DNS-rebind targets alike.
    #[serde(default)]
    pub refuse_private_destinations: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EgressRuntime {
    config: NativeCoreEgressConfig,
    socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    /// Per-dial sink for the egress binding the guard reports. `None` on the
    /// shared runtime instance; a dial clones a fresh cell via
    /// [`with_binding_recorder`](Self::with_binding_recorder) so concurrent
    /// dials never share it.
    binding_recorder: EgressBindingRecorder,
    /// The operation's lookup clock; `None` on the shared runtime instance.
    lookup_clock: Option<LookupClock>,
    resolver: Arc<resolver::Resolver>,
    dns_service: Option<Weak<crate::dns::service::DnsService>>,
    dns_context: crate::dns::service::QueryContext,
    policy: Arc<EgressPolicyLease>,
    /// The outbounds a chained node's dial goes through; weak, as the
    /// snapshot that holds them holds this.
    hops: Option<Weak<crate::outbound::Hops>>,
    /// How many hops of a chain this dial has gone through.
    hop_depth: u8,
}

#[derive(Debug)]
struct EgressPolicyLease {
    id: u64,
    cancel: CancellationToken,
    tasks: TaskTracker,
    gate: Mutex<()>,
    handshakes: dial::Handshakes,
}
impl Default for EgressPolicyLease {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            gate: Mutex::new(()),
            handshakes: dial::Handshakes::default(),
        }
    }
}

/// TCP keepalive on every egress connection: the first probe after this long
/// without traffic, then one every [`EGRESS_KEEPALIVE_INTERVAL`] until the
/// peer answers or the OS gives up. A captured client's own keepalive probes
/// end at the TUN's TCP engine, which answers them, so an idle upstream
/// connection would otherwise send nothing at all; carrier NATs drop idle
/// mappings far sooner than the two hours and four minutes RFC 5382 asks
/// (REQ-5), and a server's push into a dropped mapping is lost while the
/// client still believes the connection alive.
const EGRESS_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const EGRESS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

impl EgressRuntime {
    #[cfg(test)]
    pub(crate) fn new(config: NativeCoreEgressConfig) -> Self {
        Self::with_socket_guard(config, None)
    }

    pub(crate) fn with_socket_guard(
        config: NativeCoreEgressConfig,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    ) -> Self {
        Self {
            config,
            socket_guard,
            binding_recorder: Default::default(),
            lookup_clock: None,
            resolver: Arc::default(),
            dns_service: None,
            dns_context: Default::default(),
            policy: Arc::default(),
            hops: None,
            hop_depth: 0,
        }
    }

    pub(crate) fn with_ipv6_policy(&self, enabled: bool) -> Self {
        let mut config = self.config.clone();
        config.ipv6_enabled = enabled;
        Self {
            hops: self.hops.clone(),
            ..Self::with_socket_guard(config, self.socket_guard.clone())
        }
    }

    pub(crate) fn with_hops(&self, hops: &Arc<crate::outbound::Hops>) -> Self {
        let mut view = self.clone();
        view.hops = Some(Arc::downgrade(hops));
        view
    }

    /// The outbounds a chained node's dial goes through, while the snapshot
    /// that holds them lives.
    pub(crate) fn hops(&self) -> Option<Arc<crate::outbound::Hops>> {
        self.hops.as_ref().and_then(Weak::upgrade)
    }

    pub(crate) fn hop_depth(&self) -> u8 {
        self.hop_depth
    }

    /// This egress as a hop of a chain dials through it.
    pub(crate) fn one_hop_on(&self) -> Self {
        let mut view = self.clone();
        view.hop_depth += 1;
        view
    }

    pub(crate) fn with_dns_service(
        &self,
        service: Arc<crate::dns::service::DnsService>,
        context: crate::dns::service::QueryContext,
    ) -> Self {
        let mut view = self.clone();
        view.dns_service = Some(Arc::downgrade(&service));
        view.dns_context = context;
        view
    }

    pub(crate) fn with_dns_context(&self, context: crate::dns::service::QueryContext) -> Self {
        let mut view = self.clone();
        view.dns_context = context;
        view
    }

    pub(crate) fn physical_dns_view(&self) -> Self {
        let mut view = self.clone();
        view.dns_service = None;
        view.dns_context = Default::default();
        view.binding_recorder = Default::default();
        view.lookup_clock = None;
        view
    }

    /// A clone of this runtime whose lookups tell `clock` when the first
    /// address came.
    pub(crate) fn with_lookup_clock(&self, clock: &LookupClock) -> Self {
        let mut view = self.clone();
        view.lookup_clock = Some(clock.clone());
        view
    }

    fn dns_service(&self) -> Result<Option<Arc<crate::dns::service::DnsService>>, String> {
        match &self.dns_service {
            None => Ok(None),
            Some(service) => service
                .upgrade()
                .map(Some)
                .ok_or_else(|| "DNS service generation retired".into()),
        }
    }

    pub(crate) fn binding_recorder(&self) -> EgressBindingRecorder {
        self.binding_recorder.clone()
    }

    pub(crate) fn policy_id(&self) -> u64 {
        self.policy.id
    }

    fn handshakes(&self) -> &dial::Handshakes {
        &self.policy.handshakes
    }
    pub(crate) fn policy_cancel(&self) -> CancellationToken {
        self.policy.cancel.clone()
    }

    pub(crate) fn spawn_policy_task<F>(
        &self,
        task: F,
    ) -> Result<tokio::task::JoinHandle<()>, String>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let _gate = self.policy.gate.lock().expect("egress policy admission");
        if self.policy.cancel.is_cancelled() {
            return Err("egress policy retired".into());
        }
        Ok(self.policy.tasks.spawn(task))
    }

    pub(crate) fn retire_policy(&self) -> TaskTracker {
        let _gate = self.policy.gate.lock().expect("egress policy admission");
        self.policy.cancel.cancel();
        self.policy.tasks.close();
        self.policy.tasks.clone()
    }

    /// A clone of this runtime that records the egress binding of the next
    /// dial's physical socket into a fresh, private cell. The dial funnel reads
    /// it back with [`recorded_binding`](Self::recorded_binding) after the
    /// connector returns, then stamps the session row.
    pub(crate) fn with_binding_recorder(&self) -> Self {
        Self {
            config: self.config.clone(),
            socket_guard: self.socket_guard.clone(),
            binding_recorder: EgressBindingRecorder::enabled(),
            lookup_clock: self.lookup_clock.clone(),
            resolver: Arc::clone(&self.resolver),
            dns_service: self.dns_service.clone(),
            dns_context: self.dns_context.clone(),
            policy: self.policy.clone(),
            hops: self.hops.clone(),
            hop_depth: self.hop_depth,
        }
    }

    /// The binding the guard reported for this dial's physical egress socket,
    /// or the unbound default when no guard bound one (or none was recording).
    pub(crate) fn recorded_binding(&self) -> EgressBinding {
        self.binding_recorder.current()
    }

    pub(crate) fn socket_guard(&self) -> Option<&Arc<dyn EgressSocketGuard>> {
        self.socket_guard.as_ref()
    }

    pub(crate) fn config(&self) -> &NativeCoreEgressConfig {
        &self.config
    }

    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.socket_guard
            .as_ref()
            .and_then(|guard| guard.capture_overlay())
    }

    /// Whether a platform capture layer is active. While it is, the
    /// configuration's fake-IP pool is routed into the tunnel, and on macOS
    /// refused on the physical interfaces, so no address inside the pool can
    /// be dialled (see `DnsService::pool_claimed`).
    pub(crate) fn capture_active(&self) -> bool {
        self.capture_overlay().is_some()
    }

    /// The physical resolvers egress resolution uses: the active TUN's
    /// pre-capture resolvers, else the configured ones. Empty means the
    /// system resolver.
    pub(crate) fn dns_servers(&self) -> Vec<SocketAddr> {
        match self.capture_overlay() {
            Some(overlay) => overlay.dns_servers.clone(),
            None => self.config.dns_servers.clone(),
        }
    }

    /// The server-assembly safety floor's verdict for one resolved
    /// destination: `true` = refuse this dial. Always
    /// `false` unless the host armed `refuse_private_destinations`, so the
    /// dial funnels pay only a bool load on the common client path.
    pub(crate) fn refuses_destination(&self, ip: IpAddr) -> bool {
        self.config.refuse_private_destinations && is_forbidden_direct_destination(ip)
    }

    #[cfg(unix)]
    fn guard_egress_socket(
        &self,
        socket: &impl std::os::fd::AsRawFd,
        context: EgressSocketContext,
        socket_label: &str,
    ) -> Result<EgressBinding, String> {
        let Some(guard) = &self.socket_guard else {
            return Ok(EgressBinding::unbound());
        };
        let binding = guard
            .protect_socket(socket.as_raw_fd(), context)
            .map_err(|error| format!("egress socket guard refused {socket_label}: {error}"))?;
        Ok(binding)
    }

    #[cfg(windows)]
    fn guard_egress_socket(
        &self,
        socket: &impl std::os::windows::io::AsRawSocket,
        context: EgressSocketContext,
        socket_label: &str,
    ) -> Result<EgressBinding, String> {
        let Some(guard) = &self.socket_guard else {
            return Ok(EgressBinding::unbound());
        };
        let binding = guard
            .protect_socket(socket.as_raw_socket(), context)
            .map_err(|error| format!("egress socket guard refused {socket_label}: {error}"))?;
        Ok(binding)
    }

    /// Turns on receive coalescing for a UDP socket where the platform's
    /// guard offers it; whether it is on.
    pub(crate) fn coalesce_datagrams(&self, socket: &UdpSocket) -> bool {
        self.socket_guard
            .as_ref()
            .is_some_and(|guard| guard.coalesce_datagrams(descriptor_of(socket)))
    }

    /// One read from a socket [`Self::coalesce_datagrams`] turned coalescing
    /// on for: bytes, sender and the size of each datagram but the last.
    pub(crate) fn recv_coalesced(
        &self,
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, usize)> {
        match &self.socket_guard {
            Some(guard) => guard.recv_coalesced(descriptor_of(socket), buffer),
            None => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }

    /// Sends `payload` to `remote` as datagrams of `segment` bytes in one call
    /// where the platform's guard segments UDP sends; `Unsupported` otherwise.
    pub(crate) fn send_segmented(
        &self,
        socket: &UdpSocket,
        payload: &[u8],
        segment: usize,
        remote: SocketAddr,
    ) -> std::io::Result<usize> {
        match &self.socket_guard {
            Some(guard) => guard.send_segmented(descriptor_of(socket), payload, segment, remote),
            None => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }

    /// Stashes the guard's reported binding into the per-dial recorder, if this
    /// runtime clone is recording one. A no-op on the shared instance.
    pub(crate) fn record_binding(&self, binding: EgressBinding) {
        self.binding_recorder.record(binding);
    }

    pub(crate) fn ipv6_enabled(&self) -> bool {
        self.config.ipv6_enabled
            && self
                .capture_overlay()
                .is_none_or(|overlay| overlay.ipv6_enabled)
    }

    pub(crate) fn validate_outbound_target(
        &self,
        target: &ConnectTarget,
        is_direct: bool,
    ) -> Result<(), EgressPolicyRejection> {
        if !is_direct {
            return if target.has_ipv6_scope() {
                Err(EgressPolicyRejection::ScopedTargetRequiresDirect)
            } else {
                Ok(())
            };
        }
        if target.has_ipv6_scope() && literal_socket_addr(&target.host, target.port).is_none() {
            return Err(EgressPolicyRejection::UnresolvedIpv6Scope);
        }
        Ok(())
    }

    pub(crate) async fn connect_target_tcp(
        &self,
        target: &ConnectTarget,
    ) -> Result<TcpStream, DialError> {
        let (stream, _) = self
            .connect_tcp_host_for(
                &target.host,
                target.port,
                "upstream",
                crate::dns::service::QueryPurpose::DirectTarget,
            )
            .await?;
        Ok(stream)
    }

    /// Binds and connects a UDP socket for one relay target. Hostname targets
    /// resolve through the egress lookup path (configured egress DNS first),
    /// never through the OS connect resolver, and the local bind follows the
    /// resolved address family.
    pub(crate) async fn connect_udp_host(
        &self,
        host: &str,
        port: u16,
        socket_label: &str,
    ) -> Result<UdpSocket, DialError> {
        let remote_addr = self.udp_remote_addr_for_host(host, port).await?;
        let bind_ip: IpAddr = if remote_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|error| DialError::local(format!("failed to bind {socket_label}: {error}")))?;
        size_udp_socket_buffers(socket2::SockRef::from(&socket)).map_err(DialError::local)?;
        let binding = self
            .guard_egress_socket(
                &socket,
                EgressSocketContext::for_remote(remote_addr.ip()),
                socket_label,
            )
            .map_err(DialError::local)?;
        // Connecting a UDP socket only fixes its peer: a failure here is the
        // local stack (no route), never the remote answering.
        socket.connect(remote_addr).await.map_err(|error| {
            DialError::local(format!(
                "failed to connect UDP endpoint {}: {error}",
                authority(host, port)
            ))
        })?;
        self.record_binding(binding.at(socket.local_addr()));
        Ok(socket)
    }

    /// Dials one resolved address through an explicitly created socket so
    /// the egress socket guard sees the descriptor before connect
    /// (interface-binding and `protect()`-style hosts must exempt the socket
    /// pre-connect). Every TCP dial path funnels through here so the connect
    /// budget and the guard are universal.
    async fn connect_tcp_addr(
        &self,
        remote_addr: SocketAddr,
        connect_budget: Duration,
    ) -> Result<(TcpStream, EgressBinding), DialError> {
        // Open-proxy safety floor. This is the universal
        // TCP dial funnel, so one check here covers DIRECT targets and every
        // proxy-hop path; the flag is off for clients, so the check is a bool
        // load on their hot path.
        if self.refuses_destination(remote_addr.ip()) {
            return Err(DialError::local(format!(
                "refused private/loopback destination {} (server open-proxy safety floor)",
                remote_addr.ip()
            )));
        }
        self.connect_tcp_endpoint(remote_addr, connect_budget).await
    }

    // Physical TCP primitive shared by application dials and configured DNS.
    // The latter is trusted resolver infrastructure, not an untrusted target
    // subject to the server assembly's private-destination policy.
    pub(crate) async fn connect_tcp_endpoint(
        &self,
        remote_addr: SocketAddr,
        connect_budget: Duration,
    ) -> Result<(TcpStream, EgressBinding), DialError> {
        let socket = if remote_addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|error| DialError::local(format!("failed to create TCP socket: {error}")))?;
        // Before the SYN: the window scale it offers follows the buffer.
        // Best effort, like the options set once it connects.
        if let Some(size) = tcp_receive_buffer() {
            let _ = socket.set_recv_buffer_size(size);
        }
        let binding = self
            .guard_egress_socket(
                &socket,
                EgressSocketContext::for_remote(remote_addr.ip()),
                "egress TCP socket",
            )
            .map_err(DialError::local)?;
        // Bounded connect: every pipeline step has a budget.
        // Without it a black-holed address holds the session task for the
        // OS retry timeout and
        // a burst of such dials piles every relay up in the Dialing phase.
        // The caller carries the address context, so the error stays bare.
        let stream = timeout(connect_budget, socket.connect(remote_addr))
            .await
            .map_err(|_| {
                DialError::connect(format!(
                    "connect timed out after {:.1}s",
                    connect_budget.as_secs_f64()
                ))
            })?
            .map_err(|error| DialError::connect(error.to_string()))?;
        // Disable Nagle on every egress socket, as on the inbound side. The
        // relay carries small, latency-sensitive
        // control frames — an HTTP/2 WINDOW_UPDATE during an upload, a TLS
        // record boundary — and Nagle coalescing them against the peer's
        // delayed ACK stalls the flow for up to 200 ms per round, which
        // collapses upload throughput. Best effort: a socket that refuses the
        // option still relays.
        let _ = stream.set_nodelay(true);
        // Best effort too: a socket that refuses keepalive still relays.
        let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(EGRESS_KEEPALIVE_IDLE)
                .with_interval(EGRESS_KEEPALIVE_INTERVAL),
        );
        let binding = binding.at(stream.local_addr());
        Ok((stream, binding))
    }

    /// Resolves `host:port` to one UDP-reachable address for a single-socket
    /// UDP relay, so the bound socket and the remote address never disagree
    /// on address family.
    pub(crate) async fn udp_remote_addr_for_host(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, DialError> {
        let remote_addr = self
            .lookup_host(host, port)
            .await
            .map_err(DialError::resolve)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                DialError::resolve(format!(
                    "no addresses resolved for {}",
                    authority(host, port)
                ))
            })?;
        self.check_udp_remote(remote_addr)?;
        Ok(remote_addr)
    }

    /// The open-proxy safety floor for one resolved UDP remote, checked by
    /// every UDP-based outbound: the relay funnel above and each Hysteria2
    /// QUIC candidate.
    pub(crate) fn check_udp_remote(&self, remote: SocketAddr) -> Result<(), DialError> {
        if self.refuses_destination(remote.ip()) {
            return Err(DialError::local(format!(
                "refused private/loopback UDP destination {} (server open-proxy safety floor)",
                remote.ip()
            )));
        }
        Ok(())
    }

    pub(crate) async fn udp_direct_addr_for_target(
        &self,
        target: &ConnectTarget,
    ) -> Result<SocketAddr, String> {
        self.validate_outbound_target(target, true)
            .map_err(|error| error.to_string())?;
        let address = if let Some(address) = literal_socket_addr(&target.host, target.port) {
            address
        } else if let Some(service) = self.dns_service()? {
            let resolved = service
                .resolve_target(
                    target,
                    crate::dns::service::QueryPurpose::DirectTarget,
                    self.dns_context.clone(),
                )
                .await?;
            literal_socket_addr(&resolved.host, resolved.port)
                .ok_or("DNS did not produce a numeric UDP address")?
        } else {
            self.udp_remote_addr_for_host(&target.host, target.port)
                .await
                .map_err(|error| error.to_string())?
        };
        if self.refuses_destination(address.ip()) {
            return Err(
                "refused private/loopback UDP destination (server open-proxy safety floor)".into(),
            );
        }
        Ok(address)
    }

    pub(crate) async fn bind_udp_for_host(
        &self,
        host: &str,
        socket_label: &str,
    ) -> Result<UdpSocket, DialError> {
        self.validate_outbound_target(
            &ConnectTarget {
                host: host.into(),
                port: 0,
            },
            true,
        )
        .map_err(|reason| DialError::local(format!("UDP target {host} rejected: {reason}")))?;
        let target_ip = literal_socket_addr(host, 0).map(|address| address.ip());
        let bind_ip = default_udp_bind_ip_for_host(host);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|error| DialError::local(format!("failed to bind {socket_label}: {error}")))?;
        size_udp_socket_buffers(socket2::SockRef::from(&socket)).map_err(DialError::local)?;
        let context = match target_ip {
            Some(ip) => EgressSocketContext::for_remote(ip),
            None => EgressSocketContext::multi_destination(if bind_ip.is_ipv6() {
                EgressAddressFamily::Ipv6
            } else {
                EgressAddressFamily::Ipv4
            }),
        };
        let binding = self
            .guard_egress_socket(&socket, context, socket_label)
            .map_err(DialError::local)?;
        self.record_binding(binding.at(socket.local_addr()));
        Ok(socket)
    }

    pub(crate) async fn bind_udp_for_family(
        &self,
        family: EgressAddressFamily,
        socket_label: &str,
    ) -> Result<UdpSocket, DialError> {
        let bind_ip = match family {
            EgressAddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            EgressAddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|error| DialError::local(format!("failed to bind {socket_label}: {error}")))?;
        size_udp_socket_buffers(socket2::SockRef::from(&socket)).map_err(DialError::local)?;
        let binding = self
            .guard_egress_socket(
                &socket,
                EgressSocketContext::multi_destination(family),
                socket_label,
            )
            .map_err(DialError::local)?;
        self.record_binding(binding.at(socket.local_addr()));
        Ok(socket)
    }
}

#[cfg(unix)]
fn descriptor_of(socket: &UdpSocket) -> EgressSocketDescriptor {
    std::os::fd::AsRawFd::as_raw_fd(socket)
}

#[cfg(windows)]
fn descriptor_of(socket: &UdpSocket) -> EgressSocketDescriptor {
    std::os::windows::io::AsRawSocket::as_raw_socket(socket)
}

/// The receive and send buffer a UDP socket asks for. Datagrams that arrive
/// while the task draining a socket is not running wait in its receive
/// buffer, and the kernel drops whatever of a burst does not fit; QUIC takes
/// such a drop for congestion and slows down. Windows gives a UDP socket
/// 64 KiB, under a millisecond of a fast QUIC download, while Wi-Fi hands
/// frames over in bursts; 8 MiB holds about 60 ms at 1 Gbit/s.
///
/// This is a high-water mark, not a reservation: only the datagrams actually
/// waiting take memory, so the size does not multiply by the sockets the
/// Core holds. A burst beyond the kernel's own pool can still drop
/// datagrams, which a UDP peer must handle.
pub(crate) const UDP_SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// The smallest size [`size_udp_socket_buffers`] retries with after the host
/// refuses a larger one.
const UDP_SOCKET_BUFFER_FLOOR: usize = 1024 * 1024;

/// The size the host accepted for a UDP receive and send buffer, 0 until a
/// socket learns it, and whether a send buffer of that size was seen to hold
/// the largest datagram. A new socket asks for the accepted size at once,
/// avoiding repeated negotiation with the host's limits.
static ACCEPTED_RECV_BUFFER: AtomicUsize = AtomicUsize::new(0);
static ACCEPTED_SEND_BUFFER: AtomicUsize = AtomicUsize::new(0);
static SEND_BUFFER_HOLDS_DATAGRAM: AtomicBool = AtomicBool::new(false);

/// Grows one UDP socket's buffers toward [`UDP_SOCKET_BUFFER_BYTES`]. A size
/// the host refuses is halved down to 1 MiB (macOS refuses a buffer above
/// `kern.ipc.maxsockbuf`), Linux caps it at `net.core.rmem_max` and
/// `wmem_max` without an error, and a larger buffer the host already gives is
/// kept. Only this socket changes, never a system setting. A send buffer that
/// cannot hold the largest datagram fails the socket.
pub(crate) fn size_udp_socket_buffers(socket: socket2::SockRef<'_>) -> Result<(), String> {
    grow_socket_buffer(
        &ACCEPTED_RECV_BUFFER,
        || socket.recv_buffer_size(),
        |size| socket.set_recv_buffer_size(size),
    );
    let reused = grow_socket_buffer(
        &ACCEPTED_SEND_BUFFER,
        || socket.send_buffer_size(),
        |size| socket.set_send_buffer_size(size),
    );
    if reused && SEND_BUFFER_HOLDS_DATAGRAM.load(Ordering::Relaxed) {
        return Ok(());
    }
    let minimum = crate::outbound::UDP_DATAGRAM_CAPACITY;
    let send = socket
        .send_buffer_size()
        .map_err(|error| format!("failed to read UDP send buffer: {error}"))?;
    if send < minimum {
        SEND_BUFFER_HOLDS_DATAGRAM.store(false, Ordering::Relaxed);
        socket
            .set_send_buffer_size(minimum)
            .map_err(|error| format!("failed to size UDP send buffer: {error}"))?;
    } else if reused || ACCEPTED_SEND_BUFFER.load(Ordering::Relaxed) != 0 {
        SEND_BUFFER_HOLDS_DATAGRAM.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Sets the size `accepted` holds when there is one; otherwise grows the
/// buffer as [`size_udp_socket_buffers`] says and records the size the host
/// takes. Whether the known size was set.
fn grow_socket_buffer(
    accepted: &AtomicUsize,
    current: impl Fn() -> std::io::Result<usize>,
    set: impl Fn(usize) -> std::io::Result<()>,
) -> bool {
    let known = accepted.load(Ordering::Relaxed);
    if known != 0 && set(known).is_ok() {
        return true;
    }
    if current().is_ok_and(|size| size >= UDP_SOCKET_BUFFER_BYTES) {
        return false;
    }
    let mut size = UDP_SOCKET_BUFFER_BYTES;
    while size >= UDP_SOCKET_BUFFER_FLOOR {
        if set(size).is_ok() {
            accepted.store(size, Ordering::Relaxed);
            return false;
        }
        size /= 2;
    }
    false
}

/// Target for a physical TCP connection's receive buffer, covering the
/// path's bandwidth-delay product up to the host's buffer limits.
const TCP_RECEIVE_BUFFER_TARGET: usize = 32 * 1024 * 1024;

/// How large a host lets a TCP receive buffer grow: by its own tuning, and
/// when a socket fixes the size itself before it connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpReceiveLimits {
    tuned: usize,
    fixed: usize,
}

/// The receive buffer every physical TCP socket fixes before it connects:
/// where the host lets a socket hold more than its own tuning grows to, the
/// most it allows up to [`TCP_RECEIVE_BUFFER_TARGET`]; elsewhere `None`, and
/// the host tunes the buffer itself. Fixing a buffer turns the host's tuning
/// off for that socket, so a fixed size smaller than the tuned one would
/// only lose. Read from the host once.
///
/// macOS compares `net.inet.tcp.autorcvbufmax` with `kern.ipc.maxsockbuf`;
/// Linux compares `tcp_rmem[2]` with the fixed-buffer limit derived from
/// `net.core.rmem_max`. Values come from the running host rather than
/// assumed defaults. Windows keeps its own tuning because no limits are
/// read there. Send-buffer sizing stays with the host's tuning.
fn tcp_receive_buffer() -> Option<u32> {
    static SIZE: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        receive_buffer_for(host_tcp_receive_limits()?).and_then(|size| u32::try_from(size).ok())
    })
}

/// What [`tcp_receive_buffer`] fixes for `limits`.
fn receive_buffer_for(limits: TcpReceiveLimits) -> Option<usize> {
    let fixed = limits.fixed.min(TCP_RECEIVE_BUFFER_TARGET);
    (fixed > limits.tuned).then_some(fixed)
}

/// XNU: a set `SO_RCVBUF` clears the socket's `SB_AUTOSIZE`
/// (`sosetoptlock`, bsd/kern/uipc_socket.c), `sbreserve`
/// (bsd/kern/uipc_socket2.c) grants it up to `sb_max`, the
/// `kern.ipc.maxsockbuf` sysctl, and `tcp_get_max_rwinscale`
/// (bsd/netinet/tcp_subr.c) offers the window scale for the size set when
/// the socket connects, for `net.inet.tcp.autorcvbufmax` when none was set.
#[cfg(target_os = "macos")]
fn host_tcp_receive_limits() -> Option<TcpReceiveLimits> {
    fn sysctl(name: &std::ffi::CStr) -> Option<usize> {
        let mut value = 0u64;
        let mut size = std::mem::size_of_val(&value);
        let read = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::from_mut(&mut value).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        // Little-endian: a 4-byte value fills the low half.
        (read == 0 && (size == 4 || size == 8)).then(|| {
            usize::try_from(if size == 4 {
                value & 0xffff_ffff
            } else {
                value
            })
            .unwrap_or(usize::MAX)
        })
    }
    let tuned = if sysctl(c"net.inet.tcp.doautorcvbuf")? != 0 {
        sysctl(c"net.inet.tcp.autorcvbufmax")?
    } else {
        sysctl(c"net.inet.tcp.recvspace")?
    };
    Some(TcpReceiveLimits {
        tuned,
        fixed: sysctl(c"kern.ipc.maxsockbuf")?,
    })
}

/// Linux: `sk_setsockopt` (net/core/sock.c) caps `SO_RCVBUF` at
/// `net.core.rmem_max` and `__sock_set_rcvbuf` doubles it for the kernel's
/// overhead and locks it, which `tcp_rcvbuf_grow` (net/ipv4/tcp_input.c)
/// then leaves alone; its tuning grows to `tcp_rmem[2]` while
/// `tcp_moderate_rcvbuf` is on, see `tcp(7)`.
#[cfg(target_os = "linux")]
fn host_tcp_receive_limits() -> Option<TcpReceiveLimits> {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let rmem: Vec<usize> = read("/proc/sys/net/ipv4/tcp_rmem")?
        .split_whitespace()
        .filter_map(|field| field.parse().ok())
        .collect();
    let tuning = read("/proc/sys/net/ipv4/tcp_moderate_rcvbuf").is_none_or(|on| on.trim() != "0");
    let rmem_max: usize = read("/proc/sys/net/core/rmem_max")?.trim().parse().ok()?;
    Some(TcpReceiveLimits {
        tuned: *rmem.get(if tuning { 2 } else { 1 })?,
        fixed: rmem_max.saturating_mul(2),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_tcp_receive_limits() -> Option<TcpReceiveLimits> {
    None
}

fn default_udp_bind_ip_for_host(host: &str) -> IpAddr {
    if literal_socket_addr(host, 0).is_some_and(|address| address.is_ipv6()) {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

/// The server-assembly open-proxy safety floor's forbidden set: destinations
/// an untrusted public inbound must never reach
/// through DIRECT, because dialing them pivots into the server's own host or
/// LAN. Deliberately conservative — loopback, RFC1918 private, link-local,
/// CGNAT shared space, IPv6 unique-local/link-local, unspecified, and
/// multicast/broadcast — and it unwraps IPv4-mapped IPv6 so `::ffff:127.0.0.1`
/// cannot slip a loopback dial past the v6 arm.
///
/// Public because the same question — "would dialing this address pivot into
/// the host or its LAN?" — is asked by hosts fetching caller-supplied URLs
/// (subscriptions, rule providers). One definition, not a second copy that
/// drifts.
pub fn is_forbidden_direct_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // Shared address space / CGNAT, 100.64.0.0/10 (RFC 6598).
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_direct_destination(IpAddr::V4(mapped));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7 (RFC 4193).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10 (RFC 4291).
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn ipv6_policy_has_fresh_cache_and_retirement_tracks_carriers() {
        let old = super::EgressRuntime::new(super::NativeCoreEgressConfig::default());
        let next = old.with_ipv6_policy(true);
        assert!(!Arc::ptr_eq(&old.resolver, &next.resolver));
        assert!(Arc::ptr_eq(
            &old.resolver,
            &old.with_binding_recorder().resolver
        ));
        assert_ne!(old.policy_id(), next.policy_id());
        assert_eq!(old.policy_id(), old.with_binding_recorder().policy_id());
        let cancel = old.policy_cancel();
        let (signal, wait) = tokio::sync::oneshot::channel();
        old.spawn_policy_task(async move {
            cancel.cancelled().await;
            let _ = wait.await;
        })
        .unwrap();
        let retired = old.retire_policy();
        assert!(old.policy_cancel().is_cancelled());
        assert!(!next.policy_cancel().is_cancelled());
        assert!(!retired.is_empty());
        assert!(old.spawn_policy_task(async {}).is_err());
        signal.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), retired.wait())
            .await
            .unwrap();
    }
    use super::*;
    use resolver::{DNS_CLASS_IN, DNS_TYPE_A};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn egress_udp_sockets_get_buffers_for_bursts() {
        let egress = EgressRuntime::new(NativeCoreEgressConfig::default());
        let socket = egress
            .bind_udp_for_family(EgressAddressFamily::Ipv4, "test UDP socket")
            .await
            .unwrap();
        let socket = socket2::SockRef::from(&socket);
        // Hosts cap the size differently; every one of them gives more than
        // the 64 KiB a Windows UDP socket starts with.
        assert!(socket.recv_buffer_size().unwrap() > 64 * 1024);
        assert!(socket.send_buffer_size().unwrap() > 64 * 1024);
    }

    #[test]
    fn a_tcp_receive_buffer_is_fixed_only_where_that_reaches_past_the_hosts_tuning() {
        const MIB: usize = 1024 * 1024;
        let limits = |tuned, fixed| TcpReceiveLimits { tuned, fixed };
        // macOS's defaults: tuning stops at 4 MiB, a socket may fix 8 MiB.
        assert_eq!(receive_buffer_for(limits(4 * MIB, 8 * MIB)), Some(8 * MIB));
        // Linux's: tuning reaches 6 or 32 MiB, a fixed buffer 2 x 208 KiB.
        assert_eq!(receive_buffer_for(limits(6 * MIB, 2 * 212_992)), None);
        assert_eq!(receive_buffer_for(limits(32 * MIB, 2 * 212_992)), None);
        // A host that lets a socket fix more gives it the target, no more,
        // and never less than its own tuning would.
        assert_eq!(
            receive_buffer_for(limits(4 * MIB, 64 * MIB)),
            Some(32 * MIB)
        );
        assert_eq!(receive_buffer_for(limits(64 * MIB, 128 * MIB)), None);
        assert_eq!(receive_buffer_for(limits(32 * MIB, 32 * MIB)), None);
    }

    #[tokio::test]
    async fn a_dialed_tcp_socket_takes_the_receive_buffer_before_it_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let egress = EgressRuntime::new(NativeCoreEgressConfig::default());
        let (stream, _) = egress
            .connect_tcp_endpoint(
                listener.local_addr().unwrap(),
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();
        let Some(fixed) = tcp_receive_buffer() else {
            // The host tunes the buffer itself.
            return;
        };
        let socket = socket2::SockRef::from(&stream);
        assert!(socket.recv_buffer_size().unwrap() >= fixed as usize);
        // The SYN offered the scale the fixed size needs, not the one for
        // the 4 MiB macOS tunes to (6): 65535 << 7 covers 8 MiB.
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of_val(&info) as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        libc::TCP_CONNECTION_INFO,
                        std::ptr::from_mut(&mut info).cast(),
                        &mut size,
                    )
                },
                0
            );
            assert!(
                (usize::from(u16::MAX) + 1) << info.tcpi_rcv_wscale >= fixed as usize,
                "window scale {} for a {fixed}-byte buffer",
                info.tcpi_rcv_wscale
            );
        }
    }

    #[test]
    fn a_refused_buffer_size_is_halved_and_a_larger_one_kept() {
        let size = std::cell::Cell::new(64 * 1024);
        let tried = std::cell::RefCell::new(Vec::new());
        let set = |requested: usize| {
            tried.borrow_mut().push(requested);
            if requested > 2 * 1024 * 1024 {
                return Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory));
            }
            size.set(requested);
            Ok(())
        };
        let accepted = AtomicUsize::new(0);
        assert!(!grow_socket_buffer(&accepted, || Ok(size.get()), set));
        assert_eq!(size.get(), 2 * 1024 * 1024);
        assert_eq!(*tried.borrow(), [8 << 20, 4 << 20, 2 << 20]);

        tried.borrow_mut().clear();
        size.set(64 * 1024);
        assert!(grow_socket_buffer(&accepted, || panic!("not read"), set));
        assert_eq!(
            *tried.borrow(),
            [2 << 20],
            "the next socket asks for what was taken"
        );

        tried.borrow_mut().clear();
        size.set(16 * 1024 * 1024);
        assert!(!grow_socket_buffer(
            &AtomicUsize::new(0),
            || Ok(size.get()),
            set
        ));
        assert!(tried.borrow().is_empty(), "a larger buffer is never shrunk");

        tried.borrow_mut().clear();
        size.set(64 * 1024);
        let accepted = AtomicUsize::new(0);
        grow_socket_buffer(
            &accepted,
            || Ok(size.get()),
            |requested| {
                tried.borrow_mut().push(requested);
                Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory))
            },
        );
        assert_eq!(size.get(), 64 * 1024, "the default stays when nothing fits");
        assert_eq!(*tried.borrow(), [8 << 20, 4 << 20, 2 << 20, 1 << 20]);
        assert_eq!(accepted.load(Ordering::Relaxed), 0);
    }

    /// A guard whose TUN layer is switched by the test.
    #[derive(Debug, Default)]
    struct SwitchedTunGuard(std::sync::Mutex<Option<Arc<CaptureEgressOverlay>>>);

    impl EgressSocketGuard for SwitchedTunGuard {
        fn protect_socket(
            &self,
            _: EgressSocketDescriptor,
            _: EgressSocketContext,
        ) -> Result<EgressBinding, String> {
            Ok(EgressBinding::unbound())
        }

        fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
            self.0.lock().unwrap().clone()
        }
    }

    #[test]
    fn tun_overlay_replaces_resolvers_and_can_only_narrow_ipv6() {
        let configured: SocketAddr = "203.0.113.53:53".parse().unwrap();
        let physical: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let guard = Arc::new(SwitchedTunGuard::default());
        for (profile_ipv6, tun_ipv6, expected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let egress = EgressRuntime::with_socket_guard(
                NativeCoreEgressConfig {
                    dns_servers: vec![configured],
                    ipv6_enabled: profile_ipv6,
                    refuse_private_destinations: false,
                },
                Some(guard.clone()),
            );
            *guard.0.lock().unwrap() = None;
            assert_eq!(egress.dns_servers(), vec![configured]);
            assert_eq!(egress.ipv6_enabled(), profile_ipv6);

            *guard.0.lock().unwrap() = Some(Arc::new(CaptureEgressOverlay {
                dns_servers: vec![physical],
                ipv6_enabled: tun_ipv6,
            }));
            assert_eq!(egress.dns_servers(), vec![physical]);
            assert_eq!(egress.ipv6_enabled(), expected);
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSocketGuard {
        seen: std::sync::Mutex<Vec<(EgressSocketDescriptor, EgressSocketContext)>>,
        refuse: bool,
        binding: EgressBinding,
    }

    impl RecordingSocketGuard {
        fn refusing() -> Self {
            Self {
                refuse: true,
                ..Self::default()
            }
        }

        fn binding_to(interface_index: u32) -> Self {
            Self {
                binding: EgressBinding::bound(interface_index),
                ..Self::default()
            }
        }

        fn seen(&self) -> Vec<(EgressSocketDescriptor, EgressSocketContext)> {
            self.seen.lock().expect("guard log").clone()
        }
    }

    impl EgressSocketGuard for RecordingSocketGuard {
        fn protect_socket(
            &self,
            descriptor: EgressSocketDescriptor,
            context: EgressSocketContext,
        ) -> Result<EgressBinding, String> {
            if self.refuse {
                return Err("guard refused for test".into());
            }
            self.seen
                .lock()
                .expect("guard log")
                .push((descriptor, context));
            Ok(self.binding)
        }
    }

    #[tokio::test]
    async fn a_guarded_dial_records_the_egress_interface_binding() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let guard = Arc::new(RecordingSocketGuard::binding_to(42));
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(Arc::clone(&guard) as Arc<dyn EgressSocketGuard>),
        )
        .with_binding_recorder();

        let _stream = egress
            .connect_tcp_host("127.0.0.1", listener_addr.port(), "recorder target")
            .await
            .expect("guarded dial succeeds");

        // The dial funnel reads this back and stamps the session with the
        // interface the guard bound and the address the socket got.
        assert_eq!(
            egress.recorded_binding(),
            EgressBinding {
                interface_index: Some(42),
                local_address: Some(Ipv4Addr::LOCALHOST.into()),
            }
        );
        accept.await.expect("accept join").expect("accept ok");
    }

    #[tokio::test]
    async fn socket_guard_sees_tcp_egress_descriptor_and_remote_before_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(Arc::clone(&guard) as Arc<dyn EgressSocketGuard>),
        );

        let _stream = egress
            .connect_tcp_host("127.0.0.1", listener_addr.port(), "guarded target")
            .await
            .expect("guarded connect succeeds");

        let seen = guard.seen();
        assert_eq!(seen.len(), 1, "one dial, one guarded descriptor");
        assert_eq!(
            seen[0].1,
            EgressSocketContext {
                family: EgressAddressFamily::Ipv4,
                remote: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            },
            "the guard must see the dial's remote and family"
        );
        accept.await.expect("accept task").expect("accept");
    }

    #[tokio::test]
    async fn egress_tcp_streams_disable_nagle_and_keep_alive() {
        // Nagle on an egress socket delays the small, latency-sensitive control
        // frames the relay carries (e.g. an HTTP/2 WINDOW_UPDATE), which stalls
        // uploads; every egress dial must disable it, and keep the connection
        // alive through NATs while it idles.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let egress = EgressRuntime::new(NativeCoreEgressConfig::default());

        let stream = egress
            .connect_tcp_host("127.0.0.1", listener_addr.port(), "nodelay target")
            .await
            .expect("connect succeeds");

        assert!(
            stream.nodelay().expect("read TCP_NODELAY"),
            "egress TCP stream must disable Nagle (TCP_NODELAY)"
        );
        assert!(
            socket2::SockRef::from(&stream)
                .keepalive()
                .expect("read SO_KEEPALIVE"),
            "egress TCP stream must keep itself alive (SO_KEEPALIVE)"
        );
        accept.await.expect("accept task").expect("accept");
    }

    #[tokio::test]
    async fn socket_guard_sees_udp_egress_descriptor() {
        let target = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp target");
        let target_addr = target.local_addr().expect("target addr");
        let guard = Arc::new(RecordingSocketGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(Arc::clone(&guard) as Arc<dyn EgressSocketGuard>),
        );

        let _socket = egress
            .connect_udp_host("127.0.0.1", target_addr.port(), "guarded UDP socket")
            .await
            .expect("guarded UDP connect succeeds");

        assert_eq!(guard.seen().len(), 1);
    }

    #[tokio::test]
    async fn refusing_socket_guard_fails_the_dial() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(Arc::new(RecordingSocketGuard::refusing()) as Arc<dyn EgressSocketGuard>),
        );

        let error = egress
            .connect_tcp_host("127.0.0.1", listener_addr.port(), "guarded target")
            .await
            .expect_err("refused guard must fail the dial");

        assert_eq!(error.kind, DialFailureKind::Local, "{error}");
        assert!(
            error.message.contains("egress socket guard refused"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn forbidden_direct_destination_covers_loopback_private_and_v6_bypass() {
        for forbidden in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                is_forbidden_direct_destination(forbidden.parse().expect("ip")),
                "{forbidden} should be forbidden"
            );
        }
        for allowed in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2606:4700::1111"] {
            assert!(
                !is_forbidden_direct_destination(allowed.parse().expect("ip")),
                "{allowed} should be allowed"
            );
        }
    }

    #[tokio::test]
    async fn safety_floor_refuses_direct_tcp_dial_to_loopback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            refuse_private_destinations: true,
            ..NativeCoreEgressConfig::default()
        });

        let error = egress
            .connect_target_tcp(&ConnectTarget {
                host: "127.0.0.1".into(),
                port: listener_addr.port(),
            })
            .await
            .expect_err("safety floor must refuse the loopback dial");

        assert_eq!(error.kind, DialFailureKind::Local, "{error}");
        assert!(
            error.message.contains("open-proxy safety floor"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn safety_floor_off_allows_the_same_direct_dial() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        // Default config leaves the floor off, so a client reaches loopback.
        let egress = EgressRuntime::new(NativeCoreEgressConfig::default());

        let _stream = egress
            .connect_target_tcp(&ConnectTarget {
                host: "127.0.0.1".into(),
                port: listener_addr.port(),
            })
            .await
            .expect("client dial to loopback succeeds with the floor off");

        accept.await.expect("accept task").expect("accept");
    }

    #[tokio::test]
    async fn safety_floor_refuses_direct_udp_dial_to_loopback() {
        let target = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp target");
        let target_addr = target.local_addr().expect("target addr");
        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            refuse_private_destinations: true,
            ..NativeCoreEgressConfig::default()
        });

        let error = egress
            .connect_udp_host("127.0.0.1", target_addr.port(), "guarded UDP socket")
            .await
            .expect_err("safety floor must refuse the loopback UDP dial");

        assert_eq!(error.kind, DialFailureKind::Local, "{error}");
        assert!(
            error.message.contains("open-proxy safety floor"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn udp_numeric_ipv6_scope_is_preserved_without_dns_resolution() {
        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            ipv6_enabled: true,
            dns_servers: vec!["127.0.0.1:1".parse().unwrap()],
            ..Default::default()
        });
        assert!(default_udp_bind_ip_for_host("fe80::1234%7").is_ipv6());
        let remote = egress
            .udp_remote_addr_for_host("fe80::1234%7", 4242)
            .await
            .unwrap();
        assert_eq!(remote, "[fe80::1234%7]:4242".parse::<SocketAddr>().unwrap());
        assert_eq!(authority("fe80::1234%7", 4242), "[fe80::1234%7]:4242");
    }

    #[test]
    fn default_udp_bind_ip_uses_ipv6_socket_for_ipv6_literal() {
        assert!(default_udp_bind_ip_for_host("2001:db8::1").is_ipv6());
    }

    #[test]
    fn default_udp_bind_ip_uses_ipv4_socket_for_domain_or_ipv4_literal() {
        assert!(default_udp_bind_ip_for_host("proxy.example.com").is_ipv4());
        assert!(default_udp_bind_ip_for_host("203.0.113.8").is_ipv4());
    }

    #[tokio::test]
    async fn bind_udp_uses_ipv6_socket_for_literal_regardless_of_dns_ipv6_policy() {
        for ipv6_enabled in [false, true] {
            let egress = EgressRuntime::new(NativeCoreEgressConfig {
                ipv6_enabled,
                ..Default::default()
            });
            let socket = egress
                .bind_udp_for_host("2001:db8::1", "test UDP socket")
                .await
                .expect("IPv6 target binds an IPv6 socket");
            assert!(socket.local_addr().unwrap().is_ipv6());
        }
    }

    #[tokio::test]
    async fn configured_dns_server_resolves_without_system_lookup() {
        let dns_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS server");
        let dns_server_addr = dns_server.local_addr().expect("DNS server addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut query = [0_u8; 512];
                let (len, peer) = dns_server.recv_from(&mut query).await.expect("DNS query");
                let response = dns_a_response(&query[..len], Ipv4Addr::new(127, 0, 0, 42));
                dns_server
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS response");
            }
        });

        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![dns_server_addr],
            ipv6_enabled: true,
            ..NativeCoreEgressConfig::default()
        });
        let addresses = egress
            .lookup_host("example.com", 443)
            .await
            .expect("configured DNS resolves");
        server.await.expect("DNS server task");

        assert!(addresses.contains(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42)),
            443
        )));
    }

    #[tokio::test]
    async fn connect_udp_host_resolves_hostname_via_configured_dns() {
        let dns_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS server");
        let dns_server_addr = dns_server.local_addr().expect("DNS server addr");
        let dns_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut query = [0_u8; 512];
                let (len, peer) = dns_server.recv_from(&mut query).await.expect("DNS query");
                let response = dns_a_response(&query[..len], Ipv4Addr::LOCALHOST);
                dns_server
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS response");
            }
        });
        let echo_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP echo server");
        let echo_addr = echo_server.local_addr().expect("echo addr");
        let echo_task = tokio::spawn(async move {
            let mut datagram = [0_u8; 64];
            let (len, peer) = echo_server
                .recv_from(&mut datagram)
                .await
                .expect("echo request");
            echo_server
                .send_to(&datagram[..len], peer)
                .await
                .expect("echo response");
        });

        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![dns_server_addr],
            ipv6_enabled: true,
            ..NativeCoreEgressConfig::default()
        });
        let socket = egress
            .connect_udp_host("udp-relay.example.com", echo_addr.port(), "test UDP relay")
            .await
            .expect("hostname UDP target connects via configured DNS");
        socket.send(b"via-egress-dns").await.expect("send datagram");
        let mut response = [0_u8; 64];
        let received = socket.recv(&mut response).await.expect("recv echo");

        assert_eq!(&response[..received], b"via-egress-dns");
        dns_task.await.expect("DNS server task");
        echo_task.await.expect("echo server task");
    }

    #[tokio::test]
    async fn tcp_connect_resolves_hostname_via_configured_dns() {
        let dns_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS server");
        let dns_server_addr = dns_server.local_addr().expect("DNS server addr");
        let dns_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut query = [0_u8; 512];
                let (len, peer) = dns_server.recv_from(&mut query).await.expect("DNS query");
                let response = dns_a_response(&query[..len], Ipv4Addr::LOCALHOST);
                dns_server
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS response");
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move {
            let (_stream, peer_addr) = listener.accept().await.expect("accept");
            peer_addr.ip()
        });

        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![dns_server_addr],
            ipv6_enabled: true,
            ..NativeCoreEgressConfig::default()
        });
        let _stream = egress
            .connect_tcp_host("tcp-upstream.example.com", listener_addr.port(), "upstream")
            .await
            .expect("hostname TCP target connects via configured DNS");

        assert_eq!(
            accept.await.expect("accept task"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        dns_task.await.expect("DNS server task");
    }

    #[tokio::test]
    async fn named_ipv6_scope_is_rejected_before_dns_or_socket_creation() {
        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec!["127.0.0.1:1".parse().unwrap()],
            ..Default::default()
        });
        for error in [
            egress
                .lookup_host("fe80::1%test-interface", 443)
                .await
                .unwrap_err(),
            egress
                .bind_udp_for_host("fe80::1%test-interface", "test UDP socket")
                .await
                .unwrap_err()
                .to_string(),
        ] {
            assert!(
                error.contains("interface scope must be normalized"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn lookup_host_returns_ipv6_literal_regardless_of_dns_ipv6_policy() {
        for ipv6_enabled in [false, true] {
            let egress = EgressRuntime::new(NativeCoreEgressConfig {
                ipv6_enabled,
                dns_servers: vec!["127.0.0.1:1".parse().unwrap()],
                ..Default::default()
            });
            let addresses = egress
                .lookup_host("2001:db8::1", 443)
                .await
                .expect("IPv6 literal resolves to itself without DNS");
            assert_eq!(addresses, vec!["[2001:db8::1]:443".parse().unwrap()]);
        }
    }

    #[tokio::test]
    async fn tcp_connect_dials_ipv6_literal_regardless_of_dns_ipv6_policy() {
        for ipv6_enabled in [false, true] {
            let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let egress = EgressRuntime::new(NativeCoreEgressConfig {
                ipv6_enabled,
                ..Default::default()
            });
            let stream = egress
                .connect_tcp_host("::1", listener_addr.port(), "test target")
                .await
                .expect("numeric IPv6 remains dialable");
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, stream.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn configured_dns_skips_aaaa_query_when_ipv6_disabled() {
        let dns_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS server");
        let dns_server_addr = dns_server.local_addr().expect("DNS server addr");
        let server = tokio::spawn(async move {
            let mut seen_qtypes = Vec::new();
            loop {
                let mut query = [0_u8; 512];
                let received =
                    timeout(Duration::from_millis(300), dns_server.recv_from(&mut query)).await;
                let Ok(Ok((len, peer))) = received else {
                    return seen_qtypes;
                };
                seen_qtypes.push(u16::from_be_bytes([query[len - 4], query[len - 3]]));
                let response = dns_a_response(&query[..len], Ipv4Addr::new(127, 0, 0, 42));
                dns_server
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS response");
            }
        });

        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![dns_server_addr],
            ..NativeCoreEgressConfig::default()
        });
        let addresses = egress
            .lookup_host("example.com", 443)
            .await
            .expect("configured DNS resolves");

        assert_eq!(server.await.expect("DNS server task"), vec![DNS_TYPE_A]);
        assert_eq!(
            addresses,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42)),
                443
            )]
        );
    }

    #[tokio::test]
    async fn configured_dns_lookups_are_cached_across_dials() {
        let dns_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind stub DNS server");
        let dns_server_addr = dns_server.local_addr().expect("stub DNS addr");
        let queries_served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&queries_served);
        tokio::spawn(async move {
            let mut query = [0_u8; 512];
            loop {
                let Ok((len, peer)) = dns_server.recv_from(&mut query).await else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = dns_a_response(&query[..len], Ipv4Addr::new(10, 1, 2, 3));
                let _ = dns_server.send_to(&response, peer).await;
            }
        });

        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![dns_server_addr],
            ..NativeCoreEgressConfig::default()
        });

        let first = egress
            .lookup_host("node.example.com", 443)
            .await
            .expect("first lookup resolves");
        // Different port on the second dial: the cache stores addresses, not
        // host:port pairs.
        let second = egress
            .lookup_host("node.example.com", 8443)
            .await
            .expect("second lookup resolves");

        assert_eq!(
            first,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 443)]
        );
        assert_eq!(
            second,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                8443
            )]
        );
        assert_eq!(
            queries_served.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second dial must be served from the cache, not the resolver"
        );
    }

    fn dns_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
        response
    }
}
