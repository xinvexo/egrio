//! The listener session a host starts: one generation's TCP and DNS sockets,
//! the inbound composed behind them, and the control surface over their
//! state. Inbound composition, the accept loop, the DNS listener, the local
//! listener's scope and the generation state each have a submodule.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::task::JoinSet;

use crate::device::{CoreStartInputs, NativeCoreDevice};
use crate::egress::{EgressSocketGuard, NativeCoreEgressConfig};
use crate::profile::RuntimeProfile;
use crate::protocols::shadowsocks::udp::serve_shadowsocks_udp;
use crate::status::{now_unix, NativeCoreState, NativeCoreStatus};

mod accept;
mod compose;

// The Hysteria2 acceptor serves its own QUIC endpoint, so its streams never
// pass the accept loop and it arms this budget itself.
#[cfg(all(feature = "server", not(test)))]
pub(crate) use accept::INBOUND_HANDSHAKE_TIMEOUT;
mod dns;
mod scope;
mod state;
#[cfg(test)]
mod tests;

/// Where the mixed listener should bind, and whether another port may stand
/// in for an unusable one.
struct ListenerRequest {
    listen_addr: Option<SocketAddr>,
    port_fallback: bool,
}

/// How far above an unusable port the listener looks for a free one before
/// the system picks any: near enough to recognise, and the same port again
/// at the next start while the cause lasts.
const LISTENER_FALLBACK_SPAN: u16 = 64;

/// Binds the mixed listener. A port that is taken or reserved fails the
/// start unless `port_fallback` lets the next free port above it, or else
/// one the system picks, stand in; the second value then says which address
/// was asked for and why it was refused.
async fn bind_listener(
    requested: SocketAddr,
    port_fallback: bool,
) -> Result<(TcpListener, Option<crate::ListenerFallback>), String> {
    let error = match TcpListener::bind(requested).await {
        Ok(listener) => return Ok((listener, None)),
        Err(error) => error,
    };
    let Some(cause) = port_unavailable(&error) else {
        return Err(bind_failure(requested, &error));
    };
    if !port_fallback || requested.port() == 0 {
        return Err(bind_failure(requested, &error));
    }
    let candidates = (1..=LISTENER_FALLBACK_SPAN)
        .filter_map(|offset| requested.port().checked_add(offset))
        .chain(std::iter::once(0));
    for port in candidates {
        let mut candidate = requested;
        candidate.set_port(port);
        if let Ok(listener) = TcpListener::bind(candidate).await {
            let fallback = crate::ListenerFallback {
                requested: requested.to_string(),
                cause,
                detail: error.to_string(),
            };
            return Ok((listener, Some(fallback)));
        }
    }
    Err(bind_failure(requested, &error))
}

/// Whether a bind error means the port itself is unusable. Windows answers
/// WSAEACCES (Rust's `PermissionDenied`) for a port another program holds
/// exclusively and for ports in its excluded ranges, which Hyper-V and WSL
/// reserve in blocks (`netsh interface ipv4 show excludedportrange`); other
/// systems answer it for privileged ports.
fn port_unavailable(error: &std::io::Error) -> Option<crate::PortUnavailable> {
    match error.kind() {
        std::io::ErrorKind::AddrInUse => Some(crate::PortUnavailable::InUse),
        std::io::ErrorKind::PermissionDenied => Some(crate::PortUnavailable::Reserved),
        _ => None,
    }
}

/// A listener that cannot bind, said so that a user can act on it: which
/// address, the likely cause, and that another port is the way out.
fn bind_failure(addr: SocketAddr, error: &std::io::Error) -> String {
    let cause = match port_unavailable(error) {
        Some(crate::PortUnavailable::InUse) => "another program already uses this port",
        Some(crate::PortUnavailable::Reserved) => {
            "the system reserves this port or another program holds it exclusively"
        }
        None => return format!("cannot listen on {addr}: {error}"),
    };
    format!("cannot listen on {addr}: {cause}; choose another port ({error})")
}

use accept::run_listener;
#[cfg(feature = "server")]
use compose::build_hysteria2_inbound;
use compose::{compose_inbound, ComposedInbound, InboundStrategy};
pub use compose::{CoreInbound, Hysteria2Inbound};
use dns::run_dns_listener;
pub use scope::ListenerScopeUpdateReport;
use scope::ScopeChange;
use state::{
    finish_listener_generation, mark_failed, CoreSessionManagerInner, CoreSessionStartReservation,
    InboundHandles,
};

const NATIVE_CORE_MAX_ACTIVE_SESSIONS: usize = 2048;
const NATIVE_CORE_MAX_ACTIVE_DNS_QUERIES: usize = 1024;

/// Converts a bound local listener into an address a local client can dial.
/// Wildcard binds are not destinations; explicit interface addresses remain intact.
pub fn local_listener_address(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, address.port()))
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::from((Ipv6Addr::LOCALHOST, address.port()))
        }
        _ => address,
    }
}

#[derive(Debug)]
pub struct CoreSessionManager {
    inner: Arc<Mutex<CoreSessionManagerInner>>,
}

#[derive(Debug, Clone)]
pub struct CoreSessionStartConfig {
    pub profile: RuntimeProfile,
    pub egress: NativeCoreEgressConfig,
    pub listen_addr: Option<SocketAddr>,
    pub dns_listen_addr: Option<SocketAddr>,
    /// Which inbound wire protocol the listener terminates. Defaults to the
    /// mixed plaintext detector; a server assembly selects a Shadowsocks
    /// inbound here.
    pub inbound: CoreInbound,
    /// Optional Hysteria2 QUIC/H3 inbound of the server role. Unlike the
    /// byte-stream `inbound`, Hysteria2 rides a separate QUIC endpoint, so the
    /// manager runs it alongside the main listener rather than as another
    /// `CoreInbound` arm. Standing one up requires the `server` feature (TLS
    /// termination); a non-server build rejects a set inbound rather than
    /// silently dropping it.
    pub hysteria2: Option<Hysteria2Inbound>,
    /// Optional physical egress socket guard compiled into the device. A
    /// listener whose host also runs a capture session must bind its upstream
    /// dials to the physical uplink, or the capture routes steer the relay's
    /// own dials back into the tunnel.
    pub socket_guard: Option<Arc<dyn EgressSocketGuard>>,
}

impl Default for CoreSessionManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoreSessionManagerInner::default())),
        }
    }
}

impl CoreSessionManager {
    /// Whether previously reported pending scope cleanup has released all old
    /// LAN tasks. The accept actor keeps ownership while callers observe it.
    pub fn listener_scope_cleanup_complete(&self) -> bool {
        self.inner
            .lock()
            .expect("native core manager mutex")
            .scope_cleanup
            .as_ref()
            .is_none_or(tokio_util::task::TaskTracker::is_empty)
    }

    /// Changes only the local mixed listener's address scope on its current
    /// port. Once accepted, the actor owns completion even if this caller is
    /// cancelled. A failed binding restores the prior listener when possible.
    pub async fn reconfigure_listener_scope(
        &self,
        address: SocketAddr,
    ) -> Result<ListenerScopeUpdateReport, String> {
        let sender = {
            let inner = self.inner.lock().expect("native core manager mutex");
            if inner.status.state != NativeCoreState::Running {
                return Err("listener scope update requires a running Core".into());
            }
            inner.scope_changes.clone().ok_or_else(|| {
                "listener scope update is only supported by the local mixed listener".to_string()
            })?
        };
        let (reply, result) = oneshot::channel();
        sender
            .try_send(ScopeChange { address, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => "listener scope update is busy".to_string(),
                mpsc::error::TrySendError::Closed(_) => "listener scope controller stopped".into(),
            })?;
        result.await.map_err(|_| {
            "listener scope controller stopped before reporting the result".to_string()
        })?
    }

    pub fn status(&self) -> NativeCoreStatus {
        self.inner
            .lock()
            .expect("native core manager mutex")
            .status
            .clone()
    }

    /// Auth-failure count of the running encrypted stream inbound: Shadowsocks
    /// requests no user key authenticated, or Trojan connections that
    /// completed TLS but presented a password hash no user matched. `None`
    /// when the session serves the mixed inbound or is not running. A host
    /// alarms on a climbing value — the signal of credential probing against
    /// a public port.
    pub fn inbound_auth_failures(&self) -> Option<u64> {
        self.inner
            .lock()
            .expect("native core manager mutex")
            .inbound
            .auth_failures
            .as_ref()
            .map(|counter| counter.load(Ordering::Relaxed))
    }

    /// Auth-failure count of the running Hysteria2 QUIC/H3 inbound: connections
    /// that completed the HTTP/3 auth exchange but presented no valid
    /// credential. `None` when no Hysteria2 inbound is
    /// running. A host alarms on a climbing value — the signal of credential
    /// probing against a public Hysteria2 port.
    pub fn hysteria2_auth_failures(&self) -> Option<u64> {
        self.inner
            .lock()
            .expect("native core manager mutex")
            .inbound
            .hysteria2_auth_failures
            .as_ref()
            .map(|counter| counter.load(Ordering::Relaxed))
    }

    /// The address the running Hysteria2 QUIC/H3 inbound bound its endpoint to,
    /// resolving an ephemeral (`:0`) request to the concrete port. `None` when
    /// no Hysteria2 inbound is running.
    pub fn hysteria2_listen_addr(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("native core manager mutex")
            .inbound
            .hysteria2_listen_addr
            .clone()
    }

    /// Read-only projection of the running core's live connection table (the
    /// session-registry snapshot the UI renders). Empty when the core is not
    /// running. Adds no hot-path state: it clones the device handle and reads
    /// the existing registry snapshot, exactly like `status()` reads the
    /// manager counters — the routing path is untouched.
    pub fn connections_snapshot(&self) -> Vec<crate::TrafficConnectionSnapshot> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner.device.clone()
        };
        device
            .map(|device| device.connections_snapshot())
            .unwrap_or_default()
    }

    /// Terminal records from the running core's finished-session history
    /// ring; empty when the core is not running. The UI's connection
    /// history concatenates this with the live table.
    pub fn finished_connections_snapshot(&self) -> Vec<crate::TrafficConnectionSnapshot> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner.device.clone()
        };
        device
            .map(|device| device.finished_connections_snapshot())
            .unwrap_or_default()
    }

    /// Full UI traffic projection of the running Core (session-registry
    /// counters + live connection table + finished-session ring), for a host
    /// that serves or merges this Core's telemetry. Falls back to the
    /// counter-only (not-ready) shape when the Core is not running. Adds no
    /// hot-path state: it clones the device handle and reads existing snapshots,
    /// exactly like [`Self::connections_snapshot`].
    pub fn traffic_telemetry_snapshot(&self) -> crate::TrafficTelemetrySnapshot {
        self.traffic_telemetry_since(0).0
    }

    /// [`Self::traffic_telemetry_snapshot`] with only the terminal records
    /// newer than `after`, and the sequence number to ask after next time.
    pub fn traffic_telemetry_since(&self, after: u64) -> (crate::TrafficTelemetrySnapshot, u64) {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner.device.clone()
        };
        device.map_or_else(
            || (crate::traffic_telemetry_snapshot(&self.status()), 0),
            |device| device.traffic_telemetry_since(after),
        )
    }

    /// Bytes the running Core has relayed since it started; `None` when the
    /// listener is not running. Two atomic loads: cheap enough to poll many
    /// times a second for a rate chart.
    pub fn traffic_volume(&self) -> Option<crate::TrafficVolume> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner.device.clone()
        };
        device.map(|device| device.traffic_volume())
    }

    /// Live per-user traffic accounting: the authenticated
    /// `user` folded across the live TCP and UDP ledgers. Empty when the core is
    /// not running or in the local-capture role (no authenticated users). A
    /// server host polls this to surface or bill per-user usage.
    pub fn per_user_traffic(&self) -> Vec<crate::PerUserTraffic> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner.device.clone()
        };
        device
            .map(|device| device.per_user_traffic())
            .unwrap_or_default()
    }

    pub async fn start(&self, profile: RuntimeProfile) -> Result<NativeCoreStatus, String> {
        self.start_with_egress(profile, NativeCoreEgressConfig::default(), None)
            .await
    }

    pub async fn start_with_egress(
        &self,
        profile: RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    ) -> Result<NativeCoreStatus, String> {
        self.start_with_config(CoreSessionStartConfig {
            profile,
            egress: egress_config,
            listen_addr: None,
            dns_listen_addr: None,
            inbound: CoreInbound::Mixed,
            hysteria2: None,
            socket_guard,
        })
        .await
    }

    pub async fn start_with_config(
        &self,
        config: CoreSessionStartConfig,
    ) -> Result<NativeCoreStatus, String> {
        let reservation = match self.reserve_listener_start()? {
            Some(reservation) => reservation,
            None => return Ok(self.status()),
        };
        let device = NativeCoreDevice::from_start_inputs(CoreStartInputs {
            profile: config.profile,
            egress: config.egress,
            egress_socket_guard: config.socket_guard,
            capture: Default::default(),
            flow_scanner: None,
            fake_ip_mappings: None,
        });
        self.start_listeners(
            device,
            true,
            ListenerRequest {
                listen_addr: config.listen_addr,
                port_fallback: false,
            },
            config.dns_listen_addr,
            config.inbound,
            config.hysteria2,
            reservation,
        )
        .await
    }

    /// Starts the listener session over an already-compiled device instead
    /// of compiling one. The Runtime serves this mixed listener and its
    /// packet data plane from one generation Core, so fake-IP allocations,
    /// reverse lookups, process attribution and the session registry are
    /// shared; the caller keeps ownership of the device, and `stop` only
    /// ends the listener session. With `port_fallback`, a requested port that
    /// is taken or reserved gives way to a free one (see [`bind_listener`]),
    /// and the status reports the switch.
    pub async fn start_on_device(
        &self,
        device: NativeCoreDevice,
        listen_addr: Option<SocketAddr>,
        dns_listen_addr: Option<SocketAddr>,
        port_fallback: bool,
    ) -> Result<NativeCoreStatus, String> {
        let reservation = match self.reserve_listener_start()? {
            Some(reservation) => reservation,
            None => return Ok(self.status()),
        };
        self.start_listeners(
            device,
            false,
            ListenerRequest {
                listen_addr,
                port_fallback,
            },
            dns_listen_addr,
            CoreInbound::Mixed,
            None,
            reservation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_listeners(
        &self,
        device: NativeCoreDevice,
        owns_device: bool,
        listener_request: ListenerRequest,
        dns_listen_addr: Option<SocketAddr>,
        inbound: CoreInbound,
        hysteria2: Option<Hysteria2Inbound>,
        mut reservation: CoreSessionStartReservation,
    ) -> Result<NativeCoreStatus, String> {
        let generation = reservation.generation;

        // Compose the inbound before binding, so a bad cipher or an empty
        // user table fails fast without leaving a bound socket.
        let ComposedInbound {
            strategy,
            auth_failures,
            shadowsocks_udp,
        } = compose_inbound(inbound)?;

        // Prepare the Hysteria2 QUIC/H3 inbound the same way: parse the cert,
        // derive the user table, and bind its own QUIC endpoint up front so bad
        // material or a taken port fails fast. It is a separate endpoint from
        // the TCP listener, served on its own task below.
        #[cfg(feature = "server")]
        let hysteria2 = match hysteria2 {
            Some(inbound) => Some(build_hysteria2_inbound(inbound)?),
            None => None,
        };
        #[cfg(not(feature = "server"))]
        if hysteria2.is_some() {
            return Err("Hysteria2 inbound requires the `server` feature to terminate TLS".into());
        }

        let listen_addr = listener_request
            .listen_addr
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let dns_listen_addr =
            dns_listen_addr.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let (listener, listener_fallback) =
            bind_listener(listen_addr, listener_request.port_fallback).await?;
        let listen_addr = listener
            .local_addr()
            .map_err(|error| format!("failed to read native core listener addr: {error}"))?;
        let dns_socket = UdpSocket::bind(dns_listen_addr)
            .await
            .map_err(|error| bind_failure(dns_listen_addr, &error))?;
        let dns_listen_addr = dns_socket
            .local_addr()
            .map_err(|error| format!("failed to read native core DNS listener addr: {error}"))?;
        // The Shadowsocks inbound shares its TCP listen port for UDP associate
        // (SS convention). Bind it up front so a bind failure fails the start,
        // like the TCP and DNS listeners; pair it with the acceptor's user table
        // and auth counter.
        let shadowsocks_udp = match shadowsocks_udp {
            Some((users, auth_failures)) => {
                let socket = UdpSocket::bind(listen_addr)
                    .await
                    .map_err(|error| bind_failure(listen_addr, &error))?;
                crate::egress::size_udp_socket_buffers(socket2::SockRef::from(&socket))?;
                Some((Arc::new(socket), users, auth_failures))
            }
            None => None,
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        #[cfg(feature = "server")]
        let hy2_shutdown_rx = hysteria2.as_ref().map(|_| shutdown_tx.subscribe());
        let ss_udp_shutdown_rx = shadowsocks_udp.as_ref().map(|_| shutdown_tx.subscribe());
        let dns_shutdown_rx = shutdown_tx.subscribe();
        let scope_supported = matches!(&strategy, InboundStrategy::Mixed) && hysteria2.is_none();
        let (scope_tx, scope_rx) = mpsc::channel(1);

        {
            let mut inner = self.inner.lock().expect("native core manager mutex");
            if inner.starting_generation != Some(generation) {
                drop(inner);
                if owns_device {
                    device.close();
                }
                return Err("native core listener start was cancelled".into());
            }
            inner.starting_generation = None;
            inner.generation = generation;
            inner.pending_failure = None;
            inner.status = NativeCoreStatus {
                state: NativeCoreState::Running,
                listen_addr: Some(listen_addr.to_string()),
                listener_fallback,
                dns_listen_addr: Some(dns_listen_addr.to_string()),
                started_at_unix: Some(now_unix()),
                updated_at_unix: now_unix(),
                active_sessions: 0,
                accepted_sessions: 0,
                completed_sessions: 0,
                failed_sessions: 0,
                last_error: None,
            };
            inner.shutdown_tx = Some(shutdown_tx);
            inner.scope_changes = scope_supported.then_some(scope_tx);
            inner.scope_cleanup = None;
            inner.device = Some(device.clone());
            inner.owns_device = owns_device;
            inner.inbound = InboundHandles {
                auth_failures,
                ..Default::default()
            };
            #[cfg(feature = "server")]
            if let Some((acceptor, endpoint)) = &hysteria2 {
                inner.inbound.hysteria2_auth_failures = Some(acceptor.auth_failures_handle());
                inner.inbound.hysteria2_listen_addr =
                    endpoint.local_addr().ok().map(|addr| addr.to_string());
            }
        }
        reservation.commit();

        let mut generation_tasks = JoinSet::new();
        generation_tasks.spawn(run_listener(
            self.inner.clone(),
            generation,
            listener,
            device.clone(),
            Arc::new(Semaphore::new(NATIVE_CORE_MAX_ACTIVE_SESSIONS)),
            shutdown_rx,
            strategy,
            scope_rx,
        ));
        // Light up the active health-probe scheduler for a
        // device this manager owns; a borrowed device's owner (the Runtime)
        // lights its own. The spawn is idempotent per device, so a capture
        // pump on the same device adds no second loop. Detached: it
        // self-exits when the device closes.
        if owns_device {
            drop(device.spawn_health_probe_loop());
        }
        // The Hysteria2 QUIC/H3 endpoint serves on its own task: it pins the
        // profile snapshot current at start (its connections do not follow
        // later hot swaps), and ends when the manager's shutdown signal drops
        // the serve future, closing the endpoint.
        #[cfg(feature = "server")]
        if let Some((acceptor, endpoint)) = hysteria2 {
            let serve_device = device.clone();
            let mut hy2_shutdown_rx = hy2_shutdown_rx.expect("Hysteria2 shutdown receiver");
            let shutdown_endpoint = endpoint.clone();
            generation_tasks.spawn(async move {
                let serve = acceptor.serve(endpoint, serve_device);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut serve => {}
                    _ = wait_for_shutdown(&mut hy2_shutdown_rx) => {
                        shutdown_endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
                        serve.await;
                    }
                }
            });
        }
        // Serve the Shadowsocks UDP inbound alongside the TCP listener: a
        // direct-drive server (not an acceptor) over the shared user table,
        // ending when the manager's shutdown signal drops the serve future.
        if let Some((socket, table, auth_failures)) = shadowsocks_udp {
            let serve_device = device.clone();
            let ss_udp_shutdown_rx = ss_udp_shutdown_rx.expect("Shadowsocks UDP shutdown receiver");
            generation_tasks.spawn(serve_shadowsocks_udp(
                socket,
                serve_device,
                table,
                auth_failures,
                ss_udp_shutdown_rx,
            ));
        }
        let generation_device = device.clone();
        generation_tasks.spawn(run_dns_listener(
            self.inner.clone(),
            generation,
            Arc::new(dns_socket),
            device,
            Arc::new(Semaphore::new(NATIVE_CORE_MAX_ACTIVE_DNS_QUERIES)),
            dns_shutdown_rx,
        ));
        tokio::spawn(finalize_listener_generation(
            self.inner.clone(),
            generation,
            generation_tasks,
            generation_device,
            owns_device,
        ));

        Ok(self.status())
    }

    /// Hot-swaps the running listener's compiled profile. Established tunnel
    /// sessions keep the snapshot they were accepted under and drain
    /// naturally; connections accepted and DNS queries received after this
    /// call use the new profile. Fails when the listener is not running.
    pub fn apply_profile(&self, profile: &RuntimeProfile) -> Result<NativeCoreStatus, String> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner
                .device
                .clone()
                .ok_or_else(|| "native core listener is not running".to_string())?
        };
        device.apply_profile(profile);
        {
            let mut inner = self.inner.lock().expect("native core manager mutex");
            inner.status.updated_at_unix = now_unix();
        }
        Ok(self.status())
    }

    /// Persists the user's Select-group choice on the running core (durable
    /// across profile hot swaps). Fails when the listener is not running or
    /// the member does not belong to the group.
    pub fn select_group_member(&self, group: &str, member: &str) -> Result<(), String> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner
                .device
                .clone()
                .ok_or_else(|| "native core listener is not running".to_string())?
        };
        device.select_group_member(group, member)
    }

    /// Hot-swaps the running listener's profile and egress configuration
    /// together (the settings hot-apply path, e.g. the IPv6 switch), with the
    /// same drain semantics as [`Self::apply_profile`]. Fails when the
    /// listener is not running.
    pub fn apply_profile_and_egress(
        &self,
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
    ) -> Result<NativeCoreStatus, String> {
        let device = {
            let inner = self.inner.lock().expect("native core manager mutex");
            inner
                .device
                .clone()
                .ok_or_else(|| "native core listener is not running".to_string())?
        };
        device.apply_profile_and_egress(profile, egress_config);
        {
            let mut inner = self.inner.lock().expect("native core manager mutex");
            inner.status.updated_at_unix = now_unix();
        }
        Ok(self.status())
    }

    pub fn stop(&self) -> NativeCoreStatus {
        let (shutdown_tx, device, owns_device) = {
            let mut inner = self.inner.lock().expect("native core manager mutex");
            inner.starting_generation = None;
            if inner.active_generation.is_none()
                && inner.shutdown_tx.is_none()
                && inner.device.is_none()
            {
                inner.pending_failure = None;
                inner.status = NativeCoreStatus::stopped();
                return inner.status.clone();
            }
            inner.pending_failure = None;
            inner.status.state = NativeCoreState::Stopping;
            inner.status.updated_at_unix = now_unix();
            inner.status.last_error = None;
            inner.inbound = InboundHandles::default();
            inner.scope_changes = None;
            (
                inner.shutdown_tx.take(),
                inner.device.take(),
                inner.owns_device,
            )
        };

        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(true);
        }
        if owns_device {
            if let Some(device) = device {
                device.close();
            }
        }

        self.status()
    }

    fn reserve_listener_start(&self) -> Result<Option<CoreSessionStartReservation>, String> {
        let generation = {
            let mut inner = self.inner.lock().expect("native core manager mutex");
            if matches!(
                inner.status.state,
                NativeCoreState::Running | NativeCoreState::Stopping
            ) {
                return Ok(None);
            }
            if inner.starting_generation.is_some() {
                return Err("native core listener start is already in progress".into());
            }
            if inner.active_generation.is_some() {
                return Err("native core listener generation is still draining".into());
            }
            inner.next_generation = inner.next_generation.wrapping_add(1);
            inner.starting_generation = Some(inner.next_generation);
            inner.active_generation = Some(inner.next_generation);
            inner.next_generation
        };
        Ok(Some(CoreSessionStartReservation::new(
            self.inner.clone(),
            generation,
        )))
    }
}

async fn finalize_listener_generation(
    inner: Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    mut tasks: JoinSet<()>,
    device: NativeCoreDevice,
    owns_device: bool,
) {
    while let Some(result) = tasks.join_next().await {
        let task_failed = result.is_err();
        let task_ended_while_running = {
            let inner = inner.lock().expect("native core manager mutex");
            inner.generation == generation && inner.status.state == NativeCoreState::Running
        };
        if task_failed || task_ended_while_running {
            let error = match result {
                Ok(()) => "native core listener task exited unexpectedly".to_string(),
                Err(error) => format!("native core listener task failed: {error}"),
            };
            mark_failed(&inner, generation, error);
        }
    }
    if owns_device {
        device.close();
    }
    finish_listener_generation(&inner, generation);
}

async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
        if *shutdown_rx.borrow() {
            return;
        }
    }
}
