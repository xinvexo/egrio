//! Interface-bound egress: the Windows implementation of the core's
//! [`EgressSocketGuard`].
//!
//! The real egress interface is *maintained network state*, not something
//! re-derived per socket. [`WindowsNetworkState`] holds the physical uplink
//! (one interface index per family) and is kept current by the network-change
//! monitor; this binder is a pure reader of it. Every physical egress socket
//! the capture core creates is bound to the state's current interface for its
//! family via the documented `IP_UNICAST_IF` / `IPV6_UNICAST_IF` socket options
//! (ws2ipdef.h; the IPv4 option takes the interface index in network byte
//! order, the IPv6 option in host order). A bound socket cannot re-enter the
//! Wintun capture routes for any destination or family — this replaces the
//! deleted per-proxy-endpoint loop-protection host routes and egress source-IP
//! bindings.
//!
//! The binder never queries the route table itself: the underlying interface is
//! whatever [`WindowsNetworkState`] currently records, so a Wi-Fi→Ethernet
//! switch that the monitor has folded into the state is picked up by the next
//! dial with no work here. Loop protection lives in the state's selection (it
//! excludes our own Wintun by index), not in this reader.
//!
//! Loopback destinations are skipped: loopback is never captured (no capture
//! route covers it, WFP permits it), and an interface-bound loopback dial would
//! fail.
//!
//! Binding follows the TUN layer, not the Core's lifetime: the same Core serves
//! the system proxy alone, TUN alone, or both. [`WindowsTunEgress`] is
//! activated by the desktop packet-capture adapter with the interface index the
//! privileged service reports for the adapter it holds, and deactivated when
//! the capture capability is restored. While it is inactive there are no Egrio
//! capture routes, so dials pass through unbound. The desktop never opens the
//! Wintun adapter itself: that needs administrator rights the desktop does not
//! have.
//!
//! One network-change monitor, registered on first use and kept for the life
//! of the [`WindowsTunEgress`], re-derives the active session's uplink and
//! resolvers and publishes the physical network (each family's uplink and the
//! physical interfaces' addresses) that the Core follows to end stranded
//! connections, with or without TUN.
//!
//! ICMP echo to a DIRECT destination leaves from the uplink's address through
//! the IP Helper API while a TUN session is active.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use egrio_core::{
    CaptureEgressOverlay, EgressAddressFamily, EgressBinding, EgressNetwork, EgressSocketContext,
    EgressSocketDescriptor, EgressSocketGuard,
};
use tokio::sync::watch;
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET,
};

use crate::config::WindowsWintunConfig;
use crate::ipv6::resolve_windows_ipv6_mode;
use crate::wintun::network_state::{
    physical_uplinks, WindowsNetworkChangeMonitor, WindowsNetworkState,
};
use crate::wintun::{physical_interface_addresses, read_interface_dns_servers};

/// The live TUN egress state: the physical-uplink network state and egress
/// overlay of the current TUN session, shared by the packet-capture adapter
/// (writer) and the Core's egress binder (reader). Each activation captures a
/// fresh network state that excludes that session's adapter, because the
/// service creates a new adapter (with a new LUID) for every packet session.
#[derive(Debug)]
pub struct WindowsTunEgress {
    shared: Arc<TunEgressShared>,
    /// Keeps `shared` following the network; registered on first use. A
    /// failed registration is not fatal: the uplink then stays at what each
    /// TUN session captured, and the Core sees no network changes.
    monitor: OnceLock<Option<WindowsNetworkChangeMonitor>>,
}

struct TunEgressShared {
    config: WindowsWintunConfig,
    active: RwLock<Option<Arc<EgressBinderState>>>,
    /// The physical network the Core follows.
    network: watch::Sender<EgressNetwork>,
    /// Callbacks of different subscriptions can run at once; each derivation
    /// reads the live state, so serialized the last one publishes the truth.
    following: Mutex<()>,
}

impl Default for WindowsTunEgress {
    fn default() -> Self {
        Self::new(WindowsWintunConfig::default())
    }
}

impl WindowsTunEgress {
    pub fn new(config: WindowsWintunConfig) -> Self {
        Self {
            shared: Arc::new(TunEgressShared {
                config,
                active: RwLock::default(),
                network: watch::Sender::new(EgressNetwork::default()),
                following: Mutex::new(()),
            }),
            monitor: OnceLock::new(),
        }
    }

    /// Starts binding egress to the physical uplink that excludes the TUN
    /// adapter at `tun_interface_index`, and takes that uplink's resolvers and
    /// the IPv6 posture as the Core's egress overlay; the network-change
    /// monitor keeps both current. Fails when the host has no physical IPv4
    /// uplink or resolver, so the TUN layer fails to apply instead of every
    /// later dial.
    pub fn activate(&self, tun_interface_index: u32) -> Result<(), String> {
        let network_state = Arc::new(WindowsNetworkState::capture(tun_interface_index)?);
        let uplink = network_state
            .underlying_ipv4()
            .ok_or("the physical IPv4 uplink disappeared while TUN egress activated")?;
        let overlay = egress_overlay(&self.shared.config, uplink)?;
        self.set(Some(Arc::new(EgressBinderState {
            network_state,
            overlay: RwLock::new(Arc::new(overlay)),
        })));
        self.follow();
        Ok(())
    }

    /// The overlay of the active TUN session, if any.
    pub fn overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.current().map(|state| state.overlay())
    }

    /// The physical network as the monitor last derived it, updated on every
    /// change.
    pub fn network(&self) -> watch::Receiver<EgressNetwork> {
        self.monitor();
        self.shared.network.subscribe()
    }

    /// Core's capture configuration for this adapter: the default DNS
    /// capture, and nothing addressed into the adapter's own subnets relayed.
    pub fn core_capture_config(&self) -> egrio_core::NativeCoreCaptureConfig {
        let config = &self.shared.config;
        let prefix_len = u32::from(config.adapter_netmask).leading_ones() as u8;
        egrio_core::NativeCoreCaptureConfig::default().with_interface_networks([
            egrio_core::NativeCoreInterfaceNetwork::new(config.adapter_address, prefix_len),
            egrio_core::NativeCoreInterfaceNetwork::new(
                config.adapter_address6,
                config.adapter_prefix_length6,
            ),
        ])
    }

    /// The adapter and virtual DNS addresses the Wintun session occupies.
    pub fn reserved_addresses(&self) -> Vec<IpAddr> {
        let config = &self.shared.config;
        let mut addresses = vec![
            IpAddr::V4(config.adapter_address),
            IpAddr::V6(config.adapter_address6),
        ];
        addresses.extend(config.dns_servers.iter().copied());
        if let Some(next) = u128::from(config.adapter_address6).checked_add(1) {
            addresses.push(IpAddr::V6(next.into()));
        }
        addresses
    }

    /// Stops binding: the TUN routes are gone, so unbound dials cannot loop.
    pub fn deactivate(&self) {
        self.set(None);
        self.follow();
    }

    /// The physical uplink's address in the family of `ipv6`, for an echo to
    /// leave from.
    fn echo_source(&self, ipv6: bool) -> Option<IpAddr> {
        let network = self.shared.network.borrow();
        let uplink = if ipv6 {
            network.ipv6_uplink
        } else {
            network.ipv4_uplink
        }?;
        network
            .addresses
            .iter()
            .find(|(index, address)| *index == uplink && address.is_ipv6() == ipv6)
            .map(|(_, address)| *address)
    }

    fn set(&self, state: Option<Arc<EgressBinderState>>) {
        *self.shared.active.write().expect("TUN egress state lock") = state;
    }

    fn current(&self) -> Option<Arc<EgressBinderState>> {
        self.shared.current()
    }

    /// Re-derives the network now, registering the monitor first if needed.
    fn follow(&self) {
        if self.monitor.get().is_some() {
            follow_network(&self.shared);
        } else {
            self.monitor();
        }
    }

    fn monitor(&self) {
        self.monitor.get_or_init(|| {
            follow_network(&self.shared);
            WindowsNetworkChangeMonitor::register({
                let shared = Arc::clone(&self.shared);
                move || follow_network(&shared)
            })
            .map_err(|error| log::warn!("Windows egress will not follow network changes: {error}"))
            .ok()
        });
    }
}

impl std::fmt::Debug for TunEgressShared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunEgressShared")
            .field("config", &self.config)
            .field("active", &self.active)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl TunEgressShared {
    fn current(&self) -> Option<Arc<EgressBinderState>> {
        self.active.read().expect("TUN egress state lock").clone()
    }
}

/// [`EgressSocketGuard`] implementation that binds each egress socket to the
/// physical uplink interface the active TUN session's [`WindowsNetworkState`]
/// records for its family. It counts what it bound and what it skipped, so a
/// session can prove the binding is exercised.
pub struct WindowsEgressInterfaceBinder {
    tun: Arc<WindowsTunEgress>,
    bound_sockets: AtomicU64,
    skipped_loopback: AtomicU64,
    skipped_tun_inactive: AtomicU64,
    failed_binds: AtomicU64,
}

#[derive(Debug)]
struct EgressBinderState {
    network_state: Arc<WindowsNetworkState>,
    /// Replaced when the uplink changes: resolvers belong to the network the
    /// uplink is on, and the old network's are usually unreachable from the
    /// new one.
    overlay: RwLock<Arc<CaptureEgressOverlay>>,
}

impl EgressBinderState {
    fn overlay(&self) -> Arc<CaptureEgressOverlay> {
        Arc::clone(&self.overlay.read().expect("TUN egress overlay lock"))
    }
}

/// Re-derives the active session's uplink and resolvers, then publishes the
/// physical network. Without the addresses the Core keeps the network it
/// has: an empty one would read as every connection stranded.
fn follow_network(shared: &TunEgressShared) {
    let _following = shared.following.lock().expect("TUN egress follow lock");
    let (ipv4_uplink, ipv6_uplink) = match shared.current() {
        Some(state) => {
            follow_uplink(&state.network_state, &state.overlay, &shared.config);
            (
                state.network_state.underlying_ipv4(),
                state.network_state.underlying_ipv6(),
            )
        }
        None => physical_uplinks(None),
    };
    let Some(addresses) = physical_interface_addresses() else {
        return;
    };
    let network = EgressNetwork {
        ipv4_uplink,
        ipv6_uplink,
        addresses,
    };
    let changed = shared.network.send_if_modified(|current| {
        let changed = *current != network;
        if changed {
            *current = network.clone();
        }
        changed
    });
    if changed {
        log::info!(
            "Windows egress uplinks IPv4 {ipv4_uplink:?}, IPv6 {ipv6_uplink:?}; {} physical addresses",
            network.addresses.len()
        );
    }
}

/// Recomputes the uplink and takes the resolvers of the one now in use. An
/// uplink without a usable resolver keeps the previous ones: an empty set
/// would send DIRECT resolution back into the tunnel.
fn follow_uplink(
    network_state: &WindowsNetworkState,
    overlay: &RwLock<Arc<CaptureEgressOverlay>>,
    config: &WindowsWintunConfig,
) {
    let previous = network_state.underlying_ipv4();
    network_state.recompute();
    let Some(uplink) = network_state.underlying_ipv4() else {
        return;
    };
    match egress_overlay(config, uplink) {
        Ok(next) => {
            let mut current = overlay.write().expect("TUN egress overlay lock");
            if current.dns_servers != next.dns_servers {
                log::info!(
                    "TUN egress uplink is interface {uplink} (was {previous:?}); resolvers {:?}",
                    next.dns_servers
                );
                *current = Arc::new(next);
            }
        }
        Err(error) => log::warn!("kept the previous TUN egress resolvers: {error}"),
    }
}

impl std::fmt::Debug for WindowsEgressInterfaceBinder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsEgressInterfaceBinder")
            .field("tun_active", &self.tun.current().is_some())
            .field("stats", &self.stats())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsEgressInterfaceBinderStats {
    pub bound_sockets: u64,
    pub skipped_loopback: u64,
    pub skipped_tun_inactive: u64,
    pub failed_binds: u64,
}

impl WindowsEgressInterfaceBinder {
    pub fn new(tun: Arc<WindowsTunEgress>) -> Self {
        Self {
            tun,
            bound_sockets: AtomicU64::new(0),
            skipped_loopback: AtomicU64::new(0),
            skipped_tun_inactive: AtomicU64::new(0),
            failed_binds: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> WindowsEgressInterfaceBinderStats {
        WindowsEgressInterfaceBinderStats {
            bound_sockets: self.bound_sockets.load(Ordering::Relaxed),
            skipped_loopback: self.skipped_loopback.load(Ordering::Relaxed),
            skipped_tun_inactive: self.skipped_tun_inactive.load(Ordering::Relaxed),
            failed_binds: self.failed_binds.load(Ordering::Relaxed),
        }
    }

    fn bind_to_interface(
        &self,
        descriptor: EgressSocketDescriptor,
        family: EgressAddressFamily,
        interface_index: u32,
    ) -> Result<(), String> {
        // IP_UNICAST_IF wants the index in network byte order; IPV6_UNICAST_IF
        // wants host order (documented in ws2ipdef.h / MSDN IPPROTO_IP options).
        let (level, option, value) = match family {
            EgressAddressFamily::Ipv4 => (IPPROTO_IP, IP_UNICAST_IF, interface_index.to_be()),
            EgressAddressFamily::Ipv6 => (IPPROTO_IPV6, IPV6_UNICAST_IF, interface_index),
        };
        let result = unsafe {
            setsockopt(
                descriptor as SOCKET,
                level,
                option,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if result != 0 {
            let wsa_error = unsafe { WSAGetLastError() };
            return Err(format!(
                "setsockopt({}) to interface {interface_index} failed with WSA error {wsa_error}",
                match family {
                    EgressAddressFamily::Ipv4 => "IP_UNICAST_IF",
                    EgressAddressFamily::Ipv6 => "IPV6_UNICAST_IF",
                }
            ));
        }
        Ok(())
    }
}

impl EgressSocketGuard for WindowsEgressInterfaceBinder {
    fn protect_socket(
        &self,
        descriptor: EgressSocketDescriptor,
        context: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        if context.remote.is_some_and(|remote| remote.is_loopback()) {
            self.skipped_loopback.fetch_add(1, Ordering::Relaxed);
            return Ok(EgressBinding::unbound());
        }
        let Some(state) = self.tun.current() else {
            self.skipped_tun_inactive.fetch_add(1, Ordering::Relaxed);
            return Ok(EgressBinding::unbound());
        };
        let network_state = &state.network_state;
        let underlying = match context.family {
            EgressAddressFamily::Ipv4 => network_state.underlying_ipv4(),
            EgressAddressFamily::Ipv6 => network_state.underlying_ipv6(),
        };
        let Some(interface_index) = underlying else {
            self.failed_binds.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "no physical {} uplink is currently available; Egrio has no real {} egress interface right now",
                egress_family_label(context.family),
                egress_family_label(context.family)
            ));
        };
        match self.bind_to_interface(descriptor, context.family, interface_index) {
            Ok(()) => {
                self.bound_sockets.fetch_add(1, Ordering::Relaxed);
                Ok(EgressBinding::bound(interface_index))
            }
            Err(error) => {
                self.failed_binds.fetch_add(1, Ordering::Relaxed);
                Err(format!("Windows egress interface binding failed: {error}"))
            }
        }
    }

    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.tun.overlay()
    }

    fn network(&self) -> Option<watch::Receiver<EgressNetwork>> {
        Some(self.tun.network())
    }

    fn sends_echo(&self) -> bool {
        self.tun.current().is_some()
    }

    /// From the physical uplink's address through the IP Helper API.
    fn echo(&self, target: IpAddr, payload: &[u8], wait: Duration) -> Result<(), String> {
        if self.tun.current().is_none() {
            return Err("the TUN session relays no ICMP echo".into());
        }
        let source = self
            .tun
            .echo_source(target.is_ipv6())
            .ok_or_else(|| format!("no physical uplink address to echo {target} from"))?;
        crate::icmp_echo::echo(source, target, payload, wait)
    }
}

/// The Core's egress overlay for one TUN session: the IPv4 resolvers of the
/// physical uplink the Core binds to, and the resolved IPv6 posture.
///
/// The resolvers are load-bearing, not an optimization: with the capture
/// routes installed the system resolver points at the capture DNS itself, so
/// an empty set would send every DIRECT-flow resolution through `getaddrinfo`,
/// loop it back into the tunnel, and time out. An uplink without a usable
/// resolver therefore fails the activation instead of degrading.
fn egress_overlay(
    config: &WindowsWintunConfig,
    uplink_interface_index: u32,
) -> Result<CaptureEgressOverlay, String> {
    let dns_servers =
        egress_dns_servers(&read_interface_dns_servers(uplink_interface_index)?, config);
    if dns_servers.is_empty() {
        return Err(format!(
            "the physical uplink (interface {uplink_interface_index}) has no usable IPv4 DNS server for Core egress"
        ));
    }
    Ok(CaptureEgressOverlay {
        dns_servers,
        ipv6_enabled: resolve_windows_ipv6_mode(config).tunnels_v6(),
    })
}

/// The uplink resolvers the Core dials directly: IPv4 unicast servers on port
/// 53, never one of the Wintun virtual resolvers.
fn egress_dns_servers(servers: &[IpAddr], config: &WindowsWintunConfig) -> Vec<SocketAddr> {
    let mut servers = servers
        .iter()
        .filter(|server| {
            server.is_ipv4()
                && !server.is_unspecified()
                && !server.is_loopback()
                && !server.is_multicast()
                && !config.dns_servers.contains(server)
        })
        .map(|server| SocketAddr::new(*server, 53))
        .collect::<Vec<_>>();
    servers.sort();
    servers.dedup();
    servers
}

fn egress_family_label(family: EgressAddressFamily) -> &'static str {
    match family {
        EgressAddressFamily::Ipv4 => "IPv4",
        EgressAddressFamily::Ipv6 => "IPv6",
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn public_v4_context() -> EgressSocketContext {
        EgressSocketContext::for_remote(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    }

    /// Activates with a pinned network state, without OS reads or a monitor.
    fn activate_pinned(tun: &WindowsTunEgress, underlying_v4: Option<u32>) {
        tun.set(Some(Arc::new(EgressBinderState {
            network_state: Arc::new(WindowsNetworkState::pinned_for_tests(underlying_v4, None)),
            overlay: RwLock::new(Arc::new(CaptureEgressOverlay {
                dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
                ipv6_enabled: false,
            })),
        })));
    }

    #[test]
    fn inactive_tun_passes_dials_through_unbound() {
        let binder = WindowsEgressInterfaceBinder::new(Arc::default());

        for _ in 0..2 {
            let binding = binder
                .protect_socket(0, public_v4_context())
                .expect("TUN-inactive dial passes through");
            assert_eq!(binding, EgressBinding::unbound());
        }
        assert_eq!(binder.stats().skipped_tun_inactive, 2);
        assert_eq!(binder.stats().failed_binds, 0);
    }

    #[test]
    fn echo_is_relayed_only_while_a_session_is_active() {
        let tun = Arc::new(WindowsTunEgress::default());
        let binder = WindowsEgressInterfaceBinder::new(Arc::clone(&tun));

        assert!(!binder.sends_echo(), "no TUN session");
        activate_pinned(&tun, Some(7));
        assert!(binder.sends_echo());
        tun.deactivate();
        assert!(!binder.sends_echo(), "the relay ends with the session");
    }

    #[test]
    fn echo_leaves_from_the_uplink_address_of_its_family() {
        let tun = WindowsTunEgress::default();
        tun.shared.network.send_replace(EgressNetwork {
            ipv4_uplink: Some(7),
            ipv6_uplink: None,
            addresses: vec![
                (3, "10.0.0.9".parse().unwrap()),
                (7, "2001:db8::20".parse().unwrap()),
                (7, "192.0.2.20".parse().unwrap()),
            ],
        });
        assert_eq!(tun.echo_source(false), Some("192.0.2.20".parse().unwrap()));
        assert_eq!(tun.echo_source(true), None, "no IPv6 uplink");
    }

    #[test]
    fn loopback_dials_are_never_bound() {
        let tun = Arc::new(WindowsTunEgress::default());
        activate_pinned(&tun, Some(7));
        let binder = WindowsEgressInterfaceBinder::new(Arc::clone(&tun));

        let binding = binder
            .protect_socket(
                0,
                EgressSocketContext::for_remote(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .expect("loopback dial is never bound");
        assert_eq!(binding, EgressBinding::unbound());
        assert_eq!(binder.stats().skipped_loopback, 1);
    }

    #[test]
    fn binding_follows_tun_activation_and_deactivation() {
        let tun = Arc::new(WindowsTunEgress::default());
        let binder = WindowsEgressInterfaceBinder::new(Arc::clone(&tun));

        // Active with no physical IPv4 uplink: the dial reaches family
        // selection and fails there, without touching a socket.
        activate_pinned(&tun, None);
        let error = binder
            .protect_socket(0, public_v4_context())
            .expect_err("no-uplink state must fail the dial");
        assert!(error.contains("no physical IPv4 uplink"));
        assert_eq!(binder.stats().failed_binds, 1);

        assert_eq!(
            binder.capture_overlay().map(|overlay| overlay.ipv6_enabled),
            Some(false)
        );

        tun.set(None);
        assert_eq!(
            binder.protect_socket(0, public_v4_context()).unwrap(),
            EgressBinding::unbound()
        );
        assert_eq!(binder.stats().skipped_tun_inactive, 1);
        assert!(binder.capture_overlay().is_none());
    }

    /// The regression net for the DIRECT-flow DNS self-loop: the overlay must
    /// carry the physical uplink's resolvers. Requires a host with an uplink
    /// and configured IPv4 DNS, as every supported Windows environment has.
    #[test]
    fn the_physical_uplink_yields_egress_resolvers() {
        let uplink = crate::wintun::physical_egress_interface_index(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            None,
        )
        .expect("host has a physical IPv4 uplink");

        let overlay = egress_overlay(&WindowsWintunConfig::default(), uplink)
            .expect("the uplink has IPv4 resolvers");

        assert!(!overlay.dns_servers.is_empty());
    }

    /// Requires a host with a physical IPv4 uplink, as the test above.
    #[test]
    fn the_network_feed_reports_the_physical_uplink_and_its_addresses() {
        let tun = WindowsTunEgress::default();
        let network = tun.network().borrow().clone();
        let uplink = network
            .ipv4_uplink
            .expect("host has a physical IPv4 uplink");

        assert!(network
            .addresses
            .iter()
            .any(|(interface, address)| *interface == uplink && address.is_ipv4()));
    }

    #[test]
    fn egress_resolvers_are_uplink_ipv4_unicast_servers_only() {
        let config = WindowsWintunConfig::default();
        let servers = egress_dns_servers(
            &[
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                "2001:4860:4860::8888".parse().unwrap(),
                config.dns_servers[0],
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            ],
            &config,
        );

        assert_eq!(
            servers,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn reserved_addresses_cover_the_adapter_and_both_virtual_resolvers() {
        let config = WindowsWintunConfig::default();
        let reserved = WindowsTunEgress::new(config.clone()).reserved_addresses();
        assert!(reserved.contains(&IpAddr::V4(config.adapter_address)));
        assert!(reserved.contains(&IpAddr::V6(config.adapter_address6)));
        for server in &config.dns_servers {
            assert!(reserved.contains(server));
        }
        let next = std::net::Ipv6Addr::from(u128::from(config.adapter_address6) + 1);
        assert!(reserved.contains(&IpAddr::V6(next)));
    }
}
