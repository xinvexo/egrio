//! Physical egress binding. SDK basis: macOS netinet/in.h IP_BOUND_IF (25),
//! netinet6/in6.h IPV6_BOUND_IF (125), route(8) -ifscope, getifaddrs(3), and
//! the Network.framework path monitor (`network_monitor.rs`), which lists the
//! interfaces in the system's preference order, the service order.
//! Interface-scoped routes bypass the tunnel's routes.

use egrio_core::{
    CaptureEgressOverlay, EgressAddressFamily, EgressBinding, EgressNetwork, EgressSocketContext,
    EgressSocketDescriptor, EgressSocketGuard,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long a binder waits at construction for the path monitor's first
/// path, which follows its start at once.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const FIRST_PATH_BUDGET: Duration = Duration::from_secs(2);
/// How often a dial that finds no route of its family looks again.
const RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// The tunnel's egress state, shared by the capture (writer)
/// and the Core's binder (reader). Activated before the tunnel starts, so
/// binding is in place before its routes are, and withdrawn after restore.
#[derive(Debug, Default)]
pub struct MacosTunEgress {
    overlay: RwLock<Option<Arc<CaptureEgressOverlay>>>,
}

impl MacosTunEgress {
    pub fn activate(&self, overlay: CaptureEgressOverlay) {
        self.set(Some(Arc::new(overlay)));
    }

    pub fn deactivate(&self) {
        self.set(None);
    }

    pub fn overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.overlay.read().expect("macOS TUN egress lock").clone()
    }

    fn set(&self, overlay: Option<Arc<CaptureEgressOverlay>>) {
        *self.overlay.write().expect("macOS TUN egress lock") = overlay;
    }

    /// Takes the resolvers of the network the uplink is on now, keeping the
    /// tunnel's IPv6 posture. Whether they replaced others; a closed tunnel
    /// has none to replace.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn replace_dns_servers(&self, dns_servers: Vec<SocketAddr>) -> bool {
        let mut overlay = self.overlay.write().expect("macOS TUN egress lock");
        let Some(current) = overlay.as_ref() else {
            return false;
        };
        if current.dns_servers == dns_servers {
            return false;
        }
        let ipv6_enabled = current.ipv6_enabled;
        *overlay = Some(Arc::new(CaptureEgressOverlay {
            dns_servers,
            ipv6_enabled,
        }));
        true
    }
}

/// The interface each family's bound dials leave through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PhysicalRoutes {
    ipv4: Option<u32>,
    ipv6: Option<u32>,
}

impl PhysicalRoutes {
    fn get(&self, family: EgressAddressFamily) -> Option<u32> {
        match family {
            EgressAddressFamily::Ipv4 => self.ipv4,
            EgressAddressFamily::Ipv6 => self.ipv6,
        }
    }
}

/// The physical network as the path monitor last showed it: each family's
/// uplink, which every bound dial reads, and the network the Core follows.
/// Re-derived on every path change, never in the dial path, except when a
/// dial finds no route of its family.
#[derive(Debug)]
struct PhysicalNetwork {
    /// The physical interfaces, most preferred first; `None` until the
    /// monitor's first path.
    ranked: Mutex<Option<Vec<u32>>>,
    /// Whether the first path has been observed.
    observed: Mutex<bool>,
    first_path: Condvar,
    routes: RwLock<PhysicalRoutes>,
    feed: watch::Sender<EgressNetwork>,
    /// Whose resolvers follow the uplink while the tunnel runs.
    tun: Option<Arc<MacosTunEgress>>,
    /// When a dial last looked again for a family without a route.
    rechecked: Mutex<Option<Instant>>,
}

impl PhysicalNetwork {
    fn new(tun: Option<Arc<MacosTunEgress>>) -> Self {
        Self {
            ranked: Mutex::new(None),
            observed: Mutex::new(false),
            first_path: Condvar::new(),
            routes: RwLock::default(),
            feed: watch::Sender::new(EgressNetwork::default()),
            tun,
            rechecked: Mutex::new(None),
        }
    }

    /// A new path from the monitor.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn follow(&self, ranked: &[u32]) {
        *self.ranked.lock().expect("macOS egress path lock") = Some(ranked.to_vec());
        self.observe();
        *self.observed.lock().expect("macOS egress path lock") = true;
        self.first_path.notify_all();
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn wait_first_path(&self, budget: Duration) {
        let observed = self.observed.lock().expect("macOS egress path lock");
        drop(
            self.first_path
                .wait_timeout_while(observed, budget, |observed| !*observed)
                .expect("macOS egress path lock"),
        );
    }

    /// Re-derives each family's uplink and the interface addresses from the
    /// last path. When the network changed it goes to the Core, and a running
    /// tunnel takes the resolvers of the new uplink.
    fn observe(&self) {
        let Some(ranked) = self.ranked.lock().expect("macOS egress path lock").clone() else {
            return;
        };
        let routes = physical_routes(&ranked);
        *self.routes.write().expect("macOS egress routes lock") = routes;
        // Without the addresses the Core keeps the network it has: an empty
        // one would read as every connection stranded.
        let Some(addresses) = interface_addresses(&ranked) else {
            return;
        };
        let network = EgressNetwork {
            ipv4_uplink: routes.ipv4,
            ipv6_uplink: routes.ipv6,
            addresses,
        };
        let changed = self.feed.send_if_modified(|current| {
            let changed = *current != network;
            if changed {
                *current = network.clone();
            }
            changed
        });
        if changed {
            log::info!(
                "macOS egress uplinks IPv4 {:?}, IPv6 {:?}; {} physical addresses",
                routes.ipv4,
                routes.ipv6,
                network.addresses.len()
            );
            self.follow_resolvers(routes);
        }
    }

    fn follow_resolvers(&self, routes: PhysicalRoutes) {
        let Some(tun) = self.tun.as_ref().filter(|tun| tun.overlay().is_some()) else {
            return;
        };
        let mut uplinks = Vec::new();
        for uplink in [routes.ipv4, routes.ipv6].into_iter().flatten() {
            if !uplinks.contains(&uplink) {
                uplinks.push(uplink);
            }
        }
        match uplink_dns_servers(&uplinks) {
            Ok(servers) => {
                if tun.replace_dns_servers(servers.clone()) {
                    log::info!("macOS TUN egress resolvers follow the uplink: {servers:?}");
                }
            }
            Err(error) => log::warn!("kept the previous macOS TUN egress resolvers: {error}"),
        }
    }

    fn uplink(&self, family: EgressAddressFamily) -> Result<u32, String> {
        if let Some(index) = self
            .routes
            .read()
            .expect("macOS egress routes lock")
            .get(family)
        {
            return Ok(index);
        }
        // A link's routes can settle after the path change that announced
        // it, so a dial without a route of its family looks again, at most
        // once a second. A failed look never keeps a stale choice: a removed
        // adapter's index may be reused, and binding it could send traffic
        // into a tunnel.
        let due = {
            let mut rechecked = self.rechecked.lock().expect("macOS egress recheck lock");
            let due = rechecked.is_none_or(|at| at.elapsed() >= RECHECK_INTERVAL);
            if due {
                *rechecked = Some(Instant::now());
            }
            due
        };
        if due {
            self.observe();
        }
        self.routes
            .read()
            .expect("macOS egress routes lock")
            .get(family)
            .ok_or_else(|| format!("no physical macOS {family:?} route is currently available"))
    }
}

#[derive(Debug)]
pub struct MacosEgressInterfaceBinder {
    network: Arc<PhysicalNetwork>,
    /// `None` binds every dial (standalone probes); otherwise only while the
    /// tunnel is open, so the system proxy alone never bypasses
    /// another VPN the user runs.
    tun: Option<Arc<MacosTunEgress>>,
    /// Set by a dial left unbound because the tunnel was closed. XNU routes
    /// an unbound socket by destination, so the next tunnel recaptures it.
    unbound: AtomicBool,
    /// Keeps `network` current; dropped with the binder.
    #[cfg(target_os = "macos")]
    _monitor: Option<crate::network_monitor::PathMonitor>,
}

impl MacosEgressInterfaceBinder {
    /// Binds every dial: for probes before capture starts. Missing families
    /// fail their dial instead of looping; fails when neither has a physical
    /// default route.
    pub fn capture() -> Result<Self, String> {
        let binder = Self::watching(None);
        let routes = *binder
            .network
            .routes
            .read()
            .expect("macOS egress routes lock");
        if routes.ipv4.is_none() && routes.ipv6.is_none() {
            return Err("no physical macOS default route is available for TUN egress".into());
        }
        Ok(binder)
    }

    /// Binds only while `tun` is active; the Core outlives TUN sessions.
    pub fn tun_gated(tun: Arc<MacosTunEgress>) -> Self {
        Self::watching(Some(tun))
    }

    /// Whether a non-loopback dial went out unbound since the last call.
    pub fn take_unbound(&self) -> bool {
        self.unbound.swap(false, Ordering::AcqRel)
    }

    #[cfg(target_os = "macos")]
    fn watching(tun: Option<Arc<MacosTunEgress>>) -> Self {
        let network = Arc::new(PhysicalNetwork::new(tun.clone()));
        let monitor = crate::network_monitor::PathMonitor::start({
            let network = Arc::clone(&network);
            move |ranked: &[u32]| network.follow(ranked)
        })
        .map_err(|error| log::error!("macOS egress will not find its uplink: {error}"))
        .ok();
        network.wait_first_path(FIRST_PATH_BUDGET);
        Self {
            network,
            tun,
            unbound: AtomicBool::new(false),
            _monitor: monitor,
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn watching(tun: Option<Arc<MacosTunEgress>>) -> Self {
        Self {
            network: Arc::new(PhysicalNetwork::new(tun.clone())),
            tun,
            unbound: AtomicBool::new(false),
        }
    }
}

impl EgressSocketGuard for MacosEgressInterfaceBinder {
    fn protect_socket(
        &self,
        descriptor: EgressSocketDescriptor,
        context: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        if context.remote.is_some_and(|address| address.is_loopback()) {
            return Ok(EgressBinding::unbound());
        }
        if self.tun.as_ref().is_some_and(|tun| tun.overlay().is_none()) {
            self.unbound.store(true, Ordering::Release);
            return Ok(EgressBinding::unbound());
        }
        let interface = self.network.uplink(context.family)?;
        bind_socket(descriptor, context.family, interface)?;
        Ok(EgressBinding::bound(interface))
    }

    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.tun.as_ref().and_then(|tun| tun.overlay())
    }

    fn network(&self) -> Option<watch::Receiver<EgressNetwork>> {
        Some(self.network.feed.subscribe())
    }

    fn sends_echo(&self) -> bool {
        cfg!(unix)
    }

    /// From a ping socket bound to the uplink like every other egress socket.
    #[cfg(unix)]
    fn echo(&self, target: std::net::IpAddr, payload: &[u8], wait: Duration) -> Result<(), String> {
        egrio_platform::ping_socket_echo(target, payload, wait, |socket| {
            self.protect_socket(socket, EgressSocketContext::for_remote(target))
                .map(drop)
        })
    }
}

#[cfg(target_os = "macos")]
fn bind_socket(
    descriptor: EgressSocketDescriptor,
    family: EgressAddressFamily,
    interface: u32,
) -> Result<(), String> {
    let (level, option) = match family {
        EgressAddressFamily::Ipv4 => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
        EgressAddressFamily::Ipv6 => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
    };
    if unsafe {
        libc::setsockopt(
            descriptor,
            level,
            option,
            std::ptr::from_ref(&interface).cast(),
            std::mem::size_of_val(&interface) as libc::socklen_t,
        )
    } != 0
    {
        return Err(format!(
            "bind macOS egress socket to interface {interface}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn bind_socket(_: EgressSocketDescriptor, _: EgressAddressFamily, _: u32) -> Result<(), String> {
    Err("macOS egress binding requires macOS".into())
}

/// The first interface, in the system's preference order, with a physical
/// default route of each family.
#[cfg(target_os = "macos")]
fn physical_routes(ranked: &[u32]) -> PhysicalRoutes {
    let mut routes = PhysicalRoutes::default();
    for &index in ranked {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if routes.ipv4.is_none()
            && route_interface("-inet", &name).as_deref() == Some(name.as_str())
        {
            routes.ipv4 = Some(index);
        }
        if routes.ipv6.is_none()
            && route_interface("-inet6", &name).as_deref() == Some(name.as_str())
        {
            routes.ipv6 = Some(index);
        }
        if routes.ipv4.is_some() && routes.ipv6.is_some() {
            break;
        }
    }
    routes
}
#[cfg(not(target_os = "macos"))]
fn physical_routes(_: &[u32]) -> PhysicalRoutes {
    PhysicalRoutes::default()
}

/// The interface the `name`-scoped default route of `family` leaves through.
#[cfg(target_os = "macos")]
fn route_interface(family: &str, name: &str) -> Option<String> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", family, "-ifscope", name, "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_interface(&String::from_utf8_lossy(&output.stdout))
}
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_route_interface(output: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find_map(|(key, value)| (key == "interface").then(|| value.trim().to_string()))
}

/// The non-link-local addresses of the `ranked` interfaces; `None` when
/// getifaddrs fails.
#[cfg(target_os = "macos")]
fn interface_addresses(ranked: &[u32]) -> Option<Vec<(u32, std::net::IpAddr)>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut addresses = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
        if !ranked.contains(&index) {
            continue;
        }
        let address = match i32::from(unsafe { (*entry.ifa_addr).sa_family }) {
            libc::AF_INET => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let link_local = match address {
            IpAddr::V4(address) => address.is_link_local(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        };
        if !link_local {
            addresses.push((index, address));
        }
    }
    unsafe { libc::freeifaddrs(list) };
    addresses.sort_unstable();
    addresses.dedup();
    Some(addresses)
}
#[cfg(not(target_os = "macos"))]
fn interface_addresses(_: &[u32]) -> Option<Vec<(u32, std::net::IpAddr)>> {
    None
}

#[cfg(target_os = "macos")]
fn uplink_dns_servers(uplinks: &[u32]) -> Result<Vec<SocketAddr>, String> {
    crate::dns_snapshot::capture_macos_uplink_dns_servers(uplinks)
}
#[cfg(not(target_os = "macos"))]
fn uplink_dns_servers(_: &[u32]) -> Result<Vec<SocketAddr>, String> {
    Err("macOS resolver discovery requires macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_route_interface_is_read_from_route_get() {
        assert_eq!(
            parse_route_interface("route to: default\n  interface: en0\n"),
            Some("en0".into())
        );
        assert_eq!(
            parse_route_interface("route: writing to routing socket"),
            None
        );
    }

    #[test]
    fn a_closed_tunnel_records_its_unbound_dials_except_loopback() {
        let binder = MacosEgressInterfaceBinder::tun_gated(Arc::new(MacosTunEgress::default()));
        let loopback = EgressSocketContext::for_remote([127, 0, 0, 1].into());
        let binding = binder.protect_socket(0, loopback).unwrap();
        assert_eq!(binding.interface_index, None);
        assert!(!binder.take_unbound(), "loopback is never recaptured");

        let multi = EgressSocketContext::multi_destination(EgressAddressFamily::Ipv4);
        let binding = binder.protect_socket(0, multi).unwrap();
        assert_eq!(binding.interface_index, None);
        assert!(binder.take_unbound());
        assert!(!binder.take_unbound());
    }

    #[test]
    fn a_running_tunnel_takes_new_resolvers_and_keeps_its_ipv6_posture() {
        let tun = MacosTunEgress::default();
        let resolver = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 53);
        assert!(!tun.replace_dns_servers(vec![resolver("192.0.2.53")]));
        tun.activate(CaptureEgressOverlay {
            dns_servers: vec![resolver("192.0.2.53")],
            ipv6_enabled: false,
        });
        assert!(!tun.replace_dns_servers(vec![resolver("192.0.2.53")]));
        assert!(tun.replace_dns_servers(vec![resolver("198.51.100.53")]));
        let overlay = tun.overlay().unwrap();
        assert_eq!(overlay.dns_servers, vec![resolver("198.51.100.53")]);
        assert!(!overlay.ipv6_enabled);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_path_monitor_reports_the_machines_network() {
        let binder = MacosEgressInterfaceBinder::tun_gated(Arc::new(MacosTunEgress::default()));
        let ranked = binder
            .network
            .ranked
            .lock()
            .unwrap()
            .clone()
            .expect("the first path arrives at start");
        let network = binder.network().unwrap().borrow().clone();
        for (index, _) in &network.addresses {
            assert!(ranked.contains(index));
        }
        for uplink in [network.ipv4_uplink, network.ipv6_uplink]
            .into_iter()
            .flatten()
        {
            assert!(ranked.contains(&uplink));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn echo_leaves_from_a_ping_socket() {
        let binder = MacosEgressInterfaceBinder::tun_gated(Arc::new(MacosTunEgress::default()));
        assert!(binder.sends_echo());
        binder
            .echo(
                std::net::Ipv4Addr::LOCALHOST.into(),
                b"egrio echo",
                Duration::from_secs(2),
            )
            .expect("loopback answers the echo");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_egress_socket_binding_is_observable_through_getsockopt() {
        use std::os::fd::AsRawFd;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let c_name = std::ffi::CString::new("lo0").unwrap();
        let interface = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        assert_ne!(interface, 0);
        bind_socket(socket.as_raw_fd(), EgressAddressFamily::Ipv4, interface).unwrap();
        let mut observed = 0u32;
        let mut size = std::mem::size_of_val(&observed) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    std::ptr::from_mut(&mut observed).cast(),
                    &mut size,
                )
            },
            0
        );
        assert_eq!(observed, interface);
    }
}
