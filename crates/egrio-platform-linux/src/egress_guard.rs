use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use egrio_core::{
    CaptureEgressOverlay, EgressBinding, EgressNetwork, EgressSocketContext,
    EgressSocketDescriptor, EgressSocketGuard,
};
use tokio::sync::watch;

/// Egress state that follows the TUN: the physical resolvers captured when the
/// device opens, before the DNS capability points the system resolver at
/// Egrio, and withdrawn once the device is restored. The packet-capture
/// adapter that opens the TUN (in process, or the desktop's adapter over the
/// Linux service) activates it; the Core's egress guard reads it.
///
/// While active it re-reads the resolvers whenever systemd-resolved changes
/// them: after a network switch the first network's resolvers are usually
/// unreachable, and the Core would otherwise keep querying them.
///
/// It also follows the physical network for the Core's guard, with or
/// without TUN, from first use on (see `network_watch.rs`).
#[derive(Debug)]
pub struct LinuxTunEgress {
    overlay: Arc<RwLock<Option<Arc<CaptureEgressOverlay>>>>,
    watch: Mutex<Option<crate::resolver_watch::ResolverWatch>>,
    network: Arc<watch::Sender<EgressNetwork>>,
    /// Keeps `network` current; started on first use. Without it the Core
    /// sees no network changes.
    network_watch: OnceLock<Option<crate::network_watch::NetworkWatch>>,
}

impl Default for LinuxTunEgress {
    fn default() -> Self {
        Self {
            overlay: Arc::default(),
            watch: Mutex::default(),
            network: Arc::new(watch::Sender::new(EgressNetwork::default())),
            network_watch: OnceLock::new(),
        }
    }
}

impl LinuxTunEgress {
    /// The physical network as last observed, updated on every change.
    pub fn network(&self) -> watch::Receiver<EgressNetwork> {
        self.network_watch.get_or_init(|| {
            follow_network(&self.network);
            let network = Arc::clone(&self.network);
            crate::network_watch::NetworkWatch::start(move || follow_network(&network))
                .map_err(|error| {
                    log::warn!("Linux egress will not follow network changes: {error}")
                })
                .ok()
        });
        self.network.subscribe()
    }

    /// Takes over Core egress for the TUN: these physical resolvers, and
    /// IPv6 only where the TUN carries it.
    pub fn activate(&self, dns_servers: Vec<SocketAddr>, ipv6_enabled: bool) {
        self.set(Some(Arc::new(CaptureEgressOverlay {
            dns_servers,
            ipv6_enabled,
        })));
        let overlay = Arc::clone(&self.overlay);
        // Best effort: without the watch the resolvers stay as captured,
        // which is what the device was opened with.
        let watch =
            crate::resolver_watch::ResolverWatch::start(move || refresh_resolvers(&overlay)).ok();
        *self.watch.lock().expect("Linux TUN egress watch lock") = watch;
    }

    pub fn deactivate(&self) {
        self.watch
            .lock()
            .expect("Linux TUN egress watch lock")
            .take();
        self.set(None);
    }

    /// The TUN's egress overlay; `None` while no TUN is open.
    pub fn overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.overlay.read().expect("Linux TUN egress lock").clone()
    }

    fn set(&self, overlay: Option<Arc<CaptureEgressOverlay>>) {
        *self.overlay.write().expect("Linux TUN egress lock") = overlay;
    }
}

/// Publishes the network when it changed.
fn follow_network(network: &watch::Sender<EgressNetwork>) {
    let Some(current) = crate::network_watch::observe_network() else {
        return;
    };
    let changed = network.send_if_modified(|published| {
        let changed = *published != current;
        if changed {
            *published = current.clone();
        }
        changed
    });
    if changed {
        log::info!(
            "Linux egress uplinks IPv4 {:?}, IPv6 {:?}; {} addresses on them",
            current.ipv4_uplink,
            current.ipv6_uplink,
            current.addresses.len()
        );
    }
}

/// Takes the resolvers systemd-resolved now lists, unless none is usable: an
/// empty set would send DIRECT resolution back into the tunnel. A refresh
/// that races a deactivation finds no overlay and leaves it withdrawn.
fn refresh_resolvers(overlay: &RwLock<Option<Arc<CaptureEgressOverlay>>>) {
    let Ok(dns_servers) = crate::dns::linux_physical_dns_servers() else {
        return;
    };
    let mut current = overlay.write().expect("Linux TUN egress lock");
    if let Some(active) = current.as_ref() {
        if active.dns_servers != dns_servers {
            *current = Some(Arc::new(CaptureEgressOverlay {
                dns_servers,
                ipv6_enabled: active.ipv6_enabled,
            }));
        }
    }
}

/// Marks every Core TCP/UDP/DNS socket before connect, whether or not the TUN
/// is up: the mark only matters to the TUN's policy-routing rules, which match
/// packets without it, so a Core that serves the system proxy alone routes as
/// before and none of its connections is recaptured when TUN starts. A
/// setsockopt failure fails the dial; there is no unprotected retry.
#[derive(Debug)]
pub struct LinuxTunEgressSocketGuard {
    mark: u32,
    egress: Arc<LinuxTunEgress>,
}

impl LinuxTunEgressSocketGuard {
    pub(crate) fn new(mark: u32, egress: Arc<LinuxTunEgress>) -> Result<Self, String> {
        if mark == 0 {
            return Err("Linux TUN egress mark must be nonzero".into());
        }
        Ok(Self { mark, egress })
    }
}

impl EgressSocketGuard for LinuxTunEgressSocketGuard {
    fn protect_socket(
        &self,
        descriptor: EgressSocketDescriptor,
        _context: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        #[cfg(target_os = "linux")]
        {
            // linux/include/uapi/asm-generic/socket.h SO_MARK; socket(7).
            let result = unsafe {
                libc::setsockopt(
                    descriptor,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    std::ptr::from_ref(&self.mark).cast(),
                    std::mem::size_of_val(&self.mark) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(format!(
                    "protect Linux TUN egress socket with SO_MARK: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(EgressBinding::unbound())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (descriptor, self.mark);
            Err("Linux TUN socket protection is only available on Linux".into())
        }
    }

    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.egress.overlay()
    }

    fn network(&self) -> Option<watch::Receiver<EgressNetwork>> {
        Some(self.egress.network())
    }

    fn sends_echo(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn coalesce_datagrams(&self, descriptor: EgressSocketDescriptor) -> bool {
        #[cfg(target_os = "linux")]
        {
            crate::udp_offload::enable(descriptor)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = descriptor;
            false
        }
    }

    fn recv_coalesced(
        &self,
        descriptor: EgressSocketDescriptor,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, usize)> {
        #[cfg(target_os = "linux")]
        {
            crate::udp_offload::recv(descriptor, buffer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (descriptor, buffer);
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    fn send_segmented(
        &self,
        descriptor: EgressSocketDescriptor,
        payload: &[u8],
        segment: usize,
        remote: SocketAddr,
    ) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            crate::udp_offload::send_segmented(descriptor, payload, segment, remote)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (descriptor, payload, segment, remote);
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// From a ping socket carrying the egress mark like every other egress
    /// socket.
    #[cfg(target_os = "linux")]
    fn echo(
        &self,
        target: std::net::IpAddr,
        payload: &[u8],
        wait: std::time::Duration,
    ) -> Result<(), String> {
        egrio_platform::ping_socket_echo(target, payload, wait, |socket| {
            self.protect_socket(socket, EgressSocketContext::for_remote(target))
                .map(drop)
        })
    }
}
