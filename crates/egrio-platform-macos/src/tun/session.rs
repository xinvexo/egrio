//! One TUN session of the macOS service: the utun, the routes that send each
//! family into it less the excluded prefixes and reject the fake-IP pool on
//! the physical interfaces, and the tunnel's resolver as the system's default.
//! A routing socket follows the physical interfaces while the session lasts.
//! Dropping the session withdraws the resolver first, then the routes; the
//! utun itself goes once every descriptor of it is closed, the desktop's
//! included.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread::JoinHandle;

use egrio_runtime::IpPrefix;

use super::interface::UtunInterface;
use super::resolver::TunnelResolver;
use super::routes::{remove_leftovers, TunnelRoutes};

/// What the desktop gets for an open session.
#[derive(Debug)]
pub struct MacosTunOpen {
    /// A descriptor of the utun socket: one packet per read or write, behind
    /// the 4-byte protocol family.
    pub socket: OwnedFd,
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
}

#[derive(Debug)]
struct State {
    // Dropped in this order: the resolver, then the routes; the resolver is
    // held only for that.
    _resolver: TunnelResolver,
    routes: TunnelRoutes,
}

#[derive(Debug)]
pub struct MacosTunSession {
    state: Arc<Mutex<State>>,
    interface: UtunInterface,
    watcher: Option<InterfaceWatcher>,
}

impl MacosTunSession {
    /// Opens the tunnel: creates the utun with `mtu`, routes each family into
    /// it less the excluded prefixes, rejects the fake-IP prefixes on the
    /// physical interfaces, then makes the virtual resolver the system's
    /// default. Fails without a physical default route, since nothing
    /// captured could leave.
    pub fn open(
        mtu: u32,
        excluded_prefixes: &[IpPrefix],
        fake_ip_prefixes: &[IpPrefix],
    ) -> Result<(Self, MacosTunOpen), String> {
        remove_leftovers();
        drop(crate::MacosEgressInterfaceBinder::capture()?);
        let interface = UtunInterface::create(mtu)?;
        let socket = interface
            .duplicate()
            .map_err(|error| format!("duplicate the utun socket: {error}"))?;
        let mut routes = TunnelRoutes::new(
            interface.name(),
            excluded_prefixes.to_vec(),
            fake_ip_prefixes.to_vec(),
        );
        routes.reconcile()?;
        let resolver = TunnelResolver::publish()?;
        let state = Arc::new(Mutex::new(State {
            _resolver: resolver,
            routes,
        }));
        let watcher =
            (!fake_ip_prefixes.is_empty()).then(|| InterfaceWatcher::start(Arc::downgrade(&state)));
        let open = MacosTunOpen {
            socket,
            interface_name: interface.name().into(),
            interface_index: interface.index(),
            mtu,
        };
        log::info!("macOS TUN {} open", interface.name());
        Ok((
            Self {
                state,
                interface,
                watcher: watcher.flatten(),
            },
            open,
        ))
    }

    pub fn interface_name(&self) -> &str {
        self.interface.name()
    }

    /// Removes the routes a previous service process left.
    pub fn remove_leftovers() {
        remove_leftovers();
    }

    /// Replaces what stays outside the tunnel.
    pub fn set_excluded_prefixes(&self, prefixes: &[IpPrefix]) -> Result<(), String> {
        self.lock().routes.set_prefixes(prefixes.to_vec())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for MacosTunSession {
    fn drop(&mut self) {
        drop(self.watcher.take());
        log::info!("macOS TUN {} closed", self.interface.name());
    }
}

/// Follows the physical interfaces while the tunnel runs: a routing socket
/// (route(4)) reports an interface going up or down and an address added or
/// removed (`RTM_IFINFO`, `RTM_NEWADDR`, `RTM_DELADDR`), and the routes
/// rejecting the fake-IP pool are made to match the interfaces and addresses
/// then, so a link that comes up later is covered too. Shutting the socket
/// down ends the read the thread waits in at once.
#[derive(Debug)]
struct InterfaceWatcher {
    socket: Arc<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

impl InterfaceWatcher {
    fn start(state: Weak<Mutex<State>>) -> Option<Self> {
        // SAFETY: plain socket creation.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            log::warn!(
                "macOS TUN will not follow the physical interfaces: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }
        // SAFETY: a fresh descriptor nothing else owns.
        let socket = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let thread = std::thread::Builder::new()
            .name("egrio-tun-interfaces".into())
            .spawn({
                let socket = Arc::clone(&socket);
                move || Self::run(&socket, &state)
            })
            .map_err(|error| {
                log::warn!("macOS TUN will not follow the physical interfaces: {error}")
            })
            .ok()?;
        Some(Self {
            socket,
            thread: Some(thread),
        })
    }

    fn run(socket: &OwnedFd, state: &Weak<Mutex<State>>) {
        let mut buffer = [0u8; 2048];
        loop {
            // SAFETY: reads at most `buffer.len()` bytes into the buffer.
            let read =
                unsafe { libc::read(socket.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            let changed = match read {
                // Shut down: the session is closing.
                0 => return,
                ..0 => match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => false,
                    // Messages were dropped, an interface change maybe among
                    // them.
                    Some(libc::ENOBUFS) => true,
                    _ => {
                        log::warn!(
                            "macOS TUN stops following the physical interfaces: {}",
                            std::io::Error::last_os_error()
                        );
                        return;
                    }
                },
                // Every message starts with its length, version and type
                // (`if_msghdr`, `ifa_msghdr`).
                1..4 => false,
                _ => matches!(
                    libc::c_int::from(buffer[3]),
                    libc::RTM_IFINFO | libc::RTM_NEWADDR | libc::RTM_DELADDR
                ),
            };
            if !changed {
                continue;
            }
            let Some(state) = state.upgrade() else {
                return;
            };
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Err(error) = state.routes.reconcile() {
                log::warn!("macOS TUN routes after an interface change: {error}");
            }
        }
    }
}

impl Drop for InterfaceWatcher {
    fn drop(&mut self) {
        // SAFETY: shuts down a socket this watcher holds open.
        unsafe { libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
