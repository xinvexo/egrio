//! The Core egress guard of a Linux desktop that runs TUN mode through the
//! service.

use std::os::fd::BorrowedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use egrio_core::{
    CaptureEgressOverlay, EgressBinding, EgressNetwork, EgressSocketContext,
    EgressSocketDescriptor, EgressSocketGuard,
};
use egrio_platform_linux::{LinuxTunEgress, LINUX_MARK_SOCKET};

use super::marking::MarkClient;

/// Has the service mark every new Core socket, whether or not TUN is on, so
/// the TUN's policy routing and kill switch let it past and no connection is
/// recaptured when TUN starts.
///
/// While TUN is off, a socket the service cannot mark (it is not installed,
/// restarting, or refuses this user) dials unmarked and is recorded, so the
/// host renews those connections once it turns TUN on. While TUN is on, an
/// unmarked socket would be captured by its own TUN, so the dial fails.
#[derive(Debug)]
pub struct ServiceMarkingSocketGuard {
    marks: MarkClient,
    egress: Arc<LinuxTunEgress>,
    unmarked: AtomicBool,
}

impl ServiceMarkingSocketGuard {
    pub fn new(egress: Arc<LinuxTunEgress>) -> Self {
        Self::with_socket(LINUX_MARK_SOCKET, egress)
    }

    pub fn with_socket(path: impl Into<PathBuf>, egress: Arc<LinuxTunEgress>) -> Self {
        Self {
            marks: MarkClient::new(path),
            egress,
            unmarked: AtomicBool::new(false),
        }
    }

    /// Whether a socket dialed unmarked since the last call.
    pub fn take_unmarked(&self) -> bool {
        self.unmarked.swap(false, Ordering::AcqRel)
    }
}

impl EgressSocketGuard for ServiceMarkingSocketGuard {
    fn protect_socket(
        &self,
        descriptor: EgressSocketDescriptor,
        _context: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        // SAFETY: the Core keeps the socket open for the whole call.
        let socket = unsafe { BorrowedFd::borrow_raw(descriptor) };
        match self.marks.mark(socket) {
            Ok(()) => Ok(EgressBinding::unbound()),
            Err(error) if self.egress.overlay().is_some() => Err(format!(
                "mark the Core socket through the Egrio service: {error}"
            )),
            Err(_) => {
                self.unmarked.store(true, Ordering::Release);
                Ok(EgressBinding::unbound())
            }
        }
    }

    fn capture_overlay(&self) -> Option<Arc<CaptureEgressOverlay>> {
        self.egress.overlay()
    }

    fn network(&self) -> Option<tokio::sync::watch::Receiver<EgressNetwork>> {
        Some(self.egress.network())
    }

    fn sends_echo(&self) -> bool {
        true
    }

    /// From a ping socket the service marks like every other egress socket.
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

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use egrio_core::EgressAddressFamily;

    use super::*;

    fn context() -> EgressSocketContext {
        EgressSocketContext {
            family: EgressAddressFamily::Ipv4,
            remote: None,
        }
    }

    fn tcp_socket() -> OwnedFd {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    #[test]
    fn without_the_service_sockets_dial_unmarked_until_tun_is_on() {
        let egress = Arc::new(LinuxTunEgress::default());
        let absent = std::env::temp_dir().join(format!("egrio-no-service-{}", std::process::id()));
        let guard = ServiceMarkingSocketGuard::with_socket(absent, egress.clone());
        let socket = tcp_socket();
        assert!(guard.protect_socket(socket.as_raw_fd(), context()).is_ok());
        assert!(guard.take_unmarked());
        assert!(!guard.take_unmarked());

        egress.activate(vec!["192.0.2.53:53".parse().unwrap()], true);
        let error = guard
            .protect_socket(socket.as_raw_fd(), context())
            .unwrap_err();
        assert!(error.contains("Egrio service"), "{error}");
        assert!(!guard.take_unmarked());
        assert_eq!(
            guard.capture_overlay().unwrap().dns_servers,
            vec!["192.0.2.53:53".parse::<std::net::SocketAddr>().unwrap()]
        );
    }
}
