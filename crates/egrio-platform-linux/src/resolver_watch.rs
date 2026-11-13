//! Notices when systemd-resolved's resolvers change. resolved rewrites its
//! uplink `resolv.conf` whenever a link's DNS servers change — a new network,
//! a lost one, or a DHCP update — so an inotify watch on its runtime directory
//! is the change signal, with no polling and no D-Bus client.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const RESOLVED_RUNTIME_DIR: &str = "/run/systemd/resolve";

/// Runs `on_change` on a background thread after each change in resolved's
/// runtime directory, until dropped.
#[derive(Debug)]
pub(crate) struct ResolverWatch {
    stopped: Arc<AtomicBool>,
    /// An eventfd the thread waits on beside the inotify fd; dropping the
    /// watch writes it, so the thread sleeps without a timeout until a change
    /// or the drop.
    #[cfg(target_os = "linux")]
    stop: Arc<std::os::fd::OwnedFd>,
}

impl ResolverWatch {
    #[cfg(target_os = "linux")]
    pub(crate) fn start(on_change: impl Fn() + Send + 'static) -> Result<Self, String> {
        Self::watch(RESOLVED_RUNTIME_DIR, on_change)
    }

    #[cfg(target_os = "linux")]
    fn watch(directory: &str, on_change: impl Fn() + Send + 'static) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw < 0 {
            return Err(format!(
                "inotify_init1: {}",
                std::io::Error::last_os_error()
            ));
        }
        let inotify = unsafe { OwnedFd::from_raw_fd(raw) };
        let dir = std::ffi::CString::new(directory).map_err(|error| error.to_string())?;
        let mask = libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE;
        if unsafe { libc::inotify_add_watch(inotify.as_raw_fd(), dir.as_ptr(), mask) } < 0 {
            return Err(format!(
                "watch {directory}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(format!("eventfd: {}", std::io::Error::last_os_error()));
        }
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let stopped = Arc::new(AtomicBool::new(false));
        let (thread_stop, thread_stopped) = (Arc::clone(&stop), Arc::clone(&stopped));
        std::thread::Builder::new()
            .name("egrio-resolver-watch".into())
            .spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    let mut ready = [
                        libc::pollfd {
                            fd: inotify.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: thread_stop.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];
                    if unsafe { libc::poll(ready.as_mut_ptr(), 2, -1) } < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        break;
                    }
                    if ready[1].revents != 0 || thread_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    if ready[0].revents & libc::POLLIN == 0 {
                        continue;
                    }
                    // resolved writes several files per change; let it finish,
                    // then take every queued event as one change.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    while unsafe {
                        libc::read(
                            inotify.as_raw_fd(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                        )
                    } > 0
                    {}
                    if thread_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    on_change();
                }
            })
            .map_err(|error| format!("start the resolver watch: {error}"))?;
        Ok(Self { stopped, stop })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn start(_on_change: impl Fn() + Send + 'static) -> Result<Self, String> {
        Err(format!("{RESOLVED_RUNTIME_DIR} exists only on Linux"))
    }
}

impl Drop for ResolverWatch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let one = 1u64.to_ne_bytes();
            unsafe { libc::write(self.stop.as_raw_fd(), one.as_ptr().cast(), one.len()) };
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_change_runs_the_callback_and_a_drop_ends_the_thread() {
        let directory =
            std::env::temp_dir().join(format!("egrio-resolver-watch-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (changed, changes) = mpsc::channel();
        let watch = ResolverWatch::watch(directory.to_str().unwrap(), move || {
            let _ = changed.send(());
        })
        .unwrap();
        std::fs::write(
            directory.join("resolv.conf"),
            "nameserver 192.0.2.1
",
        )
        .unwrap();
        changes
            .recv_timeout(Duration::from_secs(5))
            .expect("the change is noticed");
        drop(watch);
        // The thread drops the callback, and the sender with it, as it ends.
        assert_eq!(
            changes.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
