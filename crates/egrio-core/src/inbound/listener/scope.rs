//! The local mixed listener's address scope: loopback-only or LAN-wide on
//! its current port, changed live without dropping loopback sessions.

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const SCOPE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ListenerScopeUpdateReport {
    pub requested_addr: SocketAddr,
    pub effective_addr: Option<SocketAddr>,
    /// Whether the requested binding replaced the previous effective binding.
    pub changed: bool,
    pub closed_non_loopback_sessions: usize,
    pub cleanup_complete: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub(super) struct ScopeChange {
    pub address: SocketAddr,
    pub reply: oneshot::Sender<Result<ListenerScopeUpdateReport, String>>,
}

pub(super) struct ListenerScope {
    pub listener: Option<TcpListener>,
    address: SocketAddr,
    loopback_only: bool,
    remote_cancel: CancellationToken,
    remote_tasks: TaskTracker,
    retiring: Option<TaskTracker>,
}

impl ListenerScope {
    pub fn new(listener: TcpListener) -> std::io::Result<Self> {
        let address = listener.local_addr()?;
        Ok(Self {
            listener: Some(listener),
            address,
            loopback_only: is_loopback(address.ip()),
            remote_cancel: CancellationToken::new(),
            remote_tasks: TaskTracker::new(),
            retiring: None,
        })
    }

    pub fn accepts(&self, peer: SocketAddr) -> bool {
        !self.loopback_only || is_loopback(peer.ip())
    }

    pub fn session_scope(&self, peer: SocketAddr) -> Option<(CancellationToken, TaskTracker)> {
        (!is_loopback(peer.ip())).then(|| (self.remote_cancel.clone(), self.remote_tasks.clone()))
    }

    pub fn pending_cleanup(&self) -> Option<TaskTracker> {
        self.retiring.clone()
    }

    pub async fn reconfigure(
        &mut self,
        requested: SocketAddr,
    ) -> Result<ListenerScopeUpdateReport, String> {
        self.reconfigure_with(requested, TcpListener::bind).await
    }

    async fn reconfigure_with<F, Fut>(
        &mut self,
        requested: SocketAddr,
        mut bind: F,
    ) -> Result<ListenerScopeUpdateReport, String>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<TcpListener>>,
    {
        if requested.port() == 0 || requested.port() != self.address.port() {
            return Err("listener scope updates cannot change the port".into());
        }
        if self.retiring.as_ref().is_some_and(TaskTracker::is_empty) {
            self.retiring = None;
        }
        let previous = self.listener.as_ref().map(|_| self.address);
        if self.retiring.is_some() {
            if previous == Some(requested) {
                return Ok(ListenerScopeUpdateReport {
                    requested_addr: requested,
                    effective_addr: previous,
                    changed: false,
                    closed_non_loopback_sessions: 0,
                    cleanup_complete: false,
                    error: Some("old LAN connection cleanup is pending".into()),
                });
            }
            return Err("previous listener scope cleanup is still pending".into());
        }
        if previous == Some(requested) {
            return Ok(ListenerScopeUpdateReport {
                requested_addr: requested,
                effective_addr: previous,
                changed: false,
                closed_non_loopback_sessions: 0,
                cleanup_complete: true,
                error: None,
            });
        }

        let previous_loopback_only = self.loopback_only;
        let cancelled_non_loopback_sessions = if is_loopback(requested.ip()) {
            // The accept actor is the admission owner: no accepted remote
            // stream can be spawned between this fence and the new binding.
            self.loopback_only = true;
            self.remote_cancel.cancel();
            self.remote_tasks.close();
            let retiring = self.remote_tasks.clone();
            let count = retiring.len();
            self.retiring = Some(retiring);
            self.remote_cancel = CancellationToken::new();
            self.remote_tasks = TaskTracker::new();
            count
        } else {
            0
        };

        // The old socket must be released before a same-port scope change.
        // Accepted streams are owned by the generation, not this socket.
        self.listener.take();
        let error = match bind(requested).await {
            Ok(listener) => {
                self.listener = Some(listener);
                self.address = requested;
                self.loopback_only = is_loopback(requested.ip());
                None
            }
            Err(error) => {
                let message = format!("failed to bind requested listener {requested}: {error}");
                match bind(self.address).await {
                    Ok(listener) => {
                        self.listener = Some(listener);
                        self.loopback_only = previous_loopback_only;
                        Some(format!("{message}; previous binding restored"))
                    }
                    Err(restore) => Some(format!(
                        "{message}; failed to restore listener {}: {restore}",
                        self.address
                    )),
                }
            }
        };
        let cleanup_complete = match self.retiring.as_ref() {
            Some(tasks) => timeout(SCOPE_CLEANUP_TIMEOUT, tasks.wait()).await.is_ok(),
            None => true,
        };
        let closed_non_loopback_sessions = cancelled_non_loopback_sessions
            .saturating_sub(self.retiring.as_ref().map_or(0, TaskTracker::len));
        if cleanup_complete {
            self.retiring = None;
        }
        let error = if cleanup_complete {
            error
        } else {
            Some(match error {
                Some(error) => format!("{error}; old LAN connection cleanup is pending"),
                None => "listener scope applied; old LAN connection cleanup is pending".into(),
            })
        };
        let effective_addr = self.listener.as_ref().map(|_| self.address);
        Ok(ListenerScopeUpdateReport {
            requested_addr: requested,
            effective_addr,
            changed: effective_addr == Some(requested) && previous != effective_addr,
            closed_non_loopback_sessions,
            cleanup_complete,
            error,
        })
    }
}

impl Drop for ListenerScope {
    fn drop(&mut self) {
        self.remote_cancel.cancel();
        self.remote_tasks.close();
    }
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
        || matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::super::{CoreInbound, CoreSessionManager, CoreSessionStartConfig};
    use super::*;
    use crate::egress::NativeCoreEgressConfig;
    use crate::profile::RuntimeProfile;
    use crate::status::NativeCoreState;

    async fn scope() -> ListenerScope {
        ListenerScope::new(TcpListener::bind("127.0.0.1:0").await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn same_binding_and_port_rejection_do_not_touch_the_listener() {
        let mut scope = scope().await;
        let address = scope.address;
        let report = scope
            .reconfigure_with(address, |_| async {
                panic!("same binding must not rebind")
            })
            .await
            .unwrap();
        assert!(!report.changed);
        assert!(report.cleanup_complete);
        let mut wrong_port = address;
        wrong_port.set_port(if address.port() == 65535 {
            1
        } else {
            address.port() + 1
        });
        assert!(scope.reconfigure(wrong_port).await.is_err());
        TcpStream::connect(address).await.unwrap();
    }

    #[tokio::test]
    async fn narrowing_cancels_and_joins_remote_handshakes_without_waiting_for_local_flows() {
        let mut scope = scope().await;
        let local = scope.address;
        // A memory admission fixture models wildcard scope while the actual
        // test listener remains loopback-only throughout.
        scope.address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, local.port()));
        scope.loopback_only = false;
        let remote: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let (cancel, tracker) = scope.session_scope(remote).unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let completed = finished.clone();
        tracker.spawn(async move {
            cancel.cancelled().await;
            completed.store(true, Ordering::SeqCst);
        });
        assert!(scope
            .session_scope("127.0.0.2:1234".parse().unwrap())
            .is_none());
        assert!(scope
            .session_scope("[::ffff:127.0.0.1]:1234".parse().unwrap())
            .is_none());
        let report = scope.reconfigure(local).await.unwrap();
        assert!(report.changed && report.cleanup_complete);
        assert_eq!(report.closed_non_loopback_sessions, 1);
        assert!(finished.load(Ordering::SeqCst));
        assert!(!scope.accepts(remote));
        assert!(scope.accepts("127.0.0.2:1234".parse().unwrap()));
    }

    #[tokio::test]
    async fn failed_bind_restores_the_previous_binding_and_reports_no_application() {
        let mut scope = scope().await;
        let old = scope.address;
        let target = SocketAddr::from((Ipv6Addr::LOCALHOST, old.port()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let report = scope
            .reconfigure_with(target, |address| {
                let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if first {
                        Err(std::io::ErrorKind::AddrInUse.into())
                    } else {
                        TcpListener::bind(address).await
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(report.effective_addr, Some(old));
        assert!(!report.changed);
        assert!(report.error.unwrap().contains("previous binding restored"));
        TcpStream::connect(old).await.unwrap();
    }

    #[tokio::test]
    async fn failed_restore_leaves_a_recoverable_listener_scope_without_random_port_fallback() {
        let mut scope = scope().await;
        let target = SocketAddr::from((Ipv6Addr::LOCALHOST, scope.address.port()));
        let report = scope
            .reconfigure_with(target, |_| async {
                Err(std::io::ErrorKind::AddrInUse.into())
            })
            .await
            .unwrap();
        assert_eq!(report.effective_addr, None);
        assert!(!report.changed);
        assert!(report.error.unwrap().contains("failed to restore listener"));
        let restored = scope.reconfigure(target).await.unwrap();
        assert_eq!(restored.effective_addr, Some(target));
        TcpStream::connect(target).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_timeout_retains_the_old_tasks_and_blocks_another_scope_change() {
        let mut scope = scope().await;
        let local = scope.address;
        let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, local.port()));
        scope.address = wildcard;
        scope.loopback_only = false;
        let held = scope
            .remote_tasks
            .track_future(std::future::pending::<()>());
        let applied = scope.reconfigure(local).await.unwrap();
        assert!(applied.changed);
        assert!(!applied.cleanup_complete);
        assert_eq!(applied.closed_non_loopback_sessions, 0);
        assert!(!scope.reconfigure(local).await.unwrap().cleanup_complete);
        assert!(scope.reconfigure(wildcard).await.is_err());
        drop(held);
        assert!(scope.reconfigure(local).await.unwrap().cleanup_complete);
    }

    async fn manager() -> CoreSessionManager {
        let manager = CoreSessionManager::default();
        manager
            .start_with_config(CoreSessionStartConfig {
                profile: RuntimeProfile::new("listener-scope-fixture"),
                egress: NativeCoreEgressConfig::default(),
                listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                dns_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                inbound: CoreInbound::Mixed,
                hysteria2: None,
                socket_guard: None,
            })
            .await
            .unwrap();
        manager
    }

    async fn wait_stopped(manager: &CoreSessionManager) {
        manager.stop();
        timeout(Duration::from_secs(2), async {
            while manager.status().state != NativeCoreState::Stopped {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listener generation stops");
    }

    #[tokio::test]
    async fn manager_scope_rebind_keeps_core_rules_generation_and_accepted_loopback_stream() {
        let manager = manager().await;
        let before = manager.status();
        let old: SocketAddr = before.listen_addr.as_ref().unwrap().parse().unwrap();
        let generation = manager.inner.lock().unwrap().generation;
        let runtime = manager
            .inner
            .lock()
            .unwrap()
            .device
            .as_ref()
            .unwrap()
            .pinned_runtime();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = source.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = source.accept().await.unwrap();
            let mut block = [0; 32];
            loop {
                let size = stream.read(&mut block).await.unwrap();
                if size == 0 {
                    break;
                }
                stream.write_all(&block[..size]).await.unwrap();
            }
        });
        let mut stream = TcpStream::connect(old).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.unwrap());
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        stream.write_all(b"before").await.unwrap();
        let mut echoed = [0; 6];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"before");
        let next = SocketAddr::from((Ipv6Addr::LOCALHOST, old.port()));
        let report = manager.reconfigure_listener_scope(next).await.unwrap();
        assert!(report.changed && report.cleanup_complete && report.error.is_none());
        assert_eq!(report.closed_non_loopback_sessions, 0);
        let after = manager.status();
        assert_eq!(after.state, NativeCoreState::Running);
        assert_eq!(after.listen_addr, Some(next.to_string()));
        assert_eq!(after.dns_listen_addr, before.dns_listen_addr);
        let inner = manager.inner.lock().unwrap();
        assert_eq!(inner.generation, generation);
        assert!(std::ptr::eq(
            runtime.rule_engine(),
            inner
                .device
                .as_ref()
                .unwrap()
                .pinned_runtime()
                .rule_engine()
        ));
        drop(inner);
        stream.write_all(b"after!").await.unwrap();
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"after!");
        let fresh = TcpStream::connect(next).await.unwrap();
        drop(fresh);
        drop(stream);
        peer.await.unwrap();
        wait_stopped(&manager).await;
    }

    #[tokio::test]
    async fn an_accepted_change_finishes_after_the_requester_drops_its_reply() {
        let manager = manager().await;
        let old: SocketAddr = manager.status().listen_addr.unwrap().parse().unwrap();
        let next = SocketAddr::from((Ipv6Addr::LOCALHOST, old.port()));
        let sender = manager.inner.lock().unwrap().scope_changes.clone().unwrap();
        let (reply, response) = oneshot::channel();
        sender
            .try_send(ScopeChange {
                address: next,
                reply,
            })
            .unwrap();
        drop(response);
        timeout(Duration::from_secs(2), async {
            while manager.status().listen_addr.as_deref() != Some(next.to_string().as_str()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(manager.status().state, NativeCoreState::Running);
        wait_stopped(&manager).await;
    }

    #[tokio::test]
    async fn occupied_scope_rolls_back_without_stopping_the_core() {
        let manager = manager().await;
        let old: SocketAddr = manager.status().listen_addr.unwrap().parse().unwrap();
        let generation = manager.inner.lock().unwrap().generation;
        let target = SocketAddr::from((Ipv6Addr::LOCALHOST, old.port()));
        let occupied = TcpListener::bind(target).await.unwrap();
        let report = manager.reconfigure_listener_scope(target).await.unwrap();
        assert!(!report.changed);
        assert_eq!(report.effective_addr, Some(old));
        assert!(report.error.is_some());
        assert_eq!(manager.status().state, NativeCoreState::Running);
        assert_eq!(manager.inner.lock().unwrap().generation, generation);
        TcpStream::connect(old).await.unwrap();
        drop(occupied);
        assert!(
            manager
                .reconfigure_listener_scope(target)
                .await
                .unwrap()
                .changed
        );
        wait_stopped(&manager).await;
    }

    #[test]
    fn cleanup_observation_follows_the_old_task_owners() {
        let manager = CoreSessionManager::default();
        let tracker = TaskTracker::new();
        let held = tracker.track_future(std::future::pending::<()>());
        tracker.close();
        manager.inner.lock().unwrap().scope_cleanup = Some(tracker);
        assert!(!manager.listener_scope_cleanup_complete());
        drop(held);
        assert!(manager.listener_scope_cleanup_complete());
    }
}
