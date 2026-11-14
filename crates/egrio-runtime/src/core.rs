use egrio_core::{
    CoreSessionManager, CoreStartInputs, NativeCoreDevice, NativeCoreEgressConfig,
    NativeCoreStatus, RuntimeProfile,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::time::{Duration, Instant};

const CORE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const CORE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeCoreGeneration(u64);

impl RuntimeCoreGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Where a telemetry poll left off: the Core generation it read and the
/// newest terminal record it received.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryCursor {
    generation: Option<u64>,
    finished: u64,
}

#[derive(Debug, Default)]
struct RuntimeCoreLifecycle {
    next_generation: u64,
    active_generation: Option<RuntimeCoreGeneration>,
}

#[derive(Debug, Default)]
/// Serializes lifecycle mutations for the in-process Core listener.
///
/// Each generation compiles one `NativeCoreDevice` and starts the listener
/// session on it (`start_on_device`), so the packet data plane, the inbound
/// listener, DNS answering, and fake-IP reverse mapping all share one engine
/// and one session registry — there is no second Core to fall out of sync
/// with. The device handle is held here and closed when the generation stops.
///
/// This type deliberately exposes only read-only projections outside its
/// lifecycle methods. It does not track independent consumer leases, but each
/// started Core generation receives an opaque token so delayed cleanup cannot
/// stop a newer generation.
pub struct RuntimeCore {
    session: CoreSessionManager,
    lifecycle: tokio::sync::Mutex<RuntimeCoreLifecycle>,
    /// The active generation's device, mirrored outside the async lifecycle
    /// lock so synchronous read paths (packet telemetry, diagnostics) can
    /// reach it. Written only by the lifecycle methods, under their lock.
    device: std::sync::RwLock<Option<NativeCoreDevice>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeCoreEnsureReport {
    pub status: NativeCoreStatus,
    pub generation: RuntimeCoreGeneration,
    /// True when this call opened the generation's ordinary listeners. The
    /// surrounding start transaction owns cleanup if activation fails.
    pub started_by_call: bool,
}

struct CoreStartRollback<'a> {
    owner: &'a RuntimeCore,
    lifecycle: &'a mut RuntimeCoreLifecycle,
    device: NativeCoreDevice,
    armed: bool,
}

impl CoreStartRollback<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CoreStartRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.session.stop();
            self.lifecycle.active_generation = None;
            self.owner.replace_device_slot(None);
            // The listener session does not own the device
            // (`start_on_device`), so a failed start must close it here or
            // its TCP engine and probe loop would leak past the rollback.
            self.device.close();
        }
    }
}

impl RuntimeCore {
    pub(crate) fn listener_scope_cleanup_complete(&self) -> bool {
        self.session.listener_scope_cleanup_complete()
    }
    pub(crate) async fn reconfigure_listener_scope(
        &self,
        address: SocketAddr,
    ) -> Result<egrio_core::ListenerScopeUpdateReport, String> {
        let _lifecycle = self.lifecycle.lock().await;
        self.session.reconfigure_listener_scope(address).await
    }
    #[must_use]
    pub fn status(&self) -> NativeCoreStatus {
        self.session.status()
    }

    /// The active generation's device, when one is running. The single Core
    /// behind both the listener session and the packet data plane.
    #[must_use]
    pub(crate) fn packet_device(&self) -> Option<NativeCoreDevice> {
        self.device
            .read()
            .expect("runtime core device slot")
            .clone()
    }

    /// Bytes the running Core generation has relayed; `None` while no Core
    /// runs. Takes no lifecycle lock, so a rate sampler can poll it often.
    pub fn traffic_volume(&self) -> Option<egrio_core::TrafficVolume> {
        self.session.traffic_volume()
    }

    pub async fn traffic_telemetry_snapshot(&self) -> egrio_core::TrafficTelemetrySnapshot {
        self.traffic_telemetry_since(TelemetryCursor::default())
            .await
            .0
    }

    /// The telemetry with only the terminal records the cursor has not
    /// seen, and the cursor for the next poll. A cursor from another Core
    /// generation starts over.
    pub async fn traffic_telemetry_since(
        &self,
        cursor: TelemetryCursor,
    ) -> (egrio_core::TrafficTelemetrySnapshot, TelemetryCursor) {
        let lifecycle = self.lifecycle.lock().await;
        let status = self.session.status();
        let generation = lifecycle
            .active_generation
            .map(|generation| generation.get());
        let after = if cursor.generation == generation {
            cursor.finished
        } else {
            0
        };
        let (mut snapshot, finished) = self.session.traffic_telemetry_since(after);
        // Active connections come from the device's live TCP/UDP tables.
        // Keep cumulative listener counters, including sessions that fail
        // before the device registry creates a row.
        snapshot.accepted_connections = status.accepted_sessions;
        snapshot.completed_connections = status.completed_sessions;
        snapshot.failed_connections = status.failed_sessions;
        if let Some(generation) = lifecycle.active_generation {
            prefix_connection_ids(&mut snapshot, generation);
        }
        (
            snapshot,
            TelemetryCursor {
                generation,
                finished,
            },
        )
    }

    #[cfg(test)]
    pub(crate) async fn ensure_with<F>(
        &self,
        start_inputs: F,
    ) -> Result<RuntimeCoreEnsureReport, String>
    where
        F: FnOnce() -> Result<CoreStartInputs, String>,
    {
        self.ensure_with_listener(start_inputs, None, None, false)
            .await
    }

    /// Ensures the Core is running, binding its listener endpoints when this
    /// call starts a new generation. The generation's device is compiled
    /// here, the listener session starts on it without owning it, and the
    /// packet data plane later runs on the same device. `port_fallback` lets
    /// a free port stand in for a taken or reserved `listen_addr`.
    pub async fn ensure_with_listener<F>(
        &self,
        start_inputs: F,
        listen_addr: Option<SocketAddr>,
        dns_listen_addr: Option<SocketAddr>,
        port_fallback: bool,
    ) -> Result<RuntimeCoreEnsureReport, String>
    where
        F: FnOnce() -> Result<CoreStartInputs, String>,
    {
        let mut lifecycle = self.lifecycle.lock().await;
        let status = self.wait_settled().await?;
        if status.state == egrio_core::NativeCoreState::Running {
            let generation = lifecycle
                .active_generation
                .ok_or_else(|| "running Runtime Core has no active generation".to_string())?;
            return Ok(RuntimeCoreEnsureReport {
                status,
                generation,
                started_by_call: false,
            });
        }

        let generation = self.prepare_locked(start_inputs, &mut lifecycle)?;
        let device = self.packet_device().expect("prepared Core device");
        let mut rollback = CoreStartRollback {
            owner: self,
            lifecycle: &mut lifecycle,
            device: device.clone(),
            armed: true,
        };
        let status = self
            .session
            .start_on_device(device.clone(), listen_addr, dns_listen_addr, port_fallback)
            .await?;
        validate_started_status(&status)?;
        rollback.disarm();
        Ok(RuntimeCoreEnsureReport {
            status,
            generation,
            started_by_call: true,
        })
    }

    /// Creates the generation's device without opening ordinary listeners.
    pub async fn prepare_with<F>(&self, start_inputs: F) -> Result<RuntimeCoreGeneration, String>
    where
        F: FnOnce() -> Result<CoreStartInputs, String>,
    {
        let mut lifecycle = self.lifecycle.lock().await;
        self.prepare_locked(start_inputs, &mut lifecycle)
    }

    fn prepare_locked<F>(
        &self,
        start_inputs: F,
        lifecycle: &mut RuntimeCoreLifecycle,
    ) -> Result<RuntimeCoreGeneration, String>
    where
        F: FnOnce() -> Result<CoreStartInputs, String>,
    {
        if let Some(generation) = lifecycle.active_generation {
            return Ok(generation);
        }
        let inputs = start_inputs()?;
        inputs.capture.validate()?;
        lifecycle.next_generation = lifecycle
            .next_generation
            .checked_add(1)
            .ok_or("Runtime Core generation counter exhausted")?;
        let generation = RuntimeCoreGeneration(lifecycle.next_generation);
        let device = NativeCoreDevice::from_start_inputs(inputs);
        drop(device.spawn_health_probe_loop());
        self.replace_device_slot(Some(device));
        lifecycle.active_generation = Some(generation);
        Ok(generation)
    }

    fn replace_device_slot(&self, device: Option<NativeCoreDevice>) {
        *self.device.write().expect("runtime core device slot") = device;
    }

    pub async fn apply_with<F>(&self, load: F) -> Result<bool, String>
    where
        F: FnOnce() -> Result<(RuntimeProfile, NativeCoreEgressConfig), String>,
    {
        let _lifecycle = self.lifecycle.lock().await;
        let status = self.wait_settled().await?;
        if status.state != egrio_core::NativeCoreState::Running {
            return Ok(false);
        }
        let (profile, egress) = load()?;
        self.session.apply_profile_and_egress(&profile, egress)?;
        Ok(true)
    }

    pub async fn stop(&self) -> Result<NativeCoreStatus, String> {
        self.stop_matching_generation(None).await
    }

    pub async fn stop_generation(
        &self,
        generation: RuntimeCoreGeneration,
    ) -> Result<Option<NativeCoreStatus>, String> {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.active_generation != Some(generation) {
            return Ok(None);
        }
        self.stop_locked(&mut lifecycle).await.map(Some)
    }

    async fn stop_matching_generation(
        &self,
        generation: Option<RuntimeCoreGeneration>,
    ) -> Result<NativeCoreStatus, String> {
        let mut lifecycle = self.lifecycle.lock().await;
        if generation.is_some() && lifecycle.active_generation != generation {
            return Ok(self.session.status());
        }
        self.stop_locked(&mut lifecycle).await
    }

    async fn stop_locked(
        &self,
        lifecycle: &mut RuntimeCoreLifecycle,
    ) -> Result<NativeCoreStatus, String> {
        let status = self.wait_settled().await?;
        if status.state == egrio_core::NativeCoreState::Stopped {
            lifecycle.active_generation = None;
            self.close_device_slot();
            return Ok(status);
        }
        self.session.stop();
        let status = self.wait_settled().await?;
        if status.state == egrio_core::NativeCoreState::Stopped {
            lifecycle.active_generation = None;
            self.close_device_slot();
            Ok(status)
        } else {
            Err(status
                .last_error
                .unwrap_or_else(|| format!("native core stopped in {:?} state", status.state)))
        }
    }

    /// Closes and releases the generation device once its listener session
    /// has stopped. The session does not own the device (`start_on_device`),
    /// so this is where the TCP engine, probe loop, and remaining sessions end.
    fn close_device_slot(&self) {
        if let Some(device) = self
            .device
            .write()
            .expect("runtime core device slot")
            .take()
        {
            device.close();
        }
    }

    async fn wait_settled(&self) -> Result<NativeCoreStatus, String> {
        let started_at = Instant::now();
        loop {
            let status = self.session.status();
            if status.state != egrio_core::NativeCoreState::Stopping {
                return Ok(status);
            }
            if started_at.elapsed() >= CORE_STOP_TIMEOUT {
                return Err("timed out waiting for the Runtime Core to stop".into());
            }
            tokio::time::sleep(CORE_STOP_POLL_INTERVAL).await;
        }
    }
}

fn validate_started_status(status: &NativeCoreStatus) -> Result<(), String> {
    if status.state == egrio_core::NativeCoreState::Running {
        Ok(())
    } else {
        Err(status
            .last_error
            .clone()
            .unwrap_or_else(|| format!("native core start completed in {:?} state", status.state)))
    }
}

fn prefix_connection_ids(
    snapshot: &mut egrio_core::TrafficTelemetrySnapshot,
    generation: RuntimeCoreGeneration,
) {
    for connection in &mut snapshot.connections {
        connection.id = format!("core-{}-{}", generation.get(), connection.id).into();
    }
}

impl Drop for RuntimeCore {
    fn drop(&mut self) {
        self.session.stop();
        // The session does not own the generation device; close it so a
        // dropped RuntimeCore cannot leak its TCP engine or probe loop.
        if let Ok(mut slot) = self.device.write() {
            if let Some(device) = slot.take() {
                device.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use egrio_core::{
        NativeCoreState, TrafficConnectionProtocol, TrafficConnectionSnapshot,
        TrafficConnectionState, TrafficTelemetrySnapshot,
    };

    use super::*;

    #[tokio::test]
    async fn concurrent_ensure_reports_exactly_one_starter() {
        let runtime_core = RuntimeCore::default();
        let (first, second) = tokio::join!(
            runtime_core.ensure_with(|| Ok(test_inputs("first"))),
            runtime_core.ensure_with(|| Ok(test_inputs("second"))),
        );

        let first = first.expect("first ensure");
        let second = second.expect("second ensure");
        assert_ne!(first.started_by_call, second.started_by_call);
        assert_eq!(first.generation, second.generation);
        assert_eq!(runtime_core.status().state, NativeCoreState::Running);
        runtime_core.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn stopped_core_skips_apply_loader() {
        let runtime_core = RuntimeCore::default();
        let applied = runtime_core
            .apply_with(|| panic!("stopped Core must not load apply inputs"))
            .await
            .expect("stopped apply is a no-op");
        assert!(!applied);
    }

    #[tokio::test]
    async fn stop_is_idempotent() {
        let runtime_core = RuntimeCore::default();

        let first = runtime_core.stop().await.expect("first stop");
        let second = runtime_core.stop().await.expect("second stop");

        assert_eq!(first.state, NativeCoreState::Stopped);
        assert_eq!(second.state, NativeCoreState::Stopped);
    }

    #[test]
    fn start_status_must_be_running() {
        let mut failed = NativeCoreStatus {
            state: NativeCoreState::Failed,
            listen_addr: None,
            listener_fallback: None,
            dns_listen_addr: None,
            started_at_unix: None,
            updated_at_unix: 0,
            active_sessions: 0,
            accepted_sessions: 0,
            completed_sessions: 0,
            failed_sessions: 0,
            last_error: Some("listener exited immediately".into()),
        };
        assert_eq!(
            validate_started_status(&failed).expect_err("failed start status must fail"),
            "listener exited immediately"
        );
        failed.state = NativeCoreState::Stopping;
        failed.last_error = None;
        assert!(validate_started_status(&failed)
            .expect_err("stopping start status must fail")
            .contains("Stopping"));
    }

    #[test]
    fn connection_ids_are_namespaced_by_core_generation() {
        let mut snapshot = TrafficTelemetrySnapshot {
            sampled_at_unix: 1,
            active_connections: 1,
            accepted_connections: 1,
            completed_connections: 0,
            failed_connections: 0,
            upload_bytes: 0,
            download_bytes: 0,
            connections: vec![TrafficConnectionSnapshot {
                id: "tcp-1".into(),
                protocol: TrafficConnectionProtocol::Tcp,
                process_name: None,
                process_path: None,
                source: None,
                destination: "example.com:443".into(),
                host: None,
                rule: None,
                inbound: "http-connect".into(),
                outbound: "DIRECT".into(),
                egress_interface: None,
                upload_bytes: 0,
                download_bytes: 0,
                opened_at_unix: 1,
                updated_at_unix: 1,
                state: TrafficConnectionState::Active,
                termination: None,
                closed_at_unix: None,
            }],
        };

        prefix_connection_ids(&mut snapshot, RuntimeCoreGeneration(7));

        assert_eq!(&*snapshot.connections[0].id, "core-7-tcp-1");
    }

    #[tokio::test]
    async fn running_telemetry_uses_the_device_projection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let runtime_core = RuntimeCore::default();
        runtime_core
            .ensure_with(|| Ok(test_inputs("telemetry")))
            .await
            .expect("start listener");

        let snapshot = runtime_core.traffic_telemetry_snapshot().await;

        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.accepted_connections, 0);

        let device = runtime_core.packet_device().unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let mut data = [0; 8];

        let mut listener_client = tokio::net::TcpStream::connect(
            runtime_core.status().listen_addr.expect("listener address"),
        )
        .await
        .unwrap();
        listener_client
            .write_all(format!("CONNECT {target_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let (mut listener_upstream, _) = timeout(Duration::from_secs(3), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut reply = [0; 128];
        let read = listener_client.read(&mut reply).await.unwrap();
        assert!(reply[..read].starts_with(b"HTTP/1.1 200"));
        listener_client.write_all(b"listener").await.unwrap();
        listener_upstream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"listener");

        let snapshot = runtime_core.traffic_telemetry_snapshot().await;
        assert_eq!(runtime_core.status().active_sessions, 1);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.accepted_connections, 1);
        assert_eq!(snapshot.completed_connections, 0);
        assert_eq!(snapshot.failed_connections, 0);

        device
            .cutover_sessions_and_wait(Duration::from_secs(3))
            .await
            .unwrap();
        let snapshot = runtime_core.traffic_telemetry_snapshot().await;
        assert_eq!(snapshot.active_connections, 0);
        assert!(!snapshot.connections.is_empty());
        assert!(snapshot
            .connections
            .iter()
            .all(|connection| connection.state != TrafficConnectionState::Active));
        runtime_core.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn stale_generation_cannot_stop_a_replacement() {
        let runtime_core = RuntimeCore::default();
        let first = runtime_core
            .ensure_with(|| Ok(test_inputs("first-generation")))
            .await
            .expect("start first generation");
        runtime_core.stop().await.expect("stop first generation");
        let second = runtime_core
            .ensure_with(|| Ok(test_inputs("second-generation")))
            .await
            .expect("start second generation");

        let stopped = runtime_core
            .stop_generation(first.generation)
            .await
            .expect("stale stop is safe");

        assert!(stopped.is_none());
        assert_ne!(first.generation, second.generation);
        assert_eq!(runtime_core.status().state, NativeCoreState::Running);
        runtime_core
            .stop_generation(second.generation)
            .await
            .expect("stop current generation")
            .expect("current generation matched");
    }

    #[tokio::test]
    async fn immediate_restart_waits_for_generation_release() {
        let runtime_core = RuntimeCore::default();
        runtime_core
            .ensure_with(|| Ok(test_inputs("before-stop")))
            .await
            .expect("start first listener");

        assert_eq!(runtime_core.session.stop().state, NativeCoreState::Stopping);
        let restarted = runtime_core
            .ensure_with(|| Ok(test_inputs("after-stop")))
            .await
            .expect("restart after stopping");

        assert!(restarted.started_by_call);
        let listen_addr = restarted
            .status
            .listen_addr
            .as_deref()
            .expect("restarted listen address")
            .parse::<SocketAddr>()
            .expect("valid listen address");
        tokio::net::TcpStream::connect(listen_addr)
            .await
            .expect("restarted listener accepts connections");
        runtime_core.stop().await.expect("stop restarted listener");
    }

    #[tokio::test]
    async fn cancelled_stop_does_not_wedge_the_lifecycle() {
        let runtime_core = Arc::new(RuntimeCore::default());
        runtime_core
            .ensure_with(|| Ok(test_inputs("before-cancelled-stop")))
            .await
            .expect("start listener");

        let stopping_core = runtime_core.clone();
        let stop = tokio::spawn(async move { stopping_core.stop().await });
        tokio::task::yield_now().await;
        stop.abort();

        let running = runtime_core
            .ensure_with(|| Ok(test_inputs("after-cancelled-stop")))
            .await
            .expect("ensure after cancelled stop");
        assert_eq!(running.status.state, NativeCoreState::Running);
        let listen_addr = running
            .status
            .listen_addr
            .as_deref()
            .expect("running listen address")
            .parse::<SocketAddr>()
            .expect("valid listen address");
        tokio::net::TcpStream::connect(listen_addr)
            .await
            .expect("listener remains usable after cancelled stop");
        runtime_core.stop().await.expect("stop running listener");
    }

    #[tokio::test]
    async fn drop_requests_listener_cleanup() {
        let listen_addr = {
            let runtime_core = RuntimeCore::default();
            let started = runtime_core
                .ensure_with(|| Ok(test_inputs("drop-cleanup")))
                .await
                .expect("start listener");
            started
                .status
                .listen_addr
                .as_deref()
                .expect("listen address")
                .parse::<SocketAddr>()
                .expect("valid listen address")
        };

        for _ in 0..100 {
            if tokio::net::TcpStream::connect(listen_addr).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("RuntimeCore drop left listener {listen_addr} reachable");
    }

    fn test_inputs(id: &str) -> CoreStartInputs {
        CoreStartInputs {
            capture: Default::default(),
            profile: RuntimeProfile::new(id),
            egress: NativeCoreEgressConfig::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        }
    }
}
