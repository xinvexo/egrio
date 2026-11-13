//! Building a device: compiling a profile, its egress and its capture into
//! the first policy snapshot.

use super::*;

impl NativeCoreDevice {
    pub fn compile(profile: &RuntimeProfile) -> Self {
        Self::compile_with_egress(profile, NativeCoreEgressConfig::default())
    }

    pub fn compile_with_egress(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
    ) -> Self {
        Self::compile_with_egress_and_capture(
            profile,
            egress_config,
            NativeCoreCaptureConfig::default(),
        )
    }

    pub fn compile_with_capture(
        profile: &RuntimeProfile,
        capture_config: NativeCoreCaptureConfig,
    ) -> Self {
        Self::compile_with_egress_and_capture(
            profile,
            NativeCoreEgressConfig::default(),
            capture_config,
        )
    }

    pub fn compile_with_egress_and_capture(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
    ) -> Self {
        Self::compile_started(profile, egress_config, capture_config, None, None)
    }

    /// Compiles and starts a Core from everything its host supplies. The
    /// egress socket guard and the flow scanner are device-durable:
    /// [`NativeCoreDevice::apply_config`] re-attaches the guard to every
    /// recompiled snapshot, so a profile hot-apply cannot drop egress loop
    /// protection, and the scanner's worker serves the device's whole life.
    pub fn from_start_inputs(inputs: CoreStartInputs) -> Self {
        let device = Self::compile_started(
            &inputs.profile,
            inputs.egress,
            inputs.capture,
            inputs.egress_socket_guard,
            inputs.flow_scanner,
        );
        device.inner.snapshot.load().rule_engine.log_warnings();
        if let Some(path) = inputs.fake_ip_mappings {
            device.keep_fake_ip_mappings(path);
        }
        device
    }

    /// Takes back the mappings the file holds, before anything is answered,
    /// and keeps it current.
    fn keep_fake_ip_mappings(&self, path: std::path::PathBuf) {
        // The pinned view allocates in the active pool; every view shares the
        // mappings.
        let store = self.pinned_runtime().fake_dns().clone();
        let keeper = fake_ip_keeper::FakeIpKeeper::restore(path, &store);
        keeper.spawn_saver(store, self.inner.sessions.lifetime.clone());
        let _ = self.inner.fake_ip_keeper.set(keeper);
    }

    fn compile_started(
        profile: &RuntimeProfile,
        egress_config: NativeCoreEgressConfig,
        capture_config: NativeCoreCaptureConfig,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
        flow_scanner: Option<Arc<dyn FlowScanner>>,
    ) -> Self {
        let device = Self::from_snapshot(
            RuntimeSnapshot::compile(
                profile,
                egress_config,
                capture_config,
                socket_guard.clone(),
                crate::policy_group::GroupStateTable::default(),
            ),
            socket_guard,
            flow_scanner,
        );
        device.start();
        device
    }

    pub(super) fn from_snapshot(
        snapshot: RuntimeSnapshot,
        socket_guard: Option<Arc<dyn EgressSocketGuard>>,
        flow_scanner: Option<Arc<dyn FlowScanner>>,
    ) -> Self {
        let sessions = NativeCoreSessionState {
            group_state: snapshot.dns.group_state(),
            ..Default::default()
        };
        Self {
            inner: Arc::new(NativeCoreDeviceInner {
                snapshot: ArcSwap::from_pointee(snapshot),
                sessions,
                state: Mutex::new(NativeCoreDeviceState::Created),
                probe_kick: Notify::new(),
                probe_reset: AtomicBool::new(false),
                probe_loop_running: AtomicBool::new(false),
                watchdog: WatchdogState::default(),
                socket_guard,
                attribution: flow_scanner
                    .map(|scanner| Arc::new(AttributionWorker::start(scanner))),
                packet_tcp: Mutex::new(PacketTcpEngines::default()),
                packet_tcp_active: Arc::new(AtomicUsize::new(0)),
                fake_ip_keeper: std::sync::OnceLock::new(),
            }),
        }
    }
}
