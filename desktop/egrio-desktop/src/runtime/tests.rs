//! The desktop Runtime's shared behavior, on every platform: layer switching
//! against an in-memory platform, and the lifecycle against a test host whose
//! system proxy is a snapshot adapter.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, CheckpointFuture,
    CheckpointId, CheckpointRevision, CheckpointStoreError, CheckpointStoreErrorCode,
    CoreConfigSource, PacketCaptureSettings, PacketCaptureSource, PlatformLeaseKey,
    RecoveryCheckpoint, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec, StoredCheckpoint,
    SystemProxyControl, SystemProxySettings,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};

use super::*;

const TEST_RUNTIME_ID: RuntimeId = RuntimeId::from_uuid(uuid::Uuid::from_u128(
    0x4c61_7965_7253_7769_7463_6854_6573_74,
));

#[derive(Debug)]
struct TestCore;

impl CoreConfigSource for TestCore {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        Ok(egrio_core::CoreStartInputs {
            capture: egrio_core::NativeCoreCaptureConfig::default(),
            profile: egrio_core::RuntimeProfile::new("runtime-sdk-test"),
            egress: egrio_core::NativeCoreEgressConfig::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

fn spec(layers: CaptureLayers) -> Result<RuntimeSpec, String> {
    RuntimeSpec::with_core(
        TEST_RUNTIME_ID,
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: layers.tun.then_some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: 1500,
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            route: layers.tun.then_some(egrio_runtime::RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            system_proxy: layers.system_proxy.then(core_listener_system_proxy_spec),
            ..RuntimePlatformSpec::default()
        },
    )
    .map_err(|error| error.to_string())
}

/// A Runtime with the SDK that created it: the SDK's Core executor runs the
/// Runtime's work, so it must outlive the Runtime.
async fn runtime() -> (Arc<Runtime>, Arc<InMemoryPlatform>, EgrioSdk) {
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCore))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    (runtime, platform, sdk)
}

async fn switch(
    runtime: &Arc<Runtime>,
    system_proxy: bool,
    tun: bool,
) -> Result<LayerSwitch, String> {
    switch_capture_layers(
        runtime,
        CaptureLayers { system_proxy, tun },
        spec,
        |spec| async {
            runtime
                .start_with_spec(spec)
                .await
                .map(|_| LayerSwitch::Started)
                .map_err(|error| error.to_string())
        },
    )
    .await
}

fn core_generation(runtime: &Runtime) -> Option<u64> {
    runtime
        .domain_status()
        .core
        .map(|core| core.generation.get())
}

#[tokio::test]
async fn one_core_generation_carries_every_layer_combination() {
    let (runtime, _, _sdk) = runtime().await;
    assert_eq!(
        switch(&runtime, true, false).await.unwrap(),
        LayerSwitch::Started
    );
    let core = core_generation(&runtime);
    assert!(core.is_some());
    for (system_proxy, tun) in [(true, true), (false, true), (true, true), (true, false)] {
        assert_eq!(
            switch(&runtime, system_proxy, tun).await.unwrap(),
            LayerSwitch::Reloaded
        );
        assert_eq!(
            spec_capture_layers(&runtime.spec()),
            CaptureLayers { system_proxy, tun }
        );
        assert_eq!(
            core_generation(&runtime),
            core,
            "switching one layer must keep the Core"
        );
    }
    assert_eq!(
        switch(&runtime, true, false).await.unwrap(),
        LayerSwitch::Unchanged
    );
    assert_eq!(
        switch(&runtime, false, false).await.unwrap(),
        LayerSwitch::Stopped
    );
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        switch(&runtime, false, false).await.unwrap(),
        LayerSwitch::Unchanged
    );
}

#[tokio::test]
async fn a_failed_switch_keeps_the_committed_layers_and_a_degraded_runtime_recovers() {
    let (runtime, platform, _sdk) = runtime().await;
    switch(&runtime, true, false).await.unwrap();
    let core = core_generation(&runtime);

    platform.fail_next_apply(CapabilityKind::Route, "injected TUN route failure");
    assert!(switch(&runtime, true, true).await.is_err());
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        spec_capture_layers(&runtime.spec()),
        CaptureLayers {
            system_proxy: true,
            tun: false
        }
    );
    assert_eq!(
        core_generation(&runtime),
        core,
        "a failed TUN switch must not take down the system proxy's Core"
    );

    platform.fail_next_restore(CapabilityKind::SystemProxy, "injected restore failure");
    assert!(switch(&runtime, false, true).await.is_err());
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        switch(&runtime, false, true).await.unwrap(),
        LayerSwitch::Started
    );
    assert_eq!(
        spec_capture_layers(&runtime.spec()),
        CaptureLayers {
            system_proxy: false,
            tun: true
        }
    );
    runtime.stop().await.unwrap();
}

/// The platform session's connection health, switched by the test.
#[derive(Debug)]
struct SessionHealth(tokio::sync::watch::Receiver<bool>);

impl egrio_runtime::ConnectionHealth for SessionHealth {
    fn wait_disconnected<'a>(&'a self) -> egrio_runtime::ConnectionHealthFuture<'a> {
        let mut lost = self.0.clone();
        Box::pin(async move {
            let _ = lost.wait_for(|lost| *lost).await;
        })
    }
}

#[tokio::test]
async fn a_lost_platform_session_recovers_in_place_and_keeps_the_system_proxy() {
    let platform = Arc::new(InMemoryPlatform::new());
    let (lost, health) = tokio::sync::watch::channel(false);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCore))
        .connection_health(Arc::new(SessionHealth(health)))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    switch(&runtime, true, true).await.unwrap();
    let core = core_generation(&runtime);
    let mut losses = runtime.subscribe_session_loss();

    lost.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(5), losses.changed())
        .await
        .expect("the lost session degrades the Runtime")
        .unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Degraded);

    // The platform is back; re-applying the committed layers restores TUN in
    // place.
    lost.send_replace(false);
    assert_eq!(
        switch(&runtime, true, true).await.unwrap(),
        LayerSwitch::Reloaded
    );
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        spec_capture_layers(&runtime.spec()),
        CaptureLayers {
            system_proxy: true,
            tun: true
        }
    );
    assert_eq!(
        core_generation(&runtime),
        core,
        "recovering TUN keeps the system proxy's Core"
    );
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    runtime.stop().await.unwrap();
}

#[test]
fn a_layer_reload_keeps_the_running_core_listener() {
    let mut current = spec(CaptureLayers::NONE).unwrap();
    current.core.as_mut().unwrap().listen_addr = Some("127.0.0.1:7890".parse().unwrap());
    let next = runtime_spec_retaining_core_listener(
        spec(CaptureLayers {
            system_proxy: true,
            tun: true,
        })
        .unwrap(),
        &current,
    );
    assert_eq!(next.core, current.core);
    assert!(next.platform.system_proxy.is_some() && next.platform.packet_capture.is_some());
    let proxy = core_listener_system_proxy_spec();
    assert_eq!(proxy.http_proxy, Some(SystemProxyEndpoint::CoreListener));
    assert_eq!(proxy.https_proxy, Some(SystemProxyEndpoint::CoreListener));
}

/// A host over an injected SDK with the test topology.
struct TestHost {
    sdk: EgrioSdk,
    preparations: AtomicUsize,
    /// A Core connection was dialed without egress protection.
    unprotected: AtomicBool,
}

impl DesktopHost for TestHost {
    type Activity = ();

    fn begin_activity() {}

    async fn create_runtime(&self) -> Result<Arc<Runtime>, String> {
        self.sdk
            .create_runtime(spec(CaptureLayers::NONE)?)
            .await
            .map_err(|error| error.to_string())
    }

    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String> {
        spec(layers)
    }

    fn default_capture_mtu(&self) -> Result<u32, String> {
        Ok(egrio_core::NativeCoreCaptureConfig::default().mtu)
    }

    fn take_unprotected_dials(&self) -> bool {
        self.unprotected.swap(false, Ordering::SeqCst)
    }

    async fn recover_unresolved(&self) -> Result<(), String> {
        self.sdk
            .recover_unresolved()
            .await
            .map(drop)
            .map_err(|error| error.to_string())
    }

    fn prepare_after_recovery(&self) -> Result<(), String> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RestartCoreConfig {
    loads: AtomicUsize,
    fail: AtomicBool,
}

impl CoreConfigSource for RestartCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        let load = self.loads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail.load(Ordering::SeqCst) {
            return Err("requested profile is invalid".into());
        }
        let mut profile = egrio_core::RuntimeProfile::new(format!("restart-profile-{load}"));
        if load > 1 {
            profile.traffic_policy_mode = egrio_core::TrafficPolicyMode::Global;
            profile.global_outbound = Some("DIRECT".into());
        }
        Ok(egrio_core::CoreStartInputs {
            capture: egrio_core::NativeCoreCaptureConfig::default(),
            profile,
            egress: egrio_core::NativeCoreEgressConfig::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

#[derive(Debug, Default)]
struct SnapshotAdapter {
    active: AtomicBool,
    fail_restore: AtomicBool,
}

impl SystemProxyControl for SnapshotAdapter {
    fn support(&self) -> CapabilitySupport {
        CapabilitySupport::Supported
    }

    fn prepare<'a>(
        &'a self,
        _settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            Ok(CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::system_proxy(),
                schema_version: 1,
                payload: serde_json::to_value(egrio_platform::unsupported_system_proxy_status(
                    "test",
                ))
                .unwrap(),
                rollback_payload: None,
            })
        })
    }

    fn apply<'a>(
        &'a self,
        _settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            self.active.store(true, Ordering::SeqCst);
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed: true,
                verified: true,
            })
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            Ok(CapabilityObservation {
                capability: CapabilityKind::SystemProxy,
                active: self.active.load(Ordering::SeqCst),
                verified: true,
            })
        })
    }

    fn restore<'a>(
        &'a self,
        _checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            if self.fail_restore.load(Ordering::SeqCst) {
                return Err(CapabilityError::new(
                    CapabilityKind::SystemProxy,
                    CapabilityErrorCode::RestoreFailed,
                    "injected restore failure",
                ));
            }
            self.active.store(false, Ordering::SeqCst);
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::SystemProxy,
                changed: true,
                verified: true,
            })
        })
    }
}

#[derive(Debug)]
struct FailOnceDeleteStore {
    inner: InMemoryCheckpointStore,
    delete_calls: AtomicUsize,
}

impl CheckpointStore for FailOnceDeleteStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.create(checkpoint)
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }

    fn replace<'a>(
        &'a self,
        revision: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.replace(revision, checkpoint)
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        if self.delete_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Box::pin(async {
                Err(CheckpointStoreError::new(
                    CheckpointStoreErrorCode::Unavailable,
                    "injected delete failure",
                ))
            })
        } else {
            self.inner.delete(id, revision)
        }
    }
}

type TestSdk = DesktopRuntime<TestHost>;

fn test_host(checkpoints: Arc<dyn CheckpointStore>, platform: Arc<SnapshotAdapter>) -> TestSdk {
    test_host_with_core(checkpoints, platform, Arc::new(TestCore))
}

fn test_host_with_core<C: CoreConfigSource + 'static>(
    checkpoints: Arc<dyn CheckpointStore>,
    platform: Arc<SnapshotAdapter>,
    core: Arc<C>,
) -> TestSdk {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(checkpoints.clone())
        .core_config(core)
        .system_proxy(platform)
        .build()
        .unwrap();
    host_over(sdk, checkpoints)
}

fn host_over(sdk: EgrioSdk, checkpoints: Arc<dyn CheckpointStore>) -> TestSdk {
    DesktopRuntime::with_host(
        TestHost {
            sdk,
            preparations: AtomicUsize::new(0),
            unprotected: AtomicBool::new(false),
        },
        checkpoints,
        Arc::default(),
        Arc::new(|| Box::pin(std::future::ready(Ok(None)))),
    )
}

async fn apply_test_layers(host: &TestSdk, system_proxy: bool, tun: bool) -> Result<(), String> {
    host.apply_capture_layers(CaptureLayers { system_proxy, tun })
        .await
}

async fn holds_background_activity(host: &TestSdk) -> bool {
    host.lifecycle.lock().await.holds_background_activity()
}

fn sdk_core_generation(host: &TestSdk) -> u64 {
    host.domain_status().unwrap().core.unwrap().generation.get()
}

fn profile_network_settings(
    profile_id: &str,
    mixed_port: u16,
    allow_lan: bool,
    bind_address: &str,
) -> crate::configuration::EffectiveConfigSnapshot {
    let mut snapshot =
        crate::configuration::compose_profile(profile_id, profile_id, "{}", &Default::default())
            .expect("fixture configuration");
    snapshot.network = crate::profile_network_settings::ProfileNetworkConfig {
        mixed_port,
        allow_lan,
        bind_address: bind_address.into(),
        ipv6: false,
        tun: Default::default(),
    };
    snapshot
}

#[test]
fn every_core_topology_refreshes_the_profile_listener_on_start_and_restart() {
    for (system_proxy, tun) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut current = spec(CaptureLayers { system_proxy, tun }).unwrap();
        let dns_listener = "127.0.0.1:5353".parse().unwrap();
        current.core.as_mut().unwrap().dns_listen_addr = Some(dns_listener);
        let topology = current.clone();
        let settings = Arc::new(std::sync::Mutex::new(None));
        let loader = {
            let settings = settings.clone();
            move || Ok::<_, String>(settings.lock().unwrap().clone())
        };

        for (next, expected) in [
            (
                profile_network_settings("profile-a", 7890, false, "*"),
                "127.0.0.1:7890",
            ),
            (
                profile_network_settings("profile-a", 7891, true, "*"),
                "0.0.0.0:7891",
            ),
            (
                profile_network_settings("profile-b", 7892, true, "192.0.2.10"),
                "192.0.2.10:7892",
            ),
        ] {
            *settings.lock().unwrap() = Some(next);
            // Restart begins with the previous generation's spec, just like production.
            current = runtime_spec_with_profile(current, loader().unwrap().as_ref()).unwrap();
            let core = current.core.as_ref().unwrap();
            assert_eq!(core.listen_addr, Some(expected.parse().unwrap()));
            assert_eq!(core.dns_listen_addr, Some(dns_listener));
            // The capture also takes the profile's fake-IP pool, there being
            // no firewall layer here to keep it inside the tunnel.
            let mut platform = current.platform.clone();
            if let Some(capture) = platform.packet_capture.as_mut() {
                capture.fake_ip_prefixes.clear();
            }
            assert_eq!(platform, topology.platform);
        }
    }
}

#[tokio::test]
async fn core_preparation_pins_the_same_snapshot_as_the_listener() {
    let mut host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );
    let source = Arc::new(std::sync::Mutex::new(profile_network_settings(
        "a", 7890, false, "*",
    )));
    let loads = Arc::new(AtomicUsize::new(0));
    host.configuration = Arc::new({
        let source = source.clone();
        let loads = loads.clone();
        move || {
            loads.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Ok(Some(source.lock().unwrap().clone()))))
        }
    });
    let started = host
        .core_start_spec(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    *source.lock().unwrap() = profile_network_settings("b", 7999, true, "*");
    let prepared = host.prepared_configuration.get().unwrap();
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    assert_eq!(prepared.profile_id, "a");
    assert_eq!(prepared.capture_mtu, 1500);
    assert_eq!(
        started.spec.core.unwrap().listen_addr,
        Some(prepared.network.listen_addr().unwrap())
    );
    host.core_start_spec(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    assert_eq!(host.prepared_configuration.get().unwrap().profile_id, "b");
    assert_eq!(loads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_core_start_takes_the_prepared_profile_and_the_next_prepares_its_own() {
    let mut host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );
    let source = Arc::new(std::sync::Mutex::new(profile_network_settings(
        "a", 7890, false, "*",
    )));
    host.configuration = Arc::new({
        let source = source.clone();
        move || Box::pin(std::future::ready(Ok(Some(source.lock().unwrap().clone()))))
    });
    host.core_start_spec(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    let prepared = host.prepared_configuration.get().unwrap();
    assert_eq!(prepared.take_profile().unwrap().id, "a");
    // The start holds the profile now. A second start from the same
    // preparation would run a profile that may have changed since.
    assert!(prepared.take_profile().is_err());
    // What the running generation is asked about stays.
    assert_eq!(prepared.profile_id, "a");
    assert_eq!(prepared.network.mixed_port, 7890);

    *source.lock().unwrap() = profile_network_settings("b", 7891, false, "*");
    host.core_start_spec(spec(CaptureLayers::NONE).unwrap())
        .await
        .unwrap();
    let next = host.prepared_configuration.get().unwrap();
    assert_eq!(next.take_profile().unwrap().id, "b");
}

/// The Core source every platform host is, without its capture
/// configuration, guard and scanner.
#[derive(Debug)]
struct PreparedTestCore(Arc<PreparedCoreConfiguration>);

impl CoreConfigSource for PreparedTestCore {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        prepared_core_inputs(&self.0, egrio_core::NativeCoreCaptureConfig::default())
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn every_core_start_runs_the_profile_read_for_it() {
    let checkpoints: Arc<dyn CheckpointStore> = Arc::new(InMemoryCheckpointStore::new());
    let prepared = Arc::new(PreparedCoreConfiguration::default());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(checkpoints.clone())
        .core_config(Arc::new(PreparedTestCore(prepared.clone())))
        .system_proxy(Arc::new(SnapshotAdapter::default()))
        .build()
        .unwrap();
    let source = Arc::new(std::sync::Mutex::new(profile_network_settings(
        "a",
        free_port(),
        false,
        "*",
    )));
    let host = DesktopRuntime::with_host(
        TestHost {
            sdk,
            preparations: AtomicUsize::new(0),
            unprotected: AtomicBool::new(false),
        },
        checkpoints,
        prepared.clone(),
        Arc::new({
            let source = source.clone();
            move || Box::pin(std::future::ready(Ok(Some(source.lock().unwrap().clone()))))
        }),
    );

    apply_test_layers(&host, true, false).await.unwrap();
    assert_eq!(host.effective_core_policy().unwrap().profile_id, "a");
    assert_eq!(host.running_profile_id().as_deref(), Some("a"));
    // The start holds the profile; the preparation answers for the
    // generation with what it kept.
    assert!(prepared.get().unwrap().take_profile().is_err());

    // A restart reads the profile as it is by then.
    *source.lock().unwrap() = profile_network_settings("b", free_port(), false, "*");
    assert!(host.restart_running_runtime().await.unwrap());
    assert_eq!(host.effective_core_policy().unwrap().profile_id, "b");
    assert_eq!(host.running_profile_id().as_deref(), Some("b"));

    // So does a start after the layers were switched off.
    apply_test_layers(&host, false, false).await.unwrap();
    assert_eq!(host.running_profile_id(), None);
    *source.lock().unwrap() = profile_network_settings("c", free_port(), false, "*");
    apply_test_layers(&host, true, false).await.unwrap();
    assert_eq!(host.effective_core_policy().unwrap().profile_id, "c");
    assert_eq!(host.running_profile_id().as_deref(), Some("c"));

    // A start nothing prepared is refused: it would have run the profile of
    // the preparation before it, whatever the profile is by now.
    host.stop_user_runtime().await.unwrap();
    let unprepared = host
        .runtime
        .get()
        .unwrap()
        .start_with_spec(
            spec(CaptureLayers {
                system_proxy: true,
                tun: false,
            })
            .unwrap(),
        )
        .await
        .unwrap_err();
    assert!(
        unprepared.to_string().contains("already started a Core"),
        "{unprepared}"
    );
}

#[tokio::test]
async fn core_preparation_pins_capture_mtu_and_rejects_invalid_input() {
    let mut host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );
    let snapshot = profile_network_settings("mtu", 7890, false, "*");
    host.configuration = Arc::new(move || Box::pin(std::future::ready(Ok(Some(snapshot.clone())))));
    let mut tun = spec(CaptureLayers {
        system_proxy: false,
        tun: true,
    })
    .unwrap();
    tun.platform.packet_capture.as_mut().unwrap().mtu = 1420;
    host.core_start_spec(tun.clone()).await.unwrap();
    let prepared = host.prepared_configuration.get().unwrap();
    assert_eq!(prepared.capture_mtu, 1420);
    tun.platform.packet_capture.as_mut().unwrap().mtu = 1279;
    assert!(host.core_start_spec(tun).await.is_err());
    assert!(Arc::ptr_eq(
        &prepared,
        &host.prepared_configuration.get().unwrap()
    ));
}

#[test]
fn profile_listener_loading_skips_absent_core_and_preserves_explicit_none_semantics() {
    let with_core = spec(CaptureLayers::NONE).unwrap();
    assert_eq!(
        runtime_spec_with_profile(with_core.clone(), None)
            .unwrap()
            .core
            .unwrap()
            .listen_addr,
        None
    );
    let mut no_core = with_core;
    no_core.core = None;
    assert_eq!(
        runtime_spec_with_profile(no_core.clone(), None).unwrap(),
        no_core
    );
}

fn excluding_snapshot(prefixes: &[&str]) -> crate::configuration::EffectiveConfigSnapshot {
    // A port nothing listens on, since the test Runtime binds it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut snapshot = profile_network_settings("excluding", port, false, "*");
    snapshot.network.tun.route_exclude_address = prefixes
        .iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();
    snapshot
}

#[test]
fn exclusions_sit_on_the_capability_that_installs_the_default_route() {
    let excluded: Vec<IpPrefix> = vec!["192.168.0.0/16".parse().unwrap()];
    let tun = CaptureLayers {
        system_proxy: false,
        tun: true,
    };
    // Windows and Linux: the Route capability, and the kill switch lets the
    // same destinations through.
    let mut routed = spec(tun).unwrap();
    routed.platform.firewall = Some(egrio_runtime::FirewallSettings {
        kill_switch: true,
        allow_lan: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    });
    let routed = with_route_exclusions(routed, excluded.clone());
    assert_eq!(
        routed.platform.route.as_ref().unwrap().excluded_prefixes,
        excluded
    );
    assert_eq!(
        routed.platform.firewall.as_ref().unwrap().excluded_prefixes,
        excluded
    );
    assert!(routed
        .platform
        .packet_capture
        .as_ref()
        .unwrap()
        .excluded_prefixes
        .is_empty());
    routed.validate().unwrap();
    // Routes without a default route have nothing to exclude from.
    let mut partial = spec(tun).unwrap();
    partial.platform.route.as_mut().unwrap().default_route = false;
    assert_eq!(
        with_route_exclusions(partial.clone(), excluded.clone()),
        partial
    );
    // A capture that installs its own default route (macOS) carries them.
    let tunnel = RuntimeSpec::with_core(
        TEST_RUNTIME_ID,
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: 1500,
                install_default_route: true,
                install_dns: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap();
    let tunnel = with_route_exclusions(tunnel, excluded.clone());
    assert_eq!(
        tunnel.platform.packet_capture.unwrap().excluded_prefixes,
        excluded
    );
}

#[test]
fn the_profile_fake_ip_pool_stays_inside_the_tunnel() {
    let mut snapshot = excluding_snapshot(&[]);
    snapshot.profile.dns.fake_ip_range = "10.42.0.1/16".parse().unwrap();
    let mut tun = spec(CaptureLayers {
        system_proxy: false,
        tun: true,
    })
    .unwrap();
    let expected: Vec<IpPrefix> = ["10.42.0.0/16", "fd11:5ca1:ab1e:1::a2a:0/112"]
        .iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();
    // Without a firewall layer the capture keeps them (macOS).
    let captured = runtime_spec_with_profile(tun.clone(), Some(&snapshot)).unwrap();
    assert_eq!(captured.platform.firewall, None);
    assert_eq!(
        captured.platform.packet_capture.unwrap().fake_ip_prefixes,
        expected
    );
    tun.platform.firewall = Some(egrio_runtime::FirewallSettings {
        kill_switch: true,
        allow_lan: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    });
    let firewalled = runtime_spec_with_profile(tun.clone(), Some(&snapshot)).unwrap();
    assert!(firewalled
        .platform
        .packet_capture
        .unwrap()
        .fake_ip_prefixes
        .is_empty());
    assert_eq!(
        runtime_spec_with_profile(tun.clone(), Some(&snapshot))
            .unwrap()
            .platform
            .firewall
            .unwrap()
            .fake_ip_prefixes,
        expected
    );
    assert!(runtime_spec_with_profile(tun, None)
        .unwrap()
        .platform
        .firewall
        .unwrap()
        .fake_ip_prefixes
        .is_empty());
}

#[test]
fn global_mode_keeps_every_destination_in_the_tunnel() {
    let snapshot = excluding_snapshot(&["192.168.0.0/16"]);
    for (mode, excluded) in [
        (TrafficPolicyMode::Rule, 1),
        (TrafficPolicyMode::Direct, 1),
        (TrafficPolicyMode::Global, 0),
    ] {
        assert_eq!(route_exclusions(&snapshot.network, mode).len(), excluded);
    }
    // A start takes the profile's own mode.
    let tun = spec(CaptureLayers {
        system_proxy: false,
        tun: true,
    })
    .unwrap();
    let excluded = |snapshot| {
        runtime_spec_with_profile(tun.clone(), Some(snapshot))
            .unwrap()
            .platform
            .route
            .unwrap()
            .excluded_prefixes
            .len()
    };
    assert_eq!(excluded(&snapshot), 1);
    let mut global = snapshot.clone();
    global.profile.traffic_policy_mode = TrafficPolicyMode::Global;
    assert_eq!(excluded(&global), 0);
}

#[tokio::test]
async fn the_running_tun_layer_takes_the_exclusions_of_the_core_mode_in_place() {
    let platform = Arc::new(InMemoryPlatform::new());
    let checkpoints: Arc<dyn CheckpointStore> = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(checkpoints.clone())
        .platform(platform.clone())
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCore))
        .build()
        .unwrap();
    let snapshot = excluding_snapshot(&["192.168.0.0/16", "fd7a:115c:a1e0::/48"]);
    let host = DesktopRuntime::with_host(
        TestHost {
            sdk,
            preparations: AtomicUsize::new(0),
            unprotected: AtomicBool::new(false),
        },
        checkpoints,
        Arc::default(),
        Arc::new(move || Box::pin(std::future::ready(Ok(Some(snapshot.clone()))))),
    );
    apply_test_layers(&host, false, true).await.unwrap();
    let runtime = host.existing_desktop_runtime().unwrap();
    let excluded = |runtime: &Runtime| {
        runtime
            .spec()
            .platform
            .route
            .unwrap()
            .excluded_prefixes
            .len()
    };
    assert_eq!(excluded(&runtime), 2);
    let core = sdk_core_generation(&host);
    host.reload_route_exclusions(&runtime, TrafficPolicyMode::Global)
        .await
        .unwrap();
    assert_eq!(excluded(&runtime), 0);
    host.reload_route_exclusions(&runtime, TrafficPolicyMode::Direct)
        .await
        .unwrap();
    assert_eq!(excluded(&runtime), 2);
    // Another layer's switch keeps the running mode's exclusions.
    apply_test_layers(&host, true, true).await.unwrap();
    assert_eq!(excluded(&runtime), 2);
    assert_eq!(sdk_core_generation(&host), core);
    apply_test_layers(&host, false, false).await.unwrap();
}

fn system_proxy_checkpoint() -> RecoveryCheckpoint {
    RecoveryCheckpoint::new(
        CheckpointId::new(),
        TEST_RUNTIME_ID,
        egrio_runtime::RuntimeGeneration::new(1),
        egrio_runtime::CheckpointOperation::Start,
        egrio_runtime::CheckpointPhase::Committed,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 1,
            payload: serde_json::Value::Null,
            rollback_payload: None,
        }],
    )
    .unwrap()
}

#[tokio::test]
async fn checkpoint_recovery_precedes_configuration_and_product_initialization() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(SnapshotAdapter::default());
    platform.active.store(true, Ordering::SeqCst);
    checkpoints.create(system_proxy_checkpoint()).await.unwrap();
    let mut host = test_host(checkpoints.clone(), platform.clone());
    host.configuration = Arc::new(|| panic!("recovery must not load a profile"));

    assert_eq!(
        host.recover_platform_before_configuration().await.unwrap(),
        1
    );
    assert!(!platform.active.load(Ordering::SeqCst));
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
    assert!(host.runtime.get().is_none());
    {
        let recovery = host.recovery.lock().await;
        assert!(recovery.runtime_recovered);
        assert!(!recovery.complete);
    }
    assert_eq!(
        host.host.preparations.load(Ordering::SeqCst),
        0,
        "recovery runs before the host prepares its first Runtime"
    );
    assert_eq!(
        host.recover_platform_before_configuration().await.unwrap(),
        0
    );
    assert_eq!(host.initialize().await.unwrap(), 1);
    assert!(host.recovery.lock().await.complete);
    assert_eq!(host.initialize().await.unwrap(), 0);
    assert_eq!(host.host.preparations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_recovery_is_retried_and_reports_the_restored_checkpoint() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(SnapshotAdapter::default());
    checkpoints.create(system_proxy_checkpoint()).await.unwrap();
    let host = test_host(checkpoints.clone(), platform.clone());

    platform.fail_restore.store(true, Ordering::SeqCst);
    assert!(host.recover_platform_before_configuration().await.is_err());
    assert_eq!(checkpoints.list_unresolved().await.unwrap().len(), 1);
    platform.fail_restore.store(false, Ordering::SeqCst);
    assert_eq!(
        host.recover_platform_before_configuration().await.unwrap(),
        1
    );
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn passive_route_evaluation_does_not_initialize_the_runtime() {
    let host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );

    assert!(host
        .evaluate_core_route(&egrio_core::RouteMatchInput::default())
        .await
        .unwrap()
        .is_none());
    assert_eq!(host.capture_layers(), CaptureLayers::NONE);
    assert!(host.runtime.get().is_none());
}

#[tokio::test]
async fn user_transition_is_shared_by_clones_and_independent_of_the_host_gate() {
    let host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );
    let user = host.begin_user_transition().await;
    let transition = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        host.begin_host_transition(),
    )
    .await
    .unwrap()
    .unwrap();
    drop(transition);
    let waiting_host = host.clone();
    let waiting = tokio::spawn(async move { waiting_host.begin_user_transition().await });
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    drop(user);
    drop(waiting.await.unwrap());
}

#[tokio::test]
async fn user_restart_replaces_the_core_generation_and_applies_the_new_policy() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(SnapshotAdapter::default());
    let config = Arc::new(RestartCoreConfig::default());
    let host = test_host_with_core(checkpoints.clone(), platform.clone(), config.clone());
    apply_test_layers(&host, true, false).await.unwrap();
    let before = sdk_core_generation(&host);
    let _user = host.begin_user_transition().await;

    assert!(host.restart_running_runtime().await.unwrap());

    assert!(sdk_core_generation(&host) > before);
    assert_eq!(config.loads.load(Ordering::SeqCst), 2);
    assert!(platform.active.load(Ordering::SeqCst));
    assert!(holds_background_activity(&host).await);
    assert_eq!(
        host.capture_layers(),
        CaptureLayers {
            system_proxy: true,
            tun: false
        }
    );
    assert_eq!(
        host.effective_core_policy().unwrap().traffic_policy_mode,
        egrio_core::TrafficPolicyMode::Global
    );
    assert_eq!(checkpoints.list_unresolved().await.unwrap().len(), 1);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn user_restart_keeps_old_runtime_when_configuration_preparation_fails() {
    let config = Arc::new(RestartCoreConfig::default());
    let mut host = test_host_with_core(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
        config.clone(),
    );
    let settings = Arc::new(std::sync::Mutex::new(None));
    let loads = Arc::new(AtomicUsize::new(0));
    host.configuration = Arc::new({
        let settings = settings.clone();
        let loads = loads.clone();
        move || {
            loads.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Ok(settings.lock().unwrap().clone())))
        }
    });
    apply_test_layers(&host, true, false).await.unwrap();
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    *settings.lock().unwrap() = Some(profile_network_settings("edited", 0, false, "*"));

    let error = host.restart_running_runtime().await.unwrap_err();

    assert!(error.contains("mixed-port: 0"));
    assert_eq!(loads.load(Ordering::SeqCst), 2);
    assert_eq!(config.loads.load(Ordering::SeqCst), 1);
    assert_eq!(
        host.domain_status().unwrap().runtime.state,
        RuntimeState::Running
    );
    assert!(holds_background_activity(&host).await);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn user_restart_never_revives_the_old_configuration_after_stop_or_start_failure() {
    for restore_failure in [false, true] {
        let checkpoints = Arc::new(InMemoryCheckpointStore::new());
        let platform = Arc::new(SnapshotAdapter::default());
        let config = Arc::new(RestartCoreConfig::default());
        let host = test_host_with_core(checkpoints.clone(), platform.clone(), config.clone());
        apply_test_layers(&host, true, false).await.unwrap();
        platform
            .fail_restore
            .store(restore_failure, Ordering::SeqCst);
        config.fail.store(!restore_failure, Ordering::SeqCst);

        assert!(host.restart_running_runtime().await.is_err());

        let runtime = host.runtime.get().unwrap();
        if restore_failure {
            assert_eq!(
                config.loads.load(Ordering::SeqCst),
                1,
                "failed stop must not attempt the new start"
            );
            assert_eq!(runtime.status().state, RuntimeState::Degraded);
            assert!(holds_background_activity(&host).await);
            assert!(runtime
                .apply_core_with(|| panic!("old configuration must stay quiesced"))
                .await
                .is_err());
            platform.fail_restore.store(false, Ordering::SeqCst);
        } else {
            assert_eq!(config.loads.load(Ordering::SeqCst), 2);
            assert_eq!(runtime.status().state, RuntimeState::Stopped);
            assert_eq!(
                runtime.core_status().state,
                egrio_core::NativeCoreState::Stopped
            );
            assert!(!platform.active.load(Ordering::SeqCst));
            assert!(!holds_background_activity(&host).await);
        }
        host.stop_user_runtime().await.unwrap();
        assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn failed_user_stop_quiesces_the_core_and_retains_restore_evidence() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(checkpoints.clone(), platform.clone());
    assert!(!host.restart_running_runtime().await.unwrap());
    apply_test_layers(&host, true, false).await.unwrap();
    let runtime = host.runtime.get().unwrap().clone();
    platform.fail_restore.store(true, Ordering::SeqCst);

    assert!(host.stop_user_runtime().await.is_err());
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert!(host.restart_running_runtime().await.is_err());
    assert!(runtime
        .apply_core_with(|| panic!("quiesced Core must not accept an update"))
        .await
        .is_err());
    assert!(holds_background_activity(&host).await);
    assert_eq!(checkpoints.list_unresolved().await.unwrap().len(), 1);

    platform.fail_restore.store(false, Ordering::SeqCst);
    host.stop_user_runtime().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
    assert!(!holds_background_activity(&host).await);
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
    // Failure cleanup never sets the terminal application-exit latch.
    apply_test_layers(&host, true, false).await.unwrap();
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_user_stop_releases_activity_after_verified_restore_with_metadata_residue() {
    let checkpoints = Arc::new(FailOnceDeleteStore {
        inner: InMemoryCheckpointStore::new(),
        delete_calls: AtomicUsize::new(0),
    });
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(checkpoints.clone(), platform.clone());
    apply_test_layers(&host, true, false).await.unwrap();

    assert!(host.stop_user_runtime().await.is_err());
    assert!(!platform.active.load(Ordering::SeqCst));
    assert!(!holds_background_activity(&host).await);

    host.stop_user_runtime().await.unwrap();
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        host.runtime.get().unwrap().core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
}

#[tokio::test]
async fn shutdown_waits_for_a_transition_and_closes_future_admission() {
    let host = test_host(
        Arc::new(InMemoryCheckpointStore::new()),
        Arc::new(SnapshotAdapter::default()),
    );
    let transition = host.begin_host_transition().await.unwrap();
    let shutdown_host = host.clone();
    let shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });

    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    drop(transition);
    assert!(shutdown.await.unwrap().is_ok());
    assert!(host.begin_host_transition().await.is_err());
    assert!(apply_test_layers(&host, true, false).await.is_err());
    assert!(host.runtime.get().is_none());
    // Stopping stays possible while the host shuts down.
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn system_proxy_layer_add_and_remove_drive_one_fixed_runtime() {
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(Arc::new(InMemoryCheckpointStore::new()), platform.clone());

    apply_test_layers(&host, true, false).await.unwrap();
    assert!(holds_background_activity(&host).await);
    let running = host.domain_status().unwrap();
    assert_eq!(running.runtime.id, TEST_RUNTIME_ID);
    assert!(running.spec.platform.system_proxy.is_some());
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    apply_test_layers(&host, false, false).await.unwrap();
    assert!(!holds_background_activity(&host).await);
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        host.domain_status().unwrap().runtime.state,
        RuntimeState::Stopped
    );
    assert_eq!(host.capture_layers(), CaptureLayers::NONE);
}

#[tokio::test]
async fn failed_system_proxy_restore_retains_the_runtime_for_retry() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(checkpoints.clone(), platform.clone());

    apply_test_layers(&host, true, false).await.unwrap();
    assert!(holds_background_activity(&host).await);
    platform.fail_restore.store(true, Ordering::SeqCst);
    assert!(apply_test_layers(&host, false, false).await.is_err());
    assert!(holds_background_activity(&host).await);
    assert_eq!(checkpoints.list_unresolved().await.unwrap().len(), 1);
    platform.fail_restore.store(false, Ordering::SeqCst);
    apply_test_layers(&host, false, false).await.unwrap();
    assert!(!holds_background_activity(&host).await);
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_shutdown_can_be_retried_and_releases_the_activity() {
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(Arc::new(InMemoryCheckpointStore::new()), platform.clone());

    apply_test_layers(&host, true, false).await.unwrap();
    assert!(holds_background_activity(&host).await);

    // Exit with the OS restore failing: the activity is deliberately kept so
    // a retry has something to release.
    platform.fail_restore.store(true, Ordering::SeqCst);
    host.shutdown()
        .await
        .expect_err("restore failure must surface");
    assert!(holds_background_activity(&host).await);

    // The retry must be able to run — a shutdown that latched itself shut
    // would strand the activity for the rest of the process's life.
    platform.fail_restore.store(false, Ordering::SeqCst);
    host.shutdown()
        .await
        .expect("shutdown retry after a restore failure");
    assert!(!holds_background_activity(&host).await);
}

mod rule_download;
