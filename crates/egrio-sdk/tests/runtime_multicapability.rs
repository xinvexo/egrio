use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use egrio_runtime::{
    CapabilityErrorCode, CapabilityKind, CheckpointId, CheckpointPhase, CheckpointStore,
    DnsControl, DnsSettings, FirewallControl, FirewallSettings, LeaseCoordinator, LeaseExpandError,
    LeaseGrant, LeaseReleaseEvidence, LeaseRequestSet, LeaseTransitionError,
    LeaseTransitionErrorCode, PacketCapture, PacketCaptureSettings, PacketCaptureSource,
    PacketDataPlane, PacketDataPlaneFuture, PlatformLeaseConflict, PlatformLeaseKey,
    PlatformLeaseState, RouteControl, RouteSettings, Runtime, RuntimeCoreSpec, RuntimeId,
    RuntimePlatformSpec, RuntimePorts, RuntimeReloadError, RuntimeResource, RuntimeResourceOutcome,
    RuntimeSpec, RuntimeStartError, RuntimeState, SystemProxyControl, SystemProxyEndpoint,
    SystemProxySettings, SystemProxySpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, PlatformLeaseCoordinator};
use uuid::Uuid;

#[derive(Debug)]
struct IdlePacketDataPlane;

#[derive(Debug, Default)]
struct FailShrinkLeaseCoordinator {
    inner: PlatformLeaseCoordinator,
}

impl FailShrinkLeaseCoordinator {
    fn status(&self, key: &PlatformLeaseKey) -> egrio_sdk::PlatformLeaseStatus {
        self.inner.status(key)
    }
}

impl LeaseCoordinator for FailShrinkLeaseCoordinator {
    fn acquire_all(&self, request: LeaseRequestSet) -> Result<LeaseGrant, PlatformLeaseConflict> {
        self.inner.acquire_all(request)
    }

    fn expand(
        &self,
        grant: &LeaseGrant,
        request: LeaseRequestSet,
    ) -> Result<LeaseGrant, LeaseExpandError> {
        self.inner.expand(grant, request)
    }

    fn begin_release(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.begin_release(grant)
    }

    fn mark_recovery_required(
        &self,
        grant: &LeaseGrant,
        checkpoint_id: CheckpointId,
    ) -> Result<(), LeaseTransitionError> {
        self.inner.mark_recovery_required(grant, checkpoint_id)
    }

    fn begin_recovery(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.begin_recovery(grant)
    }

    fn resume(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.resume(grant)
    }

    fn shrink(
        &self,
        _grant: &LeaseGrant,
        _retained_keys: Vec<PlatformLeaseKey>,
        _evidence: LeaseReleaseEvidence,
    ) -> Result<LeaseGrant, LeaseTransitionError> {
        Err(LeaseTransitionError {
            code: LeaseTransitionErrorCode::InvalidState,
            message: "injected lease shrink failure".into(),
        })
    }

    fn release(
        &self,
        grant: &LeaseGrant,
        evidence: LeaseReleaseEvidence,
    ) -> Result<(), LeaseTransitionError> {
        self.inner.release(grant, evidence)
    }
}

impl PacketDataPlane for IdlePacketDataPlane {
    fn run(
        &self,
        _core: egrio_core::NativeCoreDevice,
        queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        Box::pin(async move {
            let _queues = queues;
            stop.cancelled().await;
            Ok(egrio_core::NativeCoreDeviceRunReport::default())
        })
    }
}

/// Serves fresh Core start inputs on every load, the in-memory stand-in for
/// the desktop host re-reading its active profile per generation.
#[derive(Debug)]
struct TestCoreConfig;

impl egrio_runtime::CoreConfigSource for TestCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        Ok(egrio_core::CoreStartInputs {
            capture: Default::default(),
            profile: egrio_core::RuntimeProfile::new("multicapability-test"),
            egress: egrio_core::NativeCoreEgressConfig::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

fn spec(id: u128, revision: u16) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7000 + revision))),
                https_proxy: None,
                bypass: vec![format!("revision-{revision}")],
            })),
            route: Some(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            dns: Some(DnsSettings {
                servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, revision as u8))],
                search_domains: Vec::new(),
            }),
            firewall: Some(FirewallSettings {
                kill_switch: true,
                allow_lan: revision.is_multiple_of(2),
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn spec_without_system_proxy(id: u128, revision: u16) -> RuntimeSpec {
    let mut value = spec(id, revision);
    value.platform.system_proxy = None;
    value
}

fn system_proxy_only_spec(id: u128, revision: u16) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7000 + revision))),
                https_proxy: None,
                bypass: vec![format!("revision-{revision}")],
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn empty_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec::default(),
    )
    .unwrap()
}

fn core_only_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec::default(),
    )
    .unwrap()
}

fn core_system_proxy_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec {
                http_proxy: Some(SystemProxyEndpoint::CoreListener),
                https_proxy: None,
                bypass: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn packet_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        Some(egrio_runtime::RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: true,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

async fn all_active(platform: &InMemoryPlatform) -> bool {
    SystemProxyControl::observe(platform).await.unwrap().active
        && RouteControl::observe(platform).await.unwrap().active
        && DnsControl::observe(platform).await.unwrap().active
        && FirewallControl::observe(platform).await.unwrap().active
}

#[tokio::test]
async fn one_runtime_transaction_starts_and_stops_all_mutable_capabilities() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(100, 1)).await.unwrap();

    runtime.start().await.unwrap();
    assert!(all_active(platform.as_ref()).await);
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].checkpoint.capabilities.len(), 4);

    runtime.stop().await.unwrap();
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(
        !RouteControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(!DnsControl::observe(platform.as_ref()).await.unwrap().active);
    assert!(
        !FirewallControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn partial_start_is_rolled_back_in_one_runtime_transaction() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    platform.fail_next_apply(CapabilityKind::Route, "injected partial apply");
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(101, 1)).await.unwrap();

    assert!(runtime.start().await.is_err());
    assert_eq!(runtime.status().state, RuntimeState::Created);
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(
        !RouteControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn unverified_start_apply_is_rolled_back_without_committing() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    platform.unverify_next_apply(CapabilityKind::Route);
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(115, 1)).await.unwrap();

    assert!(matches!(
        runtime.start().await.unwrap_err(),
        RuntimeStartError::Capability(error) if error.code == CapabilityErrorCode::ApplyFailed
    ));
    assert_eq!(runtime.status().state, RuntimeState::Created);
    assert_eq!(runtime.status().generation.get(), 0);
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(
        !RouteControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(!DnsControl::observe(platform.as_ref()).await.unwrap().active);
    assert!(
        !FirewallControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    for key in [
        PlatformLeaseKey::kill_switch(),
        PlatformLeaseKey::default_route(),
        PlatformLeaseKey::system_dns(),
        PlatformLeaseKey::system_proxy(),
    ] {
        assert_eq!(sdk.lease_status(&key).state, PlatformLeaseState::Available);
    }
}

#[tokio::test]
async fn multi_capability_reload_publishes_one_generation_or_keeps_the_old_one() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store)
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(102, 1)).await.unwrap();
    runtime.start().await.unwrap();

    runtime.reload(spec(102, 2)).await.unwrap();
    assert_eq!(runtime.status().generation.get(), 2);
    assert_eq!(runtime.spec(), spec(102, 2));

    platform.fail_next_apply(CapabilityKind::Dns, "injected uncertain reload");
    assert!(matches!(
        runtime.reload(spec(102, 3)).await.unwrap_err(),
        RuntimeReloadError::Capability { .. }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 2);
    assert_eq!(runtime.spec(), spec(102, 2));
}

#[tokio::test]
async fn reload_can_restore_and_release_only_the_system_proxy_capability() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(104, 1)).await.unwrap();
    runtime.start().await.unwrap();

    let report = runtime
        .reload(spec_without_system_proxy(104, 1))
        .await
        .unwrap();

    assert!(report.committed);
    assert_eq!(report.generation.get(), 2);
    assert_eq!(runtime.spec(), spec_without_system_proxy(104, 1));
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(
        RouteControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(DnsControl::observe(platform.as_ref()).await.unwrap().active);
    assert!(
        FirewallControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Held
    );
    let stored = store.list_unresolved().await.unwrap().pop().unwrap();
    assert!(!stored
        .checkpoint
        .leases
        .contains(&PlatformLeaseKey::system_proxy()));
    assert!(!stored
        .checkpoint
        .capabilities
        .iter()
        .any(|capability| capability.lease_key == PlatformLeaseKey::system_proxy()));

    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn reload_acquires_and_expands_leases_for_added_capabilities() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(empty_spec(108)).await.unwrap();
    runtime.start().await.unwrap();

    runtime
        .reload(system_proxy_only_spec(108, 1))
        .await
        .expect("add the first platform capability");
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );

    let report = runtime
        .reload(spec(108, 1))
        .await
        .expect("expand the existing grant atomically");

    assert!(report.committed);
    assert!(report.resources.resources.iter().any(|change| {
        change.resource
            == RuntimeResource::Platform {
                capability: CapabilityKind::SystemProxy,
            }
            && change.outcome == RuntimeResourceOutcome::Retained
    }));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_dns()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::kill_switch()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .capabilities
            .len(),
        4
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn failed_added_capability_rolls_back_expanded_lease_and_old_generation() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(system_proxy_only_spec(113, 1))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    platform.fail_next_apply(CapabilityKind::Route, "injected added route failure");

    let error = runtime.reload(spec(113, 1)).await.unwrap_err();

    assert!(matches!(error, RuntimeReloadError::Capability { .. }));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), system_proxy_only_spec(113, 1));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_dns()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::kill_switch()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .capabilities
            .len(),
        1
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn failed_lease_rollback_is_fail_closed_with_the_actual_union_grant() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let coordinator = Arc::new(FailShrinkLeaseCoordinator::default());
    let runtime = Arc::new(
        Runtime::from_parts(
            system_proxy_only_spec(114, 1),
            coordinator.clone(),
            store.clone(),
            RuntimePorts {
                system_proxy: Some(platform.clone()),
                route: Some(platform.clone()),
                dns: Some(platform.clone()),
                firewall: Some(platform.clone()),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    runtime.start().await.unwrap();
    platform.fail_next_apply(CapabilityKind::Route, "injected added route failure");

    let error = runtime.reload(spec(114, 1)).await.unwrap_err();

    assert!(matches!(error, RuntimeReloadError::LeaseTransition { .. }));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), system_proxy_only_spec(114, 1));
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .capabilities
            .len(),
        1
    );
    runtime.stop().await.unwrap();
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn reload_adds_and_removes_the_runtime_owned_core_topology() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(TestCoreConfig))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(empty_spec(109)).await.unwrap();
    runtime.start().await.unwrap();

    let added = runtime.reload(core_only_spec(109)).await.unwrap();
    assert!(added.committed);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    assert_eq!(runtime.status().generation.get(), 2);

    let removed = runtime.reload(empty_spec(109)).await.unwrap();
    assert!(removed.committed);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
    assert_eq!(runtime.status().generation.get(), 3);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn a_core_started_alone_survives_network_capability_add_and_restore() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .core_config(Arc::new(TestCoreConfig))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(core_only_spec(110)).await.unwrap();
    runtime.start().await.unwrap();
    let listener = runtime.core_status().listen_addr.clone();

    runtime.reload(core_system_proxy_spec(110)).await.unwrap();
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    runtime.reload(core_only_spec(110)).await.unwrap();

    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    assert_eq!(runtime.core_status().listen_addr, listener);
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn runtime_owned_core_stops_after_complete_restore() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .core_config(Arc::new(TestCoreConfig))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(core_system_proxy_spec(111))
        .await
        .unwrap();
    runtime.start().await.unwrap();

    runtime.stop().await.unwrap();

    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn os_restore_failure_retains_core_checkpoint_and_lease() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .core_config(Arc::new(TestCoreConfig))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(core_system_proxy_spec(112))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    platform.fail_next_restore(CapabilityKind::SystemProxy, "injected restore failure");

    assert!(matches!(
        runtime.reload(core_only_spec(112)).await.unwrap_err(),
        RuntimeReloadError::RecoveryRequired { .. }
    ));

    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .phase,
        CheckpointPhase::RecoveryRequired
    );
}

#[tokio::test]
async fn reload_can_restore_and_release_the_complete_platform_topology() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(system_proxy_only_spec(107, 1))
        .await
        .unwrap();
    runtime.start().await.unwrap();
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );

    let report = runtime.reload(empty_spec(107)).await.unwrap();

    assert!(report.committed);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 2);
    assert_eq!(runtime.spec(), empty_spec(107));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn failed_system_proxy_topology_shrink_keeps_recovery_ownership() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(105, 1)).await.unwrap();
    runtime.start().await.unwrap();
    platform.fail_next_restore(
        CapabilityKind::SystemProxy,
        "injected proxy restore failure",
    );

    assert!(matches!(
        runtime
            .reload(spec_without_system_proxy(105, 1))
            .await
            .unwrap_err(),
        RuntimeReloadError::RecoveryRequired { .. }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), spec(105, 1));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    let stored = store.list_unresolved().await.unwrap().pop().unwrap();
    assert!(stored
        .checkpoint
        .capabilities
        .iter()
        .any(|capability| capability.lease_key == PlatformLeaseKey::system_proxy()));
}

#[tokio::test]
async fn failed_lease_shrink_is_visible_and_retains_recovery_ownership() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let coordinator = Arc::new(FailShrinkLeaseCoordinator::default());
    let runtime = Arc::new(
        Runtime::from_parts(
            spec(106, 1),
            coordinator.clone(),
            store.clone(),
            RuntimePorts {
                system_proxy: Some(platform.clone()),
                route: Some(platform.clone()),
                dns: Some(platform.clone()),
                firewall: Some(platform.clone()),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    runtime.start().await.unwrap();

    assert!(matches!(
        runtime
            .reload(spec_without_system_proxy(106, 1))
            .await
            .unwrap_err(),
        RuntimeReloadError::LeaseTransition {
            error: LeaseTransitionError {
                code: LeaseTransitionErrorCode::InvalidState,
                ..
            },
            ..
        }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), spec(106, 1));
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::RecoveryRequired
    );
    let stored = store.list_unresolved().await.unwrap().pop().unwrap();
    assert_eq!(stored.checkpoint.phase, CheckpointPhase::RecoveryRequired);
    assert!(stored
        .checkpoint
        .leases
        .contains(&PlatformLeaseKey::system_proxy()));
    assert!(!stored
        .checkpoint
        .capabilities
        .iter()
        .any(|capability| capability.lease_key == PlatformLeaseKey::system_proxy()));

    runtime.stop().await.unwrap();
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn packet_capture_uses_the_same_runtime_transaction_and_persists_all_leases() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .packet_data_plane(Arc::new(IdlePacketDataPlane))
        .core_config(Arc::new(TestCoreConfig))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec(103)).await.unwrap();

    runtime.start().await.unwrap();
    assert!(
        PacketCapture::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    let checkpoint = store.list_unresolved().await.unwrap().pop().unwrap();
    assert_eq!(
        checkpoint.checkpoint.leases,
        vec![
            PlatformLeaseKey::packet_capture(),
            PlatformLeaseKey::default_route(),
        ]
    );

    runtime.stop().await.unwrap();
    assert!(
        !PacketCapture::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
}
