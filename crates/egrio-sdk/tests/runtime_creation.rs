use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use egrio_runtime::{
    CheckpointStore, CoreConfigSource, PlatformLeaseKey, RuntimeCoreSpec, RuntimeId,
    RuntimePlatformSpec, RuntimeSpec, RuntimeStartError, RuntimeState, SystemProxyEndpoint,
    SystemProxySettings, SystemProxySpec,
};
use egrio_sdk::{
    EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, RuntimeCreateError, RuntimeRemoveError,
};
use uuid::Uuid;

fn spec(id: u128) -> RuntimeSpec {
    spec_with_port(id, 7890)
}

fn spec_with_port(id: u128, port: u16) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], port))),
                https_proxy: None,
                bypass: Vec::new(),
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn stopped_runtime_starts_directly_with_a_replacement_spec() {
    let sdk = sdk();
    let runtime = sdk.create_runtime(spec_with_port(17, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    runtime.stop().await.unwrap();
    let replacement = spec_with_port(17, 7891);

    let report = runtime
        .start_with_spec(replacement.clone())
        .await
        .expect("stopped Runtime starts with the replacement topology");

    assert!(report.changed);
    assert_eq!(runtime.spec(), replacement);
    runtime.stop().await.unwrap();
}

fn sdk() -> EgrioSdk {
    EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(Arc::new(egrio_sdk::InMemoryPlatform::new()))
        .build()
        .unwrap()
}

#[tokio::test]
async fn creation_is_inert_and_runtime_state_is_instance_local() {
    let sdk = sdk();
    let first = sdk.create_runtime(spec(1)).await.unwrap();
    let second = sdk.create_runtime(spec(2)).await.unwrap();
    assert_eq!(first.status().state, RuntimeState::Created);
    assert_eq!(second.status().state, RuntimeState::Created);
    assert_eq!(first.lease_request().unwrap().owner(), first.id());
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        egrio_runtime::PlatformLeaseState::Available
    );
}

fn core_inputs(id: &str) -> Result<egrio_core::CoreStartInputs, String> {
    Ok(egrio_core::CoreStartInputs {
        capture: Default::default(),
        profile: egrio_core::RuntimeProfile::new(id),
        egress: egrio_core::NativeCoreEgressConfig::default(),
        egress_socket_guard: None,
        flow_scanner: None,
        fake_ip_mappings: None,
    })
}

#[derive(Debug)]
struct TestCoreConfig(&'static str);

impl CoreConfigSource for TestCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        core_inputs(self.0)
    }
}

fn core_only_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::with_core(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn core_only_runtime_start_reload_stop_and_instances_are_isolated() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(TestCoreConfig("core-only")))
        .build()
        .unwrap();
    let first = sdk.create_runtime(core_only_spec(14)).await.unwrap();
    let second = sdk.create_runtime(core_only_spec(15)).await.unwrap();

    let first_start = first.start().await.expect("start first core-only Runtime");
    let second_start = second
        .start()
        .await
        .expect("start second core-only Runtime");
    assert!(first_start.changed);
    assert!(second_start.changed);
    assert!(first_start.checkpoint_id.is_none());
    assert!(second_start.checkpoint_id.is_none());
    let first_listener = first
        .core_status()
        .listen_addr
        .expect("first Runtime listener");
    let second_listener = second
        .core_status()
        .listen_addr
        .expect("second Runtime listener");
    assert_ne!(first_listener, second_listener);

    let reload = first
        .reload(core_only_spec(14))
        .await
        .expect("reload unchanged core-only Runtime");
    assert!(!reload.committed);
    assert_eq!(reload.generation, first_start.generation);
    assert_eq!(
        first.core_status().listen_addr.as_deref(),
        Some(first_listener.as_str())
    );

    first.stop().await.expect("stop first core-only Runtime");
    assert_eq!(
        first.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
    assert_eq!(
        second.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    second.stop().await.expect("stop second core-only Runtime");
}

#[tokio::test]
async fn listener_bind_failure_precedes_lease_checkpoint_and_os_adapter() {
    let blocked = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve listener address");
    let blocked_addr = blocked.local_addr().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let platform = Arc::new(InMemoryPlatform::with_event_log(events.clone()));
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(checkpoints.clone())
        .platform(platform)
        .core_config(Arc::new(TestCoreConfig("bind-failure")))
        .build()
        .unwrap();
    let runtime = sdk
        .create_runtime(
            RuntimeSpec::with_core(
                RuntimeId::from_uuid(Uuid::from_u128(16)),
                Some(RuntimeCoreSpec {
                    listen_addr: Some(blocked_addr),
                    dns_listen_addr: None,
                    listen_port_fallback: false,
                }),
                RuntimePlatformSpec {
                    system_proxy: Some(SystemProxySpec {
                        http_proxy: Some(SystemProxyEndpoint::CoreListener),
                        https_proxy: None,
                        bypass: Vec::new(),
                    }),
                    ..RuntimePlatformSpec::default()
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert!(matches!(
        runtime.start().await.expect_err("listener bind must fail"),
        RuntimeStartError::Core(_)
    ));
    assert_eq!(runtime.status().state, RuntimeState::Created);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        egrio_runtime::PlatformLeaseState::Available
    );
    assert!(checkpoints.list_unresolved().await.unwrap().is_empty());
    assert!(events.lock().expect("event log mutex").is_empty());
}

#[tokio::test]
async fn each_runtime_owns_an_isolated_core_lifecycle() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(TestCoreConfig("isolated-core")))
        .build()
        .unwrap();
    let first = sdk.create_runtime(core_only_spec(6)).await.unwrap();
    let second = sdk.create_runtime(core_only_spec(7)).await.unwrap();

    let started = first.start().await.expect("start first Runtime Core");

    assert!(started.changed);
    assert_eq!(
        first.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    assert_eq!(
        second.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );

    let stopped = first.stop().await.expect("stop first Runtime and Core");
    assert!(stopped.restored);
    assert_eq!(
        first.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
}

#[tokio::test]
async fn a_core_only_start_is_an_idempotent_runtime_transaction() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(TestCoreConfig("runtime-core-config")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(core_only_spec(8)).await.unwrap();
    let started = runtime.start().await.expect("start the Runtime's Core");
    let listener = runtime.core_status().listen_addr.clone();

    let retained = runtime
        .start()
        .await
        .expect("a second start of a running Runtime changes nothing");

    assert!(started.changed);
    assert!(!retained.changed);
    assert_eq!(runtime.core_status().listen_addr, listener);
    runtime.stop().await.expect("stop the Runtime and its Core");
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Stopped
    );
}

#[tokio::test]
async fn runtime_ids_remain_reserved_until_explicit_lifecycle_removal_exists() {
    let sdk = sdk();
    let first = sdk.create_runtime(spec(3)).await.unwrap();
    assert!(matches!(
        sdk.create_runtime(spec(3)).await.unwrap_err(),
        RuntimeCreateError::DuplicateRuntimeId(_)
    ));
    drop(first);
    assert!(matches!(
        sdk.create_runtime(spec(3)).await.unwrap_err(),
        RuntimeCreateError::DuplicateRuntimeId(_)
    ));
}

#[tokio::test]
async fn requested_platform_capabilities_require_injected_ports() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .build()
        .unwrap();
    assert!(matches!(
        sdk.create_runtime(spec(4)).await.unwrap_err(),
        RuntimeCreateError::Assembly(_)
    ));
}

#[tokio::test]
async fn only_verified_stopped_runtimes_can_be_removed_and_reused() {
    let sdk = sdk();
    let runtime = sdk.create_runtime(spec(5)).await.unwrap();
    assert!(matches!(
        sdk.remove_runtime(runtime.id()).await.unwrap_err(),
        RuntimeRemoveError::NotStopped { .. }
    ));
    runtime.stop().await.unwrap();
    sdk.remove_runtime(runtime.id()).await.unwrap();
    sdk.create_runtime(spec(5)).await.unwrap();
}
