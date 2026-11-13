use super::*;

fn inputs(mtu: u32) -> FixedCoreConfig {
    FixedCoreConfig::new(RuntimeProfile::new("mtu-contract")).with_capture(
        egrio_core::NativeCoreCaptureConfig::default()
            .with_mtu(mtu)
            .unwrap(),
    )
}
fn sdk(events: Arc<Mutex<Vec<&'static str>>>, store: Arc<InMemoryCheckpointStore>) -> EgrioSdk {
    EgrioSdk::builder()
        .checkpoint_store(store)
        .platform(Arc::new(InMemoryPlatform::with_event_log(events.clone())))
        .core_config(Arc::new(inputs(1420)))
        .packet_data_plane(Arc::new(RecordingDataPlane { events }))
        .build()
        .unwrap()
}
#[tokio::test]
async fn mismatched_start_mtu_is_rejected_before_core_listener_checkpoint_or_os_preparation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = sdk(events.clone(), store.clone());
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    assert!(runtime
        .start()
        .await
        .unwrap_err()
        .to_string()
        .contains("MTU"));
    assert!(events.lock().unwrap().is_empty());
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert!(runtime.core_state_audit().is_none());
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::packet_capture()).state,
        PlatformLeaseState::Available
    );
}
#[tokio::test]
async fn adding_capture_to_a_core_requires_its_existing_mtu_before_any_os_preparation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = sdk(events.clone(), store.clone());
    let runtime = sdk
        .create_runtime(core_only_packet_runtime_spec())
        .await
        .unwrap();
    runtime.start().await.unwrap();
    let generation = runtime.status().generation;
    assert!(runtime
        .reload(packet_spec())
        .await
        .unwrap_err()
        .to_string()
        .contains("MTU"));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation, generation);
    assert!(events.lock().unwrap().is_empty());
    assert!(store.list_unresolved().await.unwrap().is_empty());
    let mut matching = packet_spec();
    matching.platform.packet_capture.as_mut().unwrap().mtu = 1420;
    runtime.reload(matching.clone()).await.unwrap();
    events.lock().unwrap().clear();
    matching.platform.packet_capture.as_mut().unwrap().mtu = 1500;
    assert!(runtime
        .reload(matching)
        .await
        .unwrap_err()
        .to_string()
        .contains("MTU"));
    assert!(
        events.lock().unwrap().is_empty(),
        "active MTU changes must not reach adapter prepare/apply"
    );
    runtime.stop().await.unwrap();
}
#[test]
fn invalid_packet_mtu_is_rejected_at_spec_validation() {
    for mtu in [0, 1279, 65536, u32::MAX] {
        let mut spec = packet_spec();
        spec.platform.packet_capture.as_mut().unwrap().mtu = mtu;
        assert_eq!(
            spec.validate().unwrap_err().code,
            egrio_runtime::RuntimeSpecErrorCode::InvalidPacketMtu
        );
    }
}

/// TUN that starts with the Core or joins a running one is refused before any
/// platform preparation when the Core's fake-IP pool could hand out the TUN's
/// own interface or virtual DNS address.
#[tokio::test]
async fn capture_is_refused_when_the_fake_ip_pool_covers_a_reserved_address() {
    let mut profile = egrio_core::RuntimeProfile::new("reserved-overlap");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = egrio_core::dns::config::DnsMode::FakeIp;
    profile.dns.fake_ip_range = "10.0.0.0/8".parse().unwrap();
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let platform = std::sync::Arc::new(egrio_sdk::InMemoryPlatform::with_event_log(events.clone()));
    platform.set_reserved_addresses(vec!["10.255.255.1".parse().unwrap()]);
    let sdk = egrio_sdk::EgrioSdk::builder()
        .checkpoint_store(std::sync::Arc::new(
            egrio_sdk::InMemoryCheckpointStore::new(),
        ))
        .platform(platform.clone())
        .core_config(std::sync::Arc::new(super::FixedCoreConfig::new(profile)))
        .packet_data_plane(std::sync::Arc::new(egrio_sdk::NativeCorePacketDataPlane))
        .build()
        .unwrap();

    let runtime = sdk.create_runtime(super::packet_spec()).await.unwrap();
    let error = runtime.start().await.unwrap_err().to_string();
    assert!(error.contains("10.255.255.1"), "{error}");
    assert!(!events.lock().unwrap().contains(&"capture.prepare"));

    // A pool clear of the reservation is accepted.
    platform.set_reserved_addresses(vec!["172.31.255.1".parse().unwrap()]);
    runtime.start().await.unwrap();
    assert!(events.lock().unwrap().contains(&"capture.prepare"));
    runtime.stop().await.unwrap();
}
