#![cfg(feature = "platform-windows")]

use std::sync::Arc;

use egrio_runtime::{
    RuntimeId, RuntimePlatformSpec, RuntimeSpec, SystemProxySettings, SystemProxySpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore};

#[tokio::test]
async fn windows_feature_assembles_the_local_system_proxy_port_without_service_context() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .windows_system_proxy()
        .build()
        .unwrap();
    let spec = RuntimeSpec::new(
        RuntimeId::new(),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
                bypass: vec!["localhost".into()],
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap();

    let runtime = sdk.create_runtime(spec).await.unwrap();
    assert!(runtime.assembly_is_complete());
}
