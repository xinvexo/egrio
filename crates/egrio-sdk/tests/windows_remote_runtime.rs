#![cfg(feature = "platform-windows")]

use egrio_runtime::RuntimeId;
use egrio_sdk::WindowsServiceConfig;
use uuid::Uuid;

#[test]
fn windows_service_config_binds_one_runtime_identity() {
    let runtime_id = RuntimeId::from_uuid(Uuid::from_u128(0x1234));
    let config = WindowsServiceConfig {
        runtime_id,
        service_name: "EgrioService".into(),
        app_version: "test".into(),
        #[cfg(windows)]
        tun_egress: Default::default(),
    };

    assert_eq!(config.runtime_id, runtime_id);
    assert_eq!(config.service_name, "EgrioService");
}
