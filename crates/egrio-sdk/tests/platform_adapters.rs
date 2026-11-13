#![cfg(all(feature = "platform-macos", target_os = "macos"))]

use std::net::SocketAddr;
use std::sync::Arc;

use egrio_core::{CoreStartInputs, RuntimeProfile};
use egrio_runtime::{
    CoreConfigSource, PacketCaptureSettings, PacketCaptureSource, RuntimeCoreSpec, RuntimeId,
    RuntimePlatformSpec, RuntimeSpec, SystemProxySettings, SystemProxySpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, MacosServiceConfig};

#[derive(Debug)]
struct Config;

impl CoreConfigSource for Config {
    fn load(&self) -> Result<CoreStartInputs, String> {
        Ok(CoreStartInputs {
            capture: egrio_platform_macos::macos_tun_core_capture_config(),
            profile: RuntimeProfile::new("macos-tun-assembly"),
            egress: Default::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

/// The macOS service assembles the packet capture and the system proxy that
/// publishes through the open tunnel; nothing connects to the service until
/// a capability runs.
#[tokio::test]
async fn macos_service_assembles_the_capture_and_the_system_proxy() {
    let runtime_id = RuntimeId::new();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(Config))
        .macos_service(MacosServiceConfig {
            runtime_id,
            app_version: "test".into(),
            tun_egress: Arc::default(),
        })
        .build()
        .unwrap();
    let spec = RuntimeSpec::with_core(
        runtime_id,
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: egrio_platform_macos::MACOS_TUN_MTU,
                install_default_route: true,
                install_dns: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
                https_proxy: None,
                bypass: vec!["localhost".into()],
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap();

    let runtime = sdk.create_runtime(spec).await.unwrap();
    assert!(runtime.assembly_is_complete());
}
