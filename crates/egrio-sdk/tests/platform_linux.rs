#![cfg(feature = "platform-linux")]
use egrio_core::{CoreStartInputs, RuntimeProfile};
use egrio_platform_linux::{LinuxTun, LinuxTunConfig};
use egrio_runtime::{
    CoreConfigSource, DnsSettings, FirewallSettings, PacketCaptureSettings, PacketCaptureSource,
    RouteSettings, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec, RuntimeSpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, NativeCorePacketDataPlane};
use std::sync::Arc;
#[derive(Debug)]
struct Config;
impl CoreConfigSource for Config {
    fn load(&self) -> Result<CoreStartInputs, String> {
        let profile = RuntimeProfile::new("linux-tun-assembly");
        Ok(CoreStartInputs {
            capture: egrio_platform_linux::linux_tun_core_capture_config(),
            profile,
            egress: Default::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}
#[tokio::test]
async fn linux_feature_assembles_one_packet_plane_and_explicit_dns_firewall_ports() {
    let tun = LinuxTun::new(LinuxTunConfig::default()).unwrap();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(Config))
        .packet_capture(tun.capture)
        .route_control(tun.route)
        .dns_control(tun.dns)
        .firewall_control(tun.firewall)
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let spec = RuntimeSpec::with_core(
        RuntimeId::new(),
        Some(RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            route: Some(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            dns: Some(DnsSettings {
                servers: Vec::new(),
                search_domains: Vec::new(),
            }),
            firewall: Some(FirewallSettings {
                kill_switch: true,
                allow_lan: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let runtime = sdk.create_runtime(spec).await.unwrap();
    assert!(runtime.assembly_is_complete());
}
