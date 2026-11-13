//! The Linux host: the desktop runs as the user, the root helper applies TUN
//! mode's capabilities and marks Core sockets, and the system proxy and
//! process attribution stay in this process.
use std::sync::Arc;

use egrio_platform::CaptureLayers;
use egrio_runtime::{
    CheckpointStore, CoreConfigSource, DnsSettings, FirewallSettings, PacketCaptureSettings,
    PacketCaptureSource, RouteSettings, Runtime, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec,
    RuntimeSpec,
};
use egrio_sdk::EgrioSdk;

use super::{
    core_listener_system_proxy_spec, core_start_inputs, DesktopHost, PreparedCoreConfiguration,
};

const LINUX_RUNTIME_ID: RuntimeId = RuntimeId::from_uuid(uuid::Uuid::from_u128(
    0x436c_6173_6858_4c69_6e75_7852_756e_7469,
));

pub struct Host {
    sdk: EgrioSdk,
    /// Core's egress guard, which records sockets the service could not mark.
    egress_guard: Arc<egrio_sdk::ServiceMarkingSocketGuard>,
}

/// TUN shapes no Core input: the guard has the Linux service mark Core
/// sockets and reports the TUN's physical resolvers while the TUN layer is
/// active. The flow scanner attributes system-proxy and TUN connections alike.
#[derive(Debug)]
struct LinuxRuntimeCoreConfig {
    configuration: Arc<PreparedCoreConfiguration>,
    egress_socket_guard: Arc<dyn egrio_core::EgressSocketGuard>,
}

impl CoreConfigSource for LinuxRuntimeCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        core_start_inputs(
            &self.configuration,
            egrio_platform_linux::linux_tun_core_capture_config(),
            self.egress_socket_guard.clone(),
            Arc::new(egrio_platform_linux::LinuxFlowScanner),
        )
    }
}

impl Host {
    pub(super) fn new(
        checkpoints: &Arc<dyn CheckpointStore>,
        configuration: &Arc<PreparedCoreConfiguration>,
    ) -> Result<Self, String> {
        let tun_egress = Arc::new(egrio_platform_linux::LinuxTunEgress::default());
        let egress_guard = Arc::new(egrio_sdk::ServiceMarkingSocketGuard::new(
            tun_egress.clone(),
        ));
        let sdk = EgrioSdk::builder()
            .checkpoint_store(checkpoints.clone())
            .core_config(Arc::new(LinuxRuntimeCoreConfig {
                configuration: configuration.clone(),
                egress_socket_guard: egress_guard.clone(),
            }))
            .linux_service(egrio_sdk::LinuxServiceConfig {
                runtime_id: LINUX_RUNTIME_ID,
                app_version: env!("CARGO_PKG_VERSION").into(),
                tun_egress,
            })
            .system_proxy(Arc::new(
                egrio_platform_linux::LinuxSystemProxyAdapter::new(),
            ))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { sdk, egress_guard })
    }
}

impl DesktopHost for Host {
    type Activity = ();

    fn begin_activity() {}

    async fn create_runtime(&self) -> Result<Arc<Runtime>, String> {
        self.sdk
            .create_runtime(linux_runtime_spec(CaptureLayers::NONE)?)
            .await
            .map_err(|error| error.to_string())
    }

    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String> {
        linux_runtime_spec(layers)
    }

    fn default_capture_mtu(&self) -> Result<u32, String> {
        Ok(egrio_platform_linux::LinuxTunConfig::default().mtu)
    }

    /// A socket the service could not mark: policy routing sends it into
    /// the TUN.
    fn take_unprotected_dials(&self) -> bool {
        self.egress_guard.take_unmarked()
    }

    async fn recover_unresolved(&self) -> Result<(), String> {
        self.sdk
            .recover_unresolved()
            .await
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

fn linux_runtime_spec(layers: CaptureLayers) -> Result<RuntimeSpec, String> {
    let tun = layers.tun;
    RuntimeSpec::with_core(
        LINUX_RUNTIME_ID,
        // A taken or reserved mixed-port gives way to a free one; the
        // app warns (see `ListenerFallback`).
        Some(RuntimeCoreSpec {
            listen_port_fallback: true,
            ..RuntimeCoreSpec::default()
        }),
        RuntimePlatformSpec {
            packet_capture: tun.then_some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: egrio_platform_linux::LinuxTunConfig::default().mtu,
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            route: tun.then_some(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            // Empty servers: the TUN's own virtual resolver.
            dns: tun.then_some(DnsSettings {
                servers: Vec::new(),
                search_domains: Vec::new(),
            }),
            firewall: tun.then_some(FirewallSettings {
                kill_switch: true,
                allow_lan: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: layers.system_proxy.then(core_listener_system_proxy_spec),
        },
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::spec_capture_layers;
    use super::*;

    #[test]
    fn linux_layers_map_to_their_runtime_capabilities() {
        for (system_proxy, tun) in [(false, false), (true, false), (false, true), (true, true)] {
            let spec = linux_runtime_spec(CaptureLayers { system_proxy, tun }).unwrap();
            assert_eq!(spec.id, LINUX_RUNTIME_ID);
            assert!(spec.core.is_some());
            assert_eq!(spec.platform.route.is_some(), tun);
            assert_eq!(spec.platform.dns.is_some(), tun);
            assert_eq!(
                spec.platform.firewall,
                tun.then_some(FirewallSettings {
                    kill_switch: true,
                    allow_lan: true,
                    excluded_prefixes: Vec::new(),
                    fake_ip_prefixes: Vec::new(),
                })
            );
            assert_eq!(
                spec_capture_layers(&spec),
                CaptureLayers { system_proxy, tun }
            );
        }
    }
}
