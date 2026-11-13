//! The macOS host: the desktop runs as the user, the launchd service opens
//! the utun, routes both halves of each family into it and makes its
//! resolver the system's default, and an App Nap background activity is held
//! while a capture layer is active. Process attribution stays in this
//! process.
use std::sync::Arc;

use egrio_platform::CaptureLayers;
use egrio_platform_macos::MacosRuntimeBackgroundActivity;
use egrio_runtime::{
    CheckpointStore, CoreConfigSource, PacketCaptureSettings, PacketCaptureSource, Runtime,
    RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec, RuntimeSpec,
};
use egrio_sdk::EgrioSdk;

use super::{
    core_listener_system_proxy_spec, core_start_inputs, DesktopHost, PreparedCoreConfiguration,
    ProbeEgress,
};

const MACOS_RUNTIME_ID: RuntimeId = RuntimeId::from_uuid(uuid::Uuid::from_u128(
    0x436c_6173_6858_4d61_6352_756e_7469_6d65,
));

pub struct Host {
    sdk: EgrioSdk,
    /// Core's egress guard, which records dials it left unbound while the
    /// tunnel was closed.
    egress_guard: Arc<egrio_platform_macos::MacosEgressInterfaceBinder>,
}

/// TUN shapes no Core input: the guard binds Core sockets to the physical
/// uplink and reports its resolvers while the tunnel is open. The flow
/// scanner attributes system-proxy and TUN connections alike.
#[derive(Debug)]
struct MacosRuntimeCoreConfig {
    configuration: Arc<PreparedCoreConfiguration>,
    egress_socket_guard: Arc<dyn egrio_core::EgressSocketGuard>,
}

impl CoreConfigSource for MacosRuntimeCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        core_start_inputs(
            &self.configuration,
            egrio_platform_macos::macos_tun_core_capture_config(),
            self.egress_socket_guard.clone(),
            Arc::new(egrio_platform_macos::MacosFlowScanner::default()),
        )
    }
}

impl Host {
    pub(super) fn new(
        checkpoints: &Arc<dyn CheckpointStore>,
        configuration: &Arc<PreparedCoreConfiguration>,
    ) -> Result<Self, String> {
        let tun_egress = Arc::new(egrio_platform_macos::MacosTunEgress::default());
        let egress_guard = Arc::new(egrio_platform_macos::MacosEgressInterfaceBinder::tun_gated(
            tun_egress.clone(),
        ));
        let sdk = EgrioSdk::builder()
            .checkpoint_store(checkpoints.clone())
            .core_config(Arc::new(MacosRuntimeCoreConfig {
                configuration: configuration.clone(),
                egress_socket_guard: egress_guard.clone(),
            }))
            .macos_service(egrio_sdk::MacosServiceConfig {
                runtime_id: MACOS_RUNTIME_ID,
                app_version: env!("CARGO_PKG_VERSION").into(),
                tun_egress,
            })
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { sdk, egress_guard })
    }
}

impl DesktopHost for Host {
    type Activity = MacosRuntimeBackgroundActivity;

    fn begin_activity() -> MacosRuntimeBackgroundActivity {
        MacosRuntimeBackgroundActivity::begin()
    }

    async fn create_runtime(&self) -> Result<Arc<Runtime>, String> {
        self.sdk
            .create_runtime(macos_runtime_spec(CaptureLayers::NONE)?)
            .await
            .map_err(|error| error.to_string())
    }

    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String> {
        macos_runtime_spec(layers)
    }

    fn default_capture_mtu(&self) -> Result<u32, String> {
        Ok(egrio_platform_macos::MACOS_TUN_MTU)
    }

    /// A dial left unbound while the tunnel was closed: XNU routes it by
    /// destination, so the tunnel captures it once open.
    fn take_unprotected_dials(&self) -> bool {
        self.egress_guard.take_unbound()
    }

    async fn recover_unresolved(&self) -> Result<(), String> {
        self.sdk
            .recover_unresolved()
            .await
            .map(drop)
            .map_err(|error| error.to_string())
    }

    /// Binds the probe to the physical uplink.
    async fn standalone_probe_egress(&self) -> Result<ProbeEgress, String> {
        let physical =
            tokio::task::spawn_blocking(egrio_platform_macos::MacosPhysicalEgress::capture)
                .await
                .map_err(|error| format!("prepare node probe egress: {error}"))??;
        Ok((physical.config, Some(physical.socket_guard)))
    }
}

/// The tunnel installs its own default routes and resolver; macOS has no
/// separate Route, DNS or firewall capability.
fn macos_runtime_spec(layers: CaptureLayers) -> Result<RuntimeSpec, String> {
    RuntimeSpec::with_core(
        MACOS_RUNTIME_ID,
        // A taken or reserved mixed-port gives way to a free one; the
        // app warns (see `ListenerFallback`).
        Some(RuntimeCoreSpec {
            listen_port_fallback: true,
            ..RuntimeCoreSpec::default()
        }),
        RuntimePlatformSpec {
            packet_capture: layers.tun.then_some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: egrio_platform_macos::MACOS_TUN_MTU,
                install_default_route: true,
                install_dns: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: layers.system_proxy.then(core_listener_system_proxy_spec),
            ..RuntimePlatformSpec::default()
        },
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::{spec_capture_layers, DesktopRuntime};
    use super::*;
    use egrio_runtime::SystemProxyEndpoint;

    #[test]
    fn macos_capture_layers_map_to_four_fixed_runtime_topologies() {
        for (system_proxy, tun) in [(false, false), (true, false), (false, true), (true, true)] {
            let spec = macos_runtime_spec(CaptureLayers { system_proxy, tun }).unwrap();

            assert_eq!(spec.id, MACOS_RUNTIME_ID);
            assert!(spec.core.is_some());
            assert_eq!(
                spec_capture_layers(&spec),
                CaptureLayers { system_proxy, tun }
            );
            assert!(spec.platform.firewall.is_none());
            assert!(spec.platform.route.is_none());
            assert!(spec.platform.dns.is_none());
            if let Some(proxy) = spec.platform.system_proxy {
                assert_eq!(proxy.http_proxy, Some(SystemProxyEndpoint::CoreListener));
                assert_eq!(proxy.https_proxy, Some(SystemProxyEndpoint::CoreListener));
            }
        }
    }

    #[tokio::test]
    async fn desktop_runtime_uses_the_persistent_runtime_checkpoint_directory() {
        let directory =
            std::env::temp_dir().join(format!("egrio-desktop-runtime-{}", uuid::Uuid::new_v4()));
        let sdk = DesktopRuntime::with_checkpoint_directory(directory.clone()).unwrap();
        assert!(sdk
            .host
            .sdk
            .bootstrap_recovery()
            .await
            .unwrap()
            .checkpoints
            .is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }
}
