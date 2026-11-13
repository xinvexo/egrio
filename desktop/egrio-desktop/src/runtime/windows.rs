//! The Windows host: TUN mode through the privileged `egrio-service`, the
//! system proxy in this process, and Core egress bound to the physical
//! uplink while the TUN layer is active.
use std::sync::Arc;

use egrio_platform::CaptureLayers;
use egrio_platform_windows::{
    windows_runtime_interface_dns_servers, WindowsIpv6Policy, WindowsWintunConfig,
};
use egrio_runtime::{
    CheckpointStore, CoreConfigSource, DnsSettings, FirewallSettings, PacketCaptureSettings,
    PacketCaptureSource, RouteSettings, Runtime, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec,
    RuntimeSpec,
};
use egrio_sdk::{EgrioSdk, WindowsServiceConfig};

use super::{
    core_listener_system_proxy_spec, core_start_inputs, DesktopHost, DesktopRuntime,
    PreparedCoreConfiguration,
};

const WINDOWS_RUNTIME_ID: RuntimeId = RuntimeId::from_uuid(uuid::Uuid::from_u128(
    0x436c_6173_6858_5769_6e52_756e_7469_6d65,
));
const DEFAULT_WINDOWS_SERVICE_NAME: &str = "EgrioService";

type SystemProxyEvents =
    tokio::sync::mpsc::UnboundedReceiver<egrio_platform_windows::WindowsSystemProxyGuardEvent>;

pub struct Host {
    checkpoints: Arc<dyn CheckpointStore>,
    configuration: Arc<PreparedCoreConfiguration>,
    /// Created with the Runtime: it reads the Wintun settings, which
    /// recovery must not depend on.
    context: tokio::sync::OnceCell<Context>,
    system_proxy: Arc<egrio_platform_windows::WindowsSystemProxyAdapter>,
    system_proxy_events: std::sync::Mutex<Option<SystemProxyEvents>>,
}

struct Context {
    sdk: EgrioSdk,
    tun_egress: Arc<egrio_platform_windows::WindowsTunEgress>,
    wintun_config: WindowsWintunConfig,
}

/// TUN shapes no Core input: its physical resolvers and IPv6 posture reach
/// Core egress through the binder while the TUN layer is active. The flow
/// scanner attributes system-proxy and TUN connections alike.
#[derive(Debug)]
struct WindowsRuntimeCoreConfig {
    configuration: Arc<PreparedCoreConfiguration>,
    tun_egress: Arc<egrio_platform_windows::WindowsTunEgress>,
}

impl CoreConfigSource for WindowsRuntimeCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        core_start_inputs(
            &self.configuration,
            self.tun_egress.core_capture_config(),
            Arc::new(egrio_platform_windows::WindowsEgressInterfaceBinder::new(
                Arc::clone(&self.tun_egress),
            )),
            Arc::new(egrio_platform_windows::WindowsFlowScanner::default()),
        )
    }
}

impl Host {
    pub(super) fn new(
        checkpoints: &Arc<dyn CheckpointStore>,
        configuration: &Arc<PreparedCoreConfiguration>,
    ) -> Result<Self, String> {
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            checkpoints: checkpoints.clone(),
            configuration: configuration.clone(),
            context: tokio::sync::OnceCell::new(),
            system_proxy: Arc::new(
                egrio_platform_windows::WindowsSystemProxyAdapter::with_event_sender(events_tx),
            ),
            system_proxy_events: std::sync::Mutex::new(Some(events_rx)),
        })
    }

    fn context(&self) -> Result<&Context, String> {
        self.context
            .get()
            .ok_or_else(|| "Windows Runtime context is not initialized".into())
    }
}

/// The privileged service applies TUN mode's capabilities. Core egress binds
/// every dial to the physical uplink, so none is left unprotected.
impl DesktopHost for Host {
    type Activity = ();

    fn begin_activity() {}

    async fn create_runtime(&self) -> Result<Arc<Runtime>, String> {
        let context = self
            .context
            .get_or_try_init(|| async {
                let wintun_config = egrio_platform_windows::windows_wintun_config_from_env()?;
                let tun_egress = Arc::new(egrio_platform_windows::WindowsTunEgress::new(
                    wintun_config.clone(),
                ));
                let sdk = EgrioSdk::builder()
                    .checkpoint_store(self.checkpoints.clone())
                    .system_proxy(self.system_proxy.clone())
                    .core_config(Arc::new(WindowsRuntimeCoreConfig {
                        configuration: self.configuration.clone(),
                        tun_egress: Arc::clone(&tun_egress),
                    }))
                    .windows_service(windows_service_config(Arc::clone(&tun_egress)))
                    .build()
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(Context {
                    sdk,
                    tun_egress,
                    wintun_config,
                })
            })
            .await?;
        context
            .sdk
            .create_runtime(windows_runtime_spec(
                CaptureLayers::NONE,
                &context.wintun_config,
            )?)
            .await
            .map_err(|error| error.to_string())
    }

    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String> {
        windows_runtime_spec(layers, &self.context()?.wintun_config)
    }

    fn default_capture_mtu(&self) -> Result<u32, String> {
        Ok(self.context()?.wintun_config.mtu.into())
    }

    async fn recover_unresolved(&self) -> Result<(), String> {
        // Recovery only consumes persisted capability checkpoints. Do not
        // initialize the Core or read Wintun settings from the configuration store.
        let sdk = EgrioSdk::builder()
            .checkpoint_store(self.checkpoints.clone())
            .system_proxy(self.system_proxy.clone())
            .windows_service(windows_service_config(Arc::default()))
            .build()
            .map_err(|error| error.to_string())?;
        sdk.recover_unresolved()
            .await
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

impl DesktopRuntime {
    pub fn windows_ipv6_runtime_state(
        &self,
    ) -> Option<crate::ipv6_settings::WindowsIpv6RuntimeState> {
        use crate::ipv6_settings::{WindowsIpv6RequestedPolicy, WindowsIpv6RuntimeState};

        let context = self.host.context.get()?;
        if !self.capture_layers().tun {
            return None;
        }
        let capture_ipv6_enabled = context.tun_egress.overlay()?.ipv6_enabled;
        let requested_policy = match context.wintun_config.ipv6_policy {
            WindowsIpv6Policy::Auto => WindowsIpv6RequestedPolicy::Auto,
            WindowsIpv6Policy::Tunnel => WindowsIpv6RequestedPolicy::Tunnel,
            WindowsIpv6Policy::Block => WindowsIpv6RequestedPolicy::Block,
            WindowsIpv6Policy::Off => WindowsIpv6RequestedPolicy::Off,
        };
        Some(WindowsIpv6RuntimeState::from_capture(
            requested_policy,
            capture_ipv6_enabled,
        ))
    }

    pub fn take_windows_system_proxy_events(&self) -> Option<SystemProxyEvents> {
        self.host
            .system_proxy_events
            .lock()
            .expect("Windows system proxy event receiver mutex")
            .take()
    }
}

fn windows_service_config(
    tun_egress: Arc<egrio_platform_windows::WindowsTunEgress>,
) -> WindowsServiceConfig {
    let service_name = std::env::var("EGRIO_WINDOWS_SERVICE_NAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_WINDOWS_SERVICE_NAME.into());
    WindowsServiceConfig {
        runtime_id: WINDOWS_RUNTIME_ID,
        service_name,
        app_version: env!("CARGO_PKG_VERSION").into(),
        tun_egress,
    }
}

/// While the tunnel runs, the kill switch lets what leaves outside it through
/// (another VPN's own connections), but to fake IPs; it blocks everything
/// once the tunnel is gone.
fn windows_runtime_spec(
    layers: CaptureLayers,
    config: &WindowsWintunConfig,
) -> Result<RuntimeSpec, String> {
    let tun = layers.tun;
    let dns = if tun {
        Some(DnsSettings {
            servers: windows_runtime_interface_dns_servers(config)?,
            search_domains: Vec::new(),
        })
    } else {
        None
    };
    RuntimeSpec::with_core(
        WINDOWS_RUNTIME_ID,
        // A taken or reserved mixed-port gives way to a free one; the
        // app warns (see `ListenerFallback`).
        Some(RuntimeCoreSpec {
            listen_port_fallback: true,
            ..RuntimeCoreSpec::default()
        }),
        RuntimePlatformSpec {
            packet_capture: tun.then_some(PacketCaptureSettings {
                source: PacketCaptureSource::Tun,
                mtu: config.mtu.into(),
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: layers.system_proxy.then(core_listener_system_proxy_spec),
            route: tun.then_some(RouteSettings {
                default_route: config.route_all,
                excluded_prefixes: Vec::new(),
            }),
            dns,
            firewall: tun.then_some(FirewallSettings {
                kill_switch: true,
                allow_lan: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
        },
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::spec_capture_layers;
    use super::*;

    #[test]
    fn windows_layers_map_to_their_runtime_capabilities() {
        let config = WindowsWintunConfig::default();
        for (system_proxy, tun) in [(false, false), (true, false), (false, true), (true, true)] {
            let spec = windows_runtime_spec(CaptureLayers { system_proxy, tun }, &config).unwrap();
            assert_eq!(spec.id, WINDOWS_RUNTIME_ID);
            assert!(spec.core.is_some());
            assert_eq!(spec.platform.system_proxy.is_some(), system_proxy);
            assert_eq!(spec.platform.packet_capture.is_some(), tun);
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

    #[test]
    fn windows_tun_uses_dual_stack_interface_dns() {
        let config = WindowsWintunConfig {
            ipv6_policy: WindowsIpv6Policy::Tunnel,
            ..WindowsWintunConfig::default()
        };
        let spec = windows_runtime_spec(
            CaptureLayers {
                system_proxy: false,
                tun: true,
            },
            &config,
        )
        .unwrap();

        assert_eq!(
            spec.platform.dns.unwrap().servers,
            vec![
                "10.255.255.2".parse::<std::net::IpAddr>().unwrap(),
                "fd11:5ca1:ab1e::2".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn passive_windows_core_reads_do_not_initialize_the_runtime() {
        let directory =
            std::env::temp_dir().join(format!("egrio-desktop-runtime-{}", uuid::Uuid::new_v4()));
        let sdk = DesktopRuntime::with_checkpoint_directory(directory.clone()).unwrap();

        assert!(sdk
            .traffic_telemetry_since(Default::default())
            .await
            .is_none());
        assert!(sdk.core_status().is_none());
        assert!(sdk.traffic_volume().is_none());
        assert_eq!(sdk.capture_layers(), CaptureLayers::NONE);
        assert!(sdk
            .evaluate_core_route(&egrio_core::RouteMatchInput::default())
            .await
            .unwrap()
            .is_none());
        assert!(!sdk.restart_running_runtime().await.unwrap());
        assert!(sdk.host.context.get().is_none());
        assert!(sdk.runtime.get().is_none());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn windows_system_proxy_guard_events_have_one_host_consumer() {
        let directory =
            std::env::temp_dir().join(format!("egrio-desktop-runtime-{}", uuid::Uuid::new_v4()));
        let sdk = DesktopRuntime::with_checkpoint_directory(directory.clone()).unwrap();

        assert!(sdk.take_windows_system_proxy_events().is_some());
        assert!(sdk.take_windows_system_proxy_events().is_none());

        let _ = std::fs::remove_dir_all(directory);
    }
}
