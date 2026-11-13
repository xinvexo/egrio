#[cfg(target_os = "macos")]
mod app_identity;
#[cfg(target_os = "macos")]
mod background_activity;
mod dns_snapshot;
mod egress;
mod egress_binding;
#[cfg(target_os = "macos")]
mod network_monitor;
#[cfg(target_os = "macos")]
mod process_attribution;
mod runtime_system_proxy;
mod service_layout;
mod system_proxy;
mod tun;

#[cfg(target_os = "macos")]
pub use app_identity::resolve_app_display_identities;
#[cfg(target_os = "macos")]
pub use background_activity::{
    runtime_background_activity_is_active, MacosRuntimeBackgroundActivity,
};
pub use dns_snapshot::{capture_macos_system_dns_snapshot, MacosSystemDnsSnapshot};
pub use egress::{build_macos_native_core_egress_config, MacosPhysicalEgress};
pub use egress_binding::{MacosEgressInterfaceBinder, MacosTunEgress};
#[cfg(target_os = "macos")]
pub use process_attribution::MacosFlowScanner;
pub use runtime_system_proxy::MacosSystemProxyAdapter;
pub use service_layout::{
    MACOS_APP_IDENTIFIER, MACOS_SERVICE_BUNDLE_PROGRAM, MACOS_SERVICE_LABEL, MACOS_SERVICE_PLIST,
    MACOS_SERVICE_RUN_COMMAND, MACOS_SERVICE_SOCKET,
};
pub use system_proxy::{snapshots_have_same_effective_settings, system_proxy_status};
pub use tun::{
    macos_tun_core_capture_config, macos_tun_reserved_addresses, MACOS_TUN_IPV4,
    MACOS_TUN_IPV4_PEER, MACOS_TUN_IPV4_PREFIX, MACOS_TUN_IPV6, MACOS_TUN_IPV6_PREFIX,
    MACOS_TUN_MTU, MACOS_TUN_VIRTUAL_DNS,
};
#[cfg(target_os = "macos")]
pub use tun::{MacosTunDevice, MacosTunOpen, MacosTunSession};
