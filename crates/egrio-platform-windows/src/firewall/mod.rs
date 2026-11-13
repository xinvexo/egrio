#[cfg(not(windows))]
mod unsupported;

#[cfg(windows)]
mod windows_wfp;

#[cfg(not(windows))]
pub use unsupported::windows_firewall_net_event_diagnostic_with_input;
#[cfg(windows)]
pub use windows_wfp::{
    start_windows_firewall_kill_switch_session, windows_firewall_kill_switch_filter_plan,
    windows_firewall_net_event_diagnostic_with_input,
    windows_firewall_observe_kill_switch_filter_keys, WindowsFirewallKillSwitchRestoreReport,
    WindowsFirewallKillSwitchSession, WindowsFirewallKillSwitchSessionReport,
    WindowsFirewallSublayerReport,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallNetEventDiagnosticReport {
    pub supported_os: bool,
    pub read_only: bool,
    pub engine_opened: bool,
    pub enum_handle_opened: bool,
    pub net_events_available: bool,
    pub events_requested: u32,
    pub event_window_start_filetime: Option<u64>,
    pub event_window_end_filetime: Option<u64>,
    pub enum_filter_conditions: Vec<WindowsFirewallKillSwitchCondition>,
    pub events_returned: u32,
    pub dns_relevant_events: usize,
    pub dns_relevant_layers: Vec<WindowsFirewallNetEventLayerSummary>,
    pub events: Vec<WindowsFirewallNetEventRecord>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallNetEventDiagnosticInput {
    pub events_requested: u32,
    pub event_window_start_filetime: Option<u64>,
    pub event_window_end_filetime: Option<u64>,
    pub enum_filter_conditions: Vec<WindowsFirewallKillSwitchCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallNetEventLayerSummary {
    pub layer_id: Option<u16>,
    pub layer_name: Option<String>,
    pub dns_relevant_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallNetEventRecord {
    pub event_type: String,
    pub event_type_code: i32,
    pub timestamp_filetime: u64,
    pub flags: u32,
    pub ip_version: Option<String>,
    pub ip_protocol: Option<u8>,
    pub local_addr: Option<String>,
    pub local_addr_raw: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_addr_raw: Option<String>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub scope_id: Option<u32>,
    pub filter_id: Option<u64>,
    pub layer_id: Option<u16>,
    pub layer_name: Option<String>,
    pub reauth_reason: Option<u32>,
    pub ms_fwp_direction: Option<u32>,
    pub is_loopback: Option<bool>,
    pub dns_relevant: bool,
}

/// The IPv6 posture the filter plan enforces while capture is active. IPv6 is
/// either tunneled or blocked unless the operator explicitly chooses `Off`,
/// so global IPv6 never leaks alongside a captured IPv4 default route.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallIpv6Mode {
    /// IPv6 is routed into the tunnel like IPv4.
    Tunnel,
    /// No IPv6 enters the tunnel, so it is blocked but for loopback, the LAN
    /// scopes and excluded destinations: none leaks to the physical network.
    #[default]
    Block,
    /// No IPv6 filters at all: an explicit operator choice to leave global
    /// IPv6 to the OS (a leak relative to capture), warned about loudly.
    Off,
}

impl WindowsFirewallIpv6Mode {
    /// True when IPv6 DNS outside the tunnel is blocked: IPv6 is tunneled or
    /// blocked.
    pub fn guards_v6_dns(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// True when IPv6 stays out of the tunnel and is blocked, with the
    /// loopback, LAN-scope and excluded-destination permits under the block.
    pub fn blocks_v6(self) -> bool {
        matches!(self, Self::Block)
    }

    /// True when IPv6 is routed into the tunnel.
    pub fn tunnels_v6(self) -> bool {
        matches!(self, Self::Tunnel)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchFilterPlanInput {
    pub wintun_interface_index: Option<u32>,
    pub protected_app_paths: Vec<String>,
    pub ipv6: WindowsFirewallIpv6Mode,
    /// Destinations the capture routes leave outside the tunnel.
    pub excluded_prefixes: Vec<egrio_runtime::IpPrefix>,
    /// The Core's fake-IP pool and its IPv6 projection, blocked outside the
    /// tunnel.
    pub fake_ip_prefixes: Vec<egrio_runtime::IpPrefix>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchFilterPlan {
    pub production_ready: bool,
    pub filters: Vec<WindowsFirewallKillSwitchFilterSpec>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchFilterSpec {
    pub key: String,
    pub name: String,
    pub role: WindowsFirewallKillSwitchFilterRole,
    pub sublayer: WindowsFirewallSublayerKind,
    pub layer: WindowsFirewallKillSwitchLayer,
    pub action: WindowsFirewallKillSwitchAction,
    pub weight: u64,
    pub conditions: Vec<WindowsFirewallKillSwitchCondition>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallKillSwitchFilterRole {
    PermitWintunInterface,
    PermitDnsEgress,
    PermitLoopback,
    PermitLanBypass,
    PermitExcludedDestination,
    /// Outside the tunnel a fake IP reaches nothing: the connect fails at once.
    BlockFakeIp,
    BlockDnsLeak,
    /// IPv6 the tunnel does not carry.
    BlockUntunneledIpv6,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallSublayerKind {
    Traffic,
    DnsLeakPrevention,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallKillSwitchLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallKillSwitchAction {
    Permit,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchCondition {
    pub field: WindowsFirewallKillSwitchConditionField,
    pub matcher: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsFirewallKillSwitchConditionField {
    AleAppId,
    InterfaceIndex,
    InterfaceType,
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpRemotePort,
}
