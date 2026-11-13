use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DEFAULT_ADAPTER_NAME: &str = "Egrio Wintun";
const DEFAULT_TUNNEL_TYPE: &str = "Egrio";
const DEFAULT_ADAPTER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
const DEFAULT_ADAPTER_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);
const DEFAULT_DNS_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 2);
// ULA adapter address for the IPv6 side of the tunnel. The virtual DNS
// address is one address up. The `fd` prefix is RFC 4193 unique-local,
// keeping these addresses separate from globally routable prefixes.
const DEFAULT_ADAPTER_ADDRESS6: Ipv6Addr = Ipv6Addr::new(0xfd11, 0x5ca1, 0xab1e, 0, 0, 0, 0, 1);
const DEFAULT_ADAPTER_PREFIX_LENGTH6: u8 = 64;
const DEFAULT_INTERFACE_METRIC: u32 = 1;
const DEFAULT_ROUTE_METRIC: u32 = 1;
pub const DEFAULT_RING_CAPACITY: u32 = 4 * 1024 * 1024;
/// Wintun IP MTU: Wintun's largest packet. The tunnel never reaches a wire,
/// so it is sized for the per-packet cost of the capture path; see the
/// Windows platform document.
const DEFAULT_MTU: u16 = u16::MAX;

/// The IPv6 posture for a Windows capture session: exactly one of tunnel/block
/// is always enforced while capture is active unless the operator explicitly chooses
/// `Off`, so global IPv6 is never silently leaking alongside a captured IPv4
/// default route. `Auto` (the default) resolves at apply time to `Tunnel` when
/// the physical network has a usable IPv6 default, else `Block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowsIpv6Policy {
    #[default]
    Auto,
    Tunnel,
    Block,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsWintunConfig {
    pub adapter_name: String,
    pub tunnel_type: String,
    pub dll_path: Option<String>,
    pub adapter_address: Ipv4Addr,
    pub adapter_netmask: Ipv4Addr,
    /// The IPv6 posture: `Auto` tunnels v6 when the physical
    /// network has it and blocks it otherwise, `Tunnel`/`Block` force either
    /// state, and `Off` leaves global IPv6 to the OS. Resolved to a concrete
    /// tunnel/block/off mode at apply time, and the adapter, routes, DNS, and
    /// WFP v6 filters follow the resolved value.
    pub ipv6_policy: WindowsIpv6Policy,
    pub adapter_address6: Ipv6Addr,
    pub adapter_prefix_length6: u8,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub configure_interface: bool,
    pub restore_dns_on_exit: bool,
    pub route_all: bool,
    pub interface_metric: u32,
    pub route_metric: u32,
    pub delete_driver_on_uninstall: bool,
}

impl Default for WindowsWintunConfig {
    fn default() -> Self {
        Self {
            adapter_name: DEFAULT_ADAPTER_NAME.into(),
            tunnel_type: DEFAULT_TUNNEL_TYPE.into(),
            dll_path: None,
            adapter_address: DEFAULT_ADAPTER_ADDRESS,
            adapter_netmask: DEFAULT_ADAPTER_NETMASK,
            ipv6_policy: WindowsIpv6Policy::Auto,
            adapter_address6: DEFAULT_ADAPTER_ADDRESS6,
            adapter_prefix_length6: DEFAULT_ADAPTER_PREFIX_LENGTH6,
            dns_servers: vec![IpAddr::V4(DEFAULT_DNS_ADDRESS)],
            mtu: DEFAULT_MTU,
            ring_capacity: DEFAULT_RING_CAPACITY,
            configure_interface: true,
            restore_dns_on_exit: true,
            route_all: true,
            interface_metric: DEFAULT_INTERFACE_METRIC,
            route_metric: DEFAULT_ROUTE_METRIC,
            delete_driver_on_uninstall: false,
        }
    }
}

fn normalize_windows_wintun_config(
    mut config: WindowsWintunConfig,
) -> Result<WindowsWintunConfig, String> {
    validate_ipv4_netmask(config.adapter_netmask)?;
    validate_metric("interface_metric", config.interface_metric)?;
    validate_metric("route_metric", config.route_metric)?;
    if config.dns_servers.is_empty() {
        config.dns_servers = default_windows_wintun_dns_servers(&config)?;
    }
    Ok(config)
}

pub fn windows_wintun_config_from_env() -> Result<WindowsWintunConfig, String> {
    apply_windows_wintun_env_overrides(WindowsWintunConfig::default())
}

fn apply_windows_wintun_env_overrides(
    mut config: WindowsWintunConfig,
) -> Result<WindowsWintunConfig, String> {
    let dns_tracks_adapter = dns_servers_track_default(&config);
    let mut dns_configured = false;
    if let Some(value) = env_string("EGRIO_WINTUN_ADAPTER") {
        config.adapter_name = value;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_TUNNEL_TYPE") {
        config.tunnel_type = value;
    }
    config.dll_path = env_string("EGRIO_WINTUN_DLL");
    if let Some(value) = env_string("EGRIO_WINTUN_ADDRESS") {
        config.adapter_address = parse_ipv4_env("EGRIO_WINTUN_ADDRESS", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_NETMASK") {
        config.adapter_netmask = parse_ipv4_env("EGRIO_WINTUN_NETMASK", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_DNS") {
        config.dns_servers = parse_ip_list_env("EGRIO_WINTUN_DNS", &value)?;
        dns_configured = true;
    }
    if !dns_configured && dns_tracks_adapter {
        config.dns_servers = default_windows_wintun_dns_servers(&config)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_MTU") {
        config.mtu = parse_env("EGRIO_WINTUN_MTU", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_RING_CAPACITY") {
        config.ring_capacity = parse_env("EGRIO_WINTUN_RING_CAPACITY", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_CONFIGURE_INTERFACE") {
        config.configure_interface = parse_bool_env("EGRIO_WINTUN_CONFIGURE_INTERFACE", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_RESTORE_DNS_ON_EXIT") {
        config.restore_dns_on_exit = parse_bool_env("EGRIO_WINTUN_RESTORE_DNS_ON_EXIT", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_ROUTE_ALL") {
        config.route_all = parse_bool_env("EGRIO_WINTUN_ROUTE_ALL", &value)?;
    }
    // The IPv6 policy (auto|tunnel|block|off). Auto
    // (the default) tunnels v6 when the physical network has it and blocks it
    // otherwise; the resolved value drives the adapter v6 address/routes/DNS,
    // the egress v6 flag, and the WFP v6 filters.
    if let Some(value) = env_string("EGRIO_WINTUN_IPV6") {
        config.ipv6_policy = parse_windows_ipv6_policy_env("EGRIO_WINTUN_IPV6", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_INTERFACE_METRIC") {
        config.interface_metric = parse_env("EGRIO_WINTUN_INTERFACE_METRIC", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_ROUTE_METRIC") {
        config.route_metric = parse_env("EGRIO_WINTUN_ROUTE_METRIC", &value)?;
    }
    if let Some(value) = env_string("EGRIO_WINTUN_DELETE_DRIVER_ON_UNINSTALL") {
        config.delete_driver_on_uninstall =
            parse_bool_env("EGRIO_WINTUN_DELETE_DRIVER_ON_UNINSTALL", &value)?;
    }

    normalize_windows_wintun_config(config)
}

fn dns_servers_track_default(config: &WindowsWintunConfig) -> bool {
    config.dns_servers.is_empty()
        || default_windows_wintun_dns_servers(config)
            .is_ok_and(|default_dns| config.dns_servers == default_dns)
}

fn default_windows_wintun_dns_servers(config: &WindowsWintunConfig) -> Result<Vec<IpAddr>, String> {
    Ok(vec![IpAddr::V4(default_windows_wintun_dns_address(
        config.adapter_address,
        config.adapter_netmask,
    )?)])
}

fn default_windows_wintun_dns_address(
    adapter_address: Ipv4Addr,
    adapter_netmask: Ipv4Addr,
) -> Result<Ipv4Addr, String> {
    let mask = u32::from(adapter_netmask);
    let address = u32::from(adapter_address);
    let network = address & mask;
    let broadcast = network | !mask;
    let candidate = address.checked_add(1).ok_or_else(|| {
        format!(
            "Wintun adapter address {adapter_address} has no next IPv4 address; set EGRIO_WINTUN_DNS"
        )
    })?;

    if candidate & mask != network || candidate == network || candidate == broadcast {
        return Err(format!(
            "Wintun adapter address {adapter_address}/{adapter_netmask} has no usable next IPv4 address for virtual DNS; set EGRIO_WINTUN_DNS"
        ));
    }

    Ok(Ipv4Addr::from(candidate))
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_env<T>(name: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|error| format!("invalid {name} value '{value}': {error}"))
}

fn parse_ipv4_env(name: &str, value: &str) -> Result<Ipv4Addr, String> {
    parse_env(name, value)
}

fn parse_ip_list_env(name: &str, value: &str) -> Result<Vec<IpAddr>, String> {
    let addresses = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| parse_env(name, item))
        .collect::<Result<Vec<_>, _>>()?;
    if addresses.is_empty() {
        Err(format!("{name} must contain at least one IP address"))
    } else {
        Ok(addresses)
    }
}

fn parse_bool_env(name: &str, value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid {name} boolean value '{value}'")),
    }
}

fn parse_windows_ipv6_policy_env(name: &str, value: &str) -> Result<WindowsIpv6Policy, String> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Ok(WindowsIpv6Policy::Auto),
        "tunnel" => Ok(WindowsIpv6Policy::Tunnel),
        "block" => Ok(WindowsIpv6Policy::Block),
        "off" => Ok(WindowsIpv6Policy::Off),
        _ => Err(format!(
            "invalid {name} value '{value}'; expected auto|tunnel|block|off"
        )),
    }
}

fn validate_ipv4_netmask(netmask: Ipv4Addr) -> Result<(), String> {
    let bits = u32::from(netmask);
    if bits == 0 {
        return Err("Wintun adapter netmask must not be 0.0.0.0".into());
    }
    let inverted = !bits;
    if inverted != 0 && (inverted & (inverted + 1)) != 0 {
        return Err(format!(
            "invalid non-contiguous Wintun adapter netmask {netmask}"
        ));
    }
    Ok(())
}

fn validate_metric(name: &str, metric: u32) -> Result<(), String> {
    if metric == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_empty_dns_to_derived_virtual_address() {
        let config = WindowsWintunConfig {
            adapter_address: Ipv4Addr::new(10, 44, 0, 1),
            dns_servers: Vec::new(),
            ..WindowsWintunConfig::default()
        };

        let normalized = normalize_windows_wintun_config(config).expect("valid config");

        assert_eq!(
            normalized.dns_servers,
            vec![IpAddr::V4(Ipv4Addr::new(10, 44, 0, 2))]
        );
    }

    #[test]
    fn default_dns_derivation_requires_usable_next_address() {
        let error = default_windows_wintun_dns_address(
            Ipv4Addr::new(10, 44, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        )
        .expect_err("a /32 interface prefix has no separate virtual DNS address");

        assert!(error.contains("EGRIO_WINTUN_DNS"));
    }

    #[test]
    fn rejects_non_contiguous_netmask() {
        let config = WindowsWintunConfig {
            adapter_netmask: Ipv4Addr::new(255, 0, 255, 0),
            ..WindowsWintunConfig::default()
        };

        let error = normalize_windows_wintun_config(config)
            .expect_err("non-contiguous netmask should fail");

        assert!(error.contains("non-contiguous"));
    }
}
