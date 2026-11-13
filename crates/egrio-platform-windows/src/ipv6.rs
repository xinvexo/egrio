use crate::config::{WindowsIpv6Policy, WindowsWintunConfig};
use crate::firewall::WindowsFirewallIpv6Mode;

/// Resolves a config's [`WindowsIpv6Policy`] to the concrete WFP posture used at
/// apply time. `Auto` tunnels v6 when the physical network has a
/// usable IPv6 default and blocks it otherwise; the explicit policies pass
/// through. This is the single resolution point the adapter v6 setup, the
/// egress v6 flag, and every WFP plan-input construction call, so the installed
/// state is internally consistent.
pub fn resolve_windows_ipv6_mode(config: &WindowsWintunConfig) -> WindowsFirewallIpv6Mode {
    match config.ipv6_policy {
        WindowsIpv6Policy::Tunnel => WindowsFirewallIpv6Mode::Tunnel,
        WindowsIpv6Policy::Block => WindowsFirewallIpv6Mode::Block,
        WindowsIpv6Policy::Off => WindowsFirewallIpv6Mode::Off,
        WindowsIpv6Policy::Auto => {
            if physical_ipv6_default_available() {
                WindowsFirewallIpv6Mode::Tunnel
            } else {
                WindowsFirewallIpv6Mode::Block
            }
        }
    }
}

/// True when a usable physical IPv6 default route exists — the same physical
/// egress selection the interface-bound egress uses. No Wintun is excluded here:
/// this probes for a real v6 uplink at bring-up time, before the tunnel's v6
/// capture routes exist. Off-Windows there is no probe, so `Auto` resolves to
/// `Block` (keeping the always-blocked-or-tunneled invariant, never a silent
/// leak).
#[cfg(windows)]
fn physical_ipv6_default_available() -> bool {
    crate::wintun::physical_egress_interface_index(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        )),
        None,
    )
    .is_ok()
}

#[cfg(not(windows))]
fn physical_ipv6_default_available() -> bool {
    false
}
