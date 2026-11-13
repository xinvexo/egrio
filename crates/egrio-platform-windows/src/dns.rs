use std::net::{IpAddr, Ipv6Addr};

use crate::config::WindowsWintunConfig;
use crate::ipv6::resolve_windows_ipv6_mode;

/// The resolvers the Runtime DNS capability assigns to the Wintun interface:
/// the configured virtual resolvers, plus the IPv6 virtual resolver (the
/// address after the adapter's IPv6 address) when IPv6 is tunneled.
pub fn windows_runtime_interface_dns_servers(
    config: &WindowsWintunConfig,
) -> Result<Vec<IpAddr>, String> {
    let mut servers = config.dns_servers.clone();
    if resolve_windows_ipv6_mode(config).tunnels_v6() {
        let address = u128::from(config.adapter_address6)
            .checked_add(1)
            .map(Ipv6Addr::from)
            .ok_or_else(|| {
                format!(
                    "Wintun IPv6 adapter address {} has no next IPv6 address for virtual DNS",
                    config.adapter_address6
                )
            })?;
        servers.push(IpAddr::V6(address));
    }
    servers.sort();
    servers.dedup();
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WindowsIpv6Policy;

    #[test]
    fn tunnel_runtime_dns_adds_the_ipv6_virtual_resolver() {
        let config = WindowsWintunConfig {
            ipv6_policy: WindowsIpv6Policy::Tunnel,
            ..WindowsWintunConfig::default()
        };

        assert_eq!(
            windows_runtime_interface_dns_servers(&config).unwrap(),
            vec![
                IpAddr::V4("10.255.255.2".parse().unwrap()),
                IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn non_tunnel_runtime_dns_keeps_only_configured_servers() {
        for ipv6_policy in [WindowsIpv6Policy::Block, WindowsIpv6Policy::Off] {
            let config = WindowsWintunConfig {
                ipv6_policy,
                dns_servers: vec![
                    IpAddr::V6("2001:db8::53".parse().unwrap()),
                    IpAddr::V4("192.0.2.53".parse().unwrap()),
                    IpAddr::V4("192.0.2.53".parse().unwrap()),
                ],
                ..WindowsWintunConfig::default()
            };

            assert_eq!(
                windows_runtime_interface_dns_servers(&config).unwrap(),
                vec![
                    IpAddr::V4("192.0.2.53".parse().unwrap()),
                    IpAddr::V6("2001:db8::53".parse().unwrap()),
                ]
            );
        }
    }

    #[test]
    fn tunnel_runtime_dns_deduplicates_and_rejects_ipv6_overflow() {
        let config = WindowsWintunConfig {
            ipv6_policy: WindowsIpv6Policy::Tunnel,
            dns_servers: vec![
                IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap()),
                IpAddr::V4("10.255.255.2".parse().unwrap()),
                IpAddr::V4("10.255.255.2".parse().unwrap()),
            ],
            ..WindowsWintunConfig::default()
        };
        assert_eq!(
            windows_runtime_interface_dns_servers(&config).unwrap(),
            vec![
                IpAddr::V4("10.255.255.2".parse().unwrap()),
                IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap()),
            ]
        );

        let overflow = WindowsWintunConfig {
            ipv6_policy: WindowsIpv6Policy::Tunnel,
            adapter_address6: Ipv6Addr::from(u128::MAX),
            ..WindowsWintunConfig::default()
        };
        assert!(windows_runtime_interface_dns_servers(&overflow)
            .unwrap_err()
            .contains("no next IPv6 address"));
    }
}
