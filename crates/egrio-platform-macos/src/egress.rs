use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use egrio_core::{EgressSocketGuard, NativeCoreEgressConfig};

const MACOS_EGRESS_DNS_DEFAULT_PORT: u16 = 53;

/// Read-only physical egress inputs shared by Core startup and standalone
/// probes. OS resolver discovery and interface binding stay in this platform.
#[derive(Debug)]
pub struct MacosPhysicalEgress {
    pub config: NativeCoreEgressConfig,
    pub socket_guard: Arc<dyn EgressSocketGuard>,
}

impl MacosPhysicalEgress {
    pub fn capture() -> Result<Self, String> {
        let dns = crate::capture_macos_system_dns_snapshot()?;
        Ok(Self {
            config: build_macos_native_core_egress_config(Some(&dns.egress_dns_servers))?,
            socket_guard: Arc::new(crate::MacosEgressInterfaceBinder::capture()?),
        })
    }
}

/// Builds the native-core egress configuration from a comma-separated DNS
/// server list (`ip[:port]`, port defaults to 53).
///
/// The tunnel's resolver takes over the system's while TUN runs. Core
/// therefore resolves physical egress names through these pre-capture
/// upstream DNS servers; sockets use MacosEgressInterfaceBinder to bypass the
/// tunnel's routes.
pub fn build_macos_native_core_egress_config(
    egress_dns_servers: Option<&str>,
) -> Result<NativeCoreEgressConfig, String> {
    let Some(egress_dns_servers) = egress_dns_servers else {
        return Ok(NativeCoreEgressConfig::default());
    };

    Ok(NativeCoreEgressConfig {
        dns_servers: parse_macos_egress_dns_servers(egress_dns_servers)?,
        // The host applies the profile's IPv6 DNS policy after assembling
        // these physical resolver inputs. Numeric IPv6 stays usable either way.
        ipv6_enabled: false,
        refuse_private_destinations: false,
    })
}

fn parse_macos_egress_dns_servers(servers: &str) -> Result<Vec<SocketAddr>, String> {
    let mut parsed = Vec::new();
    for entry in servers.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            parsed.push(SocketAddr::new(ip, MACOS_EGRESS_DNS_DEFAULT_PORT));
            continue;
        }
        parsed.push(entry.parse::<SocketAddr>().map_err(|error| {
            format!("invalid macOS egress DNS server '{entry}' (expected ip or ip:port): {error}")
        })?);
    }

    if parsed.is_empty() {
        return Err("macOS egress DNS server list is empty".into());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ips_default_to_dns_port() {
        let config = build_macos_native_core_egress_config(Some("223.5.5.5, 119.29.29.29:5353"))
            .expect("egress DNS list parses");

        assert_eq!(
            config.dns_servers,
            vec![
                "223.5.5.5:53".parse().unwrap(),
                "119.29.29.29:5353".parse().unwrap()
            ]
        );
    }

    #[test]
    fn missing_list_keeps_default_egress() {
        let config = build_macos_native_core_egress_config(None).expect("default egress builds");

        assert_eq!(config, NativeCoreEgressConfig::default());
    }

    #[test]
    fn ipv6_servers_parse_with_and_without_port() {
        let config = build_macos_native_core_egress_config(Some("2400:3200::1,[2402:4e00::]:53"))
            .expect("IPv6 egress DNS list parses");

        assert_eq!(
            config.dns_servers,
            vec![
                "[2400:3200::1]:53".parse().unwrap(),
                "[2402:4e00::]:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn invalid_or_empty_lists_are_rejected() {
        assert!(build_macos_native_core_egress_config(Some("not-a-server"))
            .expect_err("invalid entry is rejected")
            .contains("invalid macOS egress DNS server"));
        assert!(build_macos_native_core_egress_config(Some(" , "))
            .expect_err("empty list is rejected")
            .contains("list is empty"));
    }
}
