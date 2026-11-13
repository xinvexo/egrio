use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

// The scutil parsing path below is reached from the cfg(macos) capture entry
// (and its tests); on other hosts it still compiles for type-checking.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
const MACOS_SYSTEM_DNS_PORT: u16 = 53;

/// The physical resolver list captured before the tunnel installs its
/// virtual DNS server. Core uses these upstreams through protected sockets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MacosSystemDnsSnapshot {
    pub servers: Vec<SocketAddr>,
    pub egress_dns_servers: String,
}

/// Captures the current system DNS servers from `scutil --dns` (the
/// `dns_configuration_copy` view configd maintains; scutil(8) is the
/// documented inspection tool for it).
#[cfg(target_os = "macos")]
pub fn capture_macos_system_dns_snapshot() -> Result<MacosSystemDnsSnapshot, String> {
    let output = std::process::Command::new("scutil")
        .arg("--dns")
        .output()
        .map_err(|error| format!("failed to run scutil --dns: {error}"))?;
    if !output.status.success() {
        return Err(format!("scutil --dns failed with {}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    snapshot_from_scutil_dns_output(&text)
}

#[cfg(not(target_os = "macos"))]
pub fn capture_macos_system_dns_snapshot() -> Result<MacosSystemDnsSnapshot, String> {
    Err("the macOS system DNS snapshot is only available on macOS".into())
}

/// The resolvers of the network the uplink is on now, for a running tunnel:
/// its own resolver is the system's global one then, so the physical ones
/// are the uplink interfaces' scoped resolvers (`uplinks`, most preferred
/// first). Falls back to the snapshot's choice when they have none.
#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_uplink_dns_servers(uplinks: &[u32]) -> Result<Vec<SocketAddr>, String> {
    let output = std::process::Command::new("scutil")
        .arg("--dns")
        .output()
        .map_err(|error| format!("failed to run scutil --dns: {error}"))?;
    if !output.status.success() {
        return Err(format!("scutil --dns failed with {}", output.status));
    }
    uplink_dns_servers(&String::from_utf8_lossy(&output.stdout), uplinks)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn uplink_dns_servers(text: &str, uplinks: &[u32]) -> Result<Vec<SocketAddr>, String> {
    let resolvers = parse_scutil_dns_resolvers(text);
    let mut servers = Vec::new();
    for uplink in uplinks {
        for resolver in resolvers
            .iter()
            .filter(|resolver| resolver.scoped && resolver.interface == Some(*uplink))
        {
            for server in &resolver.servers {
                if !servers.contains(server) {
                    servers.push(*server);
                }
            }
        }
    }
    if servers.is_empty() {
        return snapshot_from_scutil_dns_output(text).map(|snapshot| snapshot.servers);
    }
    Ok(servers)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn snapshot_from_scutil_dns_output(text: &str) -> Result<MacosSystemDnsSnapshot, String> {
    let (global, scoped) = parse_scutil_dns_nameserver_sections(text);
    // Another local proxy (its own enhanced mode active) rewrites the global
    // resolver to an address inside its fake-IP range — 198.18.0.0/15, the
    // RFC 2544 benchmarking block every fake-IP implementation uses. Such an
    // address is not a reachable upstream for this process's egress sockets,
    // so fall back to the per-interface scoped resolvers, which still carry
    // the real upstream (the router / DHCP-provided servers).
    let servers = if !global.is_empty() { global } else { scoped };
    if servers.is_empty() {
        return Err(
            "scutil --dns reported no usable nameservers (global or interface-scoped) to \
             snapshot for egress DNS; every resolver was loopback, link-local, or inside the \
             fake-IP benchmarking range"
                .to_string(),
        );
    }

    let egress_dns_servers = servers
        .iter()
        .map(|server| server.ip().to_string())
        .collect::<Vec<_>>()
        .join(",");
    Ok(MacosSystemDnsSnapshot {
        servers,
        egress_dns_servers,
    })
}

/// Extracts usable nameserver addresses in listing order, split into the
/// global section and the "for scoped queries" section of `scutil --dns`.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_scutil_dns_nameserver_sections(text: &str) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut global = Vec::new();
    let mut scoped = Vec::new();
    for resolver in parse_scutil_dns_resolvers(text) {
        let section = if resolver.scoped {
            &mut scoped
        } else {
            &mut global
        };
        for server in resolver.servers {
            if !section.contains(&server) {
                section.push(server);
            }
        }
    }
    (global, scoped)
}

/// One `resolver #n` block of `scutil --dns`.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
#[derive(Debug, Default)]
struct ScutilResolver {
    /// In the "for scoped queries" section.
    scoped: bool,
    /// Its `if_index`.
    interface: Option<u32>,
    servers: Vec<SocketAddr>,
}

/// The resolver blocks of `scutil --dns`, in listing order, with their
/// usable nameservers. Unusable addresses are dropped: link-local IPv6
/// (`fe80::/10`; their `%interface` zone does not parse and they are not
/// reachable from an unbound egress socket), link-local IPv4
/// (`169.254.0.0/16`, RFC 3927), loopback, unspecified, and the RFC 2544
/// benchmarking block `198.18.0.0/15` that fake-IP DNS implementations
/// squat on.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_scutil_dns_resolvers(text: &str) -> Vec<ScutilResolver> {
    let mut resolvers = Vec::new();
    let mut scoped = false;
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with("DNS configuration (for scoped queries)") {
            scoped = true;
            continue;
        }
        if line.starts_with("resolver #") {
            resolvers.push(ScutilResolver {
                scoped,
                ..ScutilResolver::default()
            });
            continue;
        }
        let (Some(resolver), Some((label, value))) = (resolvers.last_mut(), line.split_once(':'))
        else {
            continue;
        };
        let (label, value) = (label.trim(), value.trim());
        if label == "if_index" {
            resolver.interface = value
                .split_whitespace()
                .next()
                .and_then(|index| index.parse().ok());
        } else if label.starts_with("nameserver[") {
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            let server = SocketAddr::new(ip, MACOS_SYSTEM_DNS_PORT);
            if usable_egress_dns_ip(ip) && !resolver.servers.contains(&server) {
                resolver.servers.push(server);
            }
        }
    }
    resolvers
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn usable_egress_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let benchmarking = octets[0] == 198 && (octets[1] & 0xfe) == 18;
            !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || benchmarking)
        }
        IpAddr::V6(ip) => {
            let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
            !(ip.is_loopback() || ip.is_unspecified() || link_local)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCUTIL_DNS_FIXTURE: &str = "\
DNS configuration

resolver #1
  search domain[0] : lan.example
  nameserver[0] : 192.0.2.53
  nameserver[1] : 2001:4860:4860::8888
  if_index : 3 (en0)
  flags    : Request A records

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5

resolver #3
  nameserver[0] : fe80::1%en0

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan.example
  nameserver[0] : 10.9.9.9
  if_index : 3 (en0)
";

    #[test]
    fn snapshot_reads_global_nameservers_and_skips_scoped_section() {
        let snapshot =
            snapshot_from_scutil_dns_output(SCUTIL_DNS_FIXTURE).expect("fixture snapshot parses");

        assert_eq!(
            snapshot.servers,
            vec![
                "192.0.2.53:53".parse().unwrap(),
                "[2001:4860:4860::8888]:53".parse().unwrap()
            ]
        );
        assert_eq!(
            snapshot.egress_dns_servers,
            "192.0.2.53,2001:4860:4860::8888"
        );
    }

    #[test]
    fn snapshot_deduplicates_repeated_nameservers() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53

resolver #2
  nameserver[0] : 192.0.2.53
";
        let snapshot = snapshot_from_scutil_dns_output(text).expect("snapshot parses");

        assert_eq!(snapshot.servers.len(), 1);
        assert_eq!(snapshot.egress_dns_servers, "192.0.2.53");
    }

    #[test]
    fn snapshot_without_any_nameservers_is_an_error() {
        let error =
            snapshot_from_scutil_dns_output("DNS configuration\n\nresolver #1\n  domain : local\n")
                .expect_err("empty nameserver list is rejected");

        assert!(error.contains("no usable nameservers"));
    }

    /// The stacked-proxy machine: another local proxy's enhanced mode has
    /// rewritten the global resolver to its fake-IP DNS (198.18.0.2), while
    /// the interface-scoped resolvers still carry the real router. The
    /// snapshot must skip the fake address and fall back to the scoped
    /// upstream: dialing 198.18/15 as an egress DNS server black-holes
    /// every DIRECT hostname dial.
    #[test]
    fn snapshot_skips_fake_ip_global_resolver_and_uses_scoped_upstream() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 198.18.0.2
  if_index : 3 (en0)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : fe80::1%en0
  nameserver[1] : 192.0.2.1
  if_index : 3 (en0)
";
        let snapshot = snapshot_from_scutil_dns_output(text).expect("snapshot parses");

        assert_eq!(snapshot.servers, vec!["192.0.2.1:53".parse().unwrap()]);
        assert_eq!(snapshot.egress_dns_servers, "192.0.2.1");
    }

    /// With the tunnel up, its resolver is the global one and each physical
    /// interface keeps its own scoped resolvers.
    const SCUTIL_DNS_UNDER_TUNNEL: &str = "\
DNS configuration

resolver #1
  nameserver[0] : 198.18.0.1
  if_index : 4 (utun1)
  flags    : Request A records, Request AAAA records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 2 (en1)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 198.51.100.53
  if_index : 3 (en0)
  flags    : Scoped, Request A records

resolver #3
  nameserver[0] : 198.18.0.1
  if_index : 4 (utun1)
  flags    : Scoped, Request A records
";

    #[test]
    fn a_running_tunnel_takes_the_uplinks_scoped_resolvers() {
        assert_eq!(
            uplink_dns_servers(SCUTIL_DNS_UNDER_TUNNEL, &[3]).unwrap(),
            vec!["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            uplink_dns_servers(SCUTIL_DNS_UNDER_TUNNEL, &[2, 3]).unwrap(),
            vec![
                "192.0.2.1:53".parse::<SocketAddr>().unwrap(),
                "198.51.100.53:53".parse().unwrap()
            ]
        );
        // An uplink without scoped resolvers falls back to every usable one.
        assert_eq!(
            uplink_dns_servers(SCUTIL_DNS_UNDER_TUNNEL, &[7]).unwrap(),
            vec![
                "192.0.2.1:53".parse::<SocketAddr>().unwrap(),
                "198.51.100.53:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn snapshot_output_feeds_the_egress_config_parser() {
        let snapshot =
            snapshot_from_scutil_dns_output(SCUTIL_DNS_FIXTURE).expect("fixture snapshot parses");
        let config =
            crate::build_macos_native_core_egress_config(Some(&snapshot.egress_dns_servers))
                .expect("snapshot list feeds the egress config parser");

        assert_eq!(config.dns_servers, snapshot.servers);
    }
}
