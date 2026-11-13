//! Egrio YAML DNS sources belong to the desktop host; Core receives typed policy.

use std::net::IpAddr;

use egrio_core::dns::config::{
    DnsDomainPattern, DnsHost, DnsMode, DnsNameServerPolicy, DnsRoute, DnsTransport, DnsUpstream,
    FakeIpRange, RuntimeDnsConfig,
};
use serde::Deserialize;
use serde_yaml::Value;

/// The DNS keys Egrio reads. Others, such as `listen`, `fallback` or `ipv6`
/// (the top-level `ipv6` decides AAAA), are ignored like unknown top-level
/// keys and stay in the saved source; the editor marks them as not in effect.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileDns {
    #[serde(default)]
    enable: bool,
    use_hosts: Option<bool>,
    use_system_hosts: Option<bool>,
    enhanced_mode: Option<String>,
    nameserver: Option<Vec<String>>,
    default_nameserver: Option<Vec<String>>,
    proxy_server_nameserver: Option<Vec<String>>,
    direct_nameserver: Option<Vec<String>>,
    #[serde(default)]
    nameserver_policy: serde_yaml::Mapping,
    #[serde(default)]
    fake_ip_range: FakeIpRange,
    #[serde(default)]
    fake_ip_filter: Vec<String>,
}

pub(crate) fn parse_dns(value: Option<Value>) -> Result<RuntimeDnsConfig, String> {
    let Some(value) = value else {
        return Ok(RuntimeDnsConfig::default());
    };
    let mapping = value.as_mapping().ok_or("dns must be a mapping")?;
    let enable = match mapping.get(Value::String("enable".into())) {
        None => false,
        Some(Value::Bool(enabled)) => *enabled,
        Some(_) => return Err("dns.enable must be a boolean".into()),
    };
    if !enable {
        return Ok(RuntimeDnsConfig::default());
    }
    let dns: ProfileDns = serde_yaml::from_value(value)
        .map_err(|error| format!("unsupported or invalid DNS configuration: {error}"))?;
    // Mode names are case-insensitive. Both `normal` and `redir-host`
    // resolve to real addresses rather than allocating fake IP mappings.
    let mode = match dns
        .enhanced_mode
        .as_deref()
        .unwrap_or("redir-host")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "redir-host" | "normal" => DnsMode::RedirHost,
        "fake-ip" => DnsMode::FakeIp,
        other => return Err(format!("unsupported dns.enhanced-mode: {other}")),
    };
    let nameservers = parse_list(dns.nameserver, "dns.nameserver")?;
    let bootstrap_nameservers = parse_list(dns.default_nameserver, "dns.default-nameserver")?;
    for upstream in &bootstrap_nameservers {
        if upstream.transport != DnsTransport::System
            && upstream.host.parse::<std::net::IpAddr>().is_err()
        {
            return Err(
                "dns.default-nameserver must use numeric addresses to avoid bootstrap recursion"
                    .into(),
            );
        }
    }
    let proxy_nameservers = parse_list(dns.proxy_server_nameserver, "dns.proxy-server-nameserver")?;
    let direct_nameservers = parse_list(dns.direct_nameserver, "dns.direct-nameserver")?;
    let mut policies = Vec::new();
    for (key, value) in dns.nameserver_policy {
        let name = key
            .as_str()
            .ok_or("dns.nameserver-policy keys must be domains")?;
        let servers = match value {
            Value::String(server) => vec![server],
            Value::Sequence(servers) => servers
                .into_iter()
                .map(|server| match server {
                    Value::String(server) => Ok(server),
                    _ => Err("dns.nameserver-policy servers must be strings".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("dns.nameserver-policy values must be a server or server list".into()),
        };
        // A comma-separated key assigns the same servers to each domain.
        let nameservers = parse_list(Some(servers), "dns.nameserver-policy")?;
        for name in name.split(',') {
            policies.push(DnsNameServerPolicy {
                pattern: parse_pattern(name)?,
                nameservers: nameservers.clone(),
            });
        }
    }
    Ok(RuntimeDnsConfig {
        enabled: dns.enable,
        enhanced_mode: mode,
        nameservers,
        bootstrap_nameservers,
        proxy_nameservers,
        direct_nameservers,
        policies,
        fake_ip_range: dns.fake_ip_range,
        fake_ip_filter: dns
            .fake_ip_filter
            .iter()
            .map(|pattern| parse_pattern(pattern))
            .collect::<Result<_, _>>()?,
        // The top-level `hosts` apply whether or not DNS is enabled; the
        // source adds them after this.
        hosts: Vec::new(),
        use_hosts: dns.use_hosts.unwrap_or(true),
        use_system_hosts: dns.use_system_hosts.unwrap_or(true),
    })
}

/// The top-level `hosts`: names, or patterns as the DNS filters write them
/// (`+.`, `*.`, `*`), each mapped to an address or a list of addresses. A
/// name mapped to another name, the `lan` placeholder and an empty list
/// are refused: every entry must resolve to explicit IP addresses.
pub(crate) fn parse_hosts(value: Option<Value>) -> Result<Vec<DnsHost>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let mapping = value
        .as_mapping()
        .ok_or("hosts must map names to addresses")?;
    mapping
        .iter()
        .map(|(key, value)| {
            let name = key.as_str().ok_or("hosts keys must be names")?;
            let pattern = parse_pattern(name).map_err(|error| format!("hosts: {error}"))?;
            let values: Vec<&str> = match value {
                Value::String(address) => vec![address.as_str()],
                Value::Sequence(addresses) => addresses
                    .iter()
                    .map(|address| {
                        address
                            .as_str()
                            .ok_or_else(|| format!("hosts.{name}: addresses must be strings"))
                    })
                    .collect::<Result<_, _>>()?,
                _ => {
                    return Err(format!(
                        "hosts.{name} must be an address or a list of addresses"
                    ))
                }
            };
            if values.is_empty() {
                return Err(format!("hosts.{name} must have at least one address"));
            }
            let addresses = values
                .iter()
                .map(|text| {
                    let address = text.trim().parse::<IpAddr>().map_err(|_| {
                        format!("hosts.{name}: {text} is not an IP address; a name maps only to addresses")
                    })?;
                    Ok(match address {
                        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
                        v4 => v4,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(DnsHost { pattern, addresses })
        })
        .collect()
}

fn parse_list(values: Option<Vec<String>>, field: &str) -> Result<Vec<DnsUpstream>, String> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    if values.is_empty() {
        return Err(format!(
            "{field} must contain at least one DNS server; omit it to use the default"
        ));
    }
    values
        .iter()
        .map(|value| parse_upstream(value).map_err(|error| format!("{field}: {error}")))
        .collect()
}

fn parse_upstream(value: &str) -> Result<DnsUpstream, String> {
    let address = value.trim();
    if address == "system" {
        return Ok(DnsUpstream {
            route: Some(DnsRoute::Direct),
            ..DnsUpstream::system()
        });
    }
    let address = if address.contains("://") {
        address.to_string()
    } else if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        format!("udp://{}", std::net::SocketAddr::new(ip, 53))
    } else if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        format!("udp://{socket}")
    } else {
        return Err("DNS server must be system, an IP address, or a DNS URL".into());
    };
    let url =
        reqwest::Url::parse(&address).map_err(|error| format!("invalid DNS upstream: {error}"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("DNS upstream credentials/fragments are unsupported".into());
    }
    let (transport, default_port) = match url.scheme() {
        "udp" => (DnsTransport::Udp, 53),
        "tcp" => (DnsTransport::Tcp, 53),
        "tls" => (DnsTransport::Tls, 853),
        "http" => (DnsTransport::Http, 80),
        "https" => (DnsTransport::Https, 443),
        other => return Err(format!("unsupported DNS transport: {other}")),
    };
    let host = url
        .host_str()
        .ok_or("DNS upstream requires a host")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = url.port().unwrap_or(default_port);
    if port == 0 {
        return Err("DNS upstream port must be nonzero".into());
    }
    let path = if matches!(transport, DnsTransport::Http | DnsTransport::Https) {
        match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        }
    } else {
        if !(url.path().is_empty() || url.path() == "/") || url.query().is_some() {
            return Err("only HTTP/HTTPS DNS upstreams accept a path/query".into());
        }
        String::new()
    };
    Ok(DnsUpstream {
        transport,
        host,
        port,
        path,
        server_name: None,
        route: None,
    })
}

/// A key of `nameserver-policy` or `hosts`, or an entry of `fake-ip-filter`:
/// a pattern parsed by the Core's shared domain-pattern type.
fn parse_pattern(value: &str) -> Result<DnsDomainPattern, String> {
    value.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<RuntimeDnsConfig, String> {
        parse_dns(Some(serde_yaml::from_str(yaml).unwrap()))
    }

    #[test]
    fn absent_or_disabled_dns_uses_system_without_implicit_fake_ip() {
        for config in [
            parse_dns(None).unwrap(),
            parse("enable: false\nnameserver: [1.1.1.1]").unwrap(),
            parse("nameserver: [1.1.1.1]").unwrap(),
            parse("enable: false\nipv6: true\nnameserver: [unsupported]").unwrap(),
        ] {
            assert_eq!(config, RuntimeDnsConfig::default());
        }
        let enabled = parse("enable: true").unwrap();
        assert!(enabled.enabled);
        assert!(enabled.nameservers.is_empty());
        assert_eq!(enabled.enhanced_mode, DnsMode::RedirHost);
    }

    #[test]
    fn supported_configuration_materializes_all_nine_fields() {
        let profile = crate::profile_source::composed_profile(
            r#"dns:
  enable: true
  enhanced-mode: fake-ip
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://dns.alidns.com/dns-query
  direct-nameserver:
    - system
  proxy-server-nameserver:
    - https://doh.pub/dns-query
  nameserver-policy: {}
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
proxies: []
rules: ['MATCH,DIRECT']
"#,
        )
        .unwrap();
        let config = profile.dns;
        assert!(config.enabled);
        assert_eq!(config.enhanced_mode, DnsMode::FakeIp);
        assert_eq!(config.bootstrap_nameservers[0].host, "223.5.5.5");
        assert_eq!(config.bootstrap_nameservers[0].transport, DnsTransport::Udp);
        assert_eq!(config.nameservers[0].host, "dns.alidns.com");
        assert_eq!(config.nameservers[0].transport, DnsTransport::Https);
        assert_eq!(config.direct_nameservers[0].transport, DnsTransport::System);
        assert_eq!(config.proxy_nameservers[0].host, "doh.pub");
        assert!(config.policies.is_empty());
        assert_eq!(config.fake_ip_range, "198.18.0.0/16".parse().unwrap());
        assert!(config.fake_ip_filter[0].matches("printer.lan"));
        assert!(config.fake_ip_filter[1].matches("printer.local"));
    }

    #[test]
    fn hosts_map_names_and_patterns_whether_or_not_dns_is_enabled() {
        let profile = crate::profile_source::composed_profile(
            r#"hosts:
  nas.home: 192.168.1.10
  '+.dev.example': [127.0.0.1, '::1']
  '*.lan': '::ffff:10.0.0.1'
dns:
  enable: false
  use-hosts: false
proxies: []
rules: ['MATCH,DIRECT']
"#,
        )
        .unwrap();
        let config = profile.dns;
        assert!(
            config.use_hosts && config.use_system_hosts,
            "a disabled DNS section reads neither switch"
        );
        let address = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(
            config.hosts,
            [
                DnsHost {
                    pattern: "nas.home".parse().unwrap(),
                    addresses: vec![address("192.168.1.10")],
                },
                DnsHost {
                    pattern: "+.dev.example".parse().unwrap(),
                    addresses: vec![address("127.0.0.1"), address("::1")],
                },
                DnsHost {
                    pattern: "*.lan".parse().unwrap(),
                    // An IPv4-mapped address is the IPv4 address.
                    addresses: vec![address("10.0.0.1")],
                },
            ]
        );
    }

    #[test]
    fn the_dns_section_turns_hosts_answers_and_the_system_file_off() {
        let config = parse("enable: true\nuse-hosts: false\nuse-system-hosts: false").unwrap();
        assert!(!config.use_hosts && !config.use_system_hosts);
        let config = parse("enable: true").unwrap();
        assert!(config.use_hosts && config.use_system_hosts);
    }

    #[test]
    fn hosts_map_names_only_to_addresses() {
        for value in [
            "{a.example: b.example}",
            "{a.example: lan}",
            "{a.example: []}",
            "{a.example: [1]}",
            "{a.example: 1}",
            "{a.example: {ip: 1.1.1.1}}",
            "{'bad pattern': 1.1.1.1}",
            "[1.1.1.1]",
        ] {
            assert!(
                parse_hosts(Some(serde_yaml::from_str(value).unwrap())).is_err(),
                "{value}"
            );
        }
        assert!(parse_hosts(Some(Value::Null)).unwrap().is_empty());
    }

    #[test]
    fn the_mode_reads_without_regard_to_case_and_normal_gives_real_addresses() {
        for (text, mode) in [
            ("fake-ip", DnsMode::FakeIp),
            ("Fake-IP", DnsMode::FakeIp),
            ("redir-host", DnsMode::RedirHost),
            ("Redir-Host", DnsMode::RedirHost),
            ("normal", DnsMode::RedirHost),
        ] {
            let config = parse(&format!("enable: true\nenhanced-mode: {text}")).unwrap();
            assert_eq!(config.enhanced_mode, mode, "{text}");
        }
        assert!(parse("enable: true\nenhanced-mode: hosts").is_err());
    }

    #[test]
    fn range_does_not_enable_dns_or_select_its_mode() {
        assert!(!parse("fake-ip-range: 198.19.0.1/24").unwrap().enabled);
        let real = parse("enable: true\nfake-ip-range: 198.19.0.1/24").unwrap();
        assert_eq!(real.enhanced_mode, DnsMode::RedirHost);
        assert_eq!(real.fake_ip_range, "198.19.0.0/24".parse().unwrap());
        assert!(parse("enable: true\nfake-ip-range: 198.19.0.1/33").is_err());
    }

    #[test]
    fn preserves_source_order_protocols_and_domain_policy() {
        let config = parse(r#"enable: true
nameserver: [system, 1.1.1.1, 'http://dns.example/query?client=egrio', 'https://dns.example/dns-query', 'tcp://1.1.1.1:5353', '[2001:db8::53]:5354']
default-nameserver: [system, 8.8.8.8]
proxy-server-nameserver: [system]
direct-nameserver: ['tls://dns.example:8853']
nameserver-policy:
  '+.example.com': [system, 9.9.9.9]
  '*.example.net': 'https://dns.example/dns-query'
fake-ip-filter: ['*.lan', localhost]
"#).unwrap();
        assert_eq!(config.nameservers.len(), 6);
        assert_eq!(config.nameservers[0].transport, DnsTransport::System);
        assert_eq!(config.nameservers[0].route, Some(DnsRoute::Direct));
        assert_eq!(config.nameservers[1].transport, DnsTransport::Udp);
        assert_eq!(config.nameservers[1].port, 53);
        assert_eq!(config.nameservers[2].transport, DnsTransport::Http);
        assert_eq!(config.nameservers[2].port, 80);
        assert_eq!(config.nameservers[2].path, "/query?client=egrio");
        assert_eq!(config.nameservers[3].transport, DnsTransport::Https);
        assert_eq!(config.nameservers[3].port, 443);
        assert_eq!(config.nameservers[4].transport, DnsTransport::Tcp);
        assert_eq!(config.nameservers[4].port, 5353);
        assert_eq!(config.nameservers[5].host, "2001:db8::53");
        assert_eq!(config.nameservers[5].port, 5354);
        assert_eq!(
            config.bootstrap_nameservers[0].transport,
            DnsTransport::System
        );
        assert_eq!(config.proxy_nameservers[0].transport, DnsTransport::System);
        assert_eq!(config.direct_nameservers[0].transport, DnsTransport::Tls);
        assert_eq!(config.direct_nameservers[0].port, 8853);
        assert_eq!(config.policies.len(), 2);
        assert!(config.policies[0].pattern.matches("www.example.com"));
        assert!(!config.policies[0].pattern.matches("notexample.com"));
        assert!(config.policies[1].pattern.matches("a.example.net"));
        assert!(!config.policies[1].pattern.matches("a.b.example.net"));
    }

    /// Every supported domain-pattern form is accepted in each DNS field.
    #[test]
    fn filters_policies_and_hosts_read_every_pattern_form() {
        let config = parse(concat!(
            "enable: true\n",
            "enhanced-mode: fake-ip\n",
            "fake-ip-filter: ['*.lan', '.home.arpa', 'time.*.com', 'ntp.*.com', 'stun.*.*', ",
            "'+.stun.*.*', 'xbox.*.*.microsoft.com', '*.*.xboxlive.com', '+.market.xiaomi.com', ",
            "'localhost.ptlogin2.qq.com']\n",
            "nameserver-policy:\n",
            "  'time.*.com': 223.5.5.5\n",
            "  '.corp.example': [system]\n",
        ))
        .unwrap();
        let filtered = |name: &str| {
            config
                .fake_ip_filter
                .iter()
                .any(|pattern| pattern.matches(name))
        };
        for name in [
            "printer.lan",
            "a.b.home.arpa",
            "time.apple.com",
            "ntp.ubuntu.com",
            "stun.l.google",
            "a.stun.example.org",
            "xbox.a.b.microsoft.com",
            "a.b.xboxlive.com",
            "market.xiaomi.com",
            "localhost.ptlogin2.qq.com",
        ] {
            assert!(filtered(name), "{name}");
        }
        for name in [
            "lan",
            "home.arpa",
            "time.com",
            "time.a.b.com",
            "a.xboxlive.com",
            "example.com",
        ] {
            assert!(!filtered(name), "{name}");
        }
        assert!(config.policies[0].pattern.matches("time.windows.com"));
        assert!(config.policies[1].pattern.matches("vpn.corp.example"));
        assert!(!config.policies[1].pattern.matches("corp.example"));

        // One key naming several domains is a policy for each, in order.
        let joined = parse(
            "enable: true\nnameserver-policy: {'+.a.example, b.example': [1.1.1.1, 8.8.8.8], c.example: system}",
        )
        .unwrap();
        assert_eq!(joined.policies.len(), 3);
        assert!(joined.policies[0].pattern.matches("x.a.example"));
        assert!(joined.policies[1].pattern.matches("b.example"));
        assert_eq!(
            joined.policies[1].nameservers,
            joined.policies[0].nameservers
        );
        assert_eq!(joined.policies[1].nameservers.len(), 2);
        assert!(joined.policies[2].pattern.matches("c.example"));
        assert!(parse("enable: true\nnameserver-policy: {'a.example,': 1.1.1.1}").is_err());

        let hosts = parse_hosts(Some(
            serde_yaml::from_str("{'ntp.*.example': 10.0.0.1}").unwrap(),
        ))
        .unwrap();
        assert!(hosts[0].pattern.matches("ntp.pool.example"));

        // What is no name pattern is refused rather than left out: a filter
        // or a policy that silently did not apply would answer differently
        // from what the configuration says.
        for entry in [
            "geosite:private",
            "rule-set:fakeip",
            "a*.example",
            "例子.com",
        ] {
            assert!(
                parse(&format!("enable: true\nfake-ip-filter: ['{entry}']")).is_err(),
                "{entry}"
            );
        }
    }

    #[test]
    fn dns_transport_follows_resolver_address_rules() {
        let profile = crate::profile_source::composed_profile("dns:\n  enable: true\n  nameserver: [https://8.8.8.8/dns-query]\nproxies:\n  - name: resolver-exit\n    type: http\n    server: 127.0.0.1\n    port: 1\nrules:\n  - IP-CIDR,8.8.8.8/32,resolver-exit\n  - MATCH,DIRECT\n",
        ).unwrap();
        let evaluation = egrio_core::DnsEngine::compile(&profile, Default::default()).evaluate(
            &egrio_core::DnsQueryInput {
                query_class: 1,
                domain: "business.example".into(),
                record_type: egrio_core::DnsRecordType::A,
                process_name: None,
                process_path: None,
            },
        );
        assert_eq!(evaluation.upstreams.len(), 1);
        let upstream = &evaluation.upstreams[0];
        assert_eq!(upstream.endpoint, "8.8.8.8:443/dns-query");
        assert_eq!(upstream.outbound.as_deref(), Some("resolver-exit"));
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_active_configuration() {
        for yaml in [
            "nameserver: [proxy]",
            "nameserver: [quic://dns.example]",
            "nameserver: ['']",
            "nameserver: []",
            "default-nameserver: []",
            "direct-nameserver: []",
            "proxy-server-nameserver: []",
            "default-nameserver: [udp://dns.example]",
            "proxy-server-nameserver: ['1.1.1.1#Exit']",
            "nameserver-policy: {'geosite:cn': 1.1.1.1}",
            "nameserver-policy: {'example.com': []}",
            "nameserver: ['https://dns.example/dns-query#Exit&h3=true']",
            "nameserver: ['https://dns.example/dns-query#RULES']",
            "nameserver: ['system#DIRECT']",
        ] {
            assert!(parse(&format!("enable: true\n{yaml}")).is_err(), "{yaml}");
        }
    }

    #[test]
    fn unsupported_keys_are_ignored_like_unknown_top_level_keys() {
        let config = parse(concat!(
            "enable: true\n",
            "listen: 0.0.0.0:1053\n",
            "cache-algorithm: arc\n",
            "ipv6: false\n",
            "prefer-h3: true\n",
            "respect-rules: false\n",
            "direct-nameserver-follow-policy: true\n",
            "fallback: [tls://1.1.1.1]\n",
            "fallback-filter: {geoip: true, ipcidr: [240.0.0.0/4]}\n",
            "nameserver: [223.5.5.5]\n",
        ))
        .expect("unsupported keys do not invalidate the DNS section");
        assert_eq!(
            config,
            parse("enable: true\nnameserver: [223.5.5.5]").unwrap()
        );
    }
}
