//! The supported subset of the Clash configuration format. A Profile keeps its
//! source verbatim; this module decodes the keys Egrio uses in one pass and
//! ignores the rest, so supporting another key later adds a field to
//! [`SourceDocument`] and reads it from the sources already stored.

use egrio_core::{RuntimeProfile, TrafficPolicyMode};
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;
use sha2::{Digest, Sha256};

use crate::profile_network_settings::ProfileNetworkConfig;

mod dns;
mod edit;
mod nodes;
mod rules;

pub(crate) use edit::{edit_rules, set_top_level_scalar, RulesEdit};
pub(crate) use rules::{parse_rule_provider_entries, rule_id, rule_index, rule_line, RuleProvider};

/// The top-level keys Egrio reads besides the listener, IPv6 and TUN route
/// settings, which [`ProfileNetworkConfig`] reads. Every other key
/// (`log-level`, `proxy-providers`, ...) is ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SourceDocument {
    #[serde(default, deserialize_with = "source_mode")]
    mode: Option<TrafficPolicyMode>,
    dns: Option<Value>,
    hosts: Option<Value>,
    #[serde(default, deserialize_with = "null_as_default")]
    proxies: Vec<nodes::SourceProxy>,
    #[serde(default, deserialize_with = "null_as_default")]
    proxy_groups: Vec<nodes::SourceGroup>,
    #[serde(default, deserialize_with = "null_as_default")]
    rules: Vec<String>,
    rule_providers: Option<Value>,
}

/// A source decoded once. Composition clones its content and adds the
/// Profile's choices instead of decoding the YAML again.
#[derive(Debug)]
pub(crate) struct ParsedSource {
    /// The listener and IPv6 settings; only a key the file omits reads as
    /// the program default.
    pub(crate) network: ProfileNetworkConfig,
    /// The file's `mode`. A mode the user picks takes precedence.
    pub(crate) mode: Option<TrafficPolicyMode>,
    /// The source's nodes, groups, rules and DNS. Identity and mode are
    /// composed and are not meaningful here.
    pub(crate) content: RuntimeProfile,
    /// What the source calls the type of each rule the Core holds as one of
    /// unknown type, by the rule's place in `content.rules`.
    pub(crate) unknown_rule_kinds: std::collections::HashMap<usize, String>,
    pub(crate) rule_providers: Vec<RuleProvider>,
    /// SHA-256 of the source text, which is also its stored content hash.
    pub(crate) revision: String,
}

/// The YAML parse every decoding starts with.
fn parse_yaml(raw: &str) -> Result<Value, serde_yaml::Error> {
    serde_yaml::from_str(raw)
}

/// Where a source stops parsing as YAML: the first error of the parser that
/// decoding uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlProblem {
    pub location: Option<YamlLocation>,
    /// The parser's message, without the location.
    pub message: String,
}

/// A place in a source's text: its line and the column in characters, both
/// counted from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YamlLocation {
    pub line: usize,
    pub column: usize,
}

/// The source's first YAML error, if it does not parse.
pub fn yaml_problem(raw: &str) -> Option<YamlProblem> {
    let error = parse_yaml(raw).err()?;
    let location = error.location().map(|location| YamlLocation {
        line: location.line(),
        column: location.column(),
    });
    let mut message = error.to_string();
    if let Some(YamlLocation { line, column }) = location {
        message = message.replacen(&format!(" at line {line} column {column}"), "", 1);
    }
    Some(YamlProblem { location, message })
}

pub(crate) fn parse_source(raw: &str) -> Result<ParsedSource, String> {
    let mut value = parse_yaml(raw).map_err(|error| format!("invalid profile YAML: {error}"))?;
    if !value.is_mapping() {
        return Err("profile YAML must be a mapping".into());
    }
    // Clash configurations commonly share node and group options through
    // YAML merge keys (`<<: *anchor`).
    value
        .apply_merge()
        .map_err(|error| format!("invalid profile YAML: {error}"))?;
    let network = ProfileNetworkConfig::deserialize(&value)
        .map_err(|error| format!("invalid profile network settings: {error}"))?;
    network.listen_addr()?;
    let document: SourceDocument = serde_yaml::from_value(value)
        .map_err(|error| format!("invalid profile configuration: {error}"))?;
    let mut content = RuntimeProfile::new("");
    content.dns = dns::parse_dns(document.dns)?;
    content.dns.hosts = dns::parse_hosts(document.hosts)?;
    content.proxies = document.proxies.into_iter().map(nodes::node).collect();
    content.groups = document
        .proxy_groups
        .into_iter()
        .map(nodes::group)
        .collect();
    let rules = rules::source_rules(&document.rules)?;
    content.rules = rules.rules;
    Ok(ParsedSource {
        network,
        mode: document.mode,
        content,
        unknown_rule_kinds: rules.unknown_kinds,
        rule_providers: rules::providers(document.rule_providers),
        revision: format!("{:x}", Sha256::digest(raw.as_bytes())),
    })
}

/// `mode` is case-insensitive, accepting spellings such as `mode: Rule`.
fn source_mode<'de, D>(deserializer: D) -> Result<Option<TrafficPolicyMode>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(text) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match text.trim().to_ascii_lowercase().as_str() {
        "rule" => Ok(Some(TrafficPolicyMode::Rule)),
        "global" => Ok(Some(TrafficPolicyMode::Global)),
        "direct" => Ok(Some(TrafficPolicyMode::Direct)),
        _ => Err(serde::de::Error::custom(format!(
            "unsupported mode: {text}; it is rule, global or direct"
        ))),
    }
}

/// A key written without a value (`proxies:`) is YAML null; Clash reads it as
/// an empty list.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
pub(crate) fn composed_profile(yaml: &str) -> Result<RuntimeProfile, String> {
    crate::configuration::compose_profile("profile", "Profile", yaml, &Default::default())
        .map(|snapshot| snapshot.profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egrio_core::{PolicyGroupKind, ProxyProtocol, RuleKind};

    #[test]
    fn a_yaml_problem_names_its_place_once() {
        assert_eq!(yaml_problem("mixed-port: 7890\nmode: rule\n"), None);
        let problem = yaml_problem("proxies:\n  - name: a\n    type: ss\n   port: 1\n")
            .expect("a misindented key does not parse");
        let location = problem.location.expect("the parser names the place");
        assert_eq!(location.line, 4);
        assert!(
            !problem.message.contains("at line 4"),
            "the place is not repeated: {}",
            problem.message
        );
        let wide = yaml_problem("名字: 节点\nkey: [unclosed\n").expect("an open list");
        assert!(wide.location.is_some_and(|location| location.line >= 2));
    }

    /// A converted subscription accepts a capitalized mode and null lists.
    #[test]
    fn a_converted_subscription_reads_with_its_capitalized_mode() {
        let source = parse_source(concat!(
            "port: 7890\n",
            "socks-port: 7891\n",
            "allow-lan: true\n",
            "mode: Rule\n",
            "log-level: info\n",
            "external-controller: 127.0.0.1:9090\n",
            "proxies: ~\n",
            "proxy-groups: ~\n",
            "rules: ~\n",
        ))
        .expect("a converted subscription");
        assert_eq!(source.mode, Some(TrafficPolicyMode::Rule));
        for (text, mode) in [
            ("GLOBAL", Some(TrafficPolicyMode::Global)),
            (" direct ", Some(TrafficPolicyMode::Direct)),
            ("~", None),
        ] {
            let source = parse_source(&format!("mode: {text}\n")).expect(text);
            assert_eq!(source.mode, mode, "{text}");
        }
        assert_eq!(parse_source("proxies: []\n").unwrap().mode, None);
        let error = parse_source("mode: script\n").expect_err("a mode Egrio has not");
        assert!(error.contains("unsupported mode: script"), "{error}");
    }

    #[test]
    fn normalizes_basic_clash_yaml() {
        let yaml = r#"
proxies:
  - name: HK 01
    type: hysteria2
    server: hk.example.com
    port: "443"
    password: secret
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - HK 01
      - DIRECT
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,Proxy
"#;

        let profile = composed_profile(yaml).expect("valid clash profile");

        assert_eq!(profile.proxies.len(), 1);
        assert_eq!(profile.proxies[0].id, nodes::stable_id("proxy", "HK 01"));
        assert!(matches!(
            profile.proxies[0].protocol,
            ProxyProtocol::Hysteria2
        ));
        assert_eq!(profile.proxies[0].port, Some(443));
        assert_eq!(profile.proxies[0].options["password"], "secret");
        assert_eq!(profile.groups.len(), 1);
        assert_eq!(profile.groups[0].members, vec!["HK 01", "DIRECT"]);
        let rules: Vec<_> = profile.rules.iter().collect();
        assert_eq!(rules.len(), 3);
        assert!(matches!(rules[0].kind, RuleKind::DomainSuffix));
        assert!(rules[1].no_resolve);
        assert!(matches!(rules[2].kind, RuleKind::Match));
    }

    #[test]
    fn an_openvpn_node_names_its_ovpn_file() {
        let profile = composed_profile(
            r#"
proxies:
  - { name: office, type: openvpn, config: ~/vpn/office.ovpn, username: user, password: secret, dialer-proxy: HK 01 }
"#,
        )
        .expect("valid clash profile");
        let node = &profile.proxies[0];
        assert!(matches!(node.protocol, ProxyProtocol::OpenVpn));
        assert_eq!((node.server.as_deref(), node.port), (None, None));
        assert_eq!(node.options["config"], "~/vpn/office.ovpn");
        assert_eq!(node.dialer_proxy(), Some("HK 01"));
    }

    /// Numeric names and members are accepted without quotes; intervals
    /// also accept quoted numbers.
    #[test]
    fn node_and_group_scalars_read_whichever_way_they_are_written() {
        let profile = composed_profile(
            r#"
proxies:
  - {name: 1, type: ss, server: a.example, port: "443", cipher: aes-128-gcm, password: 123456}
  - {name: 2.5, type: ss, server: b.example, port: 443, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: 2024, type: url-test, proxies: [1, 2.5, DIRECT], interval: "300", url: "http://x.test"}
  - {name: Empty, type: select, proxies: ~, interval: ~}
rules:
  - MATCH,2024
"#,
        )
        .expect("weakly typed scalars");
        assert_eq!(profile.proxies[0].name, "1");
        assert_eq!(profile.proxies[0].port, Some(443));
        assert_eq!(profile.proxies[0].options["password"], 123456);
        assert_eq!(profile.proxies[1].name, "2.5");
        assert_eq!(profile.groups[0].name, "2024");
        assert_eq!(profile.groups[0].members, ["1", "2.5", "DIRECT"]);
        assert_eq!(profile.groups[0].interval_seconds, Some(300));
        assert!(profile.groups[1].members.is_empty());
        assert_eq!(profile.groups[1].interval_seconds, None);

        for (what, yaml) in [
            ("a list for a name", "proxies:\n  - {name: [a], type: ss}\n"),
            (
                "a mapping for a member",
                "proxy-groups:\n  - {name: G, type: select, proxies: [{a: b}]}\n",
            ),
            (
                "an interval that is no number",
                "proxy-groups:\n  - {name: G, type: select, interval: soon}\n",
            ),
            (
                "a negative interval",
                "proxy-groups:\n  - {name: G, type: select, interval: -1}\n",
            ),
        ] {
            assert!(parse_source(yaml).is_err(), "{what}");
        }
    }

    #[test]
    fn merge_keys_share_node_and_group_options() {
        let source = parse_source(
            r#"
node-defaults: &node { type: socks5, server: 192.0.2.1, udp: true }
group-defaults: &group { type: select, proxies: [a, b] }
proxies:
  - { <<: *node, name: a, port: 1080 }
  - { <<: *node, name: b, port: 1081, udp: false }
proxy-groups:
  - { <<: *group, name: Proxy }
  - { <<: *group, name: Auto, type: url-test, interval: 300 }
"#,
        )
        .unwrap();
        let [a, b] = &source.content.proxies[..] else {
            panic!("two nodes")
        };
        assert_eq!(
            (a.server.as_deref(), a.port),
            (Some("192.0.2.1"), Some(1080))
        );
        assert_eq!(a.options["udp"], true);
        assert_eq!(
            b.options["udp"], false,
            "an explicit key wins over the merged one"
        );
        assert!(!a.options.as_object().unwrap().contains_key("<<"));
        let [proxy, auto] = &source.content.groups[..] else {
            panic!("two groups")
        };
        assert!(matches!(proxy.kind, PolicyGroupKind::Select));
        assert_eq!(proxy.members, ["a", "b"]);
        assert!(matches!(auto.kind, PolicyGroupKind::UrlTest));
        assert_eq!(auto.members, ["a", "b"]);
    }

    #[test]
    fn unsupported_keys_are_ignored_and_empty_sections_are_empty() {
        let source = parse_source(
            "log-level: debug\ntun: { enable: true }\nproxy-providers: { p: { type: http, url: 'https://example.com' } }\nproxies:\nproxy-groups:\nrules:\n",
        )
        .unwrap();
        assert!(source.content.proxies.is_empty());
        assert!(source.content.groups.is_empty());
        assert!(source.content.rules.is_empty());
        assert!(parse_source("- not a mapping\n").is_err());
        assert!(parse_source("rules: ['DOMAIN-SUFFIX,example.com']\n").is_err());
    }

    #[test]
    fn rule_providers_are_read_leniently() {
        let source = parse_source(
            "rule-providers:\n  good: { type: http, behavior: domain, url: 'https://example.com/a.yaml' }\n  local: { type: file, behavior: classical, path: ./b.yaml }\n  broken: [not, a, provider]\n",
        )
        .unwrap();
        let names: Vec<_> = source
            .rule_providers
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["good", "local"]);
        assert_eq!(source.rule_providers[1].url, None);
        assert!(parse_source("rule-providers: [broken]\n")
            .unwrap()
            .rule_providers
            .is_empty());
    }

    #[test]
    fn validates_profile_network_fields_during_import_and_edit() {
        composed_profile(
            "mixed-port: 7890\nallow-lan: true\nbind-address: '::1'\nipv6: true\nproxies: []\nrules: []\n",
        )
        .expect("valid network settings");
        for yaml in [
            "mixed-port: 0\n",
            "mixed-port: 65536\n",
            "mixed-port: -1\n",
            "mixed-port: '7890'\n",
            "allow-lan: 'true'\n",
            "bind-address: localhost\n",
            "ipv6: 1\n",
        ] {
            assert!(
                composed_profile(yaml).is_err(),
                "accepted invalid settings: {yaml}",
            );
        }
    }

    #[test]
    fn keeps_ipv6_in_the_single_global_network_setting() {
        for dns in [
            "",
            "dns:\n  enable: false\n",
            "dns:\n  enable: true\n  nameserver: [https://dns.example/dns-query, system]\n",
        ] {
            let baseline = composed_profile(&format!("{dns}proxies: []\nrules: []\n"))
                .unwrap()
                .dns;
            for (network, enabled) in [
                ("", false),
                ("ipv6: false\n", false),
                ("ipv6: true\n", true),
            ] {
                let yaml = format!("{network}{dns}proxies: []\nrules: []\n");
                let snapshot = crate::configuration::compose_profile(
                    "profile",
                    "Profile",
                    &yaml,
                    &Default::default(),
                )
                .expect("single global policy parses");
                assert_eq!(snapshot.network.ipv6, enabled);
                assert_eq!(
                    snapshot.profile.dns, baseline,
                    "DNS must not acquire a second IPv6 policy"
                );
            }
        }
    }
}
