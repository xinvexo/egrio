use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

mod entries;
mod rules;
pub use entries::{RuleSetEntries, RuleSetEntriesBuilder, RuleSetTooLarge};
pub use rules::{
    rule_text, RouteRule, RouteRules, RouteRulesBuilder, RouteRulesIter, RouteRulesTooLarge,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub traffic_policy_mode: TrafficPolicyMode,
    #[serde(default)]
    pub global_outbound: Option<String>,
    #[serde(default)]
    pub dns: crate::dns::config::RuntimeDnsConfig,
    pub proxies: Vec<ProxyNode>,
    pub groups: Vec<PolicyGroup>,
    pub rules: RouteRules,
    /// Fetched rule-provider contents keyed by name, injected by the host
    /// when assembling the active document so RULE-SET rules can match.
    /// Absent for hosts that haven't fetched anything (older documents).
    #[serde(default)]
    pub rule_sets: Vec<RuleSetContent>,
    /// The GeoIP and GeoSite entries the rules name, injected by the host
    /// from its data files so GEOIP and GEOSITE rules can match.
    #[serde(default)]
    pub geodata: crate::geodata::GeoDataContent,
}

impl RuntimeProfile {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            id: name.clone(),
            name,
            traffic_policy_mode: TrafficPolicyMode::Rule,
            global_outbound: None,
            dns: crate::dns::config::RuntimeDnsConfig::default(),
            proxies: Vec::new(),
            groups: Vec::new(),
            rules: RouteRules::default(),
            rule_sets: Vec::new(),
            geodata: Default::default(),
        }
    }
}

/// One rule provider's fetched content: the entry lines of a clash
/// rule-set, already unwrapped from their yaml/text envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetContent {
    pub name: String,
    pub behavior: RuleSetBehavior,
    pub entries: RuleSetEntries,
}

/// clash rule-provider `behavior`: what the entry lines mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSetBehavior {
    /// Entries are domains (`example.com`, `+.example.com`, `*.example.com`).
    Domain,
    /// Entries are IP CIDRs matched against the destination IP.
    Ipcidr,
    /// Entries are full rule texts without an outbound (`DOMAIN-SUFFIX,x`).
    Classical,
}

impl RuleSetBehavior {
    pub fn from_clash_text(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "domain" => Some(Self::Domain),
            "ipcidr" => Some(Self::Ipcidr),
            "classical" => Some(Self::Classical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum TrafficPolicyMode {
    #[default]
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyProtocol {
    Direct,
    Reject,
    Http,
    Socks5,
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Tuic,
    #[serde(rename = "openvpn")]
    OpenVpn,
    Unknown,
}

impl ProxyProtocol {
    /// The serialized name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reject => "reject",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::OpenVpn => "openvpn",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNode {
    pub id: String,
    pub name: String,
    pub protocol: ProxyProtocol,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub options: JsonValue,
}

impl ProxyNode {
    /// `hidden: true` keeps the node out of hosts' node lists and their
    /// latency tests; rules, groups and other nodes still reach it.
    pub fn hidden(&self) -> bool {
        self.options
            .get("hidden")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
    }

    /// `test-url`, any node's: what a latency test of the node requests
    /// through it, and what the health probes of a group that names no URL
    /// do. Without one, [`crate::DEFAULT_PROBE_TEST_URL`].
    pub fn test_url(&self) -> Option<&str> {
        self.options
            .get("test-url")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }

    /// `dialer-proxy`: the outbound — a node or a policy group — the node
    /// reaches its own server through, instead of from this host.
    pub fn dialer_proxy(&self) -> Option<&str> {
        dialer_proxy(&self.options)
    }
}

/// [`ProxyNode::dialer_proxy`] from a node's options.
pub(crate) fn dialer_proxy(options: &JsonValue) -> Option<&str> {
    options
        .get("dialer-proxy")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyGroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
    Unknown,
}

impl PolicyGroupKind {
    /// The serialized name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    pub id: String,
    pub name: String,
    pub kind: PolicyGroupKind,
    pub members: Vec<String>,
    pub interval_seconds: Option<u64>,
    pub test_url: Option<String>,
    /// The Select group's initial selection, carried by the profile document
    /// so hosts can hand a persisted user choice to a freshly compiled core
    /// (for example the provider IPC host reloading its materialized profile
    /// file). The durable in-core selection, once set through
    /// `select_group_member`, takes precedence.
    #[serde(default)]
    pub selected: Option<String>,
}

/// The commonly used subset of the Clash rule types; deliberately excludes
/// the niche ones (IN-*, UID, DSCP, IP-SUFFIX, ASN, wildcards, SUB-RULE),
/// which parse as `Unknown`. Serialized names follow the lowercased clash
/// text form so the UI can round-trip them with `toUpperCase()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    Geosite,
    #[serde(rename = "geoip")]
    GeoIp,
    IpCidr,
    #[serde(rename = "ip-cidr6")]
    IpCidr6,
    SrcIpCidr,
    SrcPort,
    DstPort,
    ProcessName,
    ProcessPath,
    Network,
    And,
    Or,
    Not,
    RuleSet,
    Match,
    Unknown,
}

impl RuleKind {
    const ALL: [Self; 20] = [
        Self::Domain,
        Self::DomainSuffix,
        Self::DomainKeyword,
        Self::DomainRegex,
        Self::Geosite,
        Self::GeoIp,
        Self::IpCidr,
        Self::IpCidr6,
        Self::SrcIpCidr,
        Self::SrcPort,
        Self::DstPort,
        Self::ProcessName,
        Self::ProcessPath,
        Self::Network,
        Self::And,
        Self::Or,
        Self::Not,
        Self::RuleSet,
        Self::Match,
        Self::Unknown,
    ];

    /// The serialized name: the clash text form in lowercase.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain-suffix",
            Self::DomainKeyword => "domain-keyword",
            Self::DomainRegex => "domain-regex",
            Self::Geosite => "geosite",
            Self::GeoIp => "geoip",
            Self::IpCidr => "ip-cidr",
            Self::IpCidr6 => "ip-cidr6",
            Self::SrcIpCidr => "src-ip-cidr",
            Self::SrcPort => "src-port",
            Self::DstPort => "dst-port",
            Self::ProcessName => "process-name",
            Self::ProcessPath => "process-path",
            Self::Network => "network",
            Self::And => "and",
            Self::Or => "or",
            Self::Not => "not",
            Self::RuleSet => "rule-set",
            Self::Match => "match",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the clash rule text form (`DOMAIN-SUFFIX`, `SRC-IP-CIDR`, ...),
    /// case-insensitively. Anything unrecognized becomes `Unknown` so the
    /// profile still loads and the engine reports it as a compile warning.
    pub fn from_clash_text(text: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(text))
            .unwrap_or(Self::Unknown)
    }

    /// The `src` rule parameter turns a destination-IP rule into its
    /// source-IP counterpart; kinds without a source variant are returned
    /// unchanged.
    pub fn into_source_variant(self) -> Self {
        match self {
            Self::IpCidr | Self::IpCidr6 => Self::SrcIpCidr,
            other => other,
        }
    }

    /// Rule kinds whose payload may itself contain commas (nested rules or
    /// regular expressions); their clash text form is parsed as
    /// `KIND,<everything up to the last comma>,TARGET` with no trailing
    /// params, since only the last comma can be told from the payload's own.
    pub fn payload_may_contain_commas(self) -> bool {
        matches!(self, Self::And | Self::Or | Self::Not | Self::DomainRegex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_defaults_to_rule_policy_for_new_and_legacy_profiles() {
        let profile = RuntimeProfile::new("manual");
        assert_eq!(profile.traffic_policy_mode, TrafficPolicyMode::Rule);
        assert_eq!(profile.global_outbound, None);

        let legacy = serde_json::json!({
            "id": "legacy",
            "name": "legacy",
            "source": "manual",
            "proxies": [],
            "groups": [],
            "rules": []
        });
        let profile: RuntimeProfile = serde_json::from_value(legacy).expect("legacy profile");

        assert_eq!(profile.traffic_policy_mode, TrafficPolicyMode::Rule);
        assert_eq!(profile.global_outbound, None);
    }

    #[test]
    fn a_rule_s_text_is_the_line_its_profile_writes() {
        let rule = |kind, payload, outbound, no_resolve| RouteRule {
            kind,
            payload,
            outbound,
            no_resolve,
        };
        assert_eq!(
            rule(RuleKind::DomainSuffix, Some("example.com"), "Proxy", false).text(),
            "DOMAIN-SUFFIX,example.com,Proxy"
        );
        assert_eq!(
            rule(RuleKind::GeoIp, Some("CN"), "DIRECT", true).text(),
            "GEOIP,CN,DIRECT,no-resolve"
        );
        assert_eq!(
            rule(RuleKind::Match, None, "DIRECT", false).text(),
            "MATCH,DIRECT"
        );
        assert_eq!(
            rule(
                RuleKind::And,
                Some("((DOMAIN,a.example),(NETWORK,UDP))"),
                "REJECT",
                false
            )
            .text(),
            "AND,((DOMAIN,a.example),(NETWORK,UDP)),REJECT"
        );
        // A host that lists rules by their serialized kind writes the same
        // text, so its count of a rule's hits finds the rule.
        for kind in RuleKind::ALL {
            let listed = RuleKind::from_clash_text(kind.as_str());
            assert_eq!(
                rule_text(listed, Some("x"), "Proxy", false),
                rule(kind, Some("x"), "Proxy", false).text()
            );
        }
    }

    #[test]
    fn kind_names_are_the_serialized_names_and_the_clash_text() {
        for kind in RuleKind::ALL {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
            assert_eq!(
                RuleKind::from_clash_text(&kind.as_str().to_uppercase()),
                kind
            );
        }
        for protocol in [
            ProxyProtocol::Direct,
            ProxyProtocol::Reject,
            ProxyProtocol::Http,
            ProxyProtocol::Socks5,
            ProxyProtocol::Shadowsocks,
            ProxyProtocol::Vmess,
            ProxyProtocol::Vless,
            ProxyProtocol::Trojan,
            ProxyProtocol::Hysteria2,
            ProxyProtocol::Tuic,
            ProxyProtocol::Unknown,
        ] {
            assert_eq!(serde_json::to_value(&protocol).unwrap(), protocol.as_str());
        }
        for kind in [
            PolicyGroupKind::Select,
            PolicyGroupKind::UrlTest,
            PolicyGroupKind::Fallback,
            PolicyGroupKind::LoadBalance,
            PolicyGroupKind::Relay,
            PolicyGroupKind::Unknown,
        ] {
            assert_eq!(serde_json::to_value(&kind).unwrap(), kind.as_str());
        }
    }
}
