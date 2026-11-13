//! Host-neutral DNS policy. Product parsers translate their input format here.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub use super::fake_ip::FakeIpRange;
pub use super::pattern::DnsDomainPattern;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeDnsConfig {
    pub enabled: bool,
    pub enhanced_mode: DnsMode,
    pub nameservers: Vec<DnsUpstream>,
    pub bootstrap_nameservers: Vec<DnsUpstream>,
    pub proxy_nameservers: Vec<DnsUpstream>,
    pub direct_nameservers: Vec<DnsUpstream>,
    pub policies: Vec<DnsNameServerPolicy>,
    pub fake_ip_range: FakeIpRange,
    pub fake_ip_filter: Vec<DnsDomainPattern>,
    /// Names mapped to fixed addresses, in the profile's order; they apply
    /// whether or not the rest of this policy is enabled.
    pub hosts: Vec<DnsHost>,
    /// The apps' address questions for a mapped name are answered from the
    /// mapping. The Core's own lookups use it either way.
    pub use_hosts: bool,
    /// The system's hosts file maps the names the profile's hosts do not.
    pub use_system_hosts: bool,
}

impl Default for RuntimeDnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enhanced_mode: DnsMode::default(),
            nameservers: Vec::new(),
            bootstrap_nameservers: Vec::new(),
            proxy_nameservers: Vec::new(),
            direct_nameservers: Vec::new(),
            policies: Vec::new(),
            fake_ip_range: FakeIpRange::default(),
            fake_ip_filter: Vec::new(),
            hosts: Vec::new(),
            use_hosts: true,
            use_system_hosts: true,
        }
    }
}

/// A name, or names matching a pattern, and the addresses they map to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHost {
    pub pattern: DnsDomainPattern,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    #[default]
    RedirHost,
    FakeIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsTransport {
    System,
    Udp,
    Tcp,
    Tls,
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsRoute {
    Direct,
    Rules,
    /// Use the profile's selected proxy independently of resolver-address rules.
    /// A selection that resolves to DIRECT is unavailable for this route.
    Proxy,
    NamedOutbound(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsUpstream {
    pub transport: DnsTransport,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub server_name: Option<String>,
    /// None follows the query-purpose policy: business rules, direct bootstrap.
    pub route: Option<DnsRoute>,
}

impl DnsUpstream {
    pub fn system() -> Self {
        Self {
            transport: DnsTransport::System,
            host: String::new(),
            port: 0,
            path: String::new(),
            server_name: None,
            route: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsNameServerPolicy {
    pub pattern: DnsDomainPattern,
    pub nameservers: Vec<DnsUpstream>,
}
