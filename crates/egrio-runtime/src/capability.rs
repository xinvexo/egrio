use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;

use egrio_core::{NativeCoreDeviceRunReport, PacketDevice};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::CapabilityCheckpoint;

pub type CapabilityFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CapabilityError>> + Send + 'a>>;
pub type ConnectionHealthFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

pub trait ConnectionHealth: Send + Sync + fmt::Debug {
    fn wait_disconnected<'a>(&'a self) -> ConnectionHealthFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    PacketCapture,
    SystemProxy,
    Route,
    Dns,
    Firewall,
    /// A checkpoint or lease that names no known capability (foreign or
    /// corrupted recovery state).
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CapabilitySupport {
    Supported,
    Unsupported { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityErrorCode {
    Unsupported,
    InvalidRequest,
    Conflict,
    ApplyFailed,
    ObserveFailed,
    RestoreFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityError {
    pub capability: CapabilityKind,
    pub code: CapabilityErrorCode,
    pub message: String,
}

impl CapabilityError {
    #[must_use]
    pub fn new(
        capability: CapabilityKind,
        code: CapabilityErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn unsupported(capability: CapabilityKind, reason: impl Into<String>) -> Self {
        Self::new(capability, CapabilityErrorCode::Unsupported, reason)
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.capability, self.message)
    }
}
impl Error for CapabilityError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityObservation {
    pub capability: CapabilityKind,
    pub active: bool,
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityOperationReport {
    pub capability: CapabilityKind,
    pub changed: bool,
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum PacketCaptureSource {
    Tun,
    PacketTunnel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PacketCaptureSettings {
    /// Requested IP-layer MTU; the same generation Core must use this value.
    pub mtu: u32,
    pub source: PacketCaptureSource,
    pub install_default_route: bool,
    /// The capture adapter configures DNS as part of its network settings.
    pub install_dns: bool,
    /// Destinations the capture's own default route leaves outside the
    /// tunnel, where the capture installs the route itself.
    #[serde(default)]
    pub excluded_prefixes: Vec<IpPrefix>,
    /// The Core's fake-IP pool and its IPv6 projection, when no firewall
    /// layer keeps them inside the tunnel: the capture then makes a connect
    /// to them outside the tunnel fail at once (see
    /// [`FirewallSettings::fake_ip_prefixes`]).
    #[serde(default)]
    pub fake_ip_prefixes: Vec<IpPrefix>,
}

impl PacketCaptureSettings {
    pub fn validate(&self) -> Result<(), String> {
        egrio_core::NativeCoreCaptureConfig::validate_mtu(self.mtu)?;
        if !self.install_default_route && !self.excluded_prefixes.is_empty() {
            return Err("excluded prefixes need the capture's default route".into());
        }
        validate_excluded_prefixes(&self.excluded_prefixes)?;
        match self
            .fake_ip_prefixes
            .iter()
            .find(|prefix| !prefix.is_canonical())
        {
            Some(prefix) => Err(format!("fake-IP prefix {prefix} has host bits set")),
            None => Ok(()),
        }
    }

    /// Whether moving to `next` changes only the excluded prefixes, which an
    /// open capture takes in place.
    pub fn differs_only_in_exclusions(&self, next: &Self) -> bool {
        self.excluded_prefixes != next.excluded_prefixes
            && Self {
                excluded_prefixes: Vec::new(),
                ..self.clone()
            } == Self {
                excluded_prefixes: Vec::new(),
                ..next.clone()
            }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemProxySettings {
    pub http_proxy: Option<SocketAddr>,
    pub https_proxy: Option<SocketAddr>,
    pub bypass: Vec<String>,
}

/// An IP prefix (`192.168.0.0/16`, `fc00::/7`). Routes and filters need
/// canonical prefixes, whose host bits are clear; [`IpPrefix::new`] and
/// parsing produce only those.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    /// The prefix keeping the first `prefix_len` bits of `address`.
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, String> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > bits {
            return Err(format!(
                "{address}/{prefix_len}: the prefix length exceeds {bits}"
            ));
        }
        Ok(Self {
            address: masked(address, prefix_len),
            prefix_len,
        })
    }

    /// Whether the host bits are clear.
    pub fn is_canonical(&self) -> bool {
        Self::new(self.address, self.prefix_len).is_ok_and(|prefix| prefix == *self)
    }

    /// Whether `address` lies within this prefix.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.address.is_ipv4() == address.is_ipv4()
            && masked(address, self.prefix_len) == self.address
    }

    /// Whether `other` lies within this prefix.
    pub fn covers(&self, other: &IpPrefix) -> bool {
        self.address.is_ipv4() == other.address.is_ipv4()
            && self.prefix_len <= other.prefix_len
            && masked(other.address, self.prefix_len) == self.address
    }

    /// A Core's fake-IP pool and the IPv6 projection its AAAA answers come
    /// from: what [`FirewallSettings::fake_ip_prefixes`] keeps inside the
    /// tunnel for a Core started with `range`.
    pub fn fake_ip_pool(range: egrio_core::dns::config::FakeIpRange) -> Vec<IpPrefix> {
        let (network6, prefix_len6) = range.ipv6_network();
        vec![
            IpPrefix {
                address: range.network().into(),
                prefix_len: range.prefix_len(),
            },
            IpPrefix {
                address: network6.into(),
                prefix_len: prefix_len6,
            },
        ]
    }

    /// The two prefixes one bit longer that make up this one.
    fn halves(&self) -> (IpPrefix, IpPrefix) {
        let prefix_len = self.prefix_len + 1;
        let high = match self.address {
            IpAddr::V4(address) => IpAddr::V4((u32::from(address) | 1 << (32 - prefix_len)).into()),
            IpAddr::V6(address) => {
                IpAddr::V6((u128::from(address) | 1 << (128 - prefix_len)).into())
            }
        };
        (
            IpPrefix {
                address: self.address,
                prefix_len,
            },
            IpPrefix {
                address: high,
                prefix_len,
            },
        )
    }
}

/// The most routes one address family of a capture installs once exclusions
/// split it. Each exclusion of an `/n` prefix costs up to `n` routes; the
/// bound keeps installing them a matter of seconds.
pub const MAX_CAPTURE_ROUTES_PER_FAMILY: usize = 4096;

/// `roots` minus `excluded`. A root an exclusion covers is dropped; a root
/// that holds an exclusion is halved down to it, keeping every half that
/// does not hold it. Routed into a tunnel, these leave an excluded destination
/// to the routes the system had: its default route, an on-link network or
/// another tunnel's route. The halves next to an exclusion are longer than the
/// root, so they can be more specific than another tunnel's route that covers
/// them.
pub fn capture_prefixes(roots: &[IpPrefix], excluded: &[IpPrefix]) -> Vec<IpPrefix> {
    let mut prefixes = roots.to_vec();
    for exclusion in excluded {
        prefixes = prefixes
            .into_iter()
            .flat_map(|prefix| subtract(prefix, exclusion))
            .collect();
    }
    prefixes.sort();
    prefixes
}

/// [`capture_prefixes`] of one family's `roots` and that family's part of
/// `excluded`, refused past [`MAX_CAPTURE_ROUTES_PER_FAMILY`]: a capture
/// fails whole rather than installing part of its routes.
pub fn family_capture_prefixes(
    roots: &[IpPrefix],
    excluded: &[IpPrefix],
) -> Result<Vec<IpPrefix>, String> {
    let Some(first) = roots.first() else {
        return Ok(Vec::new());
    };
    let family = first.address.is_ipv4();
    let excluded = excluded
        .iter()
        .filter(|prefix| prefix.address.is_ipv4() == family)
        .copied()
        .collect::<Vec<_>>();
    let prefixes = capture_prefixes(roots, &excluded);
    if prefixes.len() > MAX_CAPTURE_ROUTES_PER_FAMILY {
        return Err(format!(
            "the excluded prefixes split the capture into {} routes, more than {MAX_CAPTURE_ROUTES_PER_FAMILY}; exclude fewer or shorter prefixes",
            prefixes.len()
        ));
    }
    Ok(prefixes)
}

fn subtract(prefix: IpPrefix, exclusion: &IpPrefix) -> Vec<IpPrefix> {
    if exclusion.covers(&prefix) {
        return Vec::new();
    }
    if !prefix.covers(exclusion) {
        return vec![prefix];
    }
    let mut kept = Vec::new();
    let mut current = prefix;
    while current.prefix_len < exclusion.prefix_len {
        let (low, high) = current.halves();
        if low.covers(exclusion) {
            kept.push(high);
            current = low;
        } else {
            kept.push(low);
            current = high;
        }
    }
    kept
}

fn masked(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V6((u128::from(address) & mask).into())
        }
    }
}

impl FromStr for IpPrefix {
    type Err = String;

    /// `address/length`, or a bare address for that single host.
    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (address, length) = match text.split_once('/') {
            Some((address, length)) => (address, Some(length)),
            None => (text, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("{text}: not an IP address or CIDR prefix"))?;
        let prefix_len = match length {
            Some(length) => length
                .parse()
                .map_err(|_| format!("{text}: invalid prefix length"))?,
            None if address.is_ipv4() => 32,
            None => 128,
        };
        Self::new(address, prefix_len)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix_len)
    }
}

/// The most destinations one capture keeps outside its tunnel. Each costs
/// route and filter entries on every platform; a few hundred covers real
/// configurations and keeps applying them fast.
pub const MAX_EXCLUDED_PREFIXES: usize = 256;

fn validate_excluded_prefixes(prefixes: &[IpPrefix]) -> Result<(), String> {
    if prefixes.len() > MAX_EXCLUDED_PREFIXES {
        return Err(format!(
            "{} excluded prefixes exceed the limit of {MAX_EXCLUDED_PREFIXES}",
            prefixes.len()
        ));
    }
    match prefixes.iter().find(|prefix| !prefix.is_canonical()) {
        Some(prefix) => Err(format!("excluded prefix {prefix} has host bits set")),
        None => Ok(()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteSettings {
    pub default_route: bool,
    /// Destinations the default route leaves outside the tunnel: they keep
    /// the routes the system had, so their traffic never reaches the Core.
    pub excluded_prefixes: Vec<IpPrefix>,
}

impl RouteSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !self.default_route && !self.excluded_prefixes.is_empty() {
            return Err("excluded prefixes need the default route".into());
        }
        validate_excluded_prefixes(&self.excluded_prefixes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsSettings {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirewallSettings {
    /// Block the leaks around the tunnel while it runs: DNS that does not go
    /// through it, IPv6 it does not carry and fake IPs outside it. What other
    /// software sends outside the tunnel on purpose (another VPN, a socket
    /// bound to an interface) passes, and nothing is blocked once the tunnel
    /// is gone, whether it stopped or the process holding it crashed.
    pub kill_switch: bool,
    pub allow_lan: bool,
    /// Destinations routed outside the tunnel, which the firewall lets
    /// through; the same list as the routes exclude.
    #[serde(default)]
    pub excluded_prefixes: Vec<IpPrefix>,
    /// The Core's fake-IP pool and its IPv6 projection, addresses only the
    /// Core answers, inside the tunnel: outside it a connect to them fails at
    /// once instead of waiting for a peer that is not there.
    #[serde(default)]
    pub fake_ip_prefixes: Vec<IpPrefix>,
}

macro_rules! mutable_capability {
    ($trait_name:ident, $settings:ty) => {
        pub trait $trait_name: Send + Sync + fmt::Debug {
            fn support(&self) -> CapabilitySupport;
            fn prepare<'a>(
                &'a self,
                settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityCheckpoint>;
            fn apply<'a>(
                &'a self,
                settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityOperationReport>;
            fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation>;
            fn restore<'a>(
                &'a self,
                checkpoint: &'a CapabilityCheckpoint,
            ) -> CapabilityFuture<'a, CapabilityOperationReport>;
        }
    };
}

mutable_capability!(SystemProxyControl, SystemProxySettings);
mutable_capability!(RouteControl, RouteSettings);
mutable_capability!(DnsControl, DnsSettings);
mutable_capability!(FirewallControl, FirewallSettings);

pub struct PacketCaptureOpen {
    /// The capture's queues: at least one, and no more than were asked for.
    pub queues: Vec<Box<dyn PacketDevice>>,
    pub report: CapabilityOperationReport,
}

impl fmt::Debug for PacketCaptureOpen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketCaptureOpen")
            .field("queues", &self.queues.len())
            .field(
                "device",
                &self.queues.first().map(|queue| queue.name().to_string()),
            )
            .field("report", &self.report)
            .finish()
    }
}

pub type PacketDataPlaneFuture =
    Pin<Box<dyn Future<Output = Result<NativeCoreDeviceRunReport, String>> + Send>>;

pub trait PacketDataPlane: Send + Sync + fmt::Debug {
    /// Drives each capture queue, on the executor paired with it, against the
    /// Runtime-owned Core until `stop` fires. The Core is passed per run
    /// precisely so a data plane cannot privately hold, replace, or hot-apply
    /// a second Core: the Runtime's generation Core is the only packet
    /// engine, and the listener session shares it.
    fn run(
        &self,
        core: egrio_core::NativeCoreDevice,
        queues: Vec<(Box<dyn PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture;
}

/// Supplies the start inputs for the Runtime-owned Core: the compiled
/// profile, resolved egress configuration, packet capture/DNS policy, an
/// optional egress socket guard, and the platform flow scanner that
/// attributes both listener and TUN connections. Loaded at the head of every
/// start transaction (before the listener binds and before any lease or OS
/// mutation), so hosts re-read their active profile and re-probe the
/// pre-capture network per generation. Profile hot applies during a
/// generation go through `Runtime::apply_core_with`, not through this
/// source.
pub trait CoreConfigSource: Send + Sync + fmt::Debug {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String>;
}

pub trait PacketCapture: Send + Sync + fmt::Debug {
    fn support(&self) -> CapabilitySupport;
    /// Interface and virtual DNS addresses the TUN occupies. The Runtime
    /// rejects capture while the running Core's fake-IP pool could hand any of
    /// them out as a remote destination.
    fn reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        Vec::new()
    }
    /// How many queues the capture can spread flows over, each read by a
    /// packet pump on an executor of its own (a Linux multi-queue TUN); one
    /// for a capture that reads through a single ring or descriptor.
    fn queue_limit(&self) -> usize {
        1
    }
    fn prepare<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint>;
    /// Opens the capture with as many queues as `queues` and its
    /// [`Self::queue_limit`] allow, at least one.
    fn open<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
        queues: usize,
    ) -> CapabilityFuture<'a, PacketCaptureOpen>;
    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation>;
    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport>;
    /// Replaces what the open capture keeps outside the tunnel, leaving the
    /// rest of the session as it is. Only a capture that installs its own
    /// routes takes exclusions; the session dies with the capture, so the
    /// capture's checkpoint already restores it.
    fn update_excluded_prefixes<'a>(
        &'a self,
        prefixes: &'a [IpPrefix],
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        let _ = prefixes;
        Box::pin(async {
            Err(CapabilityError::unsupported(
                CapabilityKind::PacketCapture,
                "this capture cannot change its exclusions while open",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> IpPrefix {
        text.parse().unwrap()
    }

    #[test]
    fn capture_prefixes_never_reach_an_excluded_address_and_cover_every_other() {
        let roots = [prefix("0.0.0.0/2"), prefix("64.0.0.0/2")];
        let excluded = [
            prefix("10.1.2.3/32"),
            prefix("10.0.0.0/8"),
            prefix("70.0.0.0/7"),
        ];
        let prefixes = capture_prefixes(&roots, &excluded);
        for probe in ["10.1.2.3", "10.200.0.1", "70.0.0.1", "71.255.255.255"] {
            let address = probe.parse().unwrap();
            assert!(
                prefixes.iter().all(|prefix| !prefix.contains(address)),
                "{probe}"
            );
        }
        for probe in [
            "9.255.255.255",
            "11.0.0.0",
            "69.255.255.255",
            "72.0.0.0",
            "1.1.1.1",
        ] {
            let address = probe.parse().unwrap();
            assert_eq!(
                prefixes
                    .iter()
                    .filter(|prefix| prefix.contains(address))
                    .count(),
                1,
                "{probe}"
            );
        }
    }

    #[test]
    fn an_exclusion_covering_a_root_drops_it() {
        assert!(capture_prefixes(&[prefix("0.0.0.0/2")], &[prefix("0.0.0.0/1")]).is_empty());
    }

    #[test]
    fn one_family_takes_only_its_exclusions_and_refuses_too_many_routes() {
        let roots = [prefix("::/1"), prefix("8000::/1")];
        let split = family_capture_prefixes(
            &roots,
            &[prefix("fd7a:115c:a1e0::/48"), prefix("10.0.0.0/8")],
        )
        .unwrap();
        assert_eq!(split.len(), 1 + 47, "the IPv4 exclusion leaves IPv6 alone");
        let hosts = (0..64)
            .map(|index| prefix(&format!("2001:db8:{index:x}::1/128")))
            .collect::<Vec<_>>();
        assert!(family_capture_prefixes(&roots, &hosts).is_err());
    }

    #[test]
    fn prefixes_parse_canonically_and_a_bare_address_is_one_host() {
        assert_eq!(prefix("192.168.1.5/24").to_string(), "192.168.1.0/24");
        assert_eq!(prefix("10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(
            prefix("fd7a:115c:a1e0::1/48").to_string(),
            "fd7a:115c:a1e0::/48"
        );
        assert_eq!(prefix("2001:db8::1").to_string(), "2001:db8::1/128");
        assert_eq!(prefix("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert!("10.0.0.0/33".parse::<IpPrefix>().is_err());
        assert!("::/129".parse::<IpPrefix>().is_err());
        assert!("example.com/24".parse::<IpPrefix>().is_err());
        assert!("10.0.0.0/x".parse::<IpPrefix>().is_err());
    }

    #[test]
    fn containment_stays_within_one_family() {
        let lan = prefix("192.168.0.0/16");
        assert!(lan.contains("192.168.4.4".parse().unwrap()));
        assert!(!lan.contains("192.169.0.1".parse().unwrap()));
        assert!(!lan.contains("::ffff:192.168.4.4".parse().unwrap()));
        assert!(lan.covers(&prefix("192.168.4.0/24")));
        assert!(!prefix("192.168.4.0/24").covers(&lan));
        assert!(prefix("::/0").covers(&prefix("fe80::/10")));
        assert!(!prefix("::/0").covers(&lan));
    }

    #[test]
    fn exclusions_need_the_default_route_canonical_prefixes_and_a_bound() {
        let route = |default_route, excluded_prefixes| RouteSettings {
            default_route,
            excluded_prefixes,
        };
        assert!(route(true, vec![prefix("10.0.0.0/8")]).validate().is_ok());
        assert!(route(false, vec![prefix("10.0.0.0/8")]).validate().is_err());
        let skewed = IpPrefix {
            address: "10.0.0.1".parse().unwrap(),
            prefix_len: 8,
        };
        assert!(route(true, vec![skewed]).validate().is_err());
        let many = (0..=MAX_EXCLUDED_PREFIXES)
            .map(|index| IpPrefix::new(IpAddr::from([10, 0, (index / 256) as u8, index as u8]), 32))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(route(true, many).validate().is_err());
    }

    #[test]
    fn only_an_exclusion_change_keeps_the_capture_open() {
        let capture = PacketCaptureSettings {
            mtu: 1500,
            source: PacketCaptureSource::PacketTunnel,
            install_default_route: true,
            install_dns: true,
            excluded_prefixes: Vec::new(),
            fake_ip_prefixes: Vec::new(),
        };
        let excluding = PacketCaptureSettings {
            excluded_prefixes: vec![prefix("192.168.0.0/16")],
            ..capture.clone()
        };
        assert!(capture.differs_only_in_exclusions(&excluding));
        assert!(excluding.differs_only_in_exclusions(&capture));
        assert!(!capture.differs_only_in_exclusions(&capture));
        let resized = PacketCaptureSettings {
            mtu: 1400,
            ..excluding.clone()
        };
        assert!(!capture.differs_only_in_exclusions(&resized));
        let pooled = PacketCaptureSettings {
            fake_ip_prefixes: vec![prefix("198.18.0.0/16")],
            ..excluding.clone()
        };
        assert!(!excluding.differs_only_in_exclusions(&pooled));
    }

    #[test]
    fn fake_ip_prefixes_must_be_canonical() {
        let mut capture = PacketCaptureSettings {
            mtu: 1500,
            source: PacketCaptureSource::PacketTunnel,
            install_default_route: true,
            install_dns: true,
            excluded_prefixes: Vec::new(),
            fake_ip_prefixes: vec![prefix("198.18.0.0/16")],
        };
        assert!(capture.validate().is_ok());
        capture.fake_ip_prefixes.push(IpPrefix {
            address: "198.19.0.1".parse().unwrap(),
            prefix_len: 16,
        });
        assert!(capture.validate().is_err());
    }
}
