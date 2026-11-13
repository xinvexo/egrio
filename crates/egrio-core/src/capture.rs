use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeCoreCaptureConfig {
    pub dns_hijack: NativeCoreDnsHijackConfig,
    /// IP-layer MTU shared by the TCP engine and packet output writer.
    pub mtu: u32,
    /// The capture interface's own subnets. Nothing addressed into them is
    /// relayed, neither their directed broadcast nor an address the tunnel
    /// leaves unused: sent through an egress socket it would leave through the
    /// physical uplink. Hijacked DNS is answered before this applies.
    #[serde(default)]
    pub interface_networks: Vec<NativeCoreInterfaceNetwork>,
}

/// One subnet of the capture interface, as an address and prefix length.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeCoreInterfaceNetwork {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl NativeCoreInterfaceNetwork {
    pub fn new(address: impl Into<IpAddr>, prefix_len: u8) -> Self {
        Self {
            address: address.into(),
            prefix_len,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) if self.prefix_len <= 32 => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) if self.prefix_len <= 128 => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    fn validate(&self) -> Result<(), String> {
        let limit = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len > limit {
            return Err(format!(
                "capture interface network {}/{} has an invalid prefix length",
                self.address, self.prefix_len
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeCoreDnsHijackConfig {
    pub mode: NativeCoreDnsHijackMode,
    pub udp_port: u16,
    pub virtual_dns_targets: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCoreDnsHijackMode {
    Disabled,
    UdpPort,
    UdpPortWithVirtualTcpTargets,
    VirtualDnsTargets,
}

impl NativeCoreCaptureConfig {
    pub fn with_dns_hijack(dns_hijack: NativeCoreDnsHijackConfig) -> Self {
        Self {
            dns_hijack,
            ..Self::default()
        }
    }

    pub fn with_interface_networks(
        mut self,
        networks: impl IntoIterator<Item = NativeCoreInterfaceNetwork>,
    ) -> Self {
        self.interface_networks = networks.into_iter().collect();
        self
    }

    /// Whether `ip` lies in one of the capture interface's own subnets.
    pub fn is_interface_destination(&self, ip: IpAddr) -> bool {
        self.interface_networks
            .iter()
            .any(|network| network.contains(ip))
    }

    pub fn with_mtu(mut self, mtu: u32) -> Result<Self, String> {
        Self::validate_mtu(mtu)?;
        self.mtu = mtu;
        Ok(self)
    }

    pub fn validate_mtu(mtu: u32) -> Result<(), String> {
        if !(1280..=65_535).contains(&mtu) {
            return Err(format!(
                "packet MTU must be 1280..65535 for the dual-stack capture link, got {mtu}"
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        Self::validate_mtu(self.mtu)?;
        self.interface_networks
            .iter()
            .try_for_each(NativeCoreInterfaceNetwork::validate)
    }
}

impl Default for NativeCoreCaptureConfig {
    fn default() -> Self {
        Self {
            dns_hijack: NativeCoreDnsHijackConfig::capture_udp_port(53),
            mtu: 1500,
            interface_networks: Vec::new(),
        }
    }
}

impl NativeCoreDnsHijackConfig {
    pub fn disabled() -> Self {
        Self {
            mode: NativeCoreDnsHijackMode::Disabled,
            udp_port: 53,
            virtual_dns_targets: Vec::new(),
        }
    }

    pub fn capture_udp_port(udp_port: u16) -> Self {
        Self {
            mode: NativeCoreDnsHijackMode::UdpPort,
            udp_port,
            virtual_dns_targets: Vec::new(),
        }
    }

    /// Intercept every UDP query on the configured port while terminating
    /// TCP DNS only at the virtual resolver addresses assigned to the TUN.
    /// Other TCP resolvers remain ordinary routed connections.
    pub fn capture_udp_port_with_virtual_tcp_targets(
        udp_port: u16,
        targets: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        let mut config = Self::capture_virtual_dns_targets(targets);
        config.mode = NativeCoreDnsHijackMode::UdpPortWithVirtualTcpTargets;
        config.udp_port = udp_port;
        config
    }

    pub fn capture_virtual_dns_targets(targets: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut virtual_dns_targets = targets.into_iter().collect::<Vec<_>>();
        virtual_dns_targets.sort();
        virtual_dns_targets.dedup();

        Self {
            mode: NativeCoreDnsHijackMode::VirtualDnsTargets,
            udp_port: 53,
            virtual_dns_targets,
        }
    }

    pub fn captures_udp_destination(
        &self,
        destination_ip: IpAddr,
        destination_port: Option<u16>,
    ) -> bool {
        if !self.captures_configured_port(destination_port) {
            return false;
        }

        match self.mode {
            NativeCoreDnsHijackMode::Disabled => false,
            NativeCoreDnsHijackMode::UdpPort
            | NativeCoreDnsHijackMode::UdpPortWithVirtualTcpTargets => true,
            NativeCoreDnsHijackMode::VirtualDnsTargets => {
                self.virtual_dns_targets.contains(&destination_ip)
            }
        }
    }

    pub fn captures_tcp_destination(
        &self,
        destination_ip: IpAddr,
        destination_port: Option<u16>,
    ) -> bool {
        if !self.captures_configured_port(destination_port) {
            return false;
        }

        match self.mode {
            NativeCoreDnsHijackMode::Disabled | NativeCoreDnsHijackMode::UdpPort => false,
            NativeCoreDnsHijackMode::VirtualDnsTargets
            | NativeCoreDnsHijackMode::UdpPortWithVirtualTcpTargets => {
                self.virtual_dns_targets.contains(&destination_ip)
            }
        }
    }

    fn captures_configured_port(&self, destination_port: Option<u16>) -> bool {
        if destination_port != Some(self.udp_port) {
            return false;
        }

        true
    }
}

/// Reject platform link/resolver addresses that the fake-IP pool could issue
/// as remote destinations. Otherwise the OS may resolve a fake destination
/// locally, bypassing the TUN before the Core ever sees it. Checked whatever
/// the DNS mode: global mode hands out fake IPs in every mode and can be
/// entered while the TUN runs. This performs no network I/O or mutation and
/// does not alter the pool.
pub fn validate_fake_ip_capture_addresses(
    dns: &crate::dns::config::RuntimeDnsConfig,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<(), String> {
    let range = dns.fake_ip_range;
    for address in addresses {
        let allocatable = match address {
            IpAddr::V4(ip) => range.is_allocatable(ip),
            IpAddr::V6(ip) => range.is_allocatable_ipv6(ip),
        };
        if allocatable {
            return Err(format!("fake-IP pool {range} can allocate platform capture address {address}; choose a pool disjoint from the TUN interface and virtual DNS addresses"));
        }
    }
    Ok(())
}

/// Rejects destinations routed outside the tunnel that overlap the fake-IP
/// pool or its IPv6 projection: a fake address routed past the TUN never
/// reaches the Core that answers for it. Checked whatever the DNS mode, like
/// the capture addresses.
pub fn validate_fake_ip_excluded_destinations(
    dns: &crate::dns::config::RuntimeDnsConfig,
    prefixes: impl IntoIterator<Item = (IpAddr, u8)>,
) -> Result<(), String> {
    let range = dns.fake_ip_range;
    for (address, prefix_len) in prefixes {
        if range.overlaps(address, prefix_len) {
            return Err(format!(
                "excluded prefix {address}/{prefix_len} overlaps the fake-IP pool {range}; fake addresses must stay inside the TUN"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn an_interface_network_contains_its_whole_prefix_of_its_own_family() {
        let v4 = NativeCoreInterfaceNetwork::new(Ipv4Addr::new(10, 255, 255, 1), 30);
        for last in 0..=3 {
            assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, last))));
        }
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 4))));
        assert!(!v4.contains("::1".parse().unwrap()));

        let v6 = NativeCoreInterfaceNetwork::new(
            "fd00:6572:6769:6f00::2".parse::<IpAddr>().unwrap(),
            64,
        );
        assert!(v6.contains("fd00:6572:6769:6f00::ffff".parse().unwrap()));
        assert!(!v6.contains("fd00:6572:6769:6f01::2".parse().unwrap()));

        let everything = NativeCoreInterfaceNetwork::new(Ipv4Addr::UNSPECIFIED, 0);
        assert!(everything.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));

        let invalid = NativeCoreCaptureConfig::default().with_interface_networks([
            NativeCoreInterfaceNetwork::new(Ipv4Addr::new(10, 0, 0, 1), 33),
        ]);
        assert!(invalid.validate().is_err());
        assert!(!invalid.is_interface_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn capture_mtu_has_an_explicit_dual_stack_range_and_preserves_dns_policy() {
        assert_eq!(NativeCoreCaptureConfig::default().mtu, 1500);
        let base = NativeCoreCaptureConfig::with_dns_hijack(NativeCoreDnsHijackConfig::disabled());
        for mtu in [1280, 1420, 1500, 65535] {
            let capture = base.clone().with_mtu(mtu).unwrap();
            assert_eq!(capture.mtu, mtu);
            assert_eq!(capture.dns_hijack, base.dns_hijack);
        }
        for mtu in [0, 1279, 65536, u32::MAX] {
            assert!(base.clone().with_mtu(mtu).is_err());
        }
    }

    #[test]
    fn default_dns_hijack_captures_udp_port_53() {
        let config = NativeCoreCaptureConfig::default();

        assert!(config
            .dns_hijack
            .captures_udp_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), Some(53)));
        assert!(!config
            .dns_hijack
            .captures_udp_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), Some(443)));
    }

    #[test]
    fn virtual_dns_hijack_captures_only_configured_targets() {
        let config = NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
            Ipv4Addr::new(10, 255, 255, 2),
        )]);

        assert!(
            config.captures_udp_destination(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)), Some(53))
        );
        assert!(!config.captures_udp_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), Some(53)));
    }

    #[test]
    fn virtual_dns_hijack_captures_configured_tcp_target() {
        let config = NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
            Ipv4Addr::new(10, 255, 255, 2),
        )]);

        assert!(
            config.captures_tcp_destination(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)), Some(53))
        );
        assert!(!config.captures_tcp_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), Some(53)));
        assert!(!NativeCoreDnsHijackConfig::capture_udp_port(53)
            .captures_tcp_destination(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)), Some(53)));
    }

    #[test]
    fn combined_udp_hijack_keeps_tcp_scoped_to_virtual_resolvers() {
        let virtual_dns = "198.18.0.1".parse().unwrap();
        let other = "1.1.1.1".parse().unwrap();
        let config = NativeCoreDnsHijackConfig::capture_udp_port_with_virtual_tcp_targets(
            53,
            [virtual_dns, virtual_dns],
        );
        assert_eq!(config.virtual_dns_targets, vec![virtual_dns]);
        assert!(config.captures_udp_destination(virtual_dns, Some(53)));
        assert!(config.captures_udp_destination(other, Some(53)));
        assert!(config.captures_tcp_destination(virtual_dns, Some(53)));
        assert!(!config.captures_tcp_destination(other, Some(53)));
        assert!(!config.captures_tcp_destination(virtual_dns, Some(853)));
        assert!(!NativeCoreCaptureConfig::default()
            .dns_hijack
            .captures_tcp_destination(virtual_dns, Some(53)));
    }

    #[test]
    fn fake_ip_capture_address_validation_rejects_allocated_v4_and_projected_v6() {
        let mut profile = crate::RuntimeProfile::new("capture-address-validation");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        assert!(validate_fake_ip_capture_addresses(
            &profile.dns,
            [
                "198.18.0.1".parse().unwrap(),
                "10.255.255.1".parse().unwrap(),
                "fd00:6572:6769:6f00::2".parse().unwrap()
            ]
        )
        .is_ok());
        for address in ["198.18.0.2", "fd11:5ca1:ab1e:1::c612:2"] {
            let error =
                validate_fake_ip_capture_addresses(&profile.dns, [address.parse().unwrap()])
                    .unwrap_err();
            assert!(error.contains(address));
        }
        // A DNS address reserved in the default pool may be allocatable
        // under a larger custom pool whose gateway is elsewhere.
        profile.dns.fake_ip_range = "198.16.0.0/14".parse().unwrap();
        assert!(
            validate_fake_ip_capture_addresses(&profile.dns, ["198.18.0.1".parse().unwrap()])
                .is_err()
        );
        profile.dns.fake_ip_range = "10.0.0.0/8".parse().unwrap();
        assert!(validate_fake_ip_capture_addresses(
            &profile.dns,
            ["10.255.255.1".parse().unwrap()]
        )
        .is_err());
        // Global mode hands out fake IPs in every DNS mode, so the pool is
        // checked whatever the mode.
        for (enabled, mode) in [
            (false, crate::dns::config::DnsMode::FakeIp),
            (true, crate::dns::config::DnsMode::RedirHost),
        ] {
            profile.dns.enabled = enabled;
            profile.dns.enhanced_mode = mode;
            assert!(validate_fake_ip_capture_addresses(
                &profile.dns,
                ["10.255.255.1".parse().unwrap()]
            )
            .is_err());
        }
    }
}
