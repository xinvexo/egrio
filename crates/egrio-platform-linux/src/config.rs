use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The TUN's own addresses and the virtual resolver it advertises. Core
/// answers DNS sent to the resolver; the fake-IP pool must avoid all three.
pub(crate) const LINUX_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub(crate) const LINUX_TUN_IPV4_PREFIX: u8 = 30;
pub(crate) const LINUX_TUN_IPV6: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x6572, 0x6769, 0x6f00, 0, 0, 0, 2);
pub(crate) const LINUX_TUN_IPV6_PREFIX: u8 = 64;
pub(crate) const LINUX_TUN_VIRTUAL_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The TUN's IP MTU: the largest the tun driver accepts, `MAX_MTU` (65535)
/// less its absent link-layer header (drivers/net/tun.c,
/// `tun_net_initialize`). Captured clients size their TCP segments from it,
/// so a bulk transfer crosses the device in 64 KiB packets.
const LINUX_TUN_MTU: u32 = 65535;
/// Packets the kernel holds for the Core to read. The tun driver queues what
/// the system routes into the device on a ring of `tx_queue_len` entries and
/// drops what no longer fits (drivers/net/tun.c `tun_net_xmit`,
/// `SKB_DROP_REASON_FULL_RING`); the default is `TUN_READQ_SIZE`, 500
/// (include/uapi/linux/if_tun.h). A burst of new flows waits on the packet
/// pump's admission of each; a larger queue absorbs those bursts while
/// keeping the kernel backlog bounded.
pub(crate) const LINUX_TUN_TX_QUEUE_LEN: u32 = 4096;

/// The addresses the TUN claims for itself, which a fake-IP pool must avoid.
pub fn linux_tun_reserved_addresses() -> Vec<IpAddr> {
    vec![
        LINUX_TUN_IPV4.into(),
        LINUX_TUN_VIRTUAL_DNS.into(),
        LINUX_TUN_IPV6.into(),
    ]
}

/// Core's capture configuration for this TUN: its MTU, every UDP/53 query
/// answered, TCP/53 only at the virtual resolver, and nothing addressed into
/// the TUN's own subnets relayed.
pub fn linux_tun_core_capture_config() -> egrio_core::NativeCoreCaptureConfig {
    egrio_core::NativeCoreCaptureConfig::with_dns_hijack(
        egrio_core::NativeCoreDnsHijackConfig::capture_udp_port_with_virtual_tcp_targets(
            53,
            [IpAddr::V4(LINUX_TUN_VIRTUAL_DNS)],
        ),
    )
    .with_interface_networks([
        egrio_core::NativeCoreInterfaceNetwork::new(LINUX_TUN_IPV4, LINUX_TUN_IPV4_PREFIX),
        egrio_core::NativeCoreInterfaceNetwork::new(LINUX_TUN_IPV6, LINUX_TUN_IPV6_PREFIX),
    ])
    .with_mtu(LINUX_TUN_MTU)
    .expect("the TUN MTU is a valid capture MTU")
}

/// All resources are private to one non-persistent TUN session. Existing
/// interfaces, routing tables, rule priorities and nftables names are rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxTunConfig {
    pub interface_name: String,
    pub mtu: u32,
    pub fwmark: u32,
    pub routing_table: u32,
    pub rule_priority: u32,
    pub capture_dns: bool,
    pub kill_switch: bool,
    pub allow_lan: bool,
}

impl Default for LinuxTunConfig {
    fn default() -> Self {
        Self {
            interface_name: "egrio0".into(),
            mtu: LINUX_TUN_MTU,
            fwmark: 0xe671,
            routing_table: 20220,
            rule_priority: 20220,
            capture_dns: true,
            kill_switch: true,
            allow_lan: true,
        }
    }
}

impl LinuxTunConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.interface_name.is_empty()
            || self.interface_name.len() >= 16
            || !self
                .interface_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(
                "Linux TUN interface name must contain 1..15 ASCII letters, digits or underscores"
                    .into(),
            );
        }
        if !(1280..=65535).contains(&self.mtu) {
            return Err("Linux TUN MTU must be 1280..65535 for dual-stack packets".into());
        }
        if self.fwmark == 0
            || !(1..=0xffff_fffe).contains(&self.routing_table)
            || matches!(self.routing_table, 253..=255)
            || !(2..32766).contains(&self.rule_priority)
        {
            return Err("Linux TUN requires a nonzero egress mark, private routing table and rule priority before main".into());
        }
        Ok(())
    }

    /// The kill switch's nftables table.
    pub(crate) fn nft_table(&self) -> String {
        format!("egrio_{}", self.interface_name)
    }
    /// The routing's nftables table, which marks replies to inbound
    /// connections.
    pub(crate) fn nft_reply_table(&self) -> String {
        format!("egrio_{}_replies", self.interface_name)
    }
    pub(crate) fn mark(&self) -> String {
        format!("0x{:x}", self.fwmark)
    }
}

/// Reject a custom fake-IP pool that can allocate addresses reserved by the
/// OS capture interface or its virtual resolver, before network mutation.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_shell_syntax_and_reserved_kernel_resources() {
        let mut config = LinuxTunConfig::default();
        assert!(config.validate().is_ok());
        for name in ["", "lo;echo", "tun space", "0123456789012345"] {
            config.interface_name = name.into();
            assert!(config.validate().is_err());
        }
        config = LinuxTunConfig::default();
        config.routing_table = 254;
        assert!(config.validate().is_err());
    }
}
