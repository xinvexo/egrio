//! TUN mode on macOS: a utun the privileged service creates for the desktop
//! session, routes that send both halves of each family's address space into
//! it, and its virtual resolver as the system's default; the Core reads and
//! writes its packets. The physical network service stays primary.
//!
//! The service side (`interface`, `routes`, `resolver`, `session`) runs as
//! root and owns every system change; the desktop side (`device`) only moves
//! packets on the utun socket the service handed over. The constants here
//! are the one source of the tunnel's addresses for both.

#[cfg(target_os = "macos")]
mod device;
#[cfg(target_os = "macos")]
mod interface;
#[cfg(target_os = "macos")]
mod resolver;
#[cfg(target_os = "macos")]
mod route_socket;
#[cfg(target_os = "macos")]
mod routes;
#[cfg(target_os = "macos")]
mod session;
#[cfg(target_os = "macos")]
mod utun_io;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
pub use device::MacosTunDevice;
#[cfg(target_os = "macos")]
pub use session::{MacosTunOpen, MacosTunSession};

/// The utun's own addresses and the virtual resolver the tunnel publishes.
/// The Core answers DNS sent to the resolver, and the fake-IP pool avoids
/// them all.
pub const MACOS_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
/// The utun's point-to-point peer.
pub const MACOS_TUN_IPV4_PEER: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 2);
pub const MACOS_TUN_IPV4_PREFIX: u8 = 30;
pub const MACOS_TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x6572, 0x6769, 0x6f00, 0, 0, 0, 2);
pub const MACOS_TUN_IPV6_PREFIX: u8 = 64;
pub const MACOS_TUN_VIRTUAL_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The utun's MTU. A utun the service creates takes any MTU up to the
/// interface limit of 65535 (XNU if_utun.c `SIOCSIFMTU` checks only a
/// channel's slot size, and the service opens no channel), so a TCP segment
/// of a flow through the tunnel carries up to 64 KiB, as through the Linux
/// TUN with segmentation offload.
pub const MACOS_TUN_MTU: u32 = 65535;

/// Core's capture configuration for the tunnel: every UDP/53 query is
/// answered, TCP/53 only at the virtual resolver, and nothing addressed into
/// the tunnel's own subnets is relayed.
pub fn macos_tun_core_capture_config() -> egrio_core::NativeCoreCaptureConfig {
    egrio_core::NativeCoreCaptureConfig::with_dns_hijack(
        egrio_core::NativeCoreDnsHijackConfig::capture_udp_port_with_virtual_tcp_targets(
            53,
            [IpAddr::V4(MACOS_TUN_VIRTUAL_DNS)],
        ),
    )
    .with_interface_networks([
        egrio_core::NativeCoreInterfaceNetwork::new(MACOS_TUN_IPV4, MACOS_TUN_IPV4_PREFIX),
        egrio_core::NativeCoreInterfaceNetwork::new(MACOS_TUN_IPV6, MACOS_TUN_IPV6_PREFIX),
    ])
}

/// The addresses the tunnel occupies, which the running Core's fake-IP pool
/// must not hand out.
pub fn macos_tun_reserved_addresses() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(MACOS_TUN_IPV4),
        IpAddr::V4(MACOS_TUN_IPV4_PEER),
        IpAddr::V4(MACOS_TUN_VIRTUAL_DNS),
        IpAddr::V6(MACOS_TUN_IPV6),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capture_config_reserves_the_tunnel_subnets_and_resolver() {
        let reserved = macos_tun_reserved_addresses();
        assert!(reserved.contains(&IpAddr::V4(MACOS_TUN_VIRTUAL_DNS)));
        assert!(reserved.contains(&IpAddr::V6(MACOS_TUN_IPV6)));
    }
}
