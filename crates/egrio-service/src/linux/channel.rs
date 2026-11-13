//! The desktop end of the Linux packet channel: attaches queues to the
//! persistent multi-queue TUN the service created owned by this user, and
//! hands Core egress the physical resolvers the service read before the TUN
//! took over DNS.

use egrio_core::PacketDevice;
use egrio_platform_linux::LinuxTunDevice;

use crate::protocol::PacketChannel;
use crate::remote::ServicePlatform;

impl ServicePlatform {
    pub(crate) fn attach_packet_channel(
        &self,
        channel: PacketChannel,
        queues: usize,
    ) -> Result<Vec<Box<dyn PacketDevice>>, String> {
        let PacketChannel::OwnedTun(tun) = channel else {
            return Err("the Linux service answered with another platform's packet channel".into());
        };
        let devices = LinuxTunDevice::attach(&tun.interface_name, queues)?;
        let ipv6 = egrio_platform_linux::linux_interface_carries_ipv6(&tun.interface_name);
        self.tun_egress().activate(tun.physical_dns_servers, ipv6);
        Ok(devices
            .into_iter()
            .map(|device| Box::new(device) as Box<dyn PacketDevice>)
            .collect())
    }

    pub(crate) fn tun_queue_limit(&self) -> usize {
        egrio_platform_linux::LINUX_TUN_MAX_QUEUES
    }

    pub(crate) fn tun_reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        egrio_platform_linux::linux_tun_reserved_addresses()
    }
}
