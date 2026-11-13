//! The desktop end of the macOS packet channel: binds Core egress to the
//! physical uplink before the tunnel's routes exist and adopts the utun
//! descriptor that rode the channel response.

use egrio_core::PacketDevice;
use egrio_platform_macos::MacosTunDevice;

use crate::protocol::PacketChannel;
use crate::remote::ServicePlatform;

impl ServicePlatform {
    /// Binds the Core's sockets to the physical uplink, with the resolvers
    /// of the physical network read before the tunnel's take over, before
    /// the service publishes the tunnel's routes.
    pub(crate) fn bind_egress_before_open(&self) -> Result<(), String> {
        let snapshot = egrio_platform_macos::capture_macos_system_dns_snapshot()?;
        self.tun_egress()
            .activate(egrio_core::CaptureEgressOverlay {
                dns_servers: snapshot.servers,
                ipv6_enabled: true,
            });
        Ok(())
    }

    /// The utun's one descriptor, whatever `queues` asks.
    pub(crate) fn attach_packet_channel(
        &self,
        channel: PacketChannel,
        _queues: usize,
    ) -> Result<Vec<Box<dyn PacketDevice>>, String> {
        let PacketChannel::Utun(_) = channel else {
            return Err("the macOS service answered with another platform's packet channel".into());
        };
        let socket = self
            .client()
            .take_descriptor()
            .ok_or("the macOS service sent no utun descriptor")?;
        Ok(vec![Box::new(MacosTunDevice::adopt(socket))])
    }

    /// A utun reads through one descriptor.
    pub(crate) fn tun_queue_limit(&self) -> usize {
        1
    }

    pub(crate) fn tun_reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        egrio_platform_macos::macos_tun_reserved_addresses()
    }
}
