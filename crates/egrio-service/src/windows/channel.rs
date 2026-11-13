//! The desktop end of the Windows packet channel: maps the shared rings the
//! service duplicated into this process and binds Core egress away from the
//! service-held adapter, which the desktop never opens itself.

use egrio_core::PacketDevice;

use crate::protocol::PacketChannel;
use crate::remote::ServicePlatform;
use crate::shared_memory::{CHANNEL_ABI_MAJOR, CHANNEL_ABI_MINOR};

use super::handles::DuplicatedPacketHandles;
use super::packet::RemoteWindowsPacketDevice;

impl ServicePlatform {
    /// The adapter's one pair of rings, whatever `queues` asks.
    pub(crate) fn attach_packet_channel(
        &self,
        channel: PacketChannel,
        _queues: usize,
    ) -> Result<Vec<Box<dyn PacketDevice>>, String> {
        let PacketChannel::SharedRing(handles) = channel else {
            return Err(
                "the Windows service answered with another platform's packet channel".into(),
            );
        };
        let session_id = self
            .client()
            .session_id()
            .ok_or("control session disappeared after packet channel open")?;
        let device = RemoteWindowsPacketDevice::open(
            session_id.to_string(),
            DuplicatedPacketHandles {
                channel_id: handles.channel_id,
                mapping: handles.mapping,
                rx_data_available: handles.rx_data_available,
                rx_space_available: handles.rx_space_available,
                tx_data_available: handles.tx_data_available,
                tx_space_available: handles.tx_space_available,
                mapping_len: handles.mapping_len,
            },
        )?;
        if handles.abi_major != CHANNEL_ABI_MAJOR || handles.abi_minor > CHANNEL_ABI_MINOR {
            return Err("packet channel ABI is incompatible".into());
        }
        self.tun_egress().activate(handles.interface_index)?;
        Ok(vec![Box::new(device)])
    }

    /// Wintun reads through one ring.
    pub(crate) fn tun_queue_limit(&self) -> usize {
        1
    }

    pub(crate) fn tun_reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        self.tun_egress().reserved_addresses()
    }
}
