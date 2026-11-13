//! The desktop's end of the tunnel: the Core's packet device on the utun
//! socket the service handed over. The socket registers with the reactor of
//! the runtime that first uses it, the pump's.

use std::os::fd::OwnedFd;

use egrio_core::{PacketDevice, PacketInterest, PacketReady, PacketSend};

use super::utun_io::UtunIo;

const MAX_PACKET_BYTES: usize = 65_535;
/// Room for the largest packet behind the longest utun header.
const READ_BUFFER: usize = MAX_PACKET_BYTES + 32;

#[derive(Debug)]
enum Io {
    Unregistered(Option<OwnedFd>),
    Registered(UtunIo),
}

#[derive(Debug)]
pub struct MacosTunDevice {
    io: Io,
    incoming: Box<[u8]>,
}

impl MacosTunDevice {
    /// Takes over a utun socket.
    pub fn adopt(socket: OwnedFd) -> Self {
        Self {
            io: Io::Unregistered(Some(socket)),
            incoming: vec![0; READ_BUFFER].into_boxed_slice(),
        }
    }

    fn utun(&mut self) -> Result<&mut UtunIo, String> {
        if let Io::Unregistered(socket) = &mut self.io {
            let socket = socket.take().ok_or("the utun socket is gone")?;
            self.io = Io::Registered(UtunIo::adopt(socket)?);
        }
        match &mut self.io {
            Io::Registered(utun) => Ok(utun),
            Io::Unregistered(_) => unreachable!("registered above"),
        }
    }
}

impl PacketDevice for MacosTunDevice {
    fn name(&self) -> &str {
        "macos-utun"
    }

    fn try_recv(&mut self) -> Result<Option<egrio_core::ReceivedPacket>, String> {
        self.utun()?;
        let Io::Registered(utun) = &self.io else {
            unreachable!("registered above");
        };
        let packet = utun.try_recv(&mut self.incoming)?;
        if let Some(packet) = &packet {
            if !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) {
                return Err("the utun delivered a packet that is neither IPv4 nor IPv6".into());
            }
        }
        Ok(packet.map(Into::into))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        self.try_send_parts(&[packet])
    }

    fn try_send_parts(&mut self, parts: &[&[u8]]) -> Result<PacketSend, String> {
        let length: usize = parts.iter().map(|part| part.len()).sum();
        let version = parts
            .iter()
            .find_map(|part| part.first())
            .map_or(0, |byte| byte >> 4);
        if length == 0 || length > MAX_PACKET_BYTES || !matches!(version, 4 | 6) {
            return Err("utun packet is not a bounded IPv4/IPv6 packet".into());
        }
        self.utun()?.try_send_parts(parts)
    }

    fn ready(&mut self, interest: PacketInterest) -> PacketReady<'_> {
        Box::pin(async move {
            let utun = self.utun()?;
            tokio::select! {
                ready = utun.readable(), if interest.read => ready,
                () = utun.writable(), if interest.write => Ok(()),
                else => std::future::pending().await,
            }
        })
    }
}
