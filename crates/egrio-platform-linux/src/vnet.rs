//! The virtio-net header in front of every packet of a TUN opened with
//! `IFF_VNET_HDR` (`include/uapi/linux/virtio_net.h`, `struct
//! virtio_net_hdr`; `drivers/net/tun.c` writes it with
//! `virtio_net_hdr_from_skb` and reads it with `virtio_net_hdr_to_skb`,
//! `include/linux/virtio_net.h`). The offloads the TUN takes
//! (`TUNSETOFFLOAD`) decide what it may carry:
//!
//! - from the kernel, TCP segments larger than the MTU (`GSO_TCPV4/6`), UDP
//!   datagrams of one socket's send glued together (`GSO_UDP_L4`), and
//!   checksums left partial (`NEEDS_CSUM`: the field holds the pseudo-header
//!   sum). The Core reads TCP and UDP without checking their checksums, so a
//!   TCP segment of any size passes as it is and a glued UDP frame goes to it
//!   as one train, which a learned flow sends on whole;
//! - to the kernel, TCP segments whose checksum the kernel completes or,
//!   delivering locally, takes as verified (`CHECKSUM_PARTIAL`), and trains
//!   of UDP datagrams to one client that the kernel cuts apart
//!   (`GSO_UDP_L4`).
//!
//! The header's fields are little-endian: `TUNSETVNETLE` is not used, and the
//! kernel writes the legacy header in the host's byte order
//! (`tun_is_little_endian`), so this module is for little-endian hosts.

/// Bytes of `struct virtio_net_hdr`, the size the TUN uses unless told
/// otherwise (`TUNSETVNETHDRSZ`).
pub(crate) const VNET_HDR_LEN: usize = 10;

use egrio_core::ReceivedPacket;

const F_NEEDS_CSUM: u8 = 1;
const GSO_NONE: u8 = 0;
const GSO_TCPV4: u8 = 1;
const GSO_TCPV6: u8 = 4;
const GSO_UDP_L4: u8 = 5;
const GSO_ECN: u8 = 0x80;

/// The header of a packet that needs nothing done.
pub(crate) const PLAIN: [u8; VNET_HDR_LEN] = [0; VNET_HDR_LEN];

/// The header of a TCP segment whose checksum field holds the pseudo-header
/// sum: the sum starts at the TCP header, behind the IP header of
/// `ip_header_len` bytes, and goes 16 bytes into it (RFC 9293 section 3.1).
pub(crate) fn tcp_partial_checksum(ip_header_len: usize) -> [u8; VNET_HDR_LEN] {
    let mut header = PLAIN;
    header[0] = F_NEEDS_CSUM;
    header[6..8].copy_from_slice(&(ip_header_len as u16).to_le_bytes());
    header[8..10].copy_from_slice(&16_u16.to_le_bytes());
    header
}

/// The header of a train of UDP datagrams the kernel cuts into ones of
/// `segment` payload bytes, the last one shorter (`GSO_UDP_L4`): behind the IP
/// header of `ip_header_len` bytes and the UDP header, whose lengths cover
/// the whole train, and each datagram's checksum starts at its UDP header and
/// goes 6 bytes into it, the field holding the pseudo-header sum (RFC 768).
pub(crate) fn udp_train(ip_header_len: usize, segment: usize) -> [u8; VNET_HDR_LEN] {
    let mut header = PLAIN;
    header[0] = F_NEEDS_CSUM;
    header[1] = GSO_UDP_L4;
    header[2..4].copy_from_slice(&((ip_header_len + 8) as u16).to_le_bytes());
    header[4..6].copy_from_slice(&(segment as u16).to_le_bytes());
    header[6..8].copy_from_slice(&(ip_header_len as u16).to_le_bytes());
    header[8..10].copy_from_slice(&6_u16.to_le_bytes());
    header
}

/// The IP packet in one frame read from the TUN, with the segment size of a
/// glued UDP frame (`GSO_UDP_L4`), whose datagrams the Core takes as a train.
/// A frame this module cannot read is refused.
pub(crate) fn unpack(frame: &[u8]) -> Result<ReceivedPacket, String> {
    let Some((header, packet)) = frame.split_first_chunk::<VNET_HDR_LEN>() else {
        return Err(format!(
            "TUN frame of {} bytes has no virtio-net header",
            frame.len()
        ));
    };
    let gso_size = usize::from(u16::from_le_bytes([header[4], header[5]]));
    match header[1] & !GSO_ECN {
        GSO_NONE | GSO_TCPV4 | GSO_TCPV6 => Ok(packet.to_vec().into()),
        GSO_UDP_L4 if gso_size > 0 => Ok(ReceivedPacket {
            bytes: packet.to_vec(),
            udp_segment: Some(gso_size),
        }),
        GSO_UDP_L4 => Err("TUN UDP GSO frame without a segment size".into()),
        other => Err(format!("TUN frame with GSO type {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(header: [u8; VNET_HDR_LEN], packet: &[u8]) -> Vec<u8> {
        let mut frame = header.to_vec();
        frame.extend_from_slice(packet);
        frame
    }

    fn header(flags: u8, gso_type: u8, gso_size: u16) -> [u8; VNET_HDR_LEN] {
        let mut header = PLAIN;
        header[0] = flags;
        header[1] = gso_type;
        header[4..6].copy_from_slice(&gso_size.to_le_bytes());
        header
    }

    /// An IPv4 UDP packet from 10.0.0.2:5000 to 1.1.1.1:443 with `payload`.
    fn udp4(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1, 0x13, 0x88,
            0x01, 0xbb, 0, 0, 0xab, 0xcd,
        ];
        packet.extend_from_slice(payload);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[24..26].copy_from_slice(&(total - 20).to_be_bytes());
        packet
    }

    #[test]
    fn a_plain_or_tcp_gso_frame_is_its_packet() {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        for gso_type in [GSO_NONE, GSO_TCPV4, GSO_TCPV4 | GSO_ECN, GSO_TCPV6] {
            let frame = frame(header(F_NEEDS_CSUM, gso_type, 1448), &packet);
            assert_eq!(
                unpack(&frame).unwrap(),
                ReceivedPacket::from(packet.to_vec())
            );
        }
    }

    #[test]
    fn a_udp_gso_frame_is_one_train() {
        let packet = udp4(&[7; 2500]);
        let received = unpack(&frame(header(F_NEEDS_CSUM, GSO_UDP_L4, 1200), &packet)).unwrap();
        assert_eq!(received.bytes, packet);
        assert_eq!(received.udp_segment, Some(1200));
    }

    #[test]
    fn unreadable_frames_are_refused() {
        assert!(unpack(&[0; 4]).is_err(), "no header");
        let udp = udp4(&[1; 100]);
        assert!(unpack(&frame(header(0, 3, 50), &udp)).is_err(), "UFO");
        assert!(unpack(&frame(header(0, GSO_UDP_L4, 0), &udp)).is_err());
    }

    #[test]
    fn a_udp_train_header_asks_for_segments_and_their_checksums() {
        assert_eq!(udp_train(20, 1200), [1, 5, 28, 0, 0xb0, 4, 20, 0, 6, 0]);
        assert_eq!(udp_train(40, 1232), [1, 5, 48, 0, 0xd0, 4, 40, 0, 6, 0]);
    }

    #[test]
    fn a_tcp_segment_header_points_at_the_tcp_checksum() {
        assert_eq!(tcp_partial_checksum(20), [1, 0, 0, 0, 0, 0, 20, 0, 16, 0]);
        assert_eq!(tcp_partial_checksum(40), [1, 0, 0, 0, 0, 0, 40, 0, 16, 0]);
    }
}
