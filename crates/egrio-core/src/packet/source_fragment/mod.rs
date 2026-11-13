//! Source fragmentation of Core-generated UDP/DNS replies, before device
//! writeback. This is not an IPv6 router fragmentation facility. Current
//! producers emit plain IPv4/IPv6 headers with UDP directly following them;
//! options, extension chains and pre-existing fragments are rejected here.
//!
//! Basis: RFC 791 sections 3.1/3.2, RFC 6864 sections 4/5, RFC 8200 section
//! 4.5, RFC 7112 section 5, and RFC 6946. Small IPv6 packets have no Fragment
//! header. The first IPv6 fragment includes the complete UDP header.
mod identifiers;

use super::frame::ipv4_header_checksum;
use crate::NativeCoreCaptureConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_FRAGMENTS: usize = 64;

pub(crate) fn packetize_local_udp(mut packet: Vec<u8>, mtu: u32) -> Result<Vec<Vec<u8>>, String> {
    NativeCoreCaptureConfig::validate_mtu(mtu)?;
    let mtu = mtu as usize;
    let bytes = &packet;
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => {
            if bytes.len() < 28 || bytes.len() > 65535 || bytes[0] != 0x45 || bytes[9] != 17 {
                return Err("local IPv4 UDP output requires a plain IPv4 header and a complete UDP datagram".into());
            }
            if usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len()
                || ipv4_header_checksum(&bytes[..20]) != 0
            {
                return Err("local IPv4 UDP output length/header checksum is invalid".into());
            }
            let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
            if flags & 0xbfff != 0 {
                return Err("local IPv4 UDP source output cannot already be fragmented or use a reserved flag".into());
            }
            validate_udp(&bytes[20..])?;
            if bytes.len() <= mtu {
                // Locally generated, unfragmented datagrams are atomic. This
                // avoids reusing an ID on non-atomic DF=0 small packets and
                // leaves the 16-bit namespace for actual fragmentation.
                packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
                packet[10..12].fill(0);
                let checksum = ipv4_header_checksum(&packet[..20]);
                packet[10..12].copy_from_slice(&checksum.to_be_bytes());
                return Ok(vec![packet]);
            }
            if flags & 0x4000 != 0 {
                return Err(format!("local IPv4 UDP packet is {} bytes, exceeds MTU {mtu}, and DF forbids fragmentation",bytes.len()));
            }
            let source = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap()));
            let destination =
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap()));
            fragment(packet, mtu, 20, 20, identifiers::next(source, destination))
        }
        Some(6) => {
            if bytes.len() < 48
                || bytes.len() > 65575
                || bytes[6] != 17
                || usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) + 40 != bytes.len()
            {
                return Err("local IPv6 UDP output requires a plain IPv6 header and a non-jumbo complete UDP datagram".into());
            }
            validate_udp(&bytes[40..])?;
            if bytes.len() <= mtu {
                return Ok(vec![packet]);
            }
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap()));
            let destination = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[24..40]).unwrap(),
            ));
            fragment(packet, mtu, 40, 48, identifiers::next(source, destination))
        }
        _ => Err("local UDP output has no supported IP header".into()),
    }
}

fn validate_udp(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 8
        || bytes.len() > 65535
        || usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) != bytes.len()
    {
        return Err("local UDP output length is invalid".into());
    }
    Ok(())
}

fn fragment(
    packet: Vec<u8>,
    mtu: usize,
    original_header: usize,
    fragment_header: usize,
    id: u32,
) -> Result<Vec<Vec<u8>>, String> {
    let fragment_bytes = (mtu - fragment_header) / 8 * 8;
    let data = &packet[original_header..];
    let count = data.len().div_ceil(fragment_bytes);
    if fragment_bytes < 8 || count > MAX_FRAGMENTS {
        return Err("local UDP fragmentation exceeds fragment/header budget".into());
    }
    let mut output = Vec::with_capacity(count);
    for (index, chunk) in data.chunks(fragment_bytes).enumerate() {
        let offset = index * fragment_bytes;
        let more = index + 1 < count;
        let mut bytes = packet[..original_header].to_vec();
        if original_header == 20 {
            bytes[2..4].copy_from_slice(&((20 + chunk.len()) as u16).to_be_bytes());
            bytes[4..6].copy_from_slice(&(id as u16).to_be_bytes());
            bytes[6..8].copy_from_slice(
                &((offset / 8) as u16 | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            bytes[10..12].fill(0);
            let checksum = ipv4_header_checksum(&bytes);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        } else {
            bytes[4..6].copy_from_slice(&((8 + chunk.len()) as u16).to_be_bytes());
            bytes[6] = 44;
            bytes.extend_from_slice(&[17, 0]);
            bytes.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
            bytes.extend_from_slice(&id.to_be_bytes());
        }
        bytes.extend_from_slice(chunk);
        debug_assert!(bytes.len() <= mtu);
        output.push(bytes);
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
