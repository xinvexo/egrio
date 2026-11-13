use super::*;
use crate::packet::{
    frame::{build_udp_packet, ipv6_transport_checksum},
    reassembly::PacketReassembler,
};

fn packet(v6: bool, payload: usize) -> Vec<u8> {
    let (source, destination) = if v6 {
        ("fd11:5ca1:ab1e:1::23", "fd00:23::2")
    } else {
        ("198.18.1.23", "10.23.0.2")
    };
    build_udp_packet(
        source.parse().unwrap(),
        destination.parse().unwrap(),
        443,
        54321,
        &(0..payload).map(|n| (n * 17) as u8).collect::<Vec<_>>(),
    )
    .unwrap()
}
fn header(packet: &[u8]) -> usize {
    if packet[0] >> 4 == 4 {
        20
    } else {
        40
    }
}

fn roundtrip(original: Vec<u8>, mtu: u32) {
    let packets = packetize_local_udp(original.clone(), mtu).unwrap();
    assert!(packets.len() > 1 && packets.len() <= MAX_FRAGMENTS);
    let mut id = None;
    let mut offset = 0;
    for (index, packet) in packets.iter().enumerate() {
        let bytes = packet;
        assert!(bytes.len() <= mtu as usize && bytes.len() <= 65535);
        let (current, actual_offset, more, payload) = if bytes[0] >> 4 == 4 {
            assert_eq!(ipv4_header_checksum(&bytes[..20]), 0);
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
                bytes.len()
            );
            assert_eq!(&bytes[12..20], &original[12..20]);
            let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
            (
                u32::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                usize::from(flags & 0x1fff) * 8,
                flags & 0x2000 != 0,
                &bytes[20..],
            )
        } else {
            assert_eq!(bytes[6], 44);
            assert_eq!(&bytes[8..40], &original[8..40]);
            assert_eq!(bytes[40], 17);
            assert_eq!(bytes[41], 0);
            assert_eq!(
                u16::from_be_bytes([bytes[4], bytes[5]]) as usize,
                bytes.len() - 40
            );
            let flags = u16::from_be_bytes([bytes[42], bytes[43]]);
            assert_eq!(flags & 6, 0);
            (
                u32::from_be_bytes(bytes[44..48].try_into().unwrap()),
                usize::from(flags & 0xfff8),
                flags & 1 != 0,
                &bytes[48..],
            )
        };
        assert_eq!(actual_offset, offset);
        assert_eq!(more, index + 1 < packets.len());
        if more {
            assert_eq!(payload.len() % 8, 0);
        }
        if index == 0 {
            assert_eq!(
                &payload[..8],
                &original[header(&original)..header(&original) + 8]
            );
        }
        if let Some(expected) = id {
            assert_eq!(current, expected);
        } else {
            id = Some(current);
        }
        offset += payload.len();
    }
    let mut reassembly = PacketReassembler::default();
    let mut completed = None;
    for packet in packets.into_iter().rev() {
        if let Some(packet) = reassembly.push(packet).unwrap() {
            assert!(completed.replace(packet).is_none());
        }
    }
    let completed = completed.expect("all source fragments rebuild one datagram");
    assert_eq!(
        &completed[header(&completed)..],
        &original[header(&original)..]
    );
    if completed[0] >> 4 == 6 {
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&completed[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&completed[24..40]).unwrap());
        assert_eq!(
            ipv6_transport_checksum(source, destination, 17, &completed[40..]),
            0
        );
    }
}

#[test]
fn mtu_boundaries_and_odd_tail_lengths_roundtrip_for_both_families() {
    for mtu in [1280, 1420, 1500, 65535] {
        for v6 in [false, true] {
            let overhead = if v6 { 48 } else { 28 };
            let size = mtu as usize - overhead;
            let original = packet(v6, size);
            let output = packetize_local_udp(original.clone(), mtu).unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].len(), mtu as usize);
            if v6 {
                assert_eq!(output[0], original);
            } else {
                assert_eq!(u16::from_be_bytes([output[0][6], output[0][7]]), 0x4000);
                assert_eq!(ipv4_header_checksum(&output[0][..20]), 0);
            }
            // At the maximum IPv4 size there is no legal one-byte oversize.
            if v6 || mtu < 65535 {
                roundtrip(packet(v6, size + 1), mtu);
            }
        }
    }
    for v6 in [false, true] {
        roundtrip(packet(v6, 8193), 1420);
    }
}

#[test]
fn maximum_legal_udp_packets_fit_the_device_frame_budget_after_packetization() {
    for mtu in [1280, 1420, 1500, 65535] {
        let v4 = packet(false, 65507);
        if mtu < 65535 {
            roundtrip(v4, mtu);
        } else {
            assert_eq!(packetize_local_udp(v4, mtu).unwrap().len(), 1);
        }
        let v6 = packet(true, 65527);
        assert_eq!(v6.len(), 65575);
        roundtrip(v6, mtu);
    }
}

#[test]
fn dont_fragment_is_never_cleared_to_force_an_oversize_packet_through() {
    let mut original = packet(false, 4096);
    original[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    original[10..12].fill(0);
    let checksum = ipv4_header_checksum(&original[..20]);
    original[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert!(packetize_local_udp(original, 1500)
        .unwrap_err()
        .contains("DF forbids"));
}

#[test]
fn local_udp_shape_and_length_checks_reject_routers_fragments_and_malformed_packets() {
    for mtu in [0, 1279, 65536] {
        assert!(packetize_local_udp(packet(false, 4), mtu).is_err());
    }
    let mut oversized = packet(false, 4);
    oversized.resize(65536, 0);
    assert!(packetize_local_udp(oversized, 1500).is_err());
    let mut oversized = packet(true, 4);
    oversized.resize(65576, 0);
    assert!(packetize_local_udp(oversized, 1500).is_err());
    let mut bad = packet(false, 4);
    bad[20 + 4..20 + 6].copy_from_slice(&8_u16.to_be_bytes());
    assert!(packetize_local_udp(bad, 1500).is_err());
    let mut bad = packet(false, 4);
    bad[9] = 6;
    assert!(packetize_local_udp(bad, 1500).is_err());
    let mut bad = packet(false, 4);
    bad[0] = 0x46;
    assert!(packetize_local_udp(bad, 1500).is_err());
    let mut bad = packet(false, 4);
    bad[10] ^= 1;
    assert!(packetize_local_udp(bad, 1500).is_err());
    let mut bad = packet(true, 4);
    bad[6] = 44;
    assert!(packetize_local_udp(bad, 1500).is_err());
    let mut bad = packet(true, 4);
    bad[4..6].copy_from_slice(&9_u16.to_be_bytes());
    assert!(packetize_local_udp(bad, 1500).is_err());
}

#[test]
fn separate_calls_for_the_same_tuple_do_not_restart_fragment_ids() {
    for v6 in [false, true] {
        let first = packetize_local_udp(packet(v6, 4096), 1500).unwrap();
        let second = packetize_local_udp(packet(v6, 4096), 1500).unwrap();
        if v6 {
            assert_ne!(&first[0][44..48], &second[0][44..48]);
        } else {
            assert_ne!(&first[0][4..6], &second[0][4..6]);
        }
    }
}
