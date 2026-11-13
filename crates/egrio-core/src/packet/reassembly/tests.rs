use super::*;
use crate::packet::frame::{build_udp_packet, parse_packet_flow, parse_udp_datagram};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(id: u16, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
    v4_options(id, offset, more, data, &[])
}
fn v4_options(id: u16, offset: usize, more: bool, data: &[u8], options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let ihl = 20 + options.len();
    let mut bytes = vec![0u8; ihl];
    bytes[0] = 0x40 | (ihl / 4) as u8;
    bytes[2..4].copy_from_slice(&((ihl + data.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8]
        .copy_from_slice(&((offset as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 2]);
    bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
    bytes[20..].copy_from_slice(options);
    bytes.extend_from_slice(data);
    checksum(&mut bytes);
    bytes
}
fn checksum(bytes: &mut [u8]) {
    bytes[10..12].fill(0);
    let ihl = usize::from(bytes[0] & 15) * 4;
    let value = ipv4_header_checksum(&bytes[..ihl]);
    bytes[10..12].copy_from_slice(&value.to_be_bytes());
}
fn udp_v4_data() -> Vec<u8> {
    build_udp_packet(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        53123,
        53,
        b"abcdefghijklmnopqrstuvwxy",
    )
    .unwrap()[20..]
        .to_vec()
}
fn udp_v6_data() -> Vec<u8> {
    build_udp_packet(
        IpAddr::V6("fd00::2".parse().unwrap()),
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        53123,
        53,
        b"abcdefghijklmnopqrstuvwxy",
    )
    .unwrap()[40..]
        .to_vec()
}
fn v6(id: u32, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
    v6_ext(id, offset, more, data, &[], 17)
}
fn v6_ext(id: u32, offset: usize, more: bool, data: &[u8], before: &[u8], next: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&((before.len() + 8 + data.len()) as u16).to_be_bytes());
    bytes[6] = if before.is_empty() { 44 } else { 0 };
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
    bytes[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    bytes.extend_from_slice(before);
    bytes.push(next);
    bytes.push(0);
    bytes.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}
fn assert_no_cache(assembler: &PacketReassembler) {
    assert_eq!(assembler.entries.len(), 0);
    assert_eq!(assembler.buffered_bytes, 0);
}

#[test]
fn ipv4_last_middle_first_reconstructs_transport_from_the_first_fragment_header() {
    let data = udp_v4_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(1, 24, false, &data[24..]))
        .unwrap()
        .is_none());
    assert!(assembler
        .push(v4(1, 8, true, &data[8..24]))
        .unwrap()
        .is_none());
    let whole = assembler.push(v4(1, 0, true, &data[..8])).unwrap().unwrap();
    assert_eq!(ipv4_header_checksum(&whole[..20]), 0);
    assert_eq!(whole[6..8], [0, 0]);
    assert_eq!(whole.len(), 20 + data.len());
    assert_eq!(
        parse_udp_datagram(&whole).unwrap().payload,
        b"abcdefghijklmnopqrstuvwxy"
    );
    assert_no_cache(&assembler);
}
#[test]
fn ipv4_copied_options_can_differ_in_length_and_nonfirst_headers_do_not_replace_first() {
    let data = udp_v4_data();
    let mut assembler = PacketReassembler::default();
    let first = v4_options(2, 0, true, &data[..16], &[0x82, 4, 1, 2, 0x02, 4, 3, 4]);
    let mut last = v4_options(2, 16, false, &data[16..], &[0x82, 4, 1, 2]);
    last[8] = 32;
    checksum(&mut last);
    assert!(assembler.push(last).unwrap().is_none());
    let whole = assembler.push(first).unwrap().unwrap();
    assert_eq!(whole[0] & 15, 7);
    assert_eq!(whole[8], 64);
    assert_eq!(&whole[20..28], &[0x82, 4, 1, 2, 0x02, 4, 3, 4]);
    assert_eq!(parse_udp_datagram(&whole).unwrap().payload.len(), 25);
}
#[test]
fn whole_ipv4_datagram_flushes_an_unfinished_same_id_group() {
    let data = udp_v4_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(3, 0, true, &data[..8]))
        .unwrap()
        .is_none());
    let whole = v4(3, 0, false, &data);
    assert_eq!(assembler.push(whole.clone()).unwrap(), Some(whole));
    assert_no_cache(&assembler);
}

#[test]
fn ipv4_atomic_datagrams_ignore_same_id_fragments_in_either_arrival_order() {
    let data = udp_v4_data();
    let mut atomic = v4(60, 0, false, &data);
    atomic[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    checksum(&mut atomic);
    for first in [0, 16, usize::MAX] {
        let mut assembler = PacketReassembler::default();
        if first != usize::MAX {
            let partial = if first == 0 {
                v4(60, 0, true, &data[..16])
            } else {
                v4(60, 16, false, &data[16..])
            };
            assert!(assembler.push(partial).unwrap().is_none());
        }
        let charge = assembler.buffered_bytes;
        assert_eq!(
            assembler.push(atomic.clone()).unwrap(),
            Some(atomic.clone())
        );
        assert_eq!(
            assembler.buffered_bytes, charge,
            "DF=1 atomic input cannot use its ignored ID to flush ordinary fragments"
        );
        if first == usize::MAX {
            assert_no_cache(&assembler);
            assert!(assembler
                .push(v4(60, 0, true, &data[..16]))
                .unwrap()
                .is_none());
        }
        let remaining = if first == 16 {
            v4(60, 0, true, &data[..16])
        } else {
            v4(60, 16, false, &data[16..])
        };
        let complete = assembler.push(remaining).unwrap().unwrap();
        assert_eq!(&complete[20..], data.as_slice());
        assert_no_cache(&assembler);
    }
}

#[test]
fn ipv4_atomic_datagram_cannot_clear_a_same_id_rejected_tombstone() {
    let data = udp_v4_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(61, 0, true, &data[..16]))
        .unwrap()
        .is_none());
    assert!(assembler.push(v4(61, 8, true, &data[8..24])).is_err());
    let charge = assembler.buffered_bytes;
    let mut atomic = v4(61, 0, false, &data);
    atomic[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    checksum(&mut atomic);
    assert_eq!(assembler.push(atomic.clone()).unwrap(), Some(atomic));
    assert_eq!(assembler.buffered_bytes, charge);
    assert!(assembler
        .push(v4(61, 16, false, &data[16..]))
        .unwrap_err()
        .contains("rejected"));
}
#[test]
fn ipv6_reassembly_removes_fragment_header_and_retains_complete_udp_checksum() {
    let data = udp_v6_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v6(4, 16, false, &data[16..]))
        .unwrap()
        .is_none());
    let whole = assembler
        .push(v6(4, 0, true, &data[..16]))
        .unwrap()
        .unwrap();
    assert_eq!(whole[6], 17);
    assert_eq!(whole.len(), 40 + data.len());
    assert_eq!(
        u16::from_be_bytes(whole[4..6].try_into().unwrap()) as usize,
        data.len()
    );
    assert_eq!(
        parse_udp_datagram(&whole).unwrap().payload,
        b"abcdefghijklmnopqrstuvwxy"
    );
    assert_eq!(&whole[40..], data.as_slice());
    assert_no_cache(&assembler);
}
#[test]
fn ipv6_first_fragment_selects_preceding_headers_and_next_header() {
    let data = udp_v6_data();
    let mut assembler = PacketReassembler::default();
    // RFC 8200 permits different Per-Fragment headers and next-header values.
    let mut last = v6_ext(
        5,
        16,
        false,
        &data[16..],
        &[44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        6,
    );
    last[6] = 60;
    last[7] = 32;
    assert!(assembler.push(last).unwrap().is_none());
    let first = v6_ext(5, 0, true, &data[..16], &[44, 0, 0, 0, 0, 0, 0, 0], 17);
    let whole = assembler.push(first).unwrap().unwrap();
    assert_eq!(whole[6], 0);
    assert_eq!(whole[7], 64);
    assert_eq!(whole[40], 17);
    assert_eq!(whole.len(), 48 + data.len());
    assert_eq!(parse_udp_datagram(&whole).unwrap().payload.len(), 25);
}
#[test]
fn ipv6_fragmentable_destination_options_are_preserved_and_must_fit_first_fragment() {
    let mut data = vec![17, 0, 0, 0, 0, 0, 0, 0];
    data.extend_from_slice(&udp_v6_data());
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v6_ext(6, 0, true, &data[..16], &[], 60))
        .unwrap()
        .is_none());
    let whole = assembler
        .push(v6_ext(6, 16, false, &data[16..], &[], 60))
        .unwrap()
        .unwrap();
    assert_eq!(whole[6], 60);
    assert_eq!(whole[40], 17);
    assert!(parse_packet_flow(&whole).is_ok());
    let malformed = v6_ext(7, 0, true, &[17, 1, 0, 0, 0, 0, 0, 0], &[], 60);
    assert!(assembler
        .push(malformed)
        .unwrap_err()
        .contains("splits an extension"));
}
#[test]
fn ipv6_atomic_fragment_is_independent_of_pending_and_rejected_same_id_groups() {
    let data = udp_v6_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v6(8, 0, true, &data[..16]))
        .unwrap()
        .is_none());
    let charge = assembler.buffered_bytes;
    let atomic = assembler.push(v6(8, 0, false, &data)).unwrap().unwrap();
    assert!(parse_udp_datagram(&atomic).is_ok());
    assert_eq!(assembler.buffered_bytes, charge);
    // Even malformed atomic input must not poison the independent pending ID.
    assert!(assembler.push(v6(8, 0, false, &[0; 4])).is_err());
    assert_eq!(assembler.buffered_bytes, charge);
    assert!(assembler
        .push(v6(8, 16, false, &data[16..]))
        .unwrap()
        .is_some());
    assert!(assembler
        .push(v6(9, 0, true, &data[..16]))
        .unwrap()
        .is_none());
    assert!(assembler.push(v6(9, 8, true, &data[8..24])).is_err());
    let charge = assembler.buffered_bytes;
    assert!(assembler.push(v6(9, 0, false, &data)).unwrap().is_some());
    assert_eq!(assembler.buffered_bytes, charge);
    assert!(assembler.push(v6(9, 16, false, &data[16..])).is_err());
}
#[test]
fn ipv6_atomic_no_next_header_with_empty_payload_normalizes_without_state() {
    let mut assembler = PacketReassembler::default();
    let whole = assembler
        .push(v6_ext(10, 0, false, &[], &[], 59))
        .unwrap()
        .unwrap();
    assert_eq!(whole.len(), 40);
    assert_eq!(whole[6], 59);
    assert_eq!(&whole[4..6], &[0, 0]);
    assert_no_cache(&assembler);
}
#[test]
fn both_families_reject_overlap_and_duplicate_for_the_remaining_original_lifetime() {
    let start = Instant::now();
    for ipv6 in [false, true] {
        let data = if ipv6 { udp_v6_data() } else { udp_v4_data() };
        let make = |offset, more, bytes: &[u8]| {
            if ipv6 {
                v6(11, offset, more, bytes)
            } else {
                v4(11, offset, more, bytes)
            }
        };
        for overlap in [0, 8] {
            let mut assembler = PacketReassembler::default();
            assert!(assembler
                .push_at(make(0, true, &data[..16]), start)
                .unwrap()
                .is_none());
            assert!(assembler
                .push_at(
                    make(overlap, true, &data[overlap..overlap + 16]),
                    start + Duration::from_secs(1)
                )
                .unwrap_err()
                .contains("overlapping"));
            assert!(assembler
                .push_at(
                    make(16, false, &data[16..]),
                    start + Duration::from_secs(59)
                )
                .unwrap_err()
                .contains("rejected"));
            assert_eq!(assembler.expire_at(start + Duration::from_secs(60)), 1);
            assert_no_cache(&assembler);
            assert!(assembler
                .push_at(make(0, true, &data[..16]), start + Duration::from_secs(60))
                .unwrap()
                .is_none());
            assert!(assembler
                .push_at(
                    make(16, false, &data[16..]),
                    start + Duration::from_secs(60)
                )
                .unwrap()
                .is_some());
        }
    }
}
#[test]
fn conflicting_last_fragment_and_more_beyond_known_end_discard_the_group() {
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(12, 24, false, &[1; 8]))
        .unwrap()
        .is_none());
    assert!(assembler
        .push(v4(12, 8, false, &[1; 8]))
        .unwrap_err()
        .contains("conflicting"));
    assert!(assembler.push(v4(12, 0, true, &[1; 8])).is_err());
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(13, 24, false, &[1; 8]))
        .unwrap()
        .is_none());
    assert!(assembler
        .push(v4(13, 32, true, &[1; 8]))
        .unwrap_err()
        .contains("final length"));
}
#[test]
fn rejects_invalid_alignment_empty_fragments_lengths_checksum_and_flags() {
    let mut assembler = PacketReassembler::default();
    for invalid in [
        v4(14, 0, true, &[1; 7]),
        v4(15, 8, false, &[]),
        v4(16, 65528, false, &[1; 8]),
        v6(17, 65528, false, &[1; 8]),
    ] {
        assert!(assembler.push(invalid).is_err());
    }
    let mut invalid = v4(18, 0, true, &[1; 8]);
    invalid[10] ^= 1;
    assert!(assembler.push(invalid).unwrap_err().contains("checksum"));
    let mut invalid = v4(19, 0, true, &[1; 8]);
    invalid[6] |= 0x40;
    checksum(&mut invalid);
    assert!(assembler
        .push(invalid)
        .unwrap_err()
        .contains("Don't-Fragment"));
    let invalid = v4_options(20, 8, false, &[1; 8], &[0x02, 4, 0, 0]);
    assert!(assembler.push(invalid).unwrap_err().contains("non-copied"));
}
#[test]
fn ipv6_first_fragment_rejects_partial_tcp_nested_fragments_and_bad_extension_chains() {
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v6_ext(21, 0, true, &[0; 16], &[], 6))
        .unwrap_err()
        .contains("TCP header"));
    assert!(assembler
        .push(v6_ext(22, 0, true, &[0; 8], &[], 44))
        .unwrap_err()
        .contains("nested"));
    assert!(assembler
        .push(v6_ext(23, 0, true, &[17, 0, 0, 0, 0, 0, 0, 0], &[], 0))
        .unwrap_err()
        .contains("Hop-by-Hop"));
    let mut truncated = v6(24, 0, true, &udp_v6_data()[..16]);
    truncated.truncate(44);
    assert!(assembler.push(truncated).is_err());
    let mut bad_length = v6_ext(
        25,
        0,
        true,
        &udp_v6_data()[..16],
        &[44, 4, 0, 0, 0, 0, 0, 0],
        17,
    );
    assert!(assembler.push(bad_length.clone()).is_err());
    bad_length[4..6].fill(0);
    assert!(assembler
        .push(bad_length)
        .unwrap_err()
        .contains("jumbograms"));
}
#[test]
fn first_fragment_header_length_bounds_an_already_received_tail() {
    let mut assembler = PacketReassembler::default();
    // Fits a minimum IPv4 header, not the offset-zero header with 40 option bytes.
    assert!(assembler
        .push(v4(26, 65504, false, &[1; 8]))
        .unwrap()
        .is_none());
    assert!(assembler
        .push(v4_options(26, 0, true, &[1; 8], &[0; 40]))
        .unwrap_err()
        .contains("protocol length"));
}
#[test]
fn supports_maximum_ipv4_and_non_jumbo_ipv6_sizes() {
    let mut assembler = PacketReassembler::default();
    assert!(assembler.push(v4(27, 0, true, &[1; 8])).unwrap().is_none());
    let whole = assembler
        .push(v4(27, 8, false, &vec![2; 65_535 - 20 - 8]))
        .unwrap()
        .unwrap();
    assert_eq!(whole.len(), 65_535);
    let mut assembler = PacketReassembler::default();
    let data = udp_v6_data();
    assert!(assembler
        .push(v6(28, 0, true, &data[..16]))
        .unwrap()
        .is_none());
    let whole = assembler
        .push(v6(28, 16, false, &vec![2; 65_535 - 16]))
        .unwrap()
        .unwrap();
    assert_eq!(whole.len(), 65_575);
    assert_eq!(&whole[4..6], &u16::MAX.to_be_bytes());
}
#[test]
fn entry_piece_and_aggregate_byte_limits_are_bounded_and_expirable() {
    let now = Instant::now();
    let mut assembler = PacketReassembler::default();
    for id in 0..MAX_ENTRIES {
        assert!(assembler
            .push_at(v4(id as u16, 0, true, &[1; 8]), now)
            .unwrap()
            .is_none());
    }
    assert!(assembler
        .push_at(v4(MAX_ENTRIES as u16, 0, true, &[1; 8]), now)
        .unwrap_err()
        .contains("budget"));
    assert_eq!(assembler.entries.len(), MAX_ENTRIES);
    assert_eq!(assembler.expire_at(now + LIFETIME), MAX_ENTRIES);
    assert_no_cache(&assembler);
    for index in 0..MAX_PIECES {
        assert!(assembler
            .push_at(v4(1000, index * 8, true, &[1; 8]), now)
            .unwrap()
            .is_none());
    }
    assert!(assembler
        .push_at(v4(1000, MAX_PIECES * 8, true, &[1; 8]), now)
        .unwrap_err()
        .contains("fragment-count"));
    assert!(assembler.buffered_bytes < ENTRY_CHARGE + 1024);
    assembler.expire_at(now + LIFETIME);
    let mut rejected = false;
    for id in 0..MAX_ENTRIES {
        if assembler
            .push_at(v4(id as u16, 0, true, &vec![1; 64_000]), now)
            .is_err()
        {
            rejected = true;
            break;
        }
        assert!(assembler.buffered_bytes <= MAX_BUFFERED_BYTES);
    }
    assert!(rejected);
    assert!(assembler.buffered_bytes <= MAX_BUFFERED_BYTES);
    assembler.expire_at(now + LIFETIME);
    assert_no_cache(&assembler);
}
#[test]
fn deadline_is_from_first_arrival_and_not_refreshed_by_later_fragments() {
    let now = Instant::now();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push_at(v4(29, 0, true, &[1; 8]), now)
        .unwrap()
        .is_none());
    assert!(assembler
        .push_at(v4(29, 8, true, &[2; 8]), now + Duration::from_secs(50))
        .unwrap()
        .is_none());
    assert_eq!(assembler.next_expiry(), Some(now + LIFETIME));
    assert_eq!(assembler.expire_at(now + Duration::from_secs(59)), 0);
    assert_eq!(assembler.expire_at(now + Duration::from_secs(60)), 1);
    assert_eq!(assembler.next_expiry(), None, "nothing held, no timer");
    assert_no_cache(&assembler);
}
#[test]
fn ipv4_protocol_is_part_of_the_reassembly_identity() {
    let data = udp_v4_data();
    let mut assembler = PacketReassembler::default();
    assert!(assembler
        .push(v4(30, 0, true, &data[..16]))
        .unwrap()
        .is_none());
    let mut other_protocol = v4(30, 16, false, &data[16..]);
    other_protocol[9] = 6;
    checksum(&mut other_protocol);
    assert!(assembler.push(other_protocol).unwrap().is_none());
    assert_eq!(assembler.entries.len(), 2);
    assert!(assembler
        .push(v4(30, 16, false, &data[16..]))
        .unwrap()
        .is_some());
    assert_eq!(assembler.entries.len(), 1);
}
#[test]
fn ce_marks_survive_reassembly_and_not_ect_mixtures_are_rejected() {
    for ipv6 in [false, true] {
        let data = if ipv6 { udp_v6_data() } else { udp_v4_data() };
        let make = |offset, more, data: &[u8], ecn| {
            let mut result = if ipv6 {
                v6(31, offset, more, data)
            } else {
                v4(31, offset, more, data)
            };
            if ipv6 {
                result[1] = ecn << 4;
            } else {
                result[1] = ecn;
                checksum(&mut result);
            }
            result
        };
        let mut assembler = PacketReassembler::default();
        assert!(assembler
            .push(make(0, true, &data[..16], 2))
            .unwrap()
            .is_none());
        let result = assembler
            .push(make(16, false, &data[16..], 3))
            .unwrap()
            .unwrap();
        assert_eq!(
            if ipv6 {
                (result[1] >> 4) & 3
            } else {
                result[1] & 3
            },
            3
        );
        assert!(assembler
            .push(make(0, true, &data[..16], 0))
            .unwrap()
            .is_none());
        assert!(assembler
            .push(make(16, false, &data[16..], 3))
            .unwrap_err()
            .contains("Not-ECT"));
    }
}
#[test]
fn fresh_pump_state_cannot_use_fragments_retained_by_a_previous_pump() {
    let data = udp_v4_data();
    let mut old = PacketReassembler::default();
    assert!(old.push(v4(32, 0, true, &data[..16])).unwrap().is_none());
    drop(old);
    let mut fresh = PacketReassembler::default();
    assert!(fresh
        .push(v4(32, 16, false, &data[16..]))
        .unwrap()
        .is_none());
    assert!(fresh.push(v4(32, 0, true, &data[..16])).unwrap().is_some());
}

/// The pump pushes every captured packet through the assembler, so the
/// earliest deadline is kept rather than scanned for: it follows the oldest
/// held datagram, a later arrival does not move it, and it ends with the last
/// entry.
#[test]
fn the_earliest_deadline_follows_the_oldest_held_datagram() {
    let mut assembler = PacketReassembler::default();
    let start = Instant::now();
    assert_eq!(assembler.next_expiry(), None, "nothing is held");

    assert_eq!(
        assembler.push_at(v4(1, 0, true, &[7; 16]), start).unwrap(),
        None
    );
    assert_eq!(assembler.next_expiry(), Some(start + LIFETIME));

    // A second datagram ten seconds later leaves the deadline where it is.
    let later = start + Duration::from_secs(10);
    assert_eq!(
        assembler.push_at(v4(2, 0, true, &[8; 16]), later).unwrap(),
        None
    );
    assert_eq!(
        assembler.next_expiry(),
        Some(start + LIFETIME),
        "the oldest still sets it"
    );

    // Expiring the first moves it to the second.
    assert_eq!(assembler.expire_at(start + LIFETIME), 1);
    assert_eq!(assembler.next_expiry(), Some(later + LIFETIME));

    // And the last one leaving ends it.
    assert_eq!(assembler.expire_at(later + LIFETIME), 1);
    assert_eq!(assembler.next_expiry(), None, "nothing is held again");
    assert_no_cache(&assembler);
}
