//! The internet checksum (RFC 1071) over data in several pieces.
//!
//! The one's complement sum does not depend on byte order (RFC 1071 section
//! 2(B)), so each piece is summed as native-endian 32-bit words into a 64-bit
//! accumulator, a loop the compiler vectorizes, and the folded sum converted
//! to network order. A piece that starts at an odd offset of the whole pairs
//! its bytes the other way round, which swapping the bytes of its folded sum
//! corrects (section 2(B) again).

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Checksum {
    sum: u32,
    odd: bool,
}

impl Checksum {
    pub(crate) fn add(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let folded = fold(data);
        self.sum += u32::from(if self.odd {
            folded.swap_bytes()
        } else {
            folded
        });
        self.odd ^= data.len() % 2 == 1;
    }

    /// The checksum field's value: the complement of the folded sum.
    pub(crate) fn finish(self) -> u16 {
        !self.folded()
    }

    /// The folded sum itself: what a checksum field holds while the rest of
    /// the sum is still to be added, by [`Checksum::add`] over the field or
    /// by the OS (Linux `CHECKSUM_PARTIAL`, `include/linux/skbuff.h`).
    pub(crate) fn folded(self) -> u16 {
        let sum = (self.sum & 0xffff) + (self.sum >> 16);
        let sum = (sum & 0xffff) + (sum >> 16);
        sum as u16
    }
}

/// The folded one's complement sum of `data` in network byte order.
fn fold(data: &[u8]) -> u16 {
    let mut accum: u64 = 0;
    let mut words = data.chunks_exact(4);
    for word in &mut words {
        accum += u64::from(u32::from_ne_bytes([word[0], word[1], word[2], word[3]]));
    }
    // A trailing odd byte is the high byte of its 16-bit word, which a
    // zero-padded native-endian word yields after the final conversion.
    let mut tail = [0; 4];
    let rest = words.remainder();
    tail[..rest.len()].copy_from_slice(rest);
    accum += u64::from(u32::from_ne_bytes(tail));
    let accum = (accum & 0xffff_ffff) + (accum >> 32);
    let accum = (accum & 0xffff_ffff) + (accum >> 32);
    let accum = (accum & 0xffff) + (accum >> 16);
    let accum = (accum & 0xffff) + (accum >> 16);
    let accum = (accum & 0xffff) + (accum >> 16);
    u16::from_be(accum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 section 4's reference loop: big-endian 16-bit words.
    fn reference(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut pairs = data.chunks_exact(2);
        for pair in &mut pairs {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let [last] = pairs.remainder() {
            sum += u32::from(*last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn pieces_at_any_split_match_the_reference_sum() {
        let data: Vec<u8> = (0..1031_u32).map(|i| (i * 7 + i / 3) as u8).collect();
        let expected = reference(&data);
        for first in [0, 1, 2, 3, 5, 8, 511, 1030, 1031] {
            for second in [first, first + 1, first + 3, first + 100] {
                let second = second.min(data.len());
                let mut checksum = Checksum::default();
                checksum.add(&data[..first]);
                checksum.add(&data[first..second]);
                checksum.add(&data[second..]);
                assert_eq!(checksum.finish(), expected, "split at {first}/{second}");
            }
        }
    }

    #[test]
    fn data_carrying_its_checksum_sums_to_zero() {
        let mut header = vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0x00,
            0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let mut checksum = Checksum::default();
        checksum.add(&header);
        let value = checksum.finish();
        assert_eq!(value, 0xb861, "RFC 1071-style IPv4 example");
        header[10..12].copy_from_slice(&value.to_be_bytes());
        let mut verify = Checksum::default();
        verify.add(&header);
        assert_eq!(verify.finish(), 0);
    }
}
