//! Sliding packet-ID window. Call only after AEAD, timestamp, address and
//! client-session binding validation have succeeded (SIP022 section 3.2.4).

const WINDOW_BITS: u64 = 1024;

#[derive(Default)]
pub(super) struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; 16],
}

impl ReplayWindow {
    pub(super) fn accept(&mut self, packet: u64) -> bool {
        if let Some(highest) = self.highest {
            if packet <= highest && highest - packet >= WINDOW_BITS {
                return false;
            }
            if packet > highest {
                if packet - highest >= WINDOW_BITS {
                    self.bits.fill(0);
                } else {
                    for next in highest + 1..=packet {
                        self.bits[(next % WINDOW_BITS / 64) as usize] &= !(1 << (next % 64));
                    }
                }
            }
        }
        let word = &mut self.bits[(packet % WINDOW_BITS / 64) as usize];
        let bit = 1 << (packet % 64);
        if *word & bit != 0 {
            return false;
        }
        *word |= bit;
        self.highest = Some(self.highest.map_or(packet, |highest| highest.max(packet)));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reordering_and_rejects_duplicates_and_old_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(4));
        assert!(window.accept(2));
        assert!(!window.accept(4));
        assert!(!window.accept(2));
        assert!(window.accept(1025));
        assert!(!window.accept(1));
        assert!(window.accept(1024));
        assert!(window.accept(50_000));
        assert!(!window.accept(1025));
        assert!(window.accept(u64::MAX));
        assert!(!window.accept(u64::MAX));
    }
}
