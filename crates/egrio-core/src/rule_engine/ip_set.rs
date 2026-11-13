//! Address sets for rules that hold many networks (GeoIP codes, IP-CIDR
//! rule sets): sorted, merged ranges, so a lookup is one binary search
//! however many networks the set holds.

use std::net::IpAddr;

use super::CidrRange;

#[derive(Debug, Clone, Default)]
pub(super) struct IpRangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRangeSet {
    pub(super) fn from_networks(networks: impl IntoIterator<Item = CidrRange>) -> Self {
        let mut set = Self::default();
        for network in networks {
            match network.network {
                IpAddr::V4(address) => {
                    let mask = super::cidr_mask_u32(network.prefix_len);
                    let start = u32::from(address) & mask;
                    set.v4.push((start, start | !mask));
                }
                IpAddr::V6(address) => {
                    let mask = super::cidr_mask_u128(network.prefix_len);
                    let start = u128::from(address) & mask;
                    set.v6.push((start, start | !mask));
                }
            }
        }
        merge(&mut set.v4);
        merge(&mut set.v6);
        set
    }

    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(address) => find(&self.v4, u32::from(address)),
            IpAddr::V6(address) => find(&self.v6, u128::from(address)),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

trait Address: Copy + Ord {
    fn after(self) -> Option<Self>;
}

impl Address for u32 {
    fn after(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl Address for u128 {
    fn after(self) -> Option<Self> {
        self.checked_add(1)
    }
}

/// Sorts the ranges and joins those that overlap or touch.
fn merge<T: Address>(ranges: &mut Vec<(T, T)>) {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges.iter() {
        if let Some(last) = merged.last_mut() {
            // A range ending at the top address covers everything after it.
            if last.1.after().is_none_or(|after| start <= after) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    *ranges = merged;
}

fn find<T: Address>(ranges: &[(T, T)], value: T) -> bool {
    let index = ranges.partition_point(|&(start, _)| start <= value);
    index > 0 && ranges[index - 1].1 >= value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(networks: &[&str]) -> IpRangeSet {
        IpRangeSet::from_networks(
            networks
                .iter()
                .map(|network| CidrRange::parse(network).expect("valid network")),
        )
    }

    #[test]
    fn lookups_find_every_network_and_nothing_between() {
        let set = set(&[
            "10.0.0.0/8",
            "1.0.1.0/24",
            "1.0.2.0/23",
            "1.0.3.0/24",
            "240e::/20",
        ]);
        assert_eq!(
            set.v4,
            [(0x0100_0100, 0x0100_03ff), (0x0a00_0000, 0x0aff_ffff)]
        );
        for inside in [
            "1.0.1.0",
            "1.0.3.255",
            "10.200.0.1",
            "240e:1::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(set.contains(inside.parse().unwrap()), "{inside}");
        }
        for outside in ["1.0.0.255", "1.0.4.0", "11.0.0.0", "2400::1", "0.0.0.0"] {
            assert!(!set.contains(outside.parse().unwrap()), "{outside}");
        }
    }

    #[test]
    fn whole_address_spaces_merge_without_overflow() {
        let set = set(&["0.0.0.0/0", "255.255.255.0/24", "::/0"]);
        assert_eq!(set.v4, [(0, u32::MAX)]);
        assert!(set.contains("255.255.255.255".parse().unwrap()));
        assert!(set.contains("ffff::1".parse().unwrap()));
    }
}
