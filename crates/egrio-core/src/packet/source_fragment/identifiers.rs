//! Process-lifetime fragment IDs. Fixed keyed buckets follow the shape of
//! RFC 7739 section 5.3: an address pair adds its keyed offset to one of the
//! bucket counters, so its IPv4 IDs run through all 65536 values before one
//! repeats. Counters wrap instead of holding IDs back for a reuse interval;
//! the source-fragmentation section of `docs/architecture/core.md` says why.
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

const BUCKETS: usize = 8192;

struct Identifiers {
    secret: RandomState,
    v4: Box<[AtomicU32]>,
    v6: Box<[AtomicU32]>,
}

impl Default for Identifiers {
    fn default() -> Self {
        let counters = || {
            (0..BUCKETS)
                .map(|_| AtomicU32::new(rand::random()))
                .collect()
        };
        Self {
            secret: RandomState::new(),
            v4: counters(),
            v6: counters(),
        }
    }
}

impl Identifiers {
    fn hash(&self, domain: u8, source: IpAddr, destination: IpAddr) -> u64 {
        let mut hash = self.secret.build_hasher();
        domain.hash(&mut hash);
        source.hash(&mut hash);
        destination.hash(&mut hash);
        hash.finish()
    }

    /// The next ID for the pair; IPv4 headers carry its low 16 bits.
    fn allocate(&self, source: IpAddr, destination: IpAddr) -> u32 {
        let bucket = self.hash(0, source, destination) as usize % BUCKETS;
        let offset = self.hash(1, source, destination) as u32;
        let counters = match source {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        offset.wrapping_add(counters[bucket].fetch_add(1, Ordering::Relaxed))
    }
}

/// Shared by all pumps and generation Cores in this process. A process
/// restart creates fresh random seeds: collision risk is reduced rather
/// than eliminated across a restart; there is no durable uniqueness claim.
pub(super) fn next(source: IpAddr, destination: IpAddr) -> u32 {
    static IDS: OnceLock<Identifiers> = OnceLock::new();
    IDS.get_or_init(Identifiers::default)
        .allocate(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_pair_uses_every_ipv4_id_once_per_cycle_and_wraps_without_refusing() {
        let ids = Identifiers::default();
        let source = "198.18.0.7".parse().unwrap();
        let destination = "10.255.255.1".parse().unwrap();
        let first = ids.allocate(source, destination) as u16;
        let mut seen = HashSet::from([first]);
        for _ in 1..65536 {
            assert!(seen.insert(ids.allocate(source, destination) as u16));
        }
        assert_eq!(ids.allocate(source, destination) as u16, first);
    }

    #[test]
    fn process_pool_does_not_reset_for_a_new_pump_caller() {
        let source = "2001:db8:101::1".parse().unwrap();
        let destination = "2001:db8:202::2".parse().unwrap();
        let first = next(source, destination);
        assert_ne!(next(source, destination), first);
        let pool = Identifiers::default();
        assert_eq!(pool.v4.len(), BUCKETS);
        assert_eq!(pool.v6.len(), BUCKETS);
    }
}
