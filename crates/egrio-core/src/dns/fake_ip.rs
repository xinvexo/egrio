//! Configured virtual address pools and session-owned reverse mappings.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

const MAX_MAPPINGS: usize = 1 << 17;
/// How recently a mapping must have been used (an answer naming it, a flow
/// to it) to keep its address once the pool is full; past it, the least
/// recently used go to new names first. Answers live one second: this covers
/// clients that keep them longer (browsers about a minute, Java 30 s) with
/// room to spare, and a pool full of mappings all used this recently takes
/// over 100 new names a second. Handing out addresses in allocation order
/// instead would take one from a name in constant use, misrouting the
/// clients that just got it; refusing every new name once the pool had filled
/// broke name resolution for the rest of a long session.
const REUSE_IDLE: Duration = Duration::from_secs(600);
/// Addresses one sweep of a full pool looks at, and the most it lets go in
/// one, so a sweep serves up to that many new names. A sweep looks at a
/// slice of the pool rather than every mapping, bounding how long the
/// packet pump holds the write lock while answering a query. The slice moves
/// on each time, so the pool is still covered, and an address just let go is
/// not looked at again until the sweep comes round.
const REUSE_BATCH: u32 = 1024;
/// How soon a full pool looks for idle mappings again after finding none,
/// so a pool full of mappings in use refuses new names without a pass each.
const REUSE_RETRY: Duration = Duration::from_secs(1);
/// Addresses a new name's probe looks at from its hash home before the pool
/// is taken for full. The probe is open addressing, so a pool with room
/// answers within a few -- the expected run is one over the free share, and
/// this many is reached only past about 99.6% full. Without it the probe of
/// a pool with no room costs a look at every address the pool has -- 65 534
/// of them for a /16, for every new name, with the write lock held on the
/// packet pump that was answering the query.
const PROBE_LIMIT: u32 = 256;
const IPV6_PREFIX: u128 = 0xfd11_5ca1_ab1e_0001_0000_0000_0000_0000;

/// An IPv4 CIDR pool. Host bits in the input are normalized; network,
/// first host (reserved gateway), and broadcast addresses are never allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FakeIpRange {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl FakeIpRange {
    pub fn network(self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    pub fn netmask(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX << (32 - self.prefix_len))
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & u32::from(self.netmask()) == u32::from(self.network)
    }

    fn broadcast(self) -> u32 {
        u32::from(self.network) | !u32::from(self.netmask())
    }

    fn first(self) -> u32 {
        u32::from(self.network) + 2
    }

    fn capacity(self) -> u32 {
        self.broadcast() - self.first()
    }

    /// Whether this pool can hand an address to a client. Network, first
    /// host (reserved gateway) and broadcast addresses are excluded.
    pub fn is_allocatable(self, ip: Ipv4Addr) -> bool {
        (self.first()..self.broadcast()).contains(&u32::from(ip))
    }

    /// Tests the IPv6 identity projected from an allocatable IPv4 address.
    /// This follows the engine's fixed IPv6 projection, not a second pool.
    pub fn is_allocatable_ipv6(self, ip: Ipv6Addr) -> bool {
        project_ipv6_to_ipv4(ip).is_some_and(|ip| self.is_allocatable(ip))
    }

    /// The pool's fixed IPv6 projection: its network and prefix length.
    pub fn ipv6_network(self) -> (Ipv6Addr, u8) {
        (
            Ipv6Addr::from(IPV6_PREFIX | u128::from(u32::from(self.network))),
            96 + self.prefix_len,
        )
    }

    /// Whether this pool hands `address` out: it is inside the pool, or
    /// inside the pool's fixed IPv6 projection. Such an address stands for a
    /// name instead of being an address of one.
    pub fn holds(self, address: std::net::IpAddr) -> bool {
        match address {
            std::net::IpAddr::V4(address) => self.contains(address),
            std::net::IpAddr::V6(address) => {
                project_ipv6_to_ipv4(address).is_some_and(|address| self.contains(address))
            }
        }
    }

    /// Whether the prefix `address/prefix_len` shares any address with this
    /// pool or, for IPv6, with the pool's fixed IPv6 projection.
    pub fn overlaps(self, address: std::net::IpAddr, prefix_len: u8) -> bool {
        match address {
            std::net::IpAddr::V4(address) => {
                let common = prefix_len.min(self.prefix_len);
                let mask = u32::MAX.checked_shl(32 - u32::from(common)).unwrap_or(0);
                u32::from(address) & mask == u32::from(self.network) & mask
            }
            std::net::IpAddr::V6(address) => {
                let (network, network_len) = self.ipv6_network();
                let common = prefix_len.min(network_len);
                let mask = u128::MAX.checked_shl(128 - u32::from(common)).unwrap_or(0);
                u128::from(address) & mask == u128::from(network) & mask
            }
        }
    }
}

impl Default for FakeIpRange {
    fn default() -> Self {
        Self {
            network: Ipv4Addr::new(198, 18, 0, 0),
            prefix_len: 16,
        }
    }
}

impl FromStr for FakeIpRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .trim()
            .split_once('/')
            .ok_or("fake-ip-range must be an IPv4 CIDR")?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "fake-ip-range must use an IPv4 address")?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| "fake-ip-range has an invalid prefix length")?;
        if !(1..=30).contains(&prefix_len) {
            return Err(
                "fake-ip-range prefix must be between /1 and /30 and leave allocatable hosts"
                    .into(),
            );
        }
        let network = u32::from(address) & (u32::MAX << (32 - prefix_len));
        let range = Self {
            network: Ipv4Addr::from(network),
            prefix_len,
        };
        // These destinations are local control scopes or not unicast. Reject
        // a containing CIDR too, rather than silently allocating around it.
        for (first, last) in [
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 255, 255)),
            (
                Ipv4Addr::new(127, 0, 0, 0),
                Ipv4Addr::new(127, 255, 255, 255),
            ),
            (
                Ipv4Addr::new(169, 254, 0, 0),
                Ipv4Addr::new(169, 254, 255, 255),
            ),
            (Ipv4Addr::new(224, 0, 0, 0), Ipv4Addr::BROADCAST),
        ] {
            if network <= u32::from(last) && range.broadcast() >= u32::from(first) {
                return Err("fake-ip-range must not include unspecified, loopback, link-local, multicast, or reserved addresses".into());
            }
        }
        Ok(range)
    }
}

impl fmt::Display for FakeIpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl Serialize for FakeIpRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FakeIpRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FakeDnsStore {
    range: Option<FakeIpRange>,
    inner: Arc<RwLock<FakeDnsState>>,
}

impl Default for FakeDnsStore {
    fn default() -> Self {
        Self {
            range: Some(FakeIpRange::default()),
            inner: Arc::new(RwLock::new(FakeDnsState::default())),
        }
    }
}

#[derive(Debug)]
struct FakeDnsState {
    /// What mapping use times count from.
    epoch: Instant,
    /// Each name once, shared by both maps.
    by_domain: HashMap<Arc<str>, Addresses>,
    by_ip: HashMap<Ipv4Addr, Mapping>,
    /// Addresses of mappings a full pool let go, for the next new names.
    reusable: Vec<Ipv4Addr>,
    /// Where the next sweep starts, as an offset into the pool. The pool is
    /// a range of addresses, so a sweep needs nothing but this to carry on
    /// where the last one stopped.
    sweep_from: u32,
    /// Addresses looked at since a sweep last found an idle mapping. Once it
    /// passes the pool's size every one has been looked at and none was
    /// idle, which is what [`FakeDnsState::none_idle_at`] then stands for: a
    /// slice finding nothing is not the pool having nothing.
    fruitless: u32,
    /// The pool the sweeps are walking. A different one means the configured
    /// range changed under a shared state, so one sweep lets go of what the
    /// new pool's offsets would never reach.
    swept_range: Option<FakeIpRange>,
    /// The pool a look at every one of its addresses found no room in. Only
    /// letting an address go can make room (nothing else takes a mapping out
    /// of `by_ip`), so while this stands there is nothing to look for, and a
    /// name arriving at a full pool in use costs no pass over it.
    full_range: Option<FakeIpRange>,
    /// When a full pool last found no idle mapping.
    none_idle_at: Option<Instant>,
    /// Mappings made so far, so a keeper of them can tell an unchanged store.
    changes: u64,
}

impl Default for FakeDnsState {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
            reusable: Vec::new(),
            sweep_from: 0,
            fruitless: 0,
            swept_range: None,
            full_range: None,
            none_idle_at: None,
            changes: 0,
        }
    }
}

/// The addresses a name holds: one, or several while a range from before a
/// reload still holds one too.
#[derive(Debug)]
enum Addresses {
    One(Ipv4Addr),
    Several(Vec<Ipv4Addr>),
}

impl Addresses {
    fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let (one, several) = match self {
            Self::One(ip) => (Some(*ip), &[][..]),
            Self::Several(ips) => (None, ips.as_slice()),
        };
        one.into_iter().chain(several.iter().copied())
    }

    fn push(&mut self, ip: Ipv4Addr) {
        match self {
            Self::One(first) => *self = Self::Several(vec![*first, ip]),
            Self::Several(ips) => ips.push(ip),
        }
    }

    /// Drops `ip`; whether none is left.
    fn remove(&mut self, ip: Ipv4Addr) -> bool {
        match self {
            Self::One(only) => *only == ip,
            Self::Several(ips) => {
                ips.retain(|address| *address != ip);
                ips.is_empty()
            }
        }
    }
}

#[derive(Debug)]
struct Mapping {
    domain: Arc<str>,
    /// Milliseconds after the state's epoch when an answer last named it or
    /// a flow last went to it. Uses stamp it under the read lock, so lookups
    /// never wait on each other.
    used: AtomicU64,
}

impl FakeDnsState {
    fn tick(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_millis() as u64
    }

    fn stamp(&self, mapping: &Mapping, now: Instant) {
        mapping.used.fetch_max(self.tick(now), Ordering::Relaxed);
    }

    /// The address `domain` already has in `range`, stamped as used.
    fn existing(&self, domain: &str, range: FakeIpRange, now: Instant) -> Option<Ipv4Addr> {
        let ip = self
            .by_domain
            .get(domain)?
            .iter()
            .find(|ip| range.is_allocatable(*ip))?;
        if let Some(mapping) = self.by_ip.get(&ip) {
            self.stamp(mapping, now);
        }
        Some(ip)
    }

    /// A free address for `domain`, from its hash home onwards, looking at
    /// no more than `probes` of them. Probing only picks a free address for
    /// a new name: mappings are found by their own keys in `by_domain` and
    /// `by_ip`, never by walking a probe sequence, so an address let go
    /// hides no other mapping.
    fn probe(&self, range: FakeIpRange, domain: &str, probes: u32) -> Option<Ipv4Addr> {
        let span = range.capacity();
        let home = (stable_domain_hash(domain) % u64::from(span)) as u32;
        (0..probes.min(span))
            .map(|probe| Ipv4Addr::from(range.first() + (home + probe) % span))
            .find(|ip| !self.by_ip.contains_key(ip))
    }

    /// When `ip`'s mapping was last used, if it has been idle long enough
    /// for a new name to have it.
    fn idle_use(&self, ip: Ipv4Addr, now: Instant) -> Option<u64> {
        let used = self.by_ip.get(&ip)?.used.load(Ordering::Relaxed);
        (self.tick(now).saturating_sub(used) >= REUSE_IDLE.as_millis() as u64).then_some(used)
    }

    /// Lets go of `ip`, and of its name once that was its last address.
    fn release(&mut self, ip: Ipv4Addr) {
        let Some(mapping) = self.by_ip.remove(&ip) else {
            return;
        };
        // There is room again, wherever a probe gave up before.
        self.full_range = None;
        if self
            .by_domain
            .get_mut(&mapping.domain)
            .is_some_and(|addresses| addresses.remove(ip))
        {
            self.by_domain.remove(&mapping.domain);
        }
    }

    /// Takes the idle mappings out of the next slice of `range` and leaves
    /// their addresses for new names.
    fn sweep(&mut self, range: FakeIpRange, now: Instant) {
        let span = range.capacity();
        let slice = REUSE_BATCH.min(span);
        let mut looked = 0;
        let mut idle = Vec::new();
        while looked < slice && (idle.len() as u32) < REUSE_BATCH {
            let ip = Ipv4Addr::from(range.first() + (self.sweep_from + looked) % span);
            if let Some(used) = self.idle_use(ip, now) {
                idle.push((used, ip));
            }
            looked += 1;
        }
        self.sweep_from = (self.sweep_from + looked) % span;
        // The least recently used last: new names take it first.
        idle.sort_unstable_by(|a, b| b.cmp(a));
        for (_, ip) in &idle {
            self.release(*ip);
        }
        if idle.is_empty() {
            // A slice with nothing idle says nothing about the rest of the
            // pool; only a lap of it does.
            self.fruitless = self.fruitless.saturating_add(looked);
            if self.fruitless >= span {
                self.fruitless = 0;
                self.none_idle_at = Some(now);
            }
        } else {
            self.fruitless = 0;
            self.none_idle_at = None;
        }
        self.reusable = idle.into_iter().map(|(_, ip)| ip).collect();
    }

    /// Lets go of the idle mappings outside `range`. A pool change under a
    /// shared state leaves them where no sweep of the new pool looks, and no
    /// answer can name them again, so they would hold their place in the map
    /// for as long as the Core runs. The ones a flow is still using stay,
    /// until the next pool change finds them idle.
    fn release_outside(&mut self, range: FakeIpRange, now: Instant) {
        let outside = self
            .by_ip
            .keys()
            .copied()
            .filter(|ip| !range.is_allocatable(*ip))
            .collect::<Vec<_>>();
        for ip in outside {
            if self.idle_use(ip, now).is_some() {
                self.release(ip);
            }
        }
    }

    fn bind(&mut self, ip: Ipv4Addr, domain: String, now: Instant) {
        let used = AtomicU64::new(self.tick(now));
        let domain: Arc<str> = match self.by_domain.get_key_value(domain.as_str()) {
            Some((name, _)) => Arc::clone(name),
            None => Arc::from(domain),
        };
        match self.by_domain.get_mut(&domain) {
            Some(addresses) => addresses.push(ip),
            None => {
                self.by_domain
                    .insert(Arc::clone(&domain), Addresses::One(ip));
            }
        }
        self.by_ip.insert(ip, Mapping { domain, used });
        self.changes += 1;
    }

    /// An address for a new name once the pool or the mapping cap is full:
    /// one let go before, or one the next sweep finds idle for `REUSE_IDLE`.
    /// A sweep that finds the whole pool in use is not tried again for
    /// `REUSE_RETRY`.
    fn reuse(&mut self, range: FakeIpRange, now: Instant) -> Option<Ipv4Addr> {
        if self.swept_range != Some(range) {
            self.swept_range = Some(range);
            self.release_outside(range, now);
        }
        if let Some(ip) = self.take_reusable(range) {
            return Some(ip);
        }
        if self
            .none_idle_at
            .is_none_or(|at| now.duration_since(at) >= REUSE_RETRY)
        {
            self.sweep(range, now);
        }
        self.take_reusable(range)
    }

    /// The next address a sweep left, skipping the ones a probe has bound
    /// since (a free address is a free address, whoever finds it) and the
    /// ones a pool change has put out of reach.
    fn take_reusable(&mut self, range: FakeIpRange) -> Option<Ipv4Addr> {
        while let Some(ip) = self.reusable.pop() {
            if range.is_allocatable(ip) && !self.by_ip.contains_key(&ip) {
                return Some(ip);
            }
        }
        None
    }
}

impl FakeDnsStore {
    /// Each pinned runtime allocates within its own configured pool while
    /// sharing reverse mappings with all other views of the same session.
    pub(crate) fn with_range(&self, range: Option<FakeIpRange>) -> Self {
        Self {
            range,
            inner: self.inner.clone(),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, FakeDnsState> {
        self.inner.read().expect("native core fake DNS lock")
    }

    pub(crate) fn allocate_ipv4(&self, domain: &str) -> Result<Ipv4Addr, String> {
        self.allocate_ipv4_at(domain, Instant::now())
    }

    fn allocate_ipv4_at(&self, domain: &str, now: Instant) -> Result<Ipv4Addr, String> {
        let range = self.range.ok_or("fake IP allocation is disabled")?;
        let domain = super::resolver::normalize_domain(domain);
        // A name answered before only stamps its mapping.
        if let Some(ip) = self.read().existing(&domain, range, now) {
            return Ok(ip);
        }
        let mut state = self.inner.write().expect("native core fake DNS lock");
        if let Some(ip) = state.existing(&domain, range, now) {
            return Ok(ip);
        }
        let room = state.by_ip.len() < MAX_MAPPINGS && state.full_range != Some(range);
        if room {
            if let Some(ip) = state.probe(range, &domain, PROBE_LIMIT) {
                state.bind(ip, domain, now);
                return Ok(ip);
            }
        }
        // A client can hold an answer beyond its TTL, so only an address no
        // answer named and no flow used for `REUSE_IDLE` goes to a new name.
        if let Some(ip) = state.reuse(range, now) {
            state.bind(ip, domain, now);
            return Ok(ip);
        }
        // Neither the probe's run nor an idle mapping, so the pool is as
        // good as full -- but a free address may still be sitting past
        // where the probe stopped, and refusing a name while one is there
        // would be wrong. This is the only path that costs a look at every
        // address, and it is taken when the alternative is giving up.
        if room {
            match state.probe(range, &domain, range.capacity()) {
                Some(ip) => {
                    state.bind(ip, domain, now);
                    return Ok(ip);
                }
                None => state.full_range = Some(range),
            }
        }
        Err(format!("fake DNS IPv4 pool {range} is exhausted"))
    }

    pub(crate) fn len(&self) -> usize {
        self.read().by_ip.len()
    }

    /// How many mappings have been made, restored ones included.
    pub(crate) fn changes(&self) -> u64 {
        self.read().changes
    }

    /// The mappings held, the most recently used first, with how many
    /// mappings had been made when they were read.
    pub(crate) fn mappings(&self) -> (u64, Vec<(Ipv4Addr, String)>) {
        let state = self.read();
        let mut mappings: Vec<(u64, Ipv4Addr, String)> = state
            .by_ip
            .iter()
            .map(|(ip, mapping)| {
                (
                    mapping.used.load(Ordering::Relaxed),
                    *ip,
                    mapping.domain.to_string(),
                )
            })
            .collect();
        mappings.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        let mappings = mappings
            .into_iter()
            .map(|(_, ip, domain)| (ip, domain))
            .collect();
        (state.changes, mappings)
    }

    /// Takes back mappings an earlier Core held, in their order: an address
    /// of this store's pool that no mapping holds goes back to its name when
    /// the name has none yet, counting as used now, until the mapping cap.
    /// Returns how many came back.
    pub(crate) fn restore(&self, mappings: impl IntoIterator<Item = (Ipv4Addr, String)>) -> usize {
        let Some(range) = self.range else {
            return 0;
        };
        let now = Instant::now();
        let mut state = self.inner.write().expect("native core fake DNS lock");
        let mut restored = 0;
        for (ip, domain) in mappings {
            if state.by_ip.len() >= MAX_MAPPINGS {
                break;
            }
            let domain = super::resolver::normalize_domain(&domain);
            if domain.is_empty()
                || !range.is_allocatable(ip)
                || state.by_ip.contains_key(&ip)
                || state.by_domain.contains_key(domain.as_str())
            {
                continue;
            }
            state.bind(ip, domain, now);
            restored += 1;
        }
        restored
    }

    /// The name `ip` stands for; a flow going to it counts as a use.
    pub(crate) fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<String> {
        self.lookup_ipv4_at(ip, Instant::now())
    }

    fn lookup_ipv4_at(&self, ip: Ipv4Addr, now: Instant) -> Option<String> {
        let state = self.read();
        let mapping = state.by_ip.get(&ip)?;
        state.stamp(mapping, now);
        Some(mapping.domain.to_string())
    }

    pub(crate) fn allocate_ipv6(&self, domain: &str) -> Result<Ipv6Addr, String> {
        self.allocate_ipv4(domain).map(project_ipv4_to_ipv6)
    }

    pub(crate) fn lookup_ipv6(&self, ip: Ipv6Addr) -> Option<String> {
        project_ipv6_to_ipv4(ip).and_then(|ip| self.lookup_ipv4(ip))
    }

    /// Current pool plus addresses issued by older views of this session.
    pub(crate) fn contains_ipv4(&self, ip: Ipv4Addr) -> bool {
        self.range.is_some_and(|range| range.contains(ip)) || self.read().by_ip.contains_key(&ip)
    }

    pub(crate) fn contains_ipv6(&self, ip: Ipv6Addr) -> bool {
        project_ipv6_to_ipv4(ip).is_some_and(|ip| self.contains_ipv4(ip))
    }
}

// The full IPv4 address, rather than a pool-relative offset, keeps paired
// IPv6 identities unique even while old and new ranges coexist after reload.
pub(super) fn project_ipv4_to_ipv6(ip: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from(IPV6_PREFIX | u128::from(u32::from(ip)))
}

fn project_ipv6_to_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let value = u128::from(ip);
    (value & !u128::from(u32::MAX) == IPV6_PREFIX).then(|| Ipv4Addr::from(value as u32))
}

/// FNV-1a makes home slots deterministic for the same pool and domain.
fn stable_domain_hash(domain: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in domain.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod overlap_tests {
    use super::*;

    #[test]
    fn a_prefix_overlaps_the_pool_when_either_contains_the_other() {
        let pool = FakeIpRange::default();
        let v4 = |text: &str| text.parse::<std::net::IpAddr>().unwrap();
        assert!(pool.overlaps(v4("198.18.4.0"), 24));
        assert!(pool.overlaps(v4("198.0.0.0"), 8));
        assert!(pool.overlaps(v4("0.0.0.0"), 0));
        assert!(!pool.overlaps(v4("198.19.0.0"), 16));
        assert!(!pool.overlaps(v4("10.0.0.0"), 8));
        // The IPv6 projection embeds the pool under fd11:5ca1:ab1e:1::/96.
        assert!(pool.overlaps(v4("fd11:5ca1:ab1e:1::c612:0"), 112));
        assert!(pool.overlaps(v4("fd00::"), 8));
        assert!(!pool.overlaps(v4("fd11:5ca1:ab1e:2::"), 64));
        assert!(!pool.overlaps(v4("2001:db8::"), 32));
        assert_eq!(
            pool.ipv6_network(),
            ("fd11:5ca1:ab1e:1::c612:0".parse().unwrap(), 112)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_round_trip_normalizes_host_bits_and_rejects_unusable_ranges() {
        let range: FakeIpRange = "198.18.99.1/16".parse().unwrap();
        assert_eq!(range, FakeIpRange::default());
        assert_eq!(range.to_string(), "198.18.0.0/16");
        assert_eq!(range.netmask(), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(range.prefix_len(), 16);
        assert_eq!(range.network(), Ipv4Addr::new(198, 18, 0, 0));
        let encoded = serde_json::to_string(&range).unwrap();
        assert_eq!(encoded, "\"198.18.0.0/16\"");
        assert_eq!(
            serde_json::from_str::<FakeIpRange>(&encoded).unwrap(),
            range
        );
        for value in [
            "198.18.0.1",
            "198.18.0.1/31",
            "198.18.0.1/32",
            "198.18.0.1/33",
            "198.18.0.1/0",
            "127.0.0.1/16",
            "0.0.0.0/8",
            "224.0.0.1/16",
            "169.254.0.1/16",
            "240.0.0.1/16",
            "fd00::1/64",
            "128.0.0.0/1",
        ] {
            assert!(value.parse::<FakeIpRange>().is_err(), "{value}");
        }
    }

    #[test]
    fn restored_mappings_keep_their_addresses_and_give_way_to_held_ones() {
        let range: FakeIpRange = "10.42.0.1/29".parse().unwrap();
        let before = FakeDnsStore::default().with_range(Some(range));
        let start = Instant::now();
        let a = before.allocate_ipv4_at("a.example", start).unwrap();
        let b = before
            .allocate_ipv4_at("b.example", start + Duration::from_secs(1))
            .unwrap();
        let (changes, mappings) = before.mappings();
        assert_eq!(changes, 2);
        assert_eq!(
            mappings,
            vec![(b, "b.example".to_string()), (a, "a.example".to_string())],
            "the most recently used first"
        );

        // The next Core met a name before it took the file back.
        let after = FakeDnsStore::default().with_range(Some(range));
        let held = after.allocate_ipv4("c.example").unwrap();
        let restored = after.restore(mappings.clone());
        assert_eq!(
            restored,
            mappings.iter().filter(|(ip, _)| *ip != held).count()
        );
        for (ip, domain) in &mappings {
            let expected = if *ip == held { "c.example" } else { domain };
            assert_eq!(after.lookup_ipv4(*ip).as_deref(), Some(expected));
        }

        // Another pool, and a name the file names twice, take back nothing
        // more.
        let elsewhere = FakeDnsStore::default().with_range(Some("10.43.0.1/29".parse().unwrap()));
        assert_eq!(elsewhere.restore(mappings), 0);
        let twice = FakeDnsStore::default().with_range(Some(range));
        assert_eq!(
            twice.restore([(a, "x.example".into()), (b, "X.example.".into())]),
            1
        );
        assert_eq!(twice.lookup_ipv4(b), None);
    }

    #[test]
    fn a_full_pool_gives_the_least_recently_used_idle_addresses_to_new_names() {
        let store = FakeDnsStore::default().with_range(Some("10.42.0.1/29".parse().unwrap()));
        let start = Instant::now();
        let issued = (0..5u64)
            .map(|index| {
                let domain = format!("host-{index}.example");
                let at = start + Duration::from_secs(index);
                (store.allocate_ipv4_at(&domain, at).unwrap(), domain)
            })
            .collect::<Vec<_>>();
        // Within the window one name is answered again and a flow goes to
        // another; the other three go unused.
        let later = start + REUSE_IDLE / 2;
        assert_eq!(
            store.allocate_ipv4_at(&issued[0].1, later).unwrap(),
            issued[0].0
        );
        assert!(store.lookup_ipv4_at(issued[1].0, later).is_some());
        let now = start + REUSE_IDLE + Duration::from_secs(10);
        // The idle ones go least recently used first; those used within the
        // window keep their addresses, and once the idle ones are taken the
        // pool refuses.
        for (index, name) in ["new", "second", "third"].into_iter().enumerate() {
            let domain = format!("{name}.example");
            assert_eq!(
                store.allocate_ipv4_at(&domain, now).unwrap(),
                issued[2 + index].0
            );
            assert_eq!(
                store.lookup_ipv4_at(issued[2 + index].0, now).as_deref(),
                Some(domain.as_str())
            );
            // An address let go but not yet handed out names nothing.
            for (ip, _) in &issued[3 + index..] {
                assert_eq!(store.lookup_ipv4_at(*ip, now), None);
            }
        }
        for (ip, domain) in &issued[..2] {
            assert_eq!(
                store.lookup_ipv4_at(*ip, now).as_deref(),
                Some(domain.as_str())
            );
        }
        assert!(store.allocate_ipv4_at("fourth.example", now).is_err());
        assert_eq!(store.len(), 5);
    }

    /// A sweep looks at a slice of the pool, not at every mapping it holds:
    /// a /16 full of them cost milliseconds with the write lock held, on the
    /// packet pump that was answering the query. So an idle address past the
    /// slice the sweep is at is not found yet -- the next sweep moves on and
    /// finds it.
    #[test]
    fn a_sweep_reaches_an_idle_address_a_slice_at_a_time() {
        let range: FakeIpRange = "10.42.0.0/21".parse().unwrap();
        let span = range.capacity();
        assert!(span > REUSE_BATCH, "the pool must be bigger than one slice");
        let store = FakeDnsStore::default().with_range(Some(range));
        let start = Instant::now();
        let issued = (0..span)
            .map(|index| {
                let domain = format!("host-{index}.example");
                (
                    store.allocate_ipv4_at(&domain, start).expect("an address"),
                    domain,
                )
            })
            .collect::<Vec<_>>();

        // One address goes idle, at the start of the slice after the one the
        // sweep stands at; every other mapping is used just now.
        let now = start + REUSE_IDLE + Duration::from_secs(1);
        let offset_from_sweep = |ip: Ipv4Addr| {
            let from_first = u32::from(ip) - range.first();
            (from_first + span - store.read().sweep_from) % span
        };
        let idle = issued
            .iter()
            .find(|(ip, _)| offset_from_sweep(*ip) == REUSE_BATCH)
            .expect("an address one slice past the sweep")
            .0;
        for (ip, _) in &issued {
            if *ip != idle {
                assert!(store.lookup_ipv4_at(*ip, now).is_some(), "{ip} is in use");
            }
        }

        // The sweep looks at its own slice and finds nothing to give, so the
        // name is refused even though the pool holds an idle address.
        assert!(store.allocate_ipv4_at("first.example", now).is_err());
        // The next sweep has moved on by a slice, and there it is.
        assert_eq!(
            store
                .allocate_ipv4_at("second.example", now)
                .expect("the sweep moved on to the slice holding the idle address"),
            idle
        );
        assert_eq!(
            store.lookup_ipv4_at(idle, now).as_deref(),
            Some("second.example")
        );
    }

    /// A pool a probe found no room in is remembered, so a name arriving at
    /// a full pool whose mappings are all in use costs no look at every
    /// address. What matters is that the memory goes the moment an address
    /// is let go.
    #[test]
    fn a_pool_with_no_room_takes_names_again_once_one_address_is_let_go() {
        let store = FakeDnsStore::default().with_range(Some("10.42.0.1/29".parse().unwrap()));
        let start = Instant::now();
        for index in 0..5 {
            store
                .allocate_ipv4_at(&format!("host-{index}.example"), start)
                .expect("an address");
        }
        // No room, and nothing idle to take: refused twice over.
        assert!(store.allocate_ipv4_at("early.example", start).is_err());
        assert!(store
            .allocate_ipv4_at("early-again.example", start)
            .is_err());

        // The mappings have gone idle, so a sweep lets one go and the name
        // refused a moment ago is served.
        let now = start + REUSE_IDLE + Duration::from_secs(1);
        let taken = store
            .allocate_ipv4_at("late.example", now)
            .expect("an idle mapping's address");
        assert_eq!(
            store.lookup_ipv4_at(taken, now).as_deref(),
            Some("late.example")
        );
    }

    #[test]
    fn a_late_stamp_never_moves_a_use_back() {
        // A /30 pool has one address.
        let store = FakeDnsStore::default().with_range(Some("10.42.0.1/30".parse().unwrap()));
        let start = Instant::now();
        let ip = store.allocate_ipv4_at("held.example", start).unwrap();
        assert!(store.lookup_ipv4_at(ip, start + REUSE_IDLE).is_some());
        // A lookup that read the clock earlier stamps after it.
        assert!(store.lookup_ipv4_at(ip, start).is_some());
        let within = start + REUSE_IDLE + Duration::from_secs(10);
        assert!(store.allocate_ipv4_at("new.example", within).is_err());
        let past = start + REUSE_IDLE * 2 + Duration::from_secs(10);
        assert_eq!(store.allocate_ipv4_at("new.example", past).unwrap(), ip);
    }

    #[test]
    fn configured_pool_excludes_network_gateway_and_broadcast_and_keeps_mappings_in_use() {
        let store = FakeDnsStore::default().with_range(Some("10.42.0.1/29".parse().unwrap()));
        let mut issued = Vec::new();
        for index in 0..5 {
            let domain = format!("host-{index}.example");
            let ip = store.allocate_ipv4(&domain).unwrap();
            assert_eq!(ip.octets()[..3], [10, 42, 0]);
            assert!((2..=6).contains(&ip.octets()[3]));
            assert!(!issued.iter().any(|(old, _)| old == &ip));
            issued.push((ip, domain));
        }
        assert!(store.allocate_ipv4("overflow.example").is_err());
        assert_eq!(store.len(), 5);
        for (ip, domain) in issued {
            assert_eq!(store.lookup_ipv4(ip).as_deref(), Some(domain.as_str()));
            assert_eq!(store.allocate_ipv4(&domain).unwrap(), ip);
        }
    }

    #[test]
    fn range_changes_keep_old_identities_and_never_alias_ipv6_between_pools() {
        let old = FakeDnsStore::default().with_range(Some("10.42.0.1/30".parse().unwrap()));
        let first = old.allocate_ipv4("old.example").unwrap();
        let old_v6 = old.allocate_ipv6("old.example").unwrap();
        let new = old.with_range(Some("10.43.0.1/30".parse().unwrap()));
        let second = new.allocate_ipv4("new.example").unwrap();
        let new_v6 = new.allocate_ipv6("new.example").unwrap();
        assert_ne!(old_v6, new_v6);
        assert_eq!(new.lookup_ipv4(first).as_deref(), Some("old.example"));
        assert_eq!(new.lookup_ipv6(old_v6).as_deref(), Some("old.example"));
        assert_eq!(old.lookup_ipv4(second).as_deref(), Some("new.example"));
        assert!(new.contains_ipv4(first));
        assert!(new.contains_ipv6(old_v6));
        assert!(new.contains_ipv4("10.43.0.1".parse().unwrap()));
        assert!(!new.contains_ipv4("10.42.0.3".parse().unwrap()));
        let original = new.with_range(Some("10.42.0.1/30".parse().unwrap()));
        assert!(original.allocate_ipv4("different.example").is_err());
        assert_eq!(original.allocate_ipv4("old.example").unwrap(), first);
    }

    #[test]
    fn public_allocation_checks_exclude_control_addresses_in_both_families() {
        let range: FakeIpRange = "10.42.0.0/30".parse().unwrap();
        for (ip, allocatable) in [
            ("10.42.0.0", false),
            ("10.42.0.1", false),
            ("10.42.0.2", true),
            ("10.42.0.3", false),
            ("10.42.0.4", false),
        ] {
            let ip = ip.parse().unwrap();
            assert_eq!(range.is_allocatable(ip), allocatable);
            assert_eq!(
                range.is_allocatable_ipv6(project_ipv4_to_ipv6(ip)),
                allocatable
            );
        }
        assert!(!range.is_allocatable_ipv6("fd00:6572:6769:6f00::2".parse().unwrap()));
        assert!(!range.is_allocatable_ipv6("fd11:5ca1:ab1e:2::a2a:2".parse().unwrap()));
    }

    #[test]
    fn current_range_checks_pair_ipv4_and_ipv6_and_do_not_claim_other_pools() {
        let store = FakeDnsStore::default();
        for ip in ["198.18.0.0", "198.18.0.1", "198.18.255.255"] {
            let ip = ip.parse().unwrap();
            assert!(store.contains_ipv4(ip));
            assert!(store.contains_ipv6(project_ipv4_to_ipv6(ip)));
        }
        for ip in ["198.17.255.255", "198.19.0.0", "10.42.0.1"] {
            let ip = ip.parse().unwrap();
            assert!(!store.contains_ipv4(ip));
            assert!(!store.contains_ipv6(project_ipv4_to_ipv6(ip)));
        }
        assert!(!store.contains_ipv6("fd11:5ca1:ab1e:2::c612:1".parse().unwrap()));
    }
}
