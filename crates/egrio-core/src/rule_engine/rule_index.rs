//! Where a decision looks for the profile's own rules: its names, keywords
//! and networks found over the block the profile holds the rules in, the
//! rest tried in order.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::BuildHasher;
use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use hashbrown::{DefaultHashBuilder, HashTable};

use super::{cidr_mask_u128, cidr_mask_u32, CidrRange, RouteMatchKind, RuleMatcher};
use crate::profile::RouteRules;

/// Route decisions preserve linear first-match-wins semantics: everything
/// the tables find carries its rule's place in the profile, and the
/// smallest place wins. Exact domains and domain suffixes resolve through
/// hash lookups (suffixes by walking the host's label boundaries), keywords
/// through one automaton the host is run through once, and networks through
/// a hash lookup at each prefix length the rules have; every other rule
/// kind stays an in-order scan that stops as soon as its place can no
/// longer win. A later rule of a name, keyword or network some earlier rule
/// has joins the scan: it wins only when a UDP flow skips the first one's
/// outbound.
#[derive(Clone, Default)]
pub(super) struct RuleIndex {
    hasher: DefaultHashBuilder,
    exact: Names,
    suffix: Names,
    keywords: Keywords,
    networks: Networks,
    /// The rules no table holds, in the profile's order.
    pub(super) scan: Vec<ScannedRule>,
}

/// A rule tried in its turn.
#[derive(Debug, Clone)]
pub(super) struct ScannedRule {
    /// The rule's place in the profile.
    pub(super) position: u32,
    /// An IP rule without `no-resolve`: a destination known only by name is
    /// resolved before this rule is tried.
    pub(super) resolves: bool,
    pub(super) matcher: RuleMatcher,
}

/// Each name's first rule. A rule is held by its place where its payload is
/// the name as hosts are compared, which nearly every rule's is, and under
/// a copy of the name where the payload had to be trimmed or lowercased to
/// give it.
///
/// Names hash with hashbrown's default hasher (foldhash, seeded per
/// process): the rules are the user's own and the hosts come from local
/// applications, so lookup speed matters more here than resistance to
/// crafted collisions.
#[derive(Clone, Default)]
struct Names {
    written: HashTable<u32>,
    normalized: HashMap<Box<str>, u32>,
}

/// Each keyword's first rule: one automaton finds every keyword a name
/// holds, where trying each in turn searches the name once per keyword.
#[derive(Clone, Default)]
struct Keywords {
    automaton: Option<AhoCorasick>,
    /// The rule of each of the automaton's patterns.
    places: Box<[u32]>,
}

/// Each network's first `IP-CIDR` rule, by its prefix length and its
/// address under that length: networks nest or are apart, so the rules an
/// address is in are found by asking for its network at each length some
/// rule has.
#[derive(Clone, Default)]
struct Networks {
    v4: hashbrown::HashMap<(u8, u32), u32>,
    v6: hashbrown::HashMap<(u8, u128), u32>,
    /// The prefix lengths the rules of each family have, each once.
    v4_lengths: Vec<u8>,
    v6_lengths: Vec<u8>,
    /// The held rules that ask for a name's address, the first for each
    /// outbound, in the profile's order: whether a rule's outbound takes a
    /// flow is all that tells two of them apart.
    asking: Vec<u32>,
}

/// Collects the rules as they are compiled, in the profile's order.
#[derive(Default)]
pub(super) struct RuleIndexBuilder {
    index: RuleIndex,
    /// The keyword rules, which make one automaton once all are known.
    keywords: Vec<(u32, Box<str>)>,
    /// The outbounds, by their place in the block, that a held rule already
    /// asks an address for.
    asking_outbounds: HashSet<u32>,
}

impl RuleIndexBuilder {
    /// Holds the `DOMAIN` rule at `position` under `name`, its payload
    /// normalized. False when an earlier rule has the name: this one is to
    /// be scanned.
    pub(super) fn hold_exact(&mut self, rules: &RouteRules, position: u32, name: &str) -> bool {
        let index = &mut self.index;
        index.exact.hold(rules, &index.hasher, position, name)
    }

    /// [`Self::hold_exact`] for a `DOMAIN-SUFFIX` rule.
    pub(super) fn hold_suffix(&mut self, rules: &RouteRules, position: u32, name: &str) -> bool {
        let index = &mut self.index;
        index.suffix.hold(rules, &index.hasher, position, name)
    }

    /// Takes any other rule: into the table of its kind where it is the
    /// first of its keyword or network, into the scan otherwise.
    pub(super) fn hold(
        &mut self,
        rules: &RouteRules,
        position: u32,
        resolves: bool,
        matcher: RuleMatcher,
    ) {
        match matcher {
            RuleMatcher::DomainKeyword(keyword) => self.keywords.push((position, keyword)),
            RuleMatcher::IpCidr(range) if self.index.networks.hold(position, &range) => {
                if resolves
                    && self
                        .asking_outbounds
                        .insert(rules.outbound_place(position as usize))
                {
                    self.index.networks.asking.push(position);
                }
            }
            matcher => self.index.scan.push(ScannedRule {
                position,
                resolves,
                matcher,
            }),
        }
    }

    /// The index, with its storage trimmed to the rules it holds.
    pub(super) fn finish(mut self, rules: &RouteRules) -> RuleIndex {
        let mut index = self.index;
        // Each keyword's first rule goes to the automaton, its later ones
        // to the scan; all of them when the automaton does not build.
        let mut patterns: Vec<&str> = Vec::new();
        let mut places = Vec::new();
        let mut seen = HashSet::new();
        let mut scanned = Vec::new();
        for (position, keyword) in &self.keywords {
            if seen.insert(&**keyword) {
                patterns.push(keyword);
                places.push(*position);
            } else {
                scanned.push(*position);
            }
        }
        match AhoCorasick::new(&patterns) {
            Ok(automaton) if !patterns.is_empty() => {
                index.keywords = Keywords {
                    automaton: Some(automaton),
                    places: places.into_boxed_slice(),
                };
            }
            _ => {
                scanned = self
                    .keywords
                    .iter()
                    .map(|(position, _)| *position)
                    .collect()
            }
        }
        if !scanned.is_empty() {
            let scanned: HashSet<u32> = scanned.into_iter().collect();
            for (position, keyword) in self.keywords.drain(..) {
                if scanned.contains(&position) {
                    index.scan.push(ScannedRule {
                        position,
                        resolves: false,
                        matcher: RuleMatcher::DomainKeyword(keyword),
                    });
                }
            }
            index.scan.sort_by_key(|rule| rule.position);
        }

        let hasher = &index.hasher;
        for names in [&mut index.exact, &mut index.suffix] {
            names
                .written
                .shrink_to_fit(|&held| hasher.hash_one(written_name(rules, held)));
            names.normalized.shrink_to_fit();
        }
        index.networks.v4.shrink_to_fit();
        index.networks.v6.shrink_to_fit();
        index.networks.v4_lengths.shrink_to_fit();
        index.networks.v6_lengths.shrink_to_fit();
        index.networks.asking.shrink_to_fit();
        index.scan.shrink_to_fit();
        index
    }
}

impl RuleIndex {
    /// The rules the tables hold whose name or keyword a normalized host
    /// matches, each with the kind it matched by.
    pub(super) fn by_host(
        &self,
        rules: &RouteRules,
        host: &str,
        mut found: impl FnMut(usize, RouteMatchKind),
    ) {
        if let Some(position) = self.exact.get(rules, &self.hasher, host) {
            found(position, RouteMatchKind::Domain);
        }
        if !self.suffix.is_empty() {
            let mut suffix = host;
            loop {
                if let Some(position) = self.suffix.get(rules, &self.hasher, suffix) {
                    found(position, RouteMatchKind::DomainSuffix);
                }
                match suffix.split_once('.') {
                    Some((_, rest)) => suffix = rest,
                    None => break,
                }
            }
        }
        if let Some(automaton) = &self.keywords.automaton {
            for keyword in automaton.find_overlapping_iter(host) {
                found(
                    self.keywords.places[keyword.pattern().as_usize()] as usize,
                    RouteMatchKind::DomainKeyword,
                );
            }
        }
    }

    /// The `IP-CIDR` rules the tables hold whose network has `ip`.
    pub(super) fn by_address(&self, ip: IpAddr, mut found: impl FnMut(usize)) {
        let networks = &self.networks;
        match ip.to_canonical() {
            IpAddr::V4(address) => {
                let bits = u32::from(address);
                for &length in &networks.v4_lengths {
                    if let Some(&position) =
                        networks.v4.get(&(length, bits & cidr_mask_u32(length)))
                    {
                        found(position as usize);
                    }
                }
            }
            IpAddr::V6(address) => {
                let bits = u128::from(address);
                for &length in &networks.v6_lengths {
                    if let Some(&position) =
                        networks.v6.get(&(length, bits & cidr_mask_u128(length)))
                    {
                        found(position as usize);
                    }
                }
            }
        }
    }

    /// The first rule the tables hold that asks for a name's address before
    /// it is tried and whose outbound `taken` says takes the flow.
    pub(super) fn first_asking(&self, taken: impl Fn(usize) -> bool) -> Option<usize> {
        self.networks
            .asking
            .iter()
            .map(|&position| position as usize)
            .find(|&position| taken(position))
    }
}

impl Names {
    fn hold(
        &mut self,
        rules: &RouteRules,
        hasher: &DefaultHashBuilder,
        position: u32,
        name: &str,
    ) -> bool {
        if self.get(rules, hasher, name).is_some() {
            return false;
        }
        if written_name(rules, position) == name.as_bytes() {
            self.written
                .insert_unique(hasher.hash_one(name.as_bytes()), position, |&held| {
                    hasher.hash_one(written_name(rules, held))
                });
        } else {
            self.normalized.insert(name.into(), position);
        }
        true
    }

    fn get(&self, rules: &RouteRules, hasher: &DefaultHashBuilder, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        let written = self
            .written
            .find(hasher.hash_one(name_bytes), |&held| {
                written_name(rules, held) == name_bytes
            })
            .copied();
        written
            .or_else(|| self.normalized.get(name).copied())
            .map(|position| position as usize)
    }

    fn is_empty(&self) -> bool {
        self.written.is_empty() && self.normalized.is_empty()
    }
}

impl Networks {
    /// Holds the rule at `position` under its network. False when an
    /// earlier rule has the network: this one is to be scanned.
    fn hold(&mut self, position: u32, range: &CidrRange) -> bool {
        let length = range.prefix_len;
        match range.network {
            IpAddr::V4(address) => {
                let key = (length, u32::from(address) & cidr_mask_u32(length));
                if self.v4.contains_key(&key) {
                    return false;
                }
                self.v4.insert(key, position);
                if !self.v4_lengths.contains(&length) {
                    self.v4_lengths.push(length);
                }
            }
            IpAddr::V6(address) => {
                let key = (length, u128::from(address) & cidr_mask_u128(length));
                if self.v6.contains_key(&key) {
                    return false;
                }
                self.v6.insert(key, position);
                if !self.v6_lengths.contains(&length) {
                    self.v6_lengths.push(length);
                }
            }
        }
        true
    }
}

/// The name a rule held by its place stands for: its payload.
fn written_name(rules: &RouteRules, position: u32) -> &[u8] {
    rules.payload_bytes(position as usize)
}

impl fmt::Debug for RuleIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |names: &Names| names.written.len() + names.normalized.len();
        f.debug_struct("RuleIndex")
            .field("exact", &count(&self.exact))
            .field("suffix", &count(&self.suffix))
            .field("keywords", &self.keywords.places.len())
            .field(
                "networks",
                &(self.networks.v4.len() + self.networks.v6.len()),
            )
            .field("scan", &self.scan.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{RouteRule, RuleKind};

    fn rules(kind: RuleKind, payloads: &[&str], outbounds: &[&str]) -> RouteRules {
        payloads
            .iter()
            .zip(outbounds.iter().cycle())
            .map(|(payload, outbound)| RouteRule {
                kind,
                payload: Some(payload),
                outbound,
                no_resolve: false,
            })
            .collect()
    }

    fn by_host(index: &RuleIndex, rules: &RouteRules, host: &str) -> Vec<(usize, RouteMatchKind)> {
        let mut found = Vec::new();
        index.by_host(rules, host, |position, kind| found.push((position, kind)));
        found.sort_unstable_by_key(|&(position, _)| position);
        found
    }

    fn by_address(index: &RuleIndex, ip: &str) -> Vec<usize> {
        let mut found = Vec::new();
        index.by_address(ip.parse().expect("an address"), |position| {
            found.push(position)
        });
        found.sort_unstable();
        found
    }

    /// A name is held once, by the first rule that has it, in the block
    /// where the payload reads as the name and as a copy where it does not.
    #[test]
    fn a_name_is_held_by_its_first_rule_wherever_its_text_is() {
        let rules = rules(
            RuleKind::DomainSuffix,
            &[
                "plain.example",
                "Upper.Example",
                "plain.example",
                "upper.example",
                "last.example.",
            ],
            &["Proxy"],
        );
        let mut builder = RuleIndexBuilder::default();
        let held: Vec<bool> = [
            "plain.example",
            "upper.example",
            "plain.example",
            "upper.example",
            "last.example",
        ]
        .iter()
        .enumerate()
        .map(|(position, name)| builder.hold_suffix(&rules, position as u32, name))
        .collect();
        let index = builder.finish(&rules);

        assert_eq!(held, [true, true, false, false, true]);
        assert_eq!(index.suffix.written.len(), 1);
        assert_eq!(index.suffix.normalized.len(), 2);
        let suffix = RouteMatchKind::DomainSuffix;
        assert_eq!(by_host(&index, &rules, "plain.example"), [(0, suffix)]);
        assert_eq!(by_host(&index, &rules, "a.upper.example"), [(1, suffix)]);
        assert_eq!(by_host(&index, &rules, "last.example"), [(4, suffix)]);
        assert_eq!(by_host(&index, &rules, "example"), []);
    }

    /// The two tables are apart: a `DOMAIN` rule and a `DOMAIN-SUFFIX` rule
    /// of one name are both first, and a host that is the name finds both.
    #[test]
    fn exact_and_suffix_rules_of_one_name_are_both_held() {
        let rules = rules(RuleKind::Domain, &["both.example", "both.example"], &["A"]);
        let mut builder = RuleIndexBuilder::default();
        assert!(builder.hold_exact(&rules, 0, "both.example"));
        assert!(builder.hold_suffix(&rules, 1, "both.example"));
        let index = builder.finish(&rules);
        assert_eq!(
            by_host(&index, &rules, "both.example"),
            [
                (0, RouteMatchKind::Domain),
                (1, RouteMatchKind::DomainSuffix)
            ]
        );
        assert_eq!(
            by_host(&index, &rules, "www.both.example"),
            [(1, RouteMatchKind::DomainSuffix)]
        );
    }

    /// Every keyword a name holds is found in one pass; a keyword's second
    /// rule is scanned.
    #[test]
    fn keywords_are_found_together_and_a_repeated_one_is_scanned() {
        let rules = rules(
            RuleKind::DomainKeyword,
            &["goo", "ads", "goo", ".com"],
            &["A"],
        );
        let mut builder = RuleIndexBuilder::default();
        for (position, rule) in rules.iter().enumerate() {
            let keyword = RuleMatcher::DomainKeyword(rule.payload.expect("a keyword").into());
            builder.hold(&rules, position as u32, false, keyword);
        }
        let index = builder.finish(&rules);

        let keyword = RouteMatchKind::DomainKeyword;
        assert_eq!(
            by_host(&index, &rules, "ads.google.com"),
            [(0, keyword), (1, keyword), (3, keyword)]
        );
        assert_eq!(by_host(&index, &rules, "example.org"), []);
        let scanned: Vec<u32> = index.scan.iter().map(|rule| rule.position).collect();
        assert_eq!(scanned, [2]);
    }

    /// An address finds the rule of every network it is in, whatever their
    /// prefix lengths; a network's second rule is scanned, and the rules
    /// that ask for a name's address are the first of each outbound.
    #[test]
    fn an_address_finds_every_network_it_is_in() {
        let rules = rules(
            RuleKind::IpCidr,
            &[
                "10.0.0.0/8",
                "10.1.0.0/16",
                "10.1.2.3/8",
                "fd00::/8",
                "0.0.0.0/0",
                "192.0.2.0/24",
            ],
            &["A", "B", "A"],
        );
        let mut builder = RuleIndexBuilder::default();
        for (position, rule) in rules.iter().enumerate() {
            let range = CidrRange::parse(rule.payload.expect("a network")).expect("a network");
            // Every rule but the last asks for a name's address.
            builder.hold(
                &rules,
                position as u32,
                position != 5,
                RuleMatcher::IpCidr(range),
            );
        }
        let index = builder.finish(&rules);

        assert_eq!(by_address(&index, "10.1.9.9"), [0, 1, 4]);
        assert_eq!(by_address(&index, "10.200.0.1"), [0, 4]);
        assert_eq!(by_address(&index, "192.0.2.7"), [4, 5]);
        assert_eq!(by_address(&index, "::ffff:10.1.9.9"), [0, 1, 4]);
        assert_eq!(by_address(&index, "fd00::1"), [3]);
        assert_eq!(by_address(&index, "2001:db8::1"), [0_usize; 0]);
        // `10.1.2.3/8` is `10.0.0.0/8` again.
        let scanned: Vec<u32> = index.scan.iter().map(|rule| rule.position).collect();
        assert_eq!(scanned, [2]);
        // A's first asking rule and B's; rule 3 is A's again and rule 5
        // does not ask.
        assert_eq!(index.networks.asking, [0, 1]);
        assert_eq!(index.first_asking(|_| true), Some(0));
        assert_eq!(index.first_asking(|position| position != 0), Some(1));
        assert_eq!(index.first_asking(|_| false), None);
    }
}
