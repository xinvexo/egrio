//! A rule set's domain entries, hashed by shape over the rule set's own
//! text block instead of a string per entry.

use std::collections::HashSet;
use std::fmt;
use std::hash::BuildHasher;

use hashbrown::{DefaultHashBuilder, HashTable};

use super::normalize_domain;
use crate::profile::RuleSetEntries;

/// The hashed entry shapes of a rule set's names: that name, it and every
/// subdomain, every subdomain, and exactly one more label. Each shape
/// indexes entries of the shared block by the text after the shape's
/// prefix; an entry whose text there is not its normalized name -- it has
/// to be lowercased or trimmed first, or something follows it -- is kept as
/// a normalized copy instead, which real rule lists almost never need.
///
/// Keys hash with hashbrown's default hasher (foldhash, seeded per
/// process): entries come from the user's own providers and hosts from
/// local applications, so lookup speed matters more here than resistance
/// to crafted collisions.
#[derive(Clone, Default)]
pub(super) struct DomainIndex {
    entries: RuleSetEntries,
    hasher: DefaultHashBuilder,
    exact: Shape,
    suffix: Shape,
    subdomain: Shape,
    single_label: Shape,
}

#[derive(Clone, Default)]
struct Shape {
    /// Bytes of the entry text before the name.
    prefix: usize,
    indices: HashTable<u32>,
    normalized: HashSet<Box<str>>,
}

/// What [`DomainIndex::insert`] did with an entry.
pub(super) enum Insert {
    Indexed,
    /// A `*` inside the name: the caller matches it as a pattern.
    Wildcard(String),
    Skipped,
}

impl DomainIndex {
    /// Over a `domain` rule set's entries, whose prefix says the shape:
    /// `example.com`, `+.example.com`, `.example.com` and `*.example.com`.
    pub(super) fn new(entries: RuleSetEntries) -> Self {
        Self::with_prefixes(entries, 0, "+.".len())
    }

    /// Over a `classical` rule set's entries, whose names follow the rule
    /// kind: `DOMAIN,example.com` and `DOMAIN-SUFFIX,example.com`.
    pub(super) fn classical(entries: RuleSetEntries) -> Self {
        Self::with_prefixes(entries, "DOMAIN,".len(), "DOMAIN-SUFFIX,".len())
    }

    fn with_prefixes(entries: RuleSetEntries, exact: usize, suffix: usize) -> Self {
        let shape = |prefix| Shape {
            prefix,
            ..Shape::default()
        };
        Self {
            entries,
            hasher: DefaultHashBuilder::default(),
            exact: shape(exact),
            suffix: shape(suffix),
            subdomain: shape(".".len()),
            single_label: shape("*.".len()),
        }
    }

    /// Classifies entry `index` of the block by its shape prefix and
    /// indexes it.
    pub(super) fn insert(&mut self, index: usize) -> Insert {
        let entry = normalize_domain(self.entries.get(index).unwrap_or_default());
        let (shape, name) = if let Some(rest) = entry.strip_prefix("+.") {
            (&mut self.suffix, rest)
        } else if let Some(rest) = entry.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') {
                return Insert::Wildcard(entry.into_owned());
            }
            (&mut self.single_label, rest)
        } else if let Some(rest) = entry.strip_prefix('.') {
            (&mut self.subdomain, rest)
        } else if entry.contains('*') {
            return Insert::Wildcard(entry.into_owned());
        } else {
            (&mut self.exact, &*entry)
        };
        shape.hold(&self.entries, &self.hasher, index, name)
    }

    /// Indexes entry `index` of the block as the one name `name`, which is
    /// normalized.
    pub(super) fn insert_exact(&mut self, index: usize, name: &str) -> Insert {
        self.exact.hold(&self.entries, &self.hasher, index, name)
    }

    /// Indexes entry `index` of the block as `name`, which is normalized,
    /// and every subdomain of it.
    pub(super) fn insert_suffix(&mut self, index: usize, name: &str) -> Insert {
        self.suffix.hold(&self.entries, &self.hasher, index, name)
    }

    /// Releases the spare capacity insertion left in the tables.
    pub(super) fn shrink_to_fit(&mut self) {
        let entries = &self.entries;
        let hasher = &self.hasher;
        for shape in [
            &mut self.exact,
            &mut self.suffix,
            &mut self.subdomain,
            &mut self.single_label,
        ] {
            let prefix = shape.prefix;
            shape
                .indices
                .shrink_to_fit(|&held| hasher.hash_one(held_name(entries, held, prefix)));
            shape.normalized.shrink_to_fit();
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        [
            &self.exact,
            &self.suffix,
            &self.subdomain,
            &self.single_label,
        ]
        .iter()
        .all(|shape| shape.indices.is_empty() && shape.normalized.is_empty())
    }

    /// Whether a normalized host matches: the name itself, a domain it is
    /// under, or a single-label wildcard parent.
    pub(super) fn matches(&self, host: &str) -> bool {
        if self.holds(&self.exact, host) || self.holds(&self.suffix, host) {
            return true;
        }
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if self.holds(&self.suffix, parent) || self.holds(&self.subdomain, parent) {
                return true;
            }
            rest = parent;
        }
        host.split_once('.').is_some_and(|(label, parent)| {
            !label.is_empty() && self.holds(&self.single_label, parent)
        })
    }

    fn holds(&self, shape: &Shape, name: &str) -> bool {
        if !shape.indices.is_empty() {
            let hash = self.hasher.hash_one(name);
            let prefix = shape.prefix;
            if shape
                .indices
                .find(hash, |&held| {
                    self.entries.bytes(held as usize).get(prefix..) == Some(name.as_bytes())
                })
                .is_some()
            {
                return true;
            }
        }
        !shape.normalized.is_empty() && shape.normalized.contains(name)
    }
}

impl Shape {
    /// Holds `name` for entry `index`: the entry itself where its text
    /// after the prefix is the name, a copy of the name otherwise.
    fn hold(
        &mut self,
        entries: &RuleSetEntries,
        hasher: &DefaultHashBuilder,
        index: usize,
        name: &str,
    ) -> Insert {
        if name.is_empty() {
            return Insert::Skipped;
        }
        let prefix = self.prefix;
        let in_block = u32::try_from(index).ok().filter(|_| {
            entries
                .get(index)
                .map(str::as_bytes)
                .and_then(|entry| entry.get(prefix..))
                == Some(name.as_bytes())
        });
        match in_block {
            Some(index) => {
                let hash = hasher.hash_one(name);
                if self
                    .indices
                    .find(hash, |&held| held_name(entries, held, prefix) == name)
                    .is_none()
                {
                    self.indices.insert_unique(hash, index, |&held| {
                        hasher.hash_one(held_name(entries, held, prefix))
                    });
                }
            }
            None => {
                self.normalized.insert(name.into());
            }
        }
        Insert::Indexed
    }
}

/// The name a held entry stands for. An entry is only held where its text
/// after the prefix is a name, so the prefix ends on a character boundary.
fn held_name(entries: &RuleSetEntries, held: u32, prefix: usize) -> &str {
    &entries.get(held as usize).unwrap_or_default()[prefix..]
}

impl fmt::Debug for DomainIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |shape: &Shape| shape.indices.len() + shape.normalized.len();
        f.debug_struct("DomainIndex")
            .field("exact", &count(&self.exact))
            .field("suffix", &count(&self.suffix))
            .field("subdomain", &count(&self.subdomain))
            .field("single_label", &count(&self.single_label))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(entries: &[&str]) -> (DomainIndex, Vec<String>) {
        let mut index = DomainIndex::new(entries.iter().collect());
        let mut wildcards = Vec::new();
        for position in 0..entries.len() {
            if let Insert::Wildcard(pattern) = index.insert(position) {
                wildcards.push(pattern);
            }
        }
        index.shrink_to_fit();
        (index, wildcards)
    }

    #[test]
    fn each_shape_matches_what_its_prefix_says() {
        let (index, _) = index(&[
            "full.example",
            "+.suffix.example",
            ".sub.example",
            "*.one.example",
        ]);
        assert!(index.matches("full.example"));
        assert!(!index.matches("a.full.example"));
        assert!(index.matches("suffix.example"));
        assert!(index.matches("a.b.suffix.example"));
        assert!(!index.matches("sub.example"));
        assert!(index.matches("a.sub.example"));
        assert!(!index.matches("one.example"));
        assert!(index.matches("a.one.example"));
        assert!(!index.matches("a.b.one.example"));
        assert!(!index.matches("other.example"));
    }

    #[test]
    fn entries_needing_normalization_still_match() {
        let (index, wildcards) = index(&["+.Upper.Example.", "  spaced.example  ", "a.*.example"]);
        assert!(index.matches("x.upper.example"));
        assert!(index.matches("spaced.example"));
        assert_eq!(wildcards, ["a.*.example"]);
    }

    /// A classical entry is held in the block where its text ends in the
    /// name, and as a copy where the name had to be made from it.
    #[test]
    fn a_classical_entry_is_held_by_the_name_its_text_ends_in() {
        let entries: RuleSetEntries = [
            "DOMAIN,full.example",
            "DOMAIN-SUFFIX,suffix.example",
            "domain-suffix,lower-kind.example",
            "DOMAIN-SUFFIX,Upper.Example",
            "DOMAIN, spaced.example",
            "DOMAIN-SUFFIX,tail.example,extra",
        ]
        .into_iter()
        .collect();
        let mut index = DomainIndex::classical(entries);
        index.insert_exact(0, "full.example");
        index.insert_suffix(1, "suffix.example");
        index.insert_suffix(2, "lower-kind.example");
        index.insert_suffix(3, "upper.example");
        index.insert_exact(4, "spaced.example");
        index.insert_suffix(5, "tail.example");
        index.shrink_to_fit();

        assert_eq!(index.exact.indices.len(), 1);
        assert_eq!(index.exact.normalized.len(), 1);
        assert_eq!(index.suffix.indices.len(), 2);
        assert_eq!(index.suffix.normalized.len(), 2);
        assert!(index.matches("full.example"));
        assert!(!index.matches("a.full.example"));
        assert!(index.matches("spaced.example"));
        for suffix in [
            "suffix.example",
            "lower-kind.example",
            "upper.example",
            "tail.example",
        ] {
            assert!(index.matches(suffix), "{suffix}");
            assert!(index.matches(&format!("a.b.{suffix}")), "{suffix}");
        }
        assert!(!index.matches("example"));
        assert!(matches!(index.insert_exact(0, ""), Insert::Skipped));
    }

    #[test]
    fn duplicate_and_empty_entries_do_not_grow_the_index() {
        let (index, _) = index(&["dup.example", "dup.example", "+.", ""]);
        assert_eq!(index.exact.indices.len(), 1);
        assert!(index.suffix.indices.is_empty());
        assert!(!index.is_empty());
    }
}
