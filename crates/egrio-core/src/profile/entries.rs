//! A rule provider's entry lines in one shared block.

use std::fmt;
use std::sync::Arc;

use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Most text one block addresses, so every offset fits in 31 bits.
const MAX_TEXT_BYTES: usize = i32::MAX as usize;

/// A rule provider's entry lines in one immutable block that every clone
/// shares: their text back to back, and where each one ends. The host keeps
/// the profile it started the Core with and the Core's matcher indexes the
/// same block, so a large rule set is stored once rather than as a string
/// per entry in each copy.
///
/// Serializes as a sequence of strings.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RuleSetEntries(Arc<Block>);

#[derive(Default, PartialEq, Eq)]
struct Block {
    text: Box<str>,
    /// Where each entry ends in `text`; entry `i` starts where `i - 1` ends.
    ends: Box<[u32]>,
}

impl RuleSetEntries {
    pub fn builder() -> RuleSetEntriesBuilder {
        RuleSetEntriesBuilder::default()
    }

    pub fn len(&self) -> usize {
        self.0.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.ends.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        (index < self.len()).then(|| self.entry(index))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        (0..self.len()).map(|index| self.entry(index))
    }

    /// Entry `index` as bytes, for lookups that compare many entries;
    /// `index` must be below [`Self::len`].
    pub(crate) fn bytes(&self, index: usize) -> &[u8] {
        let start = match index {
            0 => 0,
            _ => self.0.ends[index - 1] as usize,
        };
        &self.0.text.as_bytes()[start..self.0.ends[index] as usize]
    }

    fn entry(&self, index: usize) -> &str {
        let start = match index {
            0 => 0,
            _ => self.0.ends[index - 1] as usize,
        };
        &self.0.text[start..self.0.ends[index] as usize]
    }
}

impl fmt::Debug for RuleSetEntries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSetEntries")
            .field("entries", &self.len())
            .field("text_bytes", &self.0.text.len())
            .finish()
    }
}

impl<S: AsRef<str>> FromIterator<S> for RuleSetEntries {
    /// Panics past 2 GiB of text; build with [`RuleSetEntriesBuilder`] to
    /// handle that.
    fn from_iter<I: IntoIterator<Item = S>>(entries: I) -> Self {
        let mut builder = Self::builder();
        for entry in entries {
            builder
                .push(entry.as_ref())
                .expect("rule-set entries within 2 GiB of text");
        }
        builder.finish()
    }
}

impl From<Vec<String>> for RuleSetEntries {
    fn from(entries: Vec<String>) -> Self {
        entries.into_iter().collect()
    }
}

/// Collects entries into a [`RuleSetEntries`] block.
#[derive(Debug, Default)]
pub struct RuleSetEntriesBuilder {
    text: String,
    ends: Vec<u32>,
}

impl RuleSetEntriesBuilder {
    /// Appends one entry, refusing one that would take the block past
    /// 2 GiB of text.
    pub fn push(&mut self, entry: &str) -> Result<(), RuleSetTooLarge> {
        self.push_parts(&[entry])
    }

    /// Appends one entry that reads as `parts` back to back, so a prefix
    /// joins its entry without a string made for the two.
    pub fn push_parts(&mut self, parts: &[&str]) -> Result<(), RuleSetTooLarge> {
        let end = self.text.len() + parts.iter().map(|part| part.len()).sum::<usize>();
        if end > MAX_TEXT_BYTES {
            return Err(RuleSetTooLarge);
        }
        for part in parts {
            self.text.push_str(part);
        }
        self.ends.push(end as u32);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// The block, with its storage trimmed to the entries it holds.
    pub fn finish(self) -> RuleSetEntries {
        RuleSetEntries(Arc::new(Block {
            text: self.text.into_boxed_str(),
            ends: self.ends.into_boxed_slice(),
        }))
    }
}

/// Entries passing 2 GiB of text, more than one block addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSetTooLarge;

impl fmt::Display for RuleSetTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rule-set entries exceed 2 GiB of text")
    }
}

impl std::error::Error for RuleSetTooLarge {}

impl Serialize for RuleSetEntries {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for RuleSetEntries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;

        impl<'de> Visitor<'de> for Entries {
            type Value = RuleSetEntries;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of rule-set entry strings")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut builder = RuleSetEntries::builder();
                while seq.next_element_seed(Append(&mut builder))?.is_some() {}
                Ok(builder.finish())
            }
        }

        deserializer.deserialize_seq(Entries)
    }
}

/// Appends one deserialized string to the builder without an owned copy.
struct Append<'a>(&'a mut RuleSetEntriesBuilder);

impl<'de> DeserializeSeed<'de> for Append<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for Append<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a rule-set entry string")
    }

    fn visit_str<E: serde::de::Error>(self, entry: &str) -> Result<(), E> {
        self.0.push(entry).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_read_back_in_order_and_clones_share_one_block() {
        let entries: RuleSetEntries = ["+.example.com", "", "1.2.3.0/24"].into_iter().collect();
        assert_eq!(entries.len(), 3);
        let mut builder = RuleSetEntries::builder();
        builder.push_parts(&["+.", "example.com"]).unwrap();
        builder.push_parts(&[]).unwrap();
        builder.push("1.2.3.0/24").unwrap();
        assert_eq!(builder.finish(), entries);
        assert_eq!(
            entries.iter().collect::<Vec<_>>(),
            ["+.example.com", "", "1.2.3.0/24"]
        );
        assert_eq!(entries.get(2), Some("1.2.3.0/24"));
        assert_eq!(entries.get(3), None);

        let clone = entries.clone();
        assert!(Arc::ptr_eq(&clone.0, &entries.0));
    }

    #[test]
    fn entries_serialize_as_a_string_sequence() {
        let entries = RuleSetEntries::from(vec!["a.example".to_string(), "b\"q".to_string()]);
        let json = serde_json::to_string(&entries).unwrap();
        assert_eq!(json, r#"["a.example","b\"q"]"#);
        let back: RuleSetEntries = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entries);
        assert!(serde_json::from_str::<RuleSetEntries>("[1]").is_err());
    }
}
