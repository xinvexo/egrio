//! The name patterns of a profile's DNS filters, policies and hosts, and the
//! label tree that finds the most specific pattern a name matches.
//!
//! Patterns support literal labels, single-label wildcards and suffix
//! matches. Lookup prefers the most specific matching label path.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A name pattern as Clash's DNS filters, policies and hosts write it:
/// dotted labels, of which a `*` stands for exactly one label of the name,
/// behind an optional `+.` (the name and every name under it) or `.` (every
/// name under it, not the name). `*` alone is every name.
///
/// `www.example.com`, `*.example.com`, `time.*.com`, `stun.*.*`,
/// `+.example.com`, `+.stun.*.*` and `.example.com` are patterns. It reads
/// from and writes as that text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsDomainPattern {
    /// The labels in lower case, without the prefix; empty for every name.
    labels: String,
    reach: Reach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Reach {
    /// The names that have exactly the pattern's labels.
    Itself,
    /// Those names and every name under them (`+.`).
    ItselfAndUnder,
    /// Every name under them (`.`).
    Under,
    /// Every name (`*`).
    Every,
}

impl DnsDomainPattern {
    /// Whether the pattern is `name`'s, compared as names are: without
    /// regard to case or to a dot ending it.
    pub fn matches(&self, name: &str) -> bool {
        if self.reach == Reach::Every {
            return true;
        }
        let mut parts = name.trim_end_matches('.').rsplit('.');
        for label in self.labels.rsplit('.') {
            match parts.next() {
                Some(part)
                    if !part.is_empty() && (label == "*" || part.eq_ignore_ascii_case(label)) => {}
                _ => return false,
            }
        }
        let under = parts.next().is_some();
        match self.reach {
            Reach::Itself => !under,
            Reach::Under => under,
            Reach::ItselfAndUnder | Reach::Every => true,
        }
    }
}

impl FromStr for DnsDomainPattern {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let value = text.trim().trim_end_matches('.').to_ascii_lowercase();
        if value == "*" {
            return Ok(Self {
                labels: String::new(),
                reach: Reach::Every,
            });
        }
        let (reach, labels) = if let Some(labels) = value.strip_prefix("+.") {
            (Reach::ItselfAndUnder, labels)
        } else if let Some(labels) = value.strip_prefix('.') {
            (Reach::Under, labels)
        } else {
            (Reach::Itself, value.as_str())
        };
        let label_reads = |label: &str| {
            label == "*"
                || (!label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        };
        if labels.is_empty() || labels.len() > 253 || !labels.split('.').all(label_reads) {
            return Err(format!("unsupported DNS domain pattern: {}", text.trim()));
        }
        Ok(Self {
            labels: labels.to_owned(),
            reach,
        })
    }
}

impl fmt::Display for DnsDomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.reach {
            Reach::Every => return f.write_str("*"),
            Reach::Itself => "",
            Reach::ItselfAndUnder => "+.",
            Reach::Under => ".",
        };
        write!(f, "{prefix}{}", self.labels)
    }
}

impl Serialize for DnsDomainPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsDomainPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// Values by name pattern, answering a name with the value of the most
/// specific pattern it matches. Walking the name's labels from its last,
/// the label itself is tried before a `*`, and a `*` before the `+.` or `.`
/// pattern of the name reached so far, so the exact name wins over one label
/// under a name, that over the longest `+.` suffix, and `*` alone comes
/// last. The first value given for a pattern is the one it keeps.
#[derive(Debug)]
pub(crate) struct PatternTrie<T> {
    root: Node<T>,
    every: Option<T>,
}

#[derive(Debug)]
struct Node<T> {
    /// For the name that ends here.
    itself: Option<T>,
    /// For every name under the one that ends here.
    under: Option<T>,
    labels: HashMap<Box<str>, Node<T>>,
    /// The `*` label.
    any_label: Option<Box<Node<T>>>,
}

impl<T> Default for Node<T> {
    fn default() -> Self {
        Self {
            itself: None,
            under: None,
            labels: HashMap::new(),
            any_label: None,
        }
    }
}

impl<T> Default for PatternTrie<T> {
    fn default() -> Self {
        Self {
            root: Node::default(),
            every: None,
        }
    }
}

impl<T: Clone> PatternTrie<T> {
    pub(crate) fn insert(&mut self, pattern: &DnsDomainPattern, value: T) {
        if pattern.reach == Reach::Every {
            self.every.get_or_insert(value);
            return;
        }
        let mut node = &mut self.root;
        for label in pattern.labels.rsplit('.') {
            node = if label == "*" {
                node.any_label.get_or_insert_with(Box::default)
            } else {
                node.labels.entry(label.into()).or_default()
            };
        }
        match pattern.reach {
            Reach::Itself => {
                node.itself.get_or_insert(value);
            }
            Reach::Under => {
                node.under.get_or_insert(value);
            }
            Reach::ItselfAndUnder => {
                node.itself.get_or_insert_with(|| value.clone());
                node.under.get_or_insert(value);
            }
            Reach::Every => {}
        }
    }
}

impl<T> PatternTrie<T> {
    /// The value for `name`, which is in lower case and ends in no dot.
    pub(crate) fn get(&self, name: &str) -> Option<&T> {
        if name.is_empty() {
            return None;
        }
        self.root.find(Some(name)).or(self.every.as_ref())
    }
}

impl<T> Node<T> {
    /// The value for the name whose labels before this node are `rest`.
    fn find(&self, rest: Option<&str>) -> Option<&T> {
        let Some(rest) = rest else {
            return self.itself.as_ref();
        };
        let (rest, label) = match rest.rsplit_once('.') {
            Some((rest, label)) => (Some(rest), label),
            None => (None, rest),
        };
        if label.is_empty() {
            return None;
        }
        self.labels
            .get(label)
            .and_then(|node| node.find(rest))
            .or_else(|| self.any_label.as_ref().and_then(|node| node.find(rest)))
            .or(self.under.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> DnsDomainPattern {
        text.parse()
            .unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    #[test]
    fn each_form_matches_the_names_it_says() {
        for (text, matching, others) in [
            (
                "www.example.com",
                &["www.example.com", "WWW.Example.com."][..],
                &["example.com", "a.www.example.com", "wwwexample.com", ""][..],
            ),
            (
                "*.example.com",
                &["a.example.com"],
                &["example.com", "a.b.example.com", ".example.com"],
            ),
            (
                "+.example.com",
                &["example.com", "a.example.com", "a.b.example.com"],
                &["notexample.com", "com"],
            ),
            (
                ".example.com",
                &["a.example.com", "a.b.example.com"],
                &["example.com", "notexample.com"],
            ),
            (
                "time.*.com",
                &["time.apple.com", "time.windows.com"],
                &[
                    "time.com",
                    "time.a.b.com",
                    "x.time.apple.com",
                    "time.apple.org",
                ],
            ),
            (
                "stun.*.*",
                &["stun.l.google", "stun.example.org"],
                &["stun.org", "stun.a.b.c", "a.stun.b.c"],
            ),
            (
                "+.stun.*.*",
                &[
                    "stun.example.org",
                    "a.stun.example.org",
                    "a.b.stun.example.org",
                ],
                &["stun.org", "example.org"],
            ),
            (
                "*.*.xboxlive.com",
                &["a.b.xboxlive.com"],
                &["a.xboxlive.com", "a.b.c.xboxlive.com"],
            ),
            ("*", &["anything", "a.b.c"], &[]),
        ] {
            let pattern = pattern(text);
            for name in matching {
                assert!(pattern.matches(name), "{text} matches {name}");
            }
            for name in others {
                assert!(!pattern.matches(name), "{text} does not match {name}");
            }
        }
    }

    #[test]
    fn a_pattern_reads_from_and_writes_as_its_text() {
        for (text, written) in [
            (" WWW.Example.COM. ", "www.example.com"),
            ("*.lan", "*.lan"),
            ("+.Example.com", "+.example.com"),
            (".example.com", ".example.com"),
            ("time.*.com", "time.*.com"),
            ("*", "*"),
            ("_dmarc.example.com", "_dmarc.example.com"),
        ] {
            let pattern = pattern(text);
            assert_eq!(pattern.to_string(), written);
            let json = serde_json::to_string(&pattern).unwrap();
            assert_eq!(json, format!("\"{written}\""));
            assert_eq!(
                serde_json::from_str::<DnsDomainPattern>(&json).unwrap(),
                pattern
            );
        }
        for refused in [
            "",
            ".",
            "+.",
            "a..b",
            "a*.example.com",
            "geosite:cn",
            "rule-set:direct",
            "+.a.com,+.b.com",
            "exa mple.com",
            "例子.com",
        ] {
            assert!(
                refused.parse::<DnsDomainPattern>().is_err(),
                "{refused:?} is no pattern"
            );
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(long_label.parse::<DnsDomainPattern>().is_err());
        assert!(serde_json::from_str::<DnsDomainPattern>("\"a..b\"").is_err());
    }

    /// What the tree answers is what the patterns say, the most specific
    /// one first.
    #[test]
    fn the_tree_answers_with_the_most_specific_pattern() {
        let mut trie = PatternTrie::default();
        for (index, text) in [
            "*",
            "+.example.com",
            "+.deep.example.com",
            "*.example.com",
            "www.example.com",
            ".only-under.test",
            "time.*.com",
            "+.stun.*.*",
            "www.example.com",
        ]
        .into_iter()
        .enumerate()
        {
            trie.insert(&pattern(text), index);
        }
        for (name, expected) in [
            ("www.example.com", 4),
            ("api.example.com", 3),
            ("example.com", 1),
            ("a.b.example.com", 1),
            ("x.deep.example.com", 2),
            ("deep.example.com", 2),
            ("a.only-under.test", 5),
            ("a.b.only-under.test", 5),
            // Not the name itself: only `*` has it.
            ("only-under.test", 0),
            ("time.apple.com", 6),
            // A label beats the `*` beside it, and the search comes back
            // for the `*` when the label leads nowhere.
            ("time.example.com", 3),
            ("x.time.apple.com", 0),
            ("stun.example.org", 7),
            ("a.b.stun.example.org", 7),
            ("other.org", 0),
        ] {
            assert_eq!(trie.get(name), Some(&expected), "{name}");
        }
        assert_eq!(trie.get(""), None);

        let mut none = PatternTrie::default();
        none.insert(&pattern("a.test"), ());
        assert!(none.get("a.test").is_some());
        assert!(none.get("b.test").is_none() && none.get("x.a.test").is_none());
        assert!(none.get("a..test").is_none());
    }
}
