//! A profile's rules in one shared block.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::RuleKind;

/// One rule of a profile's list: what a [`RouteRules`] block gives for a
/// place in it, and what one is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RouteRule<'a> {
    pub kind: RuleKind,
    /// What the kind matches by; `MATCH` has none, and an empty one reads
    /// back as none.
    pub payload: Option<&'a str>,
    pub outbound: &'a str,
    pub no_resolve: bool,
}

impl RouteRule<'_> {
    /// The rule as a profile writes it: `DOMAIN-SUFFIX,example.com,Proxy`,
    /// `GEOIP,CN,DIRECT,no-resolve`, `MATCH,DIRECT`. A decision, a
    /// connection's row and a host's count of hits name the rule by this:
    /// what a rule says stays true when the list around it changes, which
    /// its place in the list does not. The outbound is part of it, because
    /// rules that differ only there are different rules: a flow one of them
    /// cannot carry goes on to the next.
    pub fn text(&self) -> String {
        rule_text(self.kind, self.payload, self.outbound, self.no_resolve)
    }
}

/// [`RouteRule::text`] for a rule's parts.
pub fn rule_text(
    kind: RuleKind,
    payload: Option<&str>,
    outbound: &str,
    no_resolve: bool,
) -> String {
    const NO_RESOLVE: &str = ",no-resolve";
    let kind = kind.as_str();
    let mut text = String::with_capacity(
        kind.len()
            + payload.map_or(0, |payload| payload.len() + 1)
            + outbound.len()
            + 1
            + if no_resolve { NO_RESOLVE.len() } else { 0 },
    );
    text.extend(kind.chars().map(|letter| letter.to_ascii_uppercase()));
    if let Some(payload) = payload {
        text.push(',');
        text.push_str(payload);
    }
    text.push(',');
    text.push_str(outbound);
    if no_resolve {
        text.push_str(NO_RESOLVE);
    }
    text
}

/// A profile's rules, in the order they are tried, in one immutable block
/// that every clone shares: the payloads' text back to back, each rule's
/// kind and where its payload ends, and each outbound's name once. The host
/// keeps the rules it read from a profile's source, the profile it composes
/// for the Core carries the same block and the rule engine matches over it
/// in place, so the thousands of rules of a converted subscription are
/// stored once rather than as a string for each part of each rule in each
/// of the three.
///
/// Serializes as a sequence of rules.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RouteRules(Arc<Block>);

#[derive(Default, PartialEq, Eq)]
struct Block {
    payloads: Box<str>,
    entries: Box<[Entry]>,
    /// The outbounds the rules name, each once, in the order first named.
    outbounds: Box<[Box<str>]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// Where the payload ends in `payloads`; it starts where the payload of
    /// the rule before ends.
    payload_end: u32,
    /// The outbound's place in `outbounds`.
    outbound: u32,
    kind: RuleKind,
    no_resolve: bool,
}

impl RouteRules {
    pub fn builder() -> RouteRulesBuilder {
        RouteRulesBuilder::default()
    }

    pub fn len(&self) -> usize {
        self.0.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<RouteRule<'_>> {
        (index < self.len()).then(|| self.rule(index))
    }

    pub fn iter(&self) -> RouteRulesIter<'_> {
        RouteRulesIter {
            rules: self,
            range: 0..self.len(),
        }
    }

    /// Rule `index`, which must be below [`Self::len`].
    pub(crate) fn rule(&self, index: usize) -> RouteRule<'_> {
        let entry = self.0.entries[index];
        let payload = &self.0.payloads[self.payload_range(index)];
        RouteRule {
            kind: entry.kind,
            payload: (!payload.is_empty()).then_some(payload),
            outbound: &self.0.outbounds[entry.outbound as usize],
            no_resolve: entry.no_resolve,
        }
    }

    /// The payload of rule `index` as bytes, empty where it has none, for
    /// lookups that compare many rules; `index` must be below
    /// [`Self::len`].
    pub(crate) fn payload_bytes(&self, index: usize) -> &[u8] {
        &self.0.payloads.as_bytes()[self.payload_range(index)]
    }

    /// The outbound of rule `index`, which must be below [`Self::len`].
    pub(crate) fn outbound(&self, index: usize) -> &str {
        &self.0.outbounds[self.0.entries[index].outbound as usize]
    }

    /// Which of the block's outbounds rule `index` names: two rules name
    /// one outbound exactly when this is the same for both. `index` must be
    /// below [`Self::len`].
    pub(crate) fn outbound_place(&self, index: usize) -> u32 {
        self.0.entries[index].outbound
    }

    /// Whether the two are one block, and not merely equal.
    #[cfg(test)]
    pub(crate) fn shares_block_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn payload_range(&self, index: usize) -> Range<usize> {
        let start = match index {
            0 => 0,
            _ => self.0.entries[index - 1].payload_end as usize,
        };
        start..self.0.entries[index].payload_end as usize
    }
}

impl fmt::Debug for RouteRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRules")
            .field("rules", &self.len())
            .field("payload_bytes", &self.0.payloads.len())
            .field("outbounds", &self.0.outbounds.len())
            .finish()
    }
}

/// The rules of a block, in order.
#[derive(Debug, Clone)]
pub struct RouteRulesIter<'a> {
    rules: &'a RouteRules,
    range: Range<usize>,
}

impl<'a> Iterator for RouteRulesIter<'a> {
    type Item = RouteRule<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|index| self.rules.rule(index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl DoubleEndedIterator for RouteRulesIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.range.next_back().map(|index| self.rules.rule(index))
    }
}

impl ExactSizeIterator for RouteRulesIter<'_> {}

impl<'a> IntoIterator for &'a RouteRules {
    type Item = RouteRule<'a>;
    type IntoIter = RouteRulesIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> FromIterator<RouteRule<'a>> for RouteRules {
    /// Panics past what one block addresses; build with
    /// [`RouteRulesBuilder`] to handle that.
    fn from_iter<I: IntoIterator<Item = RouteRule<'a>>>(rules: I) -> Self {
        let mut builder = Self::builder();
        for rule in rules {
            builder
                .push(rule)
                .expect("rules within what one block addresses");
        }
        builder.finish()
    }
}

impl<'a> From<Vec<RouteRule<'a>>> for RouteRules {
    fn from(rules: Vec<RouteRule<'a>>) -> Self {
        rules.into_iter().collect()
    }
}

impl<'a, const N: usize> From<[RouteRule<'a>; N]> for RouteRules {
    fn from(rules: [RouteRule<'a>; N]) -> Self {
        rules.into_iter().collect()
    }
}

/// Collects rules into a [`RouteRules`] block.
#[derive(Debug, Default)]
pub struct RouteRulesBuilder {
    payloads: String,
    entries: Vec<Entry>,
    outbounds: Vec<Box<str>>,
    /// Each outbound's place in `outbounds`.
    named: HashMap<Box<str>, u32>,
}

impl RouteRulesBuilder {
    /// Appends one rule, refusing the one that would take the block past
    /// 4 GiB of payload text or past as many rules as 32 bits count.
    pub fn push(&mut self, rule: RouteRule<'_>) -> Result<(), RouteRulesTooLarge> {
        let payload = rule.payload.unwrap_or_default();
        let payload_end =
            u32::try_from(self.payloads.len() + payload.len()).map_err(|_| RouteRulesTooLarge)?;
        if self.entries.len() >= u32::MAX as usize {
            return Err(RouteRulesTooLarge);
        }
        let outbound = match self.named.get(rule.outbound) {
            Some(&place) => place,
            None => {
                // No more outbounds than rules, which 32 bits count.
                let place = self.outbounds.len() as u32;
                self.outbounds.push(rule.outbound.into());
                self.named.insert(rule.outbound.into(), place);
                place
            }
        };
        self.payloads.push_str(payload);
        self.entries.push(Entry {
            payload_end,
            outbound,
            kind: rule.kind,
            no_resolve: rule.no_resolve,
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The block, with its storage trimmed to the rules it holds.
    pub fn finish(self) -> RouteRules {
        RouteRules(Arc::new(Block {
            payloads: self.payloads.into_boxed_str(),
            entries: self.entries.into_boxed_slice(),
            outbounds: self.outbounds.into_boxed_slice(),
        }))
    }
}

/// Rules past what one block addresses: 4 GiB of payload text, or as many
/// rules as 32 bits count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRulesTooLarge;

impl fmt::Display for RouteRulesTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the rules exceed 4 GiB of payload text")
    }
}

impl std::error::Error for RouteRulesTooLarge {}

impl Serialize for RouteRules {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for RouteRules {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// One rule of the sequence, held only until the block has it.
        #[derive(Deserialize)]
        struct Read {
            kind: RuleKind,
            #[serde(default)]
            payload: Option<String>,
            outbound: String,
            #[serde(default)]
            no_resolve: bool,
        }

        struct Rules;

        impl<'de> Visitor<'de> for Rules {
            type Value = RouteRules;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of rules")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut builder = RouteRules::builder();
                while let Some(rule) = seq.next_element::<Read>()? {
                    builder
                        .push(RouteRule {
                            kind: rule.kind,
                            payload: rule.payload.as_deref(),
                            outbound: &rule.outbound,
                            no_resolve: rule.no_resolve,
                        })
                        .map_err(serde::de::Error::custom)?;
                }
                Ok(builder.finish())
            }
        }

        deserializer.deserialize_seq(Rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule<'a>(
        kind: RuleKind,
        payload: Option<&'a str>,
        outbound: &'a str,
        no_resolve: bool,
    ) -> RouteRule<'a> {
        RouteRule {
            kind,
            payload,
            outbound,
            no_resolve,
        }
    }

    #[test]
    fn rules_read_back_in_order_and_clones_share_one_block() {
        let written = [
            rule(RuleKind::DomainSuffix, Some("example.com"), "Proxy", false),
            rule(RuleKind::GeoIp, Some("CN"), "DIRECT", true),
            rule(RuleKind::Domain, Some("a.example"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ];
        let rules = RouteRules::from(written);

        assert_eq!(rules.len(), 4);
        assert_eq!(rules.iter().collect::<Vec<_>>(), written);
        assert_eq!(rules.iter().rev().next(), Some(written[3]));
        assert_eq!(rules.get(1), Some(written[1]));
        assert_eq!(rules.get(4), None);
        assert_eq!(rules.payload_bytes(2), b"a.example");
        assert_eq!(rules.payload_bytes(3), b"");
        assert_eq!(rules.outbound(2), "Proxy");
        // Two outbounds are named, each held once.
        assert_eq!(rules.0.outbounds.len(), 2);
        assert_eq!(&*rules.0.payloads, "example.comCNa.example");

        assert!(rules.clone().shares_block_with(&rules));
        assert_eq!(written.into_iter().collect::<RouteRules>(), rules);
        assert!(RouteRules::default().is_empty());
    }

    #[test]
    fn an_empty_payload_reads_back_as_none() {
        let rules = RouteRules::from([rule(RuleKind::Domain, Some(""), "Proxy", false)]);
        assert_eq!(
            rules.get(0),
            Some(rule(RuleKind::Domain, None, "Proxy", false))
        );
    }

    #[test]
    fn rules_serialize_as_a_sequence_of_their_parts() {
        let rules = RouteRules::from([
            rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "DIRECT", true),
            rule(RuleKind::Match, None, "Proxy", false),
        ]);
        let json = serde_json::to_string(&rules).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"[{"kind":"ip-cidr","payload":"10.0.0.0/8","outbound":"DIRECT","no_resolve":true},"#,
                r#"{"kind":"match","payload":null,"outbound":"Proxy","no_resolve":false}]"#
            )
        );
        let back: RouteRules = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rules);
        // A rule may leave out what it does not set.
        let short: RouteRules =
            serde_json::from_str(r#"[{"kind":"match","outbound":"Proxy"}]"#).unwrap();
        assert_eq!(short.get(0), rules.get(1));
        assert!(serde_json::from_str::<RouteRules>(r#"[{"kind":"match"}]"#).is_err());
    }
}
