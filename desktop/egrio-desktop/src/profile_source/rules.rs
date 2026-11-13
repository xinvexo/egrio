//! `rules` lines, `rule-providers` definitions and fetched provider bodies.

use std::collections::HashMap;
use std::fmt;

use egrio_core::profile::RuleSetEntries;
use egrio_core::{RouteRule, RouteRules, RuleKind};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;

/// One `rule-providers` entry: what a RULE-SET rule's payload names. `url` is
/// absent for `file` providers.
#[derive(Debug, Clone)]
pub(crate) struct RuleProvider {
    pub(crate) name: String,
    pub(crate) url: Option<String>,
    pub(crate) behavior: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourceRuleProvider {
    url: Option<String>,
    behavior: Option<String>,
}

/// Tolerant on purpose: the section only annotates RULE-SET rules, so a
/// malformed one yields an empty or partial list instead of an error. Rules
/// that need a missing provider fail when the profile is prepared to run.
pub(super) fn providers(section: Option<Value>) -> Vec<RuleProvider> {
    let Some(Value::Mapping(section)) = section else {
        return Vec::new();
    };
    section
        .into_iter()
        .filter_map(|(key, value)| {
            let name = super::nodes::key_to_string(key)?;
            let provider: SourceRuleProvider = serde_yaml::from_value(value).ok()?;
            Some(RuleProvider {
                name,
                url: provider.url,
                behavior: provider.behavior,
            })
        })
        .collect()
}

/// The id of the source rule at `index`: its position, which is what an edit
/// of the list addresses.
pub(crate) fn rule_id(index: usize) -> String {
    format!("rule-{index}")
}

/// The position a source rule's id names.
pub(crate) fn rule_index(id: &str) -> Option<usize> {
    id.strip_prefix("rule-")?.parse().ok()
}

/// A rule's parts as the line the source writes: `KIND,payload,outbound`,
/// then `no-resolve` when set.
pub(crate) fn rule_line(
    kind: &str,
    payload: Option<&str>,
    outbound: &str,
    no_resolve: bool,
) -> String {
    let mut line = kind.to_string();
    if let Some(payload) = payload {
        line.push(',');
        line.push_str(payload);
    }
    line.push(',');
    line.push_str(outbound);
    if no_resolve {
        line.push_str(",no-resolve");
    }
    line
}

/// The source's `rules` list, read.
#[derive(Debug, Default)]
pub(crate) struct SourceRules {
    /// The block every reader of the rules shares.
    pub(crate) rules: RouteRules,
    /// What the source calls the type of each rule whose type the Core has
    /// no name for, by the rule's place. The Core holds such a rule as one
    /// of unknown type and leaves it out; the type as written is what the
    /// rule is listed with and what an edit of it writes back.
    pub(crate) unknown_kinds: HashMap<usize, String>,
}

pub(super) fn source_rules(lines: &[String]) -> Result<SourceRules, String> {
    let mut rules = RouteRules::builder();
    let mut unknown_kinds = HashMap::new();
    for (index, line) in lines.iter().enumerate() {
        let (rule, kind) = source_rule(line)?;
        if rule.kind == RuleKind::Unknown {
            unknown_kinds.insert(index, kind.to_owned());
        }
        rules.push(rule).map_err(|error| error.to_string())?;
    }
    Ok(SourceRules {
        rules: rules.finish(),
        unknown_kinds,
    })
}

/// One line of the source's `rules` list, and its type as the line writes
/// it. The rule's parts are the line's own text, each without the spaces
/// around it.
pub(super) fn source_rule(line: &str) -> Result<(RouteRule<'_>, &str), String> {
    let missing_outbound = || format!("rule is missing outbound: {line}");
    let (kind_text, rest) = match line.split_once(',') {
        Some((kind, rest)) => (kind.trim(), rest),
        None => (line.trim(), ""),
    };
    if kind_text.is_empty() {
        return Err(missing_outbound());
    }
    let mut kind = RuleKind::from_clash_text(kind_text);
    let mut parts = rest.split(',').map(str::trim);

    if matches!(kind, RuleKind::Match) {
        let outbound = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(missing_outbound)?;
        let rule = RouteRule {
            kind,
            payload: None,
            outbound,
            no_resolve: false,
        };
        return Ok((rule, kind_text));
    }

    // Logic/regex payloads may contain commas, so for those kinds the
    // outbound is the *last* segment, everything between is the payload as
    // it is written, and there are no trailing params. Every other kind is
    // the plain `KIND,payload,outbound(,params...)` shape.
    let (payload, outbound, no_resolve) = if kind.payload_may_contain_commas() {
        let (payload, outbound) = rest.rsplit_once(',').ok_or_else(missing_outbound)?;
        (payload.trim(), outbound.trim(), false)
    } else {
        let payload = parts.next().unwrap_or_default();
        let outbound = parts.next().ok_or_else(missing_outbound)?;
        // Params live strictly after the outbound; `src` flips a
        // destination-IP rule to its source variant and implies no-resolve:
        // it matches the client's address, so there is no destination to
        // resolve.
        let (mut is_src, mut no_resolve) = (false, false);
        for param in parts {
            is_src |= param.eq_ignore_ascii_case("src");
            no_resolve |= param.eq_ignore_ascii_case("no-resolve");
        }
        if is_src {
            kind = kind.into_source_variant();
        }
        (payload, outbound, is_src || no_resolve)
    };
    if outbound.is_empty() {
        return Err(missing_outbound());
    }

    let rule = RouteRule {
        kind,
        payload: (!payload.is_empty()).then_some(payload),
        outbound,
        no_resolve,
    };
    Ok((rule, kind_text))
}

#[derive(Deserialize)]
struct ProviderPayload {
    #[serde(deserialize_with = "payload_entries")]
    payload: RuleSetEntries,
}

/// Unwraps a fetched rule-provider body into its entry lines. Clash ships
/// two formats: a yaml document with a `payload:` list, or plain text with
/// one entry per line; the format is auto-detected rather than trusting the
/// provider's declared `format`, which is frequently wrong in the wild.
/// Comments (`#`) and blank lines are dropped. Entries go straight into one
/// block, so a large provider is never held as a string or yaml value per
/// entry, even while it is parsed.
pub(crate) fn parse_rule_provider_entries(body: &str) -> RuleSetEntries {
    if let Ok(document) = serde_yaml::from_str::<ProviderPayload>(body) {
        return document.payload;
    }

    let mut entries = RuleSetEntries::builder();
    for line in body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
    {
        if entries.push(line).is_err() {
            break;
        }
    }
    entries.finish()
}

/// The `payload:` list, one item at a time: a string item is the entry, any
/// other item is written back out as yaml text.
fn payload_entries<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RuleSetEntries, D::Error> {
    struct Payload;

    impl<'de> Visitor<'de> for Payload {
        type Value = RuleSetEntries;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a rule-provider payload list")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<RuleSetEntries, A::Error> {
            let mut entries = RuleSetEntries::builder();
            while let Some(item) = items.next_element::<Value>()? {
                let text = match item {
                    Value::String(text) => text,
                    other => serde_yaml::to_string(&other).unwrap_or_default(),
                };
                let entry = text.trim();
                if !entry.is_empty() && !entry.starts_with('#') {
                    entries.push(entry).map_err(A::Error::custom)?;
                }
            }
            Ok(entries.finish())
        }
    }

    deserializer.deserialize_seq(Payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(line: &str) -> Result<RouteRule<'_>, String> {
        source_rule(line).map(|(rule, _)| rule)
    }

    #[test]
    fn parses_extended_rule_kinds() {
        for (line, kind) in [
            ("DOMAIN-REGEX,^ads?\\.,REJECT", RuleKind::DomainRegex),
            ("GEOSITE,cn,DIRECT", RuleKind::Geosite),
            ("SRC-IP-CIDR,192.168.1.0/24,DIRECT", RuleKind::SrcIpCidr),
            ("DST-PORT,80/443,Proxy", RuleKind::DstPort),
            ("SRC-PORT,7777,DIRECT", RuleKind::SrcPort),
            ("NETWORK,udp,Proxy", RuleKind::Network),
            ("network,tcp,Proxy", RuleKind::Network),
        ] {
            assert_eq!(rule(line).expect(line).kind, kind, "{line}");
        }
    }

    #[test]
    fn logic_rule_payload_keeps_commas_and_last_segment_is_outbound() {
        let logic =
            rule("AND,((DOMAIN-SUFFIX,example.com),(NETWORK,udp)),Proxy").expect("logic rule");
        assert_eq!(logic.kind, RuleKind::And);
        assert_eq!(
            logic.payload,
            Some("((DOMAIN-SUFFIX,example.com),(NETWORK,udp))")
        );
        assert_eq!(logic.outbound, "Proxy");

        let regex = rule(r"DOMAIN-REGEX,^a{2,3}\.example\.com$,Proxy").expect("regex rule");
        assert_eq!(regex.kind, RuleKind::DomainRegex);
        assert_eq!(regex.payload, Some(r"^a{2,3}\.example\.com$"));
        assert_eq!(regex.outbound, "Proxy");

        // The payload is the text between the kind and the outbound, as it
        // is written: an expression's own spaces are not ours to remove.
        let spaced = rule(r"DOMAIN-REGEX , ^a{2, 3}$ , Proxy").expect("regex rule");
        assert_eq!(spaced.payload, Some("^a{2, 3}$"));
        assert_eq!(spaced.outbound, "Proxy");
    }

    #[test]
    fn the_parts_of_a_line_are_read_without_the_spaces_around_them() {
        let spaced = rule(" DOMAIN-SUFFIX , example.com , Proxy , no-resolve ").expect("a rule");
        assert_eq!(
            spaced,
            RouteRule {
                kind: RuleKind::DomainSuffix,
                payload: Some("example.com"),
                outbound: "Proxy",
                no_resolve: true,
            }
        );
        assert_eq!(
            rule("MATCH, Proxy").expect("a rule"),
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "Proxy",
                no_resolve: false,
            }
        );
        assert!(rule("MATCH").is_err());
        assert!(rule("MATCH,").is_err());
        assert!(rule(",example.com,Proxy").is_err());
        assert!(rule("DOMAIN,example.com,").is_err());
    }

    #[test]
    fn src_param_flips_ip_cidr_to_source_variant_and_implies_no_resolve() {
        let source = rule("IP-CIDR,10.0.0.0/8,DIRECT,src").expect("src rule");
        assert_eq!(source.kind, RuleKind::SrcIpCidr);
        assert!(source.no_resolve);
    }

    #[test]
    fn no_resolve_is_only_read_from_params() {
        // A payload that merely *contains* the text must not set the flag.
        let keyword = rule("DOMAIN-KEYWORD,no-resolve,Proxy").expect("keyword rule");
        assert_eq!(keyword.kind, RuleKind::DomainKeyword);
        assert_eq!(keyword.payload, Some("no-resolve"));
        assert!(!keyword.no_resolve);
    }

    #[test]
    fn unrecognized_rule_kinds_still_parse_as_unknown() {
        let niche = rule("IP-ASN,13335,DIRECT").expect("niche rule");
        assert_eq!(niche.kind, RuleKind::Unknown);
        assert_eq!(niche.outbound, "DIRECT");
    }

    /// The Core has one name for every type it does not know; what the
    /// source called each is kept beside the rules.
    #[test]
    fn the_types_the_core_does_not_know_are_kept_as_written() {
        let lines = [
            "DOMAIN,a.example,Proxy",
            " in-port , 7890 , DIRECT",
            "IP-ASN,13335,DIRECT",
        ]
        .map(String::from);
        let source = source_rules(&lines).expect("rules");
        assert_eq!(source.rules.len(), 3);
        assert_eq!(
            source.unknown_kinds,
            HashMap::from([(1, "in-port".to_string()), (2, "IP-ASN".to_string())])
        );
    }

    #[test]
    fn rule_without_outbound_is_rejected() {
        // Two segments only: nothing left over to be the outbound. A
        // malformed logic payload that still splits into three segments is
        // accepted here and surfaces as a rule-engine compile warning
        // instead, same as an invalid IP-CIDR payload.
        assert!(rule("AND,payload").is_err());
        assert!(rule("DOMAIN-SUFFIX,example.com").is_err());
    }

    #[test]
    fn rule_parts_make_the_line_the_source_writes() {
        assert_eq!(
            rule_line("IP-CIDR", Some("10.0.0.0/8"), "DIRECT", true),
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
        );
        assert_eq!(rule_line("MATCH", None, "Proxy", false), "MATCH,Proxy");
        assert_eq!(rule_index(&rule_id(3)), Some(3));
        assert_eq!(rule_index("3"), None);
    }

    #[test]
    fn the_source_s_lines_make_one_block_in_their_order() {
        let lines = ["DOMAIN,a.example,Proxy", "MATCH,DIRECT"].map(String::from);
        let source = source_rules(&lines).expect("rules");
        assert_eq!(
            source
                .rules
                .iter()
                .map(|rule| rule.text())
                .collect::<Vec<_>>(),
            lines
        );
        assert!(source.unknown_kinds.is_empty());
        assert!(source_rules(&["DOMAIN,a.example".to_string()]).is_err());
    }

    #[test]
    fn provider_bodies_unwrap_to_their_entries_in_either_format() {
        let yaml = "payload:\n  - '+.example.com'\n  - \"  spaced.example  \"\n  - 12345\n  - '# note'\n  - ''\n";
        assert_eq!(
            parse_rule_provider_entries(yaml).iter().collect::<Vec<_>>(),
            ["+.example.com", "spaced.example", "12345"]
        );
        let text = "# header\n+.plain.example\n\n// note\n  1.2.3.0/24  \n";
        assert_eq!(
            parse_rule_provider_entries(text).iter().collect::<Vec<_>>(),
            ["+.plain.example", "1.2.3.0/24"]
        );
    }
}
