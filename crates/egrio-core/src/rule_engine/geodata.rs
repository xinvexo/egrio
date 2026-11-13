//! GEOIP and GEOSITE rules against the geodata the host injected
//! ([`crate::geodata`]). Each code compiles once per engine and every rule
//! naming it shares the matcher.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::ip_set::IpRangeSet;
use super::patterns::PatternsBuilder;
use super::{logic_member_texts, normalize_keyword, parse_sub_rule, CidrRange, RuleSetMatcher};
use crate::geodata::{
    geoip_code, geosite_selection, GeoDataCodes, GeoDataContent, GeoIpContent, GeoSiteContent,
};
use crate::profile::{RuleKind, RuleSetBehavior, RuntimeProfile};

/// The GEOIP code that is no entry of the data: Clash's `LAN`, the
/// addresses that stay on the local network.
const LAN_CODE: &str = "LAN";

/// What `GEOIP,LAN` matches: the private (RFC 1918, RFC 4193), unspecified,
/// loopback, multicast and link-local unicast addresses of both families.
const LAN_NETWORKS: [&str; 12] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "0.0.0.0/32",
    "::/128",
    "127.0.0.0/8",
    "::1/128",
    "224.0.0.0/4",
    "ff00::/8",
    "169.254.0.0/16",
    "fe80::/10",
];

/// One GeoIP code's networks.
#[derive(Debug)]
pub(super) struct GeoIpMatcher {
    networks: IpRangeSet,
    /// The code stands for every address outside the networks.
    inverse: bool,
}

impl GeoIpMatcher {
    fn compile(content: &GeoIpContent) -> Self {
        Self {
            networks: IpRangeSet::from_networks(
                content
                    .cidrs
                    .iter()
                    .filter_map(|network| CidrRange::parse(network)),
            ),
            inverse: content.inverse,
        }
    }

    fn lan() -> Self {
        Self {
            networks: IpRangeSet::from_networks(
                LAN_NETWORKS
                    .iter()
                    .filter_map(|network| CidrRange::parse(network)),
            ),
            inverse: false,
        }
    }

    pub(super) fn matches(&self, ip: IpAddr) -> bool {
        self.networks.contains(ip) != self.inverse
    }
}

/// The injected geodata, compiled. `None` for a kind the host has no data
/// for.
pub(super) struct GeoDataMatchers {
    /// `LAN`, which needs no data.
    lan: Arc<GeoIpMatcher>,
    geoip: Option<HashMap<String, Arc<GeoIpMatcher>>>,
    /// Each selection's domains and how many of its regular expressions did
    /// not compile.
    geosite: Option<HashMap<String, (Arc<RuleSetMatcher>, usize)>>,
    /// What stands for every code when the data is not what is judged: a
    /// rule then compiles for what it says alone.
    any: Option<(Arc<GeoIpMatcher>, Arc<RuleSetMatcher>)>,
}

impl GeoDataMatchers {
    pub(super) fn compile(content: &GeoDataContent) -> Self {
        Self {
            lan: Arc::new(GeoIpMatcher::lan()),
            geoip: content.geoip.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|entry| (entry.code.clone(), Arc::new(GeoIpMatcher::compile(entry))))
                    .collect()
            }),
            geosite: content.geosite.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        let (matcher, skipped) = compile_geosite(entry);
                        (entry.selection.clone(), (Arc::new(matcher), skipped))
                    })
                    .collect()
            }),
            any: None,
        }
    }

    /// For judging rules by what they say: every code is taken to be in
    /// the data, with nothing in it.
    pub(super) fn any_code() -> Self {
        Self {
            lan: Arc::new(GeoIpMatcher::lan()),
            geoip: None,
            geosite: None,
            any: Some((
                Arc::new(GeoIpMatcher {
                    networks: IpRangeSet::default(),
                    inverse: false,
                }),
                Arc::new(RuleSetMatcher::default()),
            )),
        }
    }

    pub(super) fn geoip(&self, payload: &str) -> Result<Arc<GeoIpMatcher>, String> {
        let code = geoip_code(payload);
        if code == LAN_CODE {
            return Ok(Arc::clone(&self.lan));
        }
        if let Some((networks, _)) = &self.any {
            return Ok(Arc::clone(networks));
        }
        let entries = self.geoip.as_ref().ok_or(
            "GEOIP rules need GeoIP data, which is not loaded; update GEODATA in Settings",
        )?;
        entries
            .get(&code)
            .cloned()
            .ok_or_else(|| format!("the GeoIP data has no '{code}' entry"))
    }

    pub(super) fn geosite(&self, payload: &str) -> Result<(Arc<RuleSetMatcher>, usize), String> {
        if let Some((_, names)) = &self.any {
            return Ok((Arc::clone(names), 0));
        }
        let selection = geosite_selection(payload);
        let entries = self.geosite.as_ref().ok_or(
            "GEOSITE rules need GeoSite data, which is not loaded; update GEODATA in Settings",
        )?;
        entries.get(&selection).cloned().ok_or_else(|| {
            let code = selection.split('@').next().unwrap_or_default();
            format!("the GeoSite data has no '{code}' entry")
        })
    }
}

/// A selection's domains as a rule-set matcher: its names are indexed where
/// the content holds them, as a `domain` rule set's entries are, and its
/// keywords and regular expressions go to the automata a name is run
/// through.
fn compile_geosite(content: &GeoSiteContent) -> (RuleSetMatcher, usize) {
    let mut patterns = PatternsBuilder::default();
    for keyword in &content.keywords {
        patterns.keyword(&normalize_keyword(keyword));
    }
    for expression in &content.regexes {
        patterns.expression(expression.trim());
    }
    RuleSetMatcher::compile_domains(&content.names, patterns)
}

/// The GeoIP codes and GeoSite selections the profile's rules name and the
/// data has to give: top-level rules, logic sub-rules and the entries of
/// classical rule sets.
pub(crate) fn geodata_codes(profile: &RuntimeProfile) -> GeoDataCodes {
    let mut codes = GeoDataCodes::default();
    for rule in &profile.rules {
        collect(rule.kind, rule.payload.as_deref(), &mut codes);
    }
    for content in &profile.rule_sets {
        if content.behavior == RuleSetBehavior::Classical {
            for entry in content.entries.iter() {
                if let Ok((kind, payload)) = parse_sub_rule(entry) {
                    collect(kind, Some(&payload), &mut codes);
                }
            }
        }
    }
    codes
}

fn collect(kind: RuleKind, payload: Option<&str>, codes: &mut GeoDataCodes) {
    let Some(payload) = payload.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    match kind {
        RuleKind::GeoIp => {
            let code = geoip_code(payload);
            if code != LAN_CODE {
                codes.geoip.insert(code);
            }
        }
        RuleKind::Geosite => {
            codes.geosite.insert(geosite_selection(payload));
        }
        RuleKind::And | RuleKind::Or | RuleKind::Not => {
            for text in logic_member_texts(payload).unwrap_or_default() {
                if let Ok((kind, payload)) = parse_sub_rule(text) {
                    collect(kind, Some(&payload), codes);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
