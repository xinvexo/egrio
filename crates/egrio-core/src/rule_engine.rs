use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::profile::{
    ProxyProtocol, RouteRule, RouteRules, RuleKind, RuleSetBehavior, RuleSetContent,
    RuleSetEntries, RuntimeProfile, TrafficPolicyMode,
};

#[cfg(test)]
mod address_tests;
mod domain_index;
mod geodata;
#[cfg(test)]
mod index_tests;
mod ip_set;
mod patterns;
mod rule_index;

use domain_index::{DomainIndex, Insert};
pub(crate) use geodata::geodata_codes;
use geodata::{GeoDataMatchers, GeoIpMatcher};
use ip_set::IpRangeSet;
use patterns::{Patterns, PatternsBuilder};
use rule_index::{RuleIndex, RuleIndexBuilder};

/// Everything a call site knows about the flow being routed. All fields are
/// optional: a rule whose input is absent simply doesn't match and the scan
/// falls through to the next rule, so call sites only fill what they
/// actually have.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteMatchInput {
    pub host: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub destination_port: Option<u16>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub network: Option<TransportNetwork>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMatchKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    #[serde(rename = "geoip")]
    GeoIp,
    #[serde(rename = "geosite")]
    GeoSite,
    IpCidr,
    SrcIpCidr,
    DstPort,
    SrcPort,
    ProcessName,
    ProcessPath,
    Network,
    And,
    Or,
    Not,
    RuleSet,
    Match,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteDecision {
    pub traffic_policy_mode: TrafficPolicyMode,
    pub outbound: String,
    /// The rule that decided, as its profile writes it
    /// ([`RouteRule::text`]); `None` when the mode decided or no rule
    /// matched.
    pub matched_rule: Option<String>,
    pub matched_kind: Option<RouteMatchKind>,
    pub matched_payload: Option<String>,
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteEvaluation {
    pub decision: RouteDecision,
    pub resolved_outbound: String,
    /// The address the name resolved to because an IP rule asked for it.
    pub resolved_ip: Option<IpAddr>,
}

/// The address a name resolved to for the IP rules. Rules before `from_rule`
/// never see it, so an earlier rule cannot match an address that only a later
/// one asked for. `ip` is `None` when the name did not resolve: the IP rules
/// then do not match, and nothing asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleAddress {
    pub(crate) from_rule: usize,
    pub(crate) ip: Option<IpAddr>,
}

/// A route, or the rule that needs the destination's address before
/// anything can match.
#[derive(Debug, Clone)]
pub(crate) enum RouteStep {
    Decided(RouteDecision),
    NeedsAddress(usize),
}

/// Why a rule of the profile does not take part in routing, or what of it
/// does not.
#[derive(Debug, Clone, Serialize)]
pub struct RuleEngineCompileWarning {
    /// The rule's place in the profile's list.
    pub rule: usize,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RuleEngine {
    traffic_policy_mode: TrafficPolicyMode,
    /// The profile's rules, in the block the profile holds them in: a
    /// decision reads the rule it names from here.
    rules: RouteRules,
    index: RuleIndex,
    global_outbound: String,
    warnings: Vec<RuleEngineCompileWarning>,
    /// Whether compiled rules contain a reachable domain match before MATCH.
    /// The current traffic mode gates sniffing separately so mode updates can
    /// reuse this immutable index without recompiling it.
    wants_sniffed_host: bool,
    /// Whether a reachable rule before MATCH reads the flow's process, so
    /// routing has to wait for attribution; the mode gates it like sniffing.
    routes_by_process: bool,
}

/// How one rule matches a flow. The names are normalized, and everything
/// that is not small is boxed: a profile's scanned rules are a list of
/// these.
#[derive(Debug, Clone)]
enum RuleMatcher {
    Domain(Box<str>),
    DomainSuffix(Box<str>),
    DomainKeyword(Box<str>),
    DomainRegex(Box<Regex>),
    GeoIp(Arc<GeoIpMatcher>),
    GeoSite(Arc<RuleSetMatcher>),
    IpCidr(CidrRange),
    SrcIpCidr(CidrRange),
    DstPort(PortRanges),
    SrcPort(PortRanges),
    ProcessName(Box<str>),
    ProcessPath(Box<str>),
    Network(TransportNetwork),
    And(Box<[RuleMatcher]>),
    Or(Box<[RuleMatcher]>),
    Not(Box<RuleMatcher>),
    RuleSet(Box<RuleSetMatcher>),
    Match,
}

/// A compiled rule provider: one RULE-SET rule matches when any entry does.
/// Names are bucketed by shape so a host lookup stays a handful of hash
/// probes over the label boundaries instead of a scan of the set, and the
/// buckets index the provider's shared entry block rather than copying it;
/// networks are one sorted range set. That holds for every behavior: a
/// `classical` set's `DOMAIN`, `DOMAIN-SUFFIX` and `IP-CIDR` entries, which
/// are nearly all of a real list, go to the same buckets, its keywords and
/// regular expressions to the automata a name is run through once
/// (`rule_engine/patterns.rs`), and only its other rules are tried one by
/// one.
#[derive(Debug, Clone, Default)]
struct RuleSetMatcher {
    domains: DomainIndex,
    /// What reads a name without being one: keywords, regular expressions
    /// and names with an interior `*` (one label per star, as in `a.*.com`).
    patterns: Patterns,
    cidrs: IpRangeSet,
    /// The rules of a `classical` set that read anything else than the
    /// name or the destination address, tried in turn.
    scanned: Vec<RuleMatcher>,
}

impl RuleSetMatcher {
    /// Compiles the fetched entries, returning the matcher and how many
    /// entries were skipped as unparseable.
    fn compile(content: &RuleSetContent, inputs: &CompileInputs) -> (Self, usize) {
        match content.behavior {
            RuleSetBehavior::Domain => {
                Self::compile_domains(&content.entries, PatternsBuilder::default())
            }
            RuleSetBehavior::Ipcidr => Self::compile_networks(&content.entries),
            RuleSetBehavior::Classical => Self::compile_classical(&content.entries, inputs),
        }
    }

    /// Collects `ipcidr` behavior entries, returning the matcher and how
    /// many entries were skipped as unparseable.
    fn compile_networks(entries: &RuleSetEntries) -> (Self, usize) {
        let mut networks = Vec::new();
        let mut skipped = 0_usize;
        for entry in entries.iter().map(str::trim) {
            if entry.is_empty() {
                continue;
            }
            match CidrRange::parse(entry) {
                Some(range) => networks.push(range),
                None => skipped += 1,
            }
        }
        let matcher = Self {
            cidrs: IpRangeSet::from_networks(networks),
            ..Self::default()
        };
        (matcher, skipped)
    }

    /// Compiles `classical` behavior entries -- full rule texts without an
    /// outbound -- returning the matcher and how many entries were skipped
    /// as unparseable. Any entry matching makes the set match, so the names
    /// and networks among them are indexed as a `domain` and an `ipcidr`
    /// set's are, wherever they stand in the list.
    fn compile_classical(entries: &RuleSetEntries, inputs: &CompileInputs) -> (Self, usize) {
        let mut matcher = Self {
            domains: DomainIndex::classical(entries.clone()),
            ..Self::default()
        };
        let mut networks = Vec::new();
        let mut patterns = PatternsBuilder::default();
        let mut skipped = 0_usize;
        for (index, entry) in entries.iter().enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let indexed = match compile_logic_sub_rule(entry, inputs) {
                Ok(RuleMatcher::Domain(name)) => matcher.domains.insert_exact(index, &name),
                Ok(RuleMatcher::DomainSuffix(name)) => matcher.domains.insert_suffix(index, &name),
                Ok(RuleMatcher::DomainKeyword(keyword)) => {
                    patterns.keyword(&keyword);
                    Insert::Indexed
                }
                Ok(RuleMatcher::DomainRegex(regex)) => {
                    patterns.expression(regex.as_str());
                    Insert::Indexed
                }
                Ok(RuleMatcher::IpCidr(range)) => {
                    networks.push(range);
                    Insert::Indexed
                }
                Ok(other) => {
                    matcher.scanned.push(other);
                    Insert::Indexed
                }
                Err(_) => Insert::Skipped,
            };
            if matches!(indexed, Insert::Skipped) {
                skipped += 1;
            }
        }
        matcher.domains.shrink_to_fit();
        matcher.scanned.shrink_to_fit();
        matcher.cidrs = IpRangeSet::from_networks(networks);
        let (patterns, left_out) = patterns.build();
        matcher.patterns = patterns;
        (matcher, skipped + left_out)
    }

    /// Indexes `domain` behavior entries, returning the matcher and how many
    /// entries were skipped as unparseable. `patterns` are what else the
    /// set matches a name by; the entries with an interior `*` join them.
    fn compile_domains(entries: &RuleSetEntries, mut patterns: PatternsBuilder) -> (Self, usize) {
        let mut matcher = Self {
            domains: DomainIndex::new(entries.clone()),
            ..Self::default()
        };
        let mut skipped = 0_usize;
        for (index, entry) in entries.iter().enumerate() {
            if entry.trim().is_empty() {
                continue;
            }
            match matcher.domains.insert(index) {
                Insert::Indexed => {}
                Insert::Skipped => skipped += 1,
                Insert::Wildcard(entry) => patterns.wildcard_name(&entry),
            }
        }
        matcher.domains.shrink_to_fit();
        let (patterns, left_out) = patterns.build();
        matcher.patterns = patterns;
        (matcher, skipped + left_out)
    }

    fn matches(&self, flow: &Flow) -> bool {
        flow.host.is_some_and(|host| self.matches_domain(host))
            || flow
                .destination_ip
                .is_some_and(|ip| self.cidrs.contains(ip))
            || self
                .scanned
                .iter()
                .any(|matcher| matcher_matches(matcher, flow))
    }

    fn matches_domain(&self, host: &str) -> bool {
        self.domains.matches(host) || self.patterns.is_match(host)
    }

    fn uses_address(&self) -> bool {
        !self.cidrs.is_empty() || self.scanned.iter().any(matcher_uses_address)
    }

    fn uses_process(&self) -> bool {
        self.scanned.iter().any(matcher_uses_process)
    }

    fn wants_host(&self) -> bool {
        !self.domains.is_empty()
            || !self.patterns.is_empty()
            || self.scanned.iter().any(matcher_wants_host)
    }
}

#[derive(Debug, Clone)]
struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

/// A port-range payload: `80`, `80-90`, `80/443`, `8000-9000/443`, with `,`
/// accepted as a `/` synonym (only usable in logic sub-rules, where the
/// payload isn't comma-split). A reversed bound like `90-80` is normalized.
#[derive(Debug, Clone)]
struct PortRanges(Box<[(u16, u16)]>);

impl PortRanges {
    fn parse(payload: &str) -> Option<Self> {
        let normalized = payload.trim().replace(',', "/");
        let mut ranges = Vec::new();
        for segment in normalized.split('/') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let (start, end) = match segment.split_once('-') {
                Some((start, end)) => (
                    start.trim().parse::<u16>().ok()?,
                    end.trim().parse::<u16>().ok()?,
                ),
                None => {
                    let value = segment.parse::<u16>().ok()?;
                    (value, value)
                }
            };
            ranges.push((start.min(end), start.max(end)));
        }
        (!ranges.is_empty()).then(|| Self(ranges.into_boxed_slice()))
    }

    fn contains(&self, value: u16) -> bool {
        self.0
            .iter()
            .any(|&(start, end)| (start..=end).contains(&value))
    }
}

/// What rules compile against besides their own text: the rule-set
/// contents and the geodata the host injected.
struct CompileInputs<'a> {
    rule_sets: HashMap<&'a str, &'a RuleSetContent>,
    geodata: GeoDataMatchers,
}

impl RuleEngine {
    pub fn compile(profile: &RuntimeProfile) -> Self {
        let mut warnings = Vec::new();
        let inputs = CompileInputs {
            rule_sets: profile
                .rule_sets
                .iter()
                .map(|content| (content.name.as_str(), content))
                .collect(),
            geodata: GeoDataMatchers::compile(&profile.geodata),
        };
        let rules = profile.rules.clone();
        let mut index = RuleIndexBuilder::default();
        // Domain rules positioned after the first MATCH rule are unreachable
        // (MATCH always wins at a smaller index), so they don't justify
        // paying for a sniff either; nor does a process rule there justify
        // waiting for attribution.
        let mut reachable = true;
        let mut wants_sniffed_host = false;
        let mut routes_by_process = false;
        for (position, rule) in rules.iter().enumerate() {
            // The block holds no more rules than 32 bits count.
            let place = position as u32;
            let matcher = match rule.kind {
                // A name's first rule is held by its place alone; no matcher
                // is made for it.
                RuleKind::Domain | RuleKind::DomainSuffix => {
                    let exact = rule.kind == RuleKind::Domain;
                    let what = if exact { "domain" } else { "domain suffix" };
                    let name = match domain_name(payload(&rule), what) {
                        Ok(name) => name,
                        Err(message) => {
                            warnings.push(RuleEngineCompileWarning {
                                rule: position,
                                message,
                            });
                            continue;
                        }
                    };
                    let first = if exact {
                        index.hold_exact(&rules, place, &name)
                    } else {
                        index.hold_suffix(&rules, place, &name)
                    };
                    if first {
                        wants_sniffed_host |= reachable;
                        continue;
                    }
                    if exact {
                        RuleMatcher::Domain(name.into())
                    } else {
                        RuleMatcher::DomainSuffix(name.into())
                    }
                }
                _ => match compile_matcher(position, &rule, &inputs, &mut warnings) {
                    Some(matcher) => matcher,
                    None => continue,
                },
            };
            if reachable {
                wants_sniffed_host |= matcher_wants_host(&matcher);
                routes_by_process |= matcher_uses_process(&matcher);
                reachable = !matches!(matcher, RuleMatcher::Match);
            }
            let resolves = !rule.no_resolve && matcher_uses_address(&matcher);
            index.hold(&rules, place, resolves, matcher);
        }
        let index = index.finish(&rules);

        Self {
            traffic_policy_mode: profile.traffic_policy_mode,
            rules,
            index,
            global_outbound: global_outbound(profile),
            warnings,
            wants_sniffed_host,
            routes_by_process,
        }
    }

    pub fn warnings(&self) -> &[RuleEngineCompileWarning] {
        &self.warnings
    }

    /// Tells the host's log, as a Core goes live with these rules, which of
    /// them it left out or cut short: the first few by what they say, then
    /// how many more. A list that is all of a type the engine does not
    /// implement would otherwise be thousands of lines.
    pub(crate) fn log_warnings(&self) {
        const NAMED: usize = 20;
        for warning in self.warnings.iter().take(NAMED) {
            log::warn!(
                target: "rules",
                "{}: {}",
                self.rules.rule(warning.rule).text(),
                warning.message
            );
        }
        if let Some(more) = self
            .warnings
            .len()
            .checked_sub(NAMED)
            .filter(|&more| more > 0)
        {
            log::warn!(target: "rules", "{more} more rules are left out or cut short");
        }
    }

    /// Whether the sniff stage could refine routing for a bare-IP target: the
    /// compile-time short-circuit.
    pub fn wants_sniffed_host(&self) -> bool {
        self.wants_sniffed_host_for(self.traffic_policy_mode)
    }

    pub(crate) fn wants_sniffed_host_for(&self, mode: TrafficPolicyMode) -> bool {
        mode == TrafficPolicyMode::Rule && self.wants_sniffed_host
    }

    /// Whether a route under `mode` can depend on the flow's process: only
    /// then does a new flow wait for attribution before it is routed.
    pub(crate) fn routes_by_process_for(&self, mode: TrafficPolicyMode) -> bool {
        mode == TrafficPolicyMode::Rule && self.routes_by_process
    }

    pub(crate) fn traffic_policy(&self) -> (TrafficPolicyMode, &str) {
        (self.traffic_policy_mode, &self.global_outbound)
    }

    /// Routes with only the address the input carries; a rule asking for a
    /// resolved one does not match.
    pub fn route(&self, input: &RouteMatchInput) -> RouteDecision {
        self.route_unresolved(
            input,
            self.traffic_policy_mode,
            &self.global_outbound,
            &|_| true,
        )
        .0
    }

    /// [`Self::route_with_policy`] when no address can be resolved, and
    /// whether a rule asked for one.
    pub(crate) fn route_unresolved(
        &self,
        input: &RouteMatchInput,
        mode: TrafficPolicyMode,
        global_outbound: &str,
        accepts: &dyn Fn(&str) -> bool,
    ) -> (RouteDecision, bool) {
        match self.route_with_policy(input, mode, global_outbound, accepts, None) {
            RouteStep::Decided(decision) => (decision, false),
            RouteStep::NeedsAddress(from_rule) => {
                let unresolved = RuleAddress {
                    from_rule,
                    ip: None,
                };
                let RouteStep::Decided(decision) =
                    self.route_with_policy(input, mode, global_outbound, accepts, Some(unresolved))
                else {
                    unreachable!("a route given an address never asks for one");
                };
                (decision, true)
            }
        }
    }

    /// Routes under `mode`. In rule mode the first rule that matches and whose
    /// outbound `accepts` takes wins, and nothing taken routes DIRECT: a UDP
    /// flow refuses outbounds with UDP off, so it skips their rules and keeps
    /// matching. A destination known only by name stops the scan at the
    /// first IP rule that may resolve it; the caller resolves the name and
    /// routes again with the `address`.
    pub(crate) fn route_with_policy(
        &self,
        input: &RouteMatchInput,
        mode: TrafficPolicyMode,
        global_outbound: &str,
        accepts: &dyn Fn(&str) -> bool,
        address: Option<RuleAddress>,
    ) -> RouteStep {
        match mode {
            TrafficPolicyMode::Direct => {
                return RouteStep::Decided(Self::mode_decision(mode, "DIRECT"))
            }
            TrafficPolicyMode::Global => {
                return RouteStep::Decided(Self::mode_decision(mode, global_outbound))
            }
            TrafficPolicyMode::Rule => {}
        }
        let (position, kind) = match self.first_match(input, accepts, address) {
            Ok(Some(hit)) => hit,
            Ok(None) => return RouteStep::Decided(Self::mode_decision(mode, "DIRECT")),
            Err(position) => return RouteStep::NeedsAddress(position),
        };

        let rule = self.rules.rule(position);
        RouteStep::Decided(RouteDecision {
            traffic_policy_mode: mode,
            outbound: rule.outbound.to_owned(),
            matched_rule: Some(rule.text()),
            matched_kind: Some(kind),
            matched_payload: rule.payload.map(str::to_owned),
            no_resolve: rule.no_resolve,
        })
    }

    /// The first rule in profile order that matches `input` and whose
    /// outbound `accepts` takes, or the position of the IP rule that needs a
    /// name resolved first. What the tables find and the scanned rules merge
    /// by position, so the scan stops at the first of either that settles
    /// the flow.
    fn first_match(
        &self,
        input: &RouteMatchInput,
        accepts: &dyn Fn(&str) -> bool,
        address: Option<RuleAddress>,
    ) -> Result<Option<(usize, RouteMatchKind)>, usize> {
        let may_resolve =
            address.is_none() && input.destination_ip.is_none() && input.host.is_some();
        let host = input.host.as_deref().map(normalize_domain);
        let flow = Flow {
            input,
            host: host.as_deref(),
            destination_ip: input.destination_ip,
        };
        let resolved = address.and_then(|address| {
            address.ip.map(|ip| {
                (
                    address.from_rule,
                    Flow {
                        destination_ip: Some(ip),
                        ..flow
                    },
                )
            })
        });
        let taken = |position: usize| {
            let outbound = self.rules.outbound(position);
            !is_pass_outbound(outbound) && accepts(outbound)
        };

        // What the tables find, each at its rule's place.
        let mut found = Vec::new();
        if let Some(host) = flow.host {
            self.index.by_host(&self.rules, host, |position, kind| {
                found.push((position, Found::Matches(kind)));
            });
        }
        // A rule sees the address the flow came with, or from the asking
        // rule on the one its name resolved to.
        let (seen_until, seen_from) = match &resolved {
            Some((from_rule, with_address)) => (*from_rule, with_address.destination_ip),
            None => (usize::MAX, None),
        };
        for (ip, places) in [
            (flow.destination_ip, 0..seen_until),
            (seen_from, seen_until..usize::MAX),
        ] {
            let Some(ip) = ip else { continue };
            self.index.by_address(ip, |position| {
                if places.contains(&position) {
                    found.push((position, Found::Matches(RouteMatchKind::IpCidr)));
                }
            });
        }
        if may_resolve {
            if let Some(position) = self.index.first_asking(&taken) {
                found.push((position, Found::AsksAddress));
            }
        }
        found.sort_unstable_by_key(|&(position, _)| position);
        // A keyword a name holds twice is found twice.
        found.dedup_by_key(|&mut (position, _)| position);
        let mut found = found.into_iter().peekable();
        let settle = |position: usize, found: Found| match found {
            Found::Matches(kind) => taken(position).then_some(Ok(Some((position, kind)))),
            Found::AsksAddress => Some(Err(position)),
        };

        for rule in &self.index.scan {
            let position = rule.position as usize;
            while let Some((place, what)) = found.next_if(|&(place, _)| place < position) {
                if let Some(outcome) = settle(place, what) {
                    return outcome;
                }
            }
            if may_resolve && rule.resolves && taken(position) {
                return Err(position);
            }
            let flow = match &resolved {
                Some((from_rule, with_address)) if position >= *from_rule => with_address,
                _ => &flow,
            };
            if matcher_matches(&rule.matcher, flow) && taken(position) {
                return Ok(Some((position, matcher_kind(&rule.matcher))));
            }
        }
        found
            .find_map(|(place, what)| settle(place, what))
            .unwrap_or(Ok(None))
    }

    fn mode_decision(mode: TrafficPolicyMode, outbound: &str) -> RouteDecision {
        RouteDecision {
            traffic_policy_mode: mode,
            outbound: outbound.into(),
            matched_rule: None,
            matched_kind: None,
            matched_payload: None,
            no_resolve: false,
        }
    }
}

/// What the tables found at a rule's place: the rule matches the flow, or
/// it is the first rule there that asks for the name's address.
#[derive(Clone, Copy)]
enum Found {
    Matches(RouteMatchKind),
    AsksAddress,
}

/// What the matchers read of a flow: its input, with the host normalized
/// once for all of them and the address the rule at hand may see.
#[derive(Clone, Copy)]
struct Flow<'a> {
    input: &'a RouteMatchInput,
    host: Option<&'a str>,
    destination_ip: Option<IpAddr>,
}

/// The recursive match step, shared by top-level rules and logic sub-rules.
/// Absent input fields never match, so such rules fall through to the next
/// rule in the scan.
fn matcher_matches(matcher: &RuleMatcher, flow: &Flow) -> bool {
    let input = flow.input;
    match matcher {
        RuleMatcher::Domain(domain) => flow.host.is_some_and(|host| host == &**domain),
        RuleMatcher::DomainSuffix(suffix) => flow
            .host
            .is_some_and(|host| domain_has_suffix(host, suffix)),
        RuleMatcher::DomainKeyword(keyword) => {
            flow.host.is_some_and(|host| host.contains(&**keyword))
        }
        RuleMatcher::DomainRegex(regex) => flow.host.is_some_and(|host| regex.is_match(host)),
        RuleMatcher::GeoIp(networks) => flow.destination_ip.is_some_and(|ip| networks.matches(ip)),
        RuleMatcher::GeoSite(domains) => domains.matches(flow),
        RuleMatcher::IpCidr(range) => flow.destination_ip.is_some_and(|ip| range.contains(ip)),
        RuleMatcher::SrcIpCidr(range) => input.source_ip.is_some_and(|ip| range.contains(ip)),
        RuleMatcher::DstPort(ranges) => input
            .destination_port
            .is_some_and(|port| ranges.contains(port)),
        RuleMatcher::SrcPort(ranges) => input.source_port.is_some_and(|port| ranges.contains(port)),
        RuleMatcher::ProcessName(name) => input
            .process_name
            .as_deref()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name)),
        RuleMatcher::ProcessPath(path) => input
            .process_path
            .as_deref()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(path)),
        RuleMatcher::Network(network) => input.network == Some(*network),
        RuleMatcher::And(members) => members.iter().all(|member| matcher_matches(member, flow)),
        RuleMatcher::Or(members) => members.iter().any(|member| matcher_matches(member, flow)),
        RuleMatcher::Not(member) => !matcher_matches(member, flow),
        RuleMatcher::RuleSet(rule_set) => rule_set.matches(flow),
        RuleMatcher::Match => true,
    }
}

/// Whether the matcher reads the destination address, which a name has to
/// be resolved to give it.
fn matcher_uses_address(matcher: &RuleMatcher) -> bool {
    match matcher {
        RuleMatcher::IpCidr(_) | RuleMatcher::GeoIp(_) => true,
        RuleMatcher::And(members) | RuleMatcher::Or(members) => {
            members.iter().any(matcher_uses_address)
        }
        RuleMatcher::Not(member) => matcher_uses_address(member),
        RuleMatcher::RuleSet(rule_set) => rule_set.uses_address(),
        _ => false,
    }
}

/// Whether the matcher reads the flow's process, which attribution has to
/// find before the rule can be tried.
fn matcher_uses_process(matcher: &RuleMatcher) -> bool {
    match matcher {
        RuleMatcher::ProcessName(_) | RuleMatcher::ProcessPath(_) => true,
        RuleMatcher::And(members) | RuleMatcher::Or(members) => {
            members.iter().any(matcher_uses_process)
        }
        RuleMatcher::Not(member) => matcher_uses_process(member),
        RuleMatcher::RuleSet(rule_set) => rule_set.uses_process(),
        _ => false,
    }
}

/// Whether a sniffed domain could flip this matcher's verdict; logic rules
/// count when any nested matcher is domain-based (a NOT around a domain
/// rule still needs the host to evaluate correctly).
fn matcher_wants_host(matcher: &RuleMatcher) -> bool {
    match matcher {
        RuleMatcher::Domain(_)
        | RuleMatcher::DomainSuffix(_)
        | RuleMatcher::DomainKeyword(_)
        | RuleMatcher::DomainRegex(_)
        | RuleMatcher::GeoSite(_) => true,
        RuleMatcher::And(members) | RuleMatcher::Or(members) => {
            members.iter().any(matcher_wants_host)
        }
        RuleMatcher::Not(member) => matcher_wants_host(member),
        RuleMatcher::RuleSet(rule_set) => rule_set.wants_host(),
        _ => false,
    }
}

fn matcher_kind(matcher: &RuleMatcher) -> RouteMatchKind {
    match matcher {
        RuleMatcher::Domain(_) => RouteMatchKind::Domain,
        RuleMatcher::DomainSuffix(_) => RouteMatchKind::DomainSuffix,
        RuleMatcher::DomainKeyword(_) => RouteMatchKind::DomainKeyword,
        RuleMatcher::DomainRegex(_) => RouteMatchKind::DomainRegex,
        RuleMatcher::GeoIp(_) => RouteMatchKind::GeoIp,
        RuleMatcher::GeoSite(_) => RouteMatchKind::GeoSite,
        RuleMatcher::IpCidr(_) => RouteMatchKind::IpCidr,
        RuleMatcher::SrcIpCidr(_) => RouteMatchKind::SrcIpCidr,
        RuleMatcher::DstPort(_) => RouteMatchKind::DstPort,
        RuleMatcher::SrcPort(_) => RouteMatchKind::SrcPort,
        RuleMatcher::ProcessName(_) => RouteMatchKind::ProcessName,
        RuleMatcher::ProcessPath(_) => RouteMatchKind::ProcessPath,
        RuleMatcher::Network(_) => RouteMatchKind::Network,
        RuleMatcher::And(_) => RouteMatchKind::And,
        RuleMatcher::Or(_) => RouteMatchKind::Or,
        RuleMatcher::Not(_) => RouteMatchKind::Not,
        RuleMatcher::RuleSet(_) => RouteMatchKind::RuleSet,
        RuleMatcher::Match => RouteMatchKind::Match,
    }
}

impl CidrRange {
    fn parse(payload: &str) -> Option<Self> {
        let (address, prefix) = payload.split_once('/')?;
        let network = address.trim().parse::<IpAddr>().ok()?;
        let prefix_len = prefix.trim().parse::<u8>().ok()?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        (prefix_len <= max_prefix).then_some(Self {
            network,
            prefix_len,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = cidr_mask_u32(self.prefix_len);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = cidr_mask_u128(self.prefix_len);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// DOMAIN-REGEX payloads match case-insensitively, as domain names do.
fn compile_rule_regex(payload: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(payload).case_insensitive(true).build()
}

/// The rules the engine leaves out of routing whatever the host gives it,
/// each by its place with why: a kind the engine does not implement, or a
/// payload that is not what the kind reads. Whether a rule set a rule names
/// has been fetched and whether the GEODATA has a code are the host's to
/// say and are not judged: given every rule set and code, these are the
/// rules a compile warns of.
pub fn rule_support_issues(rules: &RouteRules) -> Vec<RuleEngineCompileWarning> {
    let inputs = CompileInputs {
        rule_sets: HashMap::new(),
        geodata: GeoDataMatchers::any_code(),
    };
    rules
        .iter()
        .enumerate()
        .filter_map(|(position, rule)| {
            let payload = payload(&rule);
            let issue = match rule.kind {
                RuleKind::Domain => domain_name(payload, "domain").err(),
                RuleKind::DomainSuffix => domain_name(payload, "domain suffix").err(),
                RuleKind::RuleSet => payload
                    .is_none()
                    .then(|| "rule set rule is missing payload".to_string()),
                kind => compile_kind_matcher(kind, payload, &inputs).err(),
            };
            issue.map(|message| RuleEngineCompileWarning {
                rule: position,
                message,
            })
        })
        .collect()
}

/// The matcher of the rule at `position`, or a warning saying why the rule
/// takes no part in routing.
fn compile_matcher(
    position: usize,
    rule: &RouteRule<'_>,
    inputs: &CompileInputs,
    warnings: &mut Vec<RuleEngineCompileWarning>,
) -> Option<RuleMatcher> {
    let mut warn = |message: String| {
        warnings.push(RuleEngineCompileWarning {
            rule: position,
            message,
        });
    };
    let compiled = match rule.kind {
        // RULE-SET resolves against the host-fetched provider contents,
        // which only exist at this top level — nested references (classical
        // entries, logic sub-rules) reach compile_kind_matcher's error.
        RuleKind::RuleSet => match payload(rule) {
            None => Err("rule set rule is missing payload".to_string()),
            Some(name) => match inputs.rule_sets.get(name) {
                None => Err(
                    "rule set has no fetched content yet; update it from the rules page".into(),
                ),
                Some(content) => {
                    let (matcher, skipped) = RuleSetMatcher::compile(content, inputs);
                    if skipped > 0 {
                        warn(format!(
                            "rule set '{name}' has {skipped} entries the engine could not parse"
                        ));
                    }
                    Ok(RuleMatcher::RuleSet(Box::new(matcher)))
                }
            },
        },
        RuleKind::Geosite => match payload(rule) {
            None => Err("geosite rule is missing payload".to_string()),
            Some(selection) => inputs.geodata.geosite(selection).map(|(matcher, skipped)| {
                if skipped > 0 {
                    warn(format!(
                        "geosite '{selection}' has {skipped} expressions the engine could not compile"
                    ));
                }
                RuleMatcher::GeoSite(matcher)
            }),
        },
        kind => compile_kind_matcher(kind, payload(rule), inputs),
    };
    match compiled {
        Ok(matcher) => Some(matcher),
        Err(message) => {
            warn(message);
            None
        }
    }
}

/// Compiles one (kind, payload) pair; also the recursion step for logic
/// rules, whose sub-rules are (kind, payload) pairs without an outbound.
fn compile_kind_matcher(
    kind: RuleKind,
    payload: Option<&str>,
    inputs: &CompileInputs,
) -> Result<RuleMatcher, String> {
    let payload = payload.map(str::trim).filter(|value| !value.is_empty());
    match kind {
        RuleKind::Domain => Ok(RuleMatcher::Domain(domain_name(payload, "domain")?.into())),
        RuleKind::DomainSuffix => Ok(RuleMatcher::DomainSuffix(
            domain_name(payload, "domain suffix")?.into(),
        )),
        RuleKind::DomainKeyword => Ok(RuleMatcher::DomainKeyword(
            normalize_keyword(require_payload(payload, "domain keyword")?).into(),
        )),
        RuleKind::DomainRegex => compile_rule_regex(require_payload(payload, "domain regex")?)
            .map(|regex| RuleMatcher::DomainRegex(Box::new(regex)))
            .map_err(|error| format!("domain regex payload does not compile: {error}")),
        RuleKind::GeoIp => inputs
            .geodata
            .geoip(require_payload(payload, "geoip")?)
            .map(RuleMatcher::GeoIp),
        RuleKind::Geosite => inputs
            .geodata
            .geosite(require_payload(payload, "geosite")?)
            .map(|(matcher, _)| RuleMatcher::GeoSite(matcher)),
        RuleKind::IpCidr | RuleKind::IpCidr6 => require_payload(payload, "IP CIDR")
            .and_then(|value| {
                CidrRange::parse(value).ok_or_else(|| "IP CIDR rule has invalid payload".into())
            })
            .map(RuleMatcher::IpCidr),
        RuleKind::SrcIpCidr => require_payload(payload, "source IP CIDR")
            .and_then(|value| {
                CidrRange::parse(value)
                    .ok_or_else(|| "source IP CIDR rule has invalid payload".into())
            })
            .map(RuleMatcher::SrcIpCidr),
        RuleKind::DstPort => {
            parse_port_ranges(payload, "destination port").map(RuleMatcher::DstPort)
        }
        RuleKind::SrcPort => parse_port_ranges(payload, "source port").map(RuleMatcher::SrcPort),
        RuleKind::ProcessName => Ok(RuleMatcher::ProcessName(
            require_payload(payload, "process name")?.into(),
        )),
        RuleKind::ProcessPath => Ok(RuleMatcher::ProcessPath(
            require_payload(payload, "process path")?.into(),
        )),
        RuleKind::Network => match require_payload(payload, "network")?
            .to_ascii_uppercase()
            .as_str()
        {
            "TCP" => Ok(RuleMatcher::Network(TransportNetwork::Tcp)),
            "UDP" => Ok(RuleMatcher::Network(TransportNetwork::Udp)),
            other => Err(format!("network rule only supports TCP/UDP, got '{other}'")),
        },
        RuleKind::And => {
            compile_logic_members(require_payload(payload, "AND")?, inputs).map(RuleMatcher::And)
        }
        RuleKind::Or => {
            compile_logic_members(require_payload(payload, "OR")?, inputs).map(RuleMatcher::Or)
        }
        RuleKind::Not => {
            let members = compile_logic_members(require_payload(payload, "NOT")?, inputs)?;
            match <[RuleMatcher; 1]>::try_from(members.into_vec()) {
                Ok([member]) => Ok(RuleMatcher::Not(Box::new(member))),
                Err(_) => Err("NOT rule must contain exactly one sub-rule".into()),
            }
        }
        RuleKind::Match => Ok(RuleMatcher::Match),
        // Top-level RULE-SET is resolved in compile_matcher against the
        // fetched provider contents; reaching this arm means a nested
        // reference (logic sub-rule or classical entry), which is not
        // supported.
        RuleKind::RuleSet => {
            Err("RULE-SET cannot be nested inside logic rules or rule sets".into())
        }
        RuleKind::Unknown => {
            Err("rule kind is not implemented by the native rule engine yet".into())
        }
    }
}

fn require_payload<'a>(payload: Option<&'a str>, what: &str) -> Result<&'a str, String> {
    payload.ok_or_else(|| format!("{what} rule is missing payload"))
}

fn parse_port_ranges(payload: Option<&str>, what: &str) -> Result<PortRanges, String> {
    PortRanges::parse(require_payload(payload, what)?)
        .ok_or_else(|| format!("{what} rule has invalid payload"))
}

/// Compiles each sub-rule of a logic payload `((RULE-A),(RULE-B))`.
fn compile_logic_members(
    payload: &str,
    inputs: &CompileInputs,
) -> Result<Box<[RuleMatcher]>, String> {
    logic_member_texts(payload)?
        .into_iter()
        .map(|text| compile_logic_sub_rule(text, inputs))
        .collect()
}

/// Splits a logic payload `((RULE-A),(RULE-B))` into its top-level
/// parenthesized sub-rule texts.
fn logic_member_texts(payload: &str) -> Result<Vec<&str>, String> {
    let payload = payload.trim();
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err("logic rule payload must be wrapped in parentheses".into());
    }

    let inner = &payload[1..payload.len() - 1];
    let mut members = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0_usize;
    for (index, character) in inner.char_indices() {
        match character {
            '(' => {
                if depth == 0 {
                    start = index + 1;
                }
                depth += 1;
            }
            ')' => {
                if depth == 0 {
                    return Err("logic rule payload has unbalanced parentheses".into());
                }
                depth -= 1;
                if depth == 0 {
                    members.push(&inner[start..index]);
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("logic rule payload has unbalanced parentheses".into());
    }
    if members.is_empty() {
        return Err("logic rule payload contains no sub-rules".into());
    }
    Ok(members)
}

fn compile_logic_sub_rule(text: &str, inputs: &CompileInputs) -> Result<RuleMatcher, String> {
    let (kind, payload) = parse_sub_rule(text)?;
    compile_kind_matcher(kind, Some(payload.as_str()), inputs)
}

/// One sub-rule text, e.g. `DOMAIN,baidu.com` or
/// `IP-CIDR,10.0.0.0/8,no-resolve` — a (kind, payload, params...) tuple
/// without an outbound — as its kind (`src` applied) and payload.
fn parse_sub_rule(text: &str) -> Result<(RuleKind, String), String> {
    let parts = text.split(',').map(str::trim).collect::<Vec<_>>();
    let kind_text = parts.first().copied().unwrap_or_default();
    if kind_text.is_empty() {
        return Err(format!("logic sub-rule '{text}' is missing a rule kind"));
    }

    let mut kind = RuleKind::from_clash_text(kind_text);
    if matches!(kind, RuleKind::Match) {
        return Err("MATCH is not allowed inside a logic rule".into());
    }
    if matches!(kind, RuleKind::Unknown) {
        return Err(format!(
            "logic sub-rule kind '{kind_text}' is not recognized"
        ));
    }

    let sub_payload;
    if kind.payload_may_contain_commas() {
        sub_payload = parts[1..].join(",");
    } else {
        sub_payload = parts.get(1).copied().unwrap_or_default().to_string();
        if parts
            .iter()
            .skip(2)
            .any(|part| part.eq_ignore_ascii_case("src"))
        {
            kind = kind.into_source_variant();
        }
    }

    Ok((kind, sub_payload))
}

fn payload<'a>(rule: &RouteRule<'a>) -> Option<&'a str> {
    rule.payload
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The name a `DOMAIN` or `DOMAIN-SUFFIX` payload stands for, as the
/// matchers compare it. A payload that is no name at all, as a lone dot is
/// not, leaves the rule without anything to match.
fn domain_name<'a>(payload: Option<&'a str>, what: &str) -> Result<Cow<'a, str>, String> {
    let name = normalize_domain(require_payload(payload, what)?);
    if name.is_empty() {
        return Err(format!("{what} rule is missing payload"));
    }
    Ok(name)
}

/// A keyword as it is looked for in a normalized name: trimmed, in
/// lowercase. It is not a name itself, so a dot at its end stays: `google.`
/// is in `google.com` and not in `googleapis.com`.
fn normalize_keyword(keyword: &str) -> String {
    keyword.trim().to_ascii_lowercase()
}

/// A name as the matchers compare it: trimmed, without the root's dot at
/// its end, in lowercase. Nearly every name already reads so and is handed
/// back as it is.
fn normalize_domain(domain: &str) -> Cow<'_, str> {
    let name = domain.trim().trim_end_matches('.');
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

fn domain_has_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

fn global_outbound(profile: &RuntimeProfile) -> String {
    profile
        .global_outbound
        .as_deref()
        .map(str::trim)
        .filter(|outbound| !outbound.is_empty())
        .map(str::to_string)
        .or_else(|| {
            profile
                .groups
                .iter()
                .find(|group| !is_builtin_terminal_outbound(&group.name))
                .map(|group| group.name.clone())
        })
        .or_else(|| {
            profile
                .proxies
                .iter()
                .find(|proxy| {
                    !matches!(
                        proxy.protocol,
                        ProxyProtocol::Direct | ProxyProtocol::Reject
                    ) && !is_builtin_terminal_outbound(&proxy.name)
                })
                .map(|proxy| proxy.name.clone())
        })
        .unwrap_or_else(|| "DIRECT".into())
}

/// The outbounds that refuse a flow: `REJECT`, `REJECT-DROP` and `BLOCK`.
/// Each is refused immediately.
pub(crate) fn is_reject_outbound(outbound: &str) -> bool {
    ["REJECT", "REJECT-DROP", "BLOCK"]
        .iter()
        .any(|name| outbound.eq_ignore_ascii_case(name))
}

/// `PASS` leaves the flow undecided, so subsequent rules select its outbound.
fn is_pass_outbound(outbound: &str) -> bool {
    outbound.eq_ignore_ascii_case("PASS")
}

fn is_builtin_terminal_outbound(outbound: &str) -> bool {
    outbound.eq_ignore_ascii_case("DIRECT") || is_reject_outbound(outbound)
}

fn cidr_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn cidr_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reject_outbound_matches_reject_and_block_case_insensitively() {
        assert!(is_reject_outbound("REJECT"));
        assert!(is_reject_outbound("reject"));
        assert!(is_reject_outbound("BLOCK"));
        assert!(is_reject_outbound("Block"));
        assert!(is_reject_outbound("REJECT-DROP"));
        assert!(is_reject_outbound("reject-drop"));
        assert!(!is_reject_outbound("PASS"));
        assert!(!is_reject_outbound("DIRECT"));
        assert!(!is_reject_outbound("proxy-hk"));
    }
    use crate::profile::{
        PolicyGroup, PolicyGroupKind, ProxyNode, ProxyProtocol, RouteRule, RuleKind,
        RuntimeProfile, TrafficPolicyMode,
    };

    #[test]
    fn routes_exact_domain_before_match_fallback() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Domain, Some("Example.COM"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("example.com."));

        assert_eq!(decision.outbound, "Proxy");
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN,Example.COM,Proxy")
        );
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::Domain));
    }

    #[test]
    fn routes_domain_suffix_for_root_and_subdomain() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("google.com"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(
            engine.route(&input_with_host("google.com")).outbound,
            "Proxy"
        );
        assert_eq!(
            engine.route(&input_with_host("mail.google.com")).outbound,
            "Proxy"
        );
        assert_eq!(
            engine.route(&input_with_host("notgoogle.com")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn routes_ip_cidr_for_ipv4_and_ipv6() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "Private", true),
            rule(RuleKind::IpCidr6, Some("fd00::/8"), "Private6", true),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(
            engine.route(&input_with_ip("10.20.30.40")).outbound,
            "Private"
        );
        assert_eq!(engine.route(&input_with_ip("fd00::1")).outbound, "Private6");
        assert_eq!(engine.route(&input_with_ip("8.8.8.8")).outbound, "DIRECT");
    }

    #[test]
    fn routes_process_names_case_insensitively() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::ProcessName, Some("curl"), "Direct", false),
            rule(RuleKind::Match, None, "Proxy", false),
        ]));

        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    process_name: Some("CURL".into()),
                    ..Default::default()
                })
                .outbound,
            "Direct"
        );
    }

    #[test]
    fn records_compile_warnings_for_unsupported_rules() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::IpCidr, Some("not-cidr"), "Proxy", false),
            rule(RuleKind::RuleSet, Some("remote-rules"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(engine.warnings().len(), 2);
        assert_eq!(
            engine.route(&input_with_host("example.com")).outbound,
            "DIRECT"
        );
    }

    /// A warning names its rule by the rule's place in the profile, whatever
    /// became of the rules before it, and the rules that stay are decided
    /// by their own places.
    #[test]
    fn a_warning_names_the_rule_by_its_place_in_the_profile() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Unknown, Some("7890"), "Proxy", false),
            rule(RuleKind::Domain, Some("."), "Proxy", false),
            rule(RuleKind::DomainSuffix, None, "Proxy", false),
            rule(RuleKind::DomainKeyword, Some(" "), "Proxy", false),
            rule(RuleKind::DomainSuffix, Some("kept.example"), "Kept", false),
            rule(RuleKind::DstPort, Some("port"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let warned: Vec<(usize, &str)> = engine
            .warnings()
            .iter()
            .map(|warning| (warning.rule, warning.message.as_str()))
            .collect();
        assert_eq!(
            warned,
            [
                (
                    0,
                    "rule kind is not implemented by the native rule engine yet"
                ),
                (1, "domain rule is missing payload"),
                (2, "domain suffix rule is missing payload"),
                (3, "domain keyword rule is missing payload"),
                (5, "destination port rule has invalid payload"),
            ]
        );
        let decision = engine.route(&input_with_host("a.kept.example"));
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN-SUFFIX,kept.example,Kept")
        );
        assert_eq!(
            engine
                .route(&input_with_host("other.example"))
                .matched_rule
                .as_deref(),
            Some("MATCH,DIRECT")
        );
    }

    /// What is judged without the host's data is what a compile that has
    /// all of it warns of, in the same words; a rule set not fetched and a
    /// code the data lacks are warned of by the compile alone.
    #[test]
    fn the_rules_left_out_whatever_the_data_are_those_a_full_compile_warns_of() {
        let mut profile = profile_with_rules(vec![
            rule(RuleKind::Unknown, Some("13335"), "Proxy", false),
            rule(RuleKind::Domain, Some("ok.example"), "Proxy", false),
            rule(RuleKind::Domain, Some("."), "Proxy", false),
            rule(RuleKind::DomainSuffix, None, "Proxy", false),
            rule(RuleKind::DomainKeyword, Some("ads"), "Proxy", false),
            rule(RuleKind::DomainRegex, Some("("), "Proxy", false),
            rule(RuleKind::IpCidr, Some("10.0.0.0/33"), "Proxy", true),
            rule(RuleKind::IpCidr6, Some("fd00::/8"), "Proxy", true),
            rule(RuleKind::DstPort, Some("80-x"), "Proxy", false),
            rule(RuleKind::Network, Some("icmp"), "Proxy", false),
            rule(RuleKind::ProcessName, None, "Proxy", false),
            rule(RuleKind::And, Some("((DOMAIN,a.example)"), "Proxy", false),
            rule(
                RuleKind::Or,
                Some("((GEOIP,CN),(GEOSITE,cn))"),
                "Proxy",
                false,
            ),
            rule(RuleKind::Not, Some("((RULE-SET,names))"), "Proxy", false),
            rule(RuleKind::GeoIp, Some("CN"), "Proxy", true),
            rule(RuleKind::GeoIp, None, "Proxy", true),
            rule(RuleKind::Geosite, Some("cn"), "Proxy", false),
            rule(RuleKind::Geosite, None, "Proxy", false),
            rule(RuleKind::RuleSet, Some("names"), "Proxy", false),
            rule(RuleKind::RuleSet, None, "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        let judged: Vec<(usize, String)> = rule_support_issues(&profile.rules)
            .into_iter()
            .map(|issue| (issue.rule, issue.message))
            .collect();
        let places: Vec<usize> = judged.iter().map(|(place, _)| *place).collect();
        assert_eq!(places, [0, 2, 3, 5, 6, 8, 9, 10, 11, 13, 15, 17, 19]);

        let warned = |profile: &RuntimeProfile| -> Vec<(usize, String)> {
            RuleEngine::compile(profile)
                .warnings()
                .iter()
                .map(|warning| (warning.rule, warning.message.clone()))
                .collect()
        };
        // Without the data, the rules that need it are warned of as well.
        let without: Vec<usize> = warned(&profile).iter().map(|(place, _)| *place).collect();
        assert_eq!(
            without,
            [0, 2, 3, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
        );
        profile.rule_sets = vec![RuleSetContent {
            name: "names".into(),
            behavior: RuleSetBehavior::Domain,
            entries: ["listed.example"].into_iter().collect(),
        }];
        profile.geodata = crate::geodata::GeoDataContent {
            geoip: Some(vec![crate::geodata::GeoIpContent {
                code: "CN".into(),
                cidrs: ["1.0.1.0/24"].into_iter().collect(),
                inverse: false,
            }]),
            geosite: Some(vec![crate::geodata::GeoSiteContent {
                selection: "cn".into(),
                names: ["+.cn"].into_iter().collect(),
                keywords: Vec::new(),
                regexes: Vec::new(),
            }]),
        };
        assert_eq!(warned(&profile), judged);
    }

    /// The engine matches over the block the profile holds its rules in: it
    /// keeps that block and makes nothing of its own for a name's rule, and
    /// a rule written in capitals is found by the name it stands for and
    /// named as it is written.
    #[test]
    fn the_profile_s_block_is_the_engine_s_and_names_are_read_from_it() {
        let profile = profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("plain.example"), "A", false),
            rule(RuleKind::Domain, Some("Exact.Example."), "B", false),
            rule(RuleKind::DomainSuffix, Some("plain.example"), "C", false),
            rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "D", true),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        let engine = RuleEngine::compile(&profile);

        assert!(engine.rules.shares_block_with(&profile.rules));
        // The suffix's second rule and MATCH are scanned; the names and the
        // network are found.
        let scanned: Vec<u32> = engine.index.scan.iter().map(|rule| rule.position).collect();
        assert_eq!(scanned, [2, 4]);
        assert_eq!(
            engine
                .route(&input_with_host("www.plain.example"))
                .matched_rule
                .as_deref(),
            Some("DOMAIN-SUFFIX,plain.example,A")
        );
        let exact = engine.route(&input_with_host("EXACT.example"));
        assert_eq!(
            exact.matched_rule.as_deref(),
            Some("DOMAIN,Exact.Example.,B")
        );
        assert_eq!(exact.matched_payload.as_deref(), Some("Exact.Example."));
        assert_eq!(exact.matched_kind, Some(RouteMatchKind::Domain));
        // A flow the first rule's outbound refuses goes on to the name's
        // next rule.
        let (decision, _) = engine.route_unresolved(
            &input_with_host("plain.example"),
            TrafficPolicyMode::Rule,
            "DIRECT",
            &|outbound| outbound != "A",
        );
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN-SUFFIX,plain.example,C")
        );
    }

    /// A keyword is looked for as it is written, a dot at its end included:
    /// it is not a name.
    #[test]
    fn a_keyword_keeps_the_dot_it_ends_with() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainKeyword, Some("Google."), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert_eq!(
            engine.route(&input_with_host("www.google.com")).outbound,
            "Proxy"
        );
        assert_eq!(
            engine.route(&input_with_host("googleapis.com")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn direct_mode_forces_direct_without_rule_match() {
        let mut profile = profile_with_rules(vec![rule(RuleKind::Match, None, "Proxy", false)]);
        profile.traffic_policy_mode = TrafficPolicyMode::Direct;
        let engine = RuleEngine::compile(&profile);

        let decision = engine.route(&input_with_host("example.com"));

        assert_eq!(decision.traffic_policy_mode, TrafficPolicyMode::Direct);
        assert_eq!(decision.outbound, "DIRECT");
        assert_eq!(decision.matched_rule, None);
    }

    #[test]
    fn global_mode_uses_explicit_global_outbound() {
        let mut profile = profile_with_rules(vec![rule(
            RuleKind::DomainSuffix,
            Some("lan"),
            "DIRECT",
            false,
        )]);
        profile.traffic_policy_mode = TrafficPolicyMode::Global;
        profile.global_outbound = Some("HK 01".into());
        let engine = RuleEngine::compile(&profile);

        let decision = engine.route(&input_with_host("router.lan"));

        assert_eq!(decision.traffic_policy_mode, TrafficPolicyMode::Global);
        assert_eq!(decision.outbound, "HK 01");
        assert_eq!(decision.matched_rule, None);
    }

    #[test]
    fn global_mode_defaults_to_first_policy_group_then_proxy() {
        let mut profile = profile_with_rules(vec![rule(RuleKind::Match, None, "DIRECT", false)]);
        profile.traffic_policy_mode = TrafficPolicyMode::Global;
        profile.groups = vec![PolicyGroup {
            id: "group-proxy".into(),
            name: "Proxy".into(),
            kind: PolicyGroupKind::Select,
            members: vec!["HK 01".into(), "DIRECT".into()],
            interval_seconds: None,
            test_url: None,
            selected: None,
        }];
        profile.proxies = vec![ProxyNode {
            id: "proxy-hk-01".into(),
            name: "HK 01".into(),
            protocol: ProxyProtocol::Http,
            server: Some("127.0.0.1".into()),
            port: Some(8080),
            options: serde_json::json!({}),
        }];
        let engine = RuleEngine::compile(&profile);

        assert_eq!(
            engine.route(&input_with_host("example.com")).outbound,
            "Proxy"
        );
    }

    #[test]
    fn earlier_cidr_rule_wins_over_later_exact_domain() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::IpCidr, Some("203.0.113.0/24"), "Proxy", false),
            rule(RuleKind::Domain, Some("example.com"), "Reject", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        let input = RouteMatchInput {
            host: Some("example.com".into()),
            destination_ip: Some("203.0.113.9".parse().unwrap()),
            ..Default::default()
        };

        let decision = engine.route(&input);

        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("IP-CIDR,203.0.113.0/24,Proxy")
        );
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::IpCidr));
    }

    #[test]
    fn earlier_domain_rule_wins_over_later_keyword_rule() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Domain, Some("example.com"), "Proxy", false),
            rule(RuleKind::DomainKeyword, Some("example"), "Reject", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("example.com"));

        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN,example.com,Proxy")
        );
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::Domain));
    }

    #[test]
    fn earlier_keyword_rule_wins_over_later_domain_rule() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainKeyword, Some("example"), "Proxy", false),
            rule(RuleKind::Domain, Some("example.com"), "Reject", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("example.com"));

        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN-KEYWORD,example,Proxy")
        );
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::DomainKeyword));
    }

    #[test]
    fn duplicate_exact_domain_rules_keep_the_earliest() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Domain, Some("example.com"), "Proxy", false),
            rule(RuleKind::Domain, Some("example.com"), "Reject", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("example.com"));

        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN,example.com,Proxy")
        );
        assert_eq!(decision.outbound, "Proxy");
    }

    #[test]
    fn suffix_rule_priority_follows_rule_order_not_specificity() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("example.com"), "Proxy", false),
            rule(
                RuleKind::DomainSuffix,
                Some("a.example.com"),
                "Reject",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("www.a.example.com"));

        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN-SUFFIX,example.com,Proxy")
        );
        assert_eq!(decision.outbound, "Proxy");
    }

    #[test]
    fn match_rule_before_domain_rule_still_wins() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Match, None, "Proxy", false),
            rule(RuleKind::Domain, Some("example.com"), "Reject", false),
        ]));

        let decision = engine.route(&input_with_host("example.com"));

        assert_eq!(decision.matched_rule.as_deref(), Some("MATCH,Proxy"));
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::Match));
    }

    #[test]
    fn routes_domain_regex_case_insensitively() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::DomainRegex,
                Some(r"^(api|cdn)\d*\.example\.com$"),
                "Proxy",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let decision = engine.route(&input_with_host("API2.example.com"));
        assert_eq!(decision.outbound, "Proxy");
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::DomainRegex));
        assert_eq!(
            engine.route(&input_with_host("www.example.com")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn invalid_domain_regex_becomes_compile_warning() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainRegex, Some("(["), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(engine.warnings().len(), 1);
        assert_eq!(
            engine.route(&input_with_host("example.com")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn routes_ports_with_range_and_list_payloads() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DstPort, Some("80/8000-9000"), "Web", false),
            rule(RuleKind::SrcPort, Some("5353"), "Mdns", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let by_dst = |port: u16| {
            engine
                .route(&RouteMatchInput {
                    destination_port: Some(port),
                    ..Default::default()
                })
                .outbound
        };
        assert_eq!(by_dst(80), "Web");
        assert_eq!(by_dst(8500), "Web");
        assert_eq!(by_dst(443), "DIRECT");

        let from_source = engine.route(&RouteMatchInput {
            source_port: Some(5353),
            ..Default::default()
        });
        assert_eq!(from_source.outbound, "Mdns");
        assert_eq!(from_source.matched_kind, Some(RouteMatchKind::SrcPort));
    }

    #[test]
    fn routes_source_ip_cidr_and_network() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::SrcIpCidr, Some("192.168.1.0/24"), "Lan", false),
            rule(RuleKind::Network, Some("udp"), "UdpOut", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    source_ip: Some("192.168.1.42".parse().unwrap()),
                    ..Default::default()
                })
                .outbound,
            "Lan"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    network: Some(TransportNetwork::Udp),
                    ..Default::default()
                })
                .outbound,
            "UdpOut"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    network: Some(TransportNetwork::Tcp),
                    ..Default::default()
                })
                .outbound,
            "DIRECT"
        );
    }

    #[test]
    fn logic_rules_combine_sub_matchers() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::And,
                Some("((DOMAIN-SUFFIX,example.com),(NETWORK,udp))"),
                "UdpProxy",
                false,
            ),
            rule(
                RuleKind::Or,
                Some("((DOMAIN,a.test),(DOMAIN,b.test))"),
                "Pair",
                false,
            ),
            rule(
                RuleKind::Not,
                Some("((DOMAIN-KEYWORD,internal))"),
                "External",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        let and_hit = engine.route(&RouteMatchInput {
            host: Some("www.example.com".into()),
            network: Some(TransportNetwork::Udp),
            ..Default::default()
        });
        assert_eq!(and_hit.outbound, "UdpProxy");
        assert_eq!(and_hit.matched_kind, Some(RouteMatchKind::And));

        // Same domain over TCP fails the AND, falls to the NOT rule.
        let and_miss = engine.route(&RouteMatchInput {
            host: Some("www.example.com".into()),
            network: Some(TransportNetwork::Tcp),
            ..Default::default()
        });
        assert_eq!(and_miss.outbound, "External");
        assert_eq!(and_miss.matched_kind, Some(RouteMatchKind::Not));

        assert_eq!(engine.route(&input_with_host("b.test")).outbound, "Pair");
        assert_eq!(
            engine.route(&input_with_host("internal.corp")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn nested_logic_rules_and_src_param_compile() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::And,
                Some("((OR,((DOMAIN,a.test),(DST-PORT,443))),(NOT,((NETWORK,udp))))"),
                "Nested",
                false,
            ),
            rule(
                RuleKind::And,
                Some("((IP-CIDR,10.0.0.0/8,src),(NETWORK,udp))"),
                "LanUdp",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert!(engine.warnings().is_empty());
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    destination_port: Some(443),
                    network: Some(TransportNetwork::Tcp),
                    ..Default::default()
                })
                .outbound,
            "Nested"
        );
        // The src param inside the logic sub-rule matches the *source* IP.
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    source_ip: Some("10.1.2.3".parse().unwrap()),
                    network: Some(TransportNetwork::Udp),
                    ..Default::default()
                })
                .outbound,
            "LanUdp"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    destination_ip: Some("10.1.2.3".parse().unwrap()),
                    network: Some(TransportNetwork::Udp),
                    ..Default::default()
                })
                .outbound,
            "DIRECT"
        );
    }

    #[test]
    fn malformed_logic_rules_become_compile_warnings() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::And,
                Some("((DOMAIN,a.test),(MATCH))"),
                "Proxy",
                false,
            ),
            rule(
                RuleKind::Not,
                Some("((DOMAIN,a.test),(DOMAIN,b.test))"),
                "Proxy",
                false,
            ),
            rule(RuleKind::And, Some("((DOMAIN,a.test)"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(engine.warnings().len(), 3);
        assert_eq!(engine.route(&input_with_host("a.test")).outbound, "DIRECT");
    }

    #[test]
    fn rule_set_domain_behavior_matches_entry_shapes() {
        let mut profile = profile_with_rules(vec![
            rule(RuleKind::RuleSet, Some("ads"), "Reject", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        profile.rule_sets = vec![RuleSetContent {
            name: "ads".into(),
            behavior: RuleSetBehavior::Domain,
            entries: [
                "exact.test",
                "+.suffix.test",
                ".subonly.test",
                "*.single.test",
            ]
            .into_iter()
            .collect(),
        }];
        let engine = RuleEngine::compile(&profile);

        assert!(engine.warnings().is_empty());
        assert!(engine.wants_sniffed_host());
        let outbound = |host: &str| engine.route(&input_with_host(host)).outbound;
        assert_eq!(outbound("exact.test"), "Reject");
        assert_eq!(outbound("www.exact.test"), "DIRECT");
        assert_eq!(outbound("suffix.test"), "Reject");
        assert_eq!(outbound("a.b.suffix.test"), "Reject");
        assert_eq!(outbound("subonly.test"), "DIRECT");
        assert_eq!(outbound("a.b.subonly.test"), "Reject");
        assert_eq!(outbound("one.single.test"), "Reject");
        assert_eq!(outbound("two.one.single.test"), "DIRECT");

        let decision = engine.route(&input_with_host("exact.test"));
        assert_eq!(decision.matched_kind, Some(RouteMatchKind::RuleSet));
        assert_eq!(decision.matched_payload.as_deref(), Some("ads"));
    }

    #[test]
    fn rule_set_ipcidr_and_classical_behaviors_match() {
        let mut profile = profile_with_rules(vec![
            rule(RuleKind::RuleSet, Some("cn-ip"), "Domestic", true),
            rule(RuleKind::RuleSet, Some("games"), "Game", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        profile.rule_sets = vec![
            RuleSetContent {
                name: "cn-ip".into(),
                behavior: RuleSetBehavior::Ipcidr,
                entries: ["223.5.5.0/24", "2400:3200::/32"].into_iter().collect(),
            },
            RuleSetContent {
                name: "games".into(),
                behavior: RuleSetBehavior::Classical,
                entries: [
                    "DOMAIN-SUFFIX,steamcontent.com",
                    "DST-PORT,27015-27050",
                    "not-a-rule",
                ]
                .into_iter()
                .collect(),
            },
        ];
        let engine = RuleEngine::compile(&profile);

        // The unparseable classical entry surfaces as one warning.
        assert_eq!(engine.warnings().len(), 1);
        assert!(engine.warnings()[0].message.contains("games"));

        assert_eq!(
            engine.route(&input_with_ip("223.5.5.5")).outbound,
            "Domestic"
        );
        assert_eq!(
            engine.route(&input_with_ip("2400:3200::1")).outbound,
            "Domestic"
        );
        assert_eq!(
            engine
                .route(&input_with_host("dl.steamcontent.com"))
                .outbound,
            "Game"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    destination_port: Some(27020),
                    ..Default::default()
                })
                .outbound,
            "Game"
        );
        assert_eq!(engine.route(&input_with_ip("1.1.1.1")).outbound, "DIRECT");
    }

    /// A classical set's names and networks are looked up, not tried one by
    /// one, however the entry is written; what is neither stays a rule.
    #[test]
    fn a_classical_rule_set_indexes_its_names_and_networks() {
        let mut profile = profile_with_rules(vec![
            rule(RuleKind::RuleSet, Some("mixed"), "Proxy", true),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        let entries: RuleSetEntries = [
            "DOMAIN,exact.test",
            "DOMAIN-SUFFIX,suffix.test",
            "domain-suffix , Spaced.Test. ",
            "DOMAIN,Upper.Test",
            "DOMAIN,*.literal.test",
            "DOMAIN-SUFFIX,+.literal.test",
            "IP-CIDR,10.1.0.0/16,no-resolve",
            "IP-CIDR6,2001:db8::/32",
            "IP-CIDR,192.168.0.0/16,src",
            "DOMAIN-KEYWORD,keyword",
            r"DOMAIN-REGEX,^cdn\d+\.regex\.test$",
            "DST-PORT,8443",
            "DOMAIN,.",
        ]
        .into_iter()
        .collect();
        profile.rule_sets = vec![RuleSetContent {
            name: "mixed".into(),
            behavior: RuleSetBehavior::Classical,
            entries: entries.clone(),
        }];
        let engine = RuleEngine::compile(&profile);

        // The name that is only a dot is the one entry that says nothing.
        assert_eq!(engine.warnings().len(), 1);
        let RuleMatcher::RuleSet(set) = &engine.index.scan[0].matcher else {
            panic!("the rule set compiles to a rule-set matcher");
        };
        assert!(matches!(
            set.scanned.as_slice(),
            [RuleMatcher::SrcIpCidr(_), RuleMatcher::DstPort(_)]
        ));
        assert!(engine.wants_sniffed_host());

        let outbound = |host: &str| engine.route(&input_with_host(host)).outbound;
        assert_eq!(outbound("exact.test"), "Proxy");
        assert_eq!(outbound("Exact.Test."), "Proxy");
        assert_eq!(outbound("www.exact.test"), "DIRECT");
        assert_eq!(outbound("suffix.test"), "Proxy");
        assert_eq!(outbound("a.b.suffix.test"), "Proxy");
        assert_eq!(outbound("notsuffix.test"), "DIRECT");
        assert_eq!(outbound("a.spaced.test"), "Proxy");
        assert_eq!(outbound("upper.test"), "Proxy");
        assert_eq!(outbound("has-keyword-inside.test"), "Proxy");
        assert_eq!(outbound("CDN7.regex.test"), "Proxy");
        assert_eq!(outbound("cdn.regex.test"), "DIRECT");
        // A classical name is the text itself: `*` and `+.` mean nothing.
        assert_eq!(outbound("*.literal.test"), "Proxy");
        assert_eq!(outbound("a.literal.test"), "DIRECT");
        assert_eq!(outbound("literal.test"), "DIRECT");

        assert_eq!(engine.route(&input_with_ip("10.1.2.3")).outbound, "Proxy");
        assert_eq!(engine.route(&input_with_ip("10.2.0.1")).outbound, "DIRECT");
        assert_eq!(
            engine.route(&input_with_ip("2001:db8::1")).outbound,
            "Proxy"
        );
        // The `src` network reads the source, not the destination.
        assert_eq!(
            engine.route(&input_with_ip("192.168.1.1")).outbound,
            "DIRECT"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    source_ip: "192.168.1.1".parse().ok(),
                    ..Default::default()
                })
                .outbound,
            "Proxy"
        );
        assert_eq!(
            engine
                .route(&RouteMatchInput {
                    destination_port: Some(8443),
                    ..Default::default()
                })
                .outbound,
            "Proxy"
        );
    }

    /// A rule to `PASS` routes nothing: the rules after it decide, an IP
    /// rule among them asking for the name's address as it would have.
    #[test]
    fn a_rule_to_pass_leaves_the_flow_to_the_rules_after_it() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("example.com"), "PASS", false),
            rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "pass", false),
            rule(RuleKind::DomainKeyword, Some("example"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(engine.warnings().is_empty());
        let decision = engine.route(&input_with_host("www.example.com"));
        assert_eq!(decision.outbound, "Proxy");
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("DOMAIN-KEYWORD,example,Proxy")
        );
        assert_eq!(engine.route(&input_with_ip("10.1.2.3")).outbound, "DIRECT");
        // The passed IP rule asks for no address either.
        let step = engine.route_with_policy(
            &input_with_host("other.test"),
            TrafficPolicyMode::Rule,
            "Proxy",
            &|_| true,
            None,
        );
        assert!(matches!(step, RouteStep::Decided(decision) if decision.outbound == "DIRECT"));
    }

    #[test]
    fn rule_set_without_fetched_content_warns_and_falls_through() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::RuleSet, Some("missing"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(engine.warnings().len(), 1);
        assert!(engine.warnings()[0].message.contains("no fetched content"));
        assert_eq!(
            engine.route(&input_with_host("example.com")).outbound,
            "DIRECT"
        );
    }

    #[test]
    fn geo_rules_without_geodata_warn_and_fall_through() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Geosite, Some("cn"), "Domestic", false),
            rule(RuleKind::GeoIp, Some("CN"), "Domestic", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));

        assert_eq!(engine.warnings().len(), 2);
        assert!(engine
            .warnings()
            .iter()
            .all(|warning| warning.message.contains("update GEODATA")));
        assert_eq!(
            engine.route(&input_with_host("baidu.com")).outbound,
            "DIRECT"
        );
        assert_eq!(engine.route(&input_with_ip("1.0.1.1")).outbound, "DIRECT");
    }

    #[test]
    fn routing_waits_for_the_process_only_when_a_reachable_rule_reads_it() {
        let rule_mode = TrafficPolicyMode::Rule;
        let plain = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("a.test"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(!plain.routes_by_process_for(rule_mode));

        let mut process = profile_with_rules(vec![
            rule(RuleKind::ProcessName, Some("curl"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        assert!(RuleEngine::compile(&process).routes_by_process_for(rule_mode));
        process.traffic_policy_mode = TrafficPolicyMode::Global;
        let global = RuleEngine::compile(&process);
        assert!(!global.routes_by_process_for(TrafficPolicyMode::Global));
        assert!(!global.routes_by_process_for(TrafficPolicyMode::Direct));

        let shadowed = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Match, None, "DIRECT", false),
            rule(RuleKind::ProcessPath, Some("/usr/bin/curl"), "Proxy", false),
        ]));
        assert!(!shadowed.routes_by_process_for(rule_mode));

        let nested = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Not, Some("((PROCESS-NAME,curl))"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(nested.routes_by_process_for(rule_mode));

        let mut in_set = profile_with_rules(vec![
            rule(RuleKind::RuleSet, Some("apps"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]);
        in_set.rule_sets = vec![RuleSetContent {
            name: "apps".into(),
            behavior: RuleSetBehavior::Classical,
            entries: ["DOMAIN,a.test", "PROCESS-NAME,curl"].into_iter().collect(),
        }];
        assert!(RuleEngine::compile(&in_set).routes_by_process_for(rule_mode));
    }

    #[test]
    fn sniff_short_circuit_reflects_reachable_domain_rules() {
        let no_domain_rules = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "A", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(!no_domain_rules.wants_sniffed_host());

        let domain_rule = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("example.com"), "Proxy", false),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(domain_rule.wants_sniffed_host());

        // Unreachable domain rule (after MATCH) does not justify sniffing.
        let shadowed = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::Match, None, "DIRECT", false),
            rule(RuleKind::Domain, Some("example.com"), "Proxy", false),
        ]));
        assert!(!shadowed.wants_sniffed_host());

        // Non-Rule modes never consult rules, so they never sniff.
        let mut global = profile_with_rules(vec![rule(
            RuleKind::Domain,
            Some("example.com"),
            "Proxy",
            false,
        )]);
        global.traffic_policy_mode = TrafficPolicyMode::Global;
        assert!(!RuleEngine::compile(&global).wants_sniffed_host());

        // A domain matcher nested inside a logic rule also justifies sniffing.
        let nested = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::And,
                Some("((DOMAIN-SUFFIX,example.com),(NETWORK,tcp))"),
                "Proxy",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(nested.wants_sniffed_host());

        let nested_without_domain = RuleEngine::compile(&profile_with_rules(vec![
            rule(
                RuleKind::And,
                Some("((DST-PORT,443),(NETWORK,tcp))"),
                "Proxy",
                false,
            ),
            rule(RuleKind::Match, None, "DIRECT", false),
        ]));
        assert!(!nested_without_domain.wants_sniffed_host());
    }

    #[test]
    fn a_refused_outbound_hands_its_rules_on_to_the_next_match() {
        let engine = RuleEngine::compile(&profile_with_rules(vec![
            rule(RuleKind::DomainSuffix, Some("example.com"), "NoUdp", false),
            rule(RuleKind::DstPort, Some("443"), "NoUdp", false),
            rule(RuleKind::DomainSuffix, Some("example.com"), "Udp", false),
            rule(RuleKind::Match, None, "NoUdp", false),
            rule(RuleKind::DomainSuffix, Some("late.test"), "Udp", false),
        ]));
        let refuse = |outbound: &str| outbound != "NoUdp";
        let route = |host: &str, mode| {
            engine
                .route_unresolved(
                    &RouteMatchInput {
                        host: Some(host.into()),
                        destination_port: Some(443),
                        ..Default::default()
                    },
                    mode,
                    "NoUdp",
                    &refuse,
                )
                .0
        };

        // A repeated domain rule and a rule past MATCH become reachable.
        let repeat = route("www.example.com", TrafficPolicyMode::Rule);
        assert_eq!(
            (repeat.outbound.as_str(), repeat.matched_rule.as_deref()),
            ("Udp", Some("DOMAIN-SUFFIX,example.com,Udp"))
        );
        assert_eq!(
            route("late.test", TrafficPolicyMode::Rule)
                .matched_rule
                .as_deref(),
            Some("DOMAIN-SUFFIX,late.test,Udp")
        );
        let nothing = route("other.test", TrafficPolicyMode::Rule);
        assert_eq!(
            (nothing.outbound.as_str(), nothing.matched_rule),
            ("DIRECT", None)
        );
        // Global mode does not consult the switch.
        assert_eq!(
            route("www.example.com", TrafficPolicyMode::Global).outbound,
            "NoUdp"
        );
        // Taking every outbound keeps first-match-wins.
        assert_eq!(
            engine
                .route(&input_with_host("www.example.com"))
                .matched_rule
                .as_deref(),
            Some("DOMAIN-SUFFIX,example.com,NoUdp")
        );
    }

    fn profile_with_rules(rules: Vec<RouteRule<'_>>) -> RuntimeProfile {
        let mut profile = RuntimeProfile::new("test");
        profile.rules = rules.into();
        profile
    }

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

    fn input_with_host(host: &str) -> RouteMatchInput {
        RouteMatchInput {
            host: Some(host.into()),
            ..Default::default()
        }
    }

    fn input_with_ip(ip: &str) -> RouteMatchInput {
        RouteMatchInput {
            destination_ip: Some(ip.parse().expect("valid IP")),
            ..Default::default()
        }
    }
}
