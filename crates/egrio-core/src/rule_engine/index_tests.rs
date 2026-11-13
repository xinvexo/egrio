//! The tables against the definition: whatever the index finds, a decision
//! is the one that trying every rule in its turn would make.

use std::net::IpAddr;

use super::*;
use crate::profile::{RouteRule, RouteRules, RuleKind, RuntimeProfile};

/// What trying every rule in turn decides: the first rule that matches and
/// whose outbound takes the flow, or the first that asks for the name's
/// address. Each rule is compiled on its own and nothing is looked up.
fn in_turn(
    rules: &RouteRules,
    input: &RouteMatchInput,
    accepts: &dyn Fn(&str) -> bool,
    address: Option<RuleAddress>,
) -> Result<Option<(usize, RouteMatchKind)>, usize> {
    let inputs = CompileInputs {
        rule_sets: HashMap::new(),
        geodata: GeoDataMatchers::compile(&Default::default()),
    };
    let may_resolve = address.is_none() && input.destination_ip.is_none() && input.host.is_some();
    let host = input.host.as_deref().map(normalize_domain);
    for (position, rule) in rules.iter().enumerate() {
        let Ok(matcher) = compile_kind_matcher(rule.kind, payload(&rule), &inputs) else {
            continue;
        };
        let taken = !is_pass_outbound(rule.outbound) && accepts(rule.outbound);
        if may_resolve && !rule.no_resolve && matcher_uses_address(&matcher) && taken {
            return Err(position);
        }
        let destination_ip = match address {
            Some(RuleAddress {
                from_rule,
                ip: Some(ip),
            }) if position >= from_rule => Some(ip),
            _ => input.destination_ip,
        };
        let flow = Flow {
            input,
            host: host.as_deref(),
            destination_ip,
        };
        if matcher_matches(&matcher, &flow) && taken {
            return Ok(Some((position, matcher_kind(&matcher))));
        }
    }
    Ok(None)
}

/// A small generator with a fixed seed: the cases are the same every run.
struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: usize) -> usize {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as usize % sides
    }

    fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
        from[self.roll(from.len())]
    }
}

// Few of each, so that rules repeat a name, nest their networks and share
// their keywords, and a flow often meets several rules at once.
const NAMES: [&str; 8] = [
    "example.com",
    "Example.COM",
    "a.example.com",
    "b.a.example.com",
    "test.net",
    "x.test.net.",
    "com",
    "other.org",
];
const KEYWORDS: [&str; 6] = ["exa", "test", ".com", "a.", "EXAMPLE", "zzz"];
const NETWORKS: [&str; 10] = [
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.1.2.0/24",
    "10.1.2.3/32",
    "10.9.9.9/8",
    "0.0.0.0/0",
    "fd00::/8",
    "fd00:1::/32",
    "::/0",
    "192.0.2.0/24",
];
const OUTBOUNDS: [&str; 4] = ["A", "B", "NoUdp", "PASS"];
const HOSTS: [&str; 7] = [
    "example.com",
    "A.Example.Com.",
    "b.a.example.com",
    "x.test.net",
    "www.other.org",
    "exa",
    "unclaimed.invalid",
];
const ADDRESSES: [&str; 7] = [
    "10.1.2.3",
    "10.1.9.9",
    "10.200.0.1",
    "192.0.2.7",
    "8.8.8.8",
    "fd00:1::5",
    "2001:db8::1",
];

fn rule(dice: &mut Dice) -> RouteRule<'static> {
    let (kind, payload) = match dice.roll(20) {
        0..=3 => (RuleKind::Domain, dice.pick(&NAMES)),
        4..=8 => (RuleKind::DomainSuffix, dice.pick(&NAMES)),
        9..=11 => (RuleKind::DomainKeyword, dice.pick(&KEYWORDS)),
        12..=16 => (RuleKind::IpCidr, dice.pick(&NETWORKS)),
        17 => (RuleKind::DstPort, dice.pick(&["443", "80"])),
        18 => (RuleKind::GeoIp, "LAN"),
        _ => (RuleKind::Match, ""),
    };
    RouteRule {
        kind,
        payload: (!payload.is_empty()).then_some(payload),
        outbound: dice.pick(&OUTBOUNDS),
        no_resolve: dice.roll(2) == 0,
    }
}

fn flow(dice: &mut Dice) -> RouteMatchInput {
    RouteMatchInput {
        host: (dice.roll(4) != 0).then(|| dice.pick(&HOSTS).to_owned()),
        destination_ip: (dice.roll(3) == 0)
            .then(|| dice.pick(&ADDRESSES).parse().expect("an address")),
        destination_port: Some(if dice.roll(2) == 0 { 443 } else { 8080 }),
        ..Default::default()
    }
}

#[test]
fn the_tables_decide_what_trying_every_rule_in_turn_decides() {
    let mut dice = Dice(0x9E37_79B9_7F4A_7C15);
    let mut asked = 0;
    let mut matched = 0;
    for _ in 0..400 {
        let mut profile = RuntimeProfile::new("index");
        profile.rules = (0..1 + dice.roll(24)).map(|_| rule(&mut dice)).collect();
        let engine = RuleEngine::compile(&profile);
        for _ in 0..40 {
            let input = flow(&mut dice);
            let accepts: &dyn Fn(&str) -> bool = if dice.roll(2) == 0 {
                &|_| true
            } else {
                &|outbound| outbound != "NoUdp"
            };
            let first = engine.first_match(&input, accepts, None);
            assert_eq!(
                first,
                in_turn(&profile.rules, &input, accepts, None),
                "{input:?} over {:?}",
                profile
                    .rules
                    .iter()
                    .map(|rule| rule.text())
                    .collect::<Vec<_>>()
            );
            matched += usize::from(matches!(first, Ok(Some(_))));
            // A rule asked for the name's address: the answer, or none.
            let Err(from_rule) = first else { continue };
            asked += 1;
            for ip in [
                None,
                Some(dice.pick(&ADDRESSES).parse::<IpAddr>().expect("an address")),
            ] {
                let address = Some(RuleAddress { from_rule, ip });
                assert_eq!(
                    engine.first_match(&input, accepts, address),
                    in_turn(&profile.rules, &input, accepts, address),
                    "{input:?} resolved to {ip:?} from rule {from_rule} over {:?}",
                    profile
                        .rules
                        .iter()
                        .map(|rule| rule.text())
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    // The cases reach both ends: rules that match and rules that ask.
    assert!(
        asked > 500 && matched > 5_000,
        "{asked} asked, {matched} matched"
    );
}
