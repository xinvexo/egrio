//! A destination known only by name meets an IP rule that may resolve it.

use std::net::IpAddr;

use super::*;
use crate::geodata::{GeoDataContent, GeoIpContent};

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

fn engine(rules: Vec<RouteRule<'_>>) -> RuleEngine {
    let mut profile = RuntimeProfile::new("addresses");
    profile.rules = rules.into();
    profile.geodata = GeoDataContent {
        geoip: Some(vec![GeoIpContent {
            code: "CN".into(),
            cidrs: ["1.0.1.0/24"].into_iter().collect(),
            inverse: false,
        }]),
        geosite: None,
    };
    profile.rule_sets = vec![
        RuleSetContent {
            name: "cidrs".into(),
            behavior: RuleSetBehavior::Ipcidr,
            entries: ["9.9.9.0/24"].into_iter().collect(),
        },
        RuleSetContent {
            name: "names".into(),
            behavior: RuleSetBehavior::Domain,
            entries: ["+.listed.test"].into_iter().collect(),
        },
    ];
    RuleEngine::compile(&profile)
}

fn named(host: &str) -> RouteMatchInput {
    RouteMatchInput {
        host: Some(host.into()),
        destination_port: Some(443),
        ..Default::default()
    }
}

fn step(engine: &RuleEngine, input: &RouteMatchInput, address: Option<RuleAddress>) -> RouteStep {
    engine.route_with_policy(input, TrafficPolicyMode::Rule, "Proxy", &|_| true, address)
}

fn decided(step: RouteStep) -> (String, Option<String>) {
    match step {
        RouteStep::Decided(decision) => (decision.outbound, decision.matched_rule),
        RouteStep::NeedsAddress(position) => panic!("asked for an address at {position}"),
    }
}

fn resolved(from_rule: usize, ip: &str) -> Option<RuleAddress> {
    Some(RuleAddress {
        from_rule,
        ip: Some(ip.parse::<IpAddr>().unwrap()),
    })
}

#[test]
fn a_name_stops_at_the_first_ip_rule_that_may_resolve_it() {
    let engine = engine(vec![
        rule(RuleKind::DomainSuffix, Some("listed.test"), "Listed", false),
        rule(RuleKind::IpCidr, Some("10.0.0.0/8"), "Lan", true),
        rule(RuleKind::GeoIp, Some("CN"), "Domestic", false),
        rule(RuleKind::Match, None, "Proxy", false),
    ]);
    assert!(matches!(
        step(&engine, &named("other.test"), None),
        RouteStep::NeedsAddress(2)
    ));
    assert_eq!(
        decided(step(&engine, &named("www.listed.test"), None)),
        (
            "Listed".into(),
            Some("DOMAIN-SUFFIX,listed.test,Listed".into())
        ),
        "a name an earlier rule matches is never resolved"
    );
    let numeric = RouteMatchInput {
        destination_ip: Some("1.0.1.1".parse().unwrap()),
        ..named("other.test")
    };
    assert_eq!(
        decided(step(&engine, &numeric, None)).0,
        "Domestic",
        "an address the flow carries needs no lookup"
    );
    assert_eq!(
        decided(step(&engine, &named("other.test"), resolved(2, "1.0.1.1"))).0,
        "Domestic"
    );
    assert_eq!(
        decided(step(&engine, &named("other.test"), resolved(2, "8.8.8.8"))).0,
        "Proxy"
    );
}

#[test]
fn only_the_asking_rule_and_those_after_it_see_the_resolved_address() {
    let engine = engine(vec![
        rule(RuleKind::IpCidr, Some("1.0.1.0/24"), "Early", true),
        rule(RuleKind::GeoIp, Some("JP"), "Japan", false),
        rule(RuleKind::GeoIp, Some("CN"), "Domestic", false),
        rule(RuleKind::IpCidr, Some("8.8.8.0/24"), "Late", true),
        rule(RuleKind::Match, None, "Proxy", false),
    ]);
    // The JP code is missing from the data, so that rule compiles away and
    // CN is the first rule that asks.
    assert_eq!(engine.warnings().len(), 1);
    let RouteStep::NeedsAddress(from_rule) = step(&engine, &named("site.test"), None) else {
        panic!("the CN rule asks for the address");
    };
    assert_eq!(
        decided(step(
            &engine,
            &named("site.test"),
            resolved(from_rule, "1.0.1.1")
        )),
        ("Domestic".into(), Some("GEOIP,CN,Domestic".into())),
        "a no-resolve rule before the asking one never sees the address"
    );
    assert_eq!(
        decided(step(
            &engine,
            &named("site.test"),
            resolved(from_rule, "8.8.8.8")
        )),
        (
            "Late".into(),
            Some("IP-CIDR,8.8.8.0/24,Late,no-resolve".into())
        ),
        "a no-resolve rule after it matches the address it got"
    );
}

#[test]
fn a_name_that_did_not_resolve_matches_no_ip_rule_and_asks_no_more() {
    let engine = engine(vec![
        rule(RuleKind::GeoIp, Some("CN"), "Domestic", false),
        rule(RuleKind::IpCidr, Some("8.8.8.0/24"), "Google", false),
        rule(RuleKind::Match, None, "Proxy", false),
    ]);
    let failed = Some(RuleAddress {
        from_rule: 0,
        ip: None,
    });
    assert_eq!(
        decided(step(&engine, &named("bad.test"), failed)).0,
        "Proxy"
    );
    let (decision, asked) = engine.route_unresolved(
        &named("bad.test"),
        TrafficPolicyMode::Rule,
        "Proxy",
        &|_| true,
    );
    assert!(
        asked,
        "a rule asked, and routing went on without the address"
    );
    assert_eq!(decision.matched_rule.as_deref(), Some("MATCH,Proxy"));
    assert_eq!(engine.route(&named("bad.test")).outbound, "Proxy");
}

#[test]
fn rules_that_read_no_address_or_say_no_resolve_never_ask() {
    let engine = engine(vec![
        rule(RuleKind::GeoIp, Some("CN"), "Domestic", true),
        rule(RuleKind::RuleSet, Some("names"), "Listed", false),
        rule(RuleKind::SrcIpCidr, Some("10.0.0.0/8"), "Lan", false),
        rule(RuleKind::Match, None, "Proxy", false),
    ]);
    assert_eq!(decided(step(&engine, &named("site.test"), None)).0, "Proxy");
    for mode in [TrafficPolicyMode::Global, TrafficPolicyMode::Direct] {
        let asking = engine_with_mode(mode);
        assert!(matches!(
            asking.route_with_policy(&named("site.test"), mode, "Proxy", &|_| true, None),
            RouteStep::Decided(_)
        ));
    }
}

fn engine_with_mode(mode: TrafficPolicyMode) -> RuleEngine {
    let mut profile = RuntimeProfile::new("modes");
    profile.traffic_policy_mode = mode;
    profile.rules = vec![rule(RuleKind::IpCidr, Some("1.0.0.0/8"), "A", false)].into();
    RuleEngine::compile(&profile)
}

#[test]
fn logic_rules_and_ip_rule_sets_ask_like_ip_rules() {
    for (payload_kind, payload) in [
        (RuleKind::And, "((IP-CIDR,9.9.9.0/24),(NETWORK,TCP))"),
        (RuleKind::Not, "((GEOIP,CN))"),
        (RuleKind::RuleSet, "cidrs"),
    ] {
        let engine = engine(vec![
            rule(payload_kind, Some(payload), "Asked", false),
            rule(RuleKind::Match, None, "Proxy", false),
        ]);
        assert!(
            matches!(
                step(&engine, &named("site.test"), None),
                RouteStep::NeedsAddress(0)
            ),
            "{payload}"
        );
    }
}

#[test]
fn a_rule_the_flow_cannot_take_does_not_ask() {
    let engine = engine(vec![
        rule(RuleKind::GeoIp, Some("CN"), "NoUdp", false),
        rule(RuleKind::Match, None, "Udp", false),
    ]);
    let refuse = |outbound: &str| outbound != "NoUdp";
    let RouteStep::Decided(decision) = engine.route_with_policy(
        &named("game.test"),
        TrafficPolicyMode::Rule,
        "Udp",
        &refuse,
        None,
    ) else {
        panic!("a refused rule cannot win, so it needs no address");
    };
    assert_eq!(decision.outbound, "Udp");
}
