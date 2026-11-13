use super::*;
use crate::geodata::GeoSiteDomainKind;
use crate::profile::{RouteRule, RuleSetContent};
use crate::rule_engine::{RouteMatchInput, RuleEngine, TransportNetwork};

fn rule<'a>(kind: RuleKind, payload: Option<&'a str>, outbound: &'a str) -> RouteRule<'a> {
    RouteRule {
        kind,
        payload,
        outbound,
        no_resolve: false,
    }
}

fn profile(rules: Vec<RouteRule<'_>>, geodata: GeoDataContent) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("geodata");
    profile.rules = rules.into();
    profile.geodata = geodata;
    profile
}

fn geoip(code: &str, cidrs: &[&str], inverse: bool) -> GeoIpContent {
    GeoIpContent {
        code: code.into(),
        cidrs: cidrs.iter().map(|cidr| cidr.to_string()).collect(),
        inverse,
    }
}

fn geosite(selection: &str, domains: &[(GeoSiteDomainKind, &str)]) -> GeoSiteContent {
    let mut content = GeoSiteContent::builder(selection);
    for (kind, value) in domains {
        content.push(*kind, value).unwrap();
    }
    content.finish()
}

fn to_ip(engine: &RuleEngine, ip: &str) -> String {
    engine
        .route(&RouteMatchInput {
            destination_ip: Some(ip.parse().unwrap()),
            ..Default::default()
        })
        .outbound
}

fn to_host(engine: &RuleEngine, host: &str) -> String {
    engine
        .route(&RouteMatchInput {
            host: Some(host.into()),
            ..Default::default()
        })
        .outbound
}

#[test]
fn geoip_rules_match_the_destination_address() {
    let engine = RuleEngine::compile(&profile(
        vec![
            rule(RuleKind::GeoIp, Some("cn"), "Domestic"),
            rule(RuleKind::GeoIp, Some("PRIVATE"), "Lan"),
            rule(RuleKind::Match, None, "Proxy"),
        ],
        GeoDataContent {
            geoip: Some(vec![
                geoip("CN", &["1.0.1.0/24", "240e::/20"], false),
                geoip("PRIVATE", &["0.0.0.0/0", "::/0"], true),
            ]),
            geosite: None,
        },
    ));
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
    assert_eq!(to_ip(&engine, "1.0.1.9"), "Domestic");
    assert_eq!(to_ip(&engine, "240e:3a1::1"), "Domestic");
    assert_eq!(to_ip(&engine, "8.8.8.8"), "Proxy");
    assert_eq!(
        to_host(&engine, "example.cn"),
        "Proxy",
        "a name without an address cannot match an address rule"
    );
}

/// `LAN` is Clash's own code, not the data's: it matches with no data at
/// all, and asks the host for none.
#[test]
fn the_lan_code_matches_local_addresses_without_any_data() {
    let profile = profile(
        vec![
            rule(RuleKind::GeoIp, Some("lan"), "DIRECT"),
            rule(RuleKind::And, Some("((GEOIP,LAN),(NETWORK,UDP))"), "DIRECT"),
            rule(RuleKind::Match, None, "Proxy"),
        ],
        GeoDataContent::default(),
    );
    let engine = RuleEngine::compile(&profile);
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
    for local in [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.10.1",
        "224.0.0.251",
        "0.0.0.0",
        "fd00::1",
        "fe80::1",
        "ff02::fb",
        "::1",
        "::",
        "::ffff:192.168.1.1",
    ] {
        assert_eq!(to_ip(&engine, local), "DIRECT", "{local}");
    }
    for public in [
        "8.8.8.8",
        "172.32.0.1",
        "100.64.0.1",
        "169.253.0.1",
        "2001:db8::1",
        "fec0::1",
    ] {
        assert_eq!(to_ip(&engine, public), "Proxy", "{public}");
    }
    let codes = geodata_codes(&profile);
    assert!(codes.is_empty(), "{codes:?}");
}

#[test]
fn an_inverse_code_matches_outside_its_networks() {
    let engine = RuleEngine::compile(&profile(
        vec![
            rule(RuleKind::GeoIp, Some("!CN"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ],
        GeoDataContent {
            geoip: Some(vec![geoip("!CN", &["1.0.1.0/24"], true)]),
            geosite: None,
        },
    ));
    assert_eq!(to_ip(&engine, "8.8.8.8"), "Proxy");
    assert_eq!(to_ip(&engine, "1.0.1.1"), "DIRECT");
}

#[test]
fn geosite_rules_match_names_keywords_and_expressions() {
    use GeoSiteDomainKind::*;
    let engine = RuleEngine::compile(&profile(
        vec![
            rule(RuleKind::Geosite, Some("Steam@CN"), "Domestic"),
            rule(RuleKind::Geosite, Some("google"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ],
        GeoDataContent {
            geoip: None,
            geosite: Some(vec![
                geosite("steam@cn", &[(Full, "cdn.steamchina.com")]),
                geosite(
                    "google",
                    &[
                        (Domain, "google.com"),
                        (Full, "Mail.Example.org"),
                        (Keyword, "googleapis"),
                        (Regex, r"^gstatic\d*\.cn$"),
                    ],
                ),
            ]),
        },
    ));
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
    assert_eq!(to_host(&engine, "cdn.steamchina.com"), "Domestic");
    assert_eq!(to_host(&engine, "google.com"), "Proxy");
    assert_eq!(to_host(&engine, "www.google.com"), "Proxy");
    assert_eq!(to_host(&engine, "notgoogle.com"), "DIRECT");
    assert_eq!(to_host(&engine, "mail.example.org."), "Proxy");
    assert_eq!(to_host(&engine, "a.mail.example.org"), "DIRECT");
    assert_eq!(to_host(&engine, "fonts.googleapis.cn"), "Proxy");
    assert_eq!(to_host(&engine, "GSTATIC2.cn"), "Proxy");
    assert_eq!(to_ip(&engine, "8.8.8.8"), "DIRECT");
}

#[test]
fn a_code_the_data_lacks_or_an_invalid_expression_is_reported() {
    let engine = RuleEngine::compile(&profile(
        vec![
            rule(RuleKind::GeoIp, Some("JP"), "Proxy"),
            rule(RuleKind::Geosite, Some("bad"), "Proxy"),
            rule(RuleKind::Geosite, Some("tw@cn"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ],
        GeoDataContent {
            geoip: Some(Vec::new()),
            geosite: Some(vec![geosite(
                "bad",
                &[
                    (GeoSiteDomainKind::Regex, "("),
                    (GeoSiteDomainKind::Domain, "bad.example"),
                ],
            )]),
        },
    ));
    let messages = engine
        .warnings()
        .iter()
        .map(|warning| (warning.rule, warning.message.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            (0, "the GeoIP data has no 'JP' entry"),
            (
                1,
                "geosite 'bad' has 1 expressions the engine could not compile"
            ),
            (2, "the GeoSite data has no 'tw' entry"),
        ]
    );
    assert_eq!(
        to_host(&engine, "bad.example"),
        "Proxy",
        "the rest of the selection still matches"
    );
}

#[test]
fn logic_rules_and_classical_sets_use_the_same_data() {
    let mut profile = profile(
        vec![
            rule(
                RuleKind::And,
                Some("((GEOIP,CN),(NETWORK,TCP))"),
                "Domestic",
            ),
            rule(RuleKind::RuleSet, Some("sites"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ],
        GeoDataContent {
            geoip: Some(vec![geoip("CN", &["1.0.1.0/24"], false)]),
            geosite: Some(vec![geosite(
                "google",
                &[(GeoSiteDomainKind::Domain, "google.com")],
            )]),
        },
    );
    profile.rule_sets = vec![RuleSetContent {
        name: "sites".into(),
        behavior: RuleSetBehavior::Classical,
        entries: ["GEOSITE,google"].into_iter().collect(),
    }];
    let engine = RuleEngine::compile(&profile);
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
    let route = |ip: &str, network| {
        engine
            .route(&RouteMatchInput {
                destination_ip: Some(ip.parse().unwrap()),
                network: Some(network),
                ..Default::default()
            })
            .outbound
    };
    assert_eq!(route("1.0.1.1", TransportNetwork::Tcp), "Domestic");
    assert_eq!(route("1.0.1.1", TransportNetwork::Udp), "DIRECT");
    assert_eq!(to_host(&engine, "maps.google.com"), "Proxy");
}

#[test]
fn the_codes_rules_name_are_collected_everywhere_they_appear() {
    let mut profile = profile(
        vec![
            rule(RuleKind::GeoIp, Some(" cn "), "DIRECT"),
            rule(RuleKind::Geosite, Some("Steam@CN"), "DIRECT"),
            rule(
                RuleKind::Or,
                Some("((GEOIP,JP),(NOT,((GEOSITE,google))))"),
                "Proxy",
            ),
            rule(RuleKind::RuleSet, Some("classic"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ],
        GeoDataContent::default(),
    );
    profile.rule_sets = vec![
        RuleSetContent {
            name: "classic".into(),
            behavior: RuleSetBehavior::Classical,
            entries: ["GEOIP,US", "DOMAIN,example.com"].into_iter().collect(),
        },
        RuleSetContent {
            name: "domains".into(),
            behavior: RuleSetBehavior::Domain,
            entries: ["GEOIP,NOT-A-RULE"].into_iter().collect(),
        },
    ];
    let codes = geodata_codes(&profile);
    assert_eq!(
        codes.geoip.into_iter().collect::<Vec<_>>(),
        ["CN", "JP", "US"]
    );
    assert_eq!(
        codes.geosite.into_iter().collect::<Vec<_>>(),
        ["google", "steam@cn"]
    );
}
