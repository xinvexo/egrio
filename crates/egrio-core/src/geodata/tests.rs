use std::net::IpAddr;

use super::*;

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_bytes(number: u64, bytes: &[u8], out: &mut Vec<u8>) {
    put_varint(number << 3 | 2, out);
    put_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn put_number(number: u64, value: u64, out: &mut Vec<u8>) {
    put_varint(number << 3, out);
    put_varint(value, out);
}

fn cidr(network: &str, prefix: u64) -> Vec<u8> {
    let mut out = Vec::new();
    match network.parse::<IpAddr>().unwrap() {
        IpAddr::V4(address) => put_bytes(1, &address.octets(), &mut out),
        IpAddr::V6(address) => put_bytes(1, &address.octets(), &mut out),
    }
    put_number(2, prefix, &mut out);
    // A field this decoder does not read (`ip_addr`) is skipped.
    put_bytes(68000, network.as_bytes(), &mut out);
    out
}

fn geoip_entry(code: &str, networks: &[(&str, u64)], inverse: bool) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(1, code.as_bytes(), &mut out);
    for (network, prefix) in networks {
        put_bytes(2, &cidr(network, *prefix), &mut out);
    }
    if inverse {
        put_number(3, 1, &mut out);
    }
    out
}

fn list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        put_bytes(1, entry, &mut out);
    }
    out
}

fn domain(kind: u64, value: &str, attributes: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    put_number(1, kind, &mut out);
    put_bytes(2, value.as_bytes(), &mut out);
    for key in attributes {
        let mut attribute = Vec::new();
        put_bytes(1, key.as_bytes(), &mut attribute);
        put_number(2, 1, &mut attribute);
        put_bytes(3, &attribute, &mut out);
    }
    out
}

fn geosite_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(1, code.as_bytes(), &mut out);
    for domain in domains {
        put_bytes(2, domain, &mut out);
    }
    out
}

fn codes(codes: &[&str]) -> BTreeSet<String> {
    codes.iter().map(|code| code.to_string()).collect()
}

#[test]
fn only_the_named_geoip_codes_are_kept() {
    let file = list(&[
        geoip_entry("US", &[("8.8.8.0", 24)], false),
        geoip_entry("CN", &[("1.0.1.0", 24), ("240e::", 20)], false),
        geoip_entry("PRIVATE", &[("10.0.0.0", 8)], true),
    ]);
    let found = extract_geoip(&file, &codes(&["CN", "PRIVATE", "JP"])).unwrap();
    assert_eq!(
        found,
        vec![
            GeoIpContent {
                code: "CN".into(),
                cidrs: ["1.0.1.0/24", "240e::/20"].into_iter().collect(),
                inverse: false,
            },
            GeoIpContent {
                code: "PRIVATE".into(),
                cidrs: ["10.0.0.0/8"].into_iter().collect(),
                inverse: true,
            },
        ],
        "a code the file lacks is absent"
    );
    assert_eq!(geoip_file_codes(&file).unwrap(), ["US", "CN", "PRIVATE"]);
}

#[test]
fn the_newer_code_field_names_an_entry_without_a_country_code() {
    let mut entry = Vec::new();
    put_bytes(5, b"cn", &mut entry);
    put_bytes(2, &cidr("1.0.1.0", 24), &mut entry);
    let found = extract_geoip(&list(&[entry]), &codes(&["CN"])).unwrap();
    assert_eq!(found[0].code, "CN");
    assert_eq!(found[0].cidrs.iter().collect::<Vec<_>>(), ["1.0.1.0/24"]);
}

#[test]
fn geosite_selections_keep_the_domains_with_every_named_attribute() {
    let file = list(&[
        geosite_entry("GOOGLE", &[domain(2, "google.com", &[])]),
        geosite_entry(
            "STEAM",
            &[
                domain(2, "steampowered.com", &[]),
                domain(3, "cdn.steamstatic.com.8686c.com", &["cn"]),
                domain(0, "steamcontent", &[]),
                domain(1, r"^cm\d+\.steam\.cn$", &["cn", "ads"]),
                domain(9, "a type from a newer file", &["cn"]),
            ],
        ),
    ]);
    let found = extract_geosite(
        &file,
        &codes(&["steam", "steam@cn", "steam@cn@ads", "missing"]),
    )
    .unwrap();
    let selections = found
        .iter()
        .map(|content| (content.selection.as_str(), content.len()))
        .collect::<Vec<_>>();
    assert_eq!(
        selections,
        [("steam", 4), ("steam@cn", 2), ("steam@cn@ads", 1)],
        "unknown domain types are skipped and a missing code is absent"
    );
    // Each kind where a rule set would write it: a domain with its
    // subdomains as `+.name`, a full name alone.
    assert_eq!(
        found[0].names.iter().collect::<Vec<_>>(),
        ["+.steampowered.com", "cdn.steamstatic.com.8686c.com"]
    );
    assert_eq!(found[0].keywords, ["steamcontent"]);
    assert_eq!(found[0].regexes, [r"^cm\d+\.steam\.cn$"]);
    assert_eq!(
        found[1].names.iter().collect::<Vec<_>>(),
        ["cdn.steamstatic.com.8686c.com"]
    );
    assert!(found[2].names.is_empty() && found[2].keywords.is_empty());
    assert_eq!(found[2].regexes, [r"^cm\d+\.steam\.cn$"]);
    assert_eq!(geosite_file_codes(&file).unwrap(), ["GOOGLE", "STEAM"]);
}

/// A full name that a rule set would read as another shape of entry is no
/// hostname: it is left out instead of matching what it does not say.
#[test]
fn a_full_name_that_is_no_hostname_is_left_out() {
    let mut selection = GeoSiteContent::builder("odd");
    for value in [
        "+.suffix.test",
        ".subdomains.test",
        "*.label.test",
        "a.*.test",
    ] {
        selection.push(GeoSiteDomainKind::Full, value).unwrap();
    }
    selection
        .push(GeoSiteDomainKind::Full, "plain.test")
        .unwrap();
    selection
        .push(GeoSiteDomainKind::Domain, "*.kept.test")
        .unwrap();
    let selection = selection.finish();
    assert_eq!(
        selection.names.iter().collect::<Vec<_>>(),
        ["plain.test", "+.*.kept.test"]
    );
    assert_eq!(selection.len(), 2);
    assert!(!selection.is_empty());
}

#[test]
fn a_code_with_no_selected_domain_is_still_found() {
    let file = list(&[geosite_entry(
        "STEAM",
        &[domain(2, "steampowered.com", &[])],
    )]);
    let found = extract_geosite(&file, &codes(&["steam@cn"])).unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].is_empty());
}

#[test]
fn malformed_files_are_refused() {
    let file = list(&[geoip_entry("CN", &[("1.0.1.0", 24)], false)]);
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("truncated", file[..file.len() - 3].to_vec()),
        ("group wire type", vec![0x0b]),
        ("unterminated varint", vec![0x08, 0xff, 0xff]),
    ] {
        assert!(geoip_file_codes(&bytes).is_err(), "{name}");
        assert!(extract_geoip(&bytes, &codes(&["CN"])).is_err(), "{name}");
    }
    let mut bad_address = Vec::new();
    put_bytes(1, &[1, 2, 3], &mut bad_address);
    let mut entry = Vec::new();
    put_bytes(1, b"CN", &mut entry);
    put_bytes(2, &bad_address, &mut entry);
    assert!(extract_geoip(&list(&[entry]), &codes(&["CN"])).is_err());
}

#[test]
fn rule_payloads_normalize_to_the_compared_forms() {
    assert_eq!(geoip_code(" cn "), "CN");
    assert_eq!(geosite_selection(" Steam@CN@ "), "steam@cn");
    assert_eq!(geosite_selection("geolocation-!cn"), "geolocation-!cn");
}
