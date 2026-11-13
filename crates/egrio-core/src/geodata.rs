//! GeoIP and GeoSite data in the `geoip.dat` / `geosite.dat` files V2Ray
//! defined: a protobuf `GeoIPList` / `GeoSiteList`, per v2ray-core's
//! `app/router/routercommon/common.proto`. A host keeps the files and hands
//! the Core their bytes; the Core keeps only the entries a profile's rules
//! name, so a file of every country and category costs one scan, not its
//! whole content in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::profile::{RuleSetEntries, RuleSetEntriesBuilder, RuleSetTooLarge, RuntimeProfile};

/// The geodata a profile's rules use, as the host injects it. `None` means
/// the host has no file of that kind, so such rules cannot match yet; a code
/// missing from `Some` means the file has no entry for it.
///
/// A code's networks and a selection's names are each one block of text
/// that every clone shares and the Core's matcher indexes in place, as a
/// rule provider's entries are ([`RuleSetEntries`]). Profile clones and
/// matcher indexes therefore do not duplicate an owned string per entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoDataContent {
    #[serde(default)]
    pub geoip: Option<Vec<GeoIpContent>>,
    #[serde(default)]
    pub geosite: Option<Vec<GeoSiteContent>>,
}

/// One GeoIP code's networks, e.g. `CN`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpContent {
    /// Upper case, as rules name it after normalizing.
    pub code: String,
    /// `address/prefix` networks.
    pub cidrs: RuleSetEntries,
    /// The code stands for every address outside these networks.
    #[serde(default)]
    pub inverse: bool,
}

/// One GeoSite selection as a rule names it, a code with optional attribute
/// filters (`cn`, `steam@cn`), and the domains it selects, by their kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoSiteContent {
    /// Normalized by [`geosite_selection`].
    pub selection: String,
    /// The names, as a `domain` rule set writes them: a name alone is
    /// exactly that name (`Full`), `+.name` the name and every subdomain of
    /// it (`Domain`).
    pub names: RuleSetEntries,
    /// Texts a name matches by holding them anywhere (`Keyword`).
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Regular expressions over the name (`Regex`).
    #[serde(default)]
    pub regexes: Vec<String>,
}

impl GeoSiteContent {
    pub fn builder(selection: impl Into<String>) -> GeoSiteContentBuilder {
        GeoSiteContentBuilder {
            selection: selection.into(),
            names: RuleSetEntries::builder(),
            keywords: Vec::new(),
            regexes: Vec::new(),
        }
    }

    /// How many domains the selection holds, of every kind.
    pub fn len(&self) -> usize {
        self.names.len() + self.keywords.len() + self.regexes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Collects a selection's domains into a [`GeoSiteContent`].
#[derive(Debug)]
pub struct GeoSiteContentBuilder {
    selection: String,
    names: RuleSetEntriesBuilder,
    keywords: Vec<String>,
    regexes: Vec<String>,
}

impl GeoSiteContentBuilder {
    /// Adds one domain, refusing a name that would take the selection's
    /// names past the 2 GiB a block addresses.
    pub fn push(&mut self, kind: GeoSiteDomainKind, value: &str) -> Result<(), RuleSetTooLarge> {
        match kind {
            GeoSiteDomainKind::Keyword => self.keywords.push(value.to_owned()),
            GeoSiteDomainKind::Regex => self.regexes.push(value.to_owned()),
            GeoSiteDomainKind::Domain => self.names.push_parts(&["+.", value])?,
            GeoSiteDomainKind::Full => {
                // What a rule set would read as another shape of entry --
                // subdomains, a wildcard -- is no hostname, so no name is
                // exactly it and the entry says nothing.
                let name = value.trim();
                if !(name.starts_with("+.") || name.starts_with('.') || name.contains('*')) {
                    self.names.push(value)?;
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> GeoSiteContent {
        GeoSiteContent {
            selection: self.selection,
            names: self.names.finish(),
            keywords: self.keywords,
            regexes: self.regexes,
        }
    }
}

/// The kinds of domain a GeoSite entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoSiteDomainKind {
    /// The value appears anywhere in the name (`Plain`).
    Keyword,
    /// A regular expression over the name.
    Regex,
    /// The name and every subdomain of it (`RootDomain`).
    Domain,
    /// Exactly the name.
    Full,
}

/// The GeoIP codes and GeoSite selections a profile's rules name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoDataCodes {
    pub geoip: BTreeSet<String>,
    pub geosite: BTreeSet<String>,
}

impl GeoDataCodes {
    pub fn is_empty(&self) -> bool {
        self.geoip.is_empty() && self.geosite.is_empty()
    }
}

/// The codes the profile's rules name: top-level rules, logic sub-rules and
/// the entries of classical rule sets.
pub fn referenced_codes(profile: &RuntimeProfile) -> GeoDataCodes {
    crate::rule_engine::geodata_codes(profile)
}

/// A GeoIP code as rules compare it.
pub fn geoip_code(payload: &str) -> String {
    payload.trim().to_ascii_uppercase()
}

/// A GeoSite selection as rules compare it: lower case, attribute filters
/// after `@` kept in order, empty ones dropped.
pub fn geosite_selection(payload: &str) -> String {
    let mut parts = payload
        .split('@')
        .map(|part| part.trim().to_ascii_lowercase());
    let code = parts.next().unwrap_or_default();
    parts
        .filter(|attribute| !attribute.is_empty())
        .fold(code, |selection, attribute| selection + "@" + &attribute)
}

/// The networks of `codes` in a `geoip.dat` file. A code the file lacks is
/// absent from the result.
pub fn extract_geoip(file: &[u8], codes: &BTreeSet<String>) -> Result<Vec<GeoIpContent>, String> {
    let mut found = BTreeMap::<String, (RuleSetEntriesBuilder, bool)>::new();
    for entry in list_entries(file)? {
        let code = entry_code(entry, GEOIP_COUNTRY_CODE, GEOIP_CODE)?;
        if !codes.contains(&code) {
            continue;
        }
        let (cidrs, inverse) = found.entry(code).or_default();
        for field in Fields::new(entry) {
            match field? {
                (GEOIP_CIDR, Value::Bytes(cidr)) => cidrs
                    .push(&decode_cidr(cidr)?)
                    .map_err(|error| error.to_string())?,
                (GEOIP_INVERSE_MATCH, Value::Varint(flag)) => *inverse = flag != 0,
                _ => {}
            }
        }
    }
    Ok(found
        .into_iter()
        .map(|(code, (cidrs, inverse))| GeoIpContent {
            code,
            cidrs: cidrs.finish(),
            inverse,
        })
        .collect())
}

/// The domains of `selections` in a `geosite.dat` file. A selection keeps
/// the domains that carry every attribute it names (`steam@cn`: the steam
/// domains marked `cn`). A code the file lacks is absent from the result.
pub fn extract_geosite(
    file: &[u8],
    selections: &BTreeSet<String>,
) -> Result<Vec<GeoSiteContent>, String> {
    let mut wanted = BTreeMap::<String, Vec<(&str, Vec<&str>)>>::new();
    for selection in selections {
        let mut parts = selection.split('@');
        let code = parts.next().unwrap_or_default().to_ascii_uppercase();
        wanted
            .entry(code)
            .or_default()
            .push((selection.as_str(), parts.collect()));
    }
    let mut found = BTreeMap::<&str, GeoSiteContentBuilder>::new();
    for entry in list_entries(file)? {
        let code = entry_code(entry, GEOSITE_COUNTRY_CODE, GEOSITE_CODE)?;
        let Some(requests) = wanted.get(&code) else {
            continue;
        };
        for (selection, _) in requests {
            found
                .entry(selection)
                .or_insert_with(|| GeoSiteContent::builder(*selection));
        }
        for field in Fields::new(entry) {
            let (GEOSITE_DOMAIN, Value::Bytes(domain)) = field? else {
                continue;
            };
            let Some((kind, value, attributes)) = decode_domain(domain)? else {
                continue;
            };
            for (selection, filters) in requests {
                let selected = filters.iter().all(|filter| {
                    attributes
                        .iter()
                        .any(|attribute| attribute.eq_ignore_ascii_case(filter))
                });
                if selected {
                    found
                        .get_mut(selection)
                        .expect("a requested selection has its builder")
                        .push(kind, value)
                        .map_err(|error| error.to_string())?;
                }
            }
        }
    }
    Ok(found
        .into_values()
        .map(GeoSiteContentBuilder::finish)
        .collect())
}

/// The codes a `geoip.dat` file holds, which also proves it decodes.
pub fn geoip_file_codes(file: &[u8]) -> Result<Vec<String>, String> {
    list_entries(file)?
        .into_iter()
        .map(|entry| entry_code(entry, GEOIP_COUNTRY_CODE, GEOIP_CODE))
        .collect()
}

/// The codes a `geosite.dat` file holds, which also proves it decodes.
pub fn geosite_file_codes(file: &[u8]) -> Result<Vec<String>, String> {
    list_entries(file)?
        .into_iter()
        .map(|entry| entry_code(entry, GEOSITE_COUNTRY_CODE, GEOSITE_CODE))
        .collect()
}

// Field numbers from routercommon/common.proto.
const LIST_ENTRY: u64 = 1;
const GEOIP_COUNTRY_CODE: u64 = 1;
const GEOIP_CIDR: u64 = 2;
const GEOIP_INVERSE_MATCH: u64 = 3;
const GEOIP_CODE: u64 = 5;
const CIDR_IP: u64 = 1;
const CIDR_PREFIX: u64 = 2;
const GEOSITE_COUNTRY_CODE: u64 = 1;
const GEOSITE_DOMAIN: u64 = 2;
const GEOSITE_CODE: u64 = 4;
const DOMAIN_TYPE: u64 = 1;
const DOMAIN_VALUE: u64 = 2;
const DOMAIN_ATTRIBUTE: u64 = 3;
const ATTRIBUTE_KEY: u64 = 1;

fn list_entries(file: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut entries = Vec::new();
    for field in Fields::new(file) {
        if let (LIST_ENTRY, Value::Bytes(entry)) = field? {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err("geodata file holds no entries".into());
    }
    Ok(entries)
}

/// An entry's code, upper case: `country_code`, or the newer `code` field
/// when that one is empty.
fn entry_code(entry: &[u8], country_code: u64, code: u64) -> Result<String, String> {
    let mut found = String::new();
    for field in Fields::new(entry) {
        match field? {
            (number, Value::Bytes(text)) if number == country_code && !text.is_empty() => {
                return utf8(text).map(str::to_ascii_uppercase);
            }
            (number, Value::Bytes(text)) if number == code => {
                found = utf8(text)?.to_ascii_uppercase();
            }
            _ => {}
        }
    }
    if found.is_empty() {
        return Err("geodata entry has no code".into());
    }
    Ok(found)
}

fn decode_cidr(cidr: &[u8]) -> Result<String, String> {
    let mut address = None;
    let mut prefix = 0_u64;
    for field in Fields::new(cidr) {
        match field? {
            (CIDR_IP, Value::Bytes(bytes)) => {
                address = Some(match bytes.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
                    length => return Err(format!("geoip network has a {length}-byte address")),
                });
            }
            (CIDR_PREFIX, Value::Varint(value)) => prefix = value,
            _ => {}
        }
    }
    let address = address.ok_or("geoip network has no address")?;
    let limit = if address.is_ipv4() { 32 } else { 128 };
    if prefix > limit {
        return Err(format!(
            "geoip network {address}/{prefix} has too long a prefix"
        ));
    }
    Ok(format!("{address}/{prefix}"))
}

/// A domain's kind, value and attribute keys; `None` for a type this
/// decoder does not know, which a newer file may add.
#[allow(clippy::type_complexity)]
fn decode_domain(domain: &[u8]) -> Result<Option<(GeoSiteDomainKind, &str, Vec<&str>)>, String> {
    let mut kind = 0_u64;
    let mut value = "";
    let mut attributes = Vec::new();
    for field in Fields::new(domain) {
        match field? {
            (DOMAIN_TYPE, Value::Varint(number)) => kind = number,
            (DOMAIN_VALUE, Value::Bytes(text)) => value = utf8(text)?,
            (DOMAIN_ATTRIBUTE, Value::Bytes(attribute)) => {
                for field in Fields::new(attribute) {
                    if let (ATTRIBUTE_KEY, Value::Bytes(key)) = field? {
                        attributes.push(utf8(key)?);
                    }
                }
            }
            _ => {}
        }
    }
    let kind = match kind {
        0 => GeoSiteDomainKind::Keyword,
        1 => GeoSiteDomainKind::Regex,
        2 => GeoSiteDomainKind::Domain,
        3 => GeoSiteDomainKind::Full,
        _ => return Ok(None),
    };
    if value.is_empty() {
        return Err("geosite domain has no value".into());
    }
    Ok(Some((kind, value, attributes)))
}

fn utf8(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "geodata text is not UTF-8".into())
}

/// A field value in the protobuf wire format. Groups (wire types 3 and 4)
/// do not occur in these messages.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

/// The fields of one message, in order.
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(message: &'a [u8]) -> Self {
        Self { rest: message }
    }

    fn read(&mut self) -> Result<(u64, Value<'a>), String> {
        let key = varint(&mut self.rest)?;
        let value = match key & 7 {
            0 => Value::Varint(varint(&mut self.rest)?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let length = usize::try_from(varint(&mut self.rest)?)
                    .map_err(|_| "geodata field is too long")?;
                Value::Bytes(self.take(length)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            wire => return Err(format!("geodata uses unsupported wire type {wire}")),
        };
        Ok((key >> 3, value))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        if length > self.rest.len() {
            return Err("geodata file is truncated".into());
        }
        let (head, tail) = self.rest.split_at(length);
        self.rest = tail;
        Ok(head)
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u64, Value<'a>), String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let field = self.read();
        if field.is_err() {
            // One malformed field ends the message: nothing after it can be
            // framed.
            self.rest = &[];
        }
        Some(field)
    }
}

fn varint(bytes: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes.split_first().ok_or("geodata file is truncated")?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("geodata file has a malformed varint".into())
}

#[cfg(test)]
mod tests;
