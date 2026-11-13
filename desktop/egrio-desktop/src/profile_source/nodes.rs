//! `proxies` and `proxy-groups`.
//!
//! Scalar names accept numbers as their digits, and numeric fields parse
//! quoted numbers. A name or a group member written without quotes
//! (`name: 1`) and a quoted `interval` are therefore accepted.

use egrio_core::{PolicyGroup, PolicyGroupKind, ProxyNode, ProxyProtocol};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use serde_yaml::{Mapping, Value};

#[derive(Debug, Deserialize)]
pub(super) struct SourceProxy {
    #[serde(deserialize_with = "scalar")]
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: Option<String>,
    port: Option<Value>,
    /// Protocol options (cipher, password, tls, ...), read by the Core
    /// outbound for the node's protocol.
    #[serde(flatten)]
    options: Mapping,
}

#[derive(Debug, Deserialize)]
pub(super) struct SourceGroup {
    #[serde(deserialize_with = "scalar")]
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, deserialize_with = "scalars")]
    proxies: Vec<String>,
    #[serde(default, deserialize_with = "seconds")]
    interval: Option<u64>,
    url: Option<String>,
}

/// A name: a text, or a number or boolean as it is written.
fn scalar<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    key_to_string(Value::deserialize(deserializer)?)
        .ok_or_else(|| D::Error::custom("a name must be a text or a number"))
}

/// A list of names; a key written without a value is an empty one.
fn scalars<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<Value>>::deserialize(deserializer)?
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            key_to_string(value)
                .ok_or_else(|| D::Error::custom("a group member must be a text or a number"))
        })
        .collect()
}

/// A count of seconds: a whole number, or its digits as a text.
fn seconds<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| D::Error::custom(format!("{number} is no count of seconds"))),
        Some(Value::String(text)) => text
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| D::Error::custom(format!("{text:?} is no count of seconds"))),
        Some(_) => Err(D::Error::custom("an interval is a count of seconds")),
    }
}

pub(super) fn node(proxy: SourceProxy) -> ProxyNode {
    ProxyNode {
        id: stable_id("proxy", &proxy.name),
        name: proxy.name,
        protocol: protocol(&proxy.kind),
        server: proxy.server,
        port: port(proxy.port),
        options: mapping_to_json(proxy.options),
    }
}

pub(super) fn group(group: SourceGroup) -> PolicyGroup {
    PolicyGroup {
        id: stable_id("group", &group.name),
        name: group.name,
        kind: group_kind(&group.kind),
        members: group.proxies,
        interval_seconds: group.interval,
        test_url: group.url,
        // A choice is Profile state, applied when the profile is composed.
        selected: None,
    }
}

fn protocol(kind: &str) -> ProxyProtocol {
    match kind.to_ascii_lowercase().as_str() {
        "direct" => ProxyProtocol::Direct,
        "reject" => ProxyProtocol::Reject,
        "http" => ProxyProtocol::Http,
        "socks5" => ProxyProtocol::Socks5,
        "ss" | "shadowsocks" => ProxyProtocol::Shadowsocks,
        "vmess" => ProxyProtocol::Vmess,
        "vless" => ProxyProtocol::Vless,
        "trojan" => ProxyProtocol::Trojan,
        "hysteria2" | "hy2" => ProxyProtocol::Hysteria2,
        "tuic" => ProxyProtocol::Tuic,
        "openvpn" => ProxyProtocol::OpenVpn,
        _ => ProxyProtocol::Unknown,
    }
}

fn group_kind(kind: &str) -> PolicyGroupKind {
    match kind.to_ascii_lowercase().as_str() {
        "select" => PolicyGroupKind::Select,
        "url-test" => PolicyGroupKind::UrlTest,
        "fallback" => PolicyGroupKind::Fallback,
        "load-balance" => PolicyGroupKind::LoadBalance,
        "relay" => PolicyGroupKind::Relay,
        _ => PolicyGroupKind::Unknown,
    }
}

fn port(value: Option<Value>) -> Option<u16> {
    match value {
        Some(Value::Number(number)) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        Some(Value::String(port)) => port.parse::<u16>().ok(),
        _ => None,
    }
}

fn mapping_to_json(mapping: Mapping) -> JsonValue {
    JsonValue::Object(
        mapping
            .into_iter()
            .filter_map(|(key, value)| key_to_string(key).map(|key| (key, to_json(value))))
            .collect::<JsonMap<_, _>>(),
    )
}

pub(super) fn key_to_string(value: Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn to_json(value: Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Bool(value) => JsonValue::Bool(value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                JsonValue::Number(JsonNumber::from(value))
            } else if let Some(value) = value.as_u64() {
                JsonValue::Number(JsonNumber::from(value))
            } else if let Some(value) = value.as_f64() {
                JsonNumber::from_f64(value).map_or(JsonValue::Null, JsonValue::Number)
            } else {
                JsonValue::Null
            }
        }
        Value::String(value) => JsonValue::String(value),
        Value::Sequence(values) => JsonValue::Array(values.into_iter().map(to_json).collect()),
        Value::Mapping(values) => mapping_to_json(values),
        Value::Tagged(tagged) => to_json(tagged.value),
    }
}

/// An id that follows the name, so a choice saved for a group survives a
/// source update that keeps the group.
pub(super) fn stable_id(prefix: &str, name: &str) -> String {
    let slug = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    let mut hash: u32 = 0x811c_9dc5;
    for byte in name.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let suffix = format!("{hash:08x}");

    if slug.is_empty() {
        format!("{prefix}-{suffix}")
    } else {
        format!("{prefix}-{slug}-{suffix}")
    }
}
