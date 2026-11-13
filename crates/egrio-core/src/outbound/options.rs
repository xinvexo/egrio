//! Readers for a proxy node's protocol options: the keys a profile passes
//! through untouched, looked up under each of Clash's aliases in turn.
//!
//! YAML scalar types do not always match a protocol option's type: an
//! unquoted password of digits is parsed as a number. These readers
//! normalize supported scalar values to the type the option requires.

use serde_json::Value as JsonValue;

/// The first non-empty text among `keys`; a number is the text of its
/// digits, as `password: 123456` means.
pub(crate) fn option_string(options: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match options.get(*key)? {
        JsonValue::String(text) if !text.is_empty() => Some(text.clone()),
        JsonValue::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

/// The first of `keys` that is a boolean, or a string spelling one.
pub(crate) fn option_bool(options: &JsonValue, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        let value = options.get(*key)?;
        value.as_bool().or_else(|| {
            value
                .as_str()
                .and_then(|text| match text.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" => Some(true),
                    "false" | "0" | "no" => Some(false),
                    _ => None,
                })
        })
    })
}

/// The `udp` switch on the nodes that declare it (Shadowsocks, Trojan,
/// SOCKS5). Absent means off: whether a server relays UDP cannot be learned
/// in advance, and one that does not drops datagrams without a word, so UDP
/// goes through a node only when the profile says it may.
pub(crate) fn udp_switch(options: &JsonValue) -> bool {
    option_bool(options, &["udp"]).unwrap_or(false)
}

/// A list option written either as one string or as a list of strings.
pub(crate) fn option_string_list(options: &JsonValue, key: &str) -> Vec<String> {
    match options.get(key) {
        Some(JsonValue::String(text)) if !text.is_empty() => vec![text.clone()],
        Some(JsonValue::Array(values)) => values
            .iter()
            .filter_map(JsonValue::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn aliases_are_read_in_order_and_strings_spell_booleans() {
        let options =
            json!({"servername": "b.example", "sni": "", "insecure": "yes", "alpn": "h2"});
        assert_eq!(
            option_string(&options, &["sni", "servername"]).as_deref(),
            Some("b.example")
        );
        assert_eq!(
            option_bool(&options, &["skip-cert-verify", "insecure"]),
            Some(true)
        );
        assert_eq!(option_string_list(&options, "alpn"), ["h2"]);
        assert!(option_string_list(&options, "missing").is_empty());
    }

    /// A password of digits written without quotes reaches the Core as a
    /// number; it is the password all the same.
    #[test]
    fn a_number_is_the_text_of_its_digits() {
        let options = json!({"password": 123456, "username": 1.5, "sni": true, "obfs": null});
        assert_eq!(
            option_string(&options, &["password"]).as_deref(),
            Some("123456")
        );
        assert_eq!(
            option_string(&options, &["username"]).as_deref(),
            Some("1.5")
        );
        assert_eq!(option_string(&options, &["sni", "obfs"]), None);
        // An empty text is passed over for the next alias, as before.
        assert_eq!(
            option_string(&json!({"a": "", "b": 7}), &["a", "b"]).as_deref(),
            Some("7")
        );
    }
}
