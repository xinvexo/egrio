use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use egrio_runtime::IpPrefix;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

use crate::profile_store::ProfileStore;

/// A profile's listener, IPv6 and TUN route settings, as its source writes
/// them.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct ProfileNetworkConfig {
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub bind_address: String,
    pub ipv6: bool,
    #[serde(deserialize_with = "tun_or_default")]
    pub tun: ProfileTunConfig,
}

impl Default for ProfileNetworkConfig {
    fn default() -> Self {
        Self {
            mixed_port: 7890,
            allow_lan: false,
            bind_address: "*".into(),
            ipv6: false,
            tun: ProfileTunConfig::default(),
        }
    }
}

/// The `tun` settings Egrio reads. TUN mode is the app's own switch, so
/// `enable`, the stack and the routing options there are not read.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct ProfileTunConfig {
    /// Destinations TUN mode leaves to the system routes, in source order
    /// without duplicates.
    #[serde(deserialize_with = "route_exclusions")]
    pub route_exclude_address: Vec<IpPrefix>,
}

/// `tun:` written without a value is YAML null: no settings.
fn tun_or_default<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ProfileTunConfig, D::Error> {
    Ok(Option::<ProfileTunConfig>::deserialize(deserializer)?.unwrap_or_default())
}

/// Each entry is a CIDR prefix, whose host bits are cleared, or a bare
/// address for that one host; at most as many as one capture can exclude.
fn route_exclusions<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpPrefix>, D::Error> {
    let entries = Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default();
    let mut prefixes = Vec::new();
    for entry in entries {
        let prefix = entry
            .parse::<IpPrefix>()
            .map_err(|error| D::Error::custom(format!("route-exclude-address: {error}")))?;
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    if prefixes.len() > egrio_runtime::MAX_EXCLUDED_PREFIXES {
        return Err(D::Error::custom(format!(
            "route-exclude-address lists {} prefixes, more than {}",
            prefixes.len(),
            egrio_runtime::MAX_EXCLUDED_PREFIXES
        )));
    }
    Ok(prefixes)
}

impl ProfileNetworkConfig {
    pub fn listen_addr(&self) -> Result<SocketAddr, String> {
        if self.mixed_port == 0 {
            return Err("mixed-port: 0 is unsupported: the Core requires a mixed listener".into());
        }
        let configured_ip = if self.bind_address == "*" {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else if let Some(address) = self
            .bind_address
            .strip_prefix('[')
            .and_then(|address| address.strip_suffix(']'))
        {
            address
                .parse::<Ipv6Addr>()
                .map(IpAddr::V6)
                .map_err(|_| "bind-address brackets must contain an IPv6 address".to_string())?
        } else {
            self.bind_address
                .parse::<IpAddr>()
                .map_err(|_| "bind-address must be an IP address or '*'".to_string())?
        };
        let ip = if self.allow_lan {
            configured_ip
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        Ok(SocketAddr::new(ip, self.mixed_port))
    }
}

#[cfg(test)]
pub fn parse_profile_network_config(yaml: &str) -> Result<ProfileNetworkConfig, String> {
    let config: ProfileNetworkConfig =
        serde_yaml::from_str(yaml).map_err(|error| error.to_string())?;
    config.listen_addr()?;
    Ok(config)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileNetworkSettings {
    pub profile_id: String,
    /// The source revision a setting change must name.
    pub source_revision: String,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub bind_address: String,
    pub ipv6: bool,
    pub effective_ipv6: Option<bool>,
    pub effective_allow_lan: Option<bool>,
}

impl ProfileNetworkSettings {
    pub(crate) fn from_snapshot(snapshot: &crate::configuration::EffectiveConfigSnapshot) -> Self {
        Self {
            profile_id: snapshot.profile.id.clone(),
            source_revision: snapshot.source_revision.clone(),
            mixed_port: snapshot.network.mixed_port,
            allow_lan: snapshot.network.allow_lan,
            bind_address: snapshot.network.bind_address.clone(),
            ipv6: snapshot.network.ipv6,
            effective_ipv6: None,
            effective_allow_lan: None,
        }
    }
}

pub fn load_active_profile_network_settings() -> Result<Option<ProfileNetworkSettings>, String> {
    let store = ProfileStore::open().map_err(|error| error.to_string())?;
    store
        .active_settings_snapshot()
        .map(|snapshot| snapshot.as_ref().map(ProfileNetworkSettings::from_snapshot))
        .map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileNetworkSetting {
    Ipv6,
    AllowLan,
}

impl ProfileNetworkSetting {
    /// The top-level source key the setting is written to.
    pub fn key(self) -> &'static str {
        match self {
            Self::Ipv6 => "ipv6",
            Self::AllowLan => "allow-lan",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_use_profile_defaults() {
        let config = parse_profile_network_config("proxies: []\nrules: []\n").unwrap();
        assert_eq!(config, ProfileNetworkConfig::default());
        assert_eq!(
            config.listen_addr().unwrap(),
            "127.0.0.1:7890".parse().unwrap()
        );
    }

    #[test]
    fn configured_mixed_port_and_ipv6_do_not_enable_lan() {
        let config = parse_profile_network_config(
            "mixed-port: 12345\nallow-lan: false\nbind-address: '::'\nipv6: true\n",
        )
        .unwrap();
        assert!(config.ipv6);
        assert_eq!(config.bind_address, "::");
        assert_eq!(
            config.listen_addr().unwrap(),
            "127.0.0.1:12345".parse().unwrap()
        );
    }

    #[test]
    fn lan_binding_uses_only_the_explicit_address_family() {
        for (address, ipv6, expected) in [
            ("*", true, "0.0.0.0:7890"),
            ("192.0.2.1", true, "192.0.2.1:7890"),
            ("::", false, "[::]:7890"),
            ("::1", false, "[::1]:7890"),
            ("[::1]", false, "[::1]:7890"),
            ("[2001:db8::1]", true, "[2001:db8::1]:7890"),
        ] {
            let config = parse_profile_network_config(&format!(
                "allow-lan: true\nbind-address: '{address}'\nipv6: {ipv6}\n",
            ))
            .unwrap();
            assert_eq!(config.listen_addr().unwrap(), expected.parse().unwrap());
        }
    }

    #[test]
    fn bracketed_ipv6_stays_loopback_when_lan_is_disabled() {
        let config = parse_profile_network_config(
            "mixed-port: 9876\nallow-lan: false\nbind-address: '[2001:db8::1]'\nipv6: true\n",
        )
        .unwrap();
        assert_eq!(config.bind_address, "[2001:db8::1]");
        assert_eq!(
            config.listen_addr().unwrap(),
            "127.0.0.1:9876".parse().unwrap()
        );
    }

    #[test]
    fn valid_port_boundaries_are_preserved() {
        for port in [1, u16::MAX] {
            let config = parse_profile_network_config(&format!("mixed-port: {port}\n")).unwrap();
            assert_eq!(config.listen_addr().unwrap().port(), port);
        }
    }

    #[test]
    fn disabled_or_invalid_port_is_rejected_instead_of_becoming_ephemeral() {
        assert!(parse_profile_network_config("mixed-port: 0\n")
            .unwrap_err()
            .contains("requires a mixed listener"));
        for value in ["-1", "65536", "1.5", "true", "null", "'7890'"] {
            assert!(
                parse_profile_network_config(&format!("mixed-port: {value}\n")).is_err(),
                "accepted invalid port {value}",
            );
        }
    }

    #[test]
    fn invalid_address_and_boolean_fields_are_rejected_even_with_lan_off() {
        for address in [
            "",
            "localhost",
            "[localhost]",
            "[127.0.0.1]",
            "[::1",
            "::1]",
            "[[::1]]",
            "127.0.0.1:7890",
            " 127.0.0.1 ",
        ] {
            assert!(parse_profile_network_config(&format!(
                "allow-lan: false\nbind-address: '{address}'\n",
            ))
            .is_err());
        }
        for field in ["allow-lan", "ipv6"] {
            for value in ["1", "'true'", "null"] {
                assert!(parse_profile_network_config(&format!("{field}: {value}\n")).is_err());
            }
        }
    }

    #[test]
    fn tun_route_exclusions_are_canonical_prefixes_without_duplicates() {
        let config = parse_profile_network_config(
            "tun:
  enable: true
  stack: system
  route-exclude-address:
    - 192.168.1.7/16
    - 100.64.0.0/10
    - 203.0.113.9
    - fd7a:115c:a1e0::/48
    - 192.168.0.0/16
",
        )
        .unwrap();
        assert_eq!(
            config
                .tun
                .route_exclude_address
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "192.168.0.0/16",
                "100.64.0.0/10",
                "203.0.113.9/32",
                "fd7a:115c:a1e0::/48"
            ]
        );
        for empty in [
            "tun:
  enable: true
",
            "tun:
  route-exclude-address:
",
            "tun:
",
        ] {
            assert!(parse_profile_network_config(empty)
                .unwrap()
                .tun
                .route_exclude_address
                .is_empty());
        }
        for invalid in [
            "[example.com]",
            "[10.0.0.0/33]",
            "[fe80::/129]",
            "10.0.0.0/8",
            "[1]",
        ] {
            assert!(
                parse_profile_network_config(&format!(
                    "tun:
  route-exclude-address: {invalid}
"
                ))
                .is_err(),
                "accepted {invalid}"
            );
        }
        let many = (0..=egrio_runtime::MAX_EXCLUDED_PREFIXES)
            .map(|index| format!("10.0.{}.{}", index / 256, index % 256))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(parse_profile_network_config(&format!(
            "tun:
  route-exclude-address: [{many}]
"
        ))
        .unwrap_err()
        .contains("more than 256"));
    }

    #[test]
    fn settings_keep_the_profile_identity_and_resolve_with_the_same_rules() {
        let config = parse_profile_network_config(
            "mixed-port: 9876\nallow-lan: true\nbind-address: 192.0.2.2\nipv6: true\n",
        )
        .unwrap();
        let mut snapshot = crate::configuration::compose_profile(
            "selected-profile",
            "Selected",
            "{}",
            &Default::default(),
        )
        .unwrap();
        snapshot.network = config;
        let settings = ProfileNetworkSettings::from_snapshot(&snapshot);
        assert_eq!(settings.profile_id, "selected-profile");
        assert!(settings.ipv6 && settings.allow_lan);
        assert_eq!(settings.mixed_port, snapshot.network.mixed_port);
        assert_eq!(settings.bind_address, snapshot.network.bind_address);
    }
}
