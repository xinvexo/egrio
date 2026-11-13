use egrio_core::{RouteRule, RuleKind, RuntimeProfile, TrafficPolicyMode};

pub fn load_profile(runtime_profile_path: Option<String>) -> Result<RuntimeProfile, String> {
    let Some(runtime_profile_path) = runtime_profile_path else {
        return Ok(default_direct_profile());
    };
    let document = std::fs::read_to_string(&runtime_profile_path)
        .map_err(|error| format!("failed to read profile {runtime_profile_path}: {error}"))?;
    serde_json::from_str(&document)
        .map_err(|error| format!("failed to parse profile {runtime_profile_path}: {error}"))
}

pub fn default_direct_profile() -> RuntimeProfile {
    RuntimeProfile {
        dns: Default::default(),
        id: "service-default-direct".into(),
        name: "service-default-direct".into(),
        traffic_policy_mode: TrafficPolicyMode::Rule,
        global_outbound: None,
        proxies: Vec::new(),
        groups: Vec::new(),
        rules: vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into(),
        rule_sets: Vec::new(),
        geodata: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_validation_profiles_stay_loadable() {
        for (file, expected_outbound) in [
            ("http-proxy.json", "ValidationHttpUpstream"),
            ("socks5-proxy.json", "ValidationSocks5Upstream"),
        ] {
            let path = format!(
                "{}/../../scripts/validation/profiles/{file}",
                env!("CARGO_MANIFEST_DIR")
            );
            let profile = load_profile(Some(path)).expect("validation profile loads");

            assert_eq!(profile.proxies.len(), 1, "{file} carries one proxy node");
            assert_eq!(profile.proxies[0].name, expected_outbound);
            assert!(
                profile.rules.iter().any(|rule| {
                    matches!(rule.kind, RuleKind::Match) && rule.outbound == expected_outbound
                }),
                "{file} routes MATCH traffic through {expected_outbound}"
            );
        }
    }
}
