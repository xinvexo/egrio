//! GUI-owned composition. Neither source documents nor the Profile's saved
//! choices cross the Core/SDK boundary; only the resolved profile and
//! listener values do.

use std::collections::BTreeMap;

use egrio_core::{PolicyGroup, PolicyGroupKind, RuntimeProfile, TrafficPolicyMode};

use crate::profile_network_settings::ProfileNetworkConfig;
use crate::profile_source::ParsedSource;

/// How the user uses a Profile, kept beside its source rather than in it:
/// the traffic mode they picked, their group selections and the global
/// outbound. These are choices made while using the file, not edits of its
/// content; everything the file says is changed by writing the file.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProfileChoices {
    pub traffic_mode: Option<TrafficPolicyMode>,
    pub group_selections: BTreeMap<String, String>,
    pub global_outbound: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EffectiveConfigSnapshot {
    pub profile: RuntimeProfile,
    pub network: ProfileNetworkConfig,
    pub source_revision: String,
    /// Rule sets the rules name are not downloaded yet. The profile then
    /// carries no rules, only what reaches the rule sets: its nodes, groups,
    /// choices and DNS. Only a Core start reads a profile this way.
    pub awaiting_rule_sets: bool,
}

#[cfg(test)]
pub(crate) fn compose_profile(
    profile_id: &str,
    name: &str,
    raw_yaml: &str,
    choices: &ProfileChoices,
) -> Result<EffectiveConfigSnapshot, String> {
    let source = crate::profile_source::parse_source(raw_yaml)?;
    compose(profile_id, name, &source, choices)
}

/// The mode the user picked, else the one the source writes, else the
/// default.
pub(crate) fn traffic_mode(
    written: Option<TrafficPolicyMode>,
    chosen: Option<TrafficPolicyMode>,
) -> TrafficPolicyMode {
    chosen.or(written).unwrap_or_default()
}

/// A group choice is valid while its group exists, is a Select group and
/// still lists the member. It depends on nothing else in the profile.
pub(crate) fn selectable_group<'a>(
    groups: &'a [PolicyGroup],
    id: &str,
    member: &str,
) -> Result<&'a PolicyGroup, String> {
    let group = groups
        .iter()
        .find(|group| group.id == id)
        .ok_or_else(|| format!("saved policy group no longer exists: {id}"))?;
    if !matches!(group.kind, PolicyGroupKind::Select) || !group.members.iter().any(|m| m == member)
    {
        return Err(format!(
            "saved group selection no longer exists: {} / {member}",
            group.name
        ));
    }
    Ok(group)
}

/// Whether `outbound` names something a rule can route to in `profile`.
pub(crate) fn known_outbound(profile: &RuntimeProfile, outbound: &str) -> bool {
    matches!(outbound, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS")
        || profile.proxies.iter().any(|node| node.name == outbound)
        || profile.groups.iter().any(|group| group.name == outbound)
}

/// The source with the Profile's identity and choices. Rule-set contents are
/// the store's to add.
pub(crate) fn compose(
    profile_id: &str,
    name: &str,
    source: &ParsedSource,
    choices: &ProfileChoices,
) -> Result<EffectiveConfigSnapshot, String> {
    let mut profile = source.content.clone();
    profile.id = profile_id.to_string();
    profile.name = name.to_string();
    profile.traffic_policy_mode = traffic_mode(source.mode, choices.traffic_mode);
    if let Some(outbound) = &choices.global_outbound {
        if !known_outbound(&profile, outbound) {
            return Err(format!(
                "saved global outbound no longer exists: {outbound}"
            ));
        }
        profile.global_outbound = Some(outbound.clone());
    }
    for (id, member) in &choices.group_selections {
        selectable_group(&profile.groups, id, member)?;
        if let Some(group) = profile.groups.iter_mut().find(|group| &group.id == id) {
            group.selected = Some(member.clone());
        }
    }
    Ok(EffectiveConfigSnapshot {
        profile,
        network: source.network.clone(),
        source_revision: source.revision.clone(),
        awaiting_rule_sets: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compose_raw(raw: &str, choices: &ProfileChoices) -> Result<EffectiveConfigSnapshot, String> {
        compose_profile("profile-a", "A", raw, choices)
    }

    #[test]
    fn the_source_decides_network_mode_and_dns() {
        let snapshot = compose_raw("mixed-port: 9876\nbind-address: '::'\nallow-lan: true\nipv6: true\nmode: direct\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n", &ProfileChoices::default()).unwrap();
        assert_eq!(snapshot.network.mixed_port, 9876);
        assert_eq!(snapshot.network.bind_address, "::");
        assert!(snapshot.network.allow_lan && snapshot.network.ipv6);
        assert_eq!(
            snapshot.profile.traffic_policy_mode,
            TrafficPolicyMode::Direct
        );
        assert_eq!(snapshot.profile.dns.nameservers[0].host, "1.1.1.1");
    }

    #[test]
    fn defaults_only_fill_missing_source_fields() {
        let snapshot = compose_raw("proxies: []\nrules: []\n", &ProfileChoices::default()).unwrap();
        assert_eq!(snapshot.network, ProfileNetworkConfig::default());
        assert_eq!(
            snapshot.profile.traffic_policy_mode,
            TrafficPolicyMode::Rule
        );
        assert!(!snapshot.profile.dns.enabled);
    }

    #[test]
    fn a_chosen_mode_wins_over_the_source_and_belongs_to_its_profile() {
        let raw = "mode: direct\n";
        let chosen = ProfileChoices {
            traffic_mode: Some(TrafficPolicyMode::Global),
            ..Default::default()
        };
        assert_eq!(
            compose_raw(raw, &chosen)
                .unwrap()
                .profile
                .traffic_policy_mode,
            TrafficPolicyMode::Global
        );
        let other = compose_profile("profile-b", "B", raw, &ProfileChoices::default()).unwrap();
        assert_eq!(other.profile.traffic_policy_mode, TrafficPolicyMode::Direct);
        // A chosen mode does not hide an invalid one in the file.
        assert!(compose_raw("mode: no-such-mode\n", &chosen).is_err());
    }

    #[test]
    fn invalid_dns_and_listener_values_are_rejected() {
        assert!(compose_raw(
            "dns:\n  enable: true\n  nameserver: [unsupported]\n",
            &ProfileChoices::default()
        )
        .is_err());
        assert!(compose_raw("mixed-port: 0\n", &ProfileChoices::default()).is_err());
        assert!(compose_raw("bind-address: localhost\n", &ProfileChoices::default()).is_err());
        assert!(compose_raw("ipv6: invalid\n", &ProfileChoices::default()).is_err());
    }

    #[test]
    fn choices_are_validated_against_the_source() {
        let source = "proxies:\n  - {name: Exit, type: http, server: example.com, port: 8080}\nproxy-groups:\n  - {name: Choice, type: select, proxies: [Exit, DIRECT]}\nrules: ['MATCH,DIRECT']\n";
        let base = compose_raw(source, &ProfileChoices::default()).unwrap();
        let choices = ProfileChoices {
            group_selections: BTreeMap::from([(base.profile.groups[0].id.clone(), "Exit".into())]),
            global_outbound: Some("Exit".into()),
            ..Default::default()
        };
        let resolved = compose_raw(source, &choices).unwrap();
        assert_eq!(resolved.profile.groups[0].selected.as_deref(), Some("Exit"));
        assert_eq!(resolved.profile.global_outbound.as_deref(), Some("Exit"));
        let removed_node = source.replace("proxies: [Exit, DIRECT]", "proxies: [DIRECT]");
        assert!(compose_raw(&removed_node, &choices).is_err());
    }
}
