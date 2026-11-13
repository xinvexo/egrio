//! Profile and routing evaluation operations.
//!
//! Whole-profile changes restart the Runtime. Local policy and network changes
//! use the Runtime configuration coordinator and report its completion phase.

use crate::active_profile_propagation::{
    propagate_if_active_profile, propagate_if_active_profile_locked, ProfilePropagationOutcome,
};
use crate::models::{ProfileInventory, ProfileRuleList, SavedProfileSummary};
use crate::profile_configuration::{ProfileConfigurationIntent, ProfileConfigurationUpdateReport};
use crate::runtime::DesktopRuntime;
use crate::{network_probe, profile_service, remote_fetch, rule_provider_fetch};
use egrio_core::TrafficPolicyMode;
use egrio_core::{RouteEvaluation, RouteMatchInput};

/// Maps a propagation outcome for a command whose store write already
/// succeeded: a Runtime that is not running has nothing to update.
fn propagation_result(outcome: ProfilePropagationOutcome) -> Result<(), String> {
    match outcome {
        ProfilePropagationOutcome::Applied | ProfilePropagationOutcome::NotRunning => Ok(()),
        ProfilePropagationOutcome::Failed(error) => {
            Err(format!("profile saved but Runtime update failed: {error}"))
        }
    }
}

/// The caller holds the user transition across its store write and this
/// restart.
async fn propagate_if_active_locked(sdk: &DesktopRuntime, profile_id: &str) -> Result<(), String> {
    propagation_result(propagate_if_active_profile_locked(sdk, profile_id).await)
}

pub fn import_clash_profile(name: String, yaml: String) -> Result<SavedProfileSummary, String> {
    profile_service::import_clash_profile(name, yaml)
}

pub fn create_profile(name: String, yaml: String) -> Result<SavedProfileSummary, String> {
    profile_service::create_profile(name, yaml)
}

pub fn profile_source(
    profile_id: String,
) -> Result<crate::profile_store::ProfileSourceDocument, String> {
    profile_service::get_profile_source(profile_id)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileUpdateReport {
    pub profile: SavedProfileSummary,
    pub application: ProfileConfigurationUpdateReport,
}

async fn update_profile_document(
    sdk: crate::runtime::DesktopRuntime,
    update: impl FnOnce() -> Result<(SavedProfileSummary, bool), String> + Send + 'static,
) -> Result<ProfileUpdateReport, String> {
    tokio::spawn(async move {
        let _transition = sdk.begin_user_transition().await;
        let (profile, changed) = update()?;
        use crate::profile_configuration::ProfileConfigurationPhase;
        let outcome = if changed {
            Some(
                crate::active_profile_propagation::propagate_if_active_profile_locked(
                    &sdk,
                    &profile.id,
                )
                .await,
            )
        } else {
            None
        };
        let active = profile_service::get_active_profile()
            .ok()
            .flatten()
            .is_some_and(|active| active.id == profile.id);
        let application = match outcome {
            Some(ProfilePropagationOutcome::Failed(error)) => ProfileConfigurationUpdateReport {
                operation_id: None,
                phase: ProfileConfigurationPhase::PendingApply,
                applied: false,
                generation: None,
                error: Some(error),
            },
            Some(ProfilePropagationOutcome::Applied) => ProfileConfigurationUpdateReport {
                operation_id: None,
                phase: ProfileConfigurationPhase::Applied,
                applied: true,
                generation: None,
                error: None,
            },
            Some(ProfilePropagationOutcome::NotRunning) => {
                ProfileConfigurationUpdateReport::saved(!active)
            }
            None => ProfileConfigurationUpdateReport {
                operation_id: None,
                phase: ProfileConfigurationPhase::NoChange,
                applied: false,
                generation: None,
                error: None,
            },
        };
        Ok(ProfileUpdateReport {
            profile,
            application,
        })
    })
    .await
    .map_err(|error| format!("profile update failed: {error}"))?
}

pub async fn save_profile_source(
    runtime: &DesktopRuntime,
    profile_id: String,
    yaml: String,
    expected_source_revision: String,
) -> Result<ProfileUpdateReport, String> {
    update_profile_document(runtime.clone(), move || {
        profile_service::save_profile_source(profile_id, yaml, expected_source_revision)
            .map(|profile| (profile, true))
    })
    .await
}

pub async fn delete_profile(
    runtime: &DesktopRuntime,
    profile_id: String,
    stop_if_active: bool,
) -> Result<(), String> {
    let sdk = runtime.clone();
    // Own the operation until cleanup and deletion finish even if its window closes.
    tokio::spawn(async move {
        let _transition = sdk.begin_user_transition().await;
        let active =
            profile_service::get_active_profile()?.is_some_and(|profile| profile.id == profile_id);
        if active {
            if !stop_if_active {
                return Err("active profile requires stop and delete".to_string());
            }
            sdk.stop_user_runtime().await?;
        }
        profile_service::delete_profile(profile_id)
    })
    .await
    .map_err(|error| format!("profile deletion failed: {error}"))?
}

pub fn rename_profile(profile_id: String, name: String) -> Result<SavedProfileSummary, String> {
    profile_service::rename_profile(profile_id, name)
}

pub async fn set_group_selection(
    runtime: &DesktopRuntime,
    profile_id: String,
    group_id: String,
    member: String,
) -> Result<ProfileConfigurationUpdateReport, String> {
    runtime
        .configure_profile(
            profile_id,
            ProfileConfigurationIntent::SelectGroup { group_id, member },
        )
        .await
}

/// Which member each of a profile's policy groups uses, by group id: the
/// Select groups' choices, and the member each automatic group uses now.
/// A Core serving this profile answers both from its own state; without
/// one the choices are the saved ones and no automatic group has a member,
/// because nothing is dialling through it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMembers {
    pub chosen: std::collections::HashMap<String, String>,
    pub automatic: std::collections::HashMap<String, String>,
}

pub fn group_members(runtime: &DesktopRuntime, profile_id: String) -> Result<GroupMembers, String> {
    {
        let store =
            crate::profile_store::ProfileStore::open().map_err(|error| error.to_string())?;
        let active = store.active_profile().map_err(|error| error.to_string())?;
        if active
            .as_ref()
            .is_some_and(|profile| profile.id == profile_id)
        {
            if let Some(policy) = runtime
                .effective_core_policy()
                .filter(|policy| policy.profile_id == profile_id)
            {
                let groups = store
                    .profile_inventory(&profile_id)
                    .map_err(|error| error.to_string())?
                    .groups;
                if let Some(members) = effective_group_members(&profile_id, &groups, &policy) {
                    return Ok(members);
                }
            }
        }
    }
    Ok(GroupMembers {
        chosen: profile_service::get_group_selections(profile_id)?,
        automatic: Default::default(),
    })
}

fn effective_group_members(
    profile_id: &str,
    groups: &[crate::profile_store::SavedPolicyGroup],
    policy: &egrio_core::CorePolicyState,
) -> Option<GroupMembers> {
    if policy.profile_id != profile_id {
        return None;
    }
    // The Core names groups; the interface and the store key them by the id
    // that survives a rename.
    let by_id = |members: &std::collections::BTreeMap<String, String>| {
        groups
            .iter()
            .filter_map(|group| {
                members
                    .get(&group.name)
                    .map(|member| (group.id.clone(), member.clone()))
            })
            .collect()
    };
    Some(GroupMembers {
        chosen: by_id(&policy.selected_members),
        automatic: by_id(&policy.automatic_members),
    })
}

fn apply_effective_traffic_policy(
    profile: &mut SavedProfileSummary,
    policy: &egrio_core::CorePolicyState,
) {
    if profile.id == policy.profile_id {
        profile.traffic_policy_mode = policy.traffic_policy_mode;
        profile.global_outbound = Some(policy.global_outbound.clone());
    }
}

pub async fn test_node_latency(
    runtime: &DesktopRuntime,
    profile_id: String,
    node: String,
) -> Result<u32, String> {
    network_probe::test_node_latency(runtime, profile_id, node).await
}

pub async fn import_remote_profile(
    name: String,
    url: String,
) -> Result<SavedProfileSummary, String> {
    remote_fetch::import_remote_profile(name, url).await
}

pub fn list_profiles() -> Result<Vec<SavedProfileSummary>, String> {
    profile_service::list_profiles()
}

pub fn active_profile(runtime: &DesktopRuntime) -> Result<Option<SavedProfileSummary>, String> {
    let mut profile = profile_service::get_active_profile()?;
    if let (Some(profile), Some(policy)) = (profile.as_mut(), runtime.effective_core_policy()) {
        apply_effective_traffic_policy(profile, &policy);
    }
    Ok(profile)
}

pub async fn set_active_profile(
    runtime: &DesktopRuntime,
    profile_id: String,
) -> Result<ProfileUpdateReport, String> {
    update_profile_document(runtime.clone(), move || {
        profile_service::set_active_profile(profile_id).map(|profile| (profile, true))
    })
    .await
}

pub async fn set_profile_traffic_policy(
    runtime: &DesktopRuntime,
    profile_id: String,
    traffic_policy_mode: TrafficPolicyMode,
    global_outbound: Option<String>,
) -> Result<ProfileConfigurationUpdateReport, String> {
    runtime
        .configure_profile(
            profile_id,
            ProfileConfigurationIntent::TrafficPolicy {
                mode: traffic_policy_mode,
                global_outbound,
            },
        )
        .await
}

pub fn profile_inventory(profile_id: String) -> Result<ProfileInventory, String> {
    profile_service::get_profile_inventory(profile_id)
}

pub fn profile_rules(profile_id: String) -> Result<ProfileRuleList, String> {
    profile_service::get_profile_rules(profile_id)
}

pub async fn reorder_profile_rules(
    runtime: &DesktopRuntime,
    profile_id: String,
    ordered_rule_ids: Vec<String>,
    expected_source_revision: String,
) -> Result<(), String> {
    let _transition = runtime.begin_user_transition().await;
    profile_service::reorder_profile_rules(
        profile_id.clone(),
        ordered_rule_ids,
        expected_source_revision,
    )?;
    // Reordering changes routing precedence, so hot-apply to the running
    // surfaces (only when this is the active profile) for instant effect.
    propagate_if_active_locked(runtime, &profile_id).await
}

#[allow(clippy::too_many_arguments)]
pub async fn add_profile_rule(
    runtime: &DesktopRuntime,
    profile_id: String,
    kind: String,
    payload: Option<String>,
    outbound: String,
    no_resolve: bool,
    expected_source_revision: String,
) -> Result<(), String> {
    let _transition = runtime.begin_user_transition().await;
    profile_service::add_profile_rule(
        profile_id.clone(),
        kind,
        payload,
        outbound,
        no_resolve,
        expected_source_revision,
    )?;
    propagate_if_active_locked(runtime, &profile_id).await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_profile_rule(
    runtime: &DesktopRuntime,
    profile_id: String,
    rule_id: String,
    kind: String,
    payload: Option<String>,
    outbound: String,
    no_resolve: bool,
    expected_source_revision: String,
) -> Result<(), String> {
    let _transition = runtime.begin_user_transition().await;
    profile_service::update_profile_rule(
        profile_id.clone(),
        rule_id,
        kind,
        payload,
        outbound,
        no_resolve,
        expected_source_revision,
    )?;
    // Editing a rule changes routing, so hot-apply to the running surfaces
    // (only when this is the active profile) for instant effect.
    propagate_if_active_locked(runtime, &profile_id).await
}

pub async fn delete_profile_rules(
    runtime: &DesktopRuntime,
    profile_id: String,
    rule_ids: Vec<String>,
    expected_source_revision: String,
) -> Result<(), String> {
    let _transition = runtime.begin_user_transition().await;
    profile_service::delete_profile_rules(profile_id.clone(), rule_ids, expected_source_revision)?;
    propagate_if_active_locked(runtime, &profile_id).await
}

pub async fn update_all_rule_providers(
    runtime: &DesktopRuntime,
    profile_id: String,
) -> Result<crate::rule_provider_fetch::RuleProviderRefreshReport, String> {
    let report = rule_provider_fetch::update_all_rule_providers(profile_id.clone()).await?;
    // Rechecking unchanged content or failing every download does not change
    // effective routing and must not tear down the running connections.
    if !report.updated.is_empty() {
        propagation_result(propagate_if_active_profile(runtime, &profile_id).await).map_err(
            |error| format!("rule providers were cached but Runtime application failed: {error}"),
        )?;
    }
    log::info!(target: "rule-providers", "refresh-finished profile={} updated={} unchanged={} failed={}",
        profile_id, report.updated.len(), report.unchanged.len(), report.failures.len());
    Ok(report)
}

pub async fn update_rule_provider(
    runtime: &DesktopRuntime,
    profile_id: String,
    provider_name: String,
) -> Result<crate::rule_provider_fetch::RuleProviderUpdateReport, String> {
    let report =
        rule_provider_fetch::update_rule_provider(profile_id.clone(), provider_name).await?;
    if report.changed {
        propagation_result(propagate_if_active_profile(runtime, &profile_id).await).map_err(
            |error| format!("rule provider was cached but Runtime application failed: {error}"),
        )?;
    }
    log::info!(target: "rule-providers", "provider-refresh-finished profile={} provider={} changed={}",
        profile_id, report.provider.name, report.changed);
    Ok(report)
}

pub async fn evaluate_active_profile_route(
    runtime: &DesktopRuntime,
    input: RouteMatchInput,
) -> Result<RouteEvaluation, String> {
    if let Some(evaluation) = runtime.evaluate_core_route(&input).await? {
        return Ok(evaluation);
    }
    profile_service::evaluate_active_profile_route(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_members_translate_core_names_to_stable_group_ids() {
        let groups = vec![
            crate::profile_store::SavedPolicyGroup {
                id: "stable-id".into(),
                name: "Proxy".into(),
                kind: "select".into(),
                members: vec!["Old".into(), "New".into()],
                sort_order: 0,
            },
            crate::profile_store::SavedPolicyGroup {
                id: "automatic-id".into(),
                name: "Auto".into(),
                kind: "url-test".into(),
                members: vec!["Old".into()],
                sort_order: 1,
            },
        ];
        let policy = egrio_core::CorePolicyState {
            profile_id: "current-profile".into(),
            epoch: 4,
            ipv6_enabled: false,
            traffic_policy_mode: TrafficPolicyMode::Rule,
            global_outbound: "Proxy".into(),
            selected_members: [("Proxy".into(), "Old".into())].into_iter().collect(),
            automatic_members: [("Auto".into(), "Old".into())].into_iter().collect(),
        };
        assert_eq!(
            effective_group_members("current-profile", &groups, &policy),
            Some(GroupMembers {
                chosen: [("stable-id".into(), "Old".into())].into_iter().collect(),
                automatic: [("automatic-id".into(), "Old".into())]
                    .into_iter()
                    .collect(),
            })
        );
        assert!(effective_group_members("new-profile", &groups, &policy).is_none());
    }

    #[test]
    fn effective_policy_does_not_overwrite_another_profile() {
        let mut profile = SavedProfileSummary {
            id: "new-profile".into(),
            name: "New".into(),
            revision: "1".into(),
            source_revision: "source".into(),
            traffic_policy_mode: TrafficPolicyMode::Direct,
            global_outbound: Some("New".into()),
            proxies: 1,
            groups: 1,
            rules: 0,
            updated_at_unix: 0,
        };
        let mut policy = egrio_core::CorePolicyState {
            profile_id: "old-profile".into(),
            epoch: 1,
            ipv6_enabled: false,
            traffic_policy_mode: TrafficPolicyMode::Global,
            global_outbound: "Old".into(),
            selected_members: Default::default(),
            automatic_members: Default::default(),
        };
        apply_effective_traffic_policy(&mut profile, &policy);
        assert_eq!(profile.traffic_policy_mode, TrafficPolicyMode::Direct);
        assert_eq!(profile.global_outbound.as_deref(), Some("New"));
        policy.profile_id = "new-profile".into();
        apply_effective_traffic_policy(&mut profile, &policy);
        assert_eq!(profile.traffic_policy_mode, TrafficPolicyMode::Global);
        assert_eq!(profile.global_outbound.as_deref(), Some("Old"));
    }
}
