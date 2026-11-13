//! Product intents map to explicit Runtime operations; only whole-document edits restart.
//! A network switch writes its key into the source but applies live, like a
//! choice.
use crate::profile_network_settings::ProfileNetworkSetting;
use crate::profile_store::ProfileStore;
use egrio_core::{CorePolicyUpdate, TrafficPolicyMode};
use egrio_runtime::{ConfigurationPhase, RuntimeConfigurationChange, RuntimeConfigurationReport};
use serde::Serialize;

#[derive(Debug, Clone)]
pub(crate) enum ProfileConfigurationIntent {
    SelectGroup {
        group_id: String,
        member: String,
    },
    TrafficPolicy {
        mode: TrafficPolicyMode,
        global_outbound: Option<String>,
    },
    Network {
        setting: ProfileNetworkSetting,
        enabled: bool,
        expected_source_revision: String,
    },
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileConfigurationPhase {
    NoChange,
    SavedInactive,
    SavedStopped,
    Rejected,
    PendingApply,
    Applied,
    AppliedCleanupPending,
    Degraded,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProfileConfigurationUpdateReport {
    pub operation_id: Option<String>,
    pub phase: ProfileConfigurationPhase,
    pub applied: bool,
    pub generation: Option<u64>,
    pub error: Option<String>,
}
impl ProfileConfigurationUpdateReport {
    pub(crate) fn saved(inactive: bool) -> Self {
        Self {
            operation_id: None,
            phase: if inactive {
                ProfileConfigurationPhase::SavedInactive
            } else {
                ProfileConfigurationPhase::SavedStopped
            },
            applied: false,
            generation: None,
            error: None,
        }
    }
    pub(crate) fn from_runtime(report: RuntimeConfigurationReport) -> Self {
        let phase = match report.phase {
            ConfigurationPhase::NoChange => ProfileConfigurationPhase::NoChange,
            ConfigurationPhase::SavedStopped => ProfileConfigurationPhase::SavedStopped,
            ConfigurationPhase::Rejected => ProfileConfigurationPhase::Rejected,
            ConfigurationPhase::PendingApply => ProfileConfigurationPhase::PendingApply,
            ConfigurationPhase::Applied => ProfileConfigurationPhase::Applied,
            ConfigurationPhase::AppliedCleanupPending => {
                ProfileConfigurationPhase::AppliedCleanupPending
            }
            ConfigurationPhase::Degraded => ProfileConfigurationPhase::Degraded,
        };
        Self {
            operation_id: Some(report.operation_id),
            phase,
            applied: report.phase.is_applied(),
            generation: Some(report.generation.get()),
            error: report.error,
        }
    }
}

pub(crate) struct PreparedProfileConfiguration {
    pub change: RuntimeConfigurationChange,
    pub persist: Box<dyn FnOnce() -> Result<(), String> + Send>,
}

pub(crate) fn prepare(
    store: ProfileStore,
    profile_id: String,
    intent: ProfileConfigurationIntent,
) -> Result<PreparedProfileConfiguration, String> {
    let intent = match intent {
        ProfileConfigurationIntent::TrafficPolicy {
            mode,
            global_outbound,
        } => {
            let saved = store
                .profile_summary_by_id(&profile_id)
                .map_err(|e| e.to_string())?;
            // Mode-only changes preserve the selected global exit. Resolve
            // once so Core and the durable record receive identical intent.
            let global_outbound =
                normalize_policy_outbound(global_outbound, saved.global_outbound)?;
            ProfileConfigurationIntent::TrafficPolicy {
                mode,
                global_outbound,
            }
        }
        other => other,
    };
    let change = match &intent {
        ProfileConfigurationIntent::SelectGroup { group_id, member } => {
            // The inventory carries no rules, so this costs the same at any
            // rule-list size. The live Core validates the choice again before
            // the persistence callback runs.
            let inventory = store
                .profile_inventory(&profile_id)
                .map_err(|e| e.to_string())?;
            let group = inventory
                .groups
                .iter()
                .find(|group| &group.id == group_id)
                .ok_or_else(|| "selected policy group no longer exists".to_string())?;
            if group.kind != "select" || !group.members.contains(member) {
                return Err("invalid selectable group member".into());
            }
            RuntimeConfigurationChange::Policy(CorePolicyUpdate::SelectGroup {
                group: group.name.clone(),
                member: member.clone(),
            })
        }
        ProfileConfigurationIntent::TrafficPolicy {
            mode,
            global_outbound,
        } => RuntimeConfigurationChange::Policy(CorePolicyUpdate::TrafficPolicy {
            mode: *mode,
            global_outbound: global_outbound.clone(),
        }),
        ProfileConfigurationIntent::Network {
            setting,
            enabled,
            expected_source_revision,
        } => {
            let (key, value) = (setting.key(), if *enabled { "true" } else { "false" });
            let candidate = store
                .preview_profile_setting(&profile_id, expected_source_revision, key, value)
                .map_err(|error| error.to_string())?;
            let change = match setting {
                ProfileNetworkSetting::Ipv6 => RuntimeConfigurationChange::Policy(
                    CorePolicyUpdate::Ipv6Enabled(candidate.network.ipv6),
                ),
                ProfileNetworkSetting::AllowLan => {
                    RuntimeConfigurationChange::ListenerScope(candidate.network.listen_addr()?)
                }
            };
            let expected_source_revision = expected_source_revision.clone();
            return Ok(PreparedProfileConfiguration {
                change,
                persist: Box::new(move || {
                    store
                        .set_profile_setting(&profile_id, &expected_source_revision, key, value)
                        .map_err(|error| error.to_string())
                }),
            });
        }
    };
    Ok(PreparedProfileConfiguration {
        change,
        persist: Box::new(move || match intent {
            ProfileConfigurationIntent::SelectGroup { group_id, member } => store
                .set_group_selection(&profile_id, &group_id, &member)
                .map_err(|e| e.to_string()),
            ProfileConfigurationIntent::TrafficPolicy {
                mode,
                global_outbound,
            } => store
                .set_profile_traffic_policy(&profile_id, mode, global_outbound)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            ProfileConfigurationIntent::Network { .. } => {
                unreachable!("network intent returns its CAS writer")
            }
        }),
    })
}

fn normalize_policy_outbound(
    requested: Option<String>,
    current: Option<String>,
) -> Result<Option<String>, String> {
    match requested {
        Some(value) if value.trim().is_empty() => Err("global outbound cannot be empty".into()),
        Some(value) => Ok(Some(value.trim().to_string())),
        None => Ok(current),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mode_only_updates_preserve_the_same_exit_for_live_and_persisted_policy() {
        assert_eq!(
            normalize_policy_outbound(None, Some("ExitB".into())).unwrap(),
            Some("ExitB".into())
        );
        assert_eq!(
            normalize_policy_outbound(Some(" ExitA ".into()), Some("ExitB".into())).unwrap(),
            Some("ExitA".into())
        );
        assert_eq!(normalize_policy_outbound(None, None).unwrap(), None);
        assert!(normalize_policy_outbound(Some("  ".into()), None).is_err());
    }
}
