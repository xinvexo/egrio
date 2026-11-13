//! Restarts the desktop Runtime after durable whole-profile changes.
//!
//! The desktop Runtime owns the in-process Core on macOS, Windows, and Linux;
//! the privileged service owns only OS capability adapters and never receives
//! product profiles or Core configuration.

use crate::profile_store::ProfileStore;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum ProfilePropagationOutcome {
    Applied,
    NotRunning,
    Failed(String),
}

fn propagation_outcome(result: Result<bool, String>) -> ProfilePropagationOutcome {
    match result {
        Ok(true) => ProfilePropagationOutcome::Applied,
        Ok(false) => ProfilePropagationOutcome::NotRunning,
        Err(error) => ProfilePropagationOutcome::Failed(error),
    }
}

fn is_active_profile(active_profile_id: Option<&str>, changed_profile_id: &str) -> bool {
    active_profile_id == Some(changed_profile_id)
}

async fn restart_configuration_locked(
    runtime: &crate::runtime::DesktopRuntime,
) -> ProfilePropagationOutcome {
    // Runtime already owns cleanup after a stop/start failure. A preflight
    // failure must leave the old running configuration available for retry.
    propagation_outcome(runtime.restart_running_runtime().await)
}

fn failed_restart(error: String, recovery: Result<(), String>) -> ProfilePropagationOutcome {
    ProfilePropagationOutcome::Failed(match recovery {
        Ok(()) => format!("{error}; the requested configuration is stopped"),
        Err(recovery) => format!("{error}; network recovery is incomplete: {recovery}"),
    })
}

pub async fn propagate_if_active_profile(
    runtime: &crate::runtime::DesktopRuntime,
    changed_profile_id: &str,
) -> ProfilePropagationOutcome {
    {
        let _transition = runtime.begin_user_transition().await;
        propagate_if_active_profile_locked(runtime, changed_profile_id).await
    }
}

/// The caller holds the user transition across both the store write and restart.
pub(crate) async fn propagate_if_active_profile_locked(
    runtime: &crate::runtime::DesktopRuntime,
    changed_profile_id: &str,
) -> ProfilePropagationOutcome {
    match current_active_profile_id() {
        Ok(active) if is_active_profile(active.as_deref(), changed_profile_id) => {
            restart_configuration_locked(runtime).await
        }
        Ok(_) => ProfilePropagationOutcome::NotRunning,
        Err(error) => failed_restart(error, runtime.stop_user_runtime().await),
    }
}

fn current_active_profile_id() -> Result<Option<String>, String> {
    ProfileStore::open()
        .map_err(|error| error.to_string())?
        .active_profile()
        .map_err(|error| error.to_string())
        .map(|profile| profile.map(|profile| profile.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagation_outcome_preserves_applied_not_running_and_failure() {
        assert_eq!(
            propagation_outcome(Ok(true)),
            ProfilePropagationOutcome::Applied
        );
        assert_eq!(
            propagation_outcome(Ok(false)),
            ProfilePropagationOutcome::NotRunning
        );
        assert_eq!(
            propagation_outcome(Err("reload failed".into())),
            ProfilePropagationOutcome::Failed("reload failed".into())
        );
    }

    #[test]
    fn only_the_active_profile_is_eligible_for_propagation() {
        assert!(is_active_profile(Some("active"), "active"));
        assert!(!is_active_profile(Some("active"), "other"));
        assert!(!is_active_profile(None, "active"));
    }

    #[test]
    fn failed_restart_distinguishes_stopped_configuration_from_incomplete_recovery() {
        assert_eq!(
            failed_restart("restart failed".into(), Ok(())),
            ProfilePropagationOutcome::Failed(
                "restart failed; the requested configuration is stopped".into()
            )
        );
        assert_eq!(
            failed_restart("restart failed".into(), Err("restore failed".into())),
            ProfilePropagationOutcome::Failed(
                "restart failed; network recovery is incomplete: restore failed".into()
            )
        );
    }
}
