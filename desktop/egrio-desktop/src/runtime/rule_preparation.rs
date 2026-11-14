//! Missing provider bodies are fetched by the generation that will serve them.
use super::*;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CorePreparation {
    pub layers: CaptureLayers,
    pub error: Option<String>,
}

pub(super) fn needs_providers(profile: &egrio_core::RuntimeProfile) -> bool {
    profile.rules.iter().any(|rule| {
        rule.kind == egrio_core::RuleKind::RuleSet
            && !profile
                .rule_sets
                .iter()
                .any(|set| Some(set.name.as_str()) == rule.payload)
    })
}

impl<H: DesktopHost> DesktopRuntime<H> {
    pub fn core_preparation(&self) -> Option<CorePreparation> {
        let status = self.domain_status()?;
        (status.runtime.state == RuntimeState::Preparing).then(|| CorePreparation {
            layers: spec_capture_layers(&status.spec),
            error: status.runtime.degradation_error,
        })
    }

    pub fn requested_capture_layers(&self) -> CaptureLayers {
        self.core_preparation()
            .map_or_else(|| self.capture_layers(), |preparing| preparing.layers)
    }

    pub(crate) fn download_runtime(&self) -> Option<Arc<Runtime>> {
        self.existing_desktop_runtime().filter(|runtime| {
            matches!(
                runtime.status().state,
                RuntimeState::Preparing | RuntimeState::Running
            )
        })
    }

    pub(super) fn cancel_rule_preparation(&self) {
        if let Some(task) = self
            .rule_preparation_task
            .lock()
            .expect("rule preparation task")
            .take()
        {
            task.abort();
        }
    }

    pub(super) fn start_rule_preparation(
        &self,
        runtime: Arc<Runtime>,
        generation: egrio_runtime::RuntimeCoreGeneration,
        profile_id: String,
        source_revision: String,
    ) {
        let mut task = self
            .rule_preparation_task
            .lock()
            .expect("rule preparation task");
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let host = self.clone();
        *task = Some(crate::async_runtime::spawn(async move {
            let result = async {
                crate::rule_provider_fetch::prepare_via_core(profile_id.clone(), runtime.clone())
                    .await?;
                let _transition = host.begin_user_transition().await;
                let mut activity = host.begin_host_transition().await?;
                let snapshot = (host.configuration)().await?.ok_or("no active profile")?;
                if snapshot.profile.id != profile_id || snapshot.source_revision != source_revision
                {
                    return Err(
                        "profile source changed during preparation; apply the configuration again"
                            .into(),
                    );
                }
                let spec = runtime_spec_with_profile(runtime.spec(), Some(&snapshot))?;
                runtime.prepare_core(spec).await?;
                let capture_mtu = host.prepared_configuration.get()?.capture_mtu;
                let prepared = Arc::new(PreparedCoreStart::new(snapshot, capture_mtu));
                let profile = prepared.take_profile()?;
                *host
                    .prepared_configuration
                    .inputs
                    .write()
                    .expect("configuration preparation lock") = Some(prepared);
                activity.begin_background_activity(H::begin_activity);
                let activated = runtime.activate_prepared_core(generation, profile).await;
                if !host.capture_active() {
                    activity.end_background_activity();
                }
                activated.map_err(|error| error.to_string())?;
                Ok::<_, String>(())
            }
            .await;
            if let Err(error) = result {
                runtime.core_preparation_failed(generation, error.clone());
                log::error!(target: "rule-providers", "profile-preparation-failed {error}");
                crate::events::notify_core_preparation_failed(error);
            }
            crate::events::notify_native_state_changed();
            drop(crate::events::notify_profiles_on_return());
        }));
    }
}
