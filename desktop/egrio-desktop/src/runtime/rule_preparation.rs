//! Rule sets the rules name but the cache lacks are downloaded by the Core
//! that will serve them, through the node chosen now, before that Core takes
//! any traffic. This file owns that download: its task, the profile source it
//! is for and how it ended. The Runtime only knows a prepared Core.
use super::*;
use serde::Serialize;

/// Capture waits for the profile's rule sets.
#[derive(Debug, Clone, Serialize)]
pub struct CorePreparation {
    /// The layers that turn on once the rule sets arrive.
    pub layers: CaptureLayers,
    /// Why they did not arrive; `None` while the download runs.
    pub error: Option<String>,
}

/// The profile source a prepared Core was made from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProfileSource {
    pub profile_id: String,
    pub revision: String,
}

impl ProfileSource {
    pub(super) fn of(snapshot: &crate::configuration::EffectiveConfigSnapshot) -> Self {
        Self {
            profile_id: snapshot.profile.id.clone(),
            revision: snapshot.source_revision.clone(),
        }
    }
}

/// Downloads a profile's missing rule sets through a Runtime's Core.
pub(super) type RuleSetDownload = dyn Fn(String, Arc<Runtime>) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
    + Send
    + Sync;

#[derive(Debug, Default)]
pub(super) struct RuleDownload {
    /// Downloads started so far; one that ends reports only as the latest.
    runs: u64,
    state: RuleDownloadState,
}

#[derive(Debug, Default)]
enum RuleDownloadState {
    #[default]
    Idle,
    Running {
        run: u64,
        source: ProfileSource,
        task: tokio::task::JoinHandle<()>,
    },
    /// The prepared Core stays for another attempt.
    Failed {
        source: ProfileSource,
        error: String,
    },
}

impl<H: DesktopHost> DesktopRuntime<H> {
    fn rule_download(&self) -> std::sync::MutexGuard<'_, RuleDownload> {
        self.rule_download.lock().expect("rule download state")
    }

    pub fn core_preparation(&self) -> Option<CorePreparation> {
        let status = self.domain_status()?;
        if status.runtime.state != RuntimeState::Preparing {
            return None;
        }
        let error = match &self.rule_download().state {
            RuleDownloadState::Running { task, .. } if !task.is_finished() => None,
            RuleDownloadState::Failed { error, .. } => Some(error.clone()),
            _ => Some("the rule set download did not finish".into()),
        };
        Some(CorePreparation {
            layers: spec_capture_layers(&status.spec),
            error,
        })
    }

    /// The layers the user asked for: those waiting for rule sets, else
    /// those the Runtime carries.
    pub fn requested_capture_layers(&self) -> CaptureLayers {
        self.core_preparation()
            .map_or_else(|| self.capture_layers(), |preparing| preparing.layers)
    }

    /// The Runtime whose Core downloads rule sets, when one has a Core.
    pub(crate) fn download_runtime(&self) -> Option<Arc<Runtime>> {
        self.existing_desktop_runtime().filter(|runtime| {
            matches!(
                runtime.status().state,
                RuntimeState::Preparing | RuntimeState::Running
            )
        })
    }

    /// A node change would cut the download's connection, so none is taken
    /// meanwhile.
    pub(super) fn rule_download_running(&self) -> bool {
        matches!(
            &self.rule_download().state,
            RuleDownloadState::Running { task, .. } if !task.is_finished()
        )
    }

    /// Whether the prepared Core was made from `source`.
    pub(super) fn rule_download_serves(&self, source: &ProfileSource) -> bool {
        match &self.rule_download().state {
            RuleDownloadState::Running {
                source: prepared, ..
            }
            | RuleDownloadState::Failed {
                source: prepared, ..
            } => prepared == source,
            RuleDownloadState::Idle => false,
        }
    }

    /// Ends the download with the prepared Core it was for.
    pub(super) fn cancel_rule_download(&self) {
        let mut download = self.rule_download();
        if let RuleDownloadState::Running { task, .. } = &download.state {
            task.abort();
        }
        download.state = RuleDownloadState::Idle;
    }

    /// Downloads `source`'s rule sets through the Core `generation` prepared
    /// from it, then opens that Core to traffic. One that already runs for
    /// the source goes on.
    pub(super) fn download_rule_sets(
        &self,
        runtime: Arc<Runtime>,
        generation: egrio_runtime::RuntimeCoreGeneration,
        source: ProfileSource,
    ) {
        let mut download = self.rule_download();
        if let RuleDownloadState::Running {
            source: current,
            task,
            ..
        } = &download.state
        {
            if *current == source && !task.is_finished() {
                return;
            }
            task.abort();
        }
        download.runs += 1;
        let run = download.runs;
        let host = self.clone();
        let task_source = source.clone();
        let task = crate::async_runtime::spawn(async move {
            let source = task_source;
            let downloaded = (host.rule_sets)(source.profile_id.clone(), runtime.clone()).await;
            let outcome = match downloaded {
                Ok(()) => host
                    .activate_with_rule_sets(&runtime, generation, &source)
                    .await
                    .map_err(DownloadFailure::Start),
                Err(error) => Err(DownloadFailure::Download(error)),
            };
            host.rule_download_ended(run, &runtime, source, outcome);
        });
        download.state = RuleDownloadState::Running { run, source, task };
    }

    /// Downloads again after the user changed the node a failed download
    /// went through.
    pub(super) fn retry_rule_download(&self, runtime: &Arc<Runtime>) {
        let source = match &self.rule_download().state {
            RuleDownloadState::Failed { source, .. } => source.clone(),
            _ => return,
        };
        let status = runtime.domain_status();
        if let Some(core) = status
            .core
            .filter(|_| status.runtime.state == RuntimeState::Preparing)
        {
            self.download_rule_sets(runtime.clone(), core.generation, source);
        }
    }

    /// The rule sets arrived: the prepared Core takes the complete profile
    /// and the Runtime opens its listeners and capture layers.
    async fn activate_with_rule_sets(
        &self,
        runtime: &Arc<Runtime>,
        generation: egrio_runtime::RuntimeCoreGeneration,
        source: &ProfileSource,
    ) -> Result<(), String> {
        let _transition = self.begin_user_transition().await;
        let mut host = self.begin_host_transition().await?;
        let snapshot = (self.configuration)()
            .await?
            .filter(|snapshot| {
                !snapshot.awaiting_rule_sets && ProfileSource::of(snapshot) == *source
            })
            .ok_or("the profile changed while its rule sets were downloading")?;
        // The profile's routes follow its traffic mode, which a failed
        // download leaves free to change.
        let spec = runtime_spec_with_profile(runtime.spec(), Some(&snapshot))?;
        runtime.prepare_core(spec).await?;
        let capture_mtu = self.prepared_configuration.get()?.capture_mtu;
        let prepared = Arc::new(PreparedCoreStart::new(snapshot, capture_mtu));
        let profile = prepared.take_profile()?;
        self.prepared_configuration.set(Some(prepared))?;
        host.begin_background_activity(H::begin_activity);
        let activated = runtime.activate_prepared_core(generation, profile).await;
        if !self.capture_active() {
            host.end_background_activity();
        }
        activated.map_err(|error| error.to_string())?;
        if self.capture_layers().tun {
            // The prepared Core dialed its nodes while the tunnel was closed.
            self.renew_unprotected_dials(runtime).await;
        }
        Ok(())
    }

    fn rule_download_ended(
        &self,
        run: u64,
        runtime: &Arc<Runtime>,
        source: ProfileSource,
        outcome: Result<(), DownloadFailure>,
    ) {
        let layers = spec_capture_layers(&runtime.spec());
        {
            let mut download = self.rule_download();
            if !matches!(download.state, RuleDownloadState::Running { run: latest, .. } if latest == run)
            {
                return;
            }
            download.state = match &outcome {
                Err(failure) if runtime.status().state == RuntimeState::Preparing => {
                    RuleDownloadState::Failed {
                        source,
                        error: failure.message().to_owned(),
                    }
                }
                _ => RuleDownloadState::Idle,
            };
        }
        match outcome {
            Ok(()) => {}
            Err(DownloadFailure::Download(error)) => {
                log::error!(target: "rule-providers", "rule-set-download-failed {error}");
                crate::events::notify_rule_set_download_failed(error);
            }
            Err(DownloadFailure::Start(error)) => {
                log::error!(target: "network", "capture-start-after-rule-sets-failed {error}");
                crate::events::notify_capture_start_failed(layers, error);
            }
        }
        crate::events::notify_native_state_changed();
        // The downloads changed the profile's rule providers.
        drop(crate::events::notify_profiles_on_return());
    }
}

enum DownloadFailure {
    /// The rule sets did not arrive through the chosen node.
    Download(String),
    /// They arrived, and the capture they were for did not start.
    Start(String),
}

impl DownloadFailure {
    fn message(&self) -> &str {
        match self {
            Self::Download(message) | Self::Start(message) => message,
        }
    }
}
