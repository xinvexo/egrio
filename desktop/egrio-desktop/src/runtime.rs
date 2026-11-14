//! The desktop's fixed Runtime: one per process, driven by the GUI through
//! capture-layer switches, profile configuration and lifecycle transitions.
//! This module holds what every platform shares; each platform supplies a
//! [`DesktopHost`] with its SDK assembly, Runtime topology and recovery.
use std::fmt;
use std::future::Future;
use std::sync::Arc;

mod host_lifecycle;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod node_probe;
mod rule_preparation;
pub use rule_preparation::CorePreparation;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

use egrio_core::TrafficPolicyMode;
use egrio_platform::{CaptureLayer, CaptureLayers};
use egrio_runtime::{
    CheckpointStore, IpPrefix, Runtime, RuntimeDomainStatus, RuntimeReloadError, RuntimeSpec,
    RuntimeState, RuntimeStopError, SystemProxyEndpoint, SystemProxySpec,
};
use egrio_sdk::FileCheckpointStore;
use host_lifecycle::HostLifecycle;
pub use host_lifecycle::HostTransition;

#[cfg(target_os = "linux")]
pub type PlatformHost = linux::Host;
#[cfg(target_os = "macos")]
pub type PlatformHost = macos::Host;
#[cfg(windows)]
pub type PlatformHost = windows::Host;

/// What a platform supplies to the desktop Runtime: the SDK assembly behind
/// its fixed Runtime topology, recovery of what a previous process left and
/// the bookkeeping of Core egress.
pub trait DesktopHost: Send + Sync + 'static {
    /// Held while a capture layer is active: on macOS, the activity that
    /// keeps App Nap from suspending the process.
    type Activity: Send + 'static;

    fn begin_activity() -> Self::Activity;

    /// Creates the fixed Runtime with no capture layer, once recovery is done.
    fn create_runtime(&self) -> impl Future<Output = Result<Arc<Runtime>, String>> + Send;

    /// The fixed Runtime topology carrying `layers`, once the Runtime exists.
    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String>;

    /// The capture MTU a Core is prepared with while the TUN layer is off.
    fn default_capture_mtu(&self) -> Result<u32, String>;

    /// Whether a Core dial went out without egress protection since the last
    /// call; the TUN layer would capture its connection.
    fn take_unprotected_dials(&self) -> bool {
        false
    }

    /// Restores every unresolved checkpoint. Reads no configuration.
    fn recover_unresolved(&self) -> impl Future<Output = Result<(), String>> + Send;

    /// Prepares the host for its first Runtime once recovery is done.
    fn prepare_after_recovery(&self) -> Result<(), String> {
        Ok(())
    }

    /// The egress of an endpoint probe while no Core runs.
    fn standalone_probe_egress(&self) -> impl Future<Output = Result<ProbeEgress, String>> + Send {
        std::future::ready(Ok((Default::default(), None)))
    }
}

pub type ProbeEgress = (
    egrio_core::NativeCoreEgressConfig,
    Option<Arc<dyn egrio_core::EgressSocketGuard>>,
);

pub struct DesktopRuntime<H: DesktopHost = PlatformHost> {
    host: Arc<H>,
    lifecycle: HostLifecycle<H::Activity>,
    /// The fixed desktop Runtime, created after recovery on first use.
    runtime: Arc<tokio::sync::OnceCell<Arc<Runtime>>>,
    checkpoints: Arc<dyn CheckpointStore>,
    recovery: Arc<tokio::sync::Mutex<RecoveryInitialization>>,
    user_transition: Arc<tokio::sync::Mutex<()>>,
    configuration_admission: Arc<tokio::sync::Semaphore>,
    configuration: Arc<EffectiveConfigurationLoader>,
    /// Downloads a profile's missing rule sets through a Runtime's Core.
    rule_sets: Arc<rule_preparation::RuleSetDownload>,
    rule_download: Arc<std::sync::Mutex<rule_preparation::RuleDownload>>,
    prepared_configuration: Arc<PreparedCoreConfiguration>,
    /// Why TUN mode stopped working on its own while it is being restored, or
    /// after it could not be; `None` otherwise. Not persisted.
    tun_interruption: Arc<std::sync::Mutex<Option<String>>>,
}

type ConfigurationLoad = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Option<crate::configuration::EffectiveConfigSnapshot>, String>,
            > + Send,
    >,
>;
type EffectiveConfigurationLoader = dyn Fn() -> ConfigurationLoad + Send + Sync;

/// GUI-owned preparation slot. The listener, the capture layers' routes and
/// the Core's inputs come from one reading of the active profile; reusable
/// Runtime contracts contain no source state.
#[derive(Debug, Default)]
struct PreparedCoreConfiguration {
    inputs: std::sync::RwLock<Option<Arc<PreparedCoreStart>>>,
}

/// One reading of the active profile, for the Core start that follows it and
/// the generation that start makes. The start takes the profile itself: the
/// Core is compiled from it and nothing reads it again, and with every rule
/// provider's entries and the GEODATA its rules name it is larger than the
/// Core it becomes. What stays answers for the running generation.
#[derive(Debug)]
struct PreparedCoreStart {
    profile_id: String,
    fake_ip_range: egrio_core::dns::config::FakeIpRange,
    network: crate::profile_network_settings::ProfileNetworkConfig,
    capture_mtu: u32,
    profile: std::sync::Mutex<Option<egrio_core::RuntimeProfile>>,
}

impl PreparedCoreStart {
    fn new(snapshot: crate::configuration::EffectiveConfigSnapshot, capture_mtu: u32) -> Self {
        Self {
            profile_id: snapshot.profile.id.clone(),
            fake_ip_range: snapshot.profile.dns.fake_ip_range,
            network: snapshot.network,
            capture_mtu,
            profile: std::sync::Mutex::new(Some(snapshot.profile)),
        }
    }

    /// The profile, once. Another Core start is prepared again, which reads
    /// the profile as it is by then; a start that found this one already
    /// taken would otherwise have run the profile of an earlier preparation.
    fn take_profile(&self) -> Result<egrio_core::RuntimeProfile, String> {
        self.profile
            .lock()
            .map_err(|_| "configuration preparation lock poisoned".to_string())?
            .take()
            .ok_or_else(|| "the prepared configuration already started a Core".into())
    }
}

impl PreparedCoreConfiguration {
    fn set(&self, prepared: Option<Arc<PreparedCoreStart>>) -> Result<(), String> {
        *self
            .inputs
            .write()
            .map_err(|_| "configuration preparation lock poisoned".to_string())? = prepared;
        Ok(())
    }

    fn get(&self) -> Result<Arc<PreparedCoreStart>, String> {
        self.inputs
            .read()
            .map_err(|_| "configuration preparation lock poisoned".to_string())?
            .clone()
            .ok_or_else(|| "no configuration was prepared for this Core start".into())
    }
}

/// The Core start inputs every platform shares; its host adds the capture
/// configuration, the egress socket guard and the flow scanner.
fn core_start_inputs(
    configuration: &PreparedCoreConfiguration,
    capture: egrio_core::NativeCoreCaptureConfig,
    egress_socket_guard: Arc<dyn egrio_core::EgressSocketGuard>,
    flow_scanner: Arc<dyn egrio_core::FlowScanner>,
) -> Result<egrio_core::CoreStartInputs, String> {
    // A client can hold a fake IP across a Core restart; the next Core
    // sends it to the same name.
    let fake_ip_mappings = crate::app_paths::app_data_dir()?.join("fake-ip-mappings");
    Ok(egrio_core::CoreStartInputs {
        egress_socket_guard: Some(egress_socket_guard),
        flow_scanner: Some(flow_scanner),
        fake_ip_mappings: Some(fake_ip_mappings),
        ..prepared_core_inputs(configuration, capture)?
    })
}

/// What the preparation gives the Core start it was made for: the profile,
/// its IPv6 posture and the capture MTU. The profile is taken last, so a
/// start refused before it leaves the preparation whole.
fn prepared_core_inputs(
    configuration: &PreparedCoreConfiguration,
    capture: egrio_core::NativeCoreCaptureConfig,
) -> Result<egrio_core::CoreStartInputs, String> {
    let prepared = configuration.get()?;
    let capture = capture.with_mtu(prepared.capture_mtu)?;
    Ok(egrio_core::CoreStartInputs {
        capture,
        profile: prepared.take_profile()?,
        egress: egrio_core::NativeCoreEgressConfig {
            ipv6_enabled: prepared.network.ipv6,
            ..Default::default()
        },
        egress_socket_guard: None,
        flow_scanner: None,
        fake_ip_mappings: None,
    })
}

#[derive(Debug, Default)]
struct RecoveryInitialization {
    runtime_recovered: bool,
    recovered_count: usize,
    complete: bool,
}

/// The active profile for a Core start: complete, with the GEODATA its rules
/// name, or still awaiting rule sets, which the Core prepared from it
/// downloads before its listeners open. Missing GEODATA does not hold the
/// start: it is downloaded in the background and the profile restarts with it.
fn load_active_configuration() -> ConfigurationLoad {
    Box::pin(async {
        let store =
            crate::profile_store::ProfileStore::open().map_err(|error| error.to_string())?;
        let mut snapshot = store
            .active_start_snapshot()
            .map_err(|error| error.to_string())?
            .ok_or("no active profile: apply a profile first")?;
        if !snapshot.awaiting_rule_sets {
            snapshot.profile.geodata = crate::geodata::content_for(&snapshot.profile);
            crate::geodata::fetch_missing_in_background(&snapshot.profile);
        }
        Ok(Some(snapshot))
    })
}

/// What a Core start on a spec takes from the active profile.
struct CoreStart {
    /// The spec with the profile's listener and routes.
    spec: RuntimeSpec,
    /// The profile's source while its rule sets are still to download: the
    /// Core is prepared from it and opens to traffic once they arrive.
    awaiting_rule_sets: Option<rule_preparation::ProfileSource>,
}

static PROCESS_RUNTIME: std::sync::OnceLock<DesktopRuntime> = std::sync::OnceLock::new();

/// The process's Runtime host, once [`DesktopRuntime::new`] made it; work that
/// outlives the operation that started it (a background GEODATA download)
/// reaches the running profile through it.
pub fn process_runtime() -> Option<DesktopRuntime> {
    PROCESS_RUNTIME.get().cloned()
}

impl DesktopRuntime {
    /// The process's one Runtime host; a second call fails.
    pub fn new() -> Result<Self, String> {
        let checkpoint_directory = crate::app_paths::app_data_dir()?.join("runtime-checkpoints");
        let runtime = Self::with_checkpoint_directory(checkpoint_directory)?;
        PROCESS_RUNTIME
            .set(runtime.clone())
            .map_err(|_| "the desktop Runtime host already exists".to_string())?;
        Ok(runtime)
    }

    fn with_checkpoint_directory(checkpoint_directory: std::path::PathBuf) -> Result<Self, String> {
        let checkpoints = FileCheckpointStore::new(checkpoint_directory);
        // Startup restores what the records describe before anything else and
        // ends the app when it cannot. A record no build can decode would end
        // every start from here on, with nothing in the app to clear it, and
        // it restores nothing either way. So the app runs without it, and
        // the session it recorded stays unrestored, which the log says.
        for path in checkpoints
            .set_aside_unreadable()
            .map_err(|error| format!("read the Runtime checkpoints: {error}"))?
        {
            log::error!(
                "a Runtime checkpoint could not be read, so the session it recorded is not \
                 restored; it was set aside as {}",
                path.display()
            );
        }
        let checkpoints: Arc<dyn CheckpointStore> = Arc::new(checkpoints);
        let prepared_configuration = Arc::new(PreparedCoreConfiguration::default());
        let host = PlatformHost::new(&checkpoints, &prepared_configuration)?;
        Ok(Self::with_host(
            host,
            checkpoints,
            prepared_configuration,
            Arc::new(load_active_configuration),
        ))
    }
}

impl<H: DesktopHost> DesktopRuntime<H> {
    fn with_host(
        host: H,
        checkpoints: Arc<dyn CheckpointStore>,
        prepared_configuration: Arc<PreparedCoreConfiguration>,
        configuration: Arc<EffectiveConfigurationLoader>,
    ) -> Self {
        Self {
            host: Arc::new(host),
            lifecycle: HostLifecycle::default(),
            runtime: Arc::default(),
            checkpoints,
            recovery: Arc::default(),
            user_transition: Arc::new(tokio::sync::Mutex::new(())),
            configuration_admission: Arc::new(tokio::sync::Semaphore::new(16)),
            configuration,
            rule_sets: Arc::new(|profile_id, runtime| {
                Box::pin(crate::rule_provider_fetch::prepare_via_core(
                    profile_id, runtime,
                ))
            }),
            rule_download: Arc::default(),
            prepared_configuration,
            tun_interruption: Arc::default(),
        }
    }

    /// Why TUN mode stopped working on its own, while it is being restored
    /// or after it could not be.
    pub fn tun_interruption(&self) -> Option<String> {
        self.tun_interruption
            .lock()
            .expect("TUN interruption mutex")
            .clone()
    }

    fn set_tun_interruption(&self, interruption: Option<String>) {
        *self
            .tun_interruption
            .lock()
            .expect("TUN interruption mutex") = interruption;
    }

    /// Restores TUN mode whenever the desktop Runtime loses its platform
    /// session (the Windows service stopped or crashed). Installed once, when
    /// the Runtime is created.
    fn watch_session_loss(&self, runtime: &Arc<Runtime>) {
        let mut losses = runtime.subscribe_session_loss();
        let sdk = self.clone();
        crate::async_runtime::spawn(async move {
            while losses.changed().await.is_ok() {
                sdk.recover_lost_session().await;
            }
        });
    }

    /// Readies the TUN environment and re-applies the committed layers until
    /// TUN is back, a few times with growing pauses. The degraded Runtime
    /// recovers in place, so the system proxy and the Core keep serving
    /// throughout; a user switch in the meantime ends the attempts.
    async fn recover_lost_session(&self) {
        const RETRY_DELAYS: [std::time::Duration; 4] = [
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(15),
        ];
        let reason = "the TUN mode platform session ended".to_string();
        log::warn!(target: "network", "tun-session-lost {reason}");
        self.set_tun_interruption(Some(reason.clone()));
        crate::events::notify_tun_session(crate::events::TunSessionNotice::Interrupted, reason);
        crate::events::notify_native_state_changed();
        let mut failure = String::new();
        for delay in RETRY_DELAYS {
            tokio::time::sleep(delay).await;
            let _transition = self.begin_user_transition().await;
            let Some(runtime) = self.existing_desktop_runtime() else {
                return;
            };
            if runtime.status().state != RuntimeState::Degraded {
                // A user switch already recovered or replaced the layers.
                self.set_tun_interruption(None);
                crate::events::notify_native_state_changed();
                return;
            }
            match crate::tun_environment::ensure().await {
                crate::tun_environment::TunEnvironment::Ready => {}
                crate::tun_environment::TunEnvironment::Blocked { error } => {
                    failure = error;
                    continue;
                }
                crate::tun_environment::TunEnvironment::ApprovalRequired => {
                    failure = "the Egrio service awaits approval in Login Items".into();
                    continue;
                }
            }
            match self.apply_capture_layers(self.capture_layers()).await {
                Ok(()) => {
                    log::info!(target: "network", "tun-session-recovered");
                    self.set_tun_interruption(None);
                    crate::events::notify_tun_session(
                        crate::events::TunSessionNotice::Recovered,
                        "TUN mode is restored".into(),
                    );
                    crate::events::notify_native_state_changed();
                    return;
                }
                Err(error) => failure = error,
            }
        }
        log::warn!(target: "network", "tun-session-recovery-failed {failure}");
        self.set_tun_interruption(Some(format!("TUN mode could not be restored: {failure}")));
        crate::events::notify_tun_session(crate::events::TunSessionNotice::Failed, failure);
        crate::events::notify_native_state_changed();
    }

    pub async fn begin_user_transition(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.user_transition.clone().lock_owned().await
    }

    /// Admits a host mutation; a host that is shutting down rejects it
    /// before any configuration or OS work.
    pub async fn begin_host_transition(&self) -> Result<HostTransition<H::Activity>, String> {
        self.lifecycle.admit().await
    }

    /// Reads the active profile for a Core start on `spec` and keeps it for
    /// that start. A running Core first downloads the rule sets the profile
    /// still lacks, so the restart that follows finds them.
    async fn core_start_spec(&self, spec: RuntimeSpec) -> Result<CoreStart, String> {
        if spec.core.is_none() {
            return Ok(CoreStart {
                spec,
                awaiting_rule_sets: None,
            });
        }
        let capture_mtu = match spec.platform.packet_capture.as_ref() {
            Some(capture) => capture.mtu,
            None => self.host.default_capture_mtu()?,
        };
        egrio_core::NativeCoreCaptureConfig::default().with_mtu(capture_mtu)?;
        let mut snapshot = (self.configuration)().await?;
        let awaiting = snapshot
            .as_ref()
            .filter(|snapshot| snapshot.awaiting_rule_sets);
        let running = self
            .existing_desktop_runtime()
            .filter(|runtime| runtime.status().state == RuntimeState::Running);
        if let (Some(awaiting), Some(runtime)) = (awaiting, running) {
            (self.rule_sets)(awaiting.profile.id.clone(), runtime).await?;
            snapshot = (self.configuration)().await?;
        }
        let spec = runtime_spec_with_profile(spec, snapshot.as_ref())?;
        let awaiting_rule_sets = snapshot
            .as_ref()
            .filter(|snapshot| snapshot.awaiting_rule_sets)
            .map(rule_preparation::ProfileSource::of);
        self.prepared_configuration.set(
            snapshot.map(|snapshot| Arc::new(PreparedCoreStart::new(snapshot, capture_mtu))),
        )?;
        Ok(CoreStart {
            spec,
            awaiting_rule_sets,
        })
    }

    /// Starts a stopped or preparing Runtime on `spec` with the active
    /// profile.
    async fn start_runtime(
        &self,
        runtime: &Arc<Runtime>,
        spec: RuntimeSpec,
    ) -> Result<LayerSwitch, String> {
        let start = self.core_start_spec(spec).await?;
        self.begin_core_start(runtime, start).await
    }

    /// Starts the Runtime at once with a complete profile. One whose rule
    /// sets are still to download gets a prepared Core instead, which
    /// downloads them and only then opens to traffic. A Core prepared from
    /// another source, or no longer needed, is stopped first: it never
    /// serves a profile it was not made from.
    async fn begin_core_start(
        &self,
        runtime: &Arc<Runtime>,
        start: CoreStart,
    ) -> Result<LayerSwitch, String> {
        let prepared = runtime.status().state == RuntimeState::Preparing;
        let kept = start
            .awaiting_rule_sets
            .as_ref()
            .is_some_and(|source| self.rule_download_serves(source));
        if prepared && !kept {
            self.cancel_rule_download();
            runtime.stop().await.map_err(|error| error.to_string())?;
        }
        let Some(source) = start.awaiting_rule_sets else {
            runtime
                .start_with_spec(start.spec)
                .await
                .map_err(|error| error.to_string())?;
            return Ok(LayerSwitch::Started);
        };
        let generation = runtime.prepare_core(start.spec).await?;
        self.download_rule_sets(runtime.clone(), generation, source);
        Ok(LayerSwitch::Preparing)
    }

    /// The host's spec for `layers`, keeping the running Core's excluded
    /// destinations outside the TUN and its fake-IP pool inside.
    fn runtime_spec(&self, layers: CaptureLayers) -> Result<RuntimeSpec, String> {
        let spec = self.host.runtime_spec(layers)?;
        let Ok(prepared) = self.prepared_configuration.get() else {
            return Ok(spec);
        };
        let excluded = self
            .effective_core_policy()
            .map(|policy| route_exclusions(&prepared.network, policy.traffic_policy_mode))
            .unwrap_or_default();
        Ok(with_fake_ip_pool(
            with_route_exclusions(spec, excluded),
            prepared.fake_ip_range,
        ))
    }

    /// Reloads a running TUN layer whose exclusions differ from those of the
    /// running Core's profile in `mode`.
    async fn reload_route_exclusions(
        &self,
        runtime: &Arc<Runtime>,
        mode: TrafficPolicyMode,
    ) -> Result<(), String> {
        if runtime.status().state != RuntimeState::Running {
            return Ok(());
        }
        let Ok(prepared) = self.prepared_configuration.get() else {
            return Ok(());
        };
        let current = runtime.spec();
        let next =
            with_route_exclusions(current.clone(), route_exclusions(&prepared.network, mode));
        if next == current {
            return Ok(());
        }
        runtime
            .reload(next)
            .await
            .map(drop)
            .map_err(|error| format!("update the destinations kept outside the TUN: {error}"))
    }

    pub(crate) fn existing_desktop_runtime(&self) -> Option<Arc<Runtime>> {
        self.runtime.get().cloned()
    }

    async fn desktop_runtime(&self) -> Result<Arc<Runtime>, String> {
        self.initialize().await?;
        self.runtime
            .get_or_try_init(|| async {
                let runtime = self.host.create_runtime().await?;
                self.watch_session_loss(&runtime);
                Ok(runtime)
            })
            .await
            .cloned()
    }

    fn domain_status(&self) -> Option<RuntimeDomainStatus> {
        self.existing_desktop_runtime()
            .map(|runtime| runtime.domain_status())
    }

    /// The capture layers the committed Runtime spec carries, none while the
    /// Runtime is stopped. The spec is the only record of which layers are on.
    pub fn capture_layers(&self) -> CaptureLayers {
        self.domain_status()
            .filter(|status| {
                !matches!(
                    status.runtime.state,
                    RuntimeState::Created | RuntimeState::Preparing | RuntimeState::Stopped
                )
            })
            .map_or(CaptureLayers::NONE, |status| {
                spec_capture_layers(&status.spec)
            })
    }

    pub fn core_status(&self) -> Option<egrio_core::NativeCoreStatus> {
        self.existing_desktop_runtime()
            .map(|runtime| runtime.core_status())
    }

    /// The running Core's traffic volume; `None` while no Core runs.
    pub fn traffic_volume(&self) -> Option<egrio_core::TrafficVolume> {
        let runtime = self.existing_desktop_runtime()?;
        if runtime.status().state != RuntimeState::Running {
            return None;
        }
        runtime.core_traffic_volume()
    }

    /// The running Core's telemetry with only the terminal records `cursor`
    /// has not seen, and the cursor for the next poll.
    pub async fn traffic_telemetry_since(
        &self,
        cursor: egrio_runtime::TelemetryCursor,
    ) -> Option<(
        egrio_core::TrafficTelemetrySnapshot,
        egrio_runtime::TelemetryCursor,
    )> {
        let runtime = self.existing_desktop_runtime()?;
        if runtime.status().state != RuntimeState::Running {
            return None;
        }
        Some(runtime.core_traffic_telemetry_since(cursor).await)
    }

    /// The profile the running Core serves.
    pub fn running_profile_id(&self) -> Option<String> {
        let runtime = self.existing_desktop_runtime()?;
        if !matches!(
            runtime.status().state,
            RuntimeState::Preparing | RuntimeState::Running
        ) {
            return None;
        }
        let prepared = self.prepared_configuration.get().ok()?;
        Some(prepared.profile_id.clone())
    }

    pub async fn evaluate_core_route(
        &self,
        input: &egrio_core::RouteMatchInput,
    ) -> Result<Option<egrio_core::RouteEvaluation>, String> {
        let Some(runtime) = self.existing_desktop_runtime() else {
            return Ok(None);
        };
        runtime.evaluate_core_route(input).await
    }

    pub fn effective_core_policy(&self) -> Option<egrio_core::CorePolicyState> {
        self.existing_desktop_runtime()
            .and_then(|runtime| runtime.effective_core_policy())
    }

    pub fn effective_listener(&self) -> Option<std::net::SocketAddr> {
        self.existing_desktop_runtime()
            .and_then(|runtime| runtime.domain_status().core)
            .and_then(|core| core.listen_addr)
            .and_then(|address| address.parse().ok())
    }

    /// Holds product/lifecycle serialization in an owned task. Closing the
    /// invoking window cannot drop a persisted-but-unapplied operation.
    pub(crate) async fn configure_profile(
        &self,
        profile_id: String,
        intent: crate::profile_configuration::ProfileConfigurationIntent,
    ) -> Result<crate::profile_configuration::ProfileConfigurationUpdateReport, String> {
        let permit = self
            .configuration_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| "configuration request queue is full".to_string())?;
        let sdk = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _transition = sdk.begin_user_transition().await;
            let _host = sdk.begin_host_transition().await?;
            let _notify = crate::events::notify_profiles_on_return();
            let store = crate::profile_store::ProfileStore::open().map_err(|e| e.to_string())?;
            let active = store.active_profile().map_err(|e| e.to_string())?.is_some_and(|profile| profile.id == profile_id);
            let prepared = crate::profile_configuration::prepare(store, profile_id.clone(), intent)?;
            if !active {
                (prepared.persist)()?;
                return Ok(crate::profile_configuration::ProfileConfigurationUpdateReport::saved(true));
            }
            let Some(runtime) = sdk.existing_desktop_runtime() else {
                (prepared.persist)()?;
                return Ok(crate::profile_configuration::ProfileConfigurationUpdateReport::saved(false));
            };
            if sdk.rule_download_running() {
                return Err("rule sets are downloading through the chosen node; it cannot change until they arrive".into());
            }
            if let Some(policy) = runtime.effective_core_policy() {
                if policy.profile_id != profile_id {
                    return Err("running Core belongs to another profile; wait for the configuration switch".into());
                }
            }
            // In global mode every connection goes through the Core: excluded
            // destinations re-enter the TUN before the Core switches to it and
            // leave it again only once the Core has left it.
            let mode = match &prepared.change {
                egrio_runtime::RuntimeConfigurationChange::Policy(
                    egrio_core::CorePolicyUpdate::TrafficPolicy { mode, .. },
                ) => Some(*mode),
                _ => None,
            };
            if mode == Some(TrafficPolicyMode::Global) {
                sdk.reload_route_exclusions(&runtime, TrafficPolicyMode::Global).await?;
            }
            let mut events = runtime.configuration_events();
            let mut report = runtime.configure(prepared.change, prepared.persist).await;
            if report.phase.is_applied() {
                // The node a failed rule set download went through changed.
                sdk.retry_rule_download(&runtime);
            }
            if let (Some(_), Some(policy)) = (mode, runtime.effective_core_policy()) {
                if let Err(error) = sdk.reload_route_exclusions(&runtime, policy.traffic_policy_mode).await {
                    log::warn!(target: "network", "tun-exclusions-not-updated {error}");
                    report.phase = egrio_runtime::ConfigurationPhase::PendingApply;
                    report.error = Some(error);
                }
            }
            crate::events::notify_native_state_changed();
            if report.phase == egrio_runtime::ConfigurationPhase::AppliedCleanupPending {
                let operation_id = report.operation_id.clone();
                tokio::spawn(async move {
                    loop {
                        let observed = events.borrow_and_update().clone();
                        if let Some(observed) = observed {
                            if observed.operation_id != operation_id { break; }
                            if observed.phase != egrio_runtime::ConfigurationPhase::AppliedCleanupPending {
                                drop(crate::events::notify_profiles_on_return());
                                crate::events::notify_native_state_changed();
                                break;
                            }
                        }
                        if events.changed().await.is_err() { break; }
                    }
                });
            }
            Ok(crate::profile_configuration::ProfileConfigurationUpdateReport::from_runtime(report))
        }).await.map_err(|error| format!("configuration operation failed: {error}"))?
    }

    /// Whole-profile changes use the same product serialization as local intents.
    /// The update validates and durably saves a target; Runtime owns stop/start.
    pub async fn configure_profile_document(
        &self,
        profile_id: String,
        update: impl FnOnce(&crate::profile_store::ProfileStore) -> Result<(), String> + Send + 'static,
    ) -> Result<crate::profile_configuration::ProfileConfigurationUpdateReport, String> {
        let permit = self
            .configuration_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| "configuration request queue is full".to_string())?;
        let sdk = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _transition = sdk.begin_user_transition().await;
            let mut host = sdk.begin_host_transition().await?;
            let _notify = crate::events::notify_profiles_on_return();
            let store = crate::profile_store::ProfileStore::open().map_err(|e| e.to_string())?;
            let active = store
                .active_profile()
                .map_err(|e| e.to_string())?
                .is_some_and(|profile| profile.id == profile_id);
            update(&store)?;
            if !active {
                return Ok(
                    crate::profile_configuration::ProfileConfigurationUpdateReport::saved(true),
                );
            }
            use crate::profile_configuration::{
                ProfileConfigurationPhase, ProfileConfigurationUpdateReport,
            };
            let result = sdk.restart_running_runtime_locked(&mut host).await;
            crate::events::notify_native_state_changed();
            Ok(match result {
                Ok(false) => ProfileConfigurationUpdateReport::saved(false),
                Ok(true) if sdk.core_preparation().is_some() => ProfileConfigurationUpdateReport {
                    operation_id: None,
                    phase: ProfileConfigurationPhase::PendingApply,
                    applied: false,
                    generation: None,
                    error: None,
                },
                Ok(true) => ProfileConfigurationUpdateReport {
                    operation_id: None,
                    phase: ProfileConfigurationPhase::Applied,
                    applied: true,
                    generation: None,
                    error: None,
                },
                Err(error) => ProfileConfigurationUpdateReport {
                    operation_id: None,
                    phase: ProfileConfigurationPhase::PendingApply,
                    applied: false,
                    generation: None,
                    error: Some(error),
                },
            })
        })
        .await
        .map_err(|error| format!("configuration operation failed: {error}"))?
    }

    /// The one path every desktop platform switches its capture layers
    /// through; see [`switch_capture_layers`].
    pub async fn apply_capture_layers(&self, target: CaptureLayers) -> Result<(), String> {
        let mut host = self.begin_host_transition().await?;
        let runtime = self.desktop_runtime().await?;
        if target.any() {
            // Held before Core or capture changes so a switch never opens an
            // App Nap window.
            host.begin_background_activity(H::begin_activity);
        } else {
            self.cancel_rule_download();
        }
        let switched = switch_capture_layers(
            &runtime,
            target,
            |layers| self.runtime_spec(layers),
            |spec| self.start_runtime(&runtime, spec),
        )
        .await;
        match switched {
            // The Core that carries TUN now dialed before it opened.
            Ok(LayerSwitch::Reloaded) if target.tun => {
                self.renew_unprotected_dials(&runtime).await;
            }
            // A new Core has no such connection; those of the Core before
            // it are gone with it.
            Ok(LayerSwitch::Started) if target.tun => drop(self.host.take_unprotected_dials()),
            _ => {}
        }
        if !self.capture_active() {
            host.end_background_activity();
        }
        if switched.is_ok() {
            self.set_tun_interruption(None);
        }
        crate::events::notify_native_state_changed();
        switched.map(drop)
    }

    /// Ends the Core connections dialed without egress protection, so they
    /// dial again protected. The TUN that just opened would capture them: on
    /// macOS one left unbound while the tunnel was closed (XNU routes it by
    /// destination), on Linux one the service could not mark.
    async fn renew_unprotected_dials(&self, runtime: &Arc<Runtime>) {
        if !self.host.take_unprotected_dials() {
            return;
        }
        if let Err(error) = runtime.cutover_core_sessions().await {
            log::warn!(target: "network", "renew unprotected Core connections after enabling TUN: {error}");
        }
    }

    /// Whether the Runtime holds a capture layer.
    fn capture_active(&self) -> bool {
        self.domain_status().is_some_and(|status| {
            !matches!(
                status.runtime.state,
                RuntimeState::Created | RuntimeState::Preparing | RuntimeState::Stopped
            ) && spec_capture_layers(&status.spec).any()
        })
    }

    /// Replaces the running Core generation with the active profile's
    /// current configuration on the same capture layers. Returns `false`
    /// when no Runtime is running.
    pub async fn restart_running_runtime(&self) -> Result<bool, String> {
        let mut host = self.begin_host_transition().await?;
        self.restart_running_runtime_locked(&mut host).await
    }

    async fn restart_running_runtime_locked(
        &self,
        host: &mut HostTransition<H::Activity>,
    ) -> Result<bool, String> {
        self.lifecycle.validate(host)?;
        let Some(runtime) = self.existing_desktop_runtime() else {
            return Ok(false);
        };
        if runtime.status().state == RuntimeState::Preparing {
            // Nothing is captured yet: the waiting start takes the profile
            // as it is now.
            host.begin_background_activity(H::begin_activity);
            let started = self.start_runtime(&runtime, runtime.spec()).await;
            if !self.capture_active() {
                host.end_background_activity();
            }
            return started.map(|_| true);
        }
        if !runtime_core_update_available(&runtime)? {
            return Ok(false);
        }
        let spec = runtime.spec();
        // Resolve and fetch required source dependencies while the existing
        // network is still usable. A preparation failure does not stop it.
        let start = self.core_start_spec(spec.clone()).await?;
        self.stop_user_runtime_locked(host).await?;
        if spec_capture_layers(&spec).any() {
            host.begin_background_activity(H::begin_activity);
        }
        let started = self.begin_core_start(&runtime, start).await;
        crate::events::notify_native_state_changed();
        match started {
            Ok(_) => Ok(true),
            Err(error) => {
                let cleanup = self.stop_user_runtime_locked(host).await;
                Err(match cleanup {
                    Ok(()) => format!("{error}; the requested configuration is stopped"),
                    Err(recovery) => format!("{error}; network recovery is incomplete: {recovery}"),
                })
            }
        }
    }

    /// Closes all user connections and OS flows before restoring capture resources.
    pub async fn stop_user_runtime(&self) -> Result<(), String> {
        let mut host = self.lifecycle.lock().await;
        self.stop_user_runtime_locked(&mut host).await
    }

    async fn stop_user_runtime_locked(
        &self,
        host: &mut HostTransition<H::Activity>,
    ) -> Result<(), String> {
        self.cancel_rule_download();
        let runtime = self.existing_desktop_runtime();
        let stopped = if let Some(runtime) = runtime.as_ref() {
            let quiesced = runtime.quiesce_core().await;
            match runtime.stop().await {
                Ok(report) => quiesced.map_err(|message| RuntimeStopError::Cleanup {
                    message: format!("Core was closed but its connection drain was not verified: {message}"),
                    capabilities_restored: report.restored,
                }),
                Err(error) => Err(match quiesced {
                    Ok(()) => error,
                    Err(message) => RuntimeStopError::Cleanup {
                        message: format!("Core connection drain failed: {message}; Runtime cleanup failed: {error}"),
                        capabilities_restored: error.capabilities_restored(),
                    },
                }),
            }
        } else {
            Ok(())
        };
        // The activity protects live OS resources; verified-restored
        // capabilities release it even when checkpoint cleanup failed.
        if stopped
            .as_ref()
            .map_or_else(RuntimeStopError::capabilities_restored, |_| true)
            || !self.capture_active()
        {
            host.end_background_activity();
        }
        crate::events::notify_native_state_changed();
        stopped.map_err(|error| error.to_string())?;
        if runtime.is_none()
            && !self
                .checkpoints
                .list_unresolved()
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
        {
            return Err(
                "Core is stopped but unresolved Runtime checkpoints still require recovery".into(),
            );
        }
        Ok(())
    }

    // This phase intentionally has no ProfileStore dependency: it restores
    // the network before anything reads or fetches configuration.
    pub async fn recover_platform_before_configuration(&self) -> Result<usize, String> {
        let mut recovery = self.recovery.lock().await;
        if recovery.runtime_recovered {
            return Ok(0);
        }
        let unresolved = self
            .checkpoints
            .list_unresolved()
            .await
            .map_err(|error| error.to_string())?
            .len();
        if unresolved > 0 {
            if let Err(error) = self.host.recover_unresolved().await {
                // Count what this attempt did restore, so the retry that
                // succeeds reports it too.
                let remaining = self
                    .checkpoints
                    .list_unresolved()
                    .await
                    .map_err(|evidence| {
                        format!("{error}; determine partially recovered checkpoints: {evidence}")
                    })?;
                recovery.recovered_count += unresolved.saturating_sub(remaining.len());
                return Err(error);
            }
            recovery.recovered_count += unresolved;
        }
        recovery.runtime_recovered = true;
        Ok(recovery.recovered_count)
    }

    /// Restores checkpoints a previous process left behind, then prepares
    /// the host for its first Runtime. Never starts capture.
    pub async fn initialize(&self) -> Result<usize, String> {
        self.recover_platform_before_configuration().await?;
        let mut recovery = self.recovery.lock().await;
        if recovery.complete {
            return Ok(0);
        }
        self.host.prepare_after_recovery()?;
        if recovery.recovered_count > 0 {
            crate::events::notify_native_state_changed();
        }
        recovery.complete = true;
        Ok(recovery.recovered_count)
    }

    /// Stops the Runtime for application exit and closes admission, so no
    /// later transition can start capture again.
    pub async fn shutdown(&self) -> Result<(), String> {
        let mut host = self.lifecycle.shutdown().await;
        self.cancel_rule_download();
        self.initialize().await?;
        let stopped = match self.existing_desktop_runtime() {
            Some(runtime)
                if !matches!(
                    runtime.status().state,
                    RuntimeState::Created | RuntimeState::Stopped
                ) =>
            {
                runtime
                    .stop()
                    .await
                    .map(drop)
                    .map_err(|error| error.to_string())
            }
            _ => Ok(()),
        };
        // A failed restore keeps the activity for the retry to release.
        if stopped.is_ok() {
            host.end_background_activity();
        }
        stopped
    }
}

fn spec_capture_layers(spec: &RuntimeSpec) -> CaptureLayers {
    CaptureLayers {
        system_proxy: spec.platform.system_proxy.is_some(),
        tun: spec.platform.packet_capture.is_some(),
    }
}

/// What switching the capture layers did to the Runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerSwitch {
    Unchanged,
    Started,
    /// The running Core generation now carries the target layers.
    Reloaded,
    /// The layers turn on once the profile's rule sets are downloaded.
    Preparing,
    Stopped,
}

/// Starts, reloads or stops `runtime` so its committed spec carries exactly
/// `target`; `start` starts a Runtime that is not running on a spec. A
/// running Runtime reloads: the Core generation, listener, DNS
/// cache, fake-IP pool and the unchanged layer's OS resources stay, and the
/// Runtime compensates a failed reload back to the committed layers. A
/// Degraded Runtime is first brought back to a committed state.
async fn switch_capture_layers<Start, Started>(
    runtime: &Arc<Runtime>,
    target: CaptureLayers,
    spec_for: impl Fn(CaptureLayers) -> Result<RuntimeSpec, String>,
    start: Start,
) -> Result<LayerSwitch, String>
where
    Start: FnOnce(RuntimeSpec) -> Started,
    Started: Future<Output = Result<LayerSwitch, String>>,
{
    let recovered = runtime.status().state == RuntimeState::Degraded;
    if recovered {
        recover_degraded_runtime(runtime, &spec_for).await?;
    }
    match runtime.status().state {
        RuntimeState::Preparing if !target.any() => {
            runtime.stop().await.map_err(|error| error.to_string())?;
            Ok(LayerSwitch::Stopped)
        }
        RuntimeState::Created | RuntimeState::Stopped if !target.any() => Ok(if recovered {
            LayerSwitch::Stopped
        } else {
            LayerSwitch::Unchanged
        }),
        RuntimeState::Created | RuntimeState::Stopped | RuntimeState::Preparing => {
            start(spec_for(target)?).await
        }
        RuntimeState::Running if !target.any() => {
            runtime.stop().await.map_err(|error| error.to_string())?;
            Ok(LayerSwitch::Stopped)
        }
        RuntimeState::Running => {
            let current = runtime.spec();
            if spec_capture_layers(&current) == target {
                return Ok(if recovered {
                    LayerSwitch::Reloaded
                } else {
                    LayerSwitch::Unchanged
                });
            }
            let next = runtime_spec_retaining_core_listener(spec_for(target)?, &current);
            runtime
                .reload(next)
                .await
                .map_err(|error| error.to_string())?;
            Ok(LayerSwitch::Reloaded)
        }
        state => Err(format!(
            "capture layers cannot change while the Runtime is {state:?}"
        )),
    }
}

/// `spec` with the profile's listener, the destinations its TUN mode keeps
/// outside the tunnel in the profile's traffic mode and its fake-IP pool.
fn runtime_spec_with_profile(
    mut spec: RuntimeSpec,
    snapshot: Option<&crate::configuration::EffectiveConfigSnapshot>,
) -> Result<RuntimeSpec, String> {
    if let Some(core) = spec.core.as_mut() {
        core.listen_addr = snapshot
            .map(|snapshot| snapshot.network.listen_addr())
            .transpose()?;
    }
    let excluded = snapshot
        .map(|snapshot| route_exclusions(&snapshot.network, snapshot.profile.traffic_policy_mode))
        .unwrap_or_default();
    let spec = with_route_exclusions(spec, excluded);
    Ok(match snapshot {
        Some(snapshot) => with_fake_ip_pool(spec, snapshot.profile.dns.fake_ip_range),
        None => spec,
    })
}

/// The destinations TUN mode leaves to the system routes: the profile's
/// `tun.route-exclude-address`, except in global mode, where every
/// connection goes through the Core.
fn route_exclusions(
    network: &crate::profile_network_settings::ProfileNetworkConfig,
    mode: TrafficPolicyMode,
) -> Vec<IpPrefix> {
    if mode == TrafficPolicyMode::Global {
        return Vec::new();
    }
    network.tun.route_exclude_address.clone()
}

/// Puts `excluded` on the capability that installs the default route, a
/// separate Route capability or a capture that routes itself, and lets the
/// kill switch through to the same destinations.
fn with_route_exclusions(mut spec: RuntimeSpec, excluded: Vec<IpPrefix>) -> RuntimeSpec {
    let platform = &mut spec.platform;
    if let Some(route) = platform.route.as_mut().filter(|route| route.default_route) {
        if let Some(firewall) = platform.firewall.as_mut() {
            firewall.excluded_prefixes = excluded.clone();
        }
        route.excluded_prefixes = excluded;
    } else if let Some(capture) = platform
        .packet_capture
        .as_mut()
        .filter(|capture| capture.install_default_route)
    {
        capture.excluded_prefixes = excluded;
    }
    spec
}

/// Keeps the profile's fake-IP pool and its IPv6 projection, addresses only
/// the Core answers, inside the tunnel: the kill switch does where there is
/// one, else the capture itself (macOS rejects them on the physical
/// interfaces).
fn with_fake_ip_pool(
    mut spec: RuntimeSpec,
    range: egrio_core::dns::config::FakeIpRange,
) -> RuntimeSpec {
    let pool = IpPrefix::fake_ip_pool(range);
    if let Some(firewall) = spec.platform.firewall.as_mut() {
        firewall.fake_ip_prefixes = pool;
    } else if let Some(capture) = spec.platform.packet_capture.as_mut() {
        capture.fake_ip_prefixes = pool;
    }
    spec
}

/// Brings a Degraded Runtime back to a committed state. After a lost
/// platform session it recovers in place: a reload to its layers without TUN
/// restores what lived in that session and keeps the system proxy and the
/// Core. Any other degradation no longer matches its spec and is stopped. A
/// failed in-place recovery keeps the Runtime degraded for the next attempt.
async fn recover_degraded_runtime(
    runtime: &Arc<Runtime>,
    spec_for: &impl Fn(CaptureLayers) -> Result<RuntimeSpec, String>,
) -> Result<(), String> {
    let current = runtime.spec();
    let kept = spec_capture_layers(&current).with(CaptureLayer::Tun, false);
    let kept_spec = runtime_spec_retaining_core_listener(spec_for(kept)?, &current);
    match runtime.reload(kept_spec).await {
        Ok(_) => Ok(()),
        Err(RuntimeReloadError::UnsupportedSpec(_)) => runtime
            .stop()
            .await
            .map(drop)
            .map_err(|error| format!("recover the degraded Runtime: {error}")),
        Err(error) => Err(format!("recover the degraded Runtime: {error}")),
    }
}

fn runtime_spec_retaining_core_listener(
    mut next: RuntimeSpec,
    current: &RuntimeSpec,
) -> RuntimeSpec {
    // Layer changes retain the running Core. Listener changes need stop/start.
    if next.core.is_some() && current.core.is_some() {
        next.core = current.core.clone();
    }
    next
}

/// The system-proxy layer: HTTP and HTTPS point at the Core listener.
fn core_listener_system_proxy_spec() -> SystemProxySpec {
    SystemProxySpec {
        http_proxy: Some(SystemProxyEndpoint::CoreListener),
        https_proxy: Some(SystemProxyEndpoint::CoreListener),
        bypass: egrio_platform::system_proxy_config_from_listen_addr("127.0.0.1:1")
            .expect("a loopback socket address is a valid proxy endpoint")
            .bypass,
    }
}

fn runtime_core_update_available(runtime: &Runtime) -> Result<bool, String> {
    let state = runtime.status().state;
    let core_state = runtime.core_status().state;
    if matches!(state, RuntimeState::Created | RuntimeState::Stopped)
        && core_state == egrio_core::NativeCoreState::Stopped
        && runtime.domain_status().core.is_none()
    {
        return Ok(false);
    }
    if state != RuntimeState::Running || core_state != egrio_core::NativeCoreState::Running {
        return Err(format!(
            "Core update requires a healthy running Runtime (runtime={state:?}, core={core_state:?})"
        ));
    }
    Ok(true)
}

impl<H: DesktopHost> Clone for DesktopRuntime<H> {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            lifecycle: self.lifecycle.clone(),
            runtime: self.runtime.clone(),
            checkpoints: self.checkpoints.clone(),
            recovery: self.recovery.clone(),
            user_transition: self.user_transition.clone(),
            configuration_admission: self.configuration_admission.clone(),
            configuration: self.configuration.clone(),
            rule_sets: self.rule_sets.clone(),
            rule_download: self.rule_download.clone(),
            prepared_configuration: self.prepared_configuration.clone(),
            tun_interruption: self.tun_interruption.clone(),
        }
    }
}

impl<H: DesktopHost> fmt::Debug for DesktopRuntime<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntime")
            .finish_non_exhaustive()
    }
}
