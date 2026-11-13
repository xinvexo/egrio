use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use egrio_platform_windows::{
    apply_windows_runtime_dns, apply_windows_runtime_routes, open_windows_raw_packet_session,
    resolve_windows_ipv6_mode, restore_windows_runtime_dns, restore_windows_runtime_routes,
    start_windows_firewall_kill_switch_session, windows_firewall_kill_switch_filter_plan,
    windows_firewall_observe_kill_switch_filter_keys, windows_wintun_observe_capture_dns_servers,
    windows_wintun_observe_capture_route_keys, WindowsFirewallKillSwitchFilterPlan,
    WindowsFirewallKillSwitchFilterPlanInput, WindowsFirewallKillSwitchSession,
    WindowsRawPacketSession, WindowsWintunConfig,
};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityKind, CapabilityObservation, CapabilityOperationReport,
    DnsSettings, FirewallSettings, PacketCaptureSettings, PacketCaptureSource, PlatformLeaseKey,
    RouteSettings,
};

use crate::protocol::{
    ControlErrorCode, ControlRequest, ControlResponse, PacketChannel, SharedRingChannel,
};
use crate::session::ControlRequestHandler;
use crate::shared_memory::{CHANNEL_ABI_MAJOR, CHANNEL_ABI_MINOR};

use super::handles::{duplicate_for_current_process, DuplicatedPacketHandles};
use super::identity::{AuthenticatedClient, OwnedHandle};
use super::packet::WindowsPacketSession;
use super::pipe::Event;

/// How long opening the tunnel waits for a session that still holds it. A
/// desktop that starts while the one before it is still closing its tunnel
/// finds it held; the old session lets go within the time its teardown
/// takes, and failing the new one at once would leave the user to turn TUN
/// on again by hand.
const TUNNEL_HANDOVER: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub struct WindowsPacketControlHandler {
    config: WindowsWintunConfig,
    client_executable_path: String,
    target_process: OwnedHandle,
    active: Mutex<Option<ActivePacketSession>>,
    /// Set when the packet session this connection opened stops carrying
    /// packets on its own.
    fault: Arc<Event>,
    resources: Arc<WindowsServiceResources>,
}

/// What the service's sessions share. Each control connection is a session
/// on a thread of its own, and the machine has one tunnel: its adapter, and
/// the routes, DNS servers and filters on it, belong to the session whose
/// packet capture is open.
#[derive(Debug, Default)]
pub struct WindowsServiceResources {
    /// The leak-protection firewall, which ends with the packet session it
    /// guards, whichever connection asks.
    firewall: ProcessResource<ActiveFirewallSession>,
    /// Held for each request and each session's end, so no two sessions'
    /// checks and changes of the machine's state interleave.
    operations: Mutex<()>,
    /// Whether a session holds the tunnel, and what tells a session waiting
    /// for it that it was let go.
    tunnel_held: Mutex<bool>,
    tunnel_released: Condvar,
}

/// The tunnel, held by the session whose packet capture is open.
#[derive(Debug)]
struct TunnelHold(Arc<WindowsServiceResources>);

impl TunnelHold {
    fn take(resources: &Arc<WindowsServiceResources>) -> Option<Self> {
        let mut held = lock(&resources.tunnel_held);
        if *held {
            return None;
        }
        *held = true;
        Some(Self(Arc::clone(resources)))
    }
}

impl Drop for TunnelHold {
    fn drop(&mut self) {
        *lock(&self.0.tunnel_held) = false;
        self.0.tunnel_released.notify_all();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[derive(Debug)]
struct ProcessResource<T> {
    value: Mutex<Option<T>>,
}

impl<T> Default for ProcessResource<T> {
    fn default() -> Self {
        Self {
            value: Mutex::new(None),
        }
    }
}

impl<T> ProcessResource<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<T>> {
        self.value.lock().expect("Windows service resource mutex")
    }
}

impl WindowsServiceResources {
    fn tunnel_held(&self) -> bool {
        *lock(&self.tunnel_held)
    }

    /// Waits, at most [`TUNNEL_HANDOVER`], for the session holding the
    /// tunnel to let it go.
    fn await_tunnel(&self) {
        let deadline = Instant::now() + TUNNEL_HANDOVER;
        let mut held = lock(&self.tunnel_held);
        while *held {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            held = self
                .tunnel_released
                .wait_timeout(held, left)
                .unwrap_or_else(|poison| poison.into_inner())
                .0;
        }
    }

    /// Whether the leak-protection firewall guards the tunnel on
    /// `interface_index`.
    fn firewall_guards(&self, interface_index: u32) -> bool {
        self.firewall
            .lock()
            .as_ref()
            .is_some_and(|active| active.tunnel == interface_index)
    }

    /// Ends the firewall guarding the tunnel on `interface_index`, which no
    /// longer carries packets: BFE releases its filters with the dynamic
    /// session, so the network works as it does without Egrio.
    fn end_firewall_of(&self, interface_index: u32) {
        let mut firewall = self.firewall.lock();
        if firewall
            .as_ref()
            .is_some_and(|active| active.tunnel == interface_index)
        {
            if let Some(active) = firewall.take() {
                active.session.stop();
            }
        }
    }
}

#[derive(Debug)]
struct ActivePacketSession {
    settings: PacketCaptureSettings,
    /// Stopped before the hold below is let go (field order).
    session: WindowsPacketSession,
    _tunnel: TunnelHold,
}

struct ActiveFirewallSession {
    settings: FirewallSettings,
    expected_keys: Vec<String>,
    session: WindowsFirewallKillSwitchSession,
    /// The interface of the packet session it guards, which it ends with.
    tunnel: u32,
}

impl std::fmt::Debug for ActiveFirewallSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveFirewallSession")
            .field("settings", &self.settings)
            .field("expected_keys", &self.expected_keys)
            .field("tunnel", &self.tunnel)
            .finish()
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct RouteCheckpointPayload {
    baseline_keys: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct DnsCheckpointPayload {
    baseline_servers: Vec<std::net::IpAddr>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct FirewallCheckpointPayload {
    baseline_keys: Vec<String>,
    /// The settings in force at prepare time, so a rollback can rebuild the
    /// filter set an in-place update replaced.
    #[serde(default)]
    baseline_settings: Option<FirewallSettings>,
}

impl WindowsPacketControlHandler {
    pub fn new(config: WindowsWintunConfig, client: &AuthenticatedClient) -> Result<Self, String> {
        Self::with_resources(config, client, Arc::new(WindowsServiceResources::default()))
    }

    pub fn with_resources(
        config: WindowsWintunConfig,
        client: &AuthenticatedClient,
        resources: Arc<WindowsServiceResources>,
    ) -> Result<Self, String> {
        Ok(Self {
            config,
            client_executable_path: client.executable_path.clone(),
            target_process: duplicate_for_current_process(client.process.raw())?,
            active: Mutex::new(None),
            fault: Arc::new(
                Event::new().map_err(|error| format!("failed to create an event: {error}"))?,
            ),
            resources,
        })
    }

    /// Set when the packet session this connection opened stops carrying
    /// packets on its own (its Wintun session ended, e.g. the adapter was
    /// disabled). The connection's session ends with it, as a lost service
    /// would: the desktop reports TUN interrupted and restores it through a
    /// new session.
    pub fn fault(&self) -> &Event {
        &self.fault
    }

    /// Ends the session: what it holds of the machine is released.
    pub fn disconnect(&self) {
        let _operation = lock(&self.resources.operations);
        let active = self
            .active
            .lock()
            .expect("Windows packet session mutex")
            .take();
        if let Some(mut active) = active {
            // The firewall goes with the tunnel it guards: a desktop that went
            // away leaves the network as it is without Egrio.
            let _ = active.session.stop();
            self.resources
                .end_firewall_of(active.session.interface_index());
        }
    }

    fn prepare_packet_capture(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let settings: PacketCaptureSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        settings
            .validate()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let current = self
            .active
            .lock()
            .expect("Windows packet session mutex")
            .as_ref()
            .map(|active| active.settings.clone());
        Ok(ControlResponse::Checkpoint(CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::packet_capture(),
            schema_version: 1,
            payload: serde_json::to_value(current)
                .map_err(|error| (ControlErrorCode::Internal, error.to_string()))?,
            rollback_payload: None,
        }))
    }

    fn open_packet_capture(
        &self,
        settings: PacketCaptureSettings,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let mut active = self.active.lock().expect("Windows packet session mutex");
        if active.is_some() {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "packet capture session is already active".into(),
            ));
        }
        settings
            .validate()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let tunnel = TunnelHold::take(&self.resources).ok_or_else(|| {
            (
                ControlErrorCode::CapabilityFailed,
                ANOTHER_SESSIONS_TUNNEL.to_string(),
            )
        })?;
        // The request is the session's single desired MTU. Other adapter
        // properties keep their existing service configuration and mechanisms.
        let mut capture_config = self.config.clone();
        capture_config.mtu = u16::try_from(settings.mtu).map_err(|_| {
            (
                ControlErrorCode::CapabilityFailed,
                "capture MTU exceeds the Wintun IP packet limit".into(),
            )
        })?;
        let raw = open_windows_raw_packet_session(&capture_config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let resources = Arc::clone(&self.resources);
        let fault = Arc::clone(&self.fault);
        let interface_index = raw.interface_index();
        let session = WindowsPacketSession::open(
            Box::new(raw),
            Box::new(move |error| {
                eprintln!(
                    "egrio-service: the packet session on interface {interface_index} stopped carrying packets: {error}"
                );
                resources.end_firewall_of(interface_index);
                fault.set();
            }),
        )
        .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let handles = session
            .duplicate_into(&self.target_process)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let response = ControlResponse::PacketChannel(PacketChannel::SharedRing(
            packet_channel_response(handles, session.interface_index()),
        ));
        *active = Some(ActivePacketSession {
            settings,
            session,
            _tunnel: tunnel,
        });
        Ok(response)
    }

    /// The interface of this session's open packet capture.
    fn tunnel(&self) -> Option<u32> {
        self.active
            .lock()
            .expect("Windows packet session mutex")
            .as_ref()
            .map(|active| active.session.interface_index())
    }

    fn close_packet_capture(&self) -> Result<(), (ControlErrorCode, String)> {
        let Some(tunnel) = self.tunnel() else {
            return Ok(());
        };
        if self.resources.firewall_guards(tunnel) {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "restore the Windows firewall session before closing packet capture".into(),
            ));
        }
        let mut active = self.active.lock().expect("Windows packet session mutex");
        if let Some(mut active) = active.take() {
            active
                .session
                .stop()
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        }
        Ok(())
    }

    fn observe_packet_capture(&self) -> ControlResponse {
        ControlResponse::Observation(CapabilityObservation {
            capability: CapabilityKind::PacketCapture,
            active: self
                .active
                .lock()
                .expect("Windows packet session mutex")
                .is_some(),
            verified: true,
        })
    }

    fn restore_packet_capture(
        &self,
        checkpoint: CapabilityCheckpoint,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        if checkpoint.lease_key != PlatformLeaseKey::packet_capture()
            || checkpoint.schema_version != 1
        {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "checkpoint does not match packet capture contract".into(),
            ));
        }
        let baseline: Option<PacketCaptureSettings> = serde_json::from_value(checkpoint.payload)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        if baseline.is_some() {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "adopting an active packet checkpoint is not implemented".into(),
            ));
        }
        let changed = self
            .active
            .lock()
            .expect("Windows packet session mutex")
            .is_some();
        self.close_packet_capture()?;
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::PacketCapture,
            changed,
            verified: true,
        }))
    }

    fn prepare_routes(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let _: RouteSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let baseline_keys = if self.beside_anothers_tunnel() {
            Vec::new()
        } else {
            windows_wintun_observe_capture_route_keys(&self.config)
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?
        };
        Ok(ControlResponse::Checkpoint(CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::default_route(),
            schema_version: 1,
            payload: serde_json::to_value(RouteCheckpointPayload { baseline_keys })
                .map_err(|error| (ControlErrorCode::Internal, error.to_string()))?,
            rollback_payload: None,
        }))
    }

    fn apply_routes(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let settings: RouteSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let before = windows_wintun_observe_capture_route_keys(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let observed = apply_windows_runtime_routes(&self.config, &settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let expected_active = settings.default_route;
        let verified = if expected_active {
            !observed.is_empty()
        } else {
            observed.is_empty()
        };
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Route,
            changed: before != observed,
            verified,
        }))
    }

    fn observe_routes(&self) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let observed = windows_wintun_observe_capture_route_keys(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        Ok(ControlResponse::Observation(CapabilityObservation {
            capability: CapabilityKind::Route,
            active: !observed.is_empty(),
            verified: true,
        }))
    }

    fn restore_routes(
        &self,
        checkpoint: CapabilityCheckpoint,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        if checkpoint.lease_key != PlatformLeaseKey::default_route()
            || checkpoint.schema_version != 1
        {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "checkpoint does not match route contract".into(),
            ));
        }
        let payload: RouteCheckpointPayload = serde_json::from_value(checkpoint.payload)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let before = windows_wintun_observe_capture_route_keys(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let observed = restore_windows_runtime_routes(&self.config, &payload.baseline_keys)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Route,
            changed: before != observed,
            verified: observed == payload.baseline_keys,
        }))
    }

    fn prepare_dns(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let _: DnsSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let baseline_servers = if self.beside_anothers_tunnel() {
            Vec::new()
        } else {
            windows_wintun_observe_capture_dns_servers(&self.config)
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?
        };
        Ok(ControlResponse::Checkpoint(CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_dns(),
            schema_version: 1,
            payload: serde_json::to_value(DnsCheckpointPayload { baseline_servers })
                .map_err(|error| (ControlErrorCode::Internal, error.to_string()))?,
            rollback_payload: None,
        }))
    }

    fn apply_dns(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let settings: DnsSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let before = windows_wintun_observe_capture_dns_servers(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let observed = apply_windows_runtime_dns(&self.config, &settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Dns,
            changed: before != observed,
            verified: true,
        }))
    }

    fn observe_dns(&self) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let observed = windows_wintun_observe_capture_dns_servers(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        Ok(ControlResponse::Observation(CapabilityObservation {
            capability: CapabilityKind::Dns,
            active: !observed.is_empty(),
            verified: true,
        }))
    }

    fn restore_dns(
        &self,
        checkpoint: CapabilityCheckpoint,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        if checkpoint.lease_key != PlatformLeaseKey::system_dns() || checkpoint.schema_version != 1
        {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "checkpoint does not match DNS contract".into(),
            ));
        }
        let payload: DnsCheckpointPayload = serde_json::from_value(checkpoint.payload)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let before = windows_wintun_observe_capture_dns_servers(&self.config)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let observed = restore_windows_runtime_dns(&self.config, &payload.baseline_servers)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let mut baseline = payload.baseline_servers;
        baseline.sort();
        baseline.dedup();
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Dns,
            changed: before != observed,
            verified: observed == baseline,
        }))
    }

    fn prepare_firewall(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let _: FirewallSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let (baseline_keys, baseline_settings) = if self.beside_anothers_tunnel() {
            (Vec::new(), None)
        } else {
            (
                windows_firewall_observe_kill_switch_filter_keys()
                    .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?,
                self.resources
                    .firewall
                    .lock()
                    .as_ref()
                    .map(|active| active.settings.clone()),
            )
        };
        Ok(ControlResponse::Checkpoint(CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::kill_switch(),
            schema_version: 1,
            payload: serde_json::to_value(FirewallCheckpointPayload {
                baseline_keys,
                baseline_settings,
            })
            .map_err(|error| (ControlErrorCode::Internal, error.to_string()))?,
            rollback_payload: None,
        }))
    }

    fn apply_firewall(
        &self,
        settings: serde_json::Value,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let settings: FirewallSettings = serde_json::from_value(settings)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        if settings.kill_switch && !settings.allow_lan {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "Windows runtime firewall without LAN bypass is not implemented".into(),
            ));
        }

        let before = windows_firewall_observe_kill_switch_filter_keys()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let mut active_firewall = self.resources.firewall.lock();
        if !settings.kill_switch {
            let changed = active_firewall.take().is_some();
            let observed = windows_firewall_observe_kill_switch_filter_keys()
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
            return Ok(ControlResponse::Operation(CapabilityOperationReport {
                capability: CapabilityKind::Firewall,
                changed,
                verified: observed.is_empty(),
            }));
        }
        if let Some(active) = active_firewall.as_mut() {
            if active.settings == settings {
                return Ok(ControlResponse::Operation(CapabilityOperationReport {
                    capability: CapabilityKind::Firewall,
                    changed: false,
                    verified: before == active.expected_keys,
                }));
            }
            let (plan, tunnel) = self.kill_switch_plan(&settings)?;
            active
                .session
                .reconcile_filter_plan(&plan)
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
            active.expected_keys = plan_keys(&plan);
            active.settings = settings;
            active.tunnel = tunnel;
            let observed = windows_firewall_observe_kill_switch_filter_keys()
                .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
            return Ok(ControlResponse::Operation(CapabilityOperationReport {
                capability: CapabilityKind::Firewall,
                changed: before != observed,
                verified: observed == active.expected_keys,
            }));
        }
        if !before.is_empty() {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "another Egrio WFP filter session is already active".into(),
            ));
        }
        let (plan, tunnel) = self.kill_switch_plan(&settings)?;
        let mut session = start_windows_firewall_kill_switch_session()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        session
            .install_filter_plan(&plan)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let expected_keys = plan_keys(&plan);
        let observed = windows_firewall_observe_kill_switch_filter_keys()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let verified = observed == expected_keys;
        if !verified {
            session.stop();
            return Err((
                ControlErrorCode::CapabilityFailed,
                "Windows WFP observation did not match the installed filter set".into(),
            ));
        }
        *active_firewall = Some(ActiveFirewallSession {
            settings,
            expected_keys,
            session,
            tunnel,
        });
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Firewall,
            changed: before != observed,
            verified,
        }))
    }

    fn observe_firewall(&self) -> Result<ControlResponse, (ControlErrorCode, String)> {
        let observed = windows_firewall_observe_kill_switch_filter_keys()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let firewall = self.resources.firewall.lock();
        let verified = firewall
            .as_ref()
            .map(|active| observed == active.expected_keys)
            .unwrap_or_else(|| observed.is_empty());
        Ok(ControlResponse::Observation(CapabilityObservation {
            capability: CapabilityKind::Firewall,
            active: !observed.is_empty(),
            verified,
        }))
    }

    fn restore_firewall(
        &self,
        checkpoint: CapabilityCheckpoint,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        if checkpoint.lease_key != PlatformLeaseKey::kill_switch() || checkpoint.schema_version != 1
        {
            return Err((
                ControlErrorCode::CapabilityFailed,
                "checkpoint does not match firewall contract".into(),
            ));
        }
        let payload: FirewallCheckpointPayload = serde_json::from_value(checkpoint.payload)
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))?;
        let before = windows_firewall_observe_kill_switch_filter_keys()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        let mut active_firewall = self.resources.firewall.lock();
        match (payload.baseline_settings, active_firewall.as_mut()) {
            // Rolling back an in-place update: rebuild the filters the
            // update replaced.
            (Some(settings), Some(active)) if !payload.baseline_keys.is_empty() => {
                let (plan, tunnel) = self.kill_switch_plan(&settings)?;
                active
                    .session
                    .reconcile_filter_plan(&plan)
                    .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
                active.expected_keys = plan_keys(&plan);
                active.settings = settings;
                active.tunnel = tunnel;
            }
            _ => {
                if let Some(active) = active_firewall.take() {
                    active.session.stop();
                }
            }
        }
        drop(active_firewall);
        let observed = windows_firewall_observe_kill_switch_filter_keys()
            .map_err(|error| (ControlErrorCode::CapabilityFailed, error))?;
        Ok(ControlResponse::Operation(CapabilityOperationReport {
            capability: CapabilityKind::Firewall,
            changed: before != observed,
            verified: observed == payload.baseline_keys,
        }))
    }
}

impl WindowsPacketControlHandler {
    /// The leak-protection filter plan for `settings` on this connection's
    /// packet session, and the interface it guards. A session that stopped
    /// carrying packets gets none: its firewall ended with it.
    fn kill_switch_plan(
        &self,
        settings: &FirewallSettings,
    ) -> Result<(WindowsFirewallKillSwitchFilterPlan, u32), (ControlErrorCode, String)> {
        let interface_index = self
            .active
            .lock()
            .expect("Windows packet session mutex")
            .as_ref()
            .filter(|active| active.session.carries_packets())
            .map(|active| active.session.interface_index())
            .ok_or_else(|| {
                (
                    ControlErrorCode::CapabilityFailed,
                    "Windows firewall apply requires a packet session that carries packets".into(),
                )
            })?;
        let plan =
            windows_firewall_kill_switch_filter_plan(WindowsFirewallKillSwitchFilterPlanInput {
                wintun_interface_index: Some(interface_index),
                protected_app_paths: vec![self.client_executable_path.clone()],
                ipv6: resolve_windows_ipv6_mode(&self.config),
                excluded_prefixes: settings.excluded_prefixes.clone(),
                fake_ip_prefixes: settings.fake_ip_prefixes.clone(),
            });
        if !plan.production_ready {
            return Err((
                ControlErrorCode::CapabilityFailed,
                format!(
                    "Windows WFP filter plan is not ready: {}",
                    plan.blockers.join("; ")
                ),
            ));
        }
        Ok((plan, interface_index))
    }
}

fn plan_keys(plan: &WindowsFirewallKillSwitchFilterPlan) -> Vec<String> {
    let mut keys = plan
        .filters
        .iter()
        .map(|filter| filter.key.clone())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

const ANOTHER_SESSIONS_TUNNEL: &str = "another Egrio session holds the tunnel";

/// The capability a checkpoint with `lease_key` restores.
fn restored_capability(lease_key: &PlatformLeaseKey) -> Option<CapabilityKind> {
    [
        (
            PlatformLeaseKey::packet_capture(),
            CapabilityKind::PacketCapture,
        ),
        (PlatformLeaseKey::default_route(), CapabilityKind::Route),
        (PlatformLeaseKey::system_dns(), CapabilityKind::Dns),
        (PlatformLeaseKey::kill_switch(), CapabilityKind::Firewall),
    ]
    .into_iter()
    .find_map(|(key, capability)| (&key == lease_key).then_some(capability))
}

impl WindowsPacketControlHandler {
    /// Whether another session's packet capture is open. The adapter, and
    /// the routes, DNS servers and filters on it, are then that session's:
    /// this one has nothing of its own on the machine.
    fn beside_anothers_tunnel(&self) -> bool {
        self.resources.tunnel_held() && self.tunnel().is_none()
    }

    /// What a request gets while another session holds the tunnel, where
    /// serving it as usual would take that session's state for this one's.
    /// Applying anything would change the other session's routes, DNS
    /// servers or filters under it. A checkpoint this session restores has
    /// nothing left to put back: the adapter and everything on it went with
    /// its own tunnel when that closed. What it observes of its own is
    /// nothing. Preparing is served as usual, with an empty baseline (see
    /// the `prepare_*` methods): recording the other session's state as
    /// what to restore to would have this one's restore put it back.
    fn answer_beside_anothers_tunnel(
        &self,
        request: &ControlRequest,
    ) -> Option<Result<ControlResponse, (ControlErrorCode, String)>> {
        if !self.beside_anothers_tunnel() {
            return None;
        }
        match request {
            ControlRequest::Apply { .. } | ControlRequest::OpenPacketCapture { .. } => Some(Err((
                ControlErrorCode::CapabilityFailed,
                ANOTHER_SESSIONS_TUNNEL.into(),
            ))),
            ControlRequest::Restore { checkpoint } => restored_capability(&checkpoint.lease_key)
                .map(|capability| {
                    Ok(ControlResponse::Operation(CapabilityOperationReport {
                        capability,
                        changed: false,
                        verified: true,
                    }))
                }),
            ControlRequest::Observe {
                capability:
                    capability
                    @ (CapabilityKind::Route | CapabilityKind::Dns | CapabilityKind::Firewall),
            } => Some(Ok(ControlResponse::Observation(CapabilityObservation {
                capability: *capability,
                active: false,
                verified: true,
            }))),
            _ => None,
        }
    }
}

impl ControlRequestHandler for WindowsPacketControlHandler {
    fn handle(
        &self,
        request: ControlRequest,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        if matches!(request, ControlRequest::OpenPacketCapture { .. }) && self.tunnel().is_none() {
            self.resources.await_tunnel();
        }
        let _operation = lock(&self.resources.operations);
        if let Some(answer) = self.answer_beside_anothers_tunnel(&request) {
            return answer;
        }
        match request {
            ControlRequest::Prepare {
                capability: CapabilityKind::PacketCapture,
                settings,
            } => self.prepare_packet_capture(settings),
            ControlRequest::Observe {
                capability: CapabilityKind::PacketCapture,
            } => Ok(self.observe_packet_capture()),
            ControlRequest::Restore { checkpoint }
                if checkpoint.lease_key == PlatformLeaseKey::packet_capture() =>
            {
                self.restore_packet_capture(checkpoint)
            }
            ControlRequest::Prepare {
                capability: CapabilityKind::Route,
                settings,
            } => self.prepare_routes(settings),
            ControlRequest::Apply {
                capability: CapabilityKind::Route,
                settings,
            } => self.apply_routes(settings),
            ControlRequest::Observe {
                capability: CapabilityKind::Route,
            } => self.observe_routes(),
            ControlRequest::Restore { checkpoint }
                if checkpoint.lease_key == PlatformLeaseKey::default_route() =>
            {
                self.restore_routes(checkpoint)
            }
            ControlRequest::Prepare {
                capability: CapabilityKind::Dns,
                settings,
            } => self.prepare_dns(settings),
            ControlRequest::Apply {
                capability: CapabilityKind::Dns,
                settings,
            } => self.apply_dns(settings),
            ControlRequest::Observe {
                capability: CapabilityKind::Dns,
            } => self.observe_dns(),
            ControlRequest::Restore { checkpoint }
                if checkpoint.lease_key == PlatformLeaseKey::system_dns() =>
            {
                self.restore_dns(checkpoint)
            }
            ControlRequest::Prepare {
                capability: CapabilityKind::Firewall,
                settings,
            } => self.prepare_firewall(settings),
            ControlRequest::Apply {
                capability: CapabilityKind::Firewall,
                settings,
            } => self.apply_firewall(settings),
            ControlRequest::Observe {
                capability: CapabilityKind::Firewall,
            } => self.observe_firewall(),
            ControlRequest::Restore { checkpoint }
                if checkpoint.lease_key == PlatformLeaseKey::kill_switch() =>
            {
                self.restore_firewall(checkpoint)
            }
            ControlRequest::OpenPacketCapture { settings }
                if settings.source == PacketCaptureSource::Tun =>
            {
                self.open_packet_capture(settings)
            }
            ControlRequest::OpenPacketCapture { .. } => Err((
                ControlErrorCode::CapabilityFailed,
                "Windows service packet capture requires the tun source".into(),
            )),
            _ => Err((
                ControlErrorCode::UnsupportedMethod,
                "control method is not implemented by the packet handler".into(),
            )),
        }
    }

    fn response_failed(&self, response: &ControlResponse) {
        let ControlResponse::PacketChannel(PacketChannel::SharedRing(handles)) = response else {
            return;
        };
        duplicated_from_response(handles).close_in_target(&self.target_process);
        self.disconnect();
    }
}

impl Drop for WindowsPacketControlHandler {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn packet_channel_response(
    handles: DuplicatedPacketHandles,
    interface_index: u32,
) -> SharedRingChannel {
    SharedRingChannel {
        channel_id: handles.channel_id,
        mapping: handles.mapping,
        rx_data_available: handles.rx_data_available,
        rx_space_available: handles.rx_space_available,
        tx_data_available: handles.tx_data_available,
        tx_space_available: handles.tx_space_available,
        mapping_len: handles.mapping_len,
        abi_major: CHANNEL_ABI_MAJOR,
        abi_minor: CHANNEL_ABI_MINOR,
        interface_index,
    }
}

fn duplicated_from_response(handles: &SharedRingChannel) -> DuplicatedPacketHandles {
    DuplicatedPacketHandles {
        channel_id: handles.channel_id,
        mapping: handles.mapping,
        rx_data_available: handles.rx_data_available,
        rx_space_available: handles.rx_space_available,
        tx_data_available: handles.tx_data_available,
        tx_space_available: handles.tx_space_available,
        mapping_len: handles.mapping_len,
    }
}

#[cfg(test)]
mod resource_owner_tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn process_resource_survives_connection_arc_drop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(ProcessResource::default());
        *owner.lock() = Some(DropProbe(Arc::clone(&dropped)));

        let connection_view = Arc::clone(&owner);
        drop(connection_view);
        assert!(!dropped.load(Ordering::SeqCst));

        drop(owner);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
