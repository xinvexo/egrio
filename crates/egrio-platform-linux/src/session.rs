//! The one Linux TUN session shared by the packet-capture capability and its
//! Route/DNS/Firewall controls: the ownership token minted at prepare, the
//! checkpoint of the open device, and which controls are applied. Each
//! capability is its own small type over this state; none owns a Core or
//! packet pump.

use crate::network_state::{native_backend, Backend, TunCheckpoint};
use crate::{LinuxTunConfig, LinuxTunEgress, LinuxTunEgressSocketGuard};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityKind,
    CapabilityOperationReport, IpPrefix, PlatformLeaseKey,
};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

pub(crate) const SCHEMA_VERSION: u16 = 1;

/// One OS resource group applied on top of the open TUN device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Control {
    Route,
    Dns,
    Firewall,
}

impl Control {
    pub(crate) fn kind(self) -> CapabilityKind {
        match self {
            Self::Route => CapabilityKind::Route,
            Self::Dns => CapabilityKind::Dns,
            Self::Firewall => CapabilityKind::Firewall,
        }
    }

    fn lease_key(self) -> PlatformLeaseKey {
        match self {
            Self::Route => PlatformLeaseKey::default_route(),
            Self::Dns => PlatformLeaseKey::system_dns(),
            Self::Firewall => PlatformLeaseKey::kill_switch(),
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug, Default)]
struct ControlState {
    prepared: bool,
    applied: bool,
    /// The checkpoint's route intent while applied (Route only).
    install_default_route: bool,
    /// The destinations kept outside the tunnel while applied (Route and
    /// Firewall).
    excluded_prefixes: Vec<IpPrefix>,
    /// The Core's fake-IP pool while applied (Firewall).
    fake_ip_prefixes: Vec<IpPrefix>,
}

#[derive(Debug, Default)]
struct State {
    prepared: Option<TunCheckpoint>,
    active: Option<TunCheckpoint>,
    controls: [ControlState; 3],
}

#[derive(Debug)]
pub(crate) struct LinuxTunSession {
    pub(crate) config: LinuxTunConfig,
    pub(crate) backend: Arc<dyn Backend>,
    lifecycle: AsyncMutex<()>,
    state: Mutex<State>,
    pub(crate) egress: Arc<LinuxTunEgress>,
}

pub(crate) fn capability_error(
    kind: CapabilityKind,
    code: CapabilityErrorCode,
    message: impl Into<String>,
) -> CapabilityError {
    CapabilityError::new(kind, code, message)
}

pub(crate) fn report(kind: CapabilityKind) -> CapabilityOperationReport {
    CapabilityOperationReport {
        capability: kind,
        changed: true,
        verified: true,
    }
}

impl LinuxTunSession {
    pub(crate) fn new(config: LinuxTunConfig, backend: Arc<dyn Backend>) -> Self {
        Self {
            config,
            backend,
            lifecycle: AsyncMutex::new(()),
            state: Mutex::new(State::default()),
            egress: Arc::default(),
        }
    }

    /// Serializes every capability operation on this session.
    pub(crate) async fn lifecycle(&self) -> MutexGuard<'_, ()> {
        self.lifecycle.lock().await
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("Linux TUN session state")
    }

    pub(crate) fn active(&self) -> Option<TunCheckpoint> {
        self.state().active.clone()
    }

    pub(crate) fn set_prepared(&self, checkpoint: TunCheckpoint) {
        let mut state = self.state();
        state.prepared = Some(checkpoint);
        state.controls[Control::Route.index()].prepared = false;
    }

    /// Moves the prepared checkpoint to active before the first OS mutation,
    /// so a failed open is compensated with the already-persisted token.
    pub(crate) fn activate(
        &self,
        accepts: impl FnOnce(&TunCheckpoint) -> Result<(), CapabilityError>,
    ) -> Result<TunCheckpoint, CapabilityError> {
        let kind = CapabilityKind::PacketCapture;
        let mut state = self.state();
        if state.active.is_some() {
            return Err(capability_error(
                kind,
                CapabilityErrorCode::Conflict,
                "Linux TUN is already open or recovering",
            ));
        }
        let checkpoint = state.prepared.take().ok_or_else(|| {
            capability_error(
                kind,
                CapabilityErrorCode::InvalidRequest,
                "Linux TUN open requires a prepared checkpoint",
            )
        })?;
        if let Err(error) = accepts(&checkpoint) {
            state.prepared = Some(checkpoint);
            return Err(error);
        }
        state.active = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Clears session ownership after its packet-capture restore succeeded.
    pub(crate) fn release(&self, ownership: &str) {
        let mut state = self.state();
        if state
            .active
            .as_ref()
            .is_some_and(|active| active.ownership == ownership)
        {
            state.active = None;
        }
        if state
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.ownership == ownership)
        {
            state.prepared = None;
        }
    }

    /// Whether Route owns, or will own, the session's routes.
    pub(crate) fn route_owned(&self) -> bool {
        let state = self.state();
        let route = &state.controls[Control::Route.index()];
        route.prepared || route.applied
    }

    /// A control checkpoint shares the session's ownership token and carries
    /// the control's own route intent, exclusions and fake-IP pool. Prepared
    /// while the control is applied, it records the settings in force as the
    /// baseline of an in-place update; only the route intent cannot change in
    /// place.
    pub(crate) fn prepare_control(
        &self,
        control: Control,
        install_default_route: bool,
        excluded_prefixes: &[IpPrefix],
        fake_ip_prefixes: &[IpPrefix],
    ) -> Result<CapabilityCheckpoint, CapabilityError> {
        let kind = control.kind();
        let mut state = self.state();
        let current = state.controls[control.index()].clone();
        if current.applied && current.install_default_route != install_default_route {
            return Err(capability_error(
                kind,
                CapabilityErrorCode::Conflict,
                "Linux TUN route intent requires stop/start when already active",
            ));
        }
        let mut checkpoint = state
            .active
            .as_ref()
            .or(state.prepared.as_ref())
            .ok_or_else(|| {
                capability_error(
                    kind,
                    CapabilityErrorCode::InvalidRequest,
                    "Linux TUN control requires packet capture in the same Runtime",
                )
            })?
            .clone();
        if current.applied {
            checkpoint.install_default_route = current.install_default_route;
            checkpoint.excluded_prefixes = current.excluded_prefixes;
            checkpoint.fake_ip_prefixes = current.fake_ip_prefixes;
            checkpoint.applied = true;
        } else {
            checkpoint.install_default_route = install_default_route;
            checkpoint.excluded_prefixes = excluded_prefixes.to_vec();
            checkpoint.fake_ip_prefixes = fake_ip_prefixes.to_vec();
            state.controls[control.index()].prepared = true;
        }
        Ok(CapabilityCheckpoint {
            lease_key: control.lease_key(),
            schema_version: SCHEMA_VERSION,
            payload: serde_json::to_value(checkpoint).map_err(|e| {
                capability_error(kind, CapabilityErrorCode::ApplyFailed, e.to_string())
            })?,
            rollback_payload: None,
        })
    }

    pub(crate) async fn apply_control(
        &self,
        control: Control,
        install_default_route: bool,
        excluded_prefixes: &[IpPrefix],
        fake_ip_prefixes: &[IpPrefix],
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        let kind = control.kind();
        let mut checkpoint = self.active().ok_or_else(|| {
            capability_error(
                kind,
                CapabilityErrorCode::InvalidRequest,
                "Linux TUN packet capture is not active",
            )
        })?;
        checkpoint.install_default_route = install_default_route;
        checkpoint.excluded_prefixes = excluded_prefixes.to_vec();
        checkpoint.fake_ip_prefixes = fake_ip_prefixes.to_vec();
        // Mark applied before mutating: a partial apply is restored through
        // the control's checkpoint.
        self.state().controls[control.index()] = ControlState {
            prepared: false,
            applied: true,
            install_default_route,
            excluded_prefixes: excluded_prefixes.to_vec(),
            fake_ip_prefixes: fake_ip_prefixes.to_vec(),
        };
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.apply_control(control, &checkpoint))
            .await
            .map_err(|e| capability_error(kind, CapabilityErrorCode::ApplyFailed, e.to_string()))?
            .map_err(|e| capability_error(kind, CapabilityErrorCode::ApplyFailed, e))?;
        Ok(report(kind))
    }

    pub(crate) async fn observe_control(&self, control: Control) -> Result<bool, CapabilityError> {
        let kind = control.kind();
        let ControlState {
            applied,
            install_default_route,
            excluded_prefixes,
            fake_ip_prefixes,
            ..
        } = self.state().controls[control.index()].clone();
        if !applied {
            return Ok(false);
        }
        let mut checkpoint = self.active().ok_or_else(|| {
            capability_error(
                kind,
                CapabilityErrorCode::InvalidRequest,
                "Linux TUN packet capture is not active",
            )
        })?;
        checkpoint.install_default_route = install_default_route;
        checkpoint.excluded_prefixes = excluded_prefixes;
        checkpoint.fake_ip_prefixes = fake_ip_prefixes;
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.observe_control(control, &checkpoint))
            .await
            .map_err(|e| capability_error(kind, CapabilityErrorCode::ObserveFailed, e.to_string()))?
            .map_err(|e| capability_error(kind, CapabilityErrorCode::ObserveFailed, e))
    }

    pub(crate) async fn restore_control(
        &self,
        control: Control,
        checkpoint: &CapabilityCheckpoint,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        let kind = control.kind();
        let checkpoint = self.decode(checkpoint, kind, control.lease_key())?;
        let ownership = checkpoint.ownership.clone();
        let baseline = checkpoint.applied.then(|| ControlState {
            prepared: false,
            applied: true,
            install_default_route: checkpoint.install_default_route,
            excluded_prefixes: checkpoint.excluded_prefixes.clone(),
            fake_ip_prefixes: checkpoint.fake_ip_prefixes.clone(),
        });
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.restore_control(control, &checkpoint))
            .await
            .map_err(|e| capability_error(kind, CapabilityErrorCode::RestoreFailed, e.to_string()))?
            .map_err(|e| capability_error(kind, CapabilityErrorCode::RestoreFailed, e))?;
        let mut state = self.state();
        if state
            .active
            .as_ref()
            .is_none_or(|active| active.ownership == ownership)
        {
            state.controls[control.index()] = baseline.unwrap_or_default();
        }
        Ok(report(kind))
    }

    /// Decodes a checkpoint to restore. It must name this session's kernel
    /// objects: the Linux service restores checkpoints read from the
    /// desktop user's files, and one naming another interface, mark, table
    /// or rule priority could otherwise delete resources Egrio never created.
    pub(crate) fn decode(
        &self,
        checkpoint: &CapabilityCheckpoint,
        kind: CapabilityKind,
        key: PlatformLeaseKey,
    ) -> Result<TunCheckpoint, CapabilityError> {
        let invalid =
            |message: String| capability_error(kind, CapabilityErrorCode::InvalidRequest, message);
        if checkpoint.lease_key != key || checkpoint.schema_version != SCHEMA_VERSION {
            return Err(invalid(
                "checkpoint does not match Linux TUN capability".into(),
            ));
        }
        let decoded: TunCheckpoint = serde_json::from_value(checkpoint.payload.clone())
            .map_err(|e| invalid(e.to_string()))?;
        decoded.validate().map_err(invalid)?;
        let (ours, theirs) = (&self.config, &decoded.config);
        if theirs.interface_name != ours.interface_name
            || theirs.fwmark != ours.fwmark
            || theirs.routing_table != ours.routing_table
            || theirs.rule_priority != ours.rule_priority
        {
            return Err(invalid(
                "checkpoint names Linux TUN resources this capability set does not own".into(),
            ));
        }
        Ok(decoded)
    }
}

/// The Linux TUN capability set. Register each member with its Runtime
/// port; all four share one session.
#[derive(Debug)]
pub struct LinuxTun {
    pub capture: Arc<crate::LinuxTunCapture>,
    pub route: Arc<crate::LinuxTunRouteControl>,
    pub dns: Arc<crate::LinuxTunDnsControl>,
    pub firewall: Arc<crate::LinuxTunFirewallControl>,
}

impl LinuxTun {
    pub fn new(config: LinuxTunConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self::with_backend(config, native_backend()))
    }

    pub(crate) fn with_backend(config: LinuxTunConfig, backend: Arc<dyn Backend>) -> Self {
        let session = Arc::new(LinuxTunSession::new(config, backend));
        Self {
            capture: Arc::new(crate::LinuxTunCapture::new(session.clone())),
            route: Arc::new(crate::LinuxTunRouteControl::new(session.clone())),
            dns: Arc::new(crate::LinuxTunDnsControl::new(session.clone())),
            firewall: Arc::new(crate::LinuxTunFirewallControl::new(session)),
        }
    }

    /// Marks Core's own sockets so policy routing sends them past the TUN,
    /// and reports the TUN's physical resolvers while it is up.
    pub fn egress_socket_guard(&self) -> Arc<dyn egrio_core::EgressSocketGuard> {
        Arc::new(
            LinuxTunEgressSocketGuard::new(self.capture.config().fwmark, self.capture.egress())
                .expect("validated nonzero mark"),
        )
    }
}
