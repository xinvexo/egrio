//! The macOS service's capability handler: opens the TUN as root for one
//! authorized desktop session. The tunnel is machine-wide (one set of routes,
//! one default resolver), so one session holds it at a time; the session's
//! connection ending closes it.

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, PoisonError};

use egrio_platform_macos::{MacosTunSession, MACOS_TUN_MTU};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityKind, CapabilityObservation, CapabilityOperationReport,
    PacketCaptureSettings, PlatformLeaseKey,
};

use crate::protocol::{
    ControlErrorCode, ControlRequest, ControlResponse, PacketChannel, UtunChannel,
};
use crate::session::ControlRequestHandler;

type HandlerResult<T> = Result<T, (ControlErrorCode, String)>;

const SCHEMA_VERSION: u16 = 1;

/// The capabilities a macOS service session offers: the tunnel installs its
/// own routes and resolver, and macOS has no firewall capability.
pub const MACOS_SERVICE_CAPABILITIES: [CapabilityKind; 1] = [CapabilityKind::PacketCapture];

/// What every session of the service shares: which one holds the tunnel.
#[derive(Debug, Default)]
pub struct MacosServiceResources {
    tunnel_held: Mutex<bool>,
}

impl MacosServiceResources {
    /// Whether a session holds the tunnel.
    pub fn holds_tunnel(&self) -> bool {
        *self.hold()
    }

    fn hold(&self) -> std::sync::MutexGuard<'_, bool> {
        self.tunnel_held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Serves one desktop session.
#[derive(Debug)]
pub struct MacosServiceHandler {
    resources: Arc<MacosServiceResources>,
    prepared: Mutex<bool>,
    session: Mutex<Option<MacosTunSession>>,
    /// The utun descriptor for the response being written.
    descriptor: Mutex<Option<OwnedFd>>,
}

impl MacosServiceHandler {
    pub fn new(resources: Arc<MacosServiceResources>) -> Self {
        Self {
            resources,
            prepared: Mutex::new(false),
            session: Mutex::new(None),
            descriptor: Mutex::new(None),
        }
    }

    /// Ends the session after its connection closed: closes its tunnel.
    pub fn end_session(&self) {
        self.close();
    }

    /// Closes this session's tunnel; whether it had one.
    fn close(&self) -> bool {
        let closed = lock(&self.session).take().is_some();
        if closed {
            *self.resources.hold() = false;
        }
        *lock(&self.prepared) = false;
        closed
    }

    fn prepare(&self, settings: PacketCaptureSettings) -> HandlerResult<ControlResponse> {
        validate(&settings)?;
        *lock(&self.prepared) = true;
        Ok(ControlResponse::Checkpoint(CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::packet_capture(),
            schema_version: SCHEMA_VERSION,
            payload: serde_json::json!({ "tunnel": "macos-utun" }),
            rollback_payload: None,
        }))
    }

    fn open(&self, settings: PacketCaptureSettings) -> HandlerResult<ControlResponse> {
        validate(&settings)?;
        if !*lock(&self.prepared) {
            return Err(failed("open the tunnel: the capture was not prepared"));
        }
        if lock(&self.session).is_some() {
            return Err(failed("open the tunnel: this session's tunnel is open"));
        }
        let mut held = self.resources.hold();
        if *held {
            return Err(failed("open the tunnel: another session holds it"));
        }
        let (session, open) = MacosTunSession::open(
            settings.mtu,
            &settings.excluded_prefixes,
            &settings.fake_ip_prefixes,
        )
        .map_err(|error| failed(format!("open the tunnel: {error}")))?;
        *held = true;
        *lock(&self.session) = Some(session);
        *lock(&self.descriptor) = Some(open.socket);
        Ok(ControlResponse::PacketChannel(PacketChannel::Utun(
            UtunChannel {
                interface_name: open.interface_name,
                interface_index: open.interface_index,
                mtu: open.mtu,
            },
        )))
    }

    fn with_session(
        &self,
        what: &str,
        change: impl FnOnce(&MacosTunSession) -> Result<(), String>,
    ) -> HandlerResult<ControlResponse> {
        let session = lock(&self.session);
        let session = session
            .as_ref()
            .ok_or_else(|| failed(format!("{what}: the tunnel is not open")))?;
        change(session).map_err(|error| failed(format!("{what}: {error}")))?;
        Ok(ControlResponse::Operation(report(true)))
    }
}

impl ControlRequestHandler for MacosServiceHandler {
    fn handle(&self, request: ControlRequest) -> HandlerResult<ControlResponse> {
        match request {
            ControlRequest::Prepare {
                capability: CapabilityKind::PacketCapture,
                settings,
            } => self.prepare(settings_of(settings)?),
            ControlRequest::OpenPacketCapture { settings } => self.open(settings),
            ControlRequest::Observe {
                capability: CapabilityKind::PacketCapture,
            } => Ok(ControlResponse::Observation(CapabilityObservation {
                capability: CapabilityKind::PacketCapture,
                active: lock(&self.session).is_some(),
                verified: true,
            })),
            ControlRequest::Restore { checkpoint }
                if checkpoint.lease_key == PlatformLeaseKey::packet_capture() =>
            {
                // A checkpoint of an earlier service process restores
                // nothing: its routes went at this process's start and its
                // utun with its descriptors.
                Ok(ControlResponse::Operation(report(self.close())))
            }
            ControlRequest::UpdateExcludedPrefixes { prefixes } => self
                .with_session("change the exclusions", |session| {
                    session.set_excluded_prefixes(&prefixes)
                }),
            _ => Err((
                ControlErrorCode::UnsupportedMethod,
                "control method is not implemented by the macOS service".into(),
            )),
        }
    }

    /// A channel whose response never reached the desktop leaves no tunnel
    /// behind.
    fn response_failed(&self, response: &ControlResponse) {
        if matches!(
            response,
            ControlResponse::PacketChannel(PacketChannel::Utun(_))
        ) {
            self.close();
        }
    }

    fn take_descriptor(&self) -> Option<OwnedFd> {
        lock(&self.descriptor).take()
    }
}

/// The tunnel publishes its own default routes and resolver at any MTU the
/// interface takes.
fn validate(settings: &PacketCaptureSettings) -> HandlerResult<()> {
    if !settings.install_default_route || !settings.install_dns {
        return Err(failed(
            "the macOS tunnel always installs its default routes and resolver",
        ));
    }
    if !(1280..=MACOS_TUN_MTU).contains(&settings.mtu) {
        return Err(failed(format!(
            "the macOS tunnel takes an MTU of 1280..={MACOS_TUN_MTU}, not {}",
            settings.mtu
        )));
    }
    Ok(())
}

fn report(changed: bool) -> CapabilityOperationReport {
    CapabilityOperationReport {
        capability: CapabilityKind::PacketCapture,
        changed,
        verified: true,
    }
}

fn settings_of(settings: serde_json::Value) -> HandlerResult<PacketCaptureSettings> {
    serde_json::from_value(settings)
        .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))
}

fn failed(message: impl Into<String>) -> (ControlErrorCode, String) {
    (ControlErrorCode::CapabilityFailed, message.into())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egrio_runtime::PacketCaptureSource;

    fn settings(mtu: u32) -> PacketCaptureSettings {
        PacketCaptureSettings {
            source: PacketCaptureSource::Tun,
            mtu,
            install_default_route: true,
            install_dns: true,
            excluded_prefixes: Vec::new(),
            fake_ip_prefixes: Vec::new(),
        }
    }

    #[test]
    fn the_tunnel_installs_its_routes_and_resolver_at_a_bounded_mtu() {
        assert!(validate(&settings(MACOS_TUN_MTU)).is_ok());
        assert!(validate(&settings(1280)).is_ok());
        assert!(validate(&settings(1279)).is_err());
        let mut without_dns = settings(1500);
        without_dns.install_dns = false;
        assert!(validate(&without_dns).is_err());
    }

    #[test]
    fn an_unprepared_or_closed_session_opens_and_changes_nothing() {
        let handler = MacosServiceHandler::new(Arc::default());
        assert!(handler.open(settings(1500)).is_err(), "not prepared");
        assert!(handler
            .handle(ControlRequest::UpdateExcludedPrefixes {
                prefixes: Vec::new()
            })
            .is_err());
        let restored = handler
            .handle(ControlRequest::Restore {
                checkpoint: CapabilityCheckpoint {
                    lease_key: PlatformLeaseKey::packet_capture(),
                    schema_version: SCHEMA_VERSION,
                    payload: serde_json::json!({ "tunnel": "macos-utun" }),
                    rollback_payload: None,
                },
            })
            .unwrap();
        assert!(matches!(
            restored,
            ControlResponse::Operation(CapabilityOperationReport { changed: false, .. })
        ));
    }
}
