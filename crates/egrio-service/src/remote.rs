//! The desktop's adapter for the privileged service (the Windows service,
//! the Linux root helper or the macOS launchd service). Route, DNS and
//! Firewall map one-to-one onto control requests; PacketCapture does too,
//! except that opening it hands over a platform packet channel the OS module
//! attaches to (`windows/`, `linux/`, `macos/`).

use std::sync::Arc;

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, ConnectionHealth,
    ConnectionHealthFuture, DnsControl, DnsSettings, FirewallControl, FirewallSettings,
    PlatformLeaseKey, RouteControl, RouteSettings,
};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use egrio_runtime::{PacketCapture, PacketCaptureOpen, PacketCaptureSettings};

use crate::client::ControlClient;
use crate::protocol::{ControlRequest, ControlResponse};

/// Egress state that follows the service-held TUN while a packet session is
/// open, shared with the Core's egress guard.
#[cfg(windows)]
pub type ServiceTunEgress = egrio_platform_windows::WindowsTunEgress;
#[cfg(target_os = "linux")]
pub type ServiceTunEgress = egrio_platform_linux::LinuxTunEgress;
#[cfg(target_os = "macos")]
pub type ServiceTunEgress = egrio_platform_macos::MacosTunEgress;

#[derive(Debug)]
pub struct ServicePlatform {
    client: Arc<ControlClient>,
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    tun_egress: Arc<ServiceTunEgress>,
}

impl ServicePlatform {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    pub fn new(client: Arc<ControlClient>, tun_egress: Arc<ServiceTunEgress>) -> Self {
        Self { client, tun_egress }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    pub fn new(client: Arc<ControlClient>) -> Self {
        Self { client }
    }

    pub(crate) fn client(&self) -> &ControlClient {
        &self.client
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    pub(crate) fn tun_egress(&self) -> &ServiceTunEgress {
        &self.tun_egress
    }
}

impl ConnectionHealth for ServicePlatform {
    fn wait_disconnected<'a>(&'a self) -> ConnectionHealthFuture<'a> {
        Box::pin(async move { self.client.wait_disconnected().await })
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const PACKET_CAPTURE: CapabilityKind = CapabilityKind::PacketCapture;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl PacketCapture for ServicePlatform {
    fn support(&self) -> CapabilitySupport {
        CapabilitySupport::Supported
    }

    fn reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        self.tun_reserved_addresses()
    }

    fn queue_limit(&self) -> usize {
        self.tun_queue_limit()
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let settings = serde_json::to_value(settings).map_err(|error| {
                capability_error(
                    PACKET_CAPTURE,
                    CapabilityErrorCode::InvalidRequest,
                    error.to_string(),
                )
            })?;
            let request = ControlRequest::Prepare {
                capability: PACKET_CAPTURE,
                settings,
            };
            let code = CapabilityErrorCode::ObserveFailed;
            match send(self.client(), request, PACKET_CAPTURE, code).await? {
                ControlResponse::Checkpoint(checkpoint)
                    if checkpoint.lease_key == PlatformLeaseKey::packet_capture() =>
                {
                    Ok(checkpoint)
                }
                response => Err(unexpected_response(
                    PACKET_CAPTURE,
                    "prepare",
                    code,
                    response,
                )),
            }
        })
    }

    fn open<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
        queues: usize,
    ) -> CapabilityFuture<'a, PacketCaptureOpen> {
        Box::pin(async move {
            let code = CapabilityErrorCode::ApplyFailed;
            #[cfg(target_os = "macos")]
            self.bind_egress_before_open()
                .map_err(|error| capability_error(PACKET_CAPTURE, code, error))?;
            let opened = async {
                let request = ControlRequest::OpenPacketCapture {
                    settings: settings.clone(),
                };
                let channel = match send(self.client(), request, PACKET_CAPTURE, code).await? {
                    ControlResponse::PacketChannel(channel) => channel,
                    response => {
                        return Err(unexpected_response(PACKET_CAPTURE, "open", code, response))
                    }
                };
                self.attach_packet_channel(channel, queues)
                    .map_err(|error| capability_error(PACKET_CAPTURE, code, error))
            }
            .await;
            // A tunnel that did not open leaves no binding behind; the
            // Runtime restores what the service may have opened.
            #[cfg(target_os = "macos")]
            if opened.is_err() {
                self.tun_egress().deactivate();
            }
            let queues = opened?;
            Ok(PacketCaptureOpen {
                queues,
                report: CapabilityOperationReport {
                    capability: PACKET_CAPTURE,
                    changed: true,
                    verified: true,
                },
            })
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            let request = ControlRequest::Observe {
                capability: PACKET_CAPTURE,
            };
            let code = CapabilityErrorCode::ObserveFailed;
            match send(self.client(), request, PACKET_CAPTURE, code).await? {
                ControlResponse::Observation(observation)
                    if observation.capability == PACKET_CAPTURE =>
                {
                    Ok(observation)
                }
                response => Err(unexpected_response(
                    PACKET_CAPTURE,
                    "observe",
                    code,
                    response,
                )),
            }
        })
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let request = ControlRequest::Restore {
                checkpoint: checkpoint.clone(),
            };
            let code = CapabilityErrorCode::RestoreFailed;
            match send(self.client(), request, PACKET_CAPTURE, code).await? {
                ControlResponse::Operation(report) if report.capability == PACKET_CAPTURE => {
                    self.tun_egress().deactivate();
                    Ok(report)
                }
                response => Err(unexpected_response(
                    PACKET_CAPTURE,
                    "restore",
                    code,
                    response,
                )),
            }
        })
    }

    /// The macOS tunnel installs its own routes and changes its exclusions
    /// in place.
    #[cfg(target_os = "macos")]
    fn update_excluded_prefixes<'a>(
        &'a self,
        prefixes: &'a [egrio_runtime::IpPrefix],
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let request = ControlRequest::UpdateExcludedPrefixes {
                prefixes: prefixes.to_vec(),
            };
            let code = CapabilityErrorCode::ApplyFailed;
            match send(self.client(), request, PACKET_CAPTURE, code).await? {
                ControlResponse::Operation(report) if report.capability == PACKET_CAPTURE => {
                    Ok(report)
                }
                response => Err(unexpected_response(
                    PACKET_CAPTURE,
                    "update exclusions",
                    code,
                    response,
                )),
            }
        })
    }
}

macro_rules! mutable_remote_capability {
    ($trait_name:ident, $settings:ty, $kind:expr) => {
        impl $trait_name for ServicePlatform {
            fn support(&self) -> CapabilitySupport {
                CapabilitySupport::Supported
            }

            fn prepare<'a>(
                &'a self,
                settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
                Box::pin(async move {
                    let response = send(
                        self.client(),
                        ControlRequest::Prepare {
                            capability: $kind,
                            settings: serde_json::to_value(settings).map_err(|error| {
                                capability_error(
                                    $kind,
                                    CapabilityErrorCode::InvalidRequest,
                                    error.to_string(),
                                )
                            })?,
                        },
                        $kind,
                        CapabilityErrorCode::ObserveFailed,
                    )
                    .await?;
                    match response {
                        ControlResponse::Checkpoint(checkpoint)
                            if checkpoint.lease_key == expected_lease_key($kind) =>
                        {
                            Ok(checkpoint)
                        }
                        response => Err(unexpected_response(
                            $kind,
                            "prepare",
                            CapabilityErrorCode::ObserveFailed,
                            response,
                        )),
                    }
                })
            }

            fn apply<'a>(
                &'a self,
                settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityOperationReport> {
                Box::pin(async move {
                    let response = send(
                        self.client(),
                        ControlRequest::Apply {
                            capability: $kind,
                            settings: serde_json::to_value(settings).map_err(|error| {
                                capability_error(
                                    $kind,
                                    CapabilityErrorCode::InvalidRequest,
                                    error.to_string(),
                                )
                            })?,
                        },
                        $kind,
                        CapabilityErrorCode::ApplyFailed,
                    )
                    .await?;
                    match response {
                        ControlResponse::Operation(report) if report.capability == $kind => {
                            Ok(report)
                        }
                        response => Err(unexpected_response(
                            $kind,
                            "apply",
                            CapabilityErrorCode::ApplyFailed,
                            response,
                        )),
                    }
                })
            }

            fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
                Box::pin(async move {
                    let response = send(
                        self.client(),
                        ControlRequest::Observe { capability: $kind },
                        $kind,
                        CapabilityErrorCode::ObserveFailed,
                    )
                    .await?;
                    match response {
                        ControlResponse::Observation(observation)
                            if observation.capability == $kind =>
                        {
                            Ok(observation)
                        }
                        response => Err(unexpected_response(
                            $kind,
                            "observe",
                            CapabilityErrorCode::ObserveFailed,
                            response,
                        )),
                    }
                })
            }

            fn restore<'a>(
                &'a self,
                checkpoint: &'a CapabilityCheckpoint,
            ) -> CapabilityFuture<'a, CapabilityOperationReport> {
                Box::pin(async move {
                    if checkpoint.lease_key != expected_lease_key($kind) {
                        return Err(capability_error(
                            $kind,
                            CapabilityErrorCode::InvalidRequest,
                            "checkpoint lease key does not match remote capability",
                        ));
                    }
                    let response = send(
                        self.client(),
                        ControlRequest::Restore {
                            checkpoint: checkpoint.clone(),
                        },
                        $kind,
                        CapabilityErrorCode::RestoreFailed,
                    )
                    .await?;
                    match response {
                        ControlResponse::Operation(report) if report.capability == $kind => {
                            Ok(report)
                        }
                        response => Err(unexpected_response(
                            $kind,
                            "restore",
                            CapabilityErrorCode::RestoreFailed,
                            response,
                        )),
                    }
                })
            }
        }
    };
}

mutable_remote_capability!(RouteControl, RouteSettings, CapabilityKind::Route);
mutable_remote_capability!(DnsControl, DnsSettings, CapabilityKind::Dns);
mutable_remote_capability!(FirewallControl, FirewallSettings, CapabilityKind::Firewall);

fn expected_lease_key(kind: CapabilityKind) -> PlatformLeaseKey {
    match kind {
        CapabilityKind::Route => PlatformLeaseKey::default_route(),
        CapabilityKind::Dns => PlatformLeaseKey::system_dns(),
        CapabilityKind::Firewall => PlatformLeaseKey::kill_switch(),
        _ => unreachable!("mutable remote macro only supports lease-backed capabilities"),
    }
}

async fn send(
    client: &ControlClient,
    request: ControlRequest,
    kind: CapabilityKind,
    code: CapabilityErrorCode,
) -> Result<ControlResponse, CapabilityError> {
    client
        .request(request)
        .await
        .map_err(|error| capability_error(kind, code, error.to_string()))
}

fn capability_error(
    kind: CapabilityKind,
    code: CapabilityErrorCode,
    message: impl Into<String>,
) -> CapabilityError {
    CapabilityError::new(kind, code, message)
}

fn unexpected_response(
    kind: CapabilityKind,
    operation: &str,
    code: CapabilityErrorCode,
    response: ControlResponse,
) -> CapabilityError {
    match response {
        ControlResponse::Error { message, .. } => capability_error(kind, code, message),
        response => capability_error(
            kind,
            CapabilityErrorCode::InvalidRequest,
            format!("unexpected {kind:?} {operation} response: {response:?}"),
        ),
    }
}
