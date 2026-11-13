//! Linux PacketCapture capability: prepares, opens and restores the
//! session's `/dev/net/tun` device. Runtime runs the shared packet data
//! plane over the returned device.

use crate::network_state::TunCheckpoint;
use crate::session::{capability_error, report, LinuxTunSession, SCHEMA_VERSION};
use crate::LinuxTunConfig;
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, PacketCapture,
    PacketCaptureOpen, PacketCaptureSettings, PacketCaptureSource, PlatformLeaseKey,
};
use std::sync::Arc;

/// What the service hands the desktop for a TUN it opened on the desktop
/// user's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxUserTun {
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
    /// The physical resolvers read before the DNS capability applies.
    pub physical_dns_servers: Vec<std::net::SocketAddr>,
}

#[derive(Debug)]
pub struct LinuxTunCapture {
    session: Arc<LinuxTunSession>,
}

const KIND: CapabilityKind = CapabilityKind::PacketCapture;

fn error(code: CapabilityErrorCode, message: impl Into<String>) -> CapabilityError {
    capability_error(KIND, code, message)
}

impl LinuxTunCapture {
    pub(crate) fn new(session: Arc<LinuxTunSession>) -> Self {
        Self { session }
    }

    pub(crate) fn config(&self) -> &LinuxTunConfig {
        &self.session.config
    }

    pub(crate) fn egress(&self) -> Arc<crate::LinuxTunEgress> {
        self.session.egress.clone()
    }

    /// Opens the TUN for another user's process (the Linux service on the
    /// desktop's behalf): a persistent device owned by `uid` that the user
    /// attaches to by name. The checkpoint discipline is `open`'s; the
    /// physical resolvers go to the caller instead of this process's egress.
    pub async fn open_for_user(
        &self,
        settings: &PacketCaptureSettings,
        uid: u32,
    ) -> Result<LinuxUserTun, CapabilityError> {
        let _lifecycle = self.session.lifecycle().await;
        let checkpoint = self.activate(settings)?;
        let config = checkpoint.config.clone();
        let backend = self.session.backend.clone();
        let (physical_dns_servers, interface_index) = tokio::task::spawn_blocking(move || {
            // Resolvers first: the DNS capability applies after capture.
            let dns_servers = backend.physical_dns_servers()?;
            Ok::<_, String>((dns_servers, backend.open_for_user(&checkpoint, uid)?))
        })
        .await
        .map_err(|e| error(CapabilityErrorCode::ApplyFailed, e.to_string()))?
        .map_err(|e| error(CapabilityErrorCode::ApplyFailed, e))?;
        Ok(LinuxUserTun {
            interface_name: config.interface_name,
            interface_index,
            mtu: config.mtu,
            physical_dns_servers,
        })
    }

    /// Validates `settings` against the prepared checkpoint and moves it to
    /// active before the first OS mutation.
    fn activate(&self, settings: &PacketCaptureSettings) -> Result<TunCheckpoint, CapabilityError> {
        self.validate(settings)?;
        self.session.activate(|checkpoint| {
            if checkpoint.install_default_route != settings.install_default_route
                || checkpoint.config.mtu != settings.mtu
            {
                return Err(error(
                    CapabilityErrorCode::InvalidRequest,
                    "Linux TUN settings changed after prepare",
                ));
            }
            Ok(())
        })
    }

    fn validate(&self, settings: &PacketCaptureSettings) -> Result<(), CapabilityError> {
        if settings.source != PacketCaptureSource::Tun
            || settings.install_dns
            || settings.install_default_route
        {
            return Err(error(
                CapabilityErrorCode::InvalidRequest,
                "Linux capture requires TUN source; DNS and routes are declared through separate capabilities",
            ));
        }
        if settings.mtu != self.session.config.mtu {
            return Err(error(
                CapabilityErrorCode::InvalidRequest,
                "Linux TUN request MTU differs from the configured device MTU",
            ));
        }
        Ok(())
    }
}

impl PacketCapture for LinuxTunCapture {
    fn support(&self) -> CapabilitySupport {
        if cfg!(target_os = "linux") {
            CapabilitySupport::Supported
        } else {
            CapabilitySupport::Unsupported {
                reason: "Linux TUN is only available on Linux".into(),
            }
        }
    }

    fn reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        crate::linux_tun_reserved_addresses()
    }

    fn queue_limit(&self) -> usize {
        crate::LINUX_TUN_MAX_QUEUES
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            self.validate(settings)?;
            if self.session.active().is_some() {
                return Err(error(
                    CapabilityErrorCode::Conflict,
                    "Linux TUN is active or still needs recovery",
                ));
            }
            let checkpoint = TunCheckpoint {
                config: self.session.config.clone(),
                install_default_route: settings.install_default_route,
                ownership: format!("egrio:{}", uuid::Uuid::new_v4().simple()),
                fake_ip_prefixes: Vec::new(),
                excluded_prefixes: Vec::new(),
                applied: false,
                ipv4_only: !self.session.backend.new_interfaces_carry_ipv6(),
            };
            let backend = self.session.backend.clone();
            let prepared = checkpoint.clone();
            tokio::task::spawn_blocking(move || backend.prepare(&prepared))
                .await
                .map_err(|e| error(CapabilityErrorCode::ObserveFailed, e.to_string()))?
                .map_err(|e| error(CapabilityErrorCode::Conflict, e))?;
            self.session.set_prepared(checkpoint.clone());
            Ok(CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::packet_capture(),
                schema_version: SCHEMA_VERSION,
                payload: serde_json::to_value(checkpoint)
                    .map_err(|e| error(CapabilityErrorCode::ApplyFailed, e.to_string()))?,
                rollback_payload: None,
            })
        })
    }

    fn open<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
        queues: usize,
    ) -> CapabilityFuture<'a, PacketCaptureOpen> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            let checkpoint = self.activate(settings)?;
            let backend = self.session.backend.clone();
            let (dns_servers, queues) = tokio::task::spawn_blocking(move || {
                // Resolvers first: the DNS capability applies after capture.
                let dns_servers = backend.physical_dns_servers()?;
                Ok::<_, String>((dns_servers, backend.open(&checkpoint, queues)?))
            })
            .await
            .map_err(|e| error(CapabilityErrorCode::ApplyFailed, e.to_string()))?
            .map_err(|e| error(CapabilityErrorCode::ApplyFailed, e))?;
            let ipv6 = crate::linux_interface_carries_ipv6(&self.session.config.interface_name);
            self.session.egress.activate(dns_servers, ipv6);
            Ok(PacketCaptureOpen {
                queues,
                report: report(KIND),
            })
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            let Some(checkpoint) = self.session.active() else {
                return Ok(CapabilityObservation {
                    capability: KIND,
                    active: false,
                    verified: true,
                });
            };
            let backend = self.session.backend.clone();
            let active = tokio::task::spawn_blocking(move || backend.observe(&checkpoint))
                .await
                .map_err(|e| error(CapabilityErrorCode::ObserveFailed, e.to_string()))?
                .map_err(|e| error(CapabilityErrorCode::ObserveFailed, e))?;
            Ok(CapabilityObservation {
                capability: KIND,
                active,
                verified: true,
            })
        })
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            let checkpoint =
                self.session
                    .decode(checkpoint, KIND, PlatformLeaseKey::packet_capture())?;
            let backend = self.session.backend.clone();
            let restore = checkpoint.clone();
            tokio::task::spawn_blocking(move || backend.restore(&restore))
                .await
                .map_err(|e| error(CapabilityErrorCode::RestoreFailed, e.to_string()))?
                .map_err(|e| error(CapabilityErrorCode::RestoreFailed, e))?;
            self.session.release(&checkpoint.ownership);
            self.session.egress.deactivate();
            Ok(report(KIND))
        })
    }
}
