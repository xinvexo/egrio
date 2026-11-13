//! Linux Route, DNS and Firewall capabilities over the shared TUN session.
//! Each validates its own settings and applies one resource group; DNS
//! depends on Route owning the virtual resolver's host route.

use crate::config::LINUX_TUN_VIRTUAL_DNS;
use crate::session::{capability_error, Control, LinuxTunSession};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, DnsControl, DnsSettings,
    FirewallControl, FirewallSettings, RouteControl, RouteSettings,
};
use std::net::IpAddr;
use std::sync::Arc;

fn support(enabled: bool) -> CapabilitySupport {
    if cfg!(target_os = "linux") && enabled {
        CapabilitySupport::Supported
    } else {
        CapabilitySupport::Unsupported {
            reason: "Linux TUN capability is disabled or this host is not Linux".into(),
        }
    }
}

fn invalid(control: Control, message: &str) -> CapabilityError {
    capability_error(control.kind(), CapabilityErrorCode::InvalidRequest, message)
}

async fn observation(
    session: &LinuxTunSession,
    control: Control,
) -> Result<CapabilityObservation, CapabilityError> {
    let _lifecycle = session.lifecycle().await;
    Ok(CapabilityObservation {
        capability: control.kind(),
        active: session.observe_control(control).await?,
        verified: true,
    })
}

async fn restore(
    session: &LinuxTunSession,
    control: Control,
    checkpoint: &CapabilityCheckpoint,
) -> Result<CapabilityOperationReport, CapabilityError> {
    let _lifecycle = session.lifecycle().await;
    session.restore_control(control, checkpoint).await
}

/// Policy routing into the TUN plus the virtual resolver's host route.
#[derive(Debug)]
pub struct LinuxTunRouteControl {
    session: Arc<LinuxTunSession>,
}

impl LinuxTunRouteControl {
    pub(crate) fn new(session: Arc<LinuxTunSession>) -> Self {
        Self { session }
    }

    fn validate(settings: &RouteSettings) -> Result<(), CapabilityError> {
        settings
            .validate()
            .map_err(|message| invalid(Control::Route, &message))
    }
}

impl RouteControl for LinuxTunRouteControl {
    fn support(&self) -> CapabilitySupport {
        support(true)
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a RouteSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            Self::validate(settings)?;
            self.session.prepare_control(
                Control::Route,
                settings.default_route,
                &settings.excluded_prefixes,
                &[],
            )
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a RouteSettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            Self::validate(settings)?;
            self.session
                .apply_control(
                    Control::Route,
                    settings.default_route,
                    &settings.excluded_prefixes,
                    &[],
                )
                .await
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(observation(&self.session, Control::Route))
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(restore(&self.session, Control::Route, checkpoint))
    }
}

/// systemd-resolved link DNS pointing at the virtual resolver.
#[derive(Debug)]
pub struct LinuxTunDnsControl {
    session: Arc<LinuxTunSession>,
}

impl LinuxTunDnsControl {
    pub(crate) fn new(session: Arc<LinuxTunSession>) -> Self {
        Self { session }
    }

    fn validate(&self, settings: &DnsSettings) -> Result<(), CapabilityError> {
        let virtual_dns = [IpAddr::V4(LINUX_TUN_VIRTUAL_DNS)];
        if !self.session.config.capture_dns
            || !settings.search_domains.is_empty()
            || (!settings.servers.is_empty() && settings.servers != virtual_dns)
        {
            return Err(invalid(
                Control::Dns,
                "Linux TUN DNS uses its virtual resolver with route-only domain ~.; DNS capture must be enabled",
            ));
        }
        Ok(())
    }
}

impl DnsControl for LinuxTunDnsControl {
    fn support(&self) -> CapabilitySupport {
        support(self.session.config.capture_dns)
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a DnsSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            self.validate(settings)?;
            if !self.session.route_owned() {
                return Err(invalid(
                    Control::Dns,
                    "Linux TUN DNS requires RouteControl to own its virtual DNS host route",
                ));
            }
            self.session.prepare_control(Control::Dns, false, &[], &[])
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a DnsSettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            self.validate(settings)?;
            self.session
                .apply_control(Control::Dns, false, &[], &[])
                .await
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(observation(&self.session, Control::Dns))
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(restore(&self.session, Control::Dns, checkpoint))
    }
}

/// The nftables fail-closed kill switch.
#[derive(Debug)]
pub struct LinuxTunFirewallControl {
    session: Arc<LinuxTunSession>,
}

impl LinuxTunFirewallControl {
    pub(crate) fn new(session: Arc<LinuxTunSession>) -> Self {
        Self { session }
    }

    fn validate(&self, settings: &FirewallSettings) -> Result<(), CapabilityError> {
        let config = &self.session.config;
        if !config.kill_switch || !settings.kill_switch || config.allow_lan != settings.allow_lan {
            return Err(invalid(
                Control::Firewall,
                "Linux TUN firewall settings must match its enabled kill switch and LAN policy",
            ));
        }
        Ok(())
    }
}

impl FirewallControl for LinuxTunFirewallControl {
    fn support(&self) -> CapabilitySupport {
        support(self.session.config.kill_switch)
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a FirewallSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            self.validate(settings)?;
            self.session.prepare_control(
                Control::Firewall,
                false,
                &settings.excluded_prefixes,
                &settings.fake_ip_prefixes,
            )
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a FirewallSettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            let _lifecycle = self.session.lifecycle().await;
            self.validate(settings)?;
            self.session
                .apply_control(
                    Control::Firewall,
                    false,
                    &settings.excluded_prefixes,
                    &settings.fake_ip_prefixes,
                )
                .await
        })
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(observation(&self.session, Control::Firewall))
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(restore(&self.session, Control::Firewall, checkpoint))
    }
}
