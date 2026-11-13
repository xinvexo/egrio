//! The capability plans a transaction applies and restores, in lease order,
//! and the restore of one capability from its checkpoint.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MutableCapabilityPlan {
    PacketCapture(PacketCaptureSettings),
    SystemProxy(SystemProxySettings),
    Route(RouteSettings),
    Dns(DnsSettings),
    Firewall(FirewallSettings),
}

impl MutableCapabilityPlan {
    /// Builds the ordered capability plans, resolving spec-level endpoints —
    /// a system proxy referencing the Core listener resolves to the endpoint
    /// bound by the current generation (start order: the listener binds
    /// before any lease, checkpoint, or OS mutation).
    pub(super) fn from_spec(
        spec: &RuntimeSpec,
        core_listener: Option<SocketAddr>,
    ) -> Result<Vec<Self>, RuntimeSpecError> {
        let mut plans = Vec::new();
        if let Some(value) = &spec.platform.packet_capture {
            plans.push(Self::PacketCapture(value.clone()));
        }
        if let Some(value) = &spec.platform.firewall {
            plans.push(Self::Firewall(value.clone()));
        }
        if let Some(value) = &spec.platform.route {
            plans.push(Self::Route(value.clone()));
        }
        if let Some(value) = &spec.platform.dns {
            plans.push(Self::Dns(value.clone()));
        }
        if let Some(value) = &spec.platform.system_proxy {
            plans.push(Self::SystemProxy(value.resolve(core_listener)?));
        }
        Ok(plans)
    }

    pub(super) fn lease_key(&self) -> PlatformLeaseKey {
        match self {
            Self::PacketCapture(_) => PlatformLeaseKey::packet_capture(),
            Self::SystemProxy(_) => PlatformLeaseKey::system_proxy(),
            Self::Route(_) => PlatformLeaseKey::default_route(),
            Self::Dns(_) => PlatformLeaseKey::system_dns(),
            Self::Firewall(_) => PlatformLeaseKey::kill_switch(),
        }
    }

    pub(super) fn capability(&self) -> CapabilityKind {
        match self {
            Self::PacketCapture(_) => CapabilityKind::PacketCapture,
            Self::SystemProxy(_) => CapabilityKind::SystemProxy,
            Self::Route(_) => CapabilityKind::Route,
            Self::Dns(_) => CapabilityKind::Dns,
            Self::Firewall(_) => CapabilityKind::Firewall,
        }
    }

    pub(super) fn resource(&self) -> RuntimeResource {
        RuntimeResource::Platform {
            capability: self.capability(),
        }
    }

    /// Whether the resource lives in the platform session behind packet
    /// capture: packet capture, firewall, routes and DNS. The system proxy
    /// does not, so a lost session leaves it as committed.
    pub(super) fn lives_in_platform_session(&self) -> bool {
        !matches!(self, Self::SystemProxy(_))
    }

    pub(super) async fn prepare(
        &self,
        runtime: &Runtime,
    ) -> Result<CapabilityCheckpoint, CapabilityError> {
        let ports = &runtime.ports;
        let checkpoint = match self {
            Self::PacketCapture(settings) => {
                runtime.validate_capture_addresses()?;
                runtime.validate_excluded_prefixes(
                    crate::CapabilityKind::PacketCapture,
                    &settings.excluded_prefixes,
                )?;
                ports
                    .packet_capture
                    .as_ref()
                    .unwrap()
                    .prepare(settings)
                    .await
            }
            Self::SystemProxy(settings) => {
                ports.system_proxy.as_ref().unwrap().prepare(settings).await
            }
            Self::Route(settings) => {
                runtime.validate_excluded_prefixes(
                    crate::CapabilityKind::Route,
                    &settings.excluded_prefixes,
                )?;
                ports.route.as_ref().unwrap().prepare(settings).await
            }
            Self::Dns(settings) => ports.dns.as_ref().unwrap().prepare(settings).await,
            Self::Firewall(settings) => ports.firewall.as_ref().unwrap().prepare(settings).await,
        }?;
        let expected = self.lease_key();
        if checkpoint.lease_key != expected {
            return Err(self.invalid_checkpoint(format!(
                "adapter prepared checkpoint for {}:{}, expected {}:{}",
                checkpoint.lease_key.capability(),
                checkpoint.lease_key.scope(),
                expected.capability(),
                expected.scope(),
            )));
        }
        if checkpoint.schema_version == 0 {
            return Err(
                self.invalid_checkpoint("adapter prepared an unversioned capability checkpoint")
            );
        }
        Ok(checkpoint)
    }

    pub(super) fn invalid_checkpoint(&self, message: impl Into<String>) -> CapabilityError {
        CapabilityError::new(
            self.capability(),
            crate::CapabilityErrorCode::InvalidRequest,
            message,
        )
    }

    pub(super) async fn apply(
        &self,
        runtime: &Arc<Runtime>,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        let ports = &runtime.ports;
        match self {
            Self::PacketCapture(settings) => runtime.start_packet_capture(settings).await,
            Self::SystemProxy(settings) => {
                ports.system_proxy.as_ref().unwrap().apply(settings).await
            }
            Self::Route(settings) => ports.route.as_ref().unwrap().apply(settings).await,
            Self::Dns(settings) => ports.dns.as_ref().unwrap().apply(settings).await,
            Self::Firewall(settings) => ports.firewall.as_ref().unwrap().apply(settings).await,
        }
    }
}

#[derive(Debug)]
pub(super) enum CapabilityUndo {
    Restore(CapabilityCheckpoint),
    Apply(MutableCapabilityPlan),
    /// Gives the open capture back these settings' exclusions.
    UpdateCapture(PacketCaptureSettings),
}

impl CapabilityUndo {
    pub(super) fn resource(&self) -> RuntimeResource {
        match self {
            Self::Restore(checkpoint) => resource_for_key(&checkpoint.lease_key),
            Self::Apply(plan) => plan.resource(),
            Self::UpdateCapture(_) => RuntimeResource::Platform {
                capability: CapabilityKind::PacketCapture,
            },
        }
    }
}

#[derive(Debug)]
pub(super) enum ReloadLeaseMutation {
    None,
    Acquired,
    Expanded {
        previous_keys: Vec<PlatformLeaseKey>,
    },
}

pub(super) fn lease_keys(spec: &RuntimeSpec) -> Vec<PlatformLeaseKey> {
    spec.lease_request()
        .expect("validated runtime spec lease request")
        .map(|request| request.keys().to_vec())
        .unwrap_or_default()
}

pub(super) fn union_lease_keys(
    current: &[PlatformLeaseKey],
    next: &[PlatformLeaseKey],
) -> Vec<PlatformLeaseKey> {
    current
        .iter()
        .chain(next)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn resource_change(
    plan: &MutableCapabilityPlan,
    outcome: RuntimeResourceOutcome,
) -> RuntimeResourceChange {
    RuntimeResourceChange::new(plan.resource(), outcome)
}

pub(super) fn checkpoint_contract_error(
    capability: CapabilityKind,
    context: &str,
    error: RecoveryCheckpointError,
) -> CapabilityError {
    CapabilityError::new(
        capability,
        crate::CapabilityErrorCode::InvalidRequest,
        format!("{context}: {error}"),
    )
}

pub(super) fn resource_for_key(key: &PlatformLeaseKey) -> RuntimeResource {
    RuntimeResource::Platform {
        capability: capability_kind_for_key(key),
    }
}

pub(super) fn capability_kind_for_key(key: &PlatformLeaseKey) -> CapabilityKind {
    if key == &PlatformLeaseKey::packet_capture() {
        CapabilityKind::PacketCapture
    } else if key == &PlatformLeaseKey::system_proxy() {
        CapabilityKind::SystemProxy
    } else if key == &PlatformLeaseKey::default_route() {
        CapabilityKind::Route
    } else if key == &PlatformLeaseKey::system_dns() {
        CapabilityKind::Dns
    } else if key == &PlatformLeaseKey::kill_switch() {
        CapabilityKind::Firewall
    } else {
        CapabilityKind::Unknown
    }
}

pub(super) fn capability_rank(key: &PlatformLeaseKey) -> u8 {
    match capability_kind_for_key(key) {
        CapabilityKind::PacketCapture => 1,
        CapabilityKind::Firewall => 2,
        CapabilityKind::Route => 3,
        CapabilityKind::Dns => 4,
        CapabilityKind::SystemProxy => 5,
        _ => 6,
    }
}

pub(super) async fn restore_checkpoint(
    ports: &RuntimePorts,
    checkpoint: &CapabilityCheckpoint,
) -> Result<CapabilityOperationReport, CapabilityError> {
    // The recovery path reconciles checkpoints read from disk with no prior
    // port validation, so a persisted capability whose port this assembly
    // does not wire (an older app version, a changed assembly, or a shared
    // checkpoint directory) must fail closed with an error, not panic on an
    // `unwrap`. Absent ports surface as `RestoreFailed`, which keeps the
    // lease `recovery-required` for a retry against a matching assembly.
    pub(super) fn missing_port(kind: CapabilityKind) -> CapabilityError {
        CapabilityError::new(
            kind,
            crate::CapabilityErrorCode::RestoreFailed,
            "checkpoint names a capability port that is not assembled in this runtime",
        )
    }
    if checkpoint.lease_key == PlatformLeaseKey::system_proxy() {
        ports
            .system_proxy
            .as_ref()
            .ok_or_else(|| missing_port(CapabilityKind::SystemProxy))?
            .restore(checkpoint)
            .await
    } else if checkpoint.lease_key == PlatformLeaseKey::default_route() {
        ports
            .route
            .as_ref()
            .ok_or_else(|| missing_port(CapabilityKind::Route))?
            .restore(checkpoint)
            .await
    } else if checkpoint.lease_key == PlatformLeaseKey::system_dns() {
        ports
            .dns
            .as_ref()
            .ok_or_else(|| missing_port(CapabilityKind::Dns))?
            .restore(checkpoint)
            .await
    } else if checkpoint.lease_key == PlatformLeaseKey::kill_switch() {
        ports
            .firewall
            .as_ref()
            .ok_or_else(|| missing_port(CapabilityKind::Firewall))?
            .restore(checkpoint)
            .await
    } else if checkpoint.lease_key == PlatformLeaseKey::packet_capture() {
        ports
            .packet_capture
            .as_ref()
            .ok_or_else(|| missing_port(CapabilityKind::PacketCapture))?
            .restore(checkpoint)
            .await
    } else {
        Err(CapabilityError::new(
            CapabilityKind::Unknown,
            crate::CapabilityErrorCode::InvalidRequest,
            "checkpoint has no mutable capability port",
        ))
    }
}
