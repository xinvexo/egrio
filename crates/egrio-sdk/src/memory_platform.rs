use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use egrio_core::{PacketDevice, PacketInterest, PacketReady, PacketSend};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, DnsControl, DnsSettings,
    FirewallControl, FirewallSettings, IpPrefix, PacketCapture, PacketCaptureOpen,
    PacketCaptureSettings, PlatformLeaseKey, RouteControl, RouteSettings, SystemProxyControl,
    SystemProxySettings,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Notify;

#[derive(Debug)]
struct MutableState<T> {
    current: Option<T>,
}

struct PacketCaptureState {
    current: Option<PacketCaptureSettings>,
    inbound: Arc<PacketQueue>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// The in-memory "TUN": emitted packets wait here and wake the device.
#[derive(Debug, Default)]
struct PacketQueue {
    packets: Mutex<VecDeque<Vec<u8>>>,
    pushed: Notify,
}

impl fmt::Debug for PacketCaptureState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketCaptureState")
            .field("current", &self.current)
            .field(
                "inbound",
                &self.inbound.packets.lock().expect("inbound mutex").len(),
            )
            .field(
                "outbound",
                &self.outbound.lock().expect("outbound mutex").len(),
            )
            .finish()
    }
}

#[derive(Debug)]
struct InMemoryPacketDevice {
    inbound: Arc<PacketQueue>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PacketDevice for InMemoryPacketDevice {
    fn name(&self) -> &str {
        "memory-packet-device"
    }

    fn try_recv(&mut self) -> Result<Option<egrio_core::ReceivedPacket>, String> {
        Ok(self
            .inbound
            .packets
            .lock()
            .expect("inbound mutex")
            .pop_front()
            .map(Into::into))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        self.outbound
            .lock()
            .expect("outbound mutex")
            .push(packet.to_vec());
        Ok(PacketSend::Sent)
    }

    fn ready(&mut self, _: PacketInterest) -> PacketReady<'_> {
        let inbound = Arc::clone(&self.inbound);
        Box::pin(async move {
            // `notify_one` keeps a permit, so an emit racing this check wakes us.
            if inbound.packets.lock().expect("inbound mutex").is_empty() {
                inbound.pushed.notified().await;
            }
            Ok(())
        })
    }
}

impl<T> Default for MutableState<T> {
    fn default() -> Self {
        Self { current: None }
    }
}

pub struct InMemoryPlatform {
    unsupported: Mutex<BTreeMap<CapabilityKind, String>>,
    apply_failures: Mutex<BTreeMap<CapabilityKind, String>>,
    unverified_applies: Mutex<BTreeSet<CapabilityKind>>,
    restore_failures: Mutex<BTreeMap<CapabilityKind, String>>,
    unverified_restores: Mutex<BTreeSet<CapabilityKind>>,
    packet_capture: Mutex<PacketCaptureState>,
    system_proxy: Mutex<MutableState<SystemProxySettings>>,
    route: Mutex<MutableState<RouteSettings>>,
    dns: Mutex<MutableState<DnsSettings>>,
    firewall: Mutex<MutableState<FirewallSettings>>,
    reserved_addresses: Mutex<Vec<std::net::IpAddr>>,
    event_log: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl fmt::Debug for InMemoryPlatform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryPlatform")
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryPlatform {
    fn default() -> Self {
        Self {
            unsupported: Mutex::new(BTreeMap::new()),
            apply_failures: Mutex::new(BTreeMap::new()),
            unverified_applies: Mutex::new(BTreeSet::new()),
            restore_failures: Mutex::new(BTreeMap::new()),
            unverified_restores: Mutex::new(BTreeSet::new()),
            packet_capture: Mutex::new(PacketCaptureState {
                current: None,
                inbound: Arc::default(),
                outbound: Arc::new(Mutex::new(Vec::new())),
            }),
            system_proxy: Mutex::new(MutableState::default()),
            route: Mutex::new(MutableState::default()),
            dns: Mutex::new(MutableState::default()),
            firewall: Mutex::new(MutableState::default()),
            reserved_addresses: Mutex::new(Vec::new()),
            event_log: None,
        }
    }
}

impl InMemoryPlatform {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_event_log(event_log: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            event_log: Some(event_log),
            ..Self::default()
        }
    }

    /// Addresses the in-memory TUN declares as its own.
    pub fn set_reserved_addresses(&self, addresses: Vec<std::net::IpAddr>) {
        *self
            .reserved_addresses
            .lock()
            .expect("reserved addresses mutex") = addresses;
    }

    pub fn set_unsupported(&self, capability: CapabilityKind, reason: impl Into<String>) {
        self.unsupported
            .lock()
            .expect("unsupported mutex")
            .insert(capability, reason.into());
    }

    pub fn fail_next_apply(&self, capability: CapabilityKind, message: impl Into<String>) {
        self.apply_failures
            .lock()
            .expect("apply failures mutex")
            .insert(capability, message.into());
    }

    pub fn unverify_next_apply(&self, capability: CapabilityKind) {
        self.unverified_applies
            .lock()
            .expect("unverified applies mutex")
            .insert(capability);
    }

    pub fn fail_next_restore(&self, capability: CapabilityKind, message: impl Into<String>) {
        self.restore_failures
            .lock()
            .expect("restore failures mutex")
            .insert(capability, message.into());
    }

    pub fn unverify_next_restore(&self, capability: CapabilityKind) {
        self.unverified_restores
            .lock()
            .expect("unverified restores mutex")
            .insert(capability);
    }

    /// Delivers whole IP packets as if the OS captured them.
    pub fn emit_packets(&self, packets: Vec<Vec<u8>>) -> Result<usize, CapabilityError> {
        let state = self.packet_capture.lock().expect("packet capture mutex");
        if state.current.is_none() {
            return Err(CapabilityError::new(
                CapabilityKind::PacketCapture,
                CapabilityErrorCode::Conflict,
                "packet capture is not active",
            ));
        }
        let count = packets.len();
        state
            .inbound
            .packets
            .lock()
            .expect("inbound mutex")
            .extend(packets);
        state.inbound.pushed.notify_one();
        Ok(count)
    }

    /// The settings the capture is open with.
    #[must_use]
    pub fn packet_capture_settings(&self) -> Option<PacketCaptureSettings> {
        self.packet_capture
            .lock()
            .expect("packet capture mutex")
            .current
            .clone()
    }

    #[must_use]
    pub fn written_packets(&self) -> Vec<Vec<u8>> {
        self.packet_capture
            .lock()
            .expect("packet capture mutex")
            .outbound
            .lock()
            .expect("outbound mutex")
            .clone()
    }

    fn record_event(&self, event: &'static str) {
        if let Some(log) = &self.event_log {
            log.lock().expect("event log mutex").push(event);
        }
    }

    fn support_for(&self, capability: CapabilityKind) -> CapabilitySupport {
        match self
            .unsupported
            .lock()
            .expect("unsupported mutex")
            .get(&capability)
            .cloned()
        {
            Some(reason) => CapabilitySupport::Unsupported { reason },
            None => CapabilitySupport::Supported,
        }
    }

    fn ensure_supported(&self, capability: CapabilityKind) -> Result<(), CapabilityError> {
        match self.support_for(capability) {
            CapabilitySupport::Supported => Ok(()),
            CapabilitySupport::Unsupported { reason } => {
                Err(CapabilityError::unsupported(capability, reason))
            }
        }
    }

    fn take_apply_failure(&self, capability: CapabilityKind) -> Option<String> {
        self.apply_failures
            .lock()
            .expect("apply failures mutex")
            .remove(&capability)
    }

    fn take_unverified_apply(&self, capability: CapabilityKind) -> bool {
        self.unverified_applies
            .lock()
            .expect("unverified applies mutex")
            .remove(&capability)
    }

    fn take_restore_failure(&self, capability: CapabilityKind) -> Option<String> {
        self.restore_failures
            .lock()
            .expect("restore failures mutex")
            .remove(&capability)
    }

    fn take_unverified_restore(&self, capability: CapabilityKind) -> bool {
        self.unverified_restores
            .lock()
            .expect("unverified restores mutex")
            .remove(&capability)
    }
}

fn lease_key(kind: CapabilityKind) -> PlatformLeaseKey {
    match kind {
        CapabilityKind::PacketCapture => PlatformLeaseKey::packet_capture(),
        CapabilityKind::SystemProxy => PlatformLeaseKey::system_proxy(),
        CapabilityKind::Route => PlatformLeaseKey::default_route(),
        CapabilityKind::Dns => PlatformLeaseKey::system_dns(),
        CapabilityKind::Firewall => PlatformLeaseKey::kill_switch(),
        _ => unreachable!("only mutable capabilities have checkpoints"),
    }
}

fn prepare_state<T>(
    state: &Mutex<MutableState<T>>,
    kind: CapabilityKind,
) -> Result<CapabilityCheckpoint, CapabilityError>
where
    T: Serialize,
{
    let state = state.lock().expect("memory capability mutex");
    let payload = serde_json::to_value(&state.current).map_err(|error| {
        CapabilityError::new(kind, CapabilityErrorCode::ObserveFailed, error.to_string())
    })?;
    Ok(CapabilityCheckpoint {
        lease_key: lease_key(kind),
        schema_version: 1,
        payload,
        rollback_payload: None,
    })
}

fn apply_state<T>(
    state: &Mutex<MutableState<T>>,
    kind: CapabilityKind,
    settings: &T,
) -> CapabilityOperationReport
where
    T: Clone + PartialEq,
{
    let mut state = state.lock().expect("memory capability mutex");
    let changed = state.current.as_ref() != Some(settings);
    state.current = Some(settings.clone());
    CapabilityOperationReport {
        capability: kind,
        changed,
        verified: true,
    }
}

fn observe_state<T>(state: &Mutex<MutableState<T>>, kind: CapabilityKind) -> CapabilityObservation {
    CapabilityObservation {
        capability: kind,
        active: state
            .lock()
            .expect("memory capability mutex")
            .current
            .is_some(),
        verified: true,
    }
}

fn restore_state<T>(
    state: &Mutex<MutableState<T>>,
    kind: CapabilityKind,
    checkpoint: &CapabilityCheckpoint,
) -> Result<CapabilityOperationReport, CapabilityError>
where
    T: DeserializeOwned + PartialEq,
{
    if checkpoint.lease_key != lease_key(kind) || checkpoint.schema_version != 1 {
        return Err(CapabilityError::new(
            kind,
            CapabilityErrorCode::InvalidRequest,
            "checkpoint does not match capability contract",
        ));
    }
    let baseline =
        serde_json::from_value::<Option<T>>(checkpoint.payload.clone()).map_err(|error| {
            CapabilityError::new(kind, CapabilityErrorCode::InvalidRequest, error.to_string())
        })?;
    let mut state = state.lock().expect("memory capability mutex");
    let changed = state.current != baseline;
    state.current = baseline;
    Ok(CapabilityOperationReport {
        capability: kind,
        changed,
        verified: true,
    })
}

macro_rules! impl_mutable_capability {
    ($trait_name:ident, $field:ident, $settings:ty, $kind:expr) => {
        impl $trait_name for InMemoryPlatform {
            fn support(&self) -> CapabilitySupport {
                self.support_for($kind)
            }
            fn prepare<'a>(
                &'a self,
                _settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
                Box::pin(async move {
                    self.ensure_supported($kind)?;
                    prepare_state(&self.$field, $kind)
                })
            }
            fn apply<'a>(
                &'a self,
                settings: &'a $settings,
            ) -> CapabilityFuture<'a, CapabilityOperationReport> {
                Box::pin(async move {
                    self.ensure_supported($kind)?;
                    let mut report = apply_state(&self.$field, $kind, settings);
                    if let Some(message) = self.take_apply_failure($kind) {
                        return Err(CapabilityError::new(
                            $kind,
                            CapabilityErrorCode::ApplyFailed,
                            message,
                        ));
                    }
                    if self.take_unverified_apply($kind) {
                        report.verified = false;
                    }
                    Ok(report)
                })
            }
            fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
                Box::pin(async move {
                    self.ensure_supported($kind)?;
                    Ok(observe_state(&self.$field, $kind))
                })
            }
            fn restore<'a>(
                &'a self,
                checkpoint: &'a CapabilityCheckpoint,
            ) -> CapabilityFuture<'a, CapabilityOperationReport> {
                Box::pin(async move {
                    self.ensure_supported($kind)?;
                    if let Some(message) = self.take_restore_failure($kind) {
                        return Err(CapabilityError::new(
                            $kind,
                            CapabilityErrorCode::RestoreFailed,
                            message,
                        ));
                    }
                    let mut report = restore_state(&self.$field, $kind, checkpoint)?;
                    if self.take_unverified_restore($kind) {
                        report.verified = false;
                    }
                    Ok(report)
                })
            }
        }
    };
}

impl_mutable_capability!(
    SystemProxyControl,
    system_proxy,
    SystemProxySettings,
    CapabilityKind::SystemProxy
);
impl_mutable_capability!(RouteControl, route, RouteSettings, CapabilityKind::Route);
impl_mutable_capability!(DnsControl, dns, DnsSettings, CapabilityKind::Dns);
impl_mutable_capability!(
    FirewallControl,
    firewall,
    FirewallSettings,
    CapabilityKind::Firewall
);

impl PacketCapture for InMemoryPlatform {
    fn support(&self) -> CapabilitySupport {
        self.support_for(CapabilityKind::PacketCapture)
    }
    fn reserved_addresses(&self) -> Vec<std::net::IpAddr> {
        self.reserved_addresses
            .lock()
            .expect("reserved addresses mutex")
            .clone()
    }
    fn prepare<'a>(
        &'a self,
        _settings: &'a PacketCaptureSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            self.ensure_supported(CapabilityKind::PacketCapture)?;
            self.record_event("capture.prepare");
            let state = self.packet_capture.lock().expect("packet capture mutex");
            let payload = serde_json::to_value(&state.current).map_err(|error| {
                CapabilityError::new(
                    CapabilityKind::PacketCapture,
                    CapabilityErrorCode::ObserveFailed,
                    error.to_string(),
                )
            })?;
            Ok(CapabilityCheckpoint {
                lease_key: PlatformLeaseKey::packet_capture(),
                schema_version: 1,
                payload,
                rollback_payload: None,
            })
        })
    }
    fn open<'a>(
        &'a self,
        settings: &'a PacketCaptureSettings,
        _queues: usize,
    ) -> CapabilityFuture<'a, PacketCaptureOpen> {
        Box::pin(async move {
            self.ensure_supported(CapabilityKind::PacketCapture)?;
            self.record_event("capture.open");
            let mut state = self.packet_capture.lock().expect("packet capture mutex");
            let changed = state.current.as_ref() != Some(settings);
            state.current = Some(settings.clone());
            Ok(PacketCaptureOpen {
                queues: vec![Box::new(InMemoryPacketDevice {
                    inbound: state.inbound.clone(),
                    outbound: state.outbound.clone(),
                })],
                report: CapabilityOperationReport {
                    capability: CapabilityKind::PacketCapture,
                    changed,
                    verified: true,
                },
            })
        })
    }
    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        Box::pin(async move {
            self.ensure_supported(CapabilityKind::PacketCapture)?;
            let state = self.packet_capture.lock().expect("packet capture mutex");
            Ok(CapabilityObservation {
                capability: CapabilityKind::PacketCapture,
                active: state.current.is_some(),
                verified: true,
            })
        })
    }
    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            self.ensure_supported(CapabilityKind::PacketCapture)?;
            self.record_event("capture.restore");
            let baseline =
                serde_json::from_value::<Option<PacketCaptureSettings>>(checkpoint.payload.clone())
                    .map_err(|error| {
                        CapabilityError::new(
                            CapabilityKind::PacketCapture,
                            CapabilityErrorCode::InvalidRequest,
                            error.to_string(),
                        )
                    })?;
            if checkpoint.lease_key != PlatformLeaseKey::packet_capture()
                || checkpoint.schema_version != 1
            {
                return Err(CapabilityError::new(
                    CapabilityKind::PacketCapture,
                    CapabilityErrorCode::InvalidRequest,
                    "checkpoint does not match packet capture contract",
                ));
            }
            let mut state = self.packet_capture.lock().expect("packet capture mutex");
            let changed = state.current != baseline;
            state.current = baseline;
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::PacketCapture,
                changed,
                verified: true,
            })
        })
    }
    fn update_excluded_prefixes<'a>(
        &'a self,
        prefixes: &'a [IpPrefix],
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        Box::pin(async move {
            self.ensure_supported(CapabilityKind::PacketCapture)?;
            self.record_event("capture.update");
            if let Some(message) = self.take_apply_failure(CapabilityKind::PacketCapture) {
                return Err(CapabilityError::new(
                    CapabilityKind::PacketCapture,
                    CapabilityErrorCode::ApplyFailed,
                    message,
                ));
            }
            let mut state = self.packet_capture.lock().expect("packet capture mutex");
            let Some(current) = state.current.as_mut() else {
                return Err(CapabilityError::new(
                    CapabilityKind::PacketCapture,
                    CapabilityErrorCode::Conflict,
                    "packet capture is not active",
                ));
            };
            current.excluded_prefixes = prefixes.to_vec();
            Ok(CapabilityOperationReport {
                capability: CapabilityKind::PacketCapture,
                changed: true,
                verified: true,
            })
        })
    }
}
