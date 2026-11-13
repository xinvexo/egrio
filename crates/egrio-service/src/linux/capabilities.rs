//! The Linux service's capability handler: applies TUN mode's capabilities
//! as root for one authorized desktop session.
//!
//! Each session runs its own `LinuxTun` capability set. The kernel objects
//! behind it are machine-wide (one interface name, routing table, rule
//! priority and nftables table), so their ownership tokens arbitrate between
//! sessions and every capability operation, from any session, runs alone.
//!
//! A session keeps a record of the checkpoints it issued and has not
//! restored in the service's state directory. The kernel objects outlive the
//! process; a helper that starts after one ended without releasing its
//! sessions releases what their records list before it serves anyone.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use egrio_platform_linux::{LinuxTun, LinuxTunConfig, LINUX_SERVICE_SESSIONS};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityKind, CapabilityOperationReport, DnsControl,
    FirewallControl, PacketCapture, PlatformLeaseKey, RouteControl,
};
use serde::de::DeserializeOwned;

use crate::protocol::{
    ControlErrorCode, ControlRequest, ControlResponse, OwnedTunChannel, PacketChannel,
};
use crate::session::ControlRequestHandler;

type HandlerResult<T> = Result<T, (ControlErrorCode, String)>;

/// The capabilities a Linux service session offers.
pub const LINUX_SERVICE_CAPABILITIES: [CapabilityKind; 4] = [
    CapabilityKind::PacketCapture,
    CapabilityKind::Route,
    CapabilityKind::Dns,
    CapabilityKind::Firewall,
];

/// What every session of the service shares.
#[derive(Debug, Default)]
pub struct LinuxServiceResources {
    /// Held for each capability operation, so no two sessions' checks and
    /// mutations of the machine-wide TUN resources interleave.
    operations: Mutex<()>,
}

impl LinuxServiceResources {
    fn operation(&self) -> std::sync::MutexGuard<'_, ()> {
        self.operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Serves one desktop session; the TUN it opens is owned by the session's
/// peer uid.
#[derive(Debug)]
pub struct LinuxServiceHandler {
    tun: LinuxTun,
    owner_uid: u32,
    /// Drives the capability futures on the session's own thread.
    runtime: tokio::runtime::Runtime,
    resources: Arc<LinuxServiceResources>,
    issued: Mutex<IssuedCheckpoints>,
}

impl LinuxServiceHandler {
    pub fn new(
        config: LinuxTunConfig,
        owner_uid: u32,
        resources: Arc<LinuxServiceResources>,
    ) -> Result<Self, String> {
        let record =
            Path::new(LINUX_SERVICE_SESSIONS).join(format!("{}.json", uuid::Uuid::new_v4()));
        Self::with_issued(
            config,
            owner_uid,
            resources,
            IssuedCheckpoints::recorded_at(record),
        )
    }

    fn with_issued(
        config: LinuxTunConfig,
        owner_uid: u32,
        resources: Arc<LinuxServiceResources>,
        issued: IssuedCheckpoints,
    ) -> Result<Self, String> {
        Ok(Self {
            tun: LinuxTun::new(config)?,
            owner_uid,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("failed to start the session runtime: {error}"))?,
            resources,
            issued: Mutex::new(issued),
        })
    }

    /// Ends the session after its connection closed: removes what it
    /// prepared and did not restore (DNS, routes, the firewall, then the
    /// device), so the network works as it does without Egrio, then its
    /// record.
    pub fn end_session(&self) {
        let _operation = self.resources.operation();
        let released = self.issued().take_releasable();
        for checkpoint in released {
            if let Err(error) = self.runtime.block_on(self.restore(&checkpoint)) {
                eprintln!("egrio-service: releasing an ended session failed: {error}");
            }
        }
        self.issued().forget();
    }

    fn issued(&self) -> std::sync::MutexGuard<'_, IssuedCheckpoints> {
        self.issued
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn dispatch(&self, request: ControlRequest) -> HandlerResult<ControlResponse> {
        match request {
            ControlRequest::Prepare {
                capability,
                settings,
            } => {
                let checkpoint = match capability {
                    CapabilityKind::PacketCapture => {
                        self.tun.capture.prepare(&settings_of(settings)?).await
                    }
                    CapabilityKind::Route => self.tun.route.prepare(&settings_of(settings)?).await,
                    CapabilityKind::Dns => self.tun.dns.prepare(&settings_of(settings)?).await,
                    CapabilityKind::Firewall => {
                        self.tun.firewall.prepare(&settings_of(settings)?).await
                    }
                    _ => return Err(unsupported(capability)),
                }
                .map_err(failed)?;
                self.issued().issue(checkpoint.clone());
                Ok(ControlResponse::Checkpoint(checkpoint))
            }
            ControlRequest::Apply {
                capability,
                settings,
            } => {
                let report = match capability {
                    CapabilityKind::Route => self.tun.route.apply(&settings_of(settings)?).await,
                    CapabilityKind::Dns => self.tun.dns.apply(&settings_of(settings)?).await,
                    CapabilityKind::Firewall => {
                        self.tun.firewall.apply(&settings_of(settings)?).await
                    }
                    _ => return Err(unsupported(capability)),
                };
                Ok(ControlResponse::Operation(report.map_err(failed)?))
            }
            ControlRequest::Observe { capability } => {
                let observation = match capability {
                    CapabilityKind::PacketCapture => self.tun.capture.observe().await,
                    CapabilityKind::Route => self.tun.route.observe().await,
                    CapabilityKind::Dns => self.tun.dns.observe().await,
                    CapabilityKind::Firewall => self.tun.firewall.observe().await,
                    _ => return Err(unsupported(capability)),
                };
                Ok(ControlResponse::Observation(observation.map_err(failed)?))
            }
            ControlRequest::Restore { checkpoint } => {
                let report = self.restore(&checkpoint).await.map_err(failed)?;
                self.issued().restored(&checkpoint);
                Ok(ControlResponse::Operation(report))
            }
            ControlRequest::OpenPacketCapture { settings } => {
                let tun = self
                    .tun
                    .capture
                    .open_for_user(&settings, self.owner_uid)
                    .await
                    .map_err(failed)?;
                Ok(ControlResponse::PacketChannel(PacketChannel::OwnedTun(
                    OwnedTunChannel {
                        interface_name: tun.interface_name,
                        interface_index: tun.interface_index,
                        mtu: tun.mtu,
                        physical_dns_servers: tun.physical_dns_servers,
                    },
                )))
            }
            ControlRequest::Hello { .. } | ControlRequest::UpdateExcludedPrefixes { .. } => Err((
                ControlErrorCode::UnsupportedMethod,
                "control method is not implemented by the Linux service".into(),
            )),
        }
    }

    async fn restore(
        &self,
        checkpoint: &CapabilityCheckpoint,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        let key = &checkpoint.lease_key;
        if *key == PlatformLeaseKey::packet_capture() {
            self.tun.capture.restore(checkpoint).await
        } else if *key == PlatformLeaseKey::default_route() {
            self.tun.route.restore(checkpoint).await
        } else if *key == PlatformLeaseKey::system_dns() {
            self.tun.dns.restore(checkpoint).await
        } else if *key == PlatformLeaseKey::kill_switch() {
            self.tun.firewall.restore(checkpoint).await
        } else {
            Err(CapabilityError::unsupported(
                CapabilityKind::PacketCapture,
                format!("the Linux service holds no {key:?} resources"),
            ))
        }
    }
}

/// Releases what the sessions of a helper that ended without releasing them
/// (killed, crashed, stopped) left in the kernel, as their records list; run
/// before the helper serves anyone. With the desktop gone as well, nothing
/// else would: the persistent TUN, its rules and the leak protection would
/// hold the network until the desktop started again.
pub fn release_left_sessions(config: &LinuxTunConfig, resources: &Arc<LinuxServiceResources>) {
    let Ok(entries) = fs::read_dir(LINUX_SERVICE_SESSIONS) else {
        return;
    };
    for record in entries.flatten().map(|entry| entry.path()) {
        let issued = match IssuedCheckpoints::read(&record) {
            Ok(issued) => issued,
            Err(error) => {
                // A temporary file a killed write left, or a damaged record.
                eprintln!(
                    "egrio-service: discarding the session record {}: {error}",
                    record.display()
                );
                let _ = fs::remove_file(&record);
                continue;
            }
        };
        match LinuxServiceHandler::with_issued(config.clone(), 0, Arc::clone(resources), issued) {
            Ok(handler) => handler.end_session(),
            Err(error) => eprintln!(
                "egrio-service: releasing the session {} left failed: {error}",
                record.display()
            ),
        }
    }
}

impl ControlRequestHandler for LinuxServiceHandler {
    fn handle(&self, request: ControlRequest) -> HandlerResult<ControlResponse> {
        let _operation = self.resources.operation();
        self.runtime.block_on(self.dispatch(request))
    }
}

fn settings_of<T: DeserializeOwned>(settings: serde_json::Value) -> HandlerResult<T> {
    serde_json::from_value(settings)
        .map_err(|error| (ControlErrorCode::CapabilityFailed, error.to_string()))
}

fn failed(error: CapabilityError) -> (ControlErrorCode, String) {
    // The desktop names the capability itself.
    (ControlErrorCode::CapabilityFailed, error.message)
}

fn unsupported(capability: CapabilityKind) -> (ControlErrorCode, String) {
    (
        ControlErrorCode::UnsupportedMethod,
        format!("the Linux service does not offer {capability:?} through this method"),
    )
}

/// The checkpoints a session prepared and has not restored yet, newest per
/// capability: a later prepare supersedes an earlier unused one. Kept in the
/// session's record as they change, before the objects they cover exist.
#[derive(Debug, Default)]
struct IssuedCheckpoints {
    checkpoints: Vec<CapabilityCheckpoint>,
    record: Option<PathBuf>,
}

impl IssuedCheckpoints {
    fn recorded_at(record: PathBuf) -> Self {
        Self {
            checkpoints: Vec::new(),
            record: Some(record),
        }
    }

    /// What a record left behind lists; only a whole record counts.
    fn read(record: &Path) -> Result<Self, String> {
        if record
            .extension()
            .is_none_or(|extension| extension != "json")
        {
            return Err("not a session record".into());
        }
        let bytes = fs::read(record).map_err(|error| error.to_string())?;
        let checkpoints = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        Ok(Self {
            checkpoints,
            record: Some(record.to_path_buf()),
        })
    }

    fn issue(&mut self, checkpoint: CapabilityCheckpoint) {
        self.checkpoints
            .retain(|issued| issued.lease_key != checkpoint.lease_key);
        self.checkpoints.push(checkpoint);
        self.save();
    }

    fn restored(&mut self, checkpoint: &CapabilityCheckpoint) {
        self.checkpoints.retain(|issued| issued != checkpoint);
        self.save();
    }

    /// Brings the record in step: replaced through a sibling temporary file,
    /// so a helper killed while writing leaves the previous one whole, and
    /// removed once nothing is left to restore.
    fn save(&self) {
        let Some(record) = &self.record else {
            return;
        };
        let saved = if self.checkpoints.is_empty() {
            remove_record(record)
        } else {
            write_record(record, &self.checkpoints)
        };
        if let Err(error) = saved {
            eprintln!(
                "egrio-service: keeping the session record {} failed: {error}",
                record.display()
            );
        }
    }

    /// Removes the record once what it listed is released.
    fn forget(&mut self) {
        if let Some(record) = self.record.take() {
            if let Err(error) = remove_record(&record) {
                eprintln!(
                    "egrio-service: removing the session record {} failed: {error}",
                    record.display()
                );
            }
        }
    }

    /// What an ended session releases, everything in restore order: DNS,
    /// routes and the firewall before the device they sit on, so a desktop
    /// that went away leaves the network as it is without Egrio. A checkpoint
    /// prepared for an in-place update would bring back the settings before
    /// it; released, it removes the control like the session's first one.
    fn take_releasable(&mut self) -> Vec<CapabilityCheckpoint> {
        let checkpoints = std::mem::take(&mut self.checkpoints);
        [
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::packet_capture(),
        ]
        .into_iter()
        .filter_map(|key| {
            let mut checkpoint = checkpoints
                .iter()
                .find(|checkpoint| checkpoint.lease_key == key)
                .cloned()?;
            if let Some(applied) = checkpoint.payload.get_mut("applied") {
                *applied = false.into();
            }
            Some(checkpoint)
        })
        .collect()
    }
}

fn write_record(record: &Path, checkpoints: &[CapabilityCheckpoint]) -> io::Result<()> {
    if let Some(directory) = record.parent() {
        fs::create_dir_all(directory)?;
    }
    let temporary = record.with_extension("json.new");
    fs::write(&temporary, serde_json::to_vec(checkpoints)?)?;
    fs::rename(&temporary, record)
}

fn remove_record(record: &Path) -> io::Result<()> {
    match fs::remove_file(record) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(key: PlatformLeaseKey, owner: &str) -> CapabilityCheckpoint {
        CapabilityCheckpoint {
            lease_key: key,
            schema_version: 1,
            payload: serde_json::json!({ "ownership": owner }),
            rollback_payload: None,
        }
    }

    #[test]
    fn an_ended_session_releases_dns_routes_and_the_firewall_then_the_device() {
        let mut issued = IssuedCheckpoints::default();
        for key in [
            PlatformLeaseKey::packet_capture(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_dns(),
        ] {
            issued.issue(checkpoint(key, "a"));
        }
        let released = issued.take_releasable();
        assert_eq!(
            released
                .iter()
                .map(|checkpoint| checkpoint.lease_key.clone())
                .collect::<Vec<_>>(),
            vec![
                PlatformLeaseKey::system_dns(),
                PlatformLeaseKey::default_route(),
                PlatformLeaseKey::kill_switch(),
                PlatformLeaseKey::packet_capture(),
            ]
        );
        assert!(issued.take_releasable().is_empty());
    }

    #[test]
    fn an_in_place_update_checkpoint_is_released_as_a_removal() {
        let mut issued = IssuedCheckpoints::default();
        let mut update = checkpoint(PlatformLeaseKey::kill_switch(), "a");
        update.payload["applied"] = true.into();
        issued.issue(update);
        let released = issued.take_releasable();
        assert_eq!(released[0].payload["applied"], false);
    }

    #[test]
    fn restored_and_superseded_checkpoints_are_not_released_again() {
        let mut issued = IssuedCheckpoints::default();
        issued.issue(checkpoint(PlatformLeaseKey::packet_capture(), "a"));
        issued.issue(checkpoint(PlatformLeaseKey::packet_capture(), "b"));
        issued.issue(checkpoint(PlatformLeaseKey::default_route(), "b"));
        issued.restored(&checkpoint(PlatformLeaseKey::default_route(), "b"));
        // A checkpoint from an earlier session is restored without a trace.
        issued.restored(&checkpoint(PlatformLeaseKey::system_dns(), "z"));
        assert_eq!(
            issued.take_releasable(),
            vec![checkpoint(PlatformLeaseKey::packet_capture(), "b")]
        );
    }

    /// A directory of its own for one test's session records.
    fn records() -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("egrio-service-records-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn a_session_records_what_it_has_not_restored() {
        let directory = records();
        let record = directory.join("session.json");
        let mut issued = IssuedCheckpoints::recorded_at(record.clone());
        issued.issue(checkpoint(PlatformLeaseKey::packet_capture(), "a"));
        issued.issue(checkpoint(PlatformLeaseKey::kill_switch(), "a"));
        assert_eq!(
            IssuedCheckpoints::read(&record).unwrap().checkpoints,
            issued.checkpoints
        );
        issued.restored(&checkpoint(PlatformLeaseKey::kill_switch(), "a"));
        assert_eq!(
            IssuedCheckpoints::read(&record).unwrap().checkpoints,
            vec![checkpoint(PlatformLeaseKey::packet_capture(), "a")]
        );
        issued.restored(&checkpoint(PlatformLeaseKey::packet_capture(), "a"));
        assert!(!record.exists(), "nothing left to restore keeps no record");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_record_left_behind_releases_in_restore_order_and_goes() {
        let directory = records();
        let record = directory.join("session.json");
        let mut issued = IssuedCheckpoints::recorded_at(record.clone());
        for key in [
            PlatformLeaseKey::packet_capture(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_dns(),
        ] {
            issued.issue(checkpoint(key, "a"));
        }
        // The helper is killed: only the record is left.
        drop(issued);
        let mut left = IssuedCheckpoints::read(&record).unwrap();
        assert_eq!(
            left.take_releasable()
                .into_iter()
                .map(|checkpoint| checkpoint.lease_key)
                .collect::<Vec<_>>(),
            vec![
                PlatformLeaseKey::system_dns(),
                PlatformLeaseKey::default_route(),
                PlatformLeaseKey::kill_switch(),
                PlatformLeaseKey::packet_capture(),
            ]
        );
        left.forget();
        assert!(!record.exists());
        let partial = directory.join("session.json.new");
        fs::write(&partial, b"[{").unwrap();
        assert!(IssuedCheckpoints::read(&partial).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
