//! The GEODATA files GEOIP and GEOSITE rules read, `geoip.dat` and
//! `geosite.dat`, shared by every profile in the app data directory.
//!
//! They come from Loyalsoldier's v2ray-rules-dat: its `geoip:cn` holds the
//! networks that mainland China's carriers announce (china-operator-ip)
//! rather than only a geolocation database's estimate, and its GeoSite adds
//! mainland China lists to v2fly's domain lists. A file is downloaded when a
//! starting profile's rules need it and it is missing, and whenever the user
//! updates GEODATA in Settings. The Core receives only the codes the active
//! profile names.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use egrio_core::geodata::{self, GeoDataCodes, GeoDataContent};
use egrio_core::RuntimeProfile;
use reqwest::header::USER_AGENT;
use serde::Serialize;

/// When each file was last written and its size; `None` while missing.
#[derive(Debug, Clone, Serialize)]
pub struct GeoDataStatus {
    pub geoip: Option<GeoDataFileStatus>,
    pub geosite: Option<GeoDataFileStatus>,
    /// A download is running.
    pub updating: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoDataFileStatus {
    pub updated_at_unix: i64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoDataUpdateReport {
    pub status: GeoDataStatus,
    /// Either file's content changed.
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeoDataFile {
    GeoIp,
    GeoSite,
}

impl GeoDataFile {
    const ALL: [Self; 2] = [Self::GeoIp, Self::GeoSite];

    fn name(self) -> &'static str {
        match self {
            Self::GeoIp => "geoip.dat",
            Self::GeoSite => "geosite.dat",
        }
    }

    /// The project's jsDelivr mirror and its GitHub release, as its README
    /// lists them. The mirror goes first: it is usually reachable where
    /// GitHub is not, before any proxy runs.
    fn sources(self) -> [String; 2] {
        let name = self.name();
        [
            format!("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/{name}"),
            format!(
                "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{name}"
            ),
        ]
    }

    /// Whether the bytes decode as this kind of file.
    fn validate(self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Self::GeoIp => geodata::geoip_file_codes(bytes),
            Self::GeoSite => geodata::geosite_file_codes(bytes),
        }
        .map(|_| ())
    }

    fn needed_by(self, codes: &GeoDataCodes) -> bool {
        match self {
            Self::GeoIp => !codes.geoip.is_empty(),
            Self::GeoSite => !codes.geosite.is_empty(),
        }
    }
}

/// One download at a time, manual or on demand.
static UPDATING: AtomicBool = AtomicBool::new(false);
/// Downloading on demand is tried once per run; Settings retries.
static FETCHED_ON_DEMAND: AtomicBool = AtomicBool::new(false);

struct UpdatePermit;

impl UpdatePermit {
    fn acquire() -> Result<Self, String> {
        UPDATING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "GEODATA is already updating".into())
    }
}

impl Drop for UpdatePermit {
    fn drop(&mut self) {
        UPDATING.store(false, Ordering::Release);
    }
}

fn directory() -> Result<PathBuf, String> {
    Ok(crate::app_paths::app_data_dir()?.join("geodata"))
}

pub fn status() -> Result<GeoDataStatus, String> {
    Ok(status_in(&directory()?))
}

fn status_in(directory: &Path) -> GeoDataStatus {
    let file = |kind: GeoDataFile| {
        let metadata = std::fs::metadata(directory.join(kind.name()))
            .ok()
            .filter(|metadata| metadata.is_file())?;
        Some(GeoDataFileStatus {
            updated_at_unix: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |elapsed| elapsed.as_secs() as i64),
            size_bytes: metadata.len(),
        })
    };
    GeoDataStatus {
        geoip: file(GeoDataFile::GeoIp),
        geosite: file(GeoDataFile::GeoSite),
        updating: UPDATING.load(Ordering::Acquire),
    }
}

/// Downloads both files, replacing those whose content changed, and
/// restarts the running profile when it uses a changed one.
pub async fn update(
    runtime: &crate::runtime::DesktopRuntime,
) -> Result<GeoDataUpdateReport, String> {
    let changed = {
        let _permit = UpdatePermit::acquire()?;
        fetch(&GeoDataFile::ALL).await?
    };
    apply_to_running_profile(runtime, &changed).await?;
    Ok(GeoDataUpdateReport {
        status: status()?,
        changed: !changed.is_empty(),
    })
}

/// The kinds whose content changed.
async fn fetch(kinds: &[GeoDataFile]) -> Result<Vec<GeoDataFile>, String> {
    let directory = directory()?;
    let client = crate::remote_fetch::remote_file_client()?;
    let mut changed = Vec::new();
    for &kind in kinds {
        if fetch_one(&client, &directory, kind).await? {
            changed.push(kind);
        }
    }
    Ok(changed)
}

/// Tries each source in turn; a file that does not decode counts as a
/// failed source.
async fn fetch_one(
    client: &reqwest::Client,
    directory: &Path,
    kind: GeoDataFile,
) -> Result<bool, String> {
    let mut failures = Vec::new();
    for source in kind.sources() {
        let downloaded = download(client, &source)
            .await
            .and_then(|bytes| kind.validate(&bytes).map(|()| bytes));
        match downloaded {
            Ok(bytes) => return store(directory, kind, &bytes),
            Err(error) => failures.push(format!("{source}: {error}")),
        }
    }
    Err(format!(
        "{} could not be downloaded: {}",
        kind.name(),
        failures.join("; ")
    ))
}

async fn download(client: &reqwest::Client, source: &str) -> Result<Vec<u8>, String> {
    let response = client
        .get(crate::remote_fetch::validate_remote_url(source)?)
        .header(USER_AGENT, "Egrio/0.1")
        .send()
        .await
        .map_err(crate::remote_fetch::request_error)?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    crate::remote_fetch::read_limited_bytes(response, MAX_GEODATA_BYTES).await
}

/// Larger than either file has grown to, with room to grow.
const MAX_GEODATA_BYTES: u64 = 96 * 1024 * 1024;

/// Writes the file unless it already holds these bytes; whether it changed.
fn store(directory: &Path, kind: GeoDataFile, bytes: &[u8]) -> Result<bool, String> {
    let path = directory.join(kind.name());
    if std::fs::read(&path).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("GEODATA directory is not writable: {error}"))?;
    // A finished download replaces the file in one rename, so a reader never
    // sees half of one. Its bytes reach the disk first: the rename is
    // journaled at once and the bytes are not, so a power loss in between
    // would leave the name on an empty file, which no start downloads again
    // because the file is there.
    let partial = directory.join(format!("{}.download", kind.name()));
    let publish = || {
        use std::io::Write;
        let mut file = std::fs::File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&partial, &path)
    };
    publish().map_err(|error| format!("{} could not be saved: {error}", kind.name()))?;
    Ok(true)
}

/// The entries of the codes the profile's rules name. A kind whose file is
/// missing or unreadable stays `None`, and its rules wait for the data.
pub(crate) fn content_for(profile: &RuntimeProfile) -> GeoDataContent {
    let codes = geodata::referenced_codes(profile);
    if codes.is_empty() {
        return GeoDataContent::default();
    }
    match directory() {
        Ok(directory) => content_in(&directory, &codes),
        Err(_) => GeoDataContent::default(),
    }
}

fn content_in(directory: &Path, codes: &GeoDataCodes) -> GeoDataContent {
    let read = |kind: GeoDataFile| {
        if !kind.needed_by(codes) {
            return None;
        }
        std::fs::read(directory.join(kind.name())).ok()
    };
    GeoDataContent {
        geoip: read(GeoDataFile::GeoIp).and_then(|bytes| {
            loaded(
                GeoDataFile::GeoIp,
                geodata::extract_geoip(&bytes, &codes.geoip),
            )
        }),
        geosite: read(GeoDataFile::GeoSite).and_then(|bytes| {
            loaded(
                GeoDataFile::GeoSite,
                geodata::extract_geosite(&bytes, &codes.geosite),
            )
        }),
    }
}

/// The extracted entries, or `None` with a warning for a file that does not
/// decode.
fn loaded<T>(kind: GeoDataFile, content: Result<T, String>) -> Option<T> {
    content
        .map_err(|error| log::warn!(target: "geodata", "{} is unusable: {error}", kind.name()))
        .ok()
}

/// Starts downloading, in the background, the files a starting profile's
/// rules need and the app lacks, once per run. The profile restarts with
/// them when they arrive; until then its GEO rules wait for the data.
pub(crate) fn fetch_missing_in_background(profile: &RuntimeProfile) {
    let codes = geodata::referenced_codes(profile);
    let Ok(directory) = directory() else {
        return;
    };
    let missing = GeoDataFile::ALL
        .into_iter()
        .filter(|kind| kind.needed_by(&codes) && !directory.join(kind.name()).is_file())
        .collect::<Vec<_>>();
    if missing.is_empty() || FETCHED_ON_DEMAND.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::async_runtime::spawn(async move {
        let fetched = match UpdatePermit::acquire() {
            Ok(_permit) => fetch(&missing).await,
            Err(error) => Err(error),
        };
        match fetched {
            Ok(changed) => {
                log::info!(target: "geodata", "downloaded the GEODATA the active profile needs");
                let Some(runtime) = crate::runtime::process_runtime() else {
                    return;
                };
                if let Err(error) = apply_to_running_profile(&runtime, &changed).await {
                    log::warn!(target: "geodata", "the running profile kept its old GEODATA: {error}");
                }
            }
            Err(error) => log::warn!(target: "geodata", "GEODATA download failed: {error}"),
        }
    });
}

/// Restarts the running profile when its rules use a file that changed, so
/// the Core compiles them with the new data; other connections stay.
async fn apply_to_running_profile(
    runtime: &crate::runtime::DesktopRuntime,
    changed: &[GeoDataFile],
) -> Result<(), String> {
    if changed.is_empty() {
        return Ok(());
    }
    let store = crate::profile_store::ProfileStore::open().map_err(|error| error.to_string())?;
    let Some(active) = store.active_profile().map_err(|error| error.to_string())? else {
        return Ok(());
    };
    // Rule sets may name codes too; without their contents, the rules decide.
    let snapshot = store
        .active_configuration_snapshot()
        .or_else(|_| store.active_settings_snapshot())
        .map_err(|error| error.to_string())?;
    let uses_changed = snapshot.is_some_and(|snapshot| {
        let codes = geodata::referenced_codes(&snapshot.profile);
        changed.iter().any(|kind| kind.needed_by(&codes))
    });
    if !uses_changed {
        return Ok(());
    }
    match crate::active_profile_propagation::propagate_if_active_profile(runtime, &active.id).await
    {
        crate::active_profile_propagation::ProfilePropagationOutcome::Failed(error) => Err(
            format!("GEODATA was saved but the running profile did not restart: {error}"),
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
