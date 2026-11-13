//! What the app-memory instrument needs of the composition a Runtime start
//! does (`--features bench-internals`): the active profile as the Core
//! receives it -- the source's own rules, the stored choices, every rule
//! provider's entries and the geodata its rules name -- so the instrument
//! can measure each step against a real profile instead of a synthetic one.

use egrio_core::RuntimeProfile;

/// The profile a start would hand the Core, from the data directory
/// `EGRIO_DATA_DIR` names.
pub fn active_profile_for_core() -> Result<RuntimeProfile, String> {
    let store = crate::profile_store::ProfileStore::open().map_err(|error| error.to_string())?;
    let mut snapshot = store
        .active_configuration_snapshot()
        .map_err(|error| error.to_string())?
        .ok_or("no active profile in this data directory")?;
    snapshot.profile.geodata = crate::geodata::content_for(&snapshot.profile);
    Ok(snapshot.profile)
}

/// The same, stopping before the providers' entries and the geodata, which
/// is what the pages read: the source's own rules and the stored choices.
pub fn active_profile_without_providers() -> Result<RuntimeProfile, String> {
    let store = crate::profile_store::ProfileStore::open().map_err(|error| error.to_string())?;
    let snapshot = store
        .active_settings_snapshot()
        .map_err(|error| error.to_string())?
        .ok_or("no active profile in this data directory")?;
    Ok(snapshot.profile)
}
