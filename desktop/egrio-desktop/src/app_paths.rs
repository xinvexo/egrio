use std::path::PathBuf;

use directories::{BaseDirs, ProjectDirs};

/// The product identifier, which names the log directory.
const APP_IDENTIFIER: &str = "com.xinvexo.egrio";

/// The data directory of a development or test instance, which must leave
/// the installed app's profiles, checkpoints, Runtime lock and logs alone.
fn data_dir_override() -> Option<PathBuf> {
    std::env::var_os("EGRIO_DATA_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The app data directory: `EGRIO_DATA_DIR` when set, the platform's data
/// directory otherwise.
pub fn app_data_dir() -> Result<PathBuf, String> {
    if let Some(directory) = data_dir_override() {
        return Ok(directory);
    }
    let dirs = ProjectDirs::from("com", "xinvexo", "Egrio")
        .ok_or_else(|| "could not resolve application data directory".to_string())?;
    Ok(dirs.data_dir().to_path_buf())
}

/// The log directory: `logs` in `EGRIO_DATA_DIR` when set; otherwise
/// `~/Library/Logs/com.xinvexo.egrio` on macOS and `com.xinvexo.egrio/logs`
/// in the local data directory elsewhere.
pub fn app_log_dir() -> Result<PathBuf, String> {
    if let Some(directory) = data_dir_override() {
        return Ok(directory.join("logs"));
    }
    let base = BaseDirs::new().ok_or_else(|| "could not resolve the home directory".to_string())?;
    #[cfg(target_os = "macos")]
    let directory = base.home_dir().join("Library/Logs").join(APP_IDENTIFIER);
    #[cfg(not(target_os = "macos"))]
    let directory = base.data_local_dir().join(APP_IDENTIFIER).join("logs");
    Ok(directory)
}
