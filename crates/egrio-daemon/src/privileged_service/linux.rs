//! Linux: whether the systemd unit runs this app's helper for the current
//! user, and listing the user (installing the helper outside a package)
//! through `pkexec`, once. The helper's own `install-linux-service` command
//! and a distribution package write the layout this module reads.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use egrio_platform_linux::{
    linux_service_allows, linux_service_installation, LINUX_SERVICE_INSTALL_COMMAND,
    LINUX_SERVICE_SOCKET, LINUX_SERVICE_UNIT_NAME,
};

use super::{PrivilegedServiceState, PrivilegedServiceStatus};

const START_WAIT: Duration = Duration::from_secs(5);
/// Unit states systemd moves through on its own, such as the restart of a
/// crashed helper (`Restart=always`, `RestartSec=1`).
const TRANSITIONAL_STATES: [&str; 4] = ["activating", "deactivating", "reloading", "refreshing"];

pub fn privileged_service_status() -> PrivilegedServiceStatus {
    let (state, detail) = if linux_service_installation().is_none() {
        (
            PrivilegedServiceState::NotInstalled,
            Some("the Egrio service is not installed".into()),
        )
    } else {
        match unit_state() {
            Ok(state) if state == "active" => (PrivilegedServiceState::Running, None),
            Ok(state) => (
                PrivilegedServiceState::Stopped,
                Some(format!("the Egrio service is {state}")),
            ),
            Err(error) => (PrivilegedServiceState::Unhealthy, Some(error)),
        }
    };
    PrivilegedServiceStatus {
        state,
        endpoint: Some(format!("unix:{LINUX_SERVICE_SOCKET}")),
        detail,
    }
}

/// The unit's state as `systemctl is-active` prints it (systemctl(1)); the
/// command exits non-zero for every state but active, so only the text counts.
fn unit_state() -> Result<String, String> {
    let output = Command::new("systemctl")
        .args(["is-active", LINUX_SERVICE_UNIT_NAME])
        .output()
        .map_err(|error| format!("failed to run systemctl: {error}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Whether the running service is this app's helper and serves this user.
/// A package's helper is the one beside its app, so only a copy installed
/// outside the package is compared.
pub fn privileged_service_serves(service_executable_path: &Path) -> Result<(), String> {
    let installation = linux_service_installation().ok_or("the Egrio service is not installed")?;
    let uid = unsafe { libc::getuid() };
    if !linux_service_allows(uid) {
        return Err(format!("the Egrio service does not serve uid {uid}"));
    }
    let installed = Path::new(&installation.executable);
    if installed != service_executable_path && !same_executable(installed, service_executable_path)?
    {
        return Err("the installed Egrio service differs from the copy beside this app".into());
    }
    match unit_state()?.as_str() {
        "active" => Ok(()),
        state => Err(format!("the Egrio service is {state}")),
    }
}

/// Waits while systemd brings the unit to a settled state, then reports
/// whether it serves this app's helper for this user. A crashed helper is
/// back within a second, so recovery needs no consent for it.
pub fn await_privileged_service(service_executable_path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + START_WAIT;
    loop {
        let served = privileged_service_serves(service_executable_path);
        let settling = served.is_err()
            && unit_state().is_ok_and(|state| TRANSITIONAL_STATES.contains(&state.as_str()));
        if !settling || Instant::now() >= deadline {
            return served;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Compares the installed helper with the bundled one byte for byte. Status
/// polls repeat the check, so a comparison is reused while neither file's
/// size and modification time changed.
fn same_executable(installed: &Path, bundled: &Path) -> Result<bool, String> {
    type Fingerprint = [(u64, Option<SystemTime>); 2];
    static LAST: Mutex<Option<(PathBuf, Fingerprint, bool)>> = Mutex::new(None);
    let fingerprint = |path: &Path| {
        fs::metadata(path)
            .map(|metadata| (metadata.len(), metadata.modified().ok()))
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))
    };
    let current = [fingerprint(installed)?, fingerprint(bundled)?];
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((path, fingerprint, same)) = last.as_ref() {
        if path == bundled && *fingerprint == current {
            return Ok(*same);
        }
    }
    let read = |path: &Path| {
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
    };
    let same = current[0].0 == current[1].0 && read(installed)? == read(bundled)?;
    *last = Some((bundled.to_path_buf(), current, same));
    Ok(same)
}

/// Lets the helper serve the current user, installing or updating it outside
/// a package, and starts it. `pkexec` asks the session's polkit agent for an
/// administrator's consent.
pub fn bootstrap_privileged_service_elevated(service_executable_path: &Path) -> Result<(), String> {
    let uid = unsafe { libc::getuid() }.to_string();
    let output = Command::new("pkexec")
        .arg(service_executable_path)
        .args([LINUX_SERVICE_INSTALL_COMMAND, "--allow-uid", &uid])
        .output()
        .map_err(|error| format!("failed to run pkexec: {error}"))?;
    if !output.status.success() {
        // pkexec(1): 126 when the user dismissed the authentication dialog,
        // 127 when authorization was refused or could not be obtained.
        return Err(match output.status.code() {
            Some(126) => "installing the Egrio service was cancelled".into(),
            Some(127) => "installing the Egrio service was not authorized".into(),
            _ => format!(
                "installing the Egrio service failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let deadline = Instant::now() + START_WAIT;
    while unit_state().as_deref() != Ok("active") {
        if Instant::now() >= deadline {
            return Err("the Egrio service did not start".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
