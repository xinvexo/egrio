//! The helper's installation commands, each run as root.
//!
//! `install-linux-service --allow-uid <uid>` (through `pkexec` from the
//! desktop) adds the user to the helper's list. A package's helper is then
//! started if it is not running; outside a package this executable is copied
//! to the root-owned location with the unit that runs it, and the helper is
//! restarted when either changed, which ends any live session for the desktop
//! to recover like any other session loss. A newly listed user alone needs no
//! restart: the helper reads the list at every connection.
//!
//! `install-linux-package` (the package's install script) removes a helper
//! the app installed itself, which systemd would run in place of the
//! package's, and (re)starts the package's.
//!
//! `uninstall-linux-service` (by hand, or the package's removal script) stops
//! and disables the helper, removes what was installed outside a package, the
//! list of users and the helper's session records.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use egrio_platform_linux::{
    linux_service_allowed_uids, linux_service_allowed_uids_list, linux_service_installation,
    linux_service_unit, linux_service_unit_executable, linux_tun_occupied_resources,
    LinuxTunConfig, LINUX_PACKAGE_SERVICE_EXECUTABLE, LINUX_PACKAGE_UNIT_PATH,
    LINUX_SERVICE_ALLOWED_UIDS, LINUX_SERVICE_EXECUTABLE, LINUX_SERVICE_SESSIONS,
    LINUX_SERVICE_UNIT_NAME, LINUX_SERVICE_UNIT_PATH,
};

pub(super) fn install_linux_service(uid: u32) -> Result<(), String> {
    require_root("install-linux-service")?;
    allow_uid(uid)?;
    let source = std::env::current_exe()
        .map_err(|error| format!("failed to resolve this executable: {error}"))?;
    if Path::new(LINUX_PACKAGE_UNIT_PATH).exists() {
        // A copy elsewhere would take the package's place in systemd.
        if source != Path::new(LINUX_PACKAGE_SERVICE_EXECUTABLE) {
            return Err(format!(
                "the Egrio package's service is installed; use the packaged Egrio, or remove \
                 the package before running Egrio from {}",
                source.display()
            ));
        }
        return systemctl(&["enable", "--now", LINUX_SERVICE_UNIT_NAME]);
    }
    let executable = Path::new(LINUX_SERVICE_EXECUTABLE);
    let mut changed = false;
    if source != executable {
        let contents = fs::read(&source)
            .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
        changed |= replace_file(executable, &contents, 0o755)?;
    }
    changed |= replace_file(
        Path::new(LINUX_SERVICE_UNIT_PATH),
        linux_service_unit(LINUX_SERVICE_EXECUTABLE).as_bytes(),
        0o644,
    )?;
    if !changed {
        return systemctl(&["enable", "--now", LINUX_SERVICE_UNIT_NAME]);
    }
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", LINUX_SERVICE_UNIT_NAME])?;
    systemctl(&["restart", LINUX_SERVICE_UNIT_NAME])
}

pub(super) fn install_linux_package() -> Result<(), String> {
    require_root("install-linux-package")?;
    remove_self_installed()?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", LINUX_SERVICE_UNIT_NAME])?;
    systemctl(&["restart", LINUX_SERVICE_UNIT_NAME])
}

/// Refused while the TUN resources the helper manages exist: a stopped
/// helper leaves them in the kernel and only a running one restores them
/// (from the desktop's checkpoint, or from its records when it starts), so
/// TUN mode is turned off first. With none left the records are moot.
pub(super) fn uninstall_linux_service() -> Result<(), String> {
    require_root("uninstall-linux-service")?;
    let users = Path::new(LINUX_SERVICE_ALLOWED_UIDS);
    let Some(installation) = linux_service_installation() else {
        remove_file(users)?;
        remove_own_directory(users);
        remove_records()?;
        return Ok(());
    };
    let occupied = linux_tun_occupied_resources(&LinuxTunConfig::default())?;
    if !occupied.is_empty() {
        return Err(format!(
            "TUN mode still holds {}; turn it off in Egrio before removing the helper",
            occupied.join(", ")
        ));
    }
    systemctl(&["disable", "--now", LINUX_SERVICE_UNIT_NAME])?;
    remove_self_installed()?;
    remove_file(users)?;
    remove_own_directory(users);
    remove_records()?;
    if installation.unit_path == LINUX_SERVICE_UNIT_PATH {
        systemctl(&["daemon-reload"])?;
    }
    Ok(())
}

fn require_root(command: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!(
            "{command} must run as root, for example through pkexec"
        ));
    }
    Ok(())
}

/// Adds `uid` to the list of users the helper serves; root needs no entry.
fn allow_uid(uid: u32) -> Result<(), String> {
    let path = Path::new(LINUX_SERVICE_ALLOWED_UIDS);
    let mut uids = fs::read_to_string(path)
        .map(|list| linux_service_allowed_uids(&list))
        .unwrap_or_default();
    if uid == 0 || uids.contains(&uid) {
        return Ok(());
    }
    uids.push(uid);
    replace_file(
        path,
        linux_service_allowed_uids_list(&uids).as_bytes(),
        0o644,
    )
    .map(|_| ())
}

/// Removes the unit and copy an app installed outside a package; a unit at
/// that path running anything else is left alone.
fn remove_self_installed() -> Result<(), String> {
    let unit = Path::new(LINUX_SERVICE_UNIT_PATH);
    let ours = fs::read_to_string(unit)
        .is_ok_and(|text| linux_service_unit_executable(&text) == Some(LINUX_SERVICE_EXECUTABLE));
    if ours {
        remove_file(unit)?;
    }
    let executable = Path::new(LINUX_SERVICE_EXECUTABLE);
    remove_file(executable)?;
    remove_own_directory(executable);
    Ok(())
}

/// The session records and the state directory holding them.
fn remove_records() -> Result<(), String> {
    let records = Path::new(LINUX_SERVICE_SESSIONS);
    match fs::remove_dir_all(records) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(format!("failed to remove {}: {error}", records.display()));
        }
        _ => {}
    }
    remove_own_directory(records);
    Ok(())
}

/// The directory is the helper's own; anything else placed there keeps it.
fn remove_own_directory(file: &Path) {
    if let Some(directory) = file.parent() {
        let _ = fs::remove_dir(directory);
    }
}

fn systemctl(arguments: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(arguments)
        .status()
        .map_err(|error| format!("failed to run systemctl: {error}"))?;
    if !status.success() {
        return Err(format!(
            "systemctl {} failed: {status}",
            arguments.join(" ")
        ));
    }
    Ok(())
}

fn remove_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(format!("failed to remove {}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Replaces `path` with `contents` through a sibling temporary file, so no
/// reader sees a partial file and a running service keeps its old executable
/// until the restart; whether it changed. The parent directories are created
/// root-owned.
fn replace_file(path: &Path, contents: &[u8], mode: u32) -> Result<bool, String> {
    if fs::read(path).is_ok_and(|current| current == contents) {
        return Ok(false);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.new"));
    let write = || -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    };
    write().map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("failed to install {}: {error}", path.display())
    })?;
    Ok(true)
}
