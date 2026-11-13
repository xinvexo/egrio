//! Where the Linux privileged helper lives once installed and which users it
//! serves. Two installations run the same unit. A distribution package puts
//! the helper beside the app and the unit under `/usr/lib`; their files belong
//! to the package manager. An app run from anywhere else (an AppImage, a
//! build) installs a root-owned copy of its helper under `/usr/local` and the
//! unit under `/etc`, which systemd prefers to the package's (systemd.unit(5),
//! unit load path). Either way the users the helper serves besides root are
//! listed in one file that the install command adds to and the helper reads
//! at every connection, so serving another user needs no restart. The install
//! and uninstall commands write and remove this layout, the helper's runtime
//! directory holds its sockets and its state directory the record of each
//! session; the desktop reads the layout to decide whether TUN mode's
//! environment is ready.

/// The systemd unit that runs the helper.
pub const LINUX_SERVICE_UNIT_NAME: &str = "egrio-service.service";
/// The unit a distribution package installs.
pub const LINUX_PACKAGE_UNIT_PATH: &str = "/usr/lib/systemd/system/egrio-service.service";
/// The helper a distribution package installs, beside the app.
pub const LINUX_PACKAGE_SERVICE_EXECUTABLE: &str = "/usr/bin/egrio-service";
/// The unit an app outside a package installs.
pub const LINUX_SERVICE_UNIT_PATH: &str = "/etc/systemd/system/egrio-service.service";
/// The root-owned copy of the helper an app outside a package installs; its
/// unit never points at a user-writable build or application directory.
pub const LINUX_SERVICE_EXECUTABLE: &str = "/usr/local/libexec/egrio/egrio-service";
/// The users the helper serves besides root, one uid per line.
pub const LINUX_SERVICE_ALLOWED_UIDS: &str = "/etc/egrio/allowed-uids";
/// Control sessions, in the unit's runtime directory.
pub const LINUX_SERVICE_SOCKET: &str = "/run/egrio/service.sock";
/// Core socket marking, in the unit's runtime directory.
pub const LINUX_MARK_SOCKET: &str = "/run/egrio/mark.sock";
/// The checkpoints each control session issued and has not restored, in the
/// unit's state directory, which outlives the process: a helper that starts
/// after one ended without releasing its sessions (killed, crashed, stopped)
/// releases them, since no desktop may be left to.
pub const LINUX_SERVICE_SESSIONS: &str = "/var/lib/egrio/sessions";
/// The helper command the unit runs.
pub const LINUX_SERVICE_RUN_COMMAND: &str = "run-linux-service";
/// Lets a user use the helper, installing it outside a package and starting
/// it as needed; run as root.
pub const LINUX_SERVICE_INSTALL_COMMAND: &str = "install-linux-service";
/// Starts a package's helper, in place of one an app installed itself; the
/// package's install script runs it as root.
pub const LINUX_PACKAGE_INSTALL_COMMAND: &str = "install-linux-package";
/// Stops the helper and removes what was installed outside a package and the
/// list of users; run as root.
pub const LINUX_SERVICE_UNINSTALL_COMMAND: &str = "uninstall-linux-service";

/// The unit that runs the helper at `executable`. It keeps only the
/// capabilities TUN mode needs: `CAP_NET_ADMIN` for the TUN, routes, nftables
/// and `SO_MARK`, and `CAP_NET_RAW` for `SO_MARK` on newer kernels; its state
/// directory, unlike the runtime one, stays when the unit stops and is
/// writable under `ProtectSystem=strict` (systemd.exec(5)).
pub fn linux_service_unit(executable: &str) -> String {
    format!(
        "[Unit]
Description=Egrio TUN mode helper
After=systemd-resolved.service

[Service]
Type=notify
ExecStart={executable} {LINUX_SERVICE_RUN_COMMAND}
Restart=always
RestartSec=1
RuntimeDirectory=egrio
RuntimeDirectoryMode=0755
StateDirectory=egrio
StateDirectoryMode=0700
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"
    )
}

/// The helper a unit written by [`linux_service_unit`] runs.
pub fn linux_service_unit_executable(unit: &str) -> Option<&str> {
    unit.lines()
        .find_map(|line| line.strip_prefix("ExecStart="))?
        .split_whitespace()
        .next()
}

/// The installation systemd runs: its unit file and the helper it starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxServiceInstallation {
    pub unit_path: &'static str,
    pub executable: String,
}

/// The installed helper, if any; one an app installed itself comes first, as
/// systemd loads it in place of the package's.
pub fn linux_service_installation() -> Option<LinuxServiceInstallation> {
    [LINUX_SERVICE_UNIT_PATH, LINUX_PACKAGE_UNIT_PATH]
        .into_iter()
        .find_map(|unit_path| {
            let unit = std::fs::read_to_string(unit_path).ok()?;
            Some(LinuxServiceInstallation {
                unit_path,
                executable: linux_service_unit_executable(&unit)?.to_string(),
            })
        })
}

/// The uids a list in the format of [`LINUX_SERVICE_ALLOWED_UIDS`] holds;
/// lines that are not a uid count for nothing.
pub fn linux_service_allowed_uids(list: &str) -> Vec<u32> {
    list.lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// The list of `uids` in the format of [`LINUX_SERVICE_ALLOWED_UIDS`].
pub fn linux_service_allowed_uids_list(uids: &[u32]) -> String {
    uids.iter().map(|uid| format!("{uid}\n")).collect()
}

/// Whether the helper serves `uid`: root always, other users once listed.
pub fn linux_service_allows(uid: u32) -> bool {
    uid == 0
        || std::fs::read_to_string(LINUX_SERVICE_ALLOWED_UIDS)
            .is_ok_and(|list| linux_service_allowed_uids(&list).contains(&uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_runs_the_helper_it_names() {
        let unit = linux_service_unit(LINUX_SERVICE_EXECUTABLE);
        assert!(unit.contains(&format!(
            "ExecStart={LINUX_SERVICE_EXECUTABLE} run-linux-service\n"
        )));
        assert_eq!(
            linux_service_unit_executable(&unit),
            Some(LINUX_SERVICE_EXECUTABLE)
        );
        assert_eq!(
            linux_service_unit_executable("[Service]\nType=simple\n"),
            None
        );
    }

    #[test]
    fn the_package_unit_is_the_one_the_layout_writes() {
        let shipped = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../desktop/egrio/linux/package/egrio-service.service"
        ))
        .unwrap();
        assert_eq!(
            shipped.replace("\r\n", "\n"),
            linux_service_unit(LINUX_PACKAGE_SERVICE_EXECUTABLE)
        );
    }

    #[test]
    fn the_list_of_users_holds_one_uid_a_line() {
        let list = linux_service_allowed_uids_list(&[1000, 1001]);
        assert_eq!(list, "1000\n1001\n");
        assert_eq!(linux_service_allowed_uids(&list), vec![1000, 1001]);
        assert_eq!(
            linux_service_allowed_uids("1000\nnot a uid\n\n 1002 \n"),
            vec![1000, 1002]
        );
    }
}
