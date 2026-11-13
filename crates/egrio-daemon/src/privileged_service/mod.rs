//! The desktop side of the privileged service: its status, whether it runs
//! the copy beside this app, starting it, and the one-time install (UAC on
//! Windows, polkit through `pkexec` on Linux, an SMAppService registration
//! the user allows in Login Items on macOS). The Windows and Linux services
//! register and remove themselves (`egrio-service bootstrap-windows-service`,
//! `install-linux-service` and their uninstall commands); runtime capability
//! execution (TUN, routes, DNS, firewall) lives in `egrio-service` and is
//! reached through the Runtime SDK, never through this module.

use serde::Serialize;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "linux")]
pub use linux::{
    await_privileged_service, bootstrap_privileged_service_elevated, privileged_service_serves,
};
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(target_os = "macos")]
pub use macos::{
    macos_service_registration, macos_service_serves, open_login_items_settings,
    register_macos_service, unregister_macos_service, MacosServiceRegistration,
};
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
use unsupported as platform;
#[cfg(windows)]
use windows as platform;
#[cfg(windows)]
pub use windows::{
    bootstrap_privileged_service_elevated, current_process_can_control_service,
    privileged_service_executable, start_privileged_service,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegedServiceState {
    NotInstalled,
    Stopped,
    Running,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedServiceStatus {
    pub state: PrivilegedServiceState,
    /// Where clients reach the service.
    pub endpoint: Option<String>,
    /// Why the service is not running.
    pub detail: Option<String>,
}

impl PrivilegedServiceStatus {
    pub fn running(&self) -> bool {
        self.state == PrivilegedServiceState::Running
    }
}

pub fn privileged_service_status() -> PrivilegedServiceStatus {
    platform::privileged_service_status()
}
