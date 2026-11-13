//! The macOS service as the desktop sees it. The app bundle carries the
//! service and its launchd property list; SMAppService registers it
//! (ServiceManagement `SMAppService.h`, `daemonServiceWithPlistName:`), the
//! user allows it once in System Settings > General > Login Items &
//! Extensions, and launchd then runs the bundled copy as root and keeps it
//! running.

use std::os::unix::net::UnixStream;

use egrio_platform_macos::{MACOS_SERVICE_PLIST, MACOS_SERVICE_SOCKET};
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use serde::Serialize;

use super::{PrivilegedServiceState, PrivilegedServiceStatus};

/// Where launchd's registration of the bundled service stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MacosServiceRegistration {
    Enabled,
    /// Registered; launchd runs it once the user allows it in Login Items.
    RequiresApproval,
    NotRegistered,
}

fn daemon() -> Retained<SMAppService> {
    // SAFETY: a plain constructor taking the property list's name.
    unsafe { SMAppService::daemonServiceWithPlistName(&NSString::from_str(MACOS_SERVICE_PLIST)) }
}

/// A service never registered reads as not found rather than not registered
/// (macOS 27), so both count as not registered; registering then reports
/// what is really missing.
pub fn macos_service_registration() -> MacosServiceRegistration {
    // SAFETY: reads the service's registration.
    match unsafe { daemon().status() } {
        SMAppServiceStatus::Enabled => MacosServiceRegistration::Enabled,
        SMAppServiceStatus::RequiresApproval => MacosServiceRegistration::RequiresApproval,
        _ => MacosServiceRegistration::NotRegistered,
    }
}

/// Registers the bundled service with launchd, which loads it once the user
/// has allowed it; registering an enabled service that launchd has not
/// loaded loads it. Registration the user has not allowed yet stands as
/// [`MacosServiceRegistration::RequiresApproval`].
pub fn register_macos_service() -> Result<MacosServiceRegistration, String> {
    // SAFETY: registers the service from this app's bundle.
    if let Err(error) = unsafe { daemon().registerAndReturnError() } {
        let registration = macos_service_registration();
        // A registration awaiting approval reports an error too, and so may
        // one already in place (`kSMErrorAlreadyRegistered`).
        if registration == MacosServiceRegistration::NotRegistered {
            return Err(format!(
                "register the Egrio service: {}",
                error.localizedDescription()
            ));
        }
    }
    Ok(macos_service_registration())
}

/// Removes the registration; launchd stops the service.
pub fn unregister_macos_service() -> Result<(), String> {
    // SAFETY: unregisters the service of this app's bundle.
    unsafe { daemon().unregisterAndReturnError() }.map_err(|error| {
        format!(
            "unregister the Egrio service: {}",
            error.localizedDescription()
        )
    })
}

/// Opens System Settings at Login Items, where the user allows the service.
pub fn open_login_items_settings() {
    // SAFETY: opens a System Settings pane.
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}

/// Whether the service accepts control connections now.
pub fn macos_service_serves() -> Result<(), String> {
    UnixStream::connect(MACOS_SERVICE_SOCKET)
        .map(drop)
        .map_err(|error| {
            format!("the Egrio service does not answer at {MACOS_SERVICE_SOCKET}: {error}")
        })
}

pub fn privileged_service_status() -> PrivilegedServiceStatus {
    let endpoint = Some(MACOS_SERVICE_SOCKET.to_string());
    let (state, detail) = match macos_service_registration() {
        MacosServiceRegistration::Enabled => match macos_service_serves() {
            Ok(()) => (PrivilegedServiceState::Running, None),
            Err(error) => (PrivilegedServiceState::Stopped, Some(error)),
        },
        MacosServiceRegistration::RequiresApproval => (
            PrivilegedServiceState::Stopped,
            Some("the user has not allowed the Egrio service in Login Items yet".into()),
        ),
        MacosServiceRegistration::NotRegistered => (PrivilegedServiceState::NotInstalled, None),
    };
    PrivilegedServiceStatus {
        state,
        endpoint,
        detail,
    }
}
