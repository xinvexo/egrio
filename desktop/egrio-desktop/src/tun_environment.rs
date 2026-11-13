//! The one-time environment TUN mode needs before it can start: the
//! privileged service on Windows, the launchd service the user allowed on
//! macOS, the root helper on Linux. Checking it never opens a TUN device;
//! the platform capture does that when TUN starts.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum TunEnvironment {
    Ready,
    /// The OS parked the install until the user approves it; System
    /// Settings is open where they do.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    ApprovalRequired,
    Blocked {
        error: String,
    },
}

/// Whether the environment is ready, without changing anything.
pub async fn is_ready() -> bool {
    platform::is_ready().await
}

/// Readies the environment, prompting the user where the platform requires
/// it: UAC for the Windows service install, allowing the macOS service in
/// Login Items, polkit consent for the Linux helper install.
pub async fn ensure() -> TunEnvironment {
    platform::ensure().await
}

/// The privileged service executable staged beside the app executable;
/// `EGRIO_SERVICE_PATH` overrides it for development builds.
#[cfg(any(windows, target_os = "linux"))]
fn bundled_service_executable(file_name: &str) -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("EGRIO_SERVICE_PATH").map(std::path::PathBuf::from) {
        if explicit.is_file() {
            return Some(explicit);
        }
    }
    let sibling = std::env::current_exe().ok()?.parent()?.join(file_name);
    sibling.is_file().then_some(sibling)
}

#[cfg(windows)]
mod platform {
    use std::path::{Path, PathBuf};

    use egrio_daemon::privileged_service::{
        bootstrap_privileged_service_elevated, current_process_can_control_service,
        privileged_service_executable, privileged_service_status, start_privileged_service,
    };

    use super::TunEnvironment;

    pub(super) async fn is_ready() -> bool {
        crate::async_runtime::spawn_blocking(|| {
            bundled_service().and_then(|service| service_serves(&service))
        })
        .await
        .is_ok_and(|ready| ready.is_ok())
    }

    pub(super) async fn ensure() -> TunEnvironment {
        crate::async_runtime::spawn_blocking(ensure_service)
            .await
            .unwrap_or_else(|error| TunEnvironment::Blocked {
                error: format!("TUN environment task failed: {error}"),
            })
    }

    fn ensure_service() -> TunEnvironment {
        let service = match bundled_service() {
            Ok(service) => service,
            Err(error) => return TunEnvironment::Blocked { error },
        };
        if service_serves(&service).is_ok() {
            return TunEnvironment::Ready;
        }
        // A stopped service already registered here starts without UAC.
        if registered_here(&service) && current_process_can_control_service() {
            let _ = start_privileged_service();
            if service_serves(&service).is_ok() {
                return TunEnvironment::Ready;
            }
        }
        // One UAC prompt installs or re-points, repairs and starts it.
        if let Err(error) = bootstrap_privileged_service_elevated(&service) {
            return TunEnvironment::Blocked { error };
        }
        match service_serves(&service) {
            Ok(()) => TunEnvironment::Ready,
            Err(error) => TunEnvironment::Blocked { error },
        }
    }

    /// The service executable beside this app, with the driver it loads.
    fn bundled_service() -> Result<PathBuf, String> {
        let service = super::bundled_service_executable("egrio-service.exe")
            .ok_or("egrio-service.exe is missing beside Egrio")?;
        if !service.with_file_name("wintun.dll").is_file() {
            return Err("wintun.dll is missing beside Egrio".into());
        }
        Ok(service)
    }

    /// The service admits only clients from its own directory, so TUN needs
    /// the installed service running this app's copy.
    fn service_serves(service: &Path) -> Result<(), String> {
        if !privileged_service_status().running() {
            return Err("the Egrio service is not running".into());
        }
        match privileged_service_executable() {
            Some(registered) if same_path(&registered, service) => Ok(()),
            Some(registered) => Err(format!(
                "the Egrio service runs {} instead of the copy beside this app",
                registered.display()
            )),
            None => Err("the Egrio service registration is unreadable".into()),
        }
    }

    fn registered_here(service: &Path) -> bool {
        privileged_service_executable().is_some_and(|registered| same_path(&registered, service))
    }

    fn same_path(left: &Path, right: &Path) -> bool {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::time::Duration;

    use egrio_daemon::privileged_service::{
        macos_service_serves, open_login_items_settings, register_macos_service,
        MacosServiceRegistration,
    };
    use egrio_sdk::MacosServiceHello;

    use super::TunEnvironment;

    /// How long a just-allowed service, or the copy replacing an older one,
    /// may take to answer: launchd spawns it at most every two seconds.
    const START_BUDGET: Duration = Duration::from_secs(8);

    pub(super) async fn is_ready() -> bool {
        crate::async_runtime::spawn_blocking(|| macos_service_serves().is_ok())
            .await
            .unwrap_or(false)
    }

    /// A service that answers this app is ready, however it was started.
    /// Otherwise registers the bundled service, even one that reads as
    /// enabled: macOS 13 leaves a service the user has just allowed in Login
    /// Items unloaded, and registering it again has launchd load it. A copy
    /// that answers another protocol (the previous app's) gives way, and
    /// this waits for the new one.
    pub(super) async fn ensure() -> TunEnvironment {
        if egrio_sdk::macos_service_hello(env!("CARGO_PKG_VERSION"))
            .await
            .is_ok()
        {
            return TunEnvironment::Ready;
        }
        let registration = crate::async_runtime::spawn_blocking(register_macos_service)
            .await
            .unwrap_or_else(|error| Err(format!("TUN environment task failed: {error}")));
        match registration {
            Ok(MacosServiceRegistration::Enabled) => answering().await,
            Ok(MacosServiceRegistration::RequiresApproval) => {
                open_login_items_settings();
                TunEnvironment::ApprovalRequired
            }
            Ok(_) => TunEnvironment::Blocked {
                error: "the Egrio service could not be registered".into(),
            },
            Err(error) => TunEnvironment::Blocked { error },
        }
    }

    async fn answering() -> TunEnvironment {
        let deadline = tokio::time::Instant::now() + START_BUDGET;
        loop {
            let error = match egrio_sdk::macos_service_hello(env!("CARGO_PKG_VERSION")).await {
                Ok(()) => return TunEnvironment::Ready,
                Err(MacosServiceHello::Refused(error)) => {
                    return TunEnvironment::Blocked { error };
                }
                Err(
                    MacosServiceHello::Unreachable(error) | MacosServiceHello::OtherProtocol(error),
                ) => error,
            };
            if tokio::time::Instant::now() >= deadline {
                return TunEnvironment::Blocked { error };
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::path::PathBuf;

    use egrio_daemon::privileged_service::{
        await_privileged_service, bootstrap_privileged_service_elevated, privileged_service_serves,
    };

    use super::TunEnvironment;

    pub(super) async fn is_ready() -> bool {
        crate::async_runtime::spawn_blocking(|| {
            bundled_service().and_then(|service| privileged_service_serves(&service))
        })
        .await
        .is_ok_and(|ready| ready.is_ok())
    }

    pub(super) async fn ensure() -> TunEnvironment {
        crate::async_runtime::spawn_blocking(ensure_service)
            .await
            .unwrap_or_else(|error| TunEnvironment::Blocked {
                error: format!("TUN environment task failed: {error}"),
            })
    }

    fn ensure_service() -> TunEnvironment {
        let service = match bundled_service() {
            Ok(service) => service,
            Err(error) => return TunEnvironment::Blocked { error },
        };
        // systemd restarts a crashed helper on its own; consent is only for a
        // helper that is missing, outdated, not serving this user or stopped.
        if await_privileged_service(&service).is_ok() {
            return TunEnvironment::Ready;
        }
        // One polkit prompt installs or updates the helper for this user and
        // restarts it.
        if let Err(error) = bootstrap_privileged_service_elevated(&service) {
            return TunEnvironment::Blocked { error };
        }
        match privileged_service_serves(&service) {
            Ok(()) => TunEnvironment::Ready,
            Err(error) => TunEnvironment::Blocked { error },
        }
    }

    fn bundled_service() -> Result<PathBuf, String> {
        super::bundled_service_executable("egrio-service")
            .ok_or_else(|| "egrio-service is missing beside Egrio".into())
    }
}
