//! How the Windows privileged service is registered with the Service Control
//! Manager. `egrio-service`'s bootstrap and uninstall commands write and
//! remove the registration; the desktop reads it to decide whether TUN mode's
//! environment is ready.

use std::path::PathBuf;

/// The SCM name of the service unless `EGRIO_WINDOWS_SERVICE_NAME` names
/// another.
pub const WINDOWS_SERVICE_NAME: &str = "EgrioService";
const WINDOWS_SERVICE_NAME_ENV: &str = "EGRIO_WINDOWS_SERVICE_NAME";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "Egrio Service";
/// The command the registration runs.
pub const WINDOWS_SERVICE_RUN_COMMAND: &str = "run-windows-service";
/// Registers the running executable (or re-points an Egrio registration at
/// it) and starts it; the desktop runs it elevated once.
pub const WINDOWS_SERVICE_BOOTSTRAP_COMMAND: &str = "bootstrap-windows-service";
/// Stops the service and removes its registration.
pub const WINDOWS_SERVICE_UNINSTALL_COMMAND: &str = "uninstall-windows-service";
/// The desktop app's executable, the client the service admits beside it.
pub const WINDOWS_APP_EXECUTABLE: &str = "egrio.exe";

pub fn windows_service_name() -> String {
    std::env::var(WINDOWS_SERVICE_NAME_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| WINDOWS_SERVICE_NAME.into())
}

/// The command line registered for `executable`.
pub fn windows_service_command_line(executable: &str, service_name: &str) -> String {
    format!("\"{executable}\" {WINDOWS_SERVICE_RUN_COMMAND} {service_name}")
}

/// Whether a registered command line is Egrio's: `egrio-service.exe` with the
/// run command. A foreign service that only shares the name is never
/// re-pointed, started or removed.
pub fn is_windows_service_command_line(command_line: &str) -> bool {
    let lowered = command_line.to_ascii_lowercase();
    lowered.contains("egrio-service.exe") && lowered.contains(WINDOWS_SERVICE_RUN_COMMAND)
}

/// The program of a registered command line: the leading quoted path, or the
/// first whitespace-separated word when it is unquoted.
pub fn windows_service_program(command_line: &str) -> Option<PathBuf> {
    let command_line = command_line.trim_start();
    let program = match command_line.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next()?,
        None => command_line.split_whitespace().next()?,
    };
    (!program.is_empty()).then(|| PathBuf::from(program))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_runs_the_service_executable() {
        let command = windows_service_command_line(
            r"C:\Program Files\Egrio\egrio-service.exe",
            WINDOWS_SERVICE_NAME,
        );
        assert_eq!(
            command,
            r#""C:\Program Files\Egrio\egrio-service.exe" run-windows-service EgrioService"#
        );
        assert!(is_windows_service_command_line(&command));
        assert_eq!(
            windows_service_program(&command),
            Some(PathBuf::from(r"C:\Program Files\Egrio\egrio-service.exe"))
        );
    }

    #[test]
    fn egrio_registrations_are_recognized_wherever_they_point() {
        assert!(is_windows_service_command_line(
            r#""E:\egrio\target\debug\egrio-service.exe" "run-windows-service" "EgrioService""#
        ));
        assert!(is_windows_service_command_line(
            r#""D:\EGRIO\EGRIO-SERVICE.EXE" RUN-WINDOWS-SERVICE EgrioService"#
        ));
    }

    #[test]
    fn foreign_registrations_are_not_egrio() {
        assert!(!is_windows_service_command_line(
            r#""C:\Other\payload.exe""#
        ));
        assert!(!is_windows_service_command_line("svchost.exe -k netsvcs"));
        assert!(!is_windows_service_command_line(
            r#""C:\Other\egrio-service.exe""#
        ));
    }

    #[test]
    fn registered_command_lines_yield_their_program() {
        assert_eq!(
            windows_service_program(r"C:\egrio\egrio-service.exe run-windows-service"),
            Some(PathBuf::from(r"C:\egrio\egrio-service.exe"))
        );
        assert_eq!(windows_service_program("\"\""), None);
        assert_eq!(windows_service_program("   "), None);
    }
}
