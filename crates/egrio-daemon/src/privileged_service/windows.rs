use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::Duration;

use egrio_platform_windows::{
    windows_service_name, windows_service_program, WINDOWS_SERVICE_BOOTSTRAP_COMMAND,
};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    StartServiceW, QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

use super::{PrivilegedServiceState, PrivilegedServiceStatus};

const SERVICE_START_WAIT_ATTEMPTS: usize = 25;

pub fn privileged_service_status() -> PrivilegedServiceStatus {
    let service_name = windows_service_name();
    match query_service_current_state(&service_name) {
        Ok(Some(current_state)) => status_from_service_state(&service_name, current_state),
        Ok(None) => PrivilegedServiceStatus {
            state: PrivilegedServiceState::NotInstalled,
            endpoint: Some(service_endpoint(&service_name)),
            detail: Some(format!("Windows service '{service_name}' is not installed")),
        },
        Err(error) => PrivilegedServiceStatus {
            state: PrivilegedServiceState::Unhealthy,
            endpoint: Some(service_endpoint(&service_name)),
            detail: Some(error),
        },
    }
}

fn service_endpoint(service_name: &str) -> String {
    format!("windows-service:{service_name}")
}

/// Starts the installed service and waits until it runs.
pub fn start_privileged_service() -> Result<(), String> {
    let service_name = windows_service_name();
    if let Ok(Some(SERVICE_RUNNING)) = query_service_current_state(&service_name) {
        return Ok(());
    }

    let service_name_wide = wide_null(&service_name);
    unsafe {
        let scm = ServiceHandle::open_sc_manager(SC_MANAGER_CONNECT)?;
        let Some(service) = ServiceHandle::open_service(
            scm.raw(),
            &service_name_wide,
            SERVICE_QUERY_STATUS | SERVICE_START,
        )?
        else {
            return Err(format!("Windows service '{service_name}' is not installed"));
        };
        let ok = StartServiceW(service.raw(), 0, null());
        if ok == 0 {
            let error = GetLastError();
            if error != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(format!(
                    "failed to start Windows service '{service_name}': {}",
                    os_error_message(error)
                ));
            }
        }
    }
    wait_until_service_running(&service_name)
}

/// Whether the current (possibly non-elevated) process can start and stop
/// the installed service, which the elevated install grants the interactive
/// user. `false` too when the service is not installed or the SCM cannot be
/// opened.
pub fn current_process_can_control_service() -> bool {
    let service_name = wide_null(&windows_service_name());
    unsafe {
        let Ok(scm) = ServiceHandle::open_sc_manager(SC_MANAGER_CONNECT) else {
            return false;
        };
        matches!(
            ServiceHandle::open_service(scm.raw(), &service_name, SERVICE_START | SERVICE_STOP),
            Ok(Some(_))
        )
    }
}

/// The executable the installed service is registered to run; `None` when
/// it is not installed or its registration cannot be read. The service admits
/// only clients from its own directory, so a host compares this with the copy
/// beside itself.
pub fn privileged_service_executable() -> Option<PathBuf> {
    let service_name = wide_null(&windows_service_name());
    unsafe {
        let scm = ServiceHandle::open_sc_manager(SC_MANAGER_CONNECT).ok()?;
        let service =
            ServiceHandle::open_service(scm.raw(), &service_name, SERVICE_QUERY_CONFIG).ok()??;
        windows_service_program(&query_service_command_line(&service).ok()??)
    }
}

fn wait_until_service_running(service_name: &str) -> Result<(), String> {
    for _ in 0..SERVICE_START_WAIT_ATTEMPTS {
        match query_service_current_state(service_name)? {
            Some(SERVICE_RUNNING) => return Ok(()),
            Some(SERVICE_START_PENDING) | Some(SERVICE_STOP_PENDING) => {
                thread::sleep(Duration::from_millis(200));
            }
            Some(SERVICE_STOPPED) => {
                return Err(format!(
                    "Windows service '{service_name}' stopped while waiting for startup"
                ));
            }
            None => return Err(format!("Windows service '{service_name}' is not installed")),
            Some(state) => {
                return Err(format!(
                    "Windows service '{service_name}' entered state {state} while waiting for startup"
                ));
            }
        }
    }

    Err(format!(
        "timed out waiting for Windows service '{service_name}' to start"
    ))
}

fn query_service_current_state(service_name: &str) -> Result<Option<u32>, String> {
    let service_name_wide = wide_null(service_name);

    unsafe {
        let scm = ServiceHandle::open_sc_manager(SC_MANAGER_CONNECT)?;
        let Some(service) =
            ServiceHandle::open_service(scm.raw(), &service_name_wide, SERVICE_QUERY_STATUS)?
        else {
            return Ok(None);
        };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0_u32;
        let ok = QueryServiceStatusEx(
            service.raw(),
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        );

        if ok == 0 {
            Err(format!(
                "failed to query Windows service '{service_name}' status: {}",
                last_os_error_message()
            ))
        } else {
            Ok(Some(status.dwCurrentState))
        }
    }
}

fn status_from_service_state(service_name: &str, current_state: u32) -> PrivilegedServiceStatus {
    let (state, detail) = match current_state {
        SERVICE_RUNNING => (PrivilegedServiceState::Running, None),
        SERVICE_STOPPED => (PrivilegedServiceState::Stopped, Some("is stopped".into())),
        SERVICE_START_PENDING => (PrivilegedServiceState::Stopped, Some("is starting".into())),
        SERVICE_STOP_PENDING => (
            PrivilegedServiceState::Unhealthy,
            Some("is stopping".into()),
        ),
        SERVICE_PAUSED => (PrivilegedServiceState::Unhealthy, Some("is paused".into())),
        SERVICE_PAUSE_PENDING | SERVICE_CONTINUE_PENDING => (
            PrivilegedServiceState::Unhealthy,
            Some(format!("is transitioning state {current_state}")),
        ),
        _ => (
            PrivilegedServiceState::Unhealthy,
            Some(format!("reported unknown state {current_state}")),
        ),
    };
    PrivilegedServiceStatus {
        state,
        endpoint: Some(service_endpoint(service_name)),
        detail: detail.map(|detail: String| format!("Windows service '{service_name}' {detail}")),
    }
}

struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    unsafe fn open_sc_manager(desired_access: u32) -> Result<Self, String> {
        let handle = OpenSCManagerW(null(), null(), desired_access);
        if handle.is_null() {
            Err(format!(
                "failed to open Windows Service Control Manager: {}",
                last_os_error_message()
            ))
        } else {
            Ok(Self(handle))
        }
    }

    unsafe fn open_service(
        sc_manager: SC_HANDLE,
        service_name: &[u16],
        desired_access: u32,
    ) -> Result<Option<Self>, String> {
        let handle = OpenServiceW(sc_manager, service_name.as_ptr(), desired_access);
        if !handle.is_null() {
            return Ok(Some(Self(handle)));
        }

        let error = GetLastError();
        if error == ERROR_SERVICE_DOES_NOT_EXIST {
            Ok(None)
        } else {
            Err(format!(
                "failed to open Windows service '{}': {}",
                String::from_utf16_lossy(&service_name[..service_name.len().saturating_sub(1)]),
                os_error_message(error)
            ))
        }
    }

    fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Reads an existing service's registered command line (`lpBinaryPathName`)
/// through the two-call `QueryServiceConfigW` size probe; `None` when the field
/// is empty. The buffer is over-aligned (a `u64` vec) because
/// `QUERY_SERVICE_CONFIGW` holds pointers, so casting a `u8` buffer would be
/// unsound.
unsafe fn query_service_command_line(service: &ServiceHandle) -> Result<Option<String>, String> {
    let mut needed = 0u32;
    let probe = QueryServiceConfigW(service.raw(), null_mut(), 0, &mut needed);
    if probe == 0 {
        let error = GetLastError();
        if error != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!(
                "failed to read Windows service configuration: {}",
                os_error_message(error)
            ));
        }
    }
    if needed == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0u64; (needed as usize + 7) / 8];
    let config = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    let ok = QueryServiceConfigW(service.raw(), config, needed, &mut needed);
    if ok == 0 {
        return Err(format!(
            "failed to read Windows service configuration: {}",
            last_os_error_message()
        ));
    }
    let binary_path = (*config).lpBinaryPathName;
    if binary_path.is_null() {
        return Ok(None);
    }
    Ok(Some(wide_ptr_to_string(binary_path)))
}

/// Reads a NUL-terminated wide string from a Win32 pointer into an owned
/// `String` (lossy on invalid UTF-16, which service paths never are).
unsafe fn wide_ptr_to_string(pointer: *const u16) -> String {
    let mut length = 0usize;
    while *pointer.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Installs or re-points, then starts, the service through one elevated
/// `egrio-service bootstrap-windows-service` process, so the user sees a
/// single UAC prompt and the desktop app never runs elevated.
pub fn bootstrap_privileged_service_elevated(service_executable_path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let executable = service_executable_path
        .to_str()
        .ok_or_else(|| "service executable path is not valid UTF-8".to_string())?;
    let verb = wide_null("runas");
    let file = wide_null(executable);
    let parameters = wide_null(WINDOWS_SERVICE_BOOTSTRAP_COMMAND);

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    // SW_HIDE keeps the elevated console helper from flashing a window.
    info.nShow = SW_HIDE as i32;

    let launched = unsafe { ShellExecuteExW(&mut info) };
    if launched == 0 {
        let error = unsafe { GetLastError() };
        // ERROR_CANCELLED (1223) is the user declining the UAC prompt.
        if error == 1223 {
            return Err(
                "elevation was cancelled; enhanced mode setup needs a one-time administrator approval"
                    .into(),
            );
        }
        return Err(format!(
            "failed to launch elevated privileged service bootstrap: {}",
            os_error_message(error)
        ));
    }

    if info.hProcess.is_null() {
        return Err("elevated privileged service bootstrap did not return a process handle".into());
    }

    let exit_code = unsafe {
        let wait = WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 0u32;
        let read_code = GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        if wait != WAIT_OBJECT_0 {
            return Err("timed out waiting for elevated privileged service bootstrap".into());
        }
        if read_code == 0 {
            return Err("failed to read elevated privileged service bootstrap exit code".into());
        }
        code
    };

    if exit_code != 0 && !privileged_service_status().running() {
        return Err(format!(
            "elevated privileged service bootstrap exited with code {exit_code} and the service is not running"
        ));
    }
    Ok(())
}

fn last_os_error_message() -> String {
    unsafe { os_error_message(GetLastError()) }
}

fn os_error_message(error: u32) -> String {
    std::io::Error::from_raw_os_error(error as i32).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_service_is_ready() {
        let status = status_from_service_state("EgrioService", SERVICE_RUNNING);

        assert!(status.running());
        assert_eq!(
            status.endpoint.as_deref(),
            Some("windows-service:EgrioService")
        );
        assert!(status.detail.is_none());
    }

    #[test]
    fn a_stopped_service_says_so() {
        let status = status_from_service_state("EgrioService", SERVICE_STOPPED);

        assert_eq!(status.state, PrivilegedServiceState::Stopped);
        assert_eq!(
            status.detail.as_deref(),
            Some("Windows service 'EgrioService' is stopped")
        );
    }

    #[test]
    fn an_unknown_state_is_unhealthy() {
        let status = status_from_service_state("EgrioService", 999);

        assert_eq!(status.state, PrivilegedServiceState::Unhealthy);
        assert!(status
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("unknown state 999")));
    }
}
