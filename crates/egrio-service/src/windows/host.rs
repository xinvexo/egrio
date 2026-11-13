use std::mem::size_of;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use egrio_platform_windows::{
    is_windows_service_command_line, windows_service_command_line, windows_service_name,
    WINDOWS_SERVICE_BOOTSTRAP_COMMAND, WINDOWS_SERVICE_DISPLAY_NAME, WINDOWS_SERVICE_RUN_COMMAND,
    WINDOWS_SERVICE_UNINSTALL_COMMAND,
};
use egrio_runtime::CapabilityKind;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE,
    ERROR_SERVICE_NOT_ACTIVE, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    RegisterServiceCtrlHandlerExW, SetServiceObjectSecurity, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::session::ControlServerSession;
use crate::transport::TransportErrorKind;

use super::{
    AdmittedClient, Event, Served, WindowsNamedPipeListener, WindowsPacketControlHandler,
    WindowsServiceResources,
};

/// The standard DELETE right, which `DeleteService` requires.
const SERVICE_DELETE_ACCESS: u32 = 0x0001_0000;
const SERVICE_WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const START_WAIT_ATTEMPTS: usize = 50;
const STOP_WAIT_ATTEMPTS: usize = 75;
const STOP_WAIT_HINT_MS: u32 = 12_000;
/// The pauses between accepts that keep failing: the first, and the longest
/// they double up to.
const ACCEPT_PAUSE_MIN: Duration = Duration::from_millis(100);
const ACCEPT_PAUSE_MAX: Duration = Duration::from_secs(5);
/// The capabilities a Windows service session offers.
const CAPABILITIES: [CapabilityKind; 4] = [
    CapabilityKind::PacketCapture,
    CapabilityKind::Route,
    CapabilityKind::Dns,
    CapabilityKind::Firewall,
];
const INTERACTIVE_CONTROL_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPLOCRRC;;;IU)";

static SERVICE_NAME: OnceLock<String> = OnceLock::new();
/// Set by the service control handler when the service is to stop: every
/// wait of the control loop and of its sessions watches it.
static STOP: OnceLock<Event> = OnceLock::new();
static STATUS_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(null_mut());

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCommand {
    Run { service_name: String },
    Bootstrap,
    Uninstall,
    Version,
}

pub fn parse_service_command<I, S>(arguments: I) -> Result<ServiceCommand, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    match arguments.next().as_deref() {
        None | Some("version") | Some("--version") => Ok(ServiceCommand::Version),
        Some(WINDOWS_SERVICE_RUN_COMMAND) => {
            let service_name = arguments
                .next()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(windows_service_name);
            if arguments.next().is_some() {
                return Err("run-windows-service accepts at most one service name".into());
            }
            Ok(ServiceCommand::Run { service_name })
        }
        Some(command @ (WINDOWS_SERVICE_BOOTSTRAP_COMMAND | WINDOWS_SERVICE_UNINSTALL_COMMAND)) => {
            if arguments.next().is_some() {
                return Err(format!("{command} accepts no arguments"));
            }
            Ok(if command == WINDOWS_SERVICE_BOOTSTRAP_COMMAND {
                ServiceCommand::Bootstrap
            } else {
                ServiceCommand::Uninstall
            })
        }
        Some(command) => Err(format!("unknown egrio-service command '{command}'")),
    }
}

pub fn run_from_env() -> Result<(), String> {
    restrict_library_search();
    match parse_service_command(std::env::args().skip(1))? {
        ServiceCommand::Run { service_name } => run_windows_service(service_name),
        ServiceCommand::Bootstrap => bootstrap_current_executable(),
        ServiceCommand::Uninstall => uninstall_service(&windows_service_name()),
        ServiceCommand::Version => {
            let version = crate::protocol_version();
            println!("egrio-service protocol {}.{}", version.major, version.minor);
            Ok(())
        }
    }
}

/// Libraries this process loads by name come from System32 only, as its
/// statically linked ones do (`/DEPENDENTLOADFLAG` in build.rs): the service
/// runs as LocalSystem from wherever Egrio is installed, a folder others may
/// add files to. `wintun.dll` loads by its full path beside the service.
fn restrict_library_search() {
    // SAFETY: sets this process's default library search directories.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
}

fn bootstrap_current_executable() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve egrio-service executable: {error}"))?;
    let service_name = windows_service_name();
    if install_or_update_service(&executable, &service_name)? {
        // The running process still serves the previous location, whose
        // clients this app is not among; replace it with this executable.
        stop_service(&service_name)?;
    }
    start_service(&service_name)
}

fn run_windows_service(service_name: String) -> Result<(), String> {
    let _ = SERVICE_NAME.set(service_name.clone());
    // Before the dispatcher can deliver a control to the handler that sets it.
    let stop = Event::new()
        .map_err(|error| format!("failed to create the service's stop event: {error}"))?;
    let _ = STOP.set(stop);
    STATUS_HANDLE.store(null_mut(), Ordering::SeqCst);
    let mut service_name_wide = wide_null(&service_name);
    let mut table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name_wide.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) } == 0 {
        return Err(format!(
            "failed to start Windows service dispatcher for '{service_name}': {}",
            last_os_error()
        ));
    }
    Ok(())
}

unsafe extern "system" fn service_main(_: u32, _: *mut windows_sys::core::PWSTR) {
    redirect_service_stderr_to_log();
    let service_name = SERVICE_NAME
        .get()
        .cloned()
        .unwrap_or_else(windows_service_name);
    let service_name_wide = wide_null(&service_name);
    let status_handle = RegisterServiceCtrlHandlerExW(
        service_name_wide.as_ptr(),
        Some(service_control_handler),
        null(),
    );
    if status_handle.is_null() {
        return;
    }
    STATUS_HANDLE.store(status_handle, Ordering::SeqCst);
    set_service_state(status_handle, SERVICE_START_PENDING, 0, 1, 2_000);
    let served = match STOP.get() {
        Some(stop) => serve_control_loop(&service_name, stop),
        None => Err("the service's stop event was never created".into()),
    };
    if let Err(error) = served {
        eprintln!("Windows service control loop failed: {error}");
    }
    set_service_state(status_handle, SERVICE_STOPPED, 0, 0, 0);
}

/// Serves control connections until `stop` is set, each as a session on a
/// thread of its own, then waits for the sessions to end: each releases
/// what it holds of the machine when its wait sees the stop.
fn serve_control_loop(service_name: &str, stop: &'static Event) -> Result<(), String> {
    let listener =
        WindowsNamedPipeListener::for_service(service_name).map_err(|error| error.to_string())?;
    let status_handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if !status_handle.is_null() {
        set_service_state(
            status_handle,
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
            0,
        );
    }
    let config = egrio_platform_windows::windows_wintun_config_from_env()?;
    let resources = Arc::new(WindowsServiceResources::default());
    let mut sessions: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut pause = Duration::ZERO;
    loop {
        sessions.retain(|session| !session.is_finished());
        // One bad connection never stops the service; only a stop does.
        let client = match listener.accept(stop) {
            Ok(Some(client)) => client,
            Ok(None) => break,
            // A program the service does not admit, already turned away.
            Err(error) if error.kind() == TransportErrorKind::Authentication => continue,
            Err(error) => {
                eprintln!("egrio-service: control connection accept failed: {error}");
                pause = (pause * 2).clamp(ACCEPT_PAUSE_MIN, ACCEPT_PAUSE_MAX);
                if stop.wait(pause) {
                    break;
                }
                continue;
            }
        };
        pause = Duration::ZERO;
        let config = config.clone();
        let resources = Arc::clone(&resources);
        // A thread the system will not start ends this connection, not the
        // service: `thread::spawn` panics instead.
        match thread::Builder::new()
            .name("egrio-control".into())
            .spawn(move || serve_session(client, config, resources, stop))
        {
            Ok(session) => sessions.push(session),
            Err(error) => {
                eprintln!("egrio-service: control session thread did not start: {error}");
            }
        }
    }
    for session in sessions {
        let _ = session.join();
    }
    Ok(())
}

/// One desktop's session, from its first frame to the end of its
/// connection. A client that goes away, a transport fault and a packet
/// session that stopped carrying packets each end this session alone.
fn serve_session(
    client: AdmittedClient,
    config: egrio_platform_windows::WindowsWintunConfig,
    resources: Arc<WindowsServiceResources>,
    stop: &Event,
) {
    let connection = match client.identify(stop) {
        Ok(connection) => connection,
        Err(error) => {
            // A client gone before its first frame costs nothing to say.
            if error.kind() != TransportErrorKind::Disconnected {
                eprintln!("egrio-service: control client was not identified: {error}");
            }
            return;
        }
    };
    let handler =
        match WindowsPacketControlHandler::with_resources(config, connection.client(), resources) {
            Ok(handler) => handler,
            Err(error) => {
                eprintln!("egrio-service: control handler setup failed: {error}");
                return;
            }
        };
    let session = ControlServerSession::new(env!("CARGO_PKG_VERSION"), CAPABILITIES.to_vec());
    loop {
        match connection.serve_once(&session, &handler, &[stop, handler.fault()]) {
            Ok(Served::Request) => {}
            Ok(Served::Closed | Served::Interrupted(0)) => break,
            Ok(Served::Interrupted(_)) => {
                eprintln!("egrio-service: ending the control session whose packet session faulted");
                break;
            }
            Err(error) => {
                eprintln!("egrio-service: control request failed: {error}");
                break;
            }
        }
    }
    handler.disconnect();
}

unsafe extern "system" fn service_control_handler(
    control: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    if matches!(control, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN) {
        let handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if !handle.is_null() {
            set_service_state(handle, SERVICE_STOP_PENDING, 0, 1, STOP_WAIT_HINT_MS);
        }
        if let Some(stop) = STOP.get() {
            stop.set();
        }
    }
    NO_ERROR
}

/// Registers `executable` as the service, re-pointing an existing Egrio
/// registration. Returns whether that registration ran another command.
fn install_or_update_service(executable: &Path, service_name: &str) -> Result<bool, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "egrio-service executable path is not valid UTF-8".to_string())?;
    let command = windows_service_command_line(executable, service_name);
    let binary_path = wide_null(&command);
    let service_name_wide = wide_null(service_name);
    let display_name = wide_null(WINDOWS_SERVICE_DISPLAY_NAME);
    unsafe {
        let scm = ServiceHandle::open_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let created = CreateServiceW(
            scm.0,
            service_name_wide.as_ptr(),
            display_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_WRITE_DAC_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        );
        let mut repointed = false;
        let service = if created.is_null() {
            let error = GetLastError();
            if error != ERROR_SERVICE_EXISTS {
                return Err(format!(
                    "failed to install Windows service: {}",
                    os_error(error)
                ));
            }
            let service = ServiceHandle::open(
                scm.0,
                &service_name_wide,
                SERVICE_QUERY_STATUS
                    | SERVICE_QUERY_CONFIG
                    | SERVICE_CHANGE_CONFIG
                    | SERVICE_START
                    | SERVICE_WRITE_DAC_ACCESS,
            )?
            .ok_or_else(|| "existing Windows service disappeared during repair".to_string())?;
            repointed =
                !verify_owned_service(&service, service_name)?.eq_ignore_ascii_case(&command);
            if ChangeServiceConfigW(
                service.0,
                SERVICE_NO_CHANGE,
                SERVICE_AUTO_START,
                SERVICE_NO_CHANGE,
                binary_path.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            ) == 0
            {
                return Err(format!(
                    "failed to update Windows service: {}",
                    last_os_error()
                ));
            }
            service
        } else {
            ServiceHandle(created)
        };
        grant_interactive_control(&service)?;
        Ok(repointed)
    }
}

/// Stops the service and removes its registration; a registration that runs
/// another program is refused. Without a registration there is nothing to do.
fn uninstall_service(service_name: &str) -> Result<(), String> {
    let name = wide_null(service_name);
    unsafe {
        let scm = ServiceHandle::open_scm(SC_MANAGER_CONNECT)?;
        let Some(service) =
            ServiceHandle::open(scm.0, &name, SERVICE_QUERY_CONFIG | SERVICE_DELETE_ACCESS)?
        else {
            return Ok(());
        };
        verify_owned_service(&service, service_name)?;
        stop_service(service_name)?;
        // The SCM removes the registration once the last handle closes.
        if DeleteService(service.0) == 0 {
            let error = GetLastError();
            if error != ERROR_SERVICE_MARKED_FOR_DELETE {
                return Err(format!(
                    "failed to remove Windows service: {}",
                    os_error(error)
                ));
            }
        }
    }
    Ok(())
}

fn stop_service(service_name: &str) -> Result<(), String> {
    let name = wide_null(service_name);
    unsafe {
        let scm = ServiceHandle::open_scm(SC_MANAGER_CONNECT)?;
        let Some(service) = ServiceHandle::open(scm.0, &name, SERVICE_QUERY_STATUS | SERVICE_STOP)?
        else {
            return Ok(());
        };
        let mut status = SERVICE_STATUS::default();
        if ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) == 0 {
            let error = GetLastError();
            if error != ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!(
                    "failed to stop Windows service: {}",
                    os_error(error)
                ));
            }
        }
    }
    for _ in 0..STOP_WAIT_ATTEMPTS {
        if matches!(
            query_service_state(service_name)?,
            Some(SERVICE_STOPPED) | None
        ) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "timed out waiting for Windows service '{service_name}' to stop"
    ))
}

fn start_service(service_name: &str) -> Result<(), String> {
    let name = wide_null(service_name);
    unsafe {
        let scm = ServiceHandle::open_scm(SC_MANAGER_CONNECT)?;
        let service = ServiceHandle::open(scm.0, &name, SERVICE_QUERY_STATUS | SERVICE_START)?
            .ok_or_else(|| format!("Windows service '{service_name}' is not installed"))?;
        if StartServiceW(service.0, 0, null()) == 0 {
            let error = GetLastError();
            if error != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(format!(
                    "failed to start Windows service: {}",
                    os_error(error)
                ));
            }
        }
    }
    for _ in 0..START_WAIT_ATTEMPTS {
        if query_service_state(service_name)? == Some(SERVICE_RUNNING) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "timed out waiting for Windows service '{service_name}' to start"
    ))
}

fn query_service_state(service_name: &str) -> Result<Option<u32>, String> {
    let name = wide_null(service_name);
    unsafe {
        let scm = ServiceHandle::open_scm(SC_MANAGER_CONNECT)?;
        let Some(service) = ServiceHandle::open(scm.0, &name, SERVICE_QUERY_STATUS)? else {
            return Ok(None);
        };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        if QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        ) == 0
        {
            return Err(format!(
                "failed to query Windows service: {}",
                last_os_error()
            ));
        }
        Ok(Some(status.dwCurrentState))
    }
}

/// Returns the registered command after refusing a foreign service that
/// only shares the name.
unsafe fn verify_owned_service(
    service: &ServiceHandle,
    service_name: &str,
) -> Result<String, String> {
    let mut needed = 0u32;
    let probe = QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
    if probe == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!(
            "failed to inspect Windows service: {}",
            last_os_error()
        ));
    }
    let mut buffer = vec![0u64; (needed as usize + 7) / 8];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if QueryServiceConfigW(service.0, config, needed, &mut needed) == 0 {
        return Err(format!(
            "failed to inspect Windows service: {}",
            last_os_error()
        ));
    }
    let command = wide_ptr_to_string((*config).lpBinaryPathName);
    if !is_windows_service_command_line(&command) {
        return Err(format!(
            "Windows service '{service_name}' is registered to foreign command '{command}'"
        ));
    }
    Ok(command)
}

unsafe fn grant_interactive_control(service: &ServiceHandle) -> Result<(), String> {
    let sddl = wide_null(INTERACTIVE_CONTROL_SDDL);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr(),
        SDDL_REVISION_1,
        &mut descriptor,
        null_mut(),
    ) == 0
    {
        return Err(format!("failed to build service DACL: {}", last_os_error()));
    }
    let result = SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor as _);
    if result == 0 {
        return Err(format!("failed to apply service DACL: {}", last_os_error()));
    }
    Ok(())
}

fn set_service_state(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    controls: u32,
    checkpoint: u32,
    wait_hint: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    unsafe { SetServiceStatus(handle, &status) };
}

fn redirect_service_stderr_to_log() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
    let Some(program_data) = std::env::var_os("ProgramData") else {
        return;
    };
    let directory = Path::new(&program_data).join("Egrio").join("logs");
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }
    let path = directory.join("egrio-service.log");
    if std::fs::metadata(&path)
        .map(|m| m.len() > 16 * 1024 * 1024)
        .unwrap_or(false)
    {
        let old = directory.join("egrio-service.old.log");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&path, old);
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    unsafe { SetStdHandle(STD_ERROR_HANDLE, file.into_raw_handle() as _) };
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_ptr_to_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while *value.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
}

fn last_os_error() -> String {
    os_error(unsafe { GetLastError() })
}
fn os_error(error: u32) -> String {
    std::io::Error::from_raw_os_error(error as i32).to_string()
}

struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

impl ServiceHandle {
    unsafe fn open_scm(access: u32) -> Result<Self, String> {
        let handle = OpenSCManagerW(null(), null(), access);
        if handle.is_null() {
            Err(format!(
                "failed to open Service Control Manager: {}",
                last_os_error()
            ))
        } else {
            Ok(Self(handle))
        }
    }

    unsafe fn open(
        scm: windows_sys::Win32::System::Services::SC_HANDLE,
        name: &[u16],
        access: u32,
    ) -> Result<Option<Self>, String> {
        let handle = OpenServiceW(scm, name.as_ptr(), access);
        if handle.is_null() {
            let error = GetLastError();
            if error == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(None)
            } else {
                Err(format!(
                    "failed to open Windows service: {}",
                    os_error(error)
                ))
            }
        } else {
            Ok(Some(Self(handle)))
        }
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}
