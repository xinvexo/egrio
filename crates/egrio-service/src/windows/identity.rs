use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null_mut, NonNull};

use egrio_platform_windows::WINDOWS_APP_EXECUTABLE;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken, QueryFullProcessImageNameW,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug)]
pub struct OwnedHandle(NonNull<c_void>);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn from_raw(handle: HANDLE) -> Result<Self, String> {
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        NonNull::new(handle).map(Self).ok_or_else(last_error)
    }

    pub fn raw(&self) -> HANDLE {
        self.0.as_ptr()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.raw()) };
    }
}

/// A pipe client whose program the service admits: its process, known from
/// the moment it connected.
#[derive(Debug)]
pub struct AdmittedProcess {
    pid: u32,
    process: OwnedHandle,
    executable_path: String,
}

#[derive(Debug)]
pub struct AuthenticatedClient {
    pub sid: Vec<u8>,
    pub pid: u32,
    pub process: OwnedHandle,
    pub executable_path: String,
}

/// The process at the client end of `pipe`, refused unless its program is
/// one the service admits. The system recorded the process when it opened
/// the pipe, so this asks nothing of the client and waits for nothing: a
/// program that is not Egrio's is turned away having cost a few calls.
pub fn admit_named_pipe_client(pipe: HANDLE) -> Result<AdmittedProcess, String> {
    let mut pid = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
        return Err(last_error());
    }
    let process = OwnedHandle::from_raw(unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    })?;
    let mut path = vec![0_u16; 32_768];
    let mut path_len = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.raw(), 0, path.as_mut_ptr(), &mut path_len) }
        == 0
    {
        return Err(last_error());
    }
    path.truncate(path_len as usize);
    let executable_path = String::from_utf16(&path).map_err(|error| error.to_string())?;
    authorize_named_pipe_client_executable(&executable_path)?;
    Ok(AdmittedProcess {
        pid,
        process,
        executable_path,
    })
}

/// Checks that the user `pipe`'s client acts as is the user of the process
/// admitted for it. `ImpersonateNamedPipeClient` is documented to fail with
/// ERROR_CANNOT_IMPERSONATE until the server has read data from the pipe, so
/// this runs once the client's first frame has been read.
pub fn authenticate_named_pipe_client(
    pipe: HANDLE,
    admitted: AdmittedProcess,
) -> Result<AuthenticatedClient, String> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(last_error());
    }
    let pipe_sid = (|| {
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
            return Err(last_error());
        }
        let token = OwnedHandle::from_raw(token)?;
        token_sid(token.raw())
    })();
    let reverted = unsafe { RevertToSelf() };
    if reverted == 0 {
        return Err(last_error());
    }
    let pipe_sid = pipe_sid?;

    let mut process_token = null_mut();
    if unsafe { OpenProcessToken(admitted.process.raw(), TOKEN_QUERY, &mut process_token) } == 0 {
        return Err(last_error());
    }
    let process_token = OwnedHandle::from_raw(process_token)?;
    if token_sid(process_token.raw())? != pipe_sid {
        return Err("named-pipe client SID does not match client process SID".into());
    }
    Ok(AuthenticatedClient {
        sid: pipe_sid,
        pid: admitted.pid,
        process: admitted.process,
        executable_path: admitted.executable_path,
    })
}

fn authorize_named_pipe_client_executable(client_executable: &str) -> Result<(), String> {
    let service_executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve service executable: {error}"))?;
    let service_executable = std::fs::canonicalize(&service_executable).map_err(|error| {
        format!(
            "failed to resolve service executable '{}': {error}",
            service_executable.display()
        )
    })?;
    let client_executable = std::fs::canonicalize(client_executable).map_err(|error| {
        format!("failed to resolve named-pipe client executable '{client_executable}': {error}")
    })?;

    if admitted(&service_executable, &client_executable) {
        return Ok(());
    }

    Err(format!(
        "named-pipe client executable '{}' is not the Egrio app beside the service",
        client_executable.display()
    ))
}

/// The service admits the desktop app installed beside it, or its own
/// executable: Egrio may be installed in a folder that holds other
/// programs, and only its own files are protected wherever it is.
fn admitted(service_executable: &Path, client_executable: &Path) -> bool {
    let client = client_executable.as_os_str().to_string_lossy();
    let same = |path: &Path| {
        path.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&client)
    };
    same(service_executable)
        || service_executable
            .parent()
            .is_some_and(|directory| same(&directory.join(WINDOWS_APP_EXECUTABLE)))
}

fn token_sid(token: HANDLE) -> Result<Vec<u8>, String> {
    let mut len = 0_u32;
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(last_error());
    }
    let mut buffer = vec![0_u8; len as usize];
    if unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(last_error());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid_len = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if sid_len == 0 {
        return Err(last_error());
    }
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), sid_len) }.to_vec())
}

fn last_error() -> String {
    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_app_beside_the_service_and_the_service_are_admitted() {
        let service = Path::new(r"D:\Tools\egrio-service.exe");
        assert!(admitted(service, Path::new(r"d:\tools\EGRIO.exe")));
        assert!(admitted(service, service));
        assert!(!admitted(service, Path::new(r"D:\Tools\other.exe")));
        assert!(!admitted(service, Path::new(r"D:\Other\egrio.exe")));
        assert!(!admitted(
            service,
            Path::new(r"C:\Users\Public\unauthorized.exe")
        ));
    }
}
