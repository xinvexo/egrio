//! `wintun.dll` and the adapter in it: loading the library from beside the
//! service, and telling an adapter that is absent from one that could not
//! be opened.

use super::*;

pub(super) fn load_wintun(config: &WindowsWintunConfig) -> Result<wintun::Wintun, String> {
    let path = resolve_wintun_dll_path(config);
    unsafe { wintun::load_from_path(&path).map_err(|error| error.to_string()) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WintunAdapterOpenErrorKind {
    NotFound,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WintunWrapperOpenErrorKind {
    NativeOpenFailed,
    Uncertain,
}

pub(super) const WINTUN_WRAPPER_NATIVE_OPEN_FAILED: &str = "WintunOpenAdapter failed";

pub(super) fn classify_wintun_wrapper_open_error(
    error: &wintun::Error,
) -> WintunWrapperOpenErrorKind {
    match error {
        wintun::Error::String(message) if message == WINTUN_WRAPPER_NATIVE_OPEN_FAILED => {
            WintunWrapperOpenErrorKind::NativeOpenFailed
        }
        _ => WintunWrapperOpenErrorKind::Uncertain,
    }
}

pub(super) fn classify_wintun_adapter_open_error(last_error: u32) -> WintunAdapterOpenErrorKind {
    if last_error == ERROR_NOT_FOUND {
        WintunAdapterOpenErrorKind::NotFound
    } else {
        WintunAdapterOpenErrorKind::Failed
    }
}

fn probe_wintun_adapter_presence(
    wintun: &wintun::Wintun,
    adapter_name: &str,
) -> Result<bool, String> {
    let adapter_name_wide = adapter_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let adapter = unsafe { (wintun.WintunOpenAdapter)(adapter_name_wide.as_ptr()) };
    if adapter.is_null() {
        let last_error = unsafe { GetLastError() };
        return match classify_wintun_adapter_open_error(last_error) {
            WintunAdapterOpenErrorKind::NotFound => Ok(false),
            WintunAdapterOpenErrorKind::Failed => Err(format!(
                "failed to probe Wintun adapter '{adapter_name}': GetLastError={last_error} ({})",
                std::io::Error::from_raw_os_error(last_error as i32)
            )),
        };
    }

    unsafe { (wintun.WintunCloseAdapter)(adapter) };
    Ok(true)
}

pub(super) fn open_wintun_adapter_if_present(
    wintun: &wintun::Wintun,
    adapter_name: &str,
) -> Result<Option<Arc<wintun::Adapter>>, String> {
    match wintun::Adapter::open(wintun, adapter_name) {
        Ok(adapter) => Ok(Some(adapter)),
        Err(error) => match classify_wintun_wrapper_open_error(&error) {
            WintunWrapperOpenErrorKind::NativeOpenFailed => {
                match probe_wintun_adapter_presence(wintun, adapter_name) {
                    Ok(false) => Ok(None),
                    Ok(true) => Err(format!(
                        "Wintun adapter '{adapter_name}' was present during native confirmation but the Rust wrapper could not open it: {error}"
                    )),
                    Err(probe_error) => Err(format!(
                        "failed to open Wintun adapter '{adapter_name}' through the Rust wrapper: {error}; native confirmation also failed: {probe_error}"
                    )),
                }
            }
            WintunWrapperOpenErrorKind::Uncertain => Err(format!(
                "failed to open Wintun adapter '{adapter_name}' through the Rust wrapper without its native-open failure sentinel; refusing to reopen it or treat it as absent: {error}"
            )),
        },
    }
}

/// Resolves which `wintun.dll` to load, in priority order: the explicitly
/// configured `dll_path` (e.g. `EGRIO_WINTUN_DLL`), else the copy shipped
/// beside the current executable, else the bare name for the Windows standard
/// DLL search order.
///
/// The bundled-beside-the-exe case is the production path: the privileged
/// service loads Wintun, and a service's working directory is `System32`, so
/// the ambient search is unreliable — an absolute exe-relative path pins the
/// load to the arch-matched `wintun.dll` we ship next to `egrio-service.exe`.
/// This follows the Wintun project's own guidance (keep `wintun.dll` in the
/// same directory as the executable). A bare `wintun.dll` still resolves
/// through the standard search order because it has no path component.
pub(super) fn resolve_wintun_dll_path(config: &WindowsWintunConfig) -> PathBuf {
    if let Some(path) = &config.dll_path {
        return PathBuf::from(path);
    }
    if let Some(bundled) = wintun_dll_beside_current_exe() {
        if bundled.is_file() {
            return bundled;
        }
    }
    PathBuf::from("wintun.dll")
}

/// The `wintun.dll` path next to the current executable, when the executable
/// path resolves.
pub(super) fn wintun_dll_beside_current_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("wintun.dll"))
}
