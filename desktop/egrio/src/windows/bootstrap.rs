//! Makes the Windows App Runtime available to this unpackaged process. The
//! runtime is a framework package installed on the machine; the bootstrapper
//! DLL beside the executable adds it to the process's package graph
//! (`MddBootstrapInitialize2` in the Windows App SDK's `MddBootstrap.h`, "Use
//! the Windows App SDK runtime for apps packaged with external location or
//! unpackaged"). It is loaded at run time so a missing DLL is reported
//! instead of stopping the loader.

use windows_core::{HRESULT, PCWSTR};

use super::bindings::{
    GetProcAddress, LoadLibraryExW, MessageBoxW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, MB_ICONERROR, MB_OK,
};

const BOOTSTRAP_DLL: &str = "Microsoft.WindowsAppRuntime.Bootstrap.dll";

/// The release asked for: major version 2, whose minor the bootstrapper
/// ignores (`WINDOWSAPPSDK_RELEASE_MAJORMINOR` of 2.6.5).
const RELEASE_MAJOR_MINOR: u32 = 0x0002_0006;
/// The oldest runtime accepted, 2.6.5.0 as a `PACKAGE_VERSION`
/// (`WINDOWSAPPSDK_RUNTIME_VERSION_UINT64`); xtask's `windows_app_sdk.rs`
/// pins the same release.
const MIN_RUNTIME_VERSION: u64 = 0x0002_0006_0005_0000;
/// `MddBootstrapInitializeOptions_OnNoMatch_ShowUI`: without a matching
/// runtime the bootstrapper offers the user its download.
const ON_NO_MATCH_SHOW_UI: i32 = 0x0008;

type Initialize2 = unsafe extern "system" fn(u32, PCWSTR, u64, i32) -> HRESULT;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Initializes the runtime for the process, or explains why it cannot.
pub fn initialize() -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("locate the app executable: {error}"))?;
    let path = executable.with_file_name(BOOTSTRAP_DLL);
    let name = wide(&path.to_string_lossy());
    // SAFETY: a NUL-terminated full path. Its own imports resolve beside it
    // and in System32: with the application directory alone, what the
    // bootstrapper loads cannot reach System32, which later fails the CRT's
    // `rand_s` (an abort inside WinUI's backdrop setup).
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(name.as_ptr()),
            std::ptr::null_mut(),
            (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) as u32,
        )
    };
    if module.is_null() {
        return Err(format!(
            "{BOOTSTRAP_DLL} is missing beside the app: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the module stays loaded for the process's life.
    let address = unsafe {
        GetProcAddress(
            module,
            windows_core::PCSTR(c"MddBootstrapInitialize2".as_ptr().cast()),
        )
    }
    .ok_or_else(|| format!("{BOOTSTRAP_DLL} has no MddBootstrapInitialize2"))?;
    // SAFETY: the export's signature in MddBootstrap.h; `PACKAGE_VERSION` is
    // a union around one UINT64, passed as that integer.
    let initialize: Initialize2 = unsafe { std::mem::transmute(address) };
    let result = unsafe {
        initialize(
            RELEASE_MAJOR_MINOR,
            PCWSTR::null(),
            MIN_RUNTIME_VERSION,
            ON_NO_MATCH_SHOW_UI,
        )
    };
    result
        .ok()
        .map_err(|error| format!("Windows App Runtime 2.6.5 or newer is not available: {error}"))
}

/// Tells the user why the app cannot start, before any window exists.
pub fn fail(message: &str) -> ! {
    log::error!("desktop startup failed: {message}");
    let text = wide(&format!(
        "启动未完成，原配置数据已保留。请处理以下错误后重新启动。\n{message}"
    ));
    let caption = wide("Egrio");
    // SAFETY: NUL-terminated strings; no owner window.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            (MB_OK | MB_ICONERROR) as u32,
        );
    }
    std::process::exit(1);
}
