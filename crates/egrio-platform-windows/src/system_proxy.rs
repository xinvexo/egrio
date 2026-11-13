use std::time::{SystemTime, UNIX_EPOCH};

use egrio_platform::{
    SystemProxyApplyReport, SystemProxyBackendKind, SystemProxyConfig, SystemProxyRestoreReport,
    SystemProxySnapshot,
};
#[cfg(windows)]
use egrio_platform::{SystemProxySettingKind, SystemProxySettingSnapshot};
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
    INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS,
    INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
    INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_AUTO_DETECT,
    PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
};
#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
#[cfg(windows)]
use winreg::RegKey;

#[cfg(windows)]
pub(crate) const WINDOWS_INTERNET_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
#[cfg(windows)]
const SNAPSHOT_SETTINGS: &[(&str, SystemProxySettingKind)] = &[
    ("ProxyEnable", SystemProxySettingKind::Dword),
    ("ProxyServer", SystemProxySettingKind::String),
    ("ProxyOverride", SystemProxySettingKind::String),
    ("AutoConfigURL", SystemProxySettingKind::String),
    ("AutoDetect", SystemProxySettingKind::Dword),
];

#[cfg(windows)]
pub fn system_proxy_status() -> Result<SystemProxySnapshot, String> {
    snapshot_windows_settings()
}

#[cfg(not(windows))]
pub fn system_proxy_status() -> Result<SystemProxySnapshot, String> {
    Ok(unsupported_windows_system_proxy_snapshot(
        "Windows WinINET system proxy status is only available on Windows",
    ))
}

#[cfg(windows)]
pub(super) fn apply_system_proxy(
    config: &SystemProxyConfig,
) -> Result<SystemProxyApplyReport, String> {
    let snapshot = snapshot_windows_settings()?;
    if let Err(error) = apply_windows_settings(config) {
        return Err(rollback_apply_error(error, &snapshot));
    }

    Ok(SystemProxyApplyReport {
        applied: true,
        config: config.clone(),
        snapshot,
        warnings: vec![
            "Windows system proxy mode only covers applications that honor WinINET/system proxy settings"
                .into(),
        ],
    })
}

#[cfg(not(windows))]
pub(super) fn apply_system_proxy(
    config: &SystemProxyConfig,
) -> Result<SystemProxyApplyReport, String> {
    Ok(SystemProxyApplyReport {
        applied: false,
        config: config.clone(),
        snapshot: system_proxy_status()?,
        warnings: vec!["Windows WinINET system proxy apply is only available on Windows".into()],
    })
}

#[cfg(windows)]
pub(super) fn restore_system_proxy(
    snapshot: &SystemProxySnapshot,
) -> Result<SystemProxyRestoreReport, String> {
    if snapshot.backend != SystemProxyBackendKind::WindowsWinInet {
        return Err(format!(
            "cannot restore {:?} snapshot with Windows WinINET backend",
            snapshot.backend
        ));
    }

    restore_windows_settings(snapshot)?;

    Ok(SystemProxyRestoreReport {
        restored: true,
        snapshot: snapshot.clone(),
        warnings: Vec::new(),
    })
}

#[cfg(not(windows))]
pub(super) fn restore_system_proxy(
    snapshot: &SystemProxySnapshot,
) -> Result<SystemProxyRestoreReport, String> {
    Ok(SystemProxyRestoreReport {
        restored: false,
        snapshot: snapshot.clone(),
        warnings: vec!["Windows WinINET system proxy restore is only available on Windows".into()],
    })
}

/// Re-applies the Egrio WinINET proxy settings without taking a new backup
/// snapshot: the guard's re-assert after an external overwrite must not
/// capture the foreign state as the session's restore point.
#[cfg(windows)]
pub(super) fn reassert_system_proxy(config: &SystemProxyConfig) -> Result<(), String> {
    apply_windows_settings(config)
}

#[cfg(not(windows))]
pub(super) fn reassert_system_proxy(config: &SystemProxyConfig) -> Result<(), String> {
    let _ = config;
    Err("Windows WinINET system proxy re-assert is only available on Windows".into())
}

#[cfg(windows)]
fn apply_windows_settings(config: &SystemProxyConfig) -> Result<(), String> {
    set_wininet_proxy(&WinInetProxyDesired {
        use_proxy: true,
        use_auto_detect: false,
        proxy_server: Some(config.proxy_server.clone()),
        bypass: Some(bypass_value(config)),
        autoconfig_url: None,
    })
}

/// Restores the exact pre-apply WinINET state captured in `snapshot`, back
/// through the per-connection API so the Windows Settings UI reflects it. A
/// non-empty `AutoConfigURL` restores a PAC; `AutoDetect=1` restores WPAD.
#[cfg(windows)]
fn restore_windows_settings(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    let value = |name: &str| {
        snapshot
            .settings
            .iter()
            .find(|setting| setting.name == name)
            .and_then(|setting| setting.value.clone())
    };

    set_wininet_proxy(&WinInetProxyDesired {
        use_proxy: value("ProxyEnable").as_deref() == Some("1"),
        use_auto_detect: value("AutoDetect").as_deref() == Some("1"),
        proxy_server: value("ProxyServer"),
        bypass: value("ProxyOverride"),
        autoconfig_url: value("AutoConfigURL").filter(|url| !url.is_empty()),
    })
}

#[cfg(windows)]
fn rollback_apply_error(error: String, snapshot: &SystemProxySnapshot) -> String {
    match restore_windows_settings(snapshot) {
        Ok(()) => {
            format!("{error}; previous Windows system proxy settings were restored")
        }
        Err(rollback_error) => format!(
            "{error}; attempted to restore previous Windows system proxy settings but rollback failed: {rollback_error}"
        ),
    }
}

#[cfg(windows)]
fn snapshot_windows_settings() -> Result<SystemProxySnapshot, String> {
    let key = internet_settings_key(KEY_READ)?;
    let settings = SNAPSHOT_SETTINGS
        .iter()
        .map(|(name, kind)| snapshot_setting(&key, name, kind.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SystemProxySnapshot {
        os: "windows".into(),
        backend: SystemProxyBackendKind::WindowsWinInet,
        captured_at_unix: now_unix(),
        settings,
        warnings: Vec::new(),
    })
}

#[cfg(windows)]
fn snapshot_setting(
    key: &RegKey,
    name: &str,
    kind: SystemProxySettingKind,
) -> Result<SystemProxySettingSnapshot, String> {
    let value = match kind {
        SystemProxySettingKind::Dword => match key.get_value::<u32, _>(name) {
            Ok(value) => Some(value.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("failed to read {name}: {error}")),
        },
        SystemProxySettingKind::String => match key.get_value::<String, _>(name) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("failed to read {name}: {error}")),
        },
    };

    Ok(SystemProxySettingSnapshot {
        name: name.into(),
        kind,
        value,
    })
}

#[cfg(windows)]
fn internet_settings_key(access: u32) -> Result<RegKey, String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(WINDOWS_INTERNET_SETTINGS, access)
        .map_err(|error| format!("failed to open Windows Internet Settings registry key: {error}"))
}

#[cfg(windows)]
fn refresh_wininet_proxy_settings() {
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(windows)]
struct WinInetProxyDesired {
    use_proxy: bool,
    use_auto_detect: bool,
    proxy_server: Option<String>,
    bypass: Option<String>,
    autoconfig_url: Option<String>,
}

/// Applies a WinINET proxy configuration through the per-connection options API
/// (`INTERNET_OPTION_PER_CONNECTION_OPTION`) — the same path the Windows Settings
/// "manual proxy" page and WinHTTP read. Writing the `ProxyEnable`/`ProxyServer`
/// registry values directly does not reliably surface in that UI; this does.
/// Targets the LAN / default connection (`pszConnection = null`); Clash Verge's
/// `sysproxy` crate uses the same API. Documented at
/// <https://learn.microsoft.com/windows/win32/wininet/setting-and-retrieving-internet-options>.
#[cfg(windows)]
fn set_wininet_proxy(desired: &WinInetProxyDesired) -> Result<(), String> {
    let mut flags = PROXY_TYPE_DIRECT;
    if desired.use_proxy {
        flags |= PROXY_TYPE_PROXY;
    }
    if desired.autoconfig_url.is_some() {
        flags |= PROXY_TYPE_AUTO_PROXY_URL;
    }
    if desired.use_auto_detect {
        flags |= PROXY_TYPE_AUTO_DETECT;
    }

    // These UTF-16 buffers must outlive the option list handed to WinINET.
    let mut server_w = desired.proxy_server.as_deref().map(to_wide);
    let mut bypass_w = desired.bypass.as_deref().map(to_wide);
    let mut pac_w = desired.autoconfig_url.as_deref().map(to_wide);

    let mut options = vec![INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
    }];
    if let Some(server) = server_w.as_mut() {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: server.as_mut_ptr(),
            },
        });
    }
    if let Some(bypass) = bypass_w.as_mut() {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: bypass.as_mut_ptr(),
            },
        });
    }
    if let Some(pac) = pac_w.as_mut() {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: pac.as_mut_ptr(),
            },
        });
    }

    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: std::ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };

    let applied = unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &mut list as *mut INTERNET_PER_CONN_OPTION_LISTW as *const c_void,
            list.dwSize,
        )
    };
    if applied == 0 {
        return Err(format!(
            "InternetSetOption(PER_CONNECTION_OPTION) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    refresh_wininet_proxy_settings();
    Ok(())
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn bypass_value(config: &SystemProxyConfig) -> String {
    // WinINET's per-connection bypass list is ";"-separated host patterns. A raw
    // IPv6 entry like "::1" makes InternetSetOption reject the whole option list
    // with ERROR_INVALID_PARAMETER (87), so drop colon-bearing entries here;
    // "localhost" and "<local>" already cover loopback.
    config
        .bypass
        .iter()
        .filter(|entry| !entry.contains(':'))
        .map(|entry| entry.as_str())
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(not(windows))]
fn unsupported_windows_system_proxy_snapshot(warning: impl Into<String>) -> SystemProxySnapshot {
    SystemProxySnapshot {
        os: std::env::consts::OS.into(),
        backend: SystemProxyBackendKind::Unsupported,
        captured_at_unix: now_unix(),
        settings: Vec::new(),
        warnings: vec![warning.into()],
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    // The only test here exercises the non-Windows stub; on Windows the
    // module body is empty and the import would be unused.
    #[cfg(not(windows))]
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn non_windows_build_reports_unsupported_wininet_proxy() {
        let snapshot = system_proxy_status().expect("status");

        assert_eq!(snapshot.backend, SystemProxyBackendKind::Unsupported);
        assert!(snapshot
            .warnings
            .iter()
            .any(|warning| warning.contains("only available on Windows")));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use egrio_platform::SystemProxyConfig;

    #[test]
    fn bypass_value_drops_ipv6_entries_wininet_rejects() {
        // WinINET's InternetSetOption rejects a per-connection bypass list that
        // contains a raw IPv6 entry (`::1`) with ERROR_INVALID_PARAMETER, so the
        // Windows bypass string must drop colon-bearing entries.
        let config = SystemProxyConfig {
            listen_addr: "127.0.0.1:7890".into(),
            host: "127.0.0.1".into(),
            port: 7890,
            proxy_server: "127.0.0.1:7890".into(),
            bypass: vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "::1".into(),
                "<local>".into(),
            ],
        };

        assert_eq!(bypass_value(&config), "localhost;127.0.0.1;<local>");
    }
}
