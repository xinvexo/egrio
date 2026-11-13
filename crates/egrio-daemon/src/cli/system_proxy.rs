use std::io::{self, Write};

use egrio_platform::{system_proxy_config_from_listen_addr, SystemProxySnapshot};

pub(crate) fn print_status() -> Result<(), String> {
    print_json(&system_proxy_status()?)
}

fn system_proxy_status() -> Result<SystemProxySnapshot, String> {
    #[cfg(target_os = "linux")]
    {
        egrio_platform_linux::system_proxy_status()
    }
    #[cfg(target_os = "macos")]
    {
        egrio_platform_macos::system_proxy_status()
    }
    #[cfg(windows)]
    {
        egrio_platform_windows::system_proxy_status()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok(egrio_platform::unsupported_system_proxy_status(
            std::env::consts::OS,
        ))
    }
}

pub(crate) fn print_config(listen_addr: Option<String>) -> Result<(), String> {
    let listen_addr =
        listen_addr.ok_or_else(|| "system-proxy-config requires listen address".to_string())?;
    print_json(&system_proxy_config_from_listen_addr(&listen_addr)?)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let document = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{document}");
    io::stdout().flush().map_err(|error| error.to_string())
}
