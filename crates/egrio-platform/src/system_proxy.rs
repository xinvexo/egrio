use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const DEFAULT_BYPASS: &[&str] = &["localhost", "127.0.0.1", "::1", "<local>"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SystemProxyBackendKind {
    WindowsWinInet,
    MacosNetworkSetup,
    LinuxDesktopProxy,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SystemProxySettingKind {
    Dword,
    String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProxySettingSnapshot {
    pub name: String,
    pub kind: SystemProxySettingKind,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProxyConfig {
    pub listen_addr: String,
    pub host: String,
    pub port: u16,
    pub proxy_server: String,
    pub bypass: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProxySnapshot {
    pub os: String,
    pub backend: SystemProxyBackendKind,
    pub captured_at_unix: i64,
    pub settings: Vec<SystemProxySettingSnapshot>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProxyApplyReport {
    pub applied: bool,
    pub config: SystemProxyConfig,
    pub snapshot: SystemProxySnapshot,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProxyRestoreReport {
    pub restored: bool,
    pub snapshot: SystemProxySnapshot,
    pub warnings: Vec<String>,
}

pub fn system_proxy_config_from_listen_addr(
    listen_addr: &str,
) -> Result<SystemProxyConfig, String> {
    let addr = listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("native core listen address must be host:port: {error}"))?;
    let addr = egrio_core::inbound::local_listener_address(addr);
    let host = addr.ip().to_string();
    let port = addr.port();
    // A single `host:port` (no `http=`/`https=`/`socks=` scheme prefixes) is
    // what the Windows Settings "manual proxy" address/port fields render.
    // WinINET applies it to every protocol, and the native core's mixed
    // inbound already serves HTTP CONNECT and SOCKS on the one port, so the
    // per-scheme form only broke the Settings UI display without buying
    // anything.
    let proxy_server = proxy_endpoint(&host, port);

    Ok(SystemProxyConfig {
        listen_addr: addr.to_string(),
        host,
        port,
        proxy_server,
        bypass: DEFAULT_BYPASS.iter().map(|value| (*value).into()).collect(),
    })
}

pub fn unsupported_system_proxy_status(os: impl Into<String>) -> SystemProxySnapshot {
    SystemProxySnapshot {
        os: os.into(),
        backend: SystemProxyBackendKind::Unsupported,
        captured_at_unix: now_unix(),
        settings: Vec::new(),
        warnings: vec!["system proxy status is not implemented on this OS yet".into()],
    }
}

pub fn unsupported_system_proxy_apply(
    os: impl Into<String>,
    config: &SystemProxyConfig,
) -> SystemProxyApplyReport {
    SystemProxyApplyReport {
        applied: false,
        config: config.clone(),
        snapshot: unsupported_system_proxy_status(os),
        warnings: vec!["system proxy apply is not implemented on this OS yet".into()],
    }
}

pub fn unsupported_system_proxy_restore(
    snapshot: &SystemProxySnapshot,
) -> SystemProxyRestoreReport {
    SystemProxyRestoreReport {
        restored: false,
        snapshot: snapshot.clone(),
        warnings: vec!["system proxy restore is not implemented on this OS yet".into()],
    }
}

fn proxy_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
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
    use super::*;

    #[test]
    fn system_proxy_config_targets_native_core_listener() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config");

        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 51820);
        assert_eq!(config.proxy_server, "127.0.0.1:51820");
        assert!(config.bypass.contains(&"<local>".into()));
    }

    #[test]
    fn system_proxy_config_formats_ipv6_endpoint_for_proxy_string() {
        let config = system_proxy_config_from_listen_addr("[::1]:51820").expect("config");

        assert_eq!(config.proxy_server, "[::1]:51820");
    }

    #[test]
    fn wildcard_listener_uses_loopback_for_system_proxy_clients() {
        for (bound, expected) in [
            ("0.0.0.0:7890", "127.0.0.1:7890"),
            ("[::]:7891", "[::1]:7891"),
        ] {
            let config = system_proxy_config_from_listen_addr(bound).unwrap();
            assert_eq!(config.listen_addr, expected);
            assert_eq!(config.proxy_server, expected);
        }
    }

    #[test]
    fn invalid_listen_addr_is_rejected() {
        let error = system_proxy_config_from_listen_addr("not-a-listener")
            .expect_err("invalid listener should fail");

        assert!(error.contains("host:port"));
    }

    #[test]
    fn unsupported_snapshot_keeps_warning() {
        let snapshot = unsupported_system_proxy_status("unknown");

        assert_eq!(snapshot.backend, SystemProxyBackendKind::Unsupported);
        assert_eq!(
            snapshot.warnings,
            vec!["system proxy status is not implemented on this OS yet"]
        );
    }
}
