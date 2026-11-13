#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use egrio_platform::{SystemProxyBackendKind, SystemProxySnapshot};
use egrio_platform_macos::snapshots_have_same_effective_settings;
#[cfg(target_os = "macos")]
use egrio_platform_macos::{system_proxy_status, MacosSystemProxyAdapter};
use egrio_runtime::CapabilityCheckpoint;
#[cfg(target_os = "macos")]
use egrio_runtime::{SystemProxyControl, SystemProxySettings};
use serde::Serialize;

const MACOS_SYSTEM_PROXY_CHECKPOINT_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Serialize)]
struct ValidationReport {
    listen_addr: String,
    services: usize,
    applied_verified: bool,
    restored_verified: bool,
    checkpoint_path: String,
    restored_snapshot_path: String,
}

fn main() {
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("macOS system proxy validation can only run on macOS");
        std::process::exit(69);
    }

    #[cfg(target_os = "macos")]
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;

    match args.as_slice() {
        [command, checkpoint_path] if command == "restore" => runtime.block_on(async {
            let checkpoint = read_checkpoint(Path::new(checkpoint_path))?;
            MacosSystemProxyAdapter::new()
                .restore(&checkpoint)
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        }),
        [command, listen_addr, checkpoint_path] if command == "run" => runtime.block_on(
            validate_system_proxy(listen_addr, Path::new(checkpoint_path)),
        ),
        _ => Err(
            "usage: system_proxy_validation run <listen-addr> <checkpoint-path> | restore <checkpoint-path>"
                .into(),
        ),
    }
}

#[cfg(target_os = "macos")]
async fn validate_system_proxy(listen_addr: &str, checkpoint_path: &Path) -> Result<(), String> {
    let endpoint = listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid listen address: {error}"))?;
    if !endpoint.ip().is_loopback() {
        return Err("validation listener must use a loopback address".into());
    }
    let settings = SystemProxySettings {
        http_proxy: Some(endpoint),
        https_proxy: Some(endpoint),
        bypass: vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
            "<local>".into(),
        ],
    };
    let adapter = MacosSystemProxyAdapter::new();
    let checkpoint = adapter
        .prepare(&settings)
        .await
        .map_err(|error| error.to_string())?;
    let baseline = snapshot_from_checkpoint(&checkpoint)?;
    refuse_authenticated_proxy(&baseline)?;
    write_checkpoint(checkpoint_path, &checkpoint)?;

    let result = async {
        let applied = adapter
            .apply(&settings)
            .await
            .map_err(|error| error.to_string())?;
        if !applied.changed || !applied.verified {
            return Err("adapter did not report a verified system proxy apply".into());
        }
        let applied_snapshot = system_proxy_status()?;
        let services = verify_applied_snapshot(&applied_snapshot, endpoint, &settings.bypass)?;
        let restored = adapter
            .restore(&checkpoint)
            .await
            .map_err(|error| error.to_string())?;
        if !restored.verified {
            return Err("adapter did not report a verified system proxy restore".into());
        }
        let restored_snapshot = system_proxy_status()?;
        verify_restored_snapshot(&baseline, &restored_snapshot)?;
        let restored_snapshot_path = checkpoint_path.with_file_name("restored-snapshot.json");
        write_snapshot(&restored_snapshot_path, &restored_snapshot)?;
        mark_restored(checkpoint_path)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&ValidationReport {
                listen_addr: listen_addr.into(),
                services,
                applied_verified: true,
                restored_verified: true,
                checkpoint_path: checkpoint_path.display().to_string(),
                restored_snapshot_path: restored_snapshot_path.display().to_string(),
            })
            .map_err(|error| error.to_string())?
        );
        Ok(())
    }
    .await;

    if let Err(error) = result {
        return match adapter.restore(&checkpoint).await {
            Ok(report)
                if report.verified
                    && system_proxy_status()
                        .and_then(|restored| {
                            verify_restored_snapshot(&baseline, &restored)?;
                            write_snapshot(
                                &checkpoint_path.with_file_name("restored-snapshot.json"),
                                &restored,
                            )
                        })
                        .is_ok() =>
            {
                mark_restored(checkpoint_path)?;
                Err(error)
            }
            Ok(_) => Err(format!("{error}; emergency restore was not verified")),
            Err(restore_error) => Err(format!(
                "{error}; emergency restore failed: {restore_error}; recover with the saved checkpoint"
            )),
        };
    }
    Ok(())
}

fn snapshot_from_checkpoint(
    checkpoint: &CapabilityCheckpoint,
) -> Result<SystemProxySnapshot, String> {
    let payload = match checkpoint.schema_version {
        1 => checkpoint.payload.clone(),
        MACOS_SYSTEM_PROXY_CHECKPOINT_SCHEMA_VERSION => checkpoint
            .payload
            .get("baseline")
            .cloned()
            .ok_or_else(|| "macOS system proxy checkpoint has no baseline".to_string())?,
        version => {
            return Err(format!(
                "unsupported macOS system proxy checkpoint schema {version}"
            ));
        }
    };
    serde_json::from_value(payload).map_err(|error| error.to_string())
}

fn refuse_authenticated_proxy(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    if snapshot.settings.iter().any(|setting| {
        setting.value.as_deref().is_some_and(|value| {
            value.lines().any(|line| {
                line.split_once(':').is_some_and(|(key, value)| {
                    key.trim()
                        .eq_ignore_ascii_case("Authenticated Proxy Enabled")
                        && matches!(
                            value.trim().to_ascii_lowercase().as_str(),
                            "yes" | "on" | "1" | "true"
                        )
                })
            })
        })
    }) {
        return Err(
            "authenticated proxy settings are present; validation refuses to risk credential loss"
                .into(),
        );
    }
    Ok(())
}

fn verify_applied_snapshot(
    snapshot: &SystemProxySnapshot,
    endpoint: SocketAddr,
    bypass: &[String],
) -> Result<usize, String> {
    if snapshot.backend != SystemProxyBackendKind::MacosNetworkSetup {
        return Err("applied snapshot did not use the macOS networksetup backend".into());
    }
    let services = snapshot
        .settings
        .iter()
        .find(|setting| setting.name == "macos:services")
        .and_then(|setting| setting.value.as_deref())
        .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or_default();
    if services == 0 {
        return Err("applied snapshot contained no enabled network services".into());
    }
    let expected_server = format!("Server: {}", endpoint.ip());
    let expected_port = format!("Port: {}", endpoint.port());
    let mut proxy_settings = 0;
    for setting in &snapshot.settings {
        if setting.name.ends_with(":web")
            || setting.name.ends_with(":secure-web")
            || setting.name.ends_with(":socks")
        {
            let value = setting.value.as_deref().unwrap_or_default();
            if !contains_line(value, "Enabled: Yes")
                || !contains_line(value, &expected_server)
                || !contains_line(value, &expected_port)
            {
                return Err(format!(
                    "applied proxy setting was not verified: {}",
                    setting.name
                ));
            }
            proxy_settings += 1;
        }
        if setting.name.ends_with(":bypass") {
            let value = setting.value.as_deref().unwrap_or_default();
            for domain in bypass {
                if !value.lines().any(|line| line.trim() == domain) {
                    return Err(format!(
                        "applied bypass setting {} is missing {domain}",
                        setting.name
                    ));
                }
            }
        }
    }
    if proxy_settings != services * 3 {
        return Err(format!(
            "expected {} proxy settings, observed {proxy_settings}",
            services * 3
        ));
    }
    Ok(services)
}

fn verify_restored_snapshot(
    baseline: &SystemProxySnapshot,
    restored: &SystemProxySnapshot,
) -> Result<(), String> {
    if !snapshots_have_same_effective_settings(baseline, restored) {
        return Err(
            "restored system proxy effective settings differ from the pre-run baseline".into(),
        );
    }
    Ok(())
}

fn contains_line(value: &str, expected: &str) -> bool {
    value
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case(expected))
}

fn write_checkpoint(path: &Path, checkpoint: &CapabilityCheckpoint) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, checkpoint).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn write_snapshot(path: &Path, snapshot: &SystemProxySnapshot) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, snapshot).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn read_checkpoint(path: &Path) -> Result<CapabilityCheckpoint, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn mark_restored(checkpoint_path: &Path) -> Result<(), String> {
    let marker = checkpoint_path.with_extension("restored");
    let mut file = File::create(marker).map_err(|error| error.to_string())?;
    file.write_all(b"verified\n")
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use egrio_platform::{SystemProxySettingKind, SystemProxySettingSnapshot, SystemProxySnapshot};

    use super::*;

    fn snapshot(values: &[(&str, &str)]) -> SystemProxySnapshot {
        SystemProxySnapshot {
            os: "macos".into(),
            backend: SystemProxyBackendKind::MacosNetworkSetup,
            captured_at_unix: 1,
            settings: values
                .iter()
                .map(|(name, value)| SystemProxySettingSnapshot {
                    name: (*name).into(),
                    kind: SystemProxySettingKind::String,
                    value: Some((*value).into()),
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn applied_snapshot_requires_three_proxy_kinds_per_service() {
        let value = "Enabled: Yes\nServer: 127.0.0.1\nPort: 51820\n";
        let snapshot = snapshot(&[
            ("macos:services", "Wi-Fi\n"),
            ("macos:Wi-Fi:web", value),
            ("macos:Wi-Fi:secure-web", value),
            ("macos:Wi-Fi:socks", value),
            ("macos:Wi-Fi:bypass", "localhost\n127.0.0.1\n::1\n<local>\n"),
        ]);

        assert_eq!(
            verify_applied_snapshot(
                &snapshot,
                "127.0.0.1:51820".parse().unwrap(),
                &[
                    "localhost".into(),
                    "127.0.0.1".into(),
                    "::1".into(),
                    "<local>".into()
                ],
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn restored_snapshot_compares_effective_settings() {
        let disabled_baseline = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";
        let disabled_with_metadata =
            "Enabled: No\nServer: 127.0.0.1\nPort: 51820\nAuthenticated Proxy Enabled: 0\n";
        let baseline = snapshot(&[
            ("macos:services", "Wi-Fi\n"),
            ("macos:Wi-Fi:web", disabled_baseline),
            ("macos:Wi-Fi:secure-web", disabled_baseline),
            ("macos:Wi-Fi:socks", disabled_baseline),
            ("macos:Wi-Fi:bypass", "localhost\n"),
        ]);
        let mut restored = baseline.clone();
        restored.captured_at_unix = 2;
        assert!(verify_restored_snapshot(&baseline, &restored).is_ok());
        for setting in restored.settings.iter_mut().filter(|setting| {
            setting.name.ends_with(":web")
                || setting.name.ends_with(":secure-web")
                || setting.name.ends_with(":socks")
        }) {
            setting.value = Some(disabled_with_metadata.into());
        }
        assert!(verify_restored_snapshot(&baseline, &restored).is_ok());
        restored.settings[0].value = Some("Ethernet\n".into());
        assert!(verify_restored_snapshot(&baseline, &restored).is_err());
    }

    #[test]
    fn schema_v2_checkpoint_exposes_its_baseline_snapshot() {
        let baseline = snapshot(&[("macos:services", "Wi-Fi\n")]);
        let checkpoint = CapabilityCheckpoint {
            lease_key: egrio_runtime::PlatformLeaseKey::system_proxy(),
            schema_version: MACOS_SYSTEM_PROXY_CHECKPOINT_SCHEMA_VERSION,
            payload: serde_json::json!({
                "baseline": baseline.clone(),
                "expected": {
                    "listen_addr": "127.0.0.1:7890",
                    "host": "127.0.0.1",
                    "port": 7890,
                    "proxy_server": "127.0.0.1:7890",
                    "bypass": []
                }
            }),
            rollback_payload: None,
        };

        assert_eq!(snapshot_from_checkpoint(&checkpoint).unwrap(), baseline);
    }

    #[test]
    fn authenticated_proxy_detection_accepts_numeric_networksetup_output() {
        let snapshot = snapshot(&[(
            "macos:Wi-Fi:web",
            "Enabled: Yes\nServer: proxy.example\nPort: 8080\nAuthenticated Proxy Enabled: 1\n",
        )]);

        assert!(refuse_authenticated_proxy(&snapshot).is_err());
    }
}
