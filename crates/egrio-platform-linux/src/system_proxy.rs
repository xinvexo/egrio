#![cfg_attr(test, allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use egrio_platform::{
    SystemProxyApplyReport, SystemProxyBackendKind, SystemProxyConfig, SystemProxyRestoreReport,
    SystemProxySettingKind, SystemProxySettingSnapshot, SystemProxySnapshot,
};

const GNOME_PROXY_SCHEMA: &str = "org.gnome.system.proxy";
pub(crate) const GNOME_PROXY_SETTINGS: &[(&str, &str)] = &[
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "autoconfig-url"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy", "use-same-proxy"),
    ("org.gnome.system.proxy.http", "enabled"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "use-authentication"),
    ("org.gnome.system.proxy.http", "authentication-user"),
    ("org.gnome.system.proxy.http", "authentication-password"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.ftp", "host"),
    ("org.gnome.system.proxy.ftp", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

pub fn system_proxy_status() -> Result<SystemProxySnapshot, String> {
    snapshot_linux_gsettings()
}

pub fn apply_system_proxy(config: &SystemProxyConfig) -> Result<SystemProxyApplyReport, String> {
    let snapshot = snapshot_linux_gsettings()?;
    if !snapshot_ready(&snapshot) {
        let mut warnings = snapshot.warnings.clone();
        warnings
            .push("Linux system proxy apply skipped because GNOME GSettings is unavailable".into());
        return Ok(SystemProxyApplyReport {
            applied: false,
            config: config.clone(),
            snapshot,
            warnings,
        });
    }

    apply_system_proxy_from_baseline(config, &snapshot)
}

pub(crate) fn apply_system_proxy_from_baseline(
    config: &SystemProxyConfig,
    baseline: &SystemProxySnapshot,
) -> Result<SystemProxyApplyReport, String> {
    validate_system_proxy_snapshot(baseline)?;
    let live = system_proxy_status()?;
    validate_system_proxy_snapshot(&live)?;
    if !snapshots_have_same_complete_settings(&live, baseline) {
        return Err(
            "Linux system proxy settings changed after the Runtime checkpoint was prepared".into(),
        );
    }

    if let Err(error) = apply_linux_gsettings(config) {
        return Err(rollback_apply_error(error, baseline));
    }

    Ok(SystemProxyApplyReport {
        applied: true,
        config: config.clone(),
        snapshot: baseline.clone(),
        warnings: vec![
            "Linux system proxy mode uses GNOME GSettings and only covers applications that honor org.gnome.system.proxy"
                .into(),
        ],
    })
}

pub fn restore_system_proxy(
    snapshot: &SystemProxySnapshot,
) -> Result<SystemProxyRestoreReport, String> {
    if snapshot.backend != SystemProxyBackendKind::LinuxDesktopProxy {
        return Err(format!(
            "cannot restore {:?} snapshot with Linux GNOME GSettings backend",
            snapshot.backend
        ));
    }
    if snapshot.settings.is_empty() {
        return Ok(SystemProxyRestoreReport {
            restored: false,
            snapshot: snapshot.clone(),
            warnings: vec![
                "Linux system proxy restore skipped because the snapshot has no GNOME GSettings values"
                    .into(),
            ],
        });
    }

    restore_linux_gsettings(snapshot)?;

    Ok(SystemProxyRestoreReport {
        restored: true,
        snapshot: snapshot.clone(),
        warnings: Vec::new(),
    })
}

fn snapshot_linux_gsettings() -> Result<SystemProxySnapshot, String> {
    if !gsettings_available() {
        return Ok(unavailable_snapshot(
            "gsettings command is not available; Linux desktop proxy settings cannot be inspected",
        ));
    }
    if !gnome_proxy_schema_available()? {
        return Ok(unavailable_snapshot(
            "GNOME system proxy schema org.gnome.system.proxy is not available",
        ));
    }

    let settings = GNOME_PROXY_SETTINGS
        .iter()
        .map(|(schema, key)| {
            Ok(SystemProxySettingSnapshot {
                name: gsettings_snapshot_name(schema, key),
                kind: SystemProxySettingKind::String,
                value: Some(run_gsettings(&[
                    "get".into(),
                    (*schema).into(),
                    (*key).into(),
                ])?),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(SystemProxySnapshot {
        os: "linux".into(),
        backend: SystemProxyBackendKind::LinuxDesktopProxy,
        captured_at_unix: now_unix(),
        settings,
        warnings: Vec::new(),
    })
}

fn unavailable_snapshot(warning: impl Into<String>) -> SystemProxySnapshot {
    SystemProxySnapshot {
        os: "linux".into(),
        backend: SystemProxyBackendKind::LinuxDesktopProxy,
        captured_at_unix: now_unix(),
        settings: Vec::new(),
        warnings: vec![warning.into()],
    }
}

fn snapshot_ready(snapshot: &SystemProxySnapshot) -> bool {
    snapshot.backend == SystemProxyBackendKind::LinuxDesktopProxy
        && snapshot.warnings.is_empty()
        && !snapshot.settings.is_empty()
}

pub(crate) fn validate_system_proxy_snapshot(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    if snapshot.os != "linux" || snapshot.backend != SystemProxyBackendKind::LinuxDesktopProxy {
        return Err("system proxy snapshot does not use the Linux GNOME GSettings contract".into());
    }
    if !snapshot.warnings.is_empty() {
        return Err(format!(
            "Linux system proxy snapshot is unavailable: {}",
            snapshot.warnings.join("; ")
        ));
    }
    let expected = GNOME_PROXY_SETTINGS
        .iter()
        .map(|(schema, key)| gsettings_snapshot_name(schema, key))
        .collect::<Vec<_>>();
    if snapshot.settings.len() != expected.len() {
        return Err(format!(
            "Linux system proxy snapshot has {} settings; expected {}",
            snapshot.settings.len(),
            expected.len()
        ));
    }
    let mut names = BTreeSet::new();
    for setting in &snapshot.settings {
        if setting.kind != SystemProxySettingKind::String || setting.value.is_none() {
            return Err(format!(
                "Linux system proxy snapshot setting '{}' is not a persisted string",
                setting.name
            ));
        }
        if !names.insert(setting.name.clone()) {
            return Err(format!(
                "Linux system proxy snapshot contains duplicate setting '{}'",
                setting.name
            ));
        }
    }
    for name in expected {
        if !names.contains(&name) {
            return Err(format!(
                "Linux system proxy snapshot is missing setting '{name}'"
            ));
        }
    }
    Ok(())
}

pub(crate) fn expected_setting_values(config: &SystemProxyConfig) -> BTreeMap<String, String> {
    linux_apply_gsettings_commands(config)
        .into_iter()
        .filter_map(|command| {
            (command.len() == 4).then(|| {
                (
                    gsettings_snapshot_name(&command[1], &command[2]),
                    command[3].clone(),
                )
            })
        })
        .collect()
}

pub(crate) fn snapshot_matches_config(
    snapshot: &SystemProxySnapshot,
    config: &SystemProxyConfig,
) -> bool {
    if validate_system_proxy_snapshot(snapshot).is_err() {
        return false;
    }
    let expected = expected_setting_values(config);
    expected
        .iter()
        .all(|(name, value)| setting_value(snapshot, name).is_some_and(|actual| actual == value))
}

pub(crate) fn snapshot_has_active_proxy(snapshot: &SystemProxySnapshot) -> bool {
    validate_system_proxy_snapshot(snapshot).is_ok()
        && setting_value(snapshot, "org.gnome.system.proxy:mode")
            .is_some_and(|value| value != "'none'")
}

pub(crate) fn snapshots_have_same_complete_settings(
    left: &SystemProxySnapshot,
    right: &SystemProxySnapshot,
) -> bool {
    if validate_system_proxy_snapshot(left).is_err()
        || validate_system_proxy_snapshot(right).is_err()
    {
        return false;
    }
    let values = |snapshot: &SystemProxySnapshot| {
        snapshot
            .settings
            .iter()
            .map(|setting| {
                (
                    setting.name.clone(),
                    (setting.kind.clone(), setting.value.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    values(left) == values(right)
}

pub(crate) fn snapshot_has_owned_residue(
    snapshot: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
) -> bool {
    if validate_system_proxy_snapshot(snapshot).is_err()
        || validate_system_proxy_snapshot(baseline).is_err()
    {
        return true;
    }
    let expected = expected_setting_values(expected);
    GNOME_PROXY_SETTINGS.iter().any(|(schema, key)| {
        let name = gsettings_snapshot_name(schema, key);
        let live = setting_value(snapshot, &name);
        let before = setting_value(baseline, &name);
        let wanted = expected.get(&name).map(String::as_str);
        live != before && live == wanted
    })
}

pub(crate) fn restore_owned_system_proxy(
    live: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
    _allow_partial: bool,
) -> Result<bool, String> {
    let (target, changed) = selectively_restored_snapshot(live, baseline, expected)?;
    if changed {
        restore_linux_gsettings(&target)?;
    }
    Ok(changed)
}

pub(crate) fn selectively_restored_snapshot(
    live: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
) -> Result<(SystemProxySnapshot, bool), String> {
    validate_system_proxy_snapshot(live)?;
    validate_system_proxy_snapshot(baseline)?;
    let expected_values = expected_setting_values(expected);
    let mut target = baseline.clone();
    for setting in &mut target.settings {
        let live_setting = live
            .settings
            .iter()
            .find(|candidate| candidate.name == setting.name)
            .ok_or_else(|| format!("Linux system proxy snapshot is missing {}", setting.name))?;
        let expected_value = expected_values
            .get(&setting.name)
            .ok_or_else(|| format!("Linux system proxy setting {} is not owned", setting.name))?;
        if live_setting.value.as_deref() != Some(expected_value.as_str()) {
            if live_setting.kind != SystemProxySettingKind::String {
                return Err(format!(
                    "Linux system proxy foreign setting {} has an unsupported kind",
                    setting.name
                ));
            }
            setting.value = live_setting.value.clone();
        }
    }
    let changed = !snapshots_have_same_complete_settings(&target, live);
    Ok((target, changed))
}

fn apply_linux_gsettings(config: &SystemProxyConfig) -> Result<(), String> {
    for command in linux_apply_gsettings_commands(config) {
        run_gsettings(&command)?;
    }
    Ok(())
}

fn restore_linux_gsettings(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    for command in linux_restore_gsettings_commands(snapshot)? {
        run_gsettings(&command)?;
    }
    Ok(())
}

fn rollback_apply_error(error: String, snapshot: &SystemProxySnapshot) -> String {
    match restore_linux_gsettings(snapshot) {
        Ok(()) => format!("{error}; previous Linux GNOME proxy settings were restored"),
        Err(rollback_error) => format!(
            "{error}; attempted to restore previous Linux GNOME proxy settings but rollback failed: {rollback_error}"
        ),
    }
}

fn linux_apply_gsettings_commands(config: &SystemProxyConfig) -> Vec<Vec<String>> {
    let port = config.port.to_string();
    vec![
        gsettings_set("org.gnome.system.proxy", "mode", "'manual'"),
        gsettings_set("org.gnome.system.proxy", "autoconfig-url", "''"),
        gsettings_set(
            "org.gnome.system.proxy",
            "ignore-hosts",
            &gvariant_string_array(&config.bypass),
        ),
        gsettings_set("org.gnome.system.proxy", "use-same-proxy", "false"),
        gsettings_set("org.gnome.system.proxy.http", "enabled", "true"),
        gsettings_set(
            "org.gnome.system.proxy.http",
            "host",
            &gvariant_string(&config.host),
        ),
        gsettings_set("org.gnome.system.proxy.http", "port", &port),
        gsettings_set("org.gnome.system.proxy.http", "use-authentication", "false"),
        gsettings_set("org.gnome.system.proxy.http", "authentication-user", "''"),
        gsettings_set(
            "org.gnome.system.proxy.http",
            "authentication-password",
            "''",
        ),
        gsettings_set(
            "org.gnome.system.proxy.https",
            "host",
            &gvariant_string(&config.host),
        ),
        gsettings_set("org.gnome.system.proxy.https", "port", &port),
        gsettings_set(
            "org.gnome.system.proxy.ftp",
            "host",
            &gvariant_string(&config.host),
        ),
        gsettings_set("org.gnome.system.proxy.ftp", "port", &port),
        gsettings_set(
            "org.gnome.system.proxy.socks",
            "host",
            &gvariant_string(&config.host),
        ),
        gsettings_set("org.gnome.system.proxy.socks", "port", &port),
    ]
}

fn linux_restore_gsettings_commands(
    snapshot: &SystemProxySnapshot,
) -> Result<Vec<Vec<String>>, String> {
    snapshot
        .settings
        .iter()
        .map(|setting| {
            let (schema, key) = parse_gsettings_snapshot_name(&setting.name)?;
            let value = setting
                .value
                .as_deref()
                .ok_or_else(|| format!("Linux GSettings snapshot {} has no value", setting.name))?;
            Ok(gsettings_set(schema, key, value))
        })
        .collect()
}

fn gsettings_set(schema: &str, key: &str, value: &str) -> Vec<String> {
    vec!["set".into(), schema.into(), key.into(), value.into()]
}

fn gsettings_snapshot_name(schema: &str, key: &str) -> String {
    format!("{schema}:{key}")
}

fn parse_gsettings_snapshot_name(name: &str) -> Result<(&str, &str), String> {
    name.split_once(':')
        .filter(|(schema, key)| !schema.is_empty() && !key.is_empty())
        .ok_or_else(|| format!("invalid Linux GSettings snapshot key '{name}'"))
}

pub(crate) fn setting_value<'a>(snapshot: &'a SystemProxySnapshot, name: &str) -> Option<&'a str> {
    snapshot
        .settings
        .iter()
        .find(|setting| setting.name == name)
        .and_then(|setting| setting.value.as_deref())
}

fn gvariant_string(value: &str) -> String {
    format!("'{}'", escape_gvariant_string(value))
}

fn gvariant_string_array(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| gvariant_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn escape_gvariant_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn gsettings_available() -> bool {
    Command::new("gsettings").output().is_ok()
}

fn gnome_proxy_schema_available() -> Result<bool, String> {
    let output = match run_gsettings(&["list-schemas".into()]) {
        Ok(output) => output,
        Err(_) => return Ok(false),
    };
    Ok(output
        .lines()
        .map(str::trim)
        .any(|schema| schema == GNOME_PROXY_SCHEMA))
}

fn run_gsettings(args: &[String]) -> Result<String, String> {
    let output = Command::new("gsettings")
        .args(args)
        .output()
        .map_err(|error| format!("failed to run gsettings {}: {error}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "gsettings {} failed: {}{}{}",
            args.join(" "),
            stdout,
            if stdout.is_empty() || stderr.is_empty() {
                ""
            } else {
                "\n"
            },
            stderr
        ))
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
    use egrio_platform::system_proxy_config_from_listen_addr;

    #[test]
    fn gvariant_string_array_escapes_values() {
        let values = vec![
            "localhost".to_string(),
            "*.example.com".to_string(),
            "dev's-box".to_string(),
        ];

        assert_eq!(
            gvariant_string_array(&values),
            "['localhost', '*.example.com', 'dev\\'s-box']"
        );
    }

    #[test]
    fn linux_apply_commands_follow_gnome_proxy_schema() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config");
        let commands = linux_apply_gsettings_commands(&config);

        assert!(commands.contains(&gsettings_set("org.gnome.system.proxy", "mode", "'manual'")));
        assert!(commands.contains(&gsettings_set(
            "org.gnome.system.proxy.http",
            "host",
            "'127.0.0.1'"
        )));
        assert!(commands.contains(&gsettings_set(
            "org.gnome.system.proxy.http",
            "port",
            "51820"
        )));
        assert!(commands.contains(&gsettings_set(
            "org.gnome.system.proxy.socks",
            "host",
            "'127.0.0.1'"
        )));
    }

    #[test]
    fn linux_restore_commands_replay_snapshot_values() {
        let snapshot = SystemProxySnapshot {
            os: "linux".into(),
            backend: SystemProxyBackendKind::LinuxDesktopProxy,
            captured_at_unix: 1,
            settings: vec![SystemProxySettingSnapshot {
                name: gsettings_snapshot_name("org.gnome.system.proxy", "mode"),
                kind: SystemProxySettingKind::String,
                value: Some("'none'".into()),
            }],
            warnings: Vec::new(),
        };

        let commands = linux_restore_gsettings_commands(&snapshot).expect("restore commands");

        assert_eq!(
            commands,
            vec![gsettings_set("org.gnome.system.proxy", "mode", "'none'")]
        );
    }
}
