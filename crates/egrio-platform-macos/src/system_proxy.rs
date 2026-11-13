#![cfg_attr(test, allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use egrio_platform::{
    SystemProxyApplyReport, SystemProxyBackendKind, SystemProxyConfig, SystemProxySettingKind,
    SystemProxySettingSnapshot, SystemProxySnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosProxyKind {
    Web,
    SecureWeb,
    Socks,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MacosProxyState {
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
    authenticated: bool,
    username: Option<String>,
    password: Option<String>,
}

impl MacosProxyKind {
    fn all() -> [Self; 3] {
        [Self::Web, Self::SecureWeb, Self::Socks]
    }

    fn snapshot_key(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::SecureWeb => "secure-web",
            Self::Socks => "socks",
        }
    }

    fn get_command(&self) -> &'static str {
        match self {
            Self::Web => "-getwebproxy",
            Self::SecureWeb => "-getsecurewebproxy",
            Self::Socks => "-getsocksfirewallproxy",
        }
    }

    fn set_command(&self) -> &'static str {
        match self {
            Self::Web => "-setwebproxy",
            Self::SecureWeb => "-setsecurewebproxy",
            Self::Socks => "-setsocksfirewallproxy",
        }
    }

    fn state_command(&self) -> &'static str {
        match self {
            Self::Web => "-setwebproxystate",
            Self::SecureWeb => "-setsecurewebproxystate",
            Self::Socks => "-setsocksfirewallproxystate",
        }
    }
}

pub fn system_proxy_status() -> Result<SystemProxySnapshot, String> {
    let services = macos_network_services()?;
    snapshot_macos_settings(&services)
}

pub(crate) fn apply_system_proxy_from_baseline(
    config: &SystemProxyConfig,
    baseline: &SystemProxySnapshot,
) -> Result<SystemProxyApplyReport, String> {
    validate_system_proxy_snapshot(baseline)?;
    let live = system_proxy_status()?;
    // Takeover requires the exact prepared ownership baseline, including inert
    // disabled endpoint metadata that restore verification intentionally ignores.
    if !snapshots_have_same_complete_settings(&live, baseline) {
        return Err(
            "macOS system proxy settings changed after the Runtime checkpoint was prepared".into(),
        );
    }
    let services = services_from_snapshot(baseline);

    for service in &services {
        for command in macos_apply_commands_for_service(service, config) {
            run_networksetup(&command)?;
        }
    }

    Ok(SystemProxyApplyReport {
        applied: true,
        config: config.clone(),
        snapshot: baseline.clone(),
        warnings: vec![
            "macOS system proxy mode applies to enabled Network Services that honor System Configuration proxy settings"
                .into(),
        ],
    })
}

pub(crate) fn restore_owned_system_proxy(
    live: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
    allow_partial: bool,
) -> Result<bool, String> {
    if live.backend != SystemProxyBackendKind::MacosNetworkSetup
        || baseline.backend != SystemProxyBackendKind::MacosNetworkSetup
    {
        return Err("selective macOS system proxy restore requires networksetup snapshots".into());
    }
    validate_system_proxy_snapshot(live)?;
    validate_system_proxy_snapshot(baseline)?;
    let commands = macos_owned_restore_commands(live, baseline, expected, allow_partial)?;
    for command in &commands {
        run_networksetup(command)?;
    }
    Ok(!commands.is_empty())
}

#[cfg(test)]
pub(crate) fn selectively_restored_snapshot(
    live: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
    allow_partial: bool,
) -> (SystemProxySnapshot, bool) {
    if validate_system_proxy_snapshot(live).is_err()
        || validate_system_proxy_snapshot(baseline).is_err()
    {
        return (live.clone(), false);
    }
    let mut result = live.clone();
    let mut changed = false;
    let live_services = normalized_strings(&services_from_snapshot(live));
    for service in services_from_snapshot(baseline) {
        if !live_services.contains(&service) {
            continue;
        }
        for kind in MacosProxyKind::all() {
            let name = macos_proxy_snapshot_name(&service, kind);
            let Some(live_raw) = setting_value(live, &name) else {
                continue;
            };
            let Some(baseline_raw) = setting_value(baseline, &name) else {
                continue;
            };
            let Ok(live_state) = parse_macos_proxy_state(live_raw) else {
                return (live.clone(), false);
            };
            let Ok(baseline_state) = parse_macos_proxy_state(baseline_raw) else {
                return (live.clone(), false);
            };
            if !proxy_states_have_same_effective_settings(&live_state, &baseline_state)
                && proxy_state_is_owned(&live_state, &baseline_state, expected, allow_partial)
            {
                replace_setting(&mut result, &name, Some(baseline_raw.to_string()));
                changed = true;
            }
        }
        let name = macos_bypass_snapshot_name(&service);
        let live_domains = setting_value(live, &name)
            .and_then(|raw| parse_macos_bypass_domains(raw).ok())
            .unwrap_or_default();
        let baseline_domains = setting_value(baseline, &name)
            .and_then(|raw| parse_macos_bypass_domains(raw).ok())
            .unwrap_or_default();
        if normalized_strings(&live_domains) != normalized_strings(&baseline_domains)
            && normalized_strings(&live_domains) == normalized_strings(&expected.bypass)
        {
            replace_setting(
                &mut result,
                &name,
                Some(
                    baseline_domains
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            );
            changed = true;
        }
    }
    (result, changed)
}

fn macos_network_services() -> Result<Vec<String>, String> {
    let output = run_networksetup(&["-listallnetworkservices".into()])?;
    let services = parse_macos_network_services(&output);
    if services.is_empty() {
        Err("networksetup did not report any enabled network services".into())
    } else {
        Ok(services)
    }
}

fn snapshot_macos_settings(services: &[String]) -> Result<SystemProxySnapshot, String> {
    let mut settings = vec![SystemProxySettingSnapshot {
        name: macos_services_snapshot_name(),
        kind: SystemProxySettingKind::String,
        value: Some(services.join("\n")),
    }];

    for service in services {
        for kind in MacosProxyKind::all() {
            settings.push(SystemProxySettingSnapshot {
                name: macos_proxy_snapshot_name(service, kind),
                kind: SystemProxySettingKind::String,
                value: Some(run_networksetup(&[
                    kind.get_command().into(),
                    service.clone(),
                ])?),
            });
        }
        settings.push(SystemProxySettingSnapshot {
            name: macos_bypass_snapshot_name(service),
            kind: SystemProxySettingKind::String,
            value: Some(run_networksetup(&[
                "-getproxybypassdomains".into(),
                service.clone(),
            ])?),
        });
    }

    let snapshot = SystemProxySnapshot {
        os: "macos".into(),
        backend: SystemProxyBackendKind::MacosNetworkSetup,
        captured_at_unix: now_unix(),
        settings,
        warnings: Vec::new(),
    };
    validate_system_proxy_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn services_from_snapshot(snapshot: &SystemProxySnapshot) -> Vec<String> {
    setting_value(snapshot, &macos_services_snapshot_name())
        .map(parse_macos_network_services)
        .unwrap_or_default()
}

pub(crate) fn validate_system_proxy_snapshot(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    if snapshot.os != "macos" || snapshot.backend != SystemProxyBackendKind::MacosNetworkSetup {
        return Err("system proxy snapshot does not use the macOS networksetup contract".into());
    }

    let mut names = BTreeSet::new();
    for setting in &snapshot.settings {
        if !names.insert(setting.name.as_str()) {
            return Err(format!(
                "macOS system proxy snapshot contains duplicate setting '{}'",
                setting.name
            ));
        }
        if setting.kind != SystemProxySettingKind::String || setting.value.is_none() {
            return Err(format!(
                "macOS system proxy snapshot setting '{}' is not a persisted string",
                setting.name
            ));
        }
    }

    let services_raw = setting_value(snapshot, &macos_services_snapshot_name())
        .ok_or_else(|| "macOS system proxy snapshot has no Network Service list".to_string())?;
    let services = parse_macos_network_services(services_raw);
    if services.is_empty() {
        return Err("macOS system proxy snapshot has no enabled Network Services".into());
    }
    if normalized_strings(&services).len() != services.len() {
        return Err("macOS system proxy snapshot contains duplicate Network Services".into());
    }

    for service in &services {
        for kind in MacosProxyKind::all() {
            let name = macos_proxy_snapshot_name(service, kind);
            let raw = setting_value(snapshot, &name).ok_or_else(|| {
                format!("macOS system proxy snapshot is missing setting '{name}'")
            })?;
            parse_macos_proxy_state(raw).map_err(|error| format!("{name}: {error}"))?;
        }
        let name = macos_bypass_snapshot_name(service);
        let raw = setting_value(snapshot, &name)
            .ok_or_else(|| format!("macOS system proxy snapshot is missing setting '{name}'"))?;
        parse_macos_bypass_domains(raw).map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(())
}

pub(crate) fn snapshot_has_enabled_authenticated_proxy(snapshot: &SystemProxySnapshot) -> bool {
    validate_system_proxy_snapshot(snapshot).is_ok()
        && services_from_snapshot(snapshot).iter().any(|service| {
            MacosProxyKind::all().iter().any(|kind| {
                setting_value(snapshot, &macos_proxy_snapshot_name(service, *kind))
                    .and_then(|raw| parse_macos_proxy_state(raw).ok())
                    .is_some_and(|state| state.enabled && state.authenticated)
            })
        })
}

pub(crate) fn snapshot_has_active_proxy(snapshot: &SystemProxySnapshot) -> bool {
    validate_system_proxy_snapshot(snapshot).is_ok()
        && services_from_snapshot(snapshot).iter().any(|service| {
            MacosProxyKind::all().iter().any(|kind| {
                setting_value(snapshot, &macos_proxy_snapshot_name(service, *kind))
                    .and_then(|raw| parse_macos_proxy_state(raw).ok())
                    .is_some_and(|state| state.enabled)
            })
        })
}

pub(crate) fn snapshot_matches_config(
    snapshot: &SystemProxySnapshot,
    config: &SystemProxyConfig,
) -> bool {
    if validate_system_proxy_snapshot(snapshot).is_err() {
        return false;
    }
    let services = services_from_snapshot(snapshot);
    !services.is_empty()
        && services.iter().all(|service| {
            MacosProxyKind::all().iter().all(|kind| {
                setting_value(snapshot, &macos_proxy_snapshot_name(service, *kind))
                    .and_then(|raw| parse_macos_proxy_state(raw).ok())
                    .is_some_and(|state| proxy_state_matches_config(&state, config))
            }) && setting_value(snapshot, &macos_bypass_snapshot_name(service))
                .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                .is_some_and(|domains| {
                    normalized_strings(&domains) == normalized_strings(&config.bypass)
                })
        })
}

#[cfg(test)]
pub(crate) fn snapshot_has_expected_residue(
    snapshot: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
) -> bool {
    snapshot_has_owned_residue(snapshot, baseline, expected, false)
}

pub(crate) fn snapshot_has_owned_residue(
    snapshot: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
    allow_partial: bool,
) -> bool {
    if validate_system_proxy_snapshot(snapshot).is_err()
        || validate_system_proxy_snapshot(baseline).is_err()
    {
        return true;
    }
    services_from_snapshot(baseline).iter().any(|service| {
        MacosProxyKind::all().iter().any(|kind| {
            let name = macos_proxy_snapshot_name(service, *kind);
            let live =
                setting_value(snapshot, &name).and_then(|raw| parse_macos_proxy_state(raw).ok());
            let before =
                setting_value(baseline, &name).and_then(|raw| parse_macos_proxy_state(raw).ok());
            live.zip(before).is_some_and(|(live, before)| {
                !proxy_states_have_same_effective_settings(&live, &before)
                    && proxy_state_is_owned(&live, &before, expected, allow_partial)
            })
        }) || {
            let name = macos_bypass_snapshot_name(service);
            let live = setting_value(snapshot, &name)
                .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                .unwrap_or_default();
            let before = setting_value(baseline, &name)
                .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                .unwrap_or_default();
            normalized_strings(&live) == normalized_strings(&expected.bypass)
                && normalized_strings(&live) != normalized_strings(&before)
        }
    })
}

pub fn snapshots_have_same_effective_settings(
    left: &SystemProxySnapshot,
    right: &SystemProxySnapshot,
) -> bool {
    snapshots_have_matching_settings(left, right, proxy_states_have_same_effective_settings)
}

pub(crate) fn snapshots_have_same_complete_settings(
    left: &SystemProxySnapshot,
    right: &SystemProxySnapshot,
) -> bool {
    snapshots_have_matching_settings(left, right, |left, right| left == right)
}

fn snapshots_have_matching_settings(
    left: &SystemProxySnapshot,
    right: &SystemProxySnapshot,
    proxy_states_match: impl Fn(&MacosProxyState, &MacosProxyState) -> bool + Copy,
) -> bool {
    if validate_system_proxy_snapshot(left).is_err()
        || validate_system_proxy_snapshot(right).is_err()
    {
        return false;
    }
    let left_services = normalized_strings(&services_from_snapshot(left));
    let right_services = normalized_strings(&services_from_snapshot(right));
    left_services == right_services
        && left_services.iter().all(|service| {
            MacosProxyKind::all().iter().all(|kind| {
                let name = macos_proxy_snapshot_name(service, *kind);
                setting_value(left, &name)
                    .and_then(|raw| parse_macos_proxy_state(raw).ok())
                    .zip(
                        setting_value(right, &name)
                            .and_then(|raw| parse_macos_proxy_state(raw).ok()),
                    )
                    .is_some_and(|(left, right)| proxy_states_match(&left, &right))
            }) && {
                let name = macos_bypass_snapshot_name(service);
                let left_domains = setting_value(left, &name)
                    .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                    .unwrap_or_default();
                let right_domains = setting_value(right, &name)
                    .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                    .unwrap_or_default();
                normalized_strings(&left_domains) == normalized_strings(&right_domains)
            }
        })
}

#[cfg(test)]
pub(crate) fn snapshot_is_owned_transition(
    snapshot: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
) -> bool {
    if validate_system_proxy_snapshot(snapshot).is_err()
        || validate_system_proxy_snapshot(baseline).is_err()
    {
        return false;
    }
    let services = normalized_strings(&services_from_snapshot(snapshot));
    if services.is_empty() || services != normalized_strings(&services_from_snapshot(baseline)) {
        return false;
    }
    services.iter().all(|service| {
        MacosProxyKind::all().iter().all(|kind| {
            let name = macos_proxy_snapshot_name(service, *kind);
            let live =
                setting_value(snapshot, &name).and_then(|raw| parse_macos_proxy_state(raw).ok());
            let before =
                setting_value(baseline, &name).and_then(|raw| parse_macos_proxy_state(raw).ok());
            live.as_ref()
                .zip(before.as_ref())
                .is_some_and(|(live, before)| {
                    proxy_states_have_same_effective_settings(live, before)
                })
                || live.is_some_and(|state| {
                    state.enabled
                        && !state.authenticated
                        && state.server.as_deref() == Some(expected.host.as_str())
                        && state.port == Some(expected.port)
                })
        }) && {
            let name = macos_bypass_snapshot_name(service);
            let live = setting_value(snapshot, &name)
                .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                .unwrap_or_default();
            let before = setting_value(baseline, &name)
                .and_then(|raw| parse_macos_bypass_domains(raw).ok())
                .unwrap_or_default();
            let live = normalized_strings(&live);
            live == normalized_strings(&before) || live == normalized_strings(&expected.bypass)
        }
    })
}

fn normalized_strings(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn setting_value<'a>(snapshot: &'a SystemProxySnapshot, name: &str) -> Option<&'a str> {
    snapshot
        .settings
        .iter()
        .find(|setting| setting.name == name)
        .and_then(|setting| setting.value.as_deref())
}

#[cfg(test)]
fn replace_setting(snapshot: &mut SystemProxySnapshot, name: &str, value: Option<String>) {
    if let Some(setting) = snapshot
        .settings
        .iter_mut()
        .find(|setting| setting.name == name)
    {
        setting.value = value;
    }
}

fn run_networksetup(args: &[String]) -> Result<String, String> {
    let output = Command::new("networksetup")
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(|error| format!("failed to run networksetup {}: {error}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "networksetup {} failed: {}{}",
            args.join(" "),
            stdout,
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

fn parse_macos_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

fn parse_macos_proxy_state(output: &str) -> Result<MacosProxyState, String> {
    let mut fields = BTreeMap::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("networksetup proxy line has no field separator: {line}"))?;
        let key = key.trim();
        if fields.insert(key, value.trim()).is_some() {
            return Err(format!("networksetup proxy field is duplicated: {key}"));
        }
    }

    let required = |key: &str| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("networksetup proxy field is missing: {key}"))
    };
    let enabled = parse_macos_bool(required("Enabled")?, "Enabled")?;
    let server = match required("Server")? {
        "" => None,
        value => Some(value.into()),
    };
    let port_raw = required("Port")?;
    if port_raw.is_empty() || !port_raw.bytes().all(|value| value.is_ascii_digit()) {
        return Err(format!("networksetup proxy port is invalid: {port_raw}"));
    }
    let port = port_raw
        .parse::<u16>()
        .map_err(|_| format!("networksetup proxy port is out of range: {port_raw}"))?;
    let authenticated = parse_macos_bool(
        required("Authenticated Proxy Enabled")?,
        "Authenticated Proxy Enabled",
    )?;
    if enabled && (server.is_none() || port == 0) {
        return Err("enabled networksetup proxy has no complete endpoint".into());
    }
    let username = fields
        .get("Username")
        .filter(|value| !value.is_empty())
        .map(|value| (*value).into());
    let password = fields
        .get("Password")
        .filter(|value| !value.is_empty())
        .map(|value| (*value).into());
    if enabled && authenticated && (username.is_none() || password.is_none()) {
        return Err("enabled authenticated networksetup proxy has incomplete credentials".into());
    }
    Ok(MacosProxyState {
        enabled,
        server,
        port: Some(port),
        authenticated,
        username,
        password,
    })
}

fn parse_macos_bypass_domains(output: &str) -> Result<Vec<String>, String> {
    if output
        .to_ascii_lowercase()
        .contains("there aren't any bypass domains")
    {
        return Ok(Vec::new());
    }

    let domains = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    validate_bypass_domains(&domains)?;
    Ok(domains)
}

pub(crate) fn validate_bypass_domains(domains: &[String]) -> Result<(), String> {
    if let Some(value) = domains.iter().find(|value| {
        value.is_empty()
            || !value.is_ascii()
            || value.chars().any(char::is_whitespace)
            || value.chars().any(char::is_control)
    }) {
        return Err(format!("invalid macOS system proxy bypass domain: {value}"));
    }
    Ok(())
}

fn macos_apply_commands_for_service(service: &str, config: &SystemProxyConfig) -> Vec<Vec<String>> {
    let port = config.port.to_string();
    let mut commands = Vec::new();
    for kind in MacosProxyKind::all() {
        commands.push(vec![
            kind.set_command().into(),
            service.into(),
            config.host.clone(),
            port.clone(),
        ]);
        commands.push(vec![
            kind.state_command().into(),
            service.into(),
            "on".into(),
        ]);
    }
    commands.push(macos_bypass_command_for_service(service, &config.bypass));
    commands
}

fn macos_owned_restore_commands(
    live: &SystemProxySnapshot,
    baseline: &SystemProxySnapshot,
    expected: &SystemProxyConfig,
    allow_partial: bool,
) -> Result<Vec<Vec<String>>, String> {
    let live_services = normalized_strings(&services_from_snapshot(live));
    let mut commands = Vec::new();
    for service in services_from_snapshot(baseline) {
        if !live_services.contains(&service) {
            continue;
        }
        for kind in MacosProxyKind::all() {
            let name = macos_proxy_snapshot_name(&service, kind);
            let Some(live_raw) = setting_value(live, &name) else {
                continue;
            };
            let Some(baseline_raw) = setting_value(baseline, &name) else {
                continue;
            };
            let live_state = parse_macos_proxy_state(live_raw)?;
            let baseline_state = parse_macos_proxy_state(baseline_raw)?;
            if !proxy_states_have_same_effective_settings(&live_state, &baseline_state)
                && proxy_state_is_owned(&live_state, &baseline_state, expected, allow_partial)
            {
                commands.extend(macos_restore_proxy_commands(
                    &service,
                    kind,
                    &baseline_state,
                )?);
            }
        }

        let name = macos_bypass_snapshot_name(&service);
        let live_domains = setting_value(live, &name)
            .map(parse_macos_bypass_domains)
            .transpose()?
            .unwrap_or_default();
        let baseline_domains = setting_value(baseline, &name)
            .map(parse_macos_bypass_domains)
            .transpose()?
            .unwrap_or_default();
        if normalized_strings(&live_domains) != normalized_strings(&baseline_domains)
            && normalized_strings(&live_domains) == normalized_strings(&expected.bypass)
        {
            commands.push(macos_bypass_command_for_service(
                &service,
                &baseline_domains,
            ));
        }
    }
    Ok(commands)
}

fn proxy_state_matches_config(state: &MacosProxyState, config: &SystemProxyConfig) -> bool {
    state.enabled
        && !state.authenticated
        && state.server.as_deref() == Some(config.host.as_str())
        && state.port == Some(config.port)
}

fn proxy_states_have_same_effective_settings(
    left: &MacosProxyState,
    right: &MacosProxyState,
) -> bool {
    (!left.enabled && !right.enabled) || left == right
}

fn proxy_state_is_owned(
    live: &MacosProxyState,
    baseline: &MacosProxyState,
    expected: &SystemProxyConfig,
    allow_partial: bool,
) -> bool {
    if proxy_state_matches_config(live, expected) {
        return true;
    }
    allow_partial
        && (live.enabled == baseline.enabled || live.enabled)
        && (live.server == baseline.server
            || live.server.as_deref() == Some(expected.host.as_str()))
        && (live.port == baseline.port || live.port == Some(expected.port))
        && (live.authenticated == baseline.authenticated || !live.authenticated)
        && (live.username == baseline.username || live.username.is_none())
        && (live.password == baseline.password || live.password.is_none())
}

fn macos_restore_proxy_commands(
    service: &str,
    kind: MacosProxyKind,
    state: &MacosProxyState,
) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    if state.enabled {
        let (Some(server), Some(port)) = (&state.server, state.port.filter(|port| *port != 0))
        else {
            return Err(format!(
                "enabled {} proxy baseline for {service} has no complete endpoint",
                kind.snapshot_key()
            ));
        };
        let mut set_command = vec![
            kind.set_command().into(),
            service.into(),
            server.clone(),
            port.to_string(),
        ];
        if state.authenticated {
            let (Some(username), Some(password)) = (&state.username, &state.password) else {
                return Err(format!(
                    "authenticated {} proxy baseline for {service} has incomplete credentials",
                    kind.snapshot_key()
                ));
            };
            set_command.push("on".into());
            set_command.push(username.clone());
            set_command.push(password.clone());
        }
        commands.push(set_command);
    } else {
        commands.push(vec![
            kind.state_command().into(),
            service.into(),
            "off".into(),
        ]);
    }
    Ok(commands)
}

fn macos_bypass_command_for_service(service: &str, domains: &[String]) -> Vec<String> {
    let mut command = vec!["-setproxybypassdomains".into(), service.into()];
    if domains.is_empty() {
        command.push("Empty".into());
    } else {
        command.extend(domains.iter().cloned());
    }
    command
}

fn macos_services_snapshot_name() -> String {
    "macos:services".into()
}

fn macos_proxy_snapshot_name(service: &str, kind: MacosProxyKind) -> String {
    format!("macos:{service}:{}", kind.snapshot_key())
}

fn macos_bypass_snapshot_name(service: &str) -> String {
    format!("macos:{service}:bypass")
}

fn parse_macos_bool(value: &str, field: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "on" | "1" | "true" => Ok(true),
        "no" | "off" | "0" | "false" => Ok(false),
        _ => Err(format!("networksetup proxy {field} is invalid: {value}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egrio_platform::system_proxy_config_from_listen_addr;

    #[test]
    fn parses_macos_enabled_network_services() {
        let services = parse_macos_network_services(
            r#"
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Disabled Network
Example Ethernet
"#,
        );

        assert_eq!(services, vec!["Wi-Fi", "Example Ethernet"]);
    }

    #[test]
    fn parses_macos_proxy_state_output() {
        let state = parse_macos_proxy_state(
            r#"
Enabled: Yes
Server: 127.0.0.1
Port: 7890
Authenticated Proxy Enabled: 0
"#,
        )
        .unwrap();

        assert!(state.enabled);
        assert_eq!(state.server.as_deref(), Some("127.0.0.1"));
        assert_eq!(state.port, Some(7890));
        assert!(!state.authenticated);
    }

    #[test]
    fn strict_snapshot_validation_rejects_missing_or_ambiguous_proxy_state() {
        let mut missing_service =
            proxy_snapshot("127.0.0.1", 7890, true, &["localhost".to_string()]);
        missing_service.settings[0].value = Some(String::new());
        assert!(validate_system_proxy_snapshot(&missing_service).is_err());

        let mut missing_protocol =
            proxy_snapshot("127.0.0.1", 7890, true, &["localhost".to_string()]);
        missing_protocol
            .settings
            .retain(|setting| !setting.name.ends_with(":socks"));
        assert!(validate_system_proxy_snapshot(&missing_protocol).is_err());

        let mut invalid_boolean =
            proxy_snapshot("127.0.0.1", 7890, true, &["localhost".to_string()]);
        invalid_boolean
            .settings
            .iter_mut()
            .find(|setting| setting.name.ends_with(":web"))
            .unwrap()
            .value = Some(
            "Enabled: Maybe\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n"
                .into(),
        );
        assert!(validate_system_proxy_snapshot(&invalid_boolean).is_err());

        let mut duplicate = proxy_snapshot("127.0.0.1", 7890, true, &["localhost".to_string()]);
        duplicate.settings.push(duplicate.settings[1].clone());
        assert!(validate_system_proxy_snapshot(&duplicate).is_err());
    }

    #[test]
    fn macos_apply_commands_cover_http_https_socks_and_bypass() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config");
        let commands = macos_apply_commands_for_service("Wi-Fi", &config);

        assert!(commands.contains(&strings(&["-setwebproxy", "Wi-Fi", "127.0.0.1", "51820"])));
        assert!(commands.contains(&strings(&[
            "-setsecurewebproxy",
            "Wi-Fi",
            "127.0.0.1",
            "51820",
        ])));
        assert!(commands.contains(&strings(&[
            "-setsocksfirewallproxy",
            "Wi-Fi",
            "127.0.0.1",
            "51820",
        ])));
        assert!(commands.contains(&strings(&[
            "-setproxybypassdomains",
            "Wi-Fi",
            "localhost",
            "127.0.0.1",
            "::1",
            "<local>",
        ])));
    }

    #[test]
    fn macos_restore_commands_never_enable_a_disabled_baseline_endpoint() {
        let state = parse_macos_proxy_state(
            r#"
Enabled: No
Server: 10.0.0.1
Port: 8080
Authenticated Proxy Enabled: 0
"#,
        )
        .unwrap();

        let commands = macos_restore_proxy_commands("Wi-Fi", MacosProxyKind::Web, &state).unwrap();

        assert_eq!(
            commands,
            vec![strings(&["-setwebproxystate", "Wi-Fi", "off"])]
        );
    }

    #[test]
    fn macos_restore_commands_enable_an_active_baseline_atomically() {
        let state = parse_macos_proxy_state(
            r#"
Enabled: Yes
Server: 10.0.0.1
Port: 8080
Authenticated Proxy Enabled: 0
"#,
        )
        .unwrap();

        let commands = macos_restore_proxy_commands("Wi-Fi", MacosProxyKind::Web, &state).unwrap();

        assert_eq!(
            commands,
            vec![strings(&["-setwebproxy", "Wi-Fi", "10.0.0.1", "8080"])]
        );
    }

    #[test]
    fn macos_restore_commands_reject_incomplete_enabled_baselines() {
        let missing_endpoint = parse_macos_proxy_state(
            "Enabled: Yes\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n",
        );
        assert!(missing_endpoint.is_err());

        let zero_port = parse_macos_proxy_state(
            "Enabled: Yes\nServer: proxy.example\nPort: 0\nAuthenticated Proxy Enabled: 0\n",
        );
        assert!(zero_port.is_err());

        let missing_credentials = parse_macos_proxy_state(
            "Enabled: Yes\nServer: proxy.example\nPort: 8080\nAuthenticated Proxy Enabled: 1\n",
        );
        assert!(missing_credentials.is_err());
    }

    #[test]
    fn macos_snapshot_helpers_are_stable() {
        assert_eq!(MacosProxyKind::Web.get_command(), "-getwebproxy");
        assert_eq!(macos_services_snapshot_name(), "macos:services");
        assert_eq!(
            macos_proxy_snapshot_name("Wi-Fi", MacosProxyKind::SecureWeb),
            "macos:Wi-Fi:secure-web"
        );
        assert_eq!(macos_bypass_snapshot_name("Wi-Fi"), "macos:Wi-Fi:bypass");
        assert_eq!(
            parse_macos_bypass_domains("localhost\n*.local\n").unwrap(),
            vec!["localhost", "*.local"]
        );
        assert!(
            parse_macos_bypass_domains("There aren't any bypass domains set on Wi-Fi.")
                .unwrap()
                .is_empty()
        );
        assert!(parse_macos_bypass_domains("No hay dominios de omision configurados.").is_err());
    }

    #[test]
    fn runtime_snapshot_matches_only_the_expected_listener_and_bypass() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config");
        let expected = proxy_snapshot("127.0.0.1", 51820, true, &config.bypass);
        assert!(snapshot_matches_config(&expected, &config));

        let foreign = proxy_snapshot("127.0.0.1", 10809, true, &config.bypass);
        assert!(!snapshot_matches_config(&foreign, &config));

        let disabled = proxy_snapshot("127.0.0.1", 51820, false, &config.bypass);
        assert!(!snapshot_matches_config(&disabled, &config));
    }

    #[test]
    fn disabled_proxy_metadata_is_not_an_effective_or_owned_residue() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:51820").expect("config");
        let baseline = proxy_snapshot("10.0.0.1", 8080, false, &["baseline.local".into()]);
        let disabled_expected =
            proxy_snapshot("127.0.0.1", 51820, false, &["baseline.local".into()]);

        assert!(!snapshot_has_expected_residue(
            &disabled_expected,
            &baseline,
            &config
        ));
        assert!(snapshots_have_same_effective_settings(
            &disabled_expected,
            &baseline
        ));
        assert!(!snapshot_has_owned_residue(
            &disabled_expected,
            &baseline,
            &config,
            true
        ));
        assert!(
            macos_owned_restore_commands(&disabled_expected, &baseline, &config, true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn effective_snapshot_comparison_ignores_capture_time_and_order() {
        let bypass = vec!["localhost".to_string(), "*.local".to_string()];
        let left = proxy_snapshot("127.0.0.1", 7890, true, &bypass);
        let mut right = proxy_snapshot(
            "127.0.0.1",
            7890,
            true,
            &["*.local".to_string(), "localhost".to_string()],
        );
        right.captured_at_unix = 42;
        right.settings.reverse();

        assert!(snapshots_have_same_effective_settings(&left, &right));
    }

    #[test]
    fn interrupted_apply_is_still_recognized_as_owned() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:7890").expect("config");
        let baseline = proxy_snapshot("10.0.0.1", 8080, false, &["baseline.local".to_string()]);
        let mut partial = baseline.clone();
        partial
            .settings
            .iter_mut()
            .find(|setting| setting.name.ends_with(":web"))
            .expect("web setting")
            .value = Some(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n".into(),
        );

        assert!(snapshot_is_owned_transition(&partial, &baseline, &config));

        partial
            .settings
            .iter_mut()
            .find(|setting| setting.name.ends_with(":secure-web"))
            .expect("secure web setting")
            .value = Some(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 10809\nAuthenticated Proxy Enabled: 0\n".into(),
        );
        assert!(!snapshot_is_owned_transition(&partial, &baseline, &config));
    }

    #[test]
    fn selective_restore_cleans_a_partial_apply_and_is_idempotent() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:7890").expect("config");
        let baseline = proxy_snapshot("10.0.0.1", 8080, false, &["baseline.local".into()]);
        let expected = proxy_snapshot("127.0.0.1", 7890, true, &config.bypass);
        let mut partial = baseline.clone();
        for suffix in [":web", ":socks"] {
            let mut expected_value = expected
                .settings
                .iter()
                .find(|setting| setting.name.ends_with(suffix))
                .and_then(|setting| setting.value.clone())
                .unwrap();
            if suffix == ":web" {
                expected_value = expected_value.replace("Enabled: Yes", "Enabled: No");
            }
            partial
                .settings
                .iter_mut()
                .find(|setting| setting.name.ends_with(suffix))
                .unwrap()
                .value = Some(expected_value);
        }

        let (restored, changed) = selectively_restored_snapshot(&partial, &baseline, &config, true);
        let (retried, retry_changed) =
            selectively_restored_snapshot(&restored, &baseline, &config, true);

        assert!(changed);
        assert!(snapshots_have_same_effective_settings(&restored, &baseline));
        assert!(!retry_changed);
        assert!(snapshots_have_same_effective_settings(&retried, &baseline));
    }

    #[test]
    fn selective_restore_ignores_a_service_added_after_the_checkpoint() {
        let config = system_proxy_config_from_listen_addr("127.0.0.1:7890").expect("config");
        let baseline = proxy_snapshot("10.0.0.1", 8080, false, &["baseline.local".into()]);
        let mut live = proxy_snapshot("127.0.0.1", 7890, true, &config.bypass);
        let added_service = "Example Ethernet";
        let foreign = proxy_snapshot_for_service(
            added_service,
            "127.0.0.1",
            10809,
            true,
            &["foreign.local".into()],
        );
        live.settings
            .iter_mut()
            .find(|setting| setting.name == macos_services_snapshot_name())
            .unwrap()
            .value = Some(format!("Wi-Fi\n{added_service}"));
        live.settings.extend(foreign.settings.into_iter().skip(1));

        let (restored, changed) = selectively_restored_snapshot(&live, &baseline, &config, false);
        let expected_foreign = proxy_snapshot_for_service(
            added_service,
            "127.0.0.1",
            10809,
            true,
            &["foreign.local".into()],
        );

        assert!(changed);
        assert_eq!(
            setting_value(
                &restored,
                &macos_proxy_snapshot_name(added_service, MacosProxyKind::Web)
            ),
            setting_value(
                &expected_foreign,
                &macos_proxy_snapshot_name(added_service, MacosProxyKind::Web)
            )
        );
        assert!(!snapshot_has_expected_residue(
            &restored, &baseline, &config
        ));
    }

    fn proxy_snapshot(
        host: &str,
        port: u16,
        enabled: bool,
        bypass: &[String],
    ) -> SystemProxySnapshot {
        proxy_snapshot_for_service("Wi-Fi", host, port, enabled, bypass)
    }

    fn proxy_snapshot_for_service(
        service: &str,
        host: &str,
        port: u16,
        enabled: bool,
        bypass: &[String],
    ) -> SystemProxySnapshot {
        let mut settings = vec![SystemProxySettingSnapshot {
            name: macos_services_snapshot_name(),
            kind: SystemProxySettingKind::String,
            value: Some(service.into()),
        }];
        for kind in MacosProxyKind::all() {
            settings.push(SystemProxySettingSnapshot {
                name: macos_proxy_snapshot_name(service, kind),
                kind: SystemProxySettingKind::String,
                value: Some(format!(
                    "Enabled: {}\nServer: {host}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n",
                    if enabled { "Yes" } else { "No" }
                )),
            });
        }
        settings.push(SystemProxySettingSnapshot {
            name: macos_bypass_snapshot_name(service),
            kind: SystemProxySettingKind::String,
            value: Some(bypass.join("\n")),
        });
        SystemProxySnapshot {
            os: "macos".into(),
            backend: SystemProxyBackendKind::MacosNetworkSetup,
            captured_at_unix: 0,
            settings,
            warnings: Vec::new(),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }
}
