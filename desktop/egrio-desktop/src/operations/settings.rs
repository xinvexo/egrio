//! Profile network settings and persisted app settings: the startup switches,
//! theme and language, GEODATA and the Windows TUN layer's IPv6 posture.

use crate::desktop_behavior::{
    autostart_enabled, load_check_updates, load_language_preference, load_silent_start,
    load_theme_preference, save_check_updates, save_language_preference, save_silent_start,
    save_theme_preference, set_autostart, DesktopBehaviorSettings, LanguagePreference,
    ThemePreference,
};
use crate::ipv6_settings::WindowsIpv6RuntimeState;
use crate::profile_configuration::ProfileConfigurationUpdateReport;
use crate::profile_network_settings::{
    load_active_profile_network_settings, ProfileNetworkSetting, ProfileNetworkSettings,
};
use crate::runtime::DesktopRuntime;

pub fn profile_network_settings(
    runtime: &DesktopRuntime,
) -> Result<Option<ProfileNetworkSettings>, String> {
    let mut settings = load_active_profile_network_settings()?;
    if let Some(settings) = settings.as_mut() {
        if let Some(policy) = runtime
            .effective_core_policy()
            .filter(|policy| policy.profile_id == settings.profile_id)
        {
            settings.effective_ipv6 = Some(policy.ipv6_enabled);
            settings.effective_allow_lan = Some(listener_allows_lan(runtime.effective_listener()));
        }
    }
    Ok(settings)
}

fn listener_allows_lan(listener: Option<std::net::SocketAddr>) -> bool {
    listener.is_some_and(|address| {
        let ip = address.ip();
        !ip.is_loopback()
            && !matches!(ip, std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()))
    })
}

pub async fn set_profile_network_setting(
    runtime: &DesktopRuntime,
    profile_id: String,
    setting: ProfileNetworkSetting,
    enabled: bool,
    expected_source_revision: String,
) -> Result<ProfileConfigurationUpdateReport, String> {
    runtime
        .configure_profile(
            profile_id,
            crate::profile_configuration::ProfileConfigurationIntent::Network {
                setting,
                enabled,
                expected_source_revision,
            },
        )
        .await
}

pub fn geodata_status() -> Result<crate::geodata::GeoDataStatus, String> {
    crate::geodata::status()
}

pub async fn update_geodata(
    runtime: &DesktopRuntime,
) -> Result<crate::geodata::GeoDataUpdateReport, String> {
    crate::geodata::update(runtime).await
}

pub async fn reapply_profile(
    runtime: &DesktopRuntime,
    profile_id: String,
) -> Result<ProfileConfigurationUpdateReport, String> {
    runtime
        .configure_profile_document(profile_id.clone(), move |store| {
            store
                .profile_configuration_snapshot(&profile_id)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .await
}

#[cfg(windows)]
pub fn windows_ipv6_runtime_state(runtime: &DesktopRuntime) -> Option<WindowsIpv6RuntimeState> {
    runtime.windows_ipv6_runtime_state()
}

#[cfg(not(windows))]
pub fn windows_ipv6_runtime_state(_runtime: &DesktopRuntime) -> Option<WindowsIpv6RuntimeState> {
    None
}

/// The startup and window switches: `autostart` read live from the OS login
/// items, the rest from the profile store.
pub fn desktop_behavior() -> Result<DesktopBehaviorSettings, String> {
    Ok(DesktopBehaviorSettings {
        autostart: autostart_enabled()?,
        silent_start: load_silent_start()?,
        check_updates: load_check_updates()?,
        theme: load_theme_preference()?,
        language: load_language_preference()?,
    })
}

/// Registers or clears the OS login item, then returns every switch so the
/// caller reconciles in one step.
pub fn set_autostart_enabled(enabled: bool) -> Result<DesktopBehaviorSettings, String> {
    set_autostart(enabled)?;
    desktop_behavior()
}

pub fn set_silent_start(enabled: bool) -> Result<DesktopBehaviorSettings, String> {
    save_silent_start(enabled)?;
    desktop_behavior()
}

pub fn set_check_updates(enabled: bool) -> Result<DesktopBehaviorSettings, String> {
    save_check_updates(enabled)?;
    desktop_behavior()
}

pub fn set_theme_preference(theme: ThemePreference) -> Result<DesktopBehaviorSettings, String> {
    save_theme_preference(theme)?;
    desktop_behavior()
}

pub fn set_language_preference(
    language: LanguagePreference,
) -> Result<DesktopBehaviorSettings, String> {
    save_language_preference(language)?;
    desktop_behavior()
}

#[cfg(test)]
mod tests {
    use super::listener_allows_lan;

    #[test]
    fn effective_lan_access_requires_a_non_loopback_listener() {
        assert!(!listener_allows_lan(None));
        for address in ["127.0.0.1:7890", "[::1]:7890", "[::ffff:127.0.0.1]:7890"] {
            assert!(!listener_allows_lan(Some(address.parse().unwrap())));
        }
        for address in ["0.0.0.0:7890", "[::]:7890", "192.0.2.1:7890"] {
            assert!(listener_allows_lan(Some(address.parse().unwrap())));
        }
    }
}
