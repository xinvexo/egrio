//! Persisted desktop-behavior switches (silent start, the update check at
//! launch, theme, language) plus
//! the aggregate settings surfaced to the GUI, and the capture layers the
//! next launch turns back on. Autostart is not stored here — it lives in
//! the OS login items (on macOS the app's own login item) — but it rides
//! along in `DesktopBehaviorSettings` so a single query can populate every
//! switch on the settings page.

use egrio_platform::CaptureLayers;
use serde::{Deserialize, Serialize};

use super::profile_store::ProfileStore;

const SILENT_START_SETTING_KEY: &str = "silent_start";
const CHECK_UPDATES_SETTING_KEY: &str = "check_updates";

/// The name the auto-launch crate's login item carries: a launch agent's
/// label on macOS (which the app no longer writes, see [`login_item`]), the
/// `Run` registry value on Windows, the XDG autostart entry on Linux.
const AUTOSTART_NAME: &str = "Egrio";

/// The OS login item the auto-launch crate writes for this executable, with
/// no arguments.
fn auto_launch_item() -> Result<auto_launch::AutoLaunch, String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("locate the app executable: {error}"))?;
    let mut builder = auto_launch::AutoLaunchBuilder::new();
    builder.set_app_name(AUTOSTART_NAME);
    builder.set_args(&[] as &[&str]);
    // The `Run` value is a command line, and the installed app's path has
    // spaces (Program Files).
    #[cfg(windows)]
    builder.set_app_path(&format!("\"{}\"", executable.display()));
    #[cfg(target_os = "macos")]
    {
        builder.set_macos_launch_mode(auto_launch::MacOSLaunchMode::LaunchAgent);
        let executable = executable
            .canonicalize()
            .map_err(|error| format!("resolve the app executable: {error}"))?;
        builder.set_app_path(&executable.display().to_string());
    }
    // An AppImage relaunches through its image, not the mounted executable.
    #[cfg(target_os = "linux")]
    match std::env::var_os("APPIMAGE") {
        Some(appimage) => builder.set_app_path(&appimage.to_string_lossy()),
        None => builder.set_app_path(&executable.display().to_string()),
    };
    builder.build().map_err(|error| error.to_string())
}

/// Removes the auto-launch crate's login item; removing a missing one
/// succeeds.
fn disable_auto_launch() -> Result<(), String> {
    match auto_launch_item()?.disable() {
        Ok(()) => Ok(()),
        Err(auto_launch::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// The app's own login item on macOS 13 (ServiceManagement `SMAppService.h`,
/// `mainAppService`): registering it launches the app at the following
/// logins, and the user can turn it off in System Settings > General >
/// Login Items, where it then needs approval again.
#[cfg(target_os = "macos")]
mod login_item {
    use objc2::rc::Retained;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    fn service() -> Retained<SMAppService> {
        // SAFETY: the class property for this app's own login item.
        unsafe { SMAppService::mainAppService() }
    }

    fn status() -> SMAppServiceStatus {
        // SAFETY: reads the login item's registration.
        unsafe { service().status() }
    }

    pub fn enabled() -> Result<bool, String> {
        Ok(status() == SMAppServiceStatus::Enabled)
    }

    pub fn set(enabled: bool) -> Result<(), String> {
        // The launch agent the app wrote before must not launch it too.
        super::disable_auto_launch()?;
        let service = service();
        // SAFETY: registers or unregisters this app's own login item.
        let result = unsafe {
            if enabled {
                service.registerAndReturnError()
            } else {
                service.unregisterAndReturnError()
            }
        };
        match (enabled, status()) {
            (true, SMAppServiceStatus::Enabled) | (false, SMAppServiceStatus::NotRegistered) => {
                Ok(())
            }
            // The user turned the item off in System Settings: only they
            // can allow it, so that is where they are taken.
            (true, SMAppServiceStatus::RequiresApproval) => {
                // SAFETY: opens a System Settings pane.
                unsafe { SMAppService::openSystemSettingsLoginItems() };
                Err("allow Egrio in System Settings > General > Login Items".into())
            }
            _ => Err(match result {
                Err(error) => error.localizedDescription().to_string(),
                Ok(()) => "the login item did not change".into(),
            }),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod login_item {
    pub fn enabled() -> Result<bool, String> {
        super::auto_launch_item()?
            .is_enabled()
            .map_err(|error| error.to_string())
    }

    pub fn set(enabled: bool) -> Result<(), String> {
        if enabled {
            super::auto_launch_item()?
                .enable()
                .map_err(|error| error.to_string())
        } else {
            super::disable_auto_launch()
        }
    }
}

/// Whether the login item is registered.
pub fn autostart_enabled() -> Result<bool, String> {
    login_item::enabled()
}

/// Registers or removes the login item; removing a missing one succeeds.
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    login_item::set(enabled)
}

/// The startup/window switches shown on the settings page. `autostart`
/// reflects the OS login item; the rest are stored in the
/// profile store. The window and login switches default to `false` (show the
/// window on launch, do not launch at login), the update check to `true`;
/// theme and language default to following the OS.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopBehaviorSettings {
    /// Launch at login, backed by the OS login items.
    pub autostart: bool,
    /// Start without showing the main window; reachable from the tray/dock.
    pub silent_start: bool,
    /// Look for a newer release at launch.
    pub check_updates: bool,
    /// UI theme: follow the OS, or pin light/dark.
    pub theme: ThemePreference,
    /// UI language: follow the OS locale, or pin zh-CN/en-US.
    pub language: LanguagePreference,
}

fn load_bool(key: &str) -> Result<bool, String> {
    let stored = ProfileStore::open()
        .map_err(|error| error.to_string())?
        .app_setting(key)
        .map_err(|error| error.to_string())?;
    Ok(stored.as_deref() == Some("true"))
}

fn save_bool(key: &str, value: bool) -> Result<(), String> {
    ProfileStore::open()
        .and_then(|store| store.set_app_setting(key, if value { "true" } else { "false" }))
        .map_err(|error| error.to_string())
}

pub fn load_silent_start() -> Result<bool, String> {
    load_bool(SILENT_START_SETTING_KEY)
}

pub fn save_silent_start(enabled: bool) -> Result<(), String> {
    save_bool(SILENT_START_SETTING_KEY, enabled)
}

/// On unless turned off.
pub fn load_check_updates() -> Result<bool, String> {
    let stored = ProfileStore::open()
        .map_err(|error| error.to_string())?
        .app_setting(CHECK_UPDATES_SETTING_KEY)
        .map_err(|error| error.to_string())?;
    Ok(stored.as_deref() != Some("false"))
}

pub fn save_check_updates(enabled: bool) -> Result<(), String> {
    save_bool(CHECK_UPDATES_SETTING_KEY, enabled)
}

const CAPTURE_LAYERS_SETTING_KEY: &str = "capture_layers";

/// The capture layers the user's last switch left on, which the next launch
/// turns back on; quitting turns the layers off and keeps them here.
pub fn load_capture_layers() -> Result<CaptureLayers, String> {
    let stored = ProfileStore::open()
        .map_err(|error| error.to_string())?
        .app_setting(CAPTURE_LAYERS_SETTING_KEY)
        .map_err(|error| error.to_string())?;
    Ok(capture_layers_from_setting(stored.as_deref()))
}

pub fn save_capture_layers(layers: CaptureLayers) -> Result<(), String> {
    ProfileStore::open()
        .and_then(|store| {
            store.set_app_setting(CAPTURE_LAYERS_SETTING_KEY, capture_layers_setting(layers))
        })
        .map_err(|error| error.to_string())
}

/// The layers as their names, comma-separated, or `none`.
fn capture_layers_setting(layers: CaptureLayers) -> &'static str {
    match (layers.system_proxy, layers.tun) {
        (false, false) => "none",
        (true, false) => "system-proxy",
        (false, true) => "tun",
        (true, true) => "system-proxy,tun",
    }
}

/// Unknown names count for nothing, so a missing or unreadable value turns
/// no layer on.
fn capture_layers_from_setting(stored: Option<&str>) -> CaptureLayers {
    let names: Vec<&str> = stored.unwrap_or("").split(',').map(str::trim).collect();
    CaptureLayers {
        system_proxy: names.contains(&"system-proxy"),
        tun: names.contains(&"tun"),
    }
}

const THEME_SETTING_KEY: &str = "ui_theme";
const LANGUAGE_SETTING_KEY: &str = "ui_language";

/// Tri-state UI theme preference. `System` follows the OS
/// `prefers-color-scheme` live; the concrete values pin one theme.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePreference {
    /// The profile-store KV encoding — identical to the serde/TS string so
    /// the stored value, the wire value, and the localStorage mirror agree.
    pub fn as_setting(self) -> &'static str {
        match self {
            ThemePreference::System => "system",
            ThemePreference::Light => "light",
            ThemePreference::Dark => "dark",
        }
    }

    /// Missing or unrecognized stored values degrade to `System`.
    pub fn from_setting(stored: Option<&str>) -> Self {
        match stored {
            Some("light") => ThemePreference::Light,
            Some("dark") => ThemePreference::Dark,
            _ => ThemePreference::System,
        }
    }
}

/// Tri-state UI language preference. `System` resolves against the OS locale
/// (`sys_locale::get_locale()`), defaulting to Chinese when undecidable.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LanguagePreference {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "zh-CN")]
    ZhCn,
    #[serde(rename = "en-US")]
    EnUs,
}

impl LanguagePreference {
    pub fn as_setting(self) -> &'static str {
        match self {
            LanguagePreference::System => "system",
            LanguagePreference::ZhCn => "zh-CN",
            LanguagePreference::EnUs => "en-US",
        }
    }

    pub fn from_setting(stored: Option<&str>) -> Self {
        match stored {
            Some("zh-CN") => LanguagePreference::ZhCn,
            Some("en-US") => LanguagePreference::EnUs,
            _ => LanguagePreference::System,
        }
    }
}

pub fn load_theme_preference() -> Result<ThemePreference, String> {
    let stored = ProfileStore::open()
        .map_err(|error| error.to_string())?
        .app_setting(THEME_SETTING_KEY)
        .map_err(|error| error.to_string())?;
    Ok(ThemePreference::from_setting(stored.as_deref()))
}

pub fn save_theme_preference(theme: ThemePreference) -> Result<(), String> {
    ProfileStore::open()
        .and_then(|store| store.set_app_setting(THEME_SETTING_KEY, theme.as_setting()))
        .map_err(|error| error.to_string())
}

pub fn load_language_preference() -> Result<LanguagePreference, String> {
    let stored = ProfileStore::open()
        .map_err(|error| error.to_string())?
        .app_setting(LANGUAGE_SETTING_KEY)
        .map_err(|error| error.to_string())?;
    Ok(LanguagePreference::from_setting(stored.as_deref()))
}

pub fn save_language_preference(language: LanguagePreference) -> Result<(), String> {
    ProfileStore::open()
        .and_then(|store| store.set_app_setting(LANGUAGE_SETTING_KEY, language.as_setting()))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_layers_setting_round_trips_and_unknown_names_turn_nothing_on() {
        for system_proxy in [false, true] {
            for tun in [false, true] {
                let layers = CaptureLayers { system_proxy, tun };
                assert_eq!(
                    capture_layers_from_setting(Some(capture_layers_setting(layers))),
                    layers
                );
            }
        }
        assert_eq!(capture_layers_from_setting(None), CaptureLayers::NONE);
        assert_eq!(
            capture_layers_from_setting(Some("kill-switch")),
            CaptureLayers::NONE
        );
    }

    #[test]
    fn theme_preference_setting_round_trips() {
        for pref in [
            ThemePreference::System,
            ThemePreference::Light,
            ThemePreference::Dark,
        ] {
            assert_eq!(ThemePreference::from_setting(Some(pref.as_setting())), pref);
        }
    }

    #[test]
    fn unknown_or_missing_theme_defaults_to_system() {
        assert_eq!(ThemePreference::from_setting(None), ThemePreference::System);
        assert_eq!(
            ThemePreference::from_setting(Some("solarized")),
            ThemePreference::System
        );
    }

    #[test]
    fn language_preference_setting_round_trips() {
        for pref in [
            LanguagePreference::System,
            LanguagePreference::ZhCn,
            LanguagePreference::EnUs,
        ] {
            assert_eq!(
                LanguagePreference::from_setting(Some(pref.as_setting())),
                pref
            );
        }
    }

    #[test]
    fn language_preference_serde_uses_bcp47_tags() {
        assert_eq!(
            serde_json::to_string(&LanguagePreference::ZhCn).unwrap(),
            "\"zh-CN\""
        );
        assert_eq!(
            serde_json::to_string(&LanguagePreference::System).unwrap(),
            "\"system\""
        );
    }
}
