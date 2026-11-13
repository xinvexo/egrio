//! The settings page's reads and actions. Startup switches, the log level,
//! the look and the language are app preferences saved off the main thread;
//! each changes at once and goes back if saving fails. The IPv6 and LAN
//! switches are profile configuration changes, like the traffic mode.

use egrio_desktop::desktop_behavior::{
    DesktopBehaviorSettings, LanguagePreference, ThemePreference,
};
use egrio_desktop::logging;
use egrio_desktop::operations::{capture, settings};
use egrio_desktop::profile_configuration::ProfileConfigurationPhase;
use egrio_desktop::profile_network_settings::{ProfileNetworkSetting, ProfileNetworkSettings};
use egrio_desktop::tun_environment::TunEnvironment;
use egrio_desktop::ui_text::{self, UiLang};

use super::Ui;
use crate::backend::{Appearance, Backend};
use crate::messages::{Level, Source};
use crate::msg::{Msg, SavedSetting, SettingsMsg};
use crate::state::{Change, Remote};
use crate::text::Lang;

pub(super) fn appearance(theme: ThemePreference) -> Appearance {
    match theme {
        ThemePreference::System => Appearance::System,
        ThemePreference::Light => Appearance::Light,
        ThemePreference::Dark => Appearance::Dark,
    }
}

fn lang(language: LanguagePreference) -> Lang {
    match ui_text::resolve(language) {
        UiLang::ZhCn => Lang::Zh,
        UiLang::EnUs => Lang::En,
    }
}

impl<B: Backend> Ui<B> {
    /// Everything the page shows that the other pages do not read.
    pub(super) fn load_settings(&self) {
        self.load_behavior();
        self.spawn_blocking(|| Msg::Settings(SettingsMsg::LogLevel(logging::load())));
        self.load_geodata();
        self.load_network_settings();
    }

    /// The page polls GEODATA while a download runs in the background.
    pub(super) fn poll_settings(&self) {
        if self
            .state
            .geodata
            .ready()
            .is_some_and(|status| status.updating)
        {
            self.load_geodata();
        }
    }

    fn load_behavior(&self) {
        self.spawn_blocking(|| Msg::Settings(SettingsMsg::Behavior(settings::desktop_behavior())));
    }

    fn load_geodata(&self) {
        self.spawn_blocking(|| Msg::Settings(SettingsMsg::Geodata(settings::geodata_status())));
    }

    pub(super) fn load_network_settings(&self) {
        let runtime = self.desktop.runtime.clone();
        self.spawn_blocking(move || {
            Msg::Settings(SettingsMsg::Network(settings::profile_network_settings(
                &runtime,
            )))
        });
    }

    pub(super) fn settings(&mut self, msg: SettingsMsg) {
        let text = self.state.text();
        match msg {
            SettingsMsg::PrepareTun => {
                if self.state.tun_preparing {
                    return;
                }
                self.state.tun_preparing = true;
                self.spawn(async {
                    Msg::Settings(SettingsMsg::TunPrepared(
                        capture::prepare_tun_environment().await,
                    ))
                });
            }
            SettingsMsg::TunPrepared(environment) => {
                self.state.tun_preparing = false;
                match environment {
                    // The page shows a ready environment in place.
                    TunEnvironment::Ready => {}
                    TunEnvironment::ApprovalRequired => {
                        self.note(Level::Warning, Source::Tun, text.tun_approval(), None)
                    }
                    TunEnvironment::Blocked { error } => self.note(
                        Level::Error,
                        Source::Tun,
                        text.environment_install_failed(),
                        Some(error),
                    ),
                }
                self.load_capture();
            }
            SettingsMsg::SetNetwork(setting, enabled) => {
                if self.state.transition_pending() {
                    return;
                }
                let Some(network) = self.state.network.ready().and_then(Option::as_ref) else {
                    return;
                };
                let runtime = self.desktop.runtime.clone();
                let (profile_id, revision) =
                    (network.profile_id.clone(), network.source_revision.clone());
                self.begin_change(Change::Network { setting, enabled }, async move {
                    let result = settings::set_profile_network_setting(
                        &runtime, profile_id, setting, enabled, revision,
                    )
                    .await;
                    Msg::Settings(SettingsMsg::NetworkChanged(result))
                });
            }
            SettingsMsg::NetworkChanged(result) => {
                // A saved setting shows at once; the settings read next
                // confirm it.
                let change = self.state.change.take().map(|running| running.change);
                let saved = result
                    .as_ref()
                    .is_ok_and(|report| report.phase != ProfileConfigurationPhase::Rejected);
                if let (
                    true,
                    Some(Change::Network { setting, enabled }),
                    Remote::Ready(Some(network)),
                ) = (saved, change, &mut self.state.network)
                {
                    show_saved(network, setting, enabled);
                }
                self.configuration_changed(result, text.save_failed());
                self.load_network_settings();
                self.load_active_profile();
                self.load_capture();
                self.load_core();
            }
            SettingsMsg::Network(result) => self.state.network = result.into(),
            SettingsMsg::SetAutostart(enabled) => {
                self.save_behavior(
                    SavedSetting::Startup,
                    |behavior| behavior.autostart = enabled,
                    move || settings::set_autostart_enabled(enabled),
                );
            }
            SettingsMsg::SetSilentStart(enabled) => {
                self.save_behavior(
                    SavedSetting::Startup,
                    |behavior| behavior.silent_start = enabled,
                    move || settings::set_silent_start(enabled),
                );
            }
            SettingsMsg::SetCheckUpdates(enabled) => {
                self.save_behavior(
                    SavedSetting::Startup,
                    |behavior| behavior.check_updates = enabled,
                    move || settings::set_check_updates(enabled),
                );
            }
            SettingsMsg::SetTheme(theme) => {
                if self.save_behavior(
                    SavedSetting::Theme,
                    |behavior| behavior.theme = theme,
                    move || settings::set_theme_preference(theme),
                ) {
                    self.backend.set_appearance(appearance(theme));
                }
            }
            SettingsMsg::SetLanguage(language) => {
                if self.save_behavior(
                    SavedSetting::Language,
                    |behavior| behavior.language = language,
                    move || settings::set_language_preference(language),
                ) {
                    self.set_lang(lang(language));
                }
            }
            SettingsMsg::Behavior(result) => {
                if let Ok(behavior) = &result {
                    self.follow_behavior(behavior);
                }
                self.state.behavior = result.into();
            }
            SettingsMsg::BehaviorSaved(setting, result) => {
                self.state.behavior_saving = false;
                match result {
                    Ok(behavior) => {
                        self.follow_behavior(&behavior);
                        self.state.behavior = Remote::Ready(behavior);
                    }
                    Err(error) => {
                        let title = match setting {
                            SavedSetting::Startup => text.save_failed(),
                            SavedSetting::Theme => text.theme_failed(),
                            SavedSetting::Language => text.language_failed(),
                        };
                        self.note(Level::Error, Source::Settings, title, Some(error));
                        // Back to what is stored.
                        self.load_behavior();
                    }
                }
            }
            SettingsMsg::SetLogLevel(level) => {
                self.state.log_level = Remote::Ready(level);
                self.spawn_blocking(move || {
                    Msg::Settings(SettingsMsg::LogLevelSaved(logging::save(level)))
                });
            }
            SettingsMsg::LogLevelSaved(result) => {
                if let Err(error) = result {
                    self.note(
                        Level::Error,
                        Source::Settings,
                        text.log_level_failed(),
                        Some(error),
                    );
                    self.spawn_blocking(|| Msg::Settings(SettingsMsg::LogLevel(logging::load())));
                }
            }
            SettingsMsg::LogLevel(result) => self.state.log_level = result.into(),
            SettingsMsg::UpdateGeodata => {
                if self.state.geodata_updating {
                    return;
                }
                self.state.geodata_updating = true;
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    Msg::Settings(SettingsMsg::GeodataUpdated(
                        settings::update_geodata(&runtime).await,
                    ))
                });
            }
            SettingsMsg::GeodataUpdated(result) => {
                self.state.geodata_updating = false;
                match result {
                    Ok(report) => {
                        let title = if report.changed {
                            text.geodata_updated()
                        } else {
                            text.geodata_current()
                        };
                        self.note(Level::Info, Source::Geodata, title, None);
                        self.state.geodata = Remote::Ready(report.status);
                    }
                    Err(error) => {
                        self.note(
                            Level::Error,
                            Source::Geodata,
                            text.geodata_update_failed(),
                            Some(error),
                        );
                        self.load_geodata();
                    }
                }
            }
            SettingsMsg::Geodata(result) => self.state.geodata = result.into(),
        }
    }

    /// Shows a preference changed by `show` at once and saves it off the
    /// main thread, unless another is being saved: two saves never race,
    /// and the refused control goes back. A failed save goes back to what
    /// is stored. Whether the save started.
    fn save_behavior(
        &mut self,
        setting: SavedSetting,
        show: impl FnOnce(&mut DesktopBehaviorSettings),
        save: impl FnOnce() -> Result<DesktopBehaviorSettings, String> + Send + 'static,
    ) -> bool {
        if self.state.behavior_saving {
            return false;
        }
        let Remote::Ready(behavior) = &mut self.state.behavior else {
            return false;
        };
        show(behavior);
        self.state.behavior_saving = true;
        self.spawn_blocking(move || Msg::Settings(SettingsMsg::BehaviorSaved(setting, save())));
        true
    }

    /// The look and the language the stored preferences ask for.
    fn follow_behavior(&mut self, behavior: &DesktopBehaviorSettings) {
        let stored = self.state.behavior.ready().copied();
        if stored.is_none_or(|stored| stored.theme != behavior.theme) {
            self.backend.set_appearance(appearance(behavior.theme));
        }
        let lang = lang(behavior.language);
        if lang != self.state.lang {
            self.set_lang(lang);
        }
    }
}

/// Shows a saved network setting, in the profile and in the running Core,
/// until the settings read next confirm it.
fn show_saved(network: &mut ProfileNetworkSettings, setting: ProfileNetworkSetting, enabled: bool) {
    let (saved, effective) = match setting {
        ProfileNetworkSetting::Ipv6 => (&mut network.ipv6, &mut network.effective_ipv6),
        ProfileNetworkSetting::AllowLan => {
            (&mut network.allow_lan, &mut network.effective_allow_lan)
        }
    };
    *saved = enabled;
    if let Some(effective) = effective {
        *effective = enabled;
    }
}
