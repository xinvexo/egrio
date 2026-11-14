//! The settings page: the capture layers and the active profile's network
//! settings, the app's startup and logging, its look and language, and the
//! version with its update. A switch's change runs at once; where the
//! backend refuses it the switch goes back.

use egrio_desktop::desktop_behavior::{LanguagePreference, ThemePreference};
use egrio_desktop::logging::LogLevel;
use egrio_desktop::profile_network_settings::ProfileNetworkSetting;
use egrio_platform::CaptureLayer;

use crate::msg::{Msg, SettingsMsg, UpdateMsg};
use crate::node::{
    button, column, group, icon_button, scroll, segmented, select, setting_row, switch, symbol,
    text, ButtonStyle, Icon, Node, TextStyle, Tone,
};
use crate::state::State;

pub const LOG_LEVELS: [LogLevel; 6] = [
    LogLevel::Off,
    LogLevel::Error,
    LogLevel::Warn,
    LogLevel::Info,
    LogLevel::Debug,
    LogLevel::Trace,
];

pub const THEMES: [ThemePreference; 3] = [
    ThemePreference::System,
    ThemePreference::Light,
    ThemePreference::Dark,
];

pub const LANGUAGES: [LanguagePreference; 3] = [
    LanguagePreference::System,
    LanguagePreference::ZhCn,
    LanguagePreference::EnUs,
];

pub fn view(state: &State) -> Node {
    scroll(
        column(
            20.0,
            vec![
                network(state),
                general(state),
                appearance(state),
                about(state),
            ],
        )
        .key("settings"),
    )
    .grow()
}

fn network(state: &State) -> Node {
    let text = state.text();
    let status = state.capture.as_ref();
    // A change that runs long makes the others wait.
    let waiting = state.transition_slow();
    let mut rows = Vec::new();
    if status.is_none_or(|status| status.support.system_proxy) {
        let on = state.layer_on(CaptureLayer::SystemProxy);
        rows.push(setting_row(
            text.system_proxy(),
            None,
            vec![switch(on, (on || !state.needs_profile()) && !waiting, |_| {
                Msg::ToggleCapture(CaptureLayer::SystemProxy)
            })
            .key("system-proxy")],
        ));
    }
    let tun_on = state.layer_on(CaptureLayer::Tun);
    let environment_ready = status.is_some_and(|status| status.tun_environment_ready);
    let mut tun_controls = Vec::new();
    if let Some(reason) = status.and_then(|status| status.tun_interruption.clone()) {
        tun_controls.push(
            symbol(Icon::Warning, Tone::Warning)
                .tooltip(Some(text.tun_interrupted_tooltip(&reason))),
        );
    }
    tun_controls.push(
        icon_button(Icon::Wrench)
            .tone(if environment_ready {
                Tone::Success
            } else {
                Tone::Default
            })
            .busy(state.tun_preparing)
            .on_press(Msg::Settings(SettingsMsg::PrepareTun))
            .tooltip(Some(
                if environment_ready {
                    text.environment_ready()
                } else {
                    text.environment_install()
                }
                .into(),
            )),
    );
    tun_controls.push(
        switch(
            tun_on,
            status.is_none_or(|status| status.support.tun)
                && (tun_on || !state.needs_profile())
                && !waiting,
            |_| Msg::ToggleCapture(CaptureLayer::Tun),
        )
        .key("tun"),
    );
    rows.push(setting_row(text.tun(), None, tun_controls));

    if let Some(preparing) = status.and_then(|status| status.preparation.as_ref()) {
        let controls = if preparing.error.is_some() {
            vec![button(text.retry_preparation(), ButtonStyle::Secondary)
                .on_press(Msg::RetryPreparation)]
        } else {
            Vec::new()
        };
        rows.push(setting_row(
            text.preparing_rules(),
            preparing.error.clone(),
            controls,
        ));
    }

    // The profile's settings, as the running Core has them where it runs it.
    let network = state
        .network
        .ready()
        .and_then(Option::as_ref)
        .filter(|network| {
            state
                .active_profile
                .ready()
                .and_then(Option::as_ref)
                .is_some_and(|profile| profile.id == network.profile_id)
        });
    let available = network.is_some() && !waiting && !state.downloading_rules();
    let network_switch = |setting: ProfileNetworkSetting, saved: bool, key: &'static str| {
        switch(state.network_on(setting, saved), available, move |on| {
            Msg::Settings(SettingsMsg::SetNetwork(setting, on))
        })
        .key(key)
    };
    rows.push(setting_row(
        text.ipv6(),
        None,
        vec![network_switch(
            ProfileNetworkSetting::Ipv6,
            network.is_some_and(|network| network.effective_ipv6.unwrap_or(network.ipv6)),
            "ipv6",
        )],
    ));
    rows.push(setting_row(
        text.allow_lan(),
        None,
        vec![network_switch(
            ProfileNetworkSetting::AllowLan,
            network.is_some_and(|network| network.effective_allow_lan.unwrap_or(network.allow_lan)),
            "allow-lan",
        )],
    ));
    // The Core may listen on another port than the profile's, which it
    // could not use.
    let fallback = state
        .port_fallback()
        .filter(|fallback| network.is_some_and(|network| network.mixed_port == fallback.requested));
    let (port, tone, description) = match (fallback, network) {
        (Some(fallback), _) => (
            fallback.actual.to_string(),
            Tone::Warning,
            Some(fallback.detail(text)),
        ),
        (None, Some(network)) => (network.mixed_port.to_string(), Tone::Muted, None),
        (None, None) => ("—".into(), Tone::Muted, None),
    };
    rows.push(setting_row(
        text.listener_port(),
        description,
        vec![text_value(port, tone)],
    ));
    let note = state.needs_profile().then(|| text.needs_profile().into());
    group(text.settings_network(), note, rows).key("network")
}

fn general(state: &State) -> Node {
    let text = state.text();
    let behavior = state.behavior.ready();
    let behavior_switch = |on: bool, key: &'static str, msg: fn(bool) -> SettingsMsg| {
        switch(on, behavior.is_some(), move |on| Msg::Settings(msg(on))).key(key)
    };
    let level_labels = [
        text.log_level_off(),
        text.log_level_error(),
        text.log_level_warn(),
        text.log_level_info(),
        text.log_level_debug(),
        text.log_level_trace(),
    ];
    let level = state
        .log_level
        .ready()
        .and_then(|level| LOG_LEVELS.iter().position(|candidate| candidate == level));
    let geodata_description =
        if state.geodata_updating || state.geodata.ready().is_some_and(|status| status.updating) {
            Some(text.geodata_updating().to_string())
        } else {
            match state.geodata.ready() {
                Some(status) => {
                    let times: Vec<i64> = [&status.geoip, &status.geosite]
                        .into_iter()
                        .flatten()
                        .map(|file| file.updated_at_unix)
                        .collect();
                    match times.iter().min() {
                        Some(oldest) => text.updated_at(*oldest, crate::format::now_unix()),
                        None => Some(text.geodata_missing().into()),
                    }
                }
                None => None,
            }
        };
    let geodata_busy =
        state.geodata_updating || state.geodata.ready().is_some_and(|status| status.updating);
    group(
        text.settings_general(),
        None,
        vec![
            setting_row(
                text.autostart(),
                None,
                vec![behavior_switch(
                    behavior.is_some_and(|behavior| behavior.autostart),
                    "autostart",
                    SettingsMsg::SetAutostart,
                )],
            ),
            setting_row(
                text.silent_start(),
                None,
                vec![behavior_switch(
                    behavior.is_some_and(|behavior| behavior.silent_start),
                    "silent-start",
                    SettingsMsg::SetSilentStart,
                )],
            ),
            setting_row(
                text.check_updates_at_launch(),
                None,
                vec![behavior_switch(
                    behavior.is_some_and(|behavior| behavior.check_updates),
                    "check-updates",
                    SettingsMsg::SetCheckUpdates,
                )],
            ),
            setting_row(
                text.log_level(),
                None,
                vec![select(
                    level_labels.into_iter().map(String::from).collect(),
                    level,
                    state.log_level.ready().is_some(),
                    |index| Msg::Settings(SettingsMsg::SetLogLevel(LOG_LEVELS[index])),
                )
                .key("log-level")],
            ),
            setting_row(
                text.geodata(),
                geodata_description,
                vec![button(text.geodata_update(), ButtonStyle::Secondary)
                    .busy(geodata_busy)
                    .enabled(state.geodata.ready().is_some())
                    .on_press(Msg::Settings(SettingsMsg::UpdateGeodata))],
            ),
        ],
    )
    .key("general")
}

fn appearance(state: &State) -> Node {
    let text = state.text();
    let behavior = state.behavior.ready();
    let theme =
        behavior.and_then(|behavior| THEMES.iter().position(|theme| *theme == behavior.theme));
    let language = behavior.and_then(|behavior| {
        LANGUAGES
            .iter()
            .position(|language| *language == behavior.language)
    });
    group(
        text.settings_appearance(),
        None,
        vec![
            setting_row(
                text.theme(),
                None,
                vec![segmented(
                    vec![
                        text.theme_system().into(),
                        text.theme_light().into(),
                        text.theme_dark().into(),
                    ],
                    theme,
                    behavior.is_some(),
                    |index| Msg::Settings(SettingsMsg::SetTheme(THEMES[index])),
                )
                .key("theme")],
            ),
            setting_row(
                text.language(),
                None,
                vec![segmented(
                    vec![
                        text.language_system().into(),
                        text.language_zh().into(),
                        text.language_en().into(),
                    ],
                    language,
                    behavior.is_some(),
                    |index| Msg::Settings(SettingsMsg::SetLanguage(LANGUAGES[index])),
                )
                .key("language")],
            ),
        ],
    )
    .key("appearance")
}

fn about(state: &State) -> Node {
    let text = state.text();
    let update = &state.update;
    // What the last check found, or what runs now.
    let status = if update.downloading {
        Some(text.downloading_update().to_string())
    } else if update.checking {
        Some(text.checking_updates().to_string())
    } else if let Some(release) = &update.available {
        Some(text.update_available(&release.version))
    } else if update.failed {
        Some(text.update_check_failed().to_string())
    } else if update.current {
        Some(text.up_to_date().to_string())
    } else {
        None
    };
    let action = match &update.available {
        Some(_) => button(text.upgrade(), ButtonStyle::Primary)
            .busy(update.downloading)
            .on_press(Msg::Update(UpdateMsg::Upgrade)),
        None => button(text.check_for_updates(), ButtonStyle::Secondary)
            .busy(update.checking)
            .on_press(Msg::Update(UpdateMsg::Check { asked: true })),
    };
    group(
        text.settings_about(),
        None,
        vec![
            setting_row(
                text.version(),
                None,
                vec![text_value(env!("CARGO_PKG_VERSION").into(), Tone::Muted)],
            ),
            setting_row(text.updates(), status, vec![action.key("update")]),
        ],
    )
    .key("about")
}

fn text_value(value: String, tone: Tone) -> Node {
    text(value, TextStyle::Mono, tone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Kind, Node};
    use crate::state::Remote;
    use crate::text::Lang;

    fn find<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
        if node.key.as_deref() == Some(key) {
            return Some(node);
        }
        node.children.iter().find_map(|child| find(child, key))
    }

    #[test]
    fn without_a_profile_the_network_group_says_why_and_its_switches_wait() {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(None);
        state.network = Remote::Ready(None);
        let page = view(&state);
        let network = find(&page, "network").expect("the network group");
        let Kind::Group(group) = &network.kind else {
            panic!("a group")
        };
        assert_eq!(group.note.as_deref(), Some(state.text().needs_profile()));
        for key in ["system-proxy", "tun", "ipv6", "allow-lan"] {
            let Some(Kind::Switch(switch)) = find(&page, key).map(|node| &node.kind) else {
                panic!("the {key} switch")
            };
            assert!(!switch.enabled, "{key} waits for a profile");
        }
    }

    #[test]
    fn a_network_switch_shows_the_value_it_changes_to_while_it_runs() {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(Some(egrio_desktop::models::SavedProfileSummary {
            id: "p".into(),
            name: "Profile".into(),
            revision: "1".into(),
            source_revision: "s1".into(),
            traffic_policy_mode: egrio_core::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: 0,
        }));
        state.network = Remote::Ready(Some(
            egrio_desktop::profile_network_settings::ProfileNetworkSettings {
                profile_id: "p".into(),
                source_revision: "s1".into(),
                mixed_port: 7890,
                allow_lan: false,
                bind_address: "127.0.0.1".into(),
                ipv6: false,
                effective_ipv6: Some(false),
                effective_allow_lan: None,
            },
        ));
        state.change = Some(crate::state::Running {
            change: crate::state::Change::Network {
                setting: ProfileNetworkSetting::Ipv6,
                enabled: true,
            },
            id: 1,
            slow: false,
        });
        let page = view(&state);
        let switch = |key: &str| match find(&page, key).map(|node| &node.kind) {
            Some(Kind::Switch(switch)) => switch.clone(),
            _ => panic!("the {key} switch"),
        };
        assert!(
            switch("ipv6").on,
            "the switch keeps the value it was moved to"
        );
        assert!(
            switch("ipv6").enabled && switch("allow-lan").enabled,
            "a quick change dims nothing"
        );
    }
}
