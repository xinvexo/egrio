//! The main window as a whole: the shell around the page (title, sidebar,
//! toolbar, drawer) and its content trees, the page, the drawer and an open
//! dialog. The editor window's view is in [`crate::editor`].

use egrio_core::TrafficPolicyMode;
use egrio_platform::CaptureLayer;

use crate::backend::{
    CaptureToggle, MainView, MessagePreview, MessagesButton, NavItem, PolicyControl, ToggleState,
    ToolbarView,
};
use crate::format;
use crate::messages::{Level, Message, Source};
use crate::msg::Msg;
use crate::node::{
    badge, button, caption, column, paragraph, placeholder, row, scroll, spacer, text, ButtonStyle,
    Icon, Node, TextStyle, Tone,
};
use crate::pages;
use crate::state::{Dialog, Section, State};
use crate::text::Text;

pub struct Views {
    pub main: MainView,
    pub content: Node,
    pub drawer: Node,
    /// The open dialog's content.
    pub dialog: Option<Node>,
}

pub fn section_label(section: Section, text: Text) -> &'static str {
    match section {
        Section::Activity => text.nav_activity(),
        Section::Nodes => text.nav_nodes(),
        Section::Profiles => text.nav_profiles(),
        Section::Rules => text.nav_rules(),
        Section::Connections => text.nav_connections(),
        Section::Logs => text.nav_logs(),
        Section::Settings => text.nav_settings(),
    }
}

fn section_icon(section: Section) -> Icon {
    match section {
        Section::Activity => Icon::Activity,
        Section::Nodes => Icon::Nodes,
        Section::Profiles => Icon::Profiles,
        Section::Rules => Icon::Rules,
        Section::Connections => Icon::Connections,
        Section::Logs => Icon::Logs,
        Section::Settings => Icon::Settings,
    }
}

/// A layer's toolbar toggle. A switch shows what it asks for at once; one
/// that runs long shows as pending, and the other controls wait dimmed.
fn capture_toggle(state: &State, layer: CaptureLayer) -> CaptureToggle {
    let text = state.text();
    let status = state.capture.as_ref();
    let (label, supported) = match layer {
        CaptureLayer::SystemProxy => (
            text.system_proxy(),
            status.is_none_or(|status| status.support.system_proxy),
        ),
        CaptureLayer::Tun => (text.tun(), status.is_none_or(|status| status.support.tun)),
    };
    let on = state.layer_on(layer);
    let interruption = (layer == CaptureLayer::Tun)
        .then(|| status.and_then(|status| status.tun_interruption.clone()))
        .flatten();
    let preparing = status
        .and_then(|status| status.preparation.as_ref())
        .filter(|preparing| preparing.layers.get(layer));
    let needs_profile = !on && state.needs_profile();
    CaptureToggle {
        label: label.into(),
        on,
        state: if state.transition_slow() && state.changing_layers().get(layer) {
            ToggleState::Pending
        } else if preparing.is_some_and(|preparing| preparing.error.is_some()) {
            ToggleState::Warning
        } else if preparing.is_some() {
            ToggleState::Pending
        } else if interruption.is_some() {
            ToggleState::Warning
        } else {
            ToggleState::Idle
        },
        enabled: supported && !needs_profile && !state.transition_slow(),
        tooltip: preparing
            .map(|preparing| {
                preparing
                    .error
                    .clone()
                    .unwrap_or_else(|| text.preparing_rules().into())
            })
            .or_else(|| {
                interruption
                    .map(|reason| text.tun_interrupted_tooltip(&reason))
                    .or_else(|| needs_profile.then(|| text.needs_profile().into()))
            }),
    }
}

fn toolbar(state: &State) -> ToolbarView {
    let text = state.text();
    let profile = state.active_profile.ready().and_then(Option::as_ref);
    let system_proxy_supported = state
        .capture
        .as_ref()
        .is_none_or(|status| status.support.system_proxy);
    ToolbarView {
        system_proxy: system_proxy_supported
            .then(|| capture_toggle(state, CaptureLayer::SystemProxy)),
        tun: capture_toggle(state, CaptureLayer::Tun),
        policy: PolicyControl {
            labels: [
                text.mode_rule().into(),
                text.mode_global().into(),
                text.mode_direct().into(),
            ],
            selected: profile.map(|profile| match state.mode(profile) {
                TrafficPolicyMode::Rule => 0,
                TrafficPolicyMode::Global => 1,
                TrafficPolicyMode::Direct => 2,
            }),
            enabled: profile.is_some() && !state.transition_slow() && !state.downloading_rules(),
            tooltip: state.needs_profile().then(|| text.needs_profile().into()),
        },
        messages: MessagesButton {
            label: text.messages().into(),
            count: state.messages.len(),
            level: state.messages.highest_unread(),
            preview: state
                .messages
                .newest_unread()
                .map(|entry| preview(entry, text)),
            open: state.drawer_open,
        },
    }
}

/// The newest unread message as the capsule shows it: its title and
/// the first line of its detail, the whole of it in its help.
fn preview(entry: &Message, text: Text) -> MessagePreview {
    let detail = entry
        .detail
        .as_deref()
        .map(str::trim)
        .filter(|detail| !detail.is_empty());
    let first_line =
        detail.and_then(|detail| detail.lines().map(str::trim).find(|line| !line.is_empty()));
    MessagePreview {
        level: entry.level,
        title: entry.title.clone(),
        text: first_line.map_or_else(
            || entry.title.clone(),
            |line| text.message_line(&entry.title, line),
        ),
        help: detail.map_or_else(
            || entry.title.clone(),
            |detail| format!("{}\n{detail}", entry.title),
        ),
    }
}

pub fn source_label(source: Source, text: Text) -> &'static str {
    match source {
        Source::Tun => text.source_tun(),
        Source::SystemProxy => text.source_system_proxy(),
        Source::Configuration => text.source_configuration(),
        Source::Connections => text.source_connections(),
        Source::Listener => text.source_listener(),
        Source::Settings => text.source_settings(),
        Source::Geodata => text.source_geodata(),
        Source::Rules => text.source_rules(),
        Source::Update => text.source_update(),
    }
}

fn level_tone(level: Level) -> Tone {
    match level {
        Level::Info => Tone::Accent,
        Level::Warning => Tone::Warning,
        Level::Error => Tone::Danger,
    }
}

fn message(entry: &Message, text: Text) -> Node {
    let mut when = format::time_of_day(entry.at_unix);
    if entry.count > 1 {
        when = format!("{when} ×{}", entry.count);
    }
    let mut children = vec![
        row(
            8.0,
            vec![
                badge(source_label(entry.source, text), level_tone(entry.level)),
                spacer(),
                caption(when),
            ],
        ),
        text_node(&entry.title),
    ];
    if let Some(detail) = &entry.detail {
        children.push(paragraph(detail.clone(), Tone::Muted));
    }
    column(6.0, children).key(entry.id.to_string())
}

fn text_node(value: &str) -> Node {
    let mut node = text(value, TextStyle::Body, Tone::Default);
    if let crate::node::Kind::Text(text) = &mut node.kind {
        text.single_line = false;
    }
    node
}

/// How tall the message panel's placeholder stands while there are none.
const EMPTY_DRAWER_HEIGHT: f64 = 96.0;

/// The message panel under the capsule, which names it: a count and the
/// clear button over the list, as tall as the messages up to the panel's
/// cap, then scrolling.
fn drawer(state: &State) -> Node {
    let text = state.text();
    let count = match state.messages.len() {
        0 => String::new(),
        count => text.message_count(count),
    };
    let header = row(
        8.0,
        vec![
            caption(count),
            spacer(),
            button(text.messages_clear(), ButtonStyle::Plain)
                .enabled(!state.messages.is_empty())
                .on_press(Msg::ClearMessages),
        ],
    );
    let body = if state.messages.is_empty() {
        placeholder(text.messages_empty(), None).height(EMPTY_DRAWER_HEIGHT)
    } else {
        scroll(column(
            16.0,
            state
                .messages
                .entries()
                .map(|entry| message(entry, text))
                .collect(),
        ))
        .grow()
    };
    column(12.0, vec![header, body])
}

pub fn views(state: &State) -> Views {
    let text = state.text();
    Views {
        main: MainView {
            title: section_label(state.section, text).into(),
            nav: Section::ALL
                .into_iter()
                .map(|section| NavItem {
                    section,
                    label: section_label(section, text).into(),
                    icon: section_icon(section),
                })
                .collect(),
            section: state.section,
            toolbar: toolbar(state),
            drawer_open: state.drawer_open,
        },
        content: pages::view(state),
        drawer: drawer(state),
        dialog: state.dialog.as_ref().map(|dialog| match dialog {
            Dialog::AddProfile(draft) => pages::profiles::add_dialog(state, draft),
            Dialog::Rule(draft) => pages::rules::dialog(state, draft),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Kind;
    use crate::state::{Change, Remote, Running};
    use crate::text::Lang;
    use egrio_desktop::models::SavedProfileSummary;
    use egrio_desktop::operations::capture::CaptureStatus;
    use egrio_platform::{CaptureLayers, CaptureSupport};

    /// A Rule mode profile with both layers off.
    fn with_profile() -> State {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(Some(SavedProfileSummary {
            id: "p".into(),
            name: "Profile".into(),
            revision: "1".into(),
            source_revision: "s1".into(),
            traffic_policy_mode: TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: 0,
        }));
        state.capture = Some(CaptureStatus {
            layers: CaptureLayers::NONE,
            support: CaptureSupport {
                system_proxy: true,
                tun: true,
            },
            tun_environment_ready: true,
            tun_interruption: None,
            preparation: None,
        });
        state
    }

    fn running(state: &mut State, change: Change, slow: bool) {
        state.change = Some(Running {
            change,
            id: 1,
            slow,
        });
    }

    #[test]
    fn rule_download_locks_selections_but_keeps_the_capture_stop_available() {
        let mut state = with_profile();
        state.capture.as_mut().unwrap().preparation =
            Some(egrio_desktop::runtime::CorePreparation {
                layers: CaptureLayers::NONE.with(CaptureLayer::Tun, true),
                error: None,
            });
        let preparing = toolbar(&state);
        assert!(preparing.tun.on && preparing.tun.enabled);
        assert_eq!(preparing.tun.state, ToggleState::Pending);
        assert!(!preparing.policy.enabled);
        assert!(state.downloading_rules());
        state
            .capture
            .as_mut()
            .unwrap()
            .preparation
            .as_mut()
            .unwrap()
            .error = Some("download failed".into());
        let failed = toolbar(&state);
        assert_eq!(failed.tun.state, ToggleState::Warning);
        assert!(
            failed.policy.enabled,
            "selection can change after the download has ended"
        );
    }

    #[test]
    fn a_switch_shows_what_it_asks_for_and_only_a_long_one_makes_the_others_wait() {
        let mut state = with_profile();
        let tun_on = Change::Capture {
            layer: CaptureLayer::Tun,
            enabled: true,
        };
        running(&mut state, tun_on.clone(), false);
        let quick = toolbar(&state);
        assert!(quick.tun.on, "the toggle shows the layer it turns on");
        assert_eq!(quick.tun.state, ToggleState::Idle);
        assert!(
            quick.tun.enabled && quick.policy.enabled,
            "nothing dims at once"
        );

        running(&mut state, tun_on, true);
        let slow = toolbar(&state);
        assert!(slow.tun.on);
        assert_eq!(slow.tun.state, ToggleState::Pending);
        assert!(!slow.policy.enabled && !slow.system_proxy.is_some_and(|toggle| toggle.enabled));
    }

    #[test]
    fn the_layers_turned_back_on_at_launch_show_on_while_they_start() {
        let mut state = with_profile();
        running(
            &mut state,
            Change::Restore(CaptureLayers {
                system_proxy: false,
                tun: true,
            }),
            true,
        );
        let toolbar = toolbar(&state);
        assert!(toolbar.tun.on);
        assert_eq!(toolbar.tun.state, ToggleState::Pending);
        let system_proxy = toolbar.system_proxy.expect("macOS has a system proxy");
        assert!(!system_proxy.on);
        assert_eq!(system_proxy.state, ToggleState::Idle);
    }

    #[test]
    fn the_mode_control_shows_the_mode_it_changes_to() {
        let mut state = with_profile();
        running(&mut state, Change::Mode(TrafficPolicyMode::Global), false);
        assert_eq!(toolbar(&state).policy.selected, Some(1));
        state.change = None;
        assert_eq!(toolbar(&state).policy.selected, Some(0));
    }

    #[test]
    fn the_title_bar_previews_the_newest_unread_message_until_it_is_read() {
        let mut state = with_profile();
        assert_eq!(toolbar(&state).messages.preview, None);
        state.messages.push(
            Level::Info,
            Source::Geodata,
            "GEODATA updated".into(),
            None,
            1,
        );
        state.messages.push(
            Level::Error,
            Source::Tun,
            "Couldn't turn on TUN Mode".into(),
            Some("\nthe service didn't answer\nretry later".into()),
            2,
        );
        let preview = toolbar(&state).messages.preview.expect("unread messages");
        assert_eq!(preview.level, Level::Error);
        assert_eq!(preview.title, "Couldn't turn on TUN Mode");
        assert_eq!(
            preview.text,
            "Couldn't turn on TUN Mode: the service didn't answer"
        );
        assert_eq!(
            preview.help,
            "Couldn't turn on TUN Mode\nthe service didn't answer\nretry later"
        );
        state.messages.mark_read();
        assert_eq!(toolbar(&state).messages.preview, None);
    }

    #[test]
    fn an_empty_drawer_shows_its_placeholder_and_cannot_be_cleared() {
        let tree = drawer(&State::new(Lang::En));
        let Some(Kind::Button(clear)) = tree.children[0].children.last().map(|node| &node.kind)
        else {
            panic!("the header ends with the clear button");
        };
        assert!(!clear.enabled);
        assert!(matches!(tree.children[1].kind, Kind::Placeholder(_)));
    }

    #[test]
    fn messages_scroll_newest_first_each_under_its_own_key() {
        let mut state = State::new(Lang::En);
        state
            .messages
            .push(Level::Info, Source::Tun, "first".into(), None, 1);
        state.messages.push(
            Level::Error,
            Source::Configuration,
            "second".into(),
            Some("why".into()),
            2,
        );
        let tree = drawer(&state);
        assert!(
            matches!(&tree.children[0].children[0].kind, Kind::Text(count) if count.text == "2 messages")
        );
        let list = &tree.children[1];
        assert!(
            matches!(list.kind, Kind::Scroll) && list.attrs.grow,
            "the list takes the drawer's height and scrolls"
        );
        let keys: Vec<_> = list.children[0]
            .children
            .iter()
            .map(|entry| entry.key.as_deref())
            .collect();
        assert_eq!(keys, [Some("2"), Some("1")]);
    }
}
