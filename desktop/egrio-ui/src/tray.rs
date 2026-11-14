//! The tray's menu, described once from the state: the main window, the
//! outbound mode, the active profile's policy groups, the capture layers
//! and quit. Each group is a submenu: its latency test, then its members
//! with their latencies, the hidden ones too. A Select group's members can
//! be chosen and its title names the choice; the other groups' members are
//! listed. While a change runs, the menu waits like the window's controls.
//!
//! A node can appear in many groups. Its display state is computed once
//! for all of them; each member carries only its name and states.

use egrio_core::TrafficPolicyMode;
use egrio_desktop::profile_store::{SavedPolicyGroup, SavedProxyNode};
use egrio_platform::CaptureLayer;

use std::collections::HashMap;
use std::sync::Arc;

use crate::backend::{TrayAction, TrayGroup, TrayItem, TrayLatency, TrayMember, TrayView};
use crate::latency::{nodes_by_name, GroupNodes, Probe, ProbeTarget};
use crate::pages::nodes::{member_in_use, Inventory};
use crate::state::State;
use crate::text::Text;

fn command(label: &str, action: TrayAction, enabled: bool, checked: bool) -> TrayItem {
    TrayItem::Command {
        label: label.into(),
        action,
        enabled,
        checked,
    }
}

/// What a node shows wherever it is a member.
#[derive(Clone, Copy)]
struct Shown {
    unsupported: bool,
    /// Whether the node is ever tested.
    tested: bool,
    latency: Option<TrayLatency>,
}

/// The profile's nodes and what each shows.
struct Nodes<'a> {
    by_name: HashMap<&'a str, &'a SavedProxyNode>,
    shown: HashMap<&'a str, Shown>,
    /// Whether any node's test is running.
    testing: bool,
}

impl<'a> Nodes<'a> {
    fn of(state: &State, inventory: &'a Inventory, text: Text) -> Self {
        let profile_id = &inventory.inventory.profile_id;
        let shown: HashMap<&str, Shown> = inventory
            .inventory
            .proxies
            .iter()
            .map(|node| {
                let target = ProbeTarget::of(profile_id, node);
                let latency = target
                    .as_ref()
                    .and_then(|target| state.latency.get(target))
                    .map(|probe| match probe {
                        Probe::Testing => TrayLatency::Testing,
                        Probe::Ready(milliseconds) => TrayLatency::Ready(*milliseconds),
                        Probe::Failed(_) => TrayLatency::Failed(text.latency_timeout()),
                    });
                let shown = Shown {
                    unsupported: node.unsupported.is_some(),
                    tested: target.is_some(),
                    latency,
                };
                (node.name.as_str(), shown)
            })
            .collect();
        Self {
            by_name: nodes_by_name(&inventory.inventory),
            testing: shown
                .values()
                .any(|shown| shown.latency == Some(TrayLatency::Testing)),
            shown,
        }
    }
}

fn group_menu(
    state: &State,
    inventory: &Inventory,
    nodes: &Nodes<'_>,
    group: &SavedPolicyGroup,
    busy: bool,
) -> TrayItem {
    let text = state.text();
    let selectable = group.kind == "select";
    let in_use = member_in_use(state, inventory, group);
    let reached = || GroupNodes::of(&inventory.inventory, &nodes.by_name, group);
    let shown = |node: &SavedProxyNode| nodes.shown.get(node.name.as_str());
    // The walk through the nested groups is taken only while a test runs.
    let testing = nodes.testing
        && reached().any(|node| {
            shown(node).is_some_and(|shown| shown.latency == Some(TrayLatency::Testing))
        });
    let tests = reached().any(|node| shown(node).is_some_and(|shown| shown.tested));
    let members = group
        .members
        .iter()
        .map(|member| {
            let shown = nodes.shown.get(member.as_str());
            let unsupported = shown.is_some_and(|shown| shown.unsupported);
            TrayMember {
                name: member.clone(),
                badge: unsupported.then(|| text.unsupported_badge()),
                enabled: selectable && !unsupported,
                checked: in_use == Some(member.as_str()),
                latency: shown.and_then(|shown| shown.latency),
            }
        })
        .collect();
    TrayItem::Group(Arc::new(TrayGroup {
        label: match in_use {
            Some(member) => format!("{} · {member}", group.name),
            None => group.name.clone(),
        },
        enabled: !busy,
        profile_id: inventory.inventory.profile_id.clone(),
        group_id: group.id.clone(),
        test_label: if testing {
            text.tray_latency_testing()
        } else {
            text.tray_latency_test()
        },
        test_enabled: !testing && tests,
        members,
    }))
}

pub fn view(state: &State) -> TrayView {
    let text = state.text();
    let profile = state.active_profile.ready().and_then(Option::as_ref);
    let busy = state.transition_pending();
    let selection_busy = busy || state.downloading_rules();
    let mut items = vec![
        command(text.tray_show(), TrayAction::ShowMainWindow, true, false),
        TrayItem::Separator,
    ];
    let modes = profile
        .map(|profile| {
            [
                (TrafficPolicyMode::Rule, text.mode_rule()),
                (TrafficPolicyMode::Global, text.mode_global()),
                (TrafficPolicyMode::Direct, text.mode_direct()),
            ]
            .into_iter()
            .map(|(mode, label)| {
                command(
                    label,
                    TrayAction::SetMode {
                        profile_id: profile.id.clone(),
                        mode,
                    },
                    true,
                    state.mode(profile) == mode,
                )
            })
            .collect()
        })
        .unwrap_or_default();
    items.push(TrayItem::Submenu {
        label: text.tray_outbound_mode().into(),
        enabled: !selection_busy && profile.is_some(),
        items: modes,
    });
    items.push(TrayItem::Separator);
    let inventory = profile.and_then(|profile| {
        state
            .nodes
            .inventory()
            .ready()
            .filter(|inventory| inventory.inventory.profile_id == profile.id)
    });
    if let Some(inventory) = inventory.filter(|inventory| !inventory.inventory.groups.is_empty()) {
        let nodes = Nodes::of(state, inventory, text);
        for group in &inventory.inventory.groups {
            items.push(group_menu(state, inventory, &nodes, group, selection_busy));
        }
        items.push(TrayItem::Separator);
    }
    let status = state.capture.as_ref();
    for (layer, label) in [
        (CaptureLayer::SystemProxy, text.system_proxy()),
        (CaptureLayer::Tun, text.tun()),
    ] {
        let supported = match (layer, status) {
            (CaptureLayer::SystemProxy, Some(status)) => status.support.system_proxy,
            (CaptureLayer::Tun, Some(status)) => status.support.tun,
            (_, None) => true,
        };
        let on = state.layer_on(layer);
        if !supported {
            continue;
        }
        // A layer can always be turned off, but on only with a profile.
        let enabled = !busy && (on || profile.is_some());
        items.push(command(
            label,
            TrayAction::ToggleCapture(layer),
            enabled,
            on,
        ));
    }
    items.push(TrayItem::Separator);
    items.push(command(text.tray_quit(), TrayAction::Quit, true, false));
    TrayView {
        tooltip: "Egrio".into(),
        connected: status.is_some_and(|status| status.layers.any()),
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::tests::{group, inventory, node};
    use crate::pages::nodes::Inventory;
    use crate::state::Remote;
    use crate::text::Lang;
    use egrio_desktop::models::SavedProfileSummary;

    fn state() -> State {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(Some(SavedProfileSummary {
            id: "p".into(),
            name: "Profile".into(),
            revision: "1".into(),
            source_revision: "s1".into(),
            traffic_policy_mode: TrafficPolicyMode::Global,
            global_outbound: None,
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: 0,
        }));
        let mut hidden = node("Hidden");
        hidden.hidden = true;
        let mut vmess = node("VMess");
        vmess.unsupported = Some("no".into());
        state.nodes.set_inventory(Remote::Ready(Inventory {
            source_revision: "s1".into(),
            inventory: inventory(
                vec![node("HK"), node("TW"), hidden, vmess],
                vec![
                    group("Proxy", "select", &["HK", "TW", "Hidden", "VMess"]),
                    group("Auto", "url-test", &["HK", "TW"]),
                ],
            ),
            selections: HashMap::from([("group-Proxy".to_string(), "TW".to_string())]),
            automatic: HashMap::from([("group-Auto".to_string(), "HK".to_string())]),
        }));
        state
    }

    fn submenu<'a>(view: &'a TrayView, label: &str) -> &'a [TrayItem] {
        view.items
            .iter()
            .find_map(|item| match item {
                TrayItem::Submenu {
                    label: title,
                    items,
                    ..
                } if title.starts_with(label) => Some(items.as_slice()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no submenu {label}"))
    }

    fn group_of<'a>(view: &'a TrayView, name: &str) -> &'a TrayGroup {
        view.items
            .iter()
            .find_map(|item| match item {
                TrayItem::Group(group) if group.label.starts_with(name) => Some(group.as_ref()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no group {name}"))
    }

    /// Each member's label, whether it can be chosen and whether it is
    /// marked.
    fn members(group: &TrayGroup) -> Vec<(String, bool, bool)> {
        group
            .members
            .iter()
            .map(|member| (member.label().into_owned(), member.enabled, member.checked))
            .collect()
    }

    #[test]
    fn the_menu_runs_from_the_window_to_quit_with_the_profiles_groups_between() {
        let view = view(&state());
        let titles: Vec<String> = view
            .items
            .iter()
            .map(|item| match item {
                TrayItem::Command { label, .. } | TrayItem::Submenu { label, .. } => label.clone(),
                TrayItem::Group(group) => group.label.clone(),
                TrayItem::Separator => "-".into(),
            })
            .collect();
        assert_eq!(
            titles,
            [
                "Show Main Window",
                "-",
                "Outbound Mode",
                "-",
                "Proxy · TW",
                "Auto · HK",
                "-",
                "System Proxy",
                "TUN Mode",
                "-",
                "Quit"
            ]
        );
        let modes = submenu(&view, "Outbound Mode");
        assert!(matches!(
            &modes[1],
            TrayItem::Command {
                checked: true,
                action: TrayAction::SetMode {
                    mode: TrafficPolicyMode::Global,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn a_select_groups_members_can_be_chosen_and_the_others_are_listed() {
        let state = state();
        let view = view(&state);
        let proxy = group_of(&view, "Proxy");
        assert_eq!(
            members(proxy),
            [
                ("HK".to_string(), true, false),
                ("TW".to_string(), true, true),
                ("Hidden".to_string(), true, false),
                ("VMess · Unsupported".to_string(), false, false)
            ]
        );
        // A choice names the profile, the group and the member as the
        // profile writes it, whatever its row adds to the name.
        assert_eq!(
            proxy.select(&proxy.members[3]),
            TrayAction::SelectMember {
                profile_id: "p".into(),
                group_id: "group-Proxy".into(),
                member: "VMess".into(),
            }
        );
        assert_eq!(
            proxy.test(),
            TrayAction::TestGroup {
                profile_id: "p".into(),
                group_id: "group-Proxy".into(),
            }
        );
        // An automatic group's members cannot be chosen; the one the Core
        // reports in use carries the mark.
        assert_eq!(
            members(group_of(&view, "Auto")),
            [
                ("HK".to_string(), false, true),
                ("TW".to_string(), false, false)
            ]
        );
    }

    #[test]
    fn a_test_shows_in_its_group_and_its_members_latencies() {
        let mut state = state();
        let idle = view(&state);
        let proxy = group_of(&idle, "Proxy");
        assert_eq!(
            (proxy.test_label, proxy.test_enabled),
            ("Test Latency", true)
        );
        let inventory = &state.nodes.inventory().ready().unwrap().inventory;
        let hk = ProbeTarget::of("p", &inventory.proxies[0]).unwrap();
        let tw = ProbeTarget::of("p", &inventory.proxies[1]).unwrap();
        state.latency.request([hk.clone(), tw.clone()]);
        state.latency.start();
        state.latency.finish(hk, Ok(42));
        let testing = view(&state);
        let proxy = group_of(&testing, "Proxy");
        assert_eq!(
            (proxy.test_label, proxy.test_enabled),
            ("Testing Latency…", false)
        );
        let latencies: Vec<Option<String>> = proxy
            .members
            .iter()
            .map(|member| member.latency.map(|latency| latency.text().into_owned()))
            .collect();
        assert_eq!(
            latencies,
            [Some("42 ms".to_string()), Some("…".to_string()), None, None]
        );
        // The test ends for every group the node is in.
        state.latency.finish(tw, Err("no answer".into()));
        let done = view(&state);
        for name in ["Proxy", "Auto"] {
            let group = group_of(&done, name);
            assert_eq!(
                (group.test_label, group.test_enabled),
                ("Test Latency", true)
            );
            assert_eq!(
                group.members[1].latency,
                Some(TrayLatency::Failed("Timeout"))
            );
        }
    }

    #[test]
    fn a_group_is_tested_through_the_groups_it_lists_and_not_without_a_node() {
        let mut state = state();
        let mut hidden = node("Hidden");
        hidden.hidden = true;
        state.nodes.set_inventory(Remote::Ready(Inventory {
            source_revision: "s1".into(),
            inventory: inventory(
                vec![node("HK"), hidden],
                vec![
                    group("Proxy", "select", &["Auto", "DIRECT"]),
                    group("Auto", "url-test", &["HK"]),
                    group("Quiet", "select", &["Hidden", "DIRECT", "REJECT"]),
                ],
            ),
            selections: HashMap::new(),
            automatic: HashMap::new(),
        }));
        let idle = view(&state);
        assert!(group_of(&idle, "Proxy").test_enabled);
        // Nothing the group reaches is ever tested.
        assert!(!group_of(&idle, "Quiet").test_enabled);
        let inventory = &state.nodes.inventory().ready().unwrap().inventory;
        let hk = ProbeTarget::of("p", &inventory.proxies[0]).unwrap();
        state.latency.request([hk]);
        let testing = view(&state);
        // The node is a member of Auto only, which Proxy lists.
        for name in ["Proxy", "Auto"] {
            let group = group_of(&testing, name);
            assert_eq!(
                (group.test_label, group.test_enabled),
                ("Testing Latency…", false)
            );
        }
        assert_eq!(group_of(&testing, "Quiet").test_label, "Test Latency");
    }

    #[test]
    fn the_menu_as_text_lists_each_group_under_its_title_and_finds_a_choice_by_title() {
        let mut state = state();
        let inventory = &state.nodes.inventory().ready().unwrap().inventory;
        let hk = ProbeTarget::of("p", &inventory.proxies[0]).unwrap();
        state.latency.request([hk.clone()]);
        state.latency.start();
        state.latency.finish(hk, Ok(42));
        let view = view(&state);
        let lines = view.lines();
        let proxy = lines
            .iter()
            .position(|line| line == "Proxy · TW ▸")
            .expect("the group's line");
        assert_eq!(
            lines[proxy + 1..proxy + 7],
            [
                "  Test Latency",
                "  —",
                "  HK [42 ms]",
                "  ✓ TW",
                "  Hidden",
                "  VMess · Unsupported (disabled)"
            ]
        );
        assert_eq!(
            lines[..proxy],
            [
                "Show Main Window",
                "—",
                "Outbound Mode ▸",
                "  Rule",
                "  ✓ Global",
                "  Direct",
                "—"
            ]
        );
        // A title names the first item that can be chosen: a command, a
        // group's test or a member of a group.
        assert_eq!(view.choice("Quit"), Some(TrayAction::Quit));
        assert_eq!(
            view.choice("Test Latency"),
            Some(TrayAction::TestGroup {
                profile_id: "p".into(),
                group_id: "group-Proxy".into(),
            })
        );
        assert_eq!(
            view.choice("HK"),
            Some(TrayAction::SelectMember {
                profile_id: "p".into(),
                group_id: "group-Proxy".into(),
                member: "HK".into(),
            })
        );
        // Neither a member that cannot be used nor a submenu is chosen.
        assert_eq!(view.choice("VMess · Unsupported"), None);
        assert_eq!(view.choice("Outbound Mode"), None);
    }

    #[test]
    fn without_a_profile_the_mode_waits_and_a_layer_can_only_be_turned_off() {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(None);
        let view = view(&state);
        assert!(matches!(
            &view.items[2],
            TrayItem::Submenu { enabled: false, items, .. } if items.is_empty()
        ));
        assert!(view.items.iter().any(|item| matches!(
            item,
            TrayItem::Command {
                action: TrayAction::ToggleCapture(CaptureLayer::Tun),
                enabled: false,
                ..
            }
        )));
    }
}
