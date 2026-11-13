//! The tray: a StatusNotifierItem with its menu over dbusmenu on the session
//! bus ("StatusNotifierItem" in the freedesktop specifications), served by
//! ksni on the desktop tokio runtime. GNOME shows such items through the
//! AppIndicator extension, which Ubuntu enables; libappindicator is built on
//! GTK 3 and cannot load in a GTK 4 process. A left click opens the menu.
//!
//! The menu is described again only when something it shows changed; ksni
//! then sends just the changed items' properties while the menu keeps its
//! structure, and a new layout otherwise. dbusmenu has no column for a
//! member's latency, so it follows the member's name, and the host closes
//! the menu when an item is chosen, the group's latency test too.

use std::sync::Arc;

use egrio_ui::backend::{TrayAction, TrayGroup, TrayItem, TrayView};
use ksni::menu::{CheckmarkItem, StandardItem, SubMenu};
use ksni::{MenuItem, TrayMethods};

/// The same ready-sized crystal artwork as the Windows notification area;
/// the host picks the image that fits its panel and display scale.
const ICONS: [&[u8]; 7] = [
    include_bytes!("../../icons/tray-on-16x16.png"),
    include_bytes!("../../icons/tray-on-20x20.png"),
    include_bytes!("../../icons/tray-on-24x24.png"),
    include_bytes!("../../icons/tray-on-32x32.png"),
    include_bytes!("../../icons/tray-on-48x48.png"),
    include_bytes!("../../icons/tray-on-64x64.png"),
    include_bytes!("../../icons/tray-on-128x128.png"),
];
const ICONS_OFF: [&[u8]; 7] = [
    include_bytes!("../../icons/tray-off-16x16.png"),
    include_bytes!("../../icons/tray-off-20x20.png"),
    include_bytes!("../../icons/tray-off-24x24.png"),
    include_bytes!("../../icons/tray-off-32x32.png"),
    include_bytes!("../../icons/tray-off-48x48.png"),
    include_bytes!("../../icons/tray-off-64x64.png"),
    include_bytes!("../../icons/tray-off-128x128.png"),
];

pub struct Tray {
    sender: tokio::sync::mpsc::UnboundedSender<TrayView>,
}

struct Item {
    view: TrayView,
    icons: Vec<ksni::Icon>,
    icons_off: Vec<ksni::Icon>,
}

impl ksni::Tray for Item {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "egrio".into()
    }

    fn title(&self) -> String {
        "Egrio".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        if self.view.connected {
            self.icons.clone()
        } else {
            self.icons_off.clone()
        }
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.view.tooltip.clone(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        items(&self.view.items)
    }
}

impl Tray {
    pub fn new(view: &TrayView) -> Self {
        let icons = ICONS.iter().filter_map(|png| pixmap(png)).collect();
        let icons_off = ICONS_OFF.iter().filter_map(|png| pixmap(png)).collect();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<TrayView>();
        let item = Item {
            view: view.clone(),
            icons,
            icons_off,
        };
        egrio_desktop::async_runtime::spawn(async move {
            // At login the app may start before the shell shows trays: the
            // item waits for the host instead of failing.
            let handle = match item.assume_sni_available(true).spawn().await {
                Ok(handle) => handle,
                Err(error) => {
                    log::warn!("the tray is not shown: {error}");
                    return;
                }
            };
            while let Some(view) = receiver.recv().await {
                handle.update(|item| item.view = view).await;
            }
            handle.shutdown().await;
        });
        Self { sender }
    }

    pub fn update(&self, view: &TrayView) {
        let _ = self.sender.send(view.clone());
    }
}

/// dbusmenu reads `_` as the mark of an access key and `__` as an underscore.
fn label(text: &str) -> String {
    text.replace('_', "__")
}

/// Hands what a chosen item does to the main thread, with the activation
/// token the host gave for the click, which lets a window come forward on
/// Wayland. `action` names it when the item is chosen: a member of a group
/// is one of thousands and holds no action of its own.
fn choose(
    action: impl Fn() -> Option<TrayAction> + Send + 'static,
) -> Box<dyn Fn(&mut Item) + Send> {
    Box::new(move |_| {
        let Some(action) = action() else { return };
        let token = ksni::current_xdg_activation_token();
        super::on_main(move || super::tray_event(action, token));
    })
}

/// Choices that hold a state show a check mark when they are on.
fn checkable(action: &TrayAction) -> bool {
    matches!(
        action,
        TrayAction::SetMode { .. } | TrayAction::ToggleCapture(_)
    )
}

fn items(menu: &[TrayItem]) -> Vec<MenuItem<Item>> {
    menu.iter()
        .map(|item| match item {
            TrayItem::Command {
                label: text,
                action,
                enabled,
                checked,
            } => {
                let chosen = action.clone();
                let activate = choose(move || Some(chosen.clone()));
                if checkable(action) {
                    CheckmarkItem {
                        label: label(text),
                        enabled: *enabled,
                        checked: *checked,
                        activate,
                        ..Default::default()
                    }
                    .into()
                } else {
                    StandardItem {
                        label: label(text),
                        enabled: *enabled,
                        activate,
                        ..Default::default()
                    }
                    .into()
                }
            }
            TrayItem::Submenu {
                label: text,
                enabled,
                items: inner,
            } => SubMenu {
                label: label(text),
                enabled: *enabled,
                submenu: items(inner),
                ..Default::default()
            }
            .into(),
            TrayItem::Group(group) => SubMenu {
                label: label(&group.label),
                enabled: group.enabled,
                submenu: group_items(group),
                ..Default::default()
            }
            .into(),
            TrayItem::Separator => MenuItem::Separator,
        })
        .collect()
}

/// A group's submenu: its latency test, a separator and its members, each
/// with its latency after its name.
fn group_items(group: &Arc<TrayGroup>) -> Vec<MenuItem<Item>> {
    let tested = group.clone();
    let test = StandardItem {
        label: label(group.test_label),
        enabled: group.test_enabled,
        activate: choose(move || Some(tested.test())),
        ..Default::default()
    };
    let members = group.members.iter().enumerate().map(|(index, member)| {
        let chosen = group.clone();
        CheckmarkItem {
            label: label(&match member.latency {
                Some(latency) => format!("{}    {}", member.label(), latency.text()),
                None => member.label().into_owned(),
            }),
            enabled: member.enabled,
            checked: member.checked,
            activate: choose(move || {
                let member = chosen.members.get(index)?;
                Some(chosen.select(member))
            }),
            ..Default::default()
        }
        .into()
    });
    [test.into(), MenuItem::Separator]
        .into_iter()
        .chain(members)
        .collect()
}

/// A PNG as the ARGB32 pixels in network byte order that StatusNotifierItem
/// takes.
fn pixmap(png: &'static [u8]) -> Option<ksni::Icon> {
    let pixbuf = gtk::gdk_pixbuf::Pixbuf::from_read(std::io::Cursor::new(png))
        .map_err(|error| log::warn!("decode the tray icon: {error}"))
        .ok()?;
    let pixbuf = if pixbuf.has_alpha() {
        pixbuf
    } else {
        pixbuf.add_alpha(false, 0, 0, 0).ok()?
    };
    let (width, height) = (pixbuf.width(), pixbuf.height());
    let stride = pixbuf.rowstride() as usize;
    let pixels = pixbuf.read_pixel_bytes();
    let mut data = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height as usize {
        for x in 0..width as usize {
            let at = y * stride + x * 4;
            let [red, green, blue, alpha] =
                [pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]];
            data.extend_from_slice(&[alpha, red, green, blue]);
        }
    }
    Some(ksni::Icon {
        width,
        height,
        data,
    })
}

#[cfg(test)]
mod tests {
    use egrio_ui::backend::{TrayLatency, TrayMember};

    use super::*;

    /// An item as a host reads it: its label, whether it can be chosen and
    /// its check mark; a submenu's items in a list of their own.
    #[derive(Debug, PartialEq)]
    enum Shown {
        Item(String, bool),
        Check(String, bool, bool),
        Menu(String, bool, Vec<Shown>),
        Separator,
    }

    fn shown(items: &[MenuItem<Item>]) -> Vec<Shown> {
        items
            .iter()
            .map(|item| match item {
                MenuItem::Standard(item) => Shown::Item(item.label.clone(), item.enabled),
                MenuItem::Checkmark(item) => {
                    Shown::Check(item.label.clone(), item.enabled, item.checked)
                }
                MenuItem::SubMenu(menu) => {
                    Shown::Menu(menu.label.clone(), menu.enabled, shown(&menu.submenu))
                }
                MenuItem::Separator => Shown::Separator,
                other => panic!("{other:?} in the tray's menu"),
            })
            .collect()
    }

    #[test]
    fn a_groups_submenu_is_its_test_a_separator_and_its_members() {
        let member = |name: &str, enabled: bool, checked, latency| TrayMember {
            name: name.into(),
            badge: (!enabled).then_some("Unsupported"),
            enabled,
            checked,
            latency,
        };
        let group = Arc::new(TrayGroup {
            label: "Proxy · TW".into(),
            enabled: true,
            profile_id: "p".into(),
            group_id: "group-Proxy".into(),
            test_label: "Test Latency",
            test_enabled: false,
            members: vec![
                member("H_K", true, false, Some(TrayLatency::Ready(42))),
                member("TW", true, true, None),
                member("VMess", false, false, None),
            ],
        });
        let menu = items(&[
            TrayItem::Command {
                label: "Quit".into(),
                action: TrayAction::Quit,
                enabled: true,
                checked: false,
            },
            TrayItem::Separator,
            TrayItem::Group(group),
        ]);
        let check = |label: &str, enabled, checked| Shown::Check(label.into(), enabled, checked);
        assert_eq!(
            shown(&menu),
            [
                Shown::Item("Quit".into(), true),
                Shown::Separator,
                Shown::Menu(
                    "Proxy · TW".into(),
                    true,
                    vec![
                        // A test that runs cannot be chosen again.
                        Shown::Item("Test Latency".into(), false),
                        Shown::Separator,
                        // An underscore is doubled, and the latency follows
                        // the name.
                        check("H__K    42 ms", true, false),
                        check("TW", true, true),
                        check("VMess · Unsupported", false, false),
                    ]
                )
            ]
        );
    }
}
