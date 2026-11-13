//! The contract a platform backend implements: realize the main window's
//! shell and the editor window's, and their content trees, apply patches,
//! show the tray, and report the user's actions back as [`UiEvent`]s. The
//! shells' parts (sidebar, toolbar, drawer, the editor's commands) are fixed
//! semantic pieces each platform places its own way; the page, the drawer,
//! a dialog and the editor's content are component trees.

use std::borrow::Cow;
use std::sync::Arc;

use egrio_core::TrafficPolicyMode;
use egrio_platform::CaptureLayer;

use crate::latency::{milliseconds_text, milliseconds_tone};
use crate::messages::Level;
use crate::node::{Icon, SortDirection, Tone};
use crate::reconcile::{Mounted, NodeId, Patch};
use crate::state::Section;

/// The narrowest the page pane gets, its margins included: the widest page's
/// fixed parts, the grouped connections table's columns beside its group
/// list, fit at this width.
pub const PAGE_MIN_WIDTH: f64 = 780.0;

/// The message panel's width. It drops from the message capsule, which is
/// as wide while the panel is open and never wider when it expands.
pub const DRAWER_WIDTH: f64 = 400.0;

/// The tallest the message panel gets; it is as tall as its messages up to
/// this, or the window's bottom margin, and scrolls past it.
pub const DRAWER_HEIGHT: f64 = 480.0;

/// What the main window shows around its content.
#[derive(Debug, Clone, PartialEq)]
pub struct MainView {
    /// The page title, which the window carries.
    pub title: String,
    pub nav: Vec<NavItem>,
    pub section: Section,
    pub toolbar: ToolbarView,
    pub drawer_open: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NavItem {
    pub section: Section,
    pub label: String,
    pub icon: Icon,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolbarView {
    /// Absent where the platform has no system proxy layer.
    pub system_proxy: Option<CaptureToggle>,
    pub tun: CaptureToggle,
    pub policy: PolicyControl,
    pub messages: MessagesButton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToggleState {
    Idle,
    /// The switch is changing this layer.
    Pending,
    /// Something stopped the layer on its own.
    Warning,
}

/// A capture layer's switch in the toolbar: its label never changes, a
/// status mark carries the state.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureToggle {
    pub label: String,
    pub on: bool,
    pub state: ToggleState,
    pub enabled: bool,
    pub tooltip: Option<String>,
}

/// The traffic mode: rule, global or direct.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyControl {
    pub labels: [String; 3],
    pub selected: Option<usize>,
    pub enabled: bool,
    pub tooltip: Option<String>,
}

/// The message capsule right after the page title, always there: a small
/// capsule with the bell and the number of messages the panel holds, which
/// keep one size and place in every state. With unread messages it stays
/// expanded into the free space after it, tinted by the most severe of them
/// and showing the newest one cut to one line, until they are read; only the
/// free space changes, so nothing else moves. Pressing it opens or closes the
/// message panel, which is the capsule's own surface grown out of it: it
/// widens to [`DRAWER_WIDTH`] and grows down over the page under the bell and
/// the number, which head it, and shrinks back into the capsule when the
/// panel closes. The open panel reads what arrives, so nothing is unread then.
#[derive(Debug, Clone, PartialEq)]
pub struct MessagesButton {
    pub label: String,
    /// The messages the panel holds.
    pub count: usize,
    /// The most severe unread message's level, which tints the capsule.
    pub level: Option<Level>,
    /// The newest unread message.
    pub preview: Option<MessagePreview>,
    /// The drawer is open.
    pub open: bool,
}

/// The newest unread message as the capsule shows it: one line, cut at its
/// end where it does not fit.
#[derive(Debug, Clone, PartialEq)]
pub struct MessagePreview {
    pub level: Level,
    pub title: String,
    /// The title and the first line of the detail, which the capsule shows.
    pub text: String,
    /// The title and the whole detail, the capsule's help.
    pub help: String,
}

/// What the editor window shows around its text: the profile's name,
/// whether the text has unsaved changes, and its commands, which the
/// platform places in its toolbar and menus.
#[derive(Debug, Clone, PartialEq)]
pub struct EditorView {
    pub title: String,
    /// The text differs from the saved profile.
    pub edited: bool,
    pub revert: EditorCommand,
    /// Also on the platform's save shortcut.
    pub save: EditorCommand,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EditorCommand {
    pub label: String,
    pub enabled: bool,
}

/// The app menu's items where the platform has an app menu (macOS).
#[derive(Debug, Clone, PartialEq)]
pub struct MenuView {
    pub hide: String,
    pub quit: String,
    /// The file menu, whose items act on the editor window.
    pub file: String,
    pub save: String,
    pub revert: String,
    pub edit: String,
    pub undo: String,
    pub redo: String,
    pub cut: String,
    pub copy: String,
    pub paste: String,
    pub select_all: String,
    pub window: String,
    pub minimize: String,
    pub close: String,
}

/// The app's light or dark look: the system's, or one of them pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appearance {
    System,
    Light,
    Dark,
}

/// The tray's menu: its items in order, which the platform renders as its
/// tray menu.
#[derive(Debug, Clone, PartialEq)]
pub struct TrayView {
    pub tooltip: String,
    /// Whether traffic goes through Egrio, the system proxy or TUN mode on:
    /// the icon is plain then and dimmed or gray otherwise.
    pub connected: bool,
    pub items: Vec<TrayItem>,
}

impl TrayView {
    /// The menu as text, one item per line: a check, the title, a member's
    /// latency in brackets and whether the item is disabled, a submenu's
    /// items indented under it. A host whose menu is not a tree of its own
    /// views describes it to its test control channel with this.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        tray_lines(&self.items, 0, &mut lines);
        lines
    }

    /// What choosing the first enabled item titled `title` does.
    pub fn choice(&self, title: &str) -> Option<TrayAction> {
        tray_choice(&self.items, title)
    }
}

fn tray_lines(items: &[TrayItem], depth: usize, lines: &mut Vec<String>) {
    let indent = "  ".repeat(depth);
    let check = |checked: bool| if checked { "✓ " } else { "" };
    let disabled = |enabled: bool| if enabled { "" } else { " (disabled)" };
    for item in items {
        match item {
            TrayItem::Command {
                label,
                enabled,
                checked,
                ..
            } => lines.push(format!(
                "{indent}{}{label}{}",
                check(*checked),
                disabled(*enabled)
            )),
            TrayItem::Submenu {
                label,
                enabled,
                items,
            } => {
                lines.push(format!("{indent}{label} ▸{}", disabled(*enabled)));
                tray_lines(items, depth + 1, lines);
            }
            TrayItem::Group(group) => {
                lines.push(format!(
                    "{indent}{} ▸{}",
                    group.label,
                    disabled(group.enabled)
                ));
                lines.push(format!(
                    "{indent}  {}{}",
                    group.test_label,
                    disabled(group.test_enabled)
                ));
                lines.push(format!("{indent}  —"));
                for member in &group.members {
                    let latency = member
                        .latency
                        .map(|latency| format!(" [{}]", latency.text()))
                        .unwrap_or_default();
                    lines.push(format!(
                        "{indent}  {}{}{latency}{}",
                        check(member.checked),
                        member.label(),
                        disabled(member.enabled)
                    ));
                }
            }
            TrayItem::Separator => lines.push(format!("{indent}—")),
        }
    }
}

fn tray_choice(items: &[TrayItem], title: &str) -> Option<TrayAction> {
    items.iter().find_map(|item| match item {
        TrayItem::Command {
            label,
            action,
            enabled: true,
            ..
        } if label == title => Some(action.clone()),
        TrayItem::Submenu { items, .. } => tray_choice(items, title),
        TrayItem::Group(group) if group.test_enabled && group.test_label == title => {
            Some(group.test())
        }
        TrayItem::Group(group) => group
            .members
            .iter()
            .find(|member| member.enabled && member.label() == title)
            .map(|member| group.select(member)),
        _ => None,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrayItem {
    /// A command; `checked` puts a check mark before it.
    Command {
        label: String,
        action: TrayAction,
        enabled: bool,
        checked: bool,
    },
    Submenu {
        label: String,
        enabled: bool,
        items: Vec<TrayItem>,
    },
    /// A policy group. It is shared, so a platform that keeps the menu to
    /// show it later copies none of the members.
    Group(Arc<TrayGroup>),
    Separator,
}

/// A policy group in the tray: a submenu of its latency test and, under a
/// separator, its members. A profile from a subscription lists every node
/// in most of its groups, thousands of members in all, so a platform makes
/// the rows of a group when it shows them, not when it is told of them, and
/// names what a row does when the row is chosen.
#[derive(Debug, Clone, PartialEq)]
pub struct TrayGroup {
    /// The group's name and, after it, the member it uses.
    pub label: String,
    pub enabled: bool,
    pub profile_id: String,
    pub group_id: String,
    /// The latency test's title. Its results come back into the menu, so
    /// choosing it keeps the menu open where the platform can.
    pub test_label: &'static str,
    pub test_enabled: bool,
    pub members: Vec<TrayMember>,
}

impl TrayGroup {
    /// What choosing the group's latency test does.
    pub fn test(&self) -> TrayAction {
        TrayAction::TestGroup {
            profile_id: self.profile_id.clone(),
            group_id: self.group_id.clone(),
        }
    }

    /// What choosing `member` does.
    pub fn select(&self, member: &TrayMember) -> TrayAction {
        TrayAction::SelectMember {
            profile_id: self.profile_id.clone(),
            group_id: self.group_id.clone(),
            member: member.name.clone(),
        }
    }
}

/// A policy group's member: its name, a check mark when it is the member
/// the group uses, and its latency in a column of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct TrayMember {
    pub name: String,
    /// What follows the name of a member that cannot be used.
    pub badge: Option<&'static str>,
    pub enabled: bool,
    pub checked: bool,
    pub latency: Option<TrayLatency>,
}

impl TrayMember {
    /// The member as its row names it.
    pub fn label(&self) -> Cow<'_, str> {
        match self.badge {
            Some(badge) => format!("{} · {badge}", self.name).into(),
            None => self.name.as_str().into(),
        }
    }
}

/// A member's latency as the tray shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayLatency {
    Testing,
    /// The round trip, in milliseconds.
    Ready(u32),
    /// The test failed, in the interface's words.
    Failed(&'static str),
}

impl TrayLatency {
    pub fn text(&self) -> Cow<'static, str> {
        match self {
            Self::Testing => "…".into(),
            Self::Ready(milliseconds) => milliseconds_text(*milliseconds).into(),
            Self::Failed(text) => (*text).into(),
        }
    }

    /// The color that rates it.
    pub fn tone(&self) -> Tone {
        match self {
            Self::Testing => Tone::Muted,
            Self::Ready(milliseconds) => milliseconds_tone(*milliseconds),
            Self::Failed(_) => Tone::Danger,
        }
    }
}

/// Which content tree a patch belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Content,
    Drawer,
    /// The main window's open dialog.
    Dialog,
    /// The editor window's content.
    Editor,
}

/// What a file the user is asked for is for, which its answer names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePurpose {
    ImportProfile,
    /// The program a process rule names.
    RuleExecutable,
}

/// A request for one existing file.
#[derive(Debug, Clone, PartialEq)]
pub struct FileRequest {
    pub purpose: FilePurpose,
    /// The extensions offered, such as `yaml`.
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UiEvent {
    /// An event on a node of the content or drawer tree.
    Node {
        id: NodeId,
        event: Event,
    },
    Navigate(Section),
    Toolbar(ToolbarAction),
    /// The user dismissed the open drawer, as with Esc.
    CloseDrawer,
    /// The user chose a file, or none, for a request.
    FileChosen {
        purpose: FilePurpose,
        path: Option<std::path::PathBuf>,
    },
    /// The user closed the main window; the backend has released it.
    WindowClosed,
    /// A command of the editor window, or the user closing it, which the
    /// runtime decides on.
    Editor(EditorAction),
    Tray(TrayAction),
    /// The app was opened again (Dock icon, a second launch).
    Reopen,
    /// The OS or the app menu asked the app to quit.
    QuitRequested,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolbarAction {
    ToggleSystemProxy,
    ToggleTun,
    Policy(usize),
    Messages,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorAction {
    Save,
    Revert,
    /// The user asked to close the window.
    Close,
}

/// What a tray command does. A choice names the profile and the group it
/// was made in, so a click on a menu built before the profile changed never
/// acts on another one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    ShowMainWindow,
    Quit,
    SetMode {
        profile_id: String,
        mode: TrafficPolicyMode,
    },
    ToggleCapture(CaptureLayer),
    TestGroup {
        profile_id: String,
        group_id: String,
    },
    SelectMember {
        profile_id: String,
        group_id: String,
        member: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Press,
    Toggle(bool),
    /// Editable text the user changed and committed.
    Commit(String),
    /// A text field's new value.
    Changed(String),
    Select(usize),
    RowsSelected(Vec<String>),
    RowActivated(String),
    Sort(Option<(usize, SortDirection)>),
    /// Rows, by key, dragged and dropped before the row at `to`.
    RowsMoved {
        keys: Vec<String>,
        to: usize,
    },
    /// A tile of a grid, by its key, was pressed.
    TilePressed(String),
    /// A tile's test button, by the tile's key, was pressed.
    TileTested(String),
}

pub trait Backend {
    /// Creates the main window with its first content and drawer trees.
    fn open_main(&mut self, view: &MainView, content: &Mounted, drawer: &Mounted);
    /// Releases the main window; the runtime keeps running.
    fn close_main(&mut self);
    fn update_main(&mut self, view: &MainView);
    fn patch(&mut self, surface: Surface, patches: Vec<Patch>);
    /// Shows a dialog over the main window with its content tree.
    fn open_dialog(&mut self, dialog: &Mounted);
    fn close_dialog(&mut self);
    /// Asks the user for a file; the answer comes back as
    /// [`UiEvent::FileChosen`].
    fn choose_file(&mut self, request: &FileRequest);
    /// Opens the editor window with its content tree, a window of its own
    /// centered over the main window when that is open.
    fn open_editor(&mut self, view: &EditorView, content: &Mounted);
    fn update_editor(&mut self, view: &EditorView);
    /// Closes the editor window.
    fn close_editor(&mut self);
    fn bring_editor_to_front(&mut self);
    /// Selects the character at `index` of the editor's text, counted in
    /// characters from zero, and scrolls it into view.
    fn reveal_in_editor(&mut self, index: usize);
    fn set_tray(&mut self, tray: &TrayView);
    fn set_menu(&mut self, menu: &MenuView);
    fn set_appearance(&mut self, appearance: Appearance);
    /// Hands a downloaded installer to the system, which updates the app
    /// with it: macOS mounts the disk image, Windows runs the setup program
    /// in its update mode, Linux opens the package with its default app.
    fn open_installer(&mut self, path: &std::path::Path) -> Result<(), String>;
    /// Opens a web page in the default browser.
    fn open_url(&mut self, url: &str) -> Result<(), String>;
    /// The user's event was handled and rendered: the controls show what the
    /// interface says again, also where it refused the change.
    fn settle(&mut self);
    fn bring_to_front(&mut self);
    /// The quit's cleanup is done: end the process.
    fn exit(&mut self);
}
