//! The interface runtime: it owns the state, turns the backend's events and
//! the operations' results into state changes, runs the product backend's
//! operations, and renders the main window when something changed.
//!
//! It runs on the platform's main thread. Work that touches the disk or the
//! network runs on the desktop tokio runtime and comes back as a message
//! through [`Sender`], which wakes the main thread; in-memory reads (the
//! traffic volume, the connection history) run in place. Each area keeps its
//! reads and actions in its own module: the capture layers and the traffic
//! mode, the pages, and the editor window.

mod activity;
mod capture;
mod connections;
mod editor;
mod logs;
mod nodes;
mod profiles;
mod rules;
mod settings;
mod update;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use egrio_core::TrafficPolicyMode;
use egrio_desktop::connection_history::ConnectionHistory;
use egrio_desktop::events::{DesktopEvent, SystemProxyGuardNotice, TunSessionNotice};
use egrio_desktop::runtime::DesktopRuntime;
use egrio_platform::CaptureLayer;

use crate::backend::{
    Backend, EditorAction, EditorView, Event, FilePurpose, MainView, MenuView, Surface,
    ToolbarAction, TrayAction, UiEvent,
};
use crate::format;
use crate::messages::{Level, Source};
use crate::msg::{EditorMsg, Msg, NodesMsg, ProfilesMsg, RulesMsg, UpdateMsg};
use crate::node::Kind;
use crate::reconcile::{find, mount, reconcile, Ids, Mounted};
use crate::remembered::{self, Remembered};
use crate::state::{Change, Dialog, PortFallback, Running, Section, State, SLOW_CHANGE};
use crate::text::Lang;
use crate::tray;
use crate::view;

/// The product backend's per-process objects the operations act on.
#[derive(Clone)]
pub struct Desktop {
    pub runtime: DesktopRuntime,
    pub history: Arc<Mutex<ConnectionHistory>>,
}

/// Delivers messages to the runtime from any thread and wakes the main thread.
#[derive(Clone)]
pub struct Sender {
    tx: mpsc::Sender<Msg>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Sender {
    pub fn send(&self, msg: Msg) {
        if self.tx.send(msg).is_ok() {
            (self.wake)();
        }
    }
}

struct MainWindow {
    view: MainView,
    content: Mounted,
    drawer: Mounted,
    /// The open dialog's tree.
    dialog: Option<Mounted>,
}

struct EditorWindow {
    view: EditorView,
    content: Mounted,
}

/// What the tray's menu is built from, compared before building it again.
#[derive(Debug, Clone, PartialEq)]
struct TrayKey {
    lang: Lang,
    profile: Option<(String, TrafficPolicyMode)>,
    nodes: u64,
    latency: u64,
    capture: Option<(bool, bool, bool, bool)>,
    busy: bool,
}

impl MainWindow {
    /// Shows `state` in the window: its shell, its trees and its dialog.
    fn render<B: Backend>(&mut self, backend: &mut B, ids: &mut Ids, state: &State) {
        let views = view::views(state);
        if views.main != self.view {
            backend.update_main(&views.main);
            self.view = views.main;
        }
        let patches = reconcile(&mut self.content, &views.content, ids);
        if !patches.is_empty() {
            backend.patch(Surface::Content, patches);
        }
        let patches = reconcile(&mut self.drawer, &views.drawer, ids);
        if !patches.is_empty() {
            backend.patch(Surface::Drawer, patches);
        }
        match (&mut self.dialog, views.dialog) {
            (None, Some(tree)) => {
                let mounted = mount(&tree, ids);
                backend.open_dialog(&mounted);
                self.dialog = Some(mounted);
            }
            (Some(mounted), Some(tree)) => {
                let patches = reconcile(mounted, &tree, ids);
                if !patches.is_empty() {
                    backend.patch(Surface::Dialog, patches);
                }
            }
            (Some(_), None) => {
                self.dialog = None;
                backend.close_dialog();
            }
            (None, None) => {}
        }
    }
}

pub struct Ui<B: Backend> {
    backend: B,
    desktop: Desktop,
    state: State,
    main: Option<MainWindow>,
    /// The open editor window.
    editor: Option<EditorWindow>,
    /// Editors opened so far, which numbers the next one.
    editor_instances: u64,
    ids: Ids,
    inbox: mpsc::Receiver<Msg>,
    sender: Sender,
    clock: Instant,
    window_open: Arc<AtomicBool>,
    announced_fallback: Option<PortFallback>,
    egress_read_at: Option<Instant>,
    /// What the interface remembers for the next launch, as last saved.
    remembered: Remembered,
    /// What the tray's menu shows, as last given to the backend.
    tray: Option<TrayKey>,
    /// Changes started so far, which numbers the next one.
    changes: u64,
    quitting: bool,
    dirty: bool,
}

impl<B: Backend> Ui<B> {
    pub fn new(backend: B, desktop: Desktop, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (tx, inbox) = mpsc::channel();
        Self {
            backend,
            desktop,
            state: State::new(Lang::current()),
            main: None,
            editor: None,
            editor_instances: 0,
            ids: Ids::default(),
            inbox,
            sender: Sender { tx, wake },
            clock: Instant::now(),
            window_open: Arc::new(AtomicBool::new(false)),
            announced_fallback: None,
            egress_read_at: None,
            remembered: Remembered::default(),
            tray: None,
            changes: 0,
            quitting: false,
            dirty: false,
        }
    }

    pub fn sender(&self) -> Sender {
        self.sender.clone()
    }

    /// The platform host's own windows and surfaces. A host whose toolkit
    /// keeps no list of what is open (WinUI) reaches them through here; its
    /// test control channel is the only caller.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Takes the stored look, shows the tray and the app menu, starts the
    /// timers and the event forwarding, reads the state, and opens the main
    /// window unless the app starts silently.
    pub fn start(&mut self, show_main: bool) {
        self.remembered = remembered::load();
        self.state.section = self.remembered.section;
        self.state.nodes.shown = self.remembered.nodes_entry.clone();
        let theme = egrio_desktop::desktop_behavior::load_theme_preference().unwrap_or_default();
        self.backend.set_appearance(settings::appearance(theme));
        self.show_chrome();
        self.forward_events();
        self.start_ticker();
        self.load_capture();
        self.load_core();
        self.load_active_profile();
        self.spawn_blocking(|| {
            Msg::CaptureRemembered(egrio_desktop::operations::capture::remembered_capture_layers())
        });
        if egrio_desktop::desktop_behavior::load_check_updates().unwrap_or(true) {
            self.dispatch(Msg::Update(UpdateMsg::Check { asked: false }));
        }
        if show_main {
            self.open_main();
        }
    }

    /// One event from the backend, on the main thread.
    pub fn handle(&mut self, event: UiEvent) {
        if let Some(msg) = self.message_for(event) {
            self.dispatch(msg);
        }
        self.render();
        self.backend.settle();
    }

    /// Every message waiting in the inbox, then one render.
    pub fn drain(&mut self) {
        while let Ok(msg) = self.inbox.try_recv() {
            self.dispatch(msg);
        }
        self.render();
    }

    fn message_for(&self, event: UiEvent) -> Option<Msg> {
        match event {
            UiEvent::Node { id, event } => {
                let in_main = self.main.as_ref().and_then(|main| {
                    find(&main.content, id)
                        .or_else(|| find(&main.drawer, id))
                        .or_else(|| main.dialog.as_ref().and_then(|dialog| find(dialog, id)))
                });
                let node = in_main.or_else(|| {
                    self.editor
                        .as_ref()
                        .and_then(|editor| find(&editor.content, id))
                })?;
                match (&node.kind, event) {
                    (Kind::Button(button), Event::Press) => {
                        button.on_press.as_ref().map(|handler| handler.call(()))
                    }
                    (Kind::Switch(switch), Event::Toggle(on)) => {
                        switch.on_toggle.as_ref().map(|handler| handler.call(on))
                    }
                    (Kind::Placeholder(placeholder), Event::Press) => placeholder
                        .action
                        .as_ref()
                        .map(|action| action.on_press.call(())),
                    (Kind::Radio(radio), Event::Press) => {
                        radio.on_select.as_ref().map(|handler| handler.call(()))
                    }
                    (Kind::EditableText(editable), Event::Commit(text)) => editable
                        .on_commit
                        .as_ref()
                        .map(|handler| handler.call(text)),
                    (Kind::TextField(field) | Kind::SearchField(field), Event::Changed(value)) => {
                        field.on_change.as_ref().map(|handler| handler.call(value))
                    }
                    (Kind::TextEditor(editor), Event::Changed(text)) => {
                        editor.on_change.as_ref().map(|handler| handler.call(text))
                    }
                    (Kind::Segmented(segmented), Event::Select(index)) => segmented
                        .on_select
                        .as_ref()
                        .map(|handler| handler.call(index)),
                    (Kind::Select(select), Event::Select(index)) => {
                        select.on_select.as_ref().map(|handler| handler.call(index))
                    }
                    (Kind::Table(table), Event::RowsSelected(keys)) => {
                        table.on_select.as_ref().map(|handler| handler.call(keys))
                    }
                    (Kind::Table(table), Event::RowActivated(key)) => {
                        table.on_activate.as_ref().map(|handler| handler.call(key))
                    }
                    (Kind::Table(table), Event::Sort(sort)) => {
                        table.on_sort.as_ref().map(|handler| handler.call(sort))
                    }
                    (Kind::Table(table), Event::RowsMoved { keys, to }) => table
                        .on_move
                        .as_ref()
                        .map(|handler| handler.call((keys, to))),
                    (Kind::Tiles(tiles), Event::TilePressed(key)) => {
                        tiles.on_press.as_ref().map(|handler| handler.call(key))
                    }
                    (Kind::Tiles(tiles), Event::TileTested(key)) => {
                        tiles.on_test.as_ref().map(|handler| handler.call(key))
                    }
                    _ => None,
                }
            }
            UiEvent::Navigate(section) => Some(Msg::Navigate(section)),
            UiEvent::Toolbar(ToolbarAction::ToggleSystemProxy) => {
                Some(Msg::ToggleCapture(CaptureLayer::SystemProxy))
            }
            UiEvent::Toolbar(ToolbarAction::ToggleTun) => {
                Some(Msg::ToggleCapture(CaptureLayer::Tun))
            }
            UiEvent::Toolbar(ToolbarAction::Policy(index)) => {
                Some(Msg::SetTrafficPolicy(match index {
                    1 => TrafficPolicyMode::Global,
                    2 => TrafficPolicyMode::Direct,
                    _ => TrafficPolicyMode::Rule,
                }))
            }
            UiEvent::Toolbar(ToolbarAction::Messages) => Some(Msg::ToggleDrawer),
            UiEvent::CloseDrawer => Some(Msg::CloseDrawer),
            UiEvent::FileChosen { purpose, path } => Some(match purpose {
                FilePurpose::ImportProfile => Msg::Profiles(ProfilesMsg::FileChosen(path)),
                FilePurpose::RuleExecutable => Msg::Rules(RulesMsg::ExecutableChosen(path)),
            }),
            UiEvent::WindowClosed => Some(Msg::MainWindowClosed),
            UiEvent::Editor(action) => Some(Msg::Editor(match action {
                EditorAction::Save => EditorMsg::Save,
                EditorAction::Revert => EditorMsg::Revert,
                EditorAction::Close => EditorMsg::Close,
            })),
            UiEvent::Tray(TrayAction::ShowMainWindow) | UiEvent::Reopen => {
                Some(Msg::ShowMainWindow)
            }
            UiEvent::Tray(TrayAction::Quit) | UiEvent::QuitRequested => Some(Msg::Quit),
            UiEvent::Tray(TrayAction::ToggleCapture(layer)) => Some(Msg::ToggleCapture(layer)),
            // A choice from a menu of another profile than the active one
            // does nothing.
            UiEvent::Tray(TrayAction::SetMode { profile_id, mode }) => self
                .is_active(&profile_id)
                .then_some(Msg::SetTrafficPolicy(mode)),
            UiEvent::Tray(TrayAction::TestGroup {
                profile_id,
                group_id,
            }) => self
                .is_active(&profile_id)
                .then_some(Msg::Nodes(NodesMsg::TestGroup(group_id))),
            UiEvent::Tray(TrayAction::SelectMember {
                profile_id,
                group_id,
                member,
            }) => self
                .is_active(&profile_id)
                .then_some(Msg::SelectMember { group_id, member }),
        }
    }

    fn is_active(&self, profile_id: &str) -> bool {
        self.state
            .active_profile
            .ready()
            .and_then(Option::as_ref)
            .is_some_and(|profile| profile.id == profile_id)
    }

    fn dispatch(&mut self, msg: Msg) {
        self.dirty = true;
        match msg {
            Msg::Navigate(section) => {
                self.state.section = section;
                self.remember();
                self.release_hidden_pages();
                self.load_page();
            }
            Msg::ToggleDrawer => {
                self.state.drawer_open = !self.state.drawer_open;
                if self.state.drawer_open {
                    self.state.messages.mark_read();
                }
            }
            Msg::CloseDrawer => self.state.drawer_open = false,
            Msg::ClearMessages => self.state.messages.clear(),
            Msg::ShowMainWindow => {
                if self.main.is_some() {
                    self.backend.bring_to_front();
                } else {
                    self.open_main();
                }
            }
            Msg::MainWindowClosed => {
                self.main = None;
                self.backend.close_main();
                self.window_open.store(false, Ordering::Relaxed);
                self.release_hidden_pages();
            }
            Msg::Quit => self.quit(),
            Msg::ExitReady => self.backend.exit(),
            Msg::ToggleCapture(layer) => self.toggle_capture(layer),
            Msg::SetTrafficPolicy(mode) => self.set_traffic_policy(mode),
            Msg::SelectMember { group_id, member } => self.select_member(group_id, member),
            Msg::MemberSelected(result) => {
                let failed = self.state.text().select_failed();
                self.policy_changed(result, failed);
                self.load_group_members();
            }
            Msg::Nodes(msg) => self.nodes(msg),
            Msg::Rules(msg) => self.rules(msg),
            Msg::Connections(msg) => self.connections(msg),
            Msg::Logs(msg) => self.logs(msg),
            Msg::Settings(msg) => self.settings(msg),
            Msg::Update(msg) => self.update(msg),
            Msg::Profiles(msg) => self.profiles(msg),
            Msg::Editor(msg) => self.editor(msg),
            Msg::CloseDialog => {
                let pending =
                    matches!(&self.state.dialog, Some(Dialog::AddProfile(draft)) if draft.pending);
                if !pending {
                    self.state.dialog = None;
                }
            }
            Msg::SampleTraffic => self.sample_traffic(),
            Msg::PollLogs => self.poll_logs(),
            Msg::PollTelemetry => {
                if self.main.is_some() {
                    self.poll_page();
                }
            }
            Msg::PollState => {
                self.load_capture();
                self.load_core();
                self.load_active_profile();
            }
            Msg::Desktop(event) => self.desktop_event(event),
            Msg::CaptureStatus(status) => self.capture_status(status),
            Msg::ActiveProfile(result) => self.active_profile_loaded(result),
            Msg::PublicIp(result) => self.public_ip(*result),
            Msg::ProcessIdentities {
                queries,
                identities,
            } => self.process_identities(queries, identities),
            Msg::CaptureChanged(result) => self.capture_changed(result),
            Msg::CaptureRemembered(layers) => self.restore_capture(layers),
            Msg::CaptureRestored(result) => self.capture_restored(result),
            Msg::PolicyChanged(result) => {
                let failed = self.state.text().mode_failed();
                self.policy_changed(result, failed);
            }
            Msg::ChangeSlow(id) => {
                if let Some(running) = self
                    .state
                    .change
                    .as_mut()
                    .filter(|running| running.id == id)
                {
                    running.slow = true;
                }
            }
            Msg::Measured { target, result } => self.measured(target, result),
        }
    }

    fn render(&mut self) {
        if !std::mem::take(&mut self.dirty) {
            return;
        }
        let Self {
            main,
            editor,
            backend,
            ids,
            state,
            ..
        } = self;
        if let Some(main) = main.as_mut() {
            main.render(backend, ids, state);
        }
        let view = state
            .editor
            .as_ref()
            .map(|open| crate::editor::view(open, state.text()));
        match (editor.as_mut(), view) {
            (None, Some((view, tree))) => {
                let content = mount(&tree, ids);
                backend.open_editor(&view, &content);
                *editor = Some(EditorWindow { view, content });
            }
            (Some(window), Some((view, tree))) => {
                if view != window.view {
                    backend.update_editor(&view);
                    window.view = view;
                }
                let patches = reconcile(&mut window.content, &tree, ids);
                if !patches.is_empty() {
                    backend.patch(Surface::Editor, patches);
                }
            }
            (Some(_), None) => {
                *editor = None;
                backend.close_editor();
            }
            (None, None) => {}
        }
        self.render_tray();
    }

    /// The tray's menu, built again only when something it shows changed.
    fn render_tray(&mut self) {
        let state = &self.state;
        let key = TrayKey {
            lang: state.lang,
            profile: state
                .active_profile
                .ready()
                .and_then(Option::as_ref)
                .map(|profile| (profile.id.clone(), state.mode(profile))),
            nodes: state.nodes.reads(),
            latency: state.latency.revision(),
            capture: state.capture.as_ref().map(|status| {
                (
                    state.layer_on(CaptureLayer::SystemProxy),
                    state.layer_on(CaptureLayer::Tun),
                    status.support.system_proxy,
                    status.support.tun,
                )
            }),
            busy: state.selection_locked(),
        };
        if self.tray.as_ref() == Some(&key) {
            return;
        }
        self.backend.set_tray(&tray::view(state));
        self.tray = Some(key);
    }

    fn open_main(&mut self) {
        let views = view::views(&self.state);
        let content = mount(&views.content, &mut self.ids);
        let drawer = mount(&views.drawer, &mut self.ids);
        self.backend.open_main(&views.main, &content, &drawer);
        self.main = Some(MainWindow {
            view: views.main,
            content,
            drawer,
            dialog: None,
        });
        // An open dialog comes back with the next render.
        self.dirty = true;
        self.window_open.store(true, Ordering::Relaxed);
        self.dispatch(Msg::SampleTraffic);
        self.load_page();
    }

    /// Saves the section and the nodes page's entry when one of them changed.
    fn remember(&mut self) {
        let now = Remembered {
            section: self.state.section,
            nodes_entry: self.state.nodes.shown.clone(),
        };
        if now != self.remembered {
            remembered::save(now.clone());
            self.remembered = now;
        }
    }

    fn quit(&mut self) {
        if std::mem::replace(&mut self.quitting, true) {
            return;
        }
        let sender = self.sender.clone();
        egrio_desktop::exit::request_quit(&self.desktop.runtime, move || {
            sender.send(Msg::ExitReady)
        });
    }

    /// Gives back what only a shown page holds: the connection table's rows,
    /// and the table rows each page built for its last render. With the
    /// window closed or another page showing they would stay for as long as
    /// the app runs, megabytes of them for a full connection history or a
    /// long rule list; a page reads and builds them again when it shows.
    fn release_hidden_pages(&mut self) {
        let shown = self.main.as_ref().map(|_| self.state.section);
        if shown != Some(Section::Connections) {
            self.state.connections.release();
        }
        if shown != Some(Section::Rules) {
            self.state.rules.forget_rows();
        }
        if shown != Some(Section::Logs) {
            self.state.logs.forget_rows();
        }
        if shown != Some(Section::Nodes) {
            self.state.nodes.forget_rows();
        }
    }

    /// Everything the shown page reads when it appears.
    fn load_page(&mut self) {
        match self.state.section {
            Section::Activity => self.load_activity(),
            Section::Connections => self.load_connections(),
            Section::Logs => self.load_logs(),
            Section::Settings => self.load_settings(),
            Section::Profiles => self.load_profiles(),
            Section::Nodes => self.load_nodes(),
            Section::Rules => self.load_rules_page(),
        }
    }

    /// What the shown page reads again every two seconds.
    fn poll_page(&mut self) {
        match self.state.section {
            Section::Activity => self.load_activity(),
            Section::Connections => self.load_connections(),
            Section::Settings => self.poll_settings(),
            Section::Rules => self.poll_rules(),
            Section::Logs | Section::Nodes | Section::Profiles => {}
        }
    }

    /// The tray and the app menu, in the interface's language.
    fn show_chrome(&mut self) {
        let text = self.state.text();
        self.render_tray();
        self.backend.set_menu(&MenuView {
            hide: text.menu_hide().into(),
            quit: text.menu_quit().into(),
            file: text.menu_file().into(),
            save: text.save().into(),
            revert: text.revert().into(),
            edit: text.menu_edit().into(),
            undo: text.menu_undo().into(),
            redo: text.menu_redo().into(),
            cut: text.menu_cut().into(),
            copy: text.menu_copy().into(),
            paste: text.menu_paste().into(),
            select_all: text.menu_select_all().into(),
            window: text.menu_window().into(),
            minimize: text.menu_minimize().into(),
            close: text.menu_close().into(),
        });
    }

    /// Shows the interface in `lang` from the next render on.
    fn set_lang(&mut self, lang: Lang) {
        self.state.lang = lang;
        self.show_chrome();
    }

    /// Runs `work` on the desktop runtime and delivers its message.
    fn spawn(&self, work: impl Future<Output = Msg> + Send + 'static) {
        let sender = self.sender.clone();
        egrio_desktop::async_runtime::spawn(async move { sender.send(work.await) });
    }

    /// Starts `change`, which `work` makes; the other changes wait for it.
    /// Its controls show what it asks for at once, and the controls waiting
    /// for it dim only once it has run for [`SLOW_CHANGE`].
    fn begin_change(&mut self, change: Change, work: impl Future<Output = Msg> + Send + 'static) {
        self.changes += 1;
        let id = self.changes;
        self.state.change = Some(Running {
            change,
            id,
            slow: false,
        });
        self.spawn(work);
        self.spawn(async move {
            tokio::time::sleep(SLOW_CHANGE).await;
            Msg::ChangeSlow(id)
        });
    }

    /// Runs blocking `work` (store reads) off the main thread.
    fn spawn_blocking(&self, work: impl FnOnce() -> Msg + Send + 'static) {
        let sender = self.sender.clone();
        egrio_desktop::async_runtime::spawn_blocking(move || sender.send(work()));
    }

    fn forward_events(&self) {
        let sender = self.sender.clone();
        let mut events = egrio_desktop::events::subscribe();
        egrio_desktop::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                sender.send(Msg::Desktop(event));
            }
        });
    }

    /// One timer for the main window: the chart and the logs read every
    /// second, the shown page every two, the state that events keep current
    /// every eight. It sends nothing while the window is closed.
    fn start_ticker(&self) {
        let sender = self.sender.clone();
        let window_open = self.window_open.clone();
        egrio_desktop::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut tick: u64 = 0;
            loop {
                interval.tick().await;
                tick += 1;
                if !window_open.load(Ordering::Relaxed) {
                    continue;
                }
                sender.send(Msg::SampleTraffic);
                sender.send(Msg::PollLogs);
                if tick.is_multiple_of(2) {
                    sender.send(Msg::PollTelemetry);
                }
                if tick.is_multiple_of(8) {
                    sender.send(Msg::PollState);
                }
            }
        });
    }

    fn note(
        &mut self,
        level: Level,
        source: Source,
        title: impl Into<String>,
        detail: Option<String>,
    ) {
        self.state
            .messages
            .push(level, source, title.into(), detail, format::now_unix());
        // The open panel shows it as it arrives; otherwise the capsule shows
        // it until it is read.
        if self.state.drawer_open {
            self.state.messages.mark_read();
        }
    }

    fn desktop_event(&mut self, event: DesktopEvent) {
        let text = self.state.text();
        match event {
            DesktopEvent::RuleSetDownloadFailed { message } => {
                self.note(
                    Level::Error,
                    Source::Rules,
                    text.rule_sets_failed(),
                    Some(message),
                );
            }
            DesktopEvent::CaptureStartFailed { layers, message } => {
                self.capture_start_failed(layers, message);
            }
            DesktopEvent::NativeStateChanged => {
                self.load_capture();
                self.load_core();
                self.load_active_profile();
                self.refresh_egress_if_needed(true);
                if self.state.section == Section::Settings {
                    self.load_network_settings();
                }
            }
            // A profile's groups may be other groups, with other members.
            DesktopEvent::ProfilesChanged => {
                self.load_active_profile();
                self.load_group_members();
                self.profiles_changed();
                self.editor_profiles_changed();
                self.rules_profiles_changed();
                if self.state.section == Section::Settings {
                    self.load_network_settings();
                }
            }
            DesktopEvent::GroupMembersChanged => self.load_group_members(),
            DesktopEvent::TunSession { notice, message } => {
                // The interruption and the recovery say all in their titles;
                // a failed recovery carries the error that stopped it.
                let (level, title, detail) = match notice {
                    TunSessionNotice::Interrupted => (Level::Warning, text.tun_interrupted(), None),
                    TunSessionNotice::Recovered => (Level::Info, text.tun_recovered(), None),
                    TunSessionNotice::Failed => {
                        (Level::Error, text.tun_recovery_failed(), Some(message))
                    }
                };
                self.note(level, Source::Tun, title, detail);
            }
            DesktopEvent::SystemProxyGuard { notice, message } => match notice {
                SystemProxyGuardNotice::Yielded => self.note(
                    Level::Warning,
                    Source::SystemProxy,
                    text.guard_yielded(),
                    Some(message),
                ),
                SystemProxyGuardNotice::Reasserted => self.note(
                    Level::Info,
                    Source::SystemProxy,
                    text.guard_reasserted(),
                    None,
                ),
            },
        }
    }
}
