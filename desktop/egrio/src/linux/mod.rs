//! The Linux app: GTK 4 and libadwaita realize the interface `egrio-ui`
//! describes. The interface runtime lives on the main thread; messages from
//! the desktop runtime, events from the native controls and work from other
//! threads each schedule one drain on the main context, so no native
//! callback runs inside a render.
//!
//! `GtkApplication`'s uniqueness on the session bus keeps one instance per
//! data directory: a second launch activates the running one, which shows
//! its window, and ends.

mod cells;
mod chart;
mod dialog;
mod editor;
mod exact;
mod messages;
mod picker;
mod style;
mod table;
#[cfg(feature = "test-control")]
mod test_control;
mod text_editor;
mod tiles;
mod tray;
mod widgets;
mod window;
mod window_state;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use egrio_desktop::connection_history::ConnectionHistory;
use egrio_desktop::runtime::DesktopRuntime;
use egrio_desktop::runtime_owner::RuntimeOwnerError;
use egrio_ui::backend::{
    Appearance, Backend, EditorView, FileRequest, MainView, MenuView, Surface, TrayAction,
    TrayView, UiEvent,
};
use egrio_ui::reconcile::{Mounted, Patch};
use egrio_ui::runtime::{Desktop, Ui};

use editor::EditorWindow;
use tray::Tray;
use window::MainWindow;

/// The installed app's D-Bus name; the desktop file carries the same name.
const APPLICATION_ID: &str = "com.xinvexo.egrio";

thread_local! {
    static UI: RefCell<Option<Ui<LinuxBackend>>> = const { RefCell::new(None) };
    static EVENTS: RefCell<VecDeque<UiEvent>> = const { RefCell::new(VecDeque::new()) };
    static EVENTS_SCHEDULED: Cell<bool> = const { Cell::new(false) };
    /// The activation token of the tray click that asked for a window,
    /// which lets the window come forward on Wayland (`xdg-activation-v1`).
    static TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
}

static DRAIN_SCHEDULED: AtomicBool = AtomicBool::new(false);

/// Runs `work` on the main thread after what it is doing; callable from any
/// thread.
pub fn on_main(work: impl FnOnce() + Send + 'static) {
    glib::idle_add_once(work);
}

/// Queues a native event for the runtime; it runs after the current call
/// stack. Main thread only.
pub fn post(event: UiEvent) {
    EVENTS.with(|events| events.borrow_mut().push_back(event));
    if !EVENTS_SCHEDULED.replace(true) {
        glib::idle_add_local_once(|| {
            EVENTS_SCHEDULED.set(false);
            while let Some(event) = EVENTS.with(|events| events.borrow_mut().pop_front()) {
                with_ui(|ui| ui.handle(event));
            }
        });
    }
}

/// A tray item's action, with the activation token of its click.
fn tray_event(action: TrayAction, token: Option<String>) {
    if token.is_some() {
        TOKEN.with(|pending| *pending.borrow_mut() = token);
    }
    post(UiEvent::Tray(action));
}

fn take_token() -> Option<String> {
    TOKEN.with(|pending| pending.borrow_mut().take())
}

/// Wakes the main thread to read the runtime's inbox; callable from any thread.
fn wake() {
    if !DRAIN_SCHEDULED.swap(true, Ordering::AcqRel) {
        glib::idle_add_once(|| {
            DRAIN_SCHEDULED.store(false, Ordering::Release);
            with_ui(|ui| ui.drain());
        });
    }
}

fn with_ui(work: impl FnOnce(&mut Ui<LinuxBackend>)) {
    UI.with(|ui| {
        if let Some(ui) = ui.borrow_mut().as_mut() {
            work(ui);
        }
    });
}

pub struct LinuxBackend {
    app: adw::Application,
    window: Option<MainWindow>,
    /// The open editor window.
    editor: Option<EditorWindow>,
    tray: Option<Tray>,
}

/// Opens a file or a page with the desktop's default app for it
/// (`g_app_info_launch_default_for_uri`), which fails when no app handles
/// it.
fn launch_default(uri: &str) -> Result<(), String> {
    let context = gtk::gdk::Display::default().map(|display| display.app_launch_context());
    gtk::gio::AppInfo::launch_default_for_uri(uri, context.as_ref())
        .map_err(|error| format!("couldn't open {uri}: {error}"))
}

impl Backend for LinuxBackend {
    fn open_main(&mut self, view: &MainView, content: &Mounted, drawer: &Mounted) {
        let window = MainWindow::open(&self.app, view, content, drawer, post);
        window.present(take_token().as_deref());
        self.window = Some(window);
    }

    fn close_main(&mut self) {
        if let Some(window) = self.window.take() {
            window.close();
        }
    }

    fn update_main(&mut self, view: &MainView) {
        if let Some(window) = self.window.as_mut() {
            window.update(view);
        }
    }

    fn patch(&mut self, surface: Surface, patches: Vec<Patch>) {
        if surface == Surface::Editor {
            if let Some(editor) = self.editor.as_mut() {
                editor.surface.apply(patches);
            }
            return;
        }
        if let Some(window) = self.window.as_mut() {
            match surface {
                Surface::Content => window.content.apply(patches),
                Surface::Drawer => window.drawer.apply(patches),
                Surface::Dialog => {
                    if let Some(dialog) = window.dialog.as_ref() {
                        dialog.apply(patches);
                    }
                }
                Surface::Editor => {}
            }
        }
    }

    fn open_dialog(&mut self, dialog: &Mounted) {
        if let Some(window) = self.window.as_mut() {
            window.open_dialog(dialog);
        }
    }

    fn close_dialog(&mut self) {
        if let Some(window) = self.window.as_mut() {
            window.close_dialog();
        }
    }

    fn choose_file(&mut self, request: &FileRequest) {
        let parent: Option<gtk::Window> = self
            .window
            .as_ref()
            .map(|window| window.window().clone().upcast())
            .or_else(|| {
                self.editor
                    .as_ref()
                    .map(|editor| editor.window().clone().upcast())
            });
        picker::choose_file(parent.as_ref(), request, post);
    }

    fn open_editor(&mut self, view: &EditorView, content: &Mounted) {
        if let Some(editor) = self.editor.take() {
            editor.close();
        }
        self.editor = Some(EditorWindow::open(&self.app, view, content, post));
    }

    fn update_editor(&mut self, view: &EditorView) {
        if let Some(editor) = self.editor.as_ref() {
            editor.update(view);
        }
    }

    fn close_editor(&mut self) {
        if let Some(editor) = self.editor.take() {
            editor.close();
        }
    }

    fn bring_editor_to_front(&mut self) {
        if let Some(editor) = self.editor.as_ref() {
            editor.present(take_token().as_deref());
        }
    }

    fn reveal_in_editor(&mut self, index: usize) {
        if let Some(editor) = self.editor.as_ref() {
            editor.reveal(index);
        }
    }

    fn set_tray(&mut self, view: &TrayView) {
        #[cfg(feature = "test-control")]
        test_control::set_tray(view);
        match self.tray.as_ref() {
            Some(tray) => tray.update(view),
            None => self.tray = Some(Tray::new(view)),
        }
    }

    /// GNOME apps have no app menu; the editor's commands are its buttons
    /// and Ctrl+S.
    fn set_menu(&mut self, _menu: &MenuView) {}

    fn open_installer(&mut self, path: &std::path::Path) -> Result<(), String> {
        launch_default(&gtk::gio::File::for_path(path).uri())
    }

    fn open_url(&mut self, url: &str) -> Result<(), String> {
        launch_default(url)
    }

    fn set_appearance(&mut self, appearance: Appearance) {
        adw::StyleManager::default().set_color_scheme(match appearance {
            Appearance::System => adw::ColorScheme::Default,
            Appearance::Light => adw::ColorScheme::ForceLight,
            Appearance::Dark => adw::ColorScheme::ForceDark,
        });
    }

    fn settle(&mut self) {
        if let Some(window) = self.window.as_ref() {
            window.settle();
        }
        if let Some(editor) = self.editor.as_ref() {
            editor.surface.settle();
        }
    }

    fn bring_to_front(&mut self) {
        if let Some(window) = self.window.as_ref() {
            window.present(take_token().as_deref());
        }
    }

    fn exit(&mut self) {
        // The windows' sizes are kept for the next launch, as closing them
        // keeps them; quitting closes neither.
        if let Some(window) = self.window.as_mut() {
            window.close_dialog();
            window.remember();
        }
        if let Some(editor) = self.editor.as_ref() {
            editor.remember();
        }
        self.tray = None;
        self.app.quit();
    }
}

/// The app's name on the session bus, which keeps one instance per data
/// directory: the installed app's, or one of its own for each data
/// directory a development instance sets (`EGRIO_DATA_DIR`).
fn application_id() -> String {
    match std::env::var_os("EGRIO_DATA_DIR").filter(|directory| !directory.is_empty()) {
        None => APPLICATION_ID.into(),
        Some(directory) => {
            // FNV-1a: a stable name for the same directory in every launch.
            let hash = directory
                .as_encoded_bytes()
                .iter()
                .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                    (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
                });
            format!("{APPLICATION_ID}.data_{hash:016x}")
        }
    }
}

/// Startup that reads no configuration first: the previous session's OS
/// changes are restored before the profile store is read and the Runtime
/// host initialized.
async fn finish_startup(runtime: DesktopRuntime) -> Result<(), String> {
    runtime
        .recover_platform_before_configuration()
        .await
        .map_err(|error| format!("restore previous network session: {error}"))?;
    let _host_transition = runtime.begin_host_transition().await?;
    runtime.initialize().await?;
    Ok(())
}

/// Tells the user why the app could not start, then ends it.
fn fail(message: &str) {
    log::error!("desktop startup failed: {message}");
    let alert = gtk::AlertDialog::builder()
        .modal(true)
        .message("Egrio")
        .detail(format!(
            "启动未完成，原配置数据已保留。请处理以下错误后重新启动。\n{message}"
        ))
        .build();
    alert.choose(None::<&gtk::Window>, None::<&gio::Cancellable>, |_| {
        std::process::exit(1)
    });
}

async fn start(app: adw::Application) {
    let runtime = match DesktopRuntime::new() {
        Ok(runtime) => runtime,
        Err(error) => return fail(&error),
    };
    let history = Arc::new(Mutex::new(ConnectionHistory::default()));
    egrio_desktop::async_runtime::spawn(
        egrio_desktop::operations::telemetry::absorb_connection_history(
            runtime.clone(),
            history.clone(),
        ),
    );
    egrio_desktop::system_proxy_guard::init(&runtime);
    egrio_desktop::policy_watch::init(&runtime);
    let desktop = Desktop {
        runtime: runtime.clone(),
        history,
    };
    match egrio_desktop::async_runtime::spawn(finish_startup(runtime)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return fail(&error),
        Err(error) => return fail(&error.to_string()),
    }
    let silent = egrio_desktop::desktop_behavior::load_silent_start().unwrap_or(false);
    let backend = LinuxBackend {
        app,
        window: None,
        editor: None,
        tray: None,
    };
    UI.with(|ui| *ui.borrow_mut() = Some(Ui::new(backend, desktop, Arc::new(wake))));
    with_ui(|ui| ui.start(!silent));
    #[cfg(feature = "test-control")]
    if let Ok(directory) = egrio_desktop::app_paths::app_data_dir() {
        test_control::start(directory);
    }
    log::info!("Egrio {} started", env!("CARGO_PKG_VERSION"));
}

/// Another launch activated the app: it shows its window. The activation is
/// handled at once, inside the signal, so the window takes the activation
/// token GTK holds for it only that long.
fn reopen() {
    UI.with(|ui| match ui.try_borrow_mut() {
        Ok(mut ui) => {
            if let Some(ui) = ui.as_mut() {
                ui.handle(UiEvent::Reopen);
            }
        }
        Err(_) => post(UiEvent::Reopen),
    });
}

/// A request to end the process (SIGTERM, SIGINT, SIGHUP) ends it the way
/// Quit does, after the capture layers are turned off.
fn quit_on_signals() {
    use tokio::signal::unix::{signal, SignalKind};
    for kind in [
        SignalKind::terminate(),
        SignalKind::interrupt(),
        SignalKind::hangup(),
    ] {
        egrio_desktop::async_runtime::spawn(async move {
            let Ok(mut signals) = signal(kind) else {
                log::warn!("couldn't listen for signal {}", kind.as_raw_value());
                return;
            };
            while signals.recv().await.is_some() {
                on_main(|| post(UiEvent::QuitRequested));
            }
        });
    }
}

/// What GNOME apps bind: Ctrl+Q quits, Ctrl+W closes the window a user
/// works in, which the window's own close request then decides on.
fn install_shortcuts(app: &adw::Application) {
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(|_, _| post(UiEvent::QuitRequested));
    app.add_action(&quit);
    app.set_accels_for_action("app.quit", &["<Ctrl>q"]);
    let close = gio::SimpleAction::new("close-window", None);
    let windows = app.clone();
    close.connect_activate(move |_, _| {
        if let Some(window) = windows.active_window() {
            window.close();
        }
    });
    app.add_action(&close);
    app.set_accels_for_action("app.close-window", &["<Ctrl>w"]);
}

pub fn run() {
    let app = adw::Application::builder()
        .application_id(application_id())
        .build();
    if let Err(error) = app.register(None::<&gio::Cancellable>) {
        log::error!("desktop startup failed: register on the session bus: {error}");
        std::process::exit(1);
    }
    if app.is_remote() {
        log::info!("Egrio is running already, so this launch shows its window and ends");
        app.run_with_args(&[] as &[&str]);
        return;
    }
    // Without a session bus GApplication registers locally and every launch
    // believes it is the only one, so the data directory's lock decides.
    let _owner = match egrio_desktop::runtime_owner::acquire() {
        Ok(owner) => owner,
        Err(RuntimeOwnerError::Held(message)) => {
            log::info!("Egrio is running already, so this process ends: {message}");
            return;
        }
        Err(error) => {
            log::error!("desktop startup failed: {error}");
            std::process::exit(1);
        }
    };
    // Registering ran the application's startup, which opened the display.
    match gdk::Display::default() {
        Some(display) => style::install(&display),
        None => {
            log::error!("desktop startup failed: no display");
            std::process::exit(1);
        }
    }
    // The app keeps running with no window: the tray and the Core stay.
    let _hold = app.hold();
    app.connect_activate(|_| reopen());
    install_shortcuts(&app);
    quit_on_signals();
    glib::MainContext::default().spawn_local(start(app.clone()));
    app.run_with_args(&[] as &[&str]);
}
