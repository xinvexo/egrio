//! The Windows app: WinUI 3 realizes the interface `egrio-ui` describes. The
//! interface runtime lives on the UI thread; messages from the desktop
//! runtime, events from the native controls and work from other threads
//! each enqueue one drain on the thread's `DispatcherQueue`, so no native
//! callback runs inside a render. A call into the runtime can itself run a
//! nested message loop (`ShellExecuteW` waits in one while Windows asks to
//! elevate a setup program), in which queued drains find the runtime busy:
//! they wait until that call returns.

#[allow(
    clippy::all,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_qualifications
)]
mod bindings;

mod app;
mod bootstrap;
mod chart;
mod dialog;
mod editor;
mod hwnd;
mod images;
mod instance;
mod keys;
mod messages;
mod picker;
mod popover;
mod table;
#[cfg(feature = "test-control")]
mod test_control;
mod text_editor;
mod tiles;
mod title_bar;
mod tray;
mod widgets;
mod window;
mod window_state;
mod xaml;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use windows_core::Interface;

use egrio_desktop::connection_history::ConnectionHistory;
use egrio_desktop::runtime::DesktopRuntime;
use egrio_ui::backend::{
    Appearance, Backend, EditorView, FileRequest, MainView, MenuView, Surface, TrayView, UiEvent,
};
use egrio_ui::reconcile::{Mounted, Patch};
use egrio_ui::runtime::{Desktop, Ui};

use bindings::{
    CoInitializeEx, DispatcherQueue, DispatcherQueueHandler, DispatcherQueuePriority, IWindow2,
    COINIT_APARTMENTTHREADED,
};
use editor::EditorWindow;
use tray::Tray;
use widgets::check;
use window::MainWindow;

thread_local! {
    static UI: RefCell<Option<Ui<WindowsBackend>>> = const { RefCell::new(None) };
    static EVENTS: RefCell<VecDeque<UiEvent>> = const { RefCell::new(VecDeque::new()) };
    static EVENTS_SCHEDULED: Cell<bool> = const { Cell::new(false) };
    /// A drain found the runtime busy below a nested message loop.
    static MISSED: Cell<bool> = const { Cell::new(false) };
}

/// The UI thread's queue, which any thread may enqueue work on.
static QUEUE: OnceLock<DispatcherQueue> = OnceLock::new();
static DRAIN_SCHEDULED: AtomicBool = AtomicBool::new(false);

/// Runs `work` on the UI thread after what it is doing; callable from any
/// thread.
fn on_main(work: impl FnOnce() + Send + 'static) {
    let Some(queue) = QUEUE.get() else {
        log::warn!("work for the UI thread arrived before it was ready");
        return;
    };
    let work = Mutex::new(Some(work));
    let handler = DispatcherQueueHandler::new(move || {
        if let Some(work) = work.lock().ok().and_then(|mut work| work.take()) {
            work();
        }
    });
    if !matches!(
        queue.TryEnqueueWithPriority(DispatcherQueuePriority::Normal, &handler),
        Ok(true)
    ) {
        log::warn!("the UI thread's queue refused work; the app is shutting down");
    }
}

/// Queues a native event for the runtime; it runs after the current call
/// stack. UI thread only.
pub fn post(event: UiEvent) {
    EVENTS.with(|events| events.borrow_mut().push_back(event));
    schedule_events();
}

fn schedule_events() {
    if !EVENTS_SCHEDULED.replace(true) {
        on_main(|| {
            EVENTS_SCHEDULED.set(false);
            with_ui(|ui| {
                while let Some(event) = EVENTS.with(|events| events.borrow_mut().pop_front()) {
                    ui.handle(event);
                }
            });
        });
    }
}

/// Wakes the UI thread to read the runtime's inbox; callable from any thread.
fn wake() {
    if !DRAIN_SCHEDULED.swap(true, Ordering::AcqRel) {
        on_main(|| {
            DRAIN_SCHEDULED.store(false, Ordering::Release);
            with_ui(|ui| ui.drain());
        });
    }
}

/// Runs `work` with the runtime; when the runtime is busy below a nested
/// message loop, the drains it missed are queued again once it returns.
fn with_ui(work: impl FnOnce(&mut Ui<WindowsBackend>)) {
    let ran = UI.with(|ui| {
        let Ok(mut ui) = ui.try_borrow_mut() else {
            return false;
        };
        if let Some(ui) = ui.as_mut() {
            work(ui);
        }
        true
    });
    if !ran {
        MISSED.set(true);
    } else if MISSED.replace(false) {
        wake();
        schedule_events();
    }
}

pub struct WindowsBackend {
    window: Option<MainWindow>,
    /// The open editor window.
    editor: Option<EditorWindow>,
    tray: Option<Tray>,
    appearance: Appearance,
}

/// The installer's switch for updating the installed app: it only shows its
/// progress, then starts the app again (`desktop/egrio/windows/installer.nsi`).
const INSTALLER_UPDATE: &str = "/UPDATE";

/// Opens a file or a page with its default app, the shell's open verb
/// (`ShellExecuteW`, which answers above 32 when it did): a setup program
/// runs with `parameters`, a page opens in the browser.
fn shell_open(target: &std::ffi::OsStr, parameters: Option<&str>) -> Result<(), String> {
    let wide = windows_core::HSTRING::from(target);
    let parameters = parameters.map(windows_core::HSTRING::from);
    // SAFETY: null-terminated strings that outlive the call.
    let result = unsafe {
        bindings::ShellExecuteW(
            std::ptr::null_mut(),
            windows_core::w!("open"),
            windows_core::PCWSTR(wide.as_ptr()),
            parameters
                .as_ref()
                .map_or(windows_core::PCWSTR::null(), |parameters| {
                    windows_core::PCWSTR(parameters.as_ptr())
                }),
            windows_core::PCWSTR::null(),
            bindings::SW_SHOWNORMAL,
        )
    };
    if result as isize > 32 {
        Ok(())
    } else {
        Err(format!(
            "Windows could not open {} ({})",
            target.display(),
            result as isize
        ))
    }
}

impl Backend for WindowsBackend {
    fn open_main(&mut self, view: &MainView, content: &Mounted, drawer: &Mounted) {
        match MainWindow::open(view, content, drawer, self.appearance, post) {
            Ok(window) => self.window = Some(window),
            Err(error) => {
                log::error!("open the main window: {error}");
                // The interface must not go on thinking it has a window;
                // it hears of this one as it would of the user's close.
                post(UiEvent::WindowClosed);
            }
        }
    }

    fn close_main(&mut self) {
        if let Some(window) = self.window.take() {
            window.close();
        }
    }

    fn update_main(&mut self, view: &MainView) {
        if let Some(window) = self.window.as_mut() {
            check(window.update(view), "update the main window");
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

    fn set_tray(&mut self, view: &TrayView) {
        match self.tray.as_ref() {
            Some(tray) => tray.update(view),
            None => match Tray::new(view, post) {
                Ok(tray) => self.tray = Some(tray),
                Err(error) => log::error!("add the notification area icon: {error}"),
            },
        }
    }

    fn open_dialog(&mut self, dialog: &Mounted) {
        if let Some(window) = self.window.as_mut() {
            check(
                window.open_dialog(dialog, self.appearance),
                "open the dialog",
            );
        }
    }

    fn close_dialog(&mut self) {
        if let Some(window) = self.window.as_mut() {
            window.close_dialog();
        }
    }

    fn choose_file(&mut self, request: &FileRequest) {
        let owner = self
            .window
            .as_ref()
            .map(MainWindow::window)
            .or(self.editor.as_ref().map(EditorWindow::window))
            .and_then(|window| window.cast::<IWindow2>().ok()?.AppWindow().ok()?.Id().ok());
        let asked = owner.map(|owner| picker::choose_file(owner, request));
        if !matches!(asked, Some(Ok(()))) {
            if let Some(Err(error)) = asked {
                log::warn!("open the file picker: {error}");
            }
            // Nothing to ask over: no file.
            post(UiEvent::FileChosen {
                purpose: request.purpose,
                path: None,
            });
        }
    }

    fn open_editor(&mut self, view: &EditorView, content: &Mounted) {
        if let Some(editor) = self.editor.take() {
            editor.close();
        }
        let over = self.window.as_ref().map(MainWindow::window);
        match EditorWindow::open(over, view, content, self.appearance, post) {
            Ok(editor) => self.editor = Some(editor),
            Err(error) => log::error!("open the editor window: {error}"),
        }
    }

    fn update_editor(&mut self, view: &EditorView) {
        if let Some(editor) = self.editor.as_ref() {
            check(editor.update(view), "update the editor window");
        }
    }

    fn close_editor(&mut self) {
        if let Some(editor) = self.editor.take() {
            editor.close();
        }
    }

    fn bring_editor_to_front(&mut self) {
        if let Some(editor) = self.editor.as_ref() {
            editor.bring_to_front();
        }
    }

    fn reveal_in_editor(&mut self, index: usize) {
        if let Some(editor) = self.editor.as_ref() {
            editor.reveal(index);
        }
    }

    /// Windows apps have no app menu; the editor's commands are its buttons
    /// and Ctrl+S.
    fn set_menu(&mut self, _menu: &MenuView) {}

    fn open_installer(&mut self, path: &std::path::Path) -> Result<(), String> {
        shell_open(path.as_os_str(), Some(INSTALLER_UPDATE))
    }

    fn open_url(&mut self, url: &str) -> Result<(), String> {
        shell_open(std::ffi::OsStr::new(url), None)
    }

    fn set_appearance(&mut self, appearance: Appearance) {
        self.appearance = appearance;
        if let Some(window) = self.window.as_ref() {
            check(
                window.set_appearance(appearance),
                "set the main window's theme",
            );
        }
        if let Some(editor) = self.editor.as_ref() {
            check(editor.set_appearance(appearance), "set the editor's theme");
        }
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
            check(window.bring_to_front(), "bring the main window forward");
        }
    }

    fn exit(&mut self) {
        if let Some(window) = self.window.as_mut() {
            window.remember_place();
            window.close_dialog();
        }
        if let Some(editor) = self.editor.as_ref() {
            editor.remember_place();
        }
        self.tray = None;
        if tray::session_ending() {
            // The cleanup is done; Windows ends the process with the session.
            log::info!("the session's end quit is done");
            std::process::exit(0);
        }
        app::exit();
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

pub fn run() {
    if let Err(error) = bootstrap::initialize() {
        bootstrap::fail(&error);
    }
    // Before the UI thread's apartment: a second process waits here while
    // it hands its activation to the first.
    let _instance = instance::claim()
        .unwrap_or_else(|error| bootstrap::fail(&format!("app instancing: {error}")));
    // SAFETY: before any window; WinUI runs in a single-threaded apartment.
    unsafe {
        let _ = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }
    let runtime = DesktopRuntime::new().unwrap_or_else(|error| bootstrap::fail(&error));
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

    let result = app::run(move || {
        match DispatcherQueue::GetForCurrentThread() {
            Ok(queue) => {
                let _ = QUEUE.set(queue);
            }
            Err(error) => bootstrap::fail(&format!("the UI thread's queue: {error}")),
        }
        egrio_desktop::async_runtime::spawn(async move {
            let started = finish_startup(runtime).await;
            on_main(move || {
                if let Err(error) = started {
                    bootstrap::fail(&error);
                }
                let silent = egrio_desktop::desktop_behavior::load_silent_start().unwrap_or(false);
                let backend = WindowsBackend {
                    window: None,
                    editor: None,
                    tray: None,
                    appearance: Appearance::System,
                };
                UI.with(|ui| *ui.borrow_mut() = Some(Ui::new(backend, desktop, Arc::new(wake))));
                with_ui(|ui| ui.start(!silent));
                #[cfg(feature = "test-control")]
                if let Ok(directory) = egrio_desktop::app_paths::app_data_dir() {
                    test_control::start(directory);
                }
                log::info!("Egrio {} started", env!("CARGO_PKG_VERSION"));
            });
        });
    });
    if let Err(error) = result {
        bootstrap::fail(&format!("WinUI: {error}"));
    }
}
