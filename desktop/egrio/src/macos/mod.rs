//! The macOS app: AppKit realizes the interface `egrio-ui` describes. The
//! interface runtime lives on the main thread; messages from the desktop
//! runtime and events from the native controls each schedule one drain on
//! the main queue, so no native callback runs inside a render.

mod app;
mod button;
mod chart;
mod editor;
mod hover_help;
mod messages;
mod panels;
mod popover;
mod style;
mod table;
mod target;
#[cfg(feature = "test-control")]
mod test_control;
mod text;
mod text_editor;
mod tiles;
mod tray;
mod widgets;
mod window;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use objc2_app_kit::{
    NSAlert, NSAppearance, NSAppearanceName, NSAppearanceNameAqua, NSAppearanceNameDarkAqua,
    NSApplication, NSApplicationActivationPolicy,
};
use objc2_foundation::NSString;

use egrio_desktop::connection_history::ConnectionHistory;
use egrio_desktop::runtime::DesktopRuntime;
use egrio_desktop::runtime_owner::RuntimeOwnerError;
use egrio_ui::backend::{
    Appearance, Backend, EditorView, FileRequest, MainView, MenuView, Surface, TrayView, UiEvent,
};
use egrio_ui::reconcile::{Mounted, Patch};
use egrio_ui::runtime::{Desktop, Ui};

use editor::EditorWindow;
use tray::Tray;
use window::MainWindow;

thread_local! {
    static UI: RefCell<Option<Ui<MacBackend>>> = const { RefCell::new(None) };
    static EVENTS: RefCell<VecDeque<UiEvent>> = const { RefCell::new(VecDeque::new()) };
    static EVENTS_SCHEDULED: Cell<bool> = const { Cell::new(false) };
}

static DRAIN_SCHEDULED: AtomicBool = AtomicBool::new(false);

/// Queues a native event for the runtime; it runs after the current call stack.
pub fn post(event: UiEvent) {
    EVENTS.with(|events| events.borrow_mut().push_back(event));
    if !EVENTS_SCHEDULED.replace(true) {
        DispatchQueue::main().exec_async(|| {
            EVENTS_SCHEDULED.set(false);
            while let Some(event) = EVENTS.with(|events| events.borrow_mut().pop_front()) {
                with_ui(|ui| ui.handle(event));
            }
        });
    }
}

/// Wakes the main thread to read the runtime's inbox; callable from any thread.
fn wake() {
    if !DRAIN_SCHEDULED.swap(true, Ordering::AcqRel) {
        DispatchQueue::main().exec_async(|| {
            DRAIN_SCHEDULED.store(false, Ordering::Release);
            with_ui(|ui| ui.drain());
        });
    }
}

fn with_ui(work: impl FnOnce(&mut Ui<MacBackend>)) {
    UI.with(|ui| {
        if let Some(ui) = ui.borrow_mut().as_mut() {
            work(ui);
        }
    });
}

pub struct MacBackend {
    mtm: MainThreadMarker,
    window: Option<MainWindow>,
    /// The open editor window.
    editor: Option<EditorWindow>,
    tray: Option<Tray>,
}

/// Opens a file or a page with its default app (`NSWorkspace openURL:`).
fn open(url: &objc2_foundation::NSURL) -> bool {
    objc2_app_kit::NSWorkspace::sharedWorkspace().openURL(url)
}

impl Backend for MacBackend {
    fn open_main(&mut self, view: &MainView, content: &Mounted, drawer: &Mounted) {
        self.window = Some(MainWindow::open(self.mtm, view, content, drawer, post));
        self.follow_windows(true);
    }

    fn close_main(&mut self) {
        if let Some(window) = self.window.take() {
            window.close();
        }
        self.follow_windows(false);
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
                    if let Some(dialog) = window.dialog.as_mut() {
                        dialog.surface.apply(patches);
                    }
                }
                Surface::Editor => {}
            }
        }
    }

    fn set_tray(&mut self, view: &TrayView) {
        match self.tray.as_mut() {
            Some(tray) => tray.update(self.mtm, view),
            None => self.tray = Some(Tray::new(self.mtm, view, post)),
        }
    }

    fn open_dialog(&mut self, dialog: &Mounted) {
        if let Some(window) = self.window.as_mut() {
            window.open_dialog(self.mtm, dialog, post);
        }
    }

    fn close_dialog(&mut self) {
        if let Some(window) = self.window.as_mut() {
            window.close_dialog();
        }
    }

    fn choose_file(&mut self, request: &FileRequest) {
        match self.window.as_ref() {
            Some(window) => panels::choose_file(self.mtm, window.sheet_parent(), request, post),
            // Nothing to ask over: no file.
            None => post(UiEvent::FileChosen {
                purpose: request.purpose,
                path: None,
            }),
        }
    }

    fn open_editor(&mut self, view: &EditorView, content: &Mounted) {
        if let Some(editor) = self.editor.take() {
            editor.close();
        }
        let over = self.window.as_ref().map(MainWindow::window);
        self.editor = Some(EditorWindow::open(self.mtm, over, view, content, post));
        self.follow_windows(true);
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
        self.follow_windows(false);
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

    fn set_menu(&mut self, menu: &MenuView) {
        app::install_menu(self.mtm, menu);
    }

    fn set_appearance(&mut self, appearance: Appearance) {
        let named = |name: &NSAppearanceName| NSAppearance::appearanceNamed(name);
        let appearance = match appearance {
            Appearance::System => None,
            Appearance::Light => named(unsafe { NSAppearanceNameAqua }),
            Appearance::Dark => named(unsafe { NSAppearanceNameDarkAqua }),
        };
        NSApplication::sharedApplication(self.mtm).setAppearance(appearance.as_deref());
    }

    fn open_installer(&mut self, path: &std::path::Path) -> Result<(), String> {
        let url =
            objc2_foundation::NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()));
        open(&url)
            .then_some(())
            .ok_or_else(|| format!("macOS could not open {}", path.display()))
    }

    fn open_url(&mut self, url: &str) -> Result<(), String> {
        objc2_foundation::NSURL::URLWithString(&NSString::from_str(url))
            .filter(|url| open(url))
            .map(|_| ())
            .ok_or_else(|| format!("macOS could not open {url}"))
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
        #[allow(deprecated)]
        NSApplication::sharedApplication(self.mtm).activateIgnoringOtherApps(true);
        if let Some(window) = self.window.as_ref() {
            window.bring_to_front();
        }
    }

    fn exit(&mut self) {
        // AppKit does not terminate while a sheet is attached to a window.
        if let Some(window) = self.window.as_mut() {
            window.close_dialog();
        }
        app::finish_termination(self.mtm);
    }
}

impl MacBackend {
    /// In the Dock only while a window exists: the main window or the
    /// editor. A window that just opened brings the app forward.
    fn follow_windows(&self, opened: bool) {
        let app = NSApplication::sharedApplication(self.mtm);
        let policy = if self.window.is_some() || self.editor.is_some() {
            NSApplicationActivationPolicy::Regular
        } else {
            NSApplicationActivationPolicy::Accessory
        };
        app.setActivationPolicy(policy);
        if opened {
            #[allow(deprecated)]
            app.activateIgnoringOtherApps(true);
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

fn fail(mtm: MainThreadMarker, message: &str) -> ! {
    log::error!("desktop startup failed: {message}");
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Egrio"));
    alert.setInformativeText(&NSString::from_str(&format!(
        "启动未完成，原配置数据已保留。请处理以下错误后重新启动。\n{message}"
    )));
    alert.runModal();
    std::process::exit(1);
}

pub fn run() {
    let mtm = MainThreadMarker::new().expect("the app runs on the main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let _delegate = app::AppDelegate::install(mtm, post);

    let _owner = match egrio_desktop::runtime_owner::acquire() {
        Ok(owner) => owner,
        // A launch LaunchServices routes to the running app never gets here;
        // another process of this user has nothing to do.
        Err(RuntimeOwnerError::Held(message)) => {
            log::info!("Egrio is running already, so this process ends: {message}");
            std::process::exit(0);
        }
        Err(error) => fail(mtm, &error.to_string()),
    };
    let runtime = DesktopRuntime::new().unwrap_or_else(|error| fail(mtm, &error));
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
    egrio_desktop::async_runtime::spawn(async move {
        let started = finish_startup(runtime).await;
        DispatchQueue::main().exec_async(move || {
            let mtm = MainThreadMarker::new().expect("main queue");
            if let Err(error) = started {
                fail(mtm, &error);
            }
            let silent = egrio_desktop::desktop_behavior::load_silent_start().unwrap_or(false);
            let backend = MacBackend {
                mtm,
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
        });
    });

    app.run();
}
