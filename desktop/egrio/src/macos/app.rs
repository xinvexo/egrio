//! The application delegate and the menu bar. A quit from the app menu, the
//! Dock or the OS goes through `applicationShouldTerminate:`: until the quit's
//! cleanup has stopped the Runtime the app answers `NSTerminateLater`, then
//! replies once the cleanup is done.

use std::cell::Cell;

use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, sel, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationDelegate, NSApplicationTerminateReply, NSMenu, NSMenuItem,
};
use objc2_foundation::{NSObject, NSString};

use egrio_ui::backend::{MenuView, UiEvent};

thread_local! {
    /// An `NSTerminateLater` answer awaits its reply.
    static TERMINATE_PENDING: Cell<bool> = const { Cell::new(false) };
}

pub struct AppIvars {
    post: fn(UiEvent),
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioAppDelegate"]
    #[thread_kind = MainThreadOnly]
    #[ivars = AppIvars]
    pub struct AppDelegate;

    unsafe impl NSObjectProtocol for AppDelegate {}

    unsafe impl NSApplicationDelegate for AppDelegate {
        #[unsafe(method(applicationShouldTerminate:))]
        fn should_terminate(&self, _app: &NSApplication) -> NSApplicationTerminateReply {
            if egrio_desktop::exit::is_ready_to_exit() {
                return NSApplicationTerminateReply::TerminateNow;
            }
            TERMINATE_PENDING.set(true);
            (self.ivars().post)(UiEvent::QuitRequested);
            NSApplicationTerminateReply::TerminateLater
        }

        #[unsafe(method(applicationShouldHandleReopen:hasVisibleWindows:))]
        fn should_reopen(&self, _app: &NSApplication, _visible: bool) -> bool {
            (self.ivars().post)(UiEvent::Reopen);
            false
        }

        #[unsafe(method(applicationShouldTerminateAfterLastWindowClosed:))]
        fn terminate_after_last_window(&self, _app: &NSApplication) -> bool {
            false
        }
    }
);

impl AppDelegate {
    pub fn install(mtm: MainThreadMarker, post: fn(UiEvent)) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(AppIvars { post });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        NSApplication::sharedApplication(mtm).setDelegate(Some(ProtocolObject::from_ref(&*this)));
        this
    }
}

/// Ends the process once the quit's cleanup is done.
pub fn finish_termination(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    if TERMINATE_PENDING.replace(false) {
        app.replyToApplicationShouldTerminate(true);
    } else {
        app.terminate(None);
    }
}

fn item(
    mtm: MainThreadMarker,
    title: &str,
    action: Option<objc2::runtime::Sel>,
    key: &str,
) -> Retained<NSMenuItem> {
    unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            action,
            &NSString::from_str(key),
        )
    }
}

fn submenu(
    mtm: MainThreadMarker,
    title: &str,
    items: Vec<Retained<NSMenuItem>>,
) -> Retained<NSMenuItem> {
    let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str(title));
    for entry in &items {
        menu.addItem(entry);
    }
    let holder = item(mtm, title, None, "");
    holder.setSubmenu(Some(&menu));
    holder
}

/// The app, File, Edit and Window menus; their items reach the first
/// responder. The File menu's Save and Revert act on the editor window.
pub fn install_menu(mtm: MainThreadMarker, view: &MenuView) {
    let main = NSMenu::new(mtm);
    main.addItem(&submenu(
        mtm,
        "Egrio",
        vec![
            item(mtm, &view.hide, Some(sel!(hide:)), "h"),
            NSMenuItem::separatorItem(mtm),
            item(mtm, &view.quit, Some(sel!(terminate:)), "q"),
        ],
    ));
    main.addItem(&submenu(
        mtm,
        &view.file,
        vec![
            item(mtm, &view.save, Some(sel!(saveDocument:)), "s"),
            item(mtm, &view.revert, Some(sel!(revertDocumentToSaved:)), ""),
            NSMenuItem::separatorItem(mtm),
            item(mtm, &view.close, Some(sel!(performClose:)), "w"),
        ],
    ));
    main.addItem(&submenu(
        mtm,
        &view.edit,
        vec![
            item(mtm, &view.undo, Some(sel!(undo:)), "z"),
            item(mtm, &view.redo, Some(sel!(redo:)), "Z"),
            NSMenuItem::separatorItem(mtm),
            item(mtm, &view.cut, Some(sel!(cut:)), "x"),
            item(mtm, &view.copy, Some(sel!(copy:)), "c"),
            item(mtm, &view.paste, Some(sel!(paste:)), "v"),
            item(mtm, &view.select_all, Some(sel!(selectAll:)), "a"),
        ],
    ));
    main.addItem(&submenu(
        mtm,
        &view.window,
        vec![item(
            mtm,
            &view.minimize,
            Some(sel!(performMiniaturize:)),
            "m",
        )],
    ));
    NSApplication::sharedApplication(mtm).setMainMenu(Some(&main));
}
