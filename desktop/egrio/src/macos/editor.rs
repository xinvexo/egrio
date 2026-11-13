//! The editor window: a document window of its own, opened over the main
//! window. Its title is the profile's name, its close button carries the
//! unsaved mark, its toolbar holds the commands, and the File menu's Save and
//! Revert reach it through the responder chain. Closing asks the interface,
//! which closes the window in its render.
//!
//! It locks nothing: `terminate:` does nothing while a sheet is attached to
//! any window, so a sheet holding the main window would keep the app from
//! quitting for as long as the editor is open.

use std::cell::Cell;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, sel, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSBezelStyle, NSButton, NSControlSize, NSMenuItem,
    NSMenuItemValidation, NSToolbar, NSToolbarDelegate, NSToolbarDisplayMode,
    NSToolbarFlexibleSpaceItemIdentifier, NSToolbarItem, NSToolbarItemIdentifier,
    NSUserInterfaceItemIdentification, NSView, NSWindow, NSWindowDelegate, NSWindowStyleMask,
    NSWindowToolbarStyle,
};
use objc2_foundation::{NSArray, NSCopying, NSObject, NSPoint, NSRect, NSSize, NSString};

use egrio_ui::backend::{EditorAction, EditorCommand, EditorView, UiEvent};
use egrio_ui::reconcile::Mounted;

use super::target::ActionTarget;
use super::text_editor;
use super::widgets::Surface;

/// What test control and the frame autosave know the window by.
pub const IDENTIFIER: &str = "egrio.editor";
const FRAME_NAME: &str = "EgrioEditor";
const REVERT: &str = "egrio.editor.revert";
const SAVE: &str = "egrio.editor.save";

pub struct ControllerIvars {
    post: fn(UiEvent),
    revert: Retained<NSButton>,
    save: Retained<NSButton>,
    /// What the File menu's items may do, as the window's view says.
    can_revert: Cell<bool>,
    can_save: Cell<bool>,
    _targets: Vec<Retained<ActionTarget>>,
}

define_class!(
    /// The editor window's delegate, its toolbar's delegate, and the
    /// responder the File menu's Save and Revert reach.
    #[unsafe(super(NSObject))]
    #[name = "EgrioEditorController"]
    #[thread_kind = MainThreadOnly]
    #[ivars = ControllerIvars]
    pub struct EditorController;

    unsafe impl NSObjectProtocol for EditorController {}

    unsafe impl NSWindowDelegate for EditorController {
        #[unsafe(method(windowShouldClose:))]
        fn should_close(&self, _window: &NSWindow) -> bool {
            (self.ivars().post)(UiEvent::Editor(EditorAction::Close));
            false
        }
    }

    unsafe impl NSToolbarDelegate for EditorController {
        #[unsafe(method_id(toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:))]
        fn item_for(
            &self,
            _toolbar: &NSToolbar,
            identifier: &NSToolbarItemIdentifier,
            _inserted: bool,
        ) -> Option<Retained<NSToolbarItem>> {
            self.make_item(identifier)
        }

        #[unsafe(method_id(toolbarDefaultItemIdentifiers:))]
        fn default_items(&self, _toolbar: &NSToolbar) -> Retained<NSArray<NSToolbarItemIdentifier>> {
            identifiers()
        }

        #[unsafe(method_id(toolbarAllowedItemIdentifiers:))]
        fn allowed_items(&self, _toolbar: &NSToolbar) -> Retained<NSArray<NSToolbarItemIdentifier>> {
            identifiers()
        }
    }

    unsafe impl NSMenuItemValidation for EditorController {
        #[unsafe(method(validateMenuItem:))]
        fn validate_menu_item(&self, item: &NSMenuItem) -> bool {
            let action = item.action();
            if action == Some(sel!(saveDocument:)) {
                self.ivars().can_save.get()
            } else if action == Some(sel!(revertDocumentToSaved:)) {
                self.ivars().can_revert.get()
            } else {
                true
            }
        }
    }

    impl EditorController {
        #[unsafe(method(saveDocument:))]
        fn save_document(&self, _sender: Option<&AnyObject>) {
            if self.ivars().can_save.get() {
                (self.ivars().post)(UiEvent::Editor(EditorAction::Save));
            }
        }

        #[unsafe(method(revertDocumentToSaved:))]
        fn revert_document(&self, _sender: Option<&AnyObject>) {
            if self.ivars().can_revert.get() {
                (self.ivars().post)(UiEvent::Editor(EditorAction::Revert));
            }
        }
    }
);

fn identifiers() -> Retained<NSArray<NSToolbarItemIdentifier>> {
    NSArray::from_retained_slice(&[
        unsafe { NSToolbarFlexibleSpaceItemIdentifier.copy() },
        NSString::from_str(REVERT),
        NSString::from_str(SAVE),
    ])
}

impl EditorController {
    fn make_item(&self, identifier: &NSToolbarItemIdentifier) -> Option<Retained<NSToolbarItem>> {
        let ivars = self.ivars();
        let button = match identifier.to_string().as_str() {
            REVERT => &ivars.revert,
            SAVE => &ivars.save,
            _ => return None,
        };
        let item = NSToolbarItem::initWithItemIdentifier(
            NSToolbarItem::alloc(MainThreadMarker::from(self)),
            identifier,
        );
        item.setView(Some(button));
        Some(item)
    }

    fn new(mtm: MainThreadMarker, post: fn(UiEvent)) -> Retained<Self> {
        let command = |action: EditorAction| {
            let button = NSButton::new(mtm);
            button.setBezelStyle(NSBezelStyle::Toolbar);
            button.setControlSize(NSControlSize::Small);
            let target = ActionTarget::new(mtm, move |_| post(UiEvent::Editor(action)));
            let object: &AnyObject = target.as_ref();
            unsafe {
                button.setTarget(Some(object));
                button.setAction(Some(ActionTarget::selector()));
            }
            (button, target)
        };
        let (revert, revert_target) = command(EditorAction::Revert);
        let (save, save_target) = command(EditorAction::Save);
        let this = Self::alloc(mtm).set_ivars(ControllerIvars {
            post,
            revert,
            save,
            can_revert: Cell::new(false),
            can_save: Cell::new(false),
            _targets: vec![revert_target, save_target],
        });
        unsafe { msg_send![super(this), init] }
    }
}

/// Centers `window` over `other`, inside the visible part of `other`'s
/// screen.
fn center_over(window: &NSWindow, other: &NSWindow) {
    let over = other.frame();
    let visible = other.screen().map(|screen| screen.visibleFrame());
    let mut frame = window.frame();
    if let Some(visible) = visible {
        frame.size.width = frame.size.width.min(visible.size.width);
        frame.size.height = frame.size.height.min(visible.size.height);
    }
    frame.origin.x = over.origin.x + (over.size.width - frame.size.width) / 2.0;
    frame.origin.y = over.origin.y + (over.size.height - frame.size.height) / 2.0;
    if let Some(visible) = visible {
        let right = visible.origin.x + visible.size.width - frame.size.width;
        let top = visible.origin.y + visible.size.height - frame.size.height;
        frame.origin.x = frame.origin.x.clamp(visible.origin.x, right);
        frame.origin.y = frame.origin.y.clamp(visible.origin.y, top);
    }
    window.setFrame_display(frame, false);
}

fn style_command(button: &NSButton, command: &EditorCommand) {
    button.setTitle(&NSString::from_str(&command.label));
    button.setEnabled(command.enabled);
}

pub struct EditorWindow {
    window: Retained<NSWindow>,
    controller: Retained<EditorController>,
    _toolbar: Retained<NSToolbar>,
    pub surface: Surface,
}

impl EditorWindow {
    /// Opens the window centered over `over`, or on the screen.
    pub fn open(
        mtm: MainThreadMarker,
        over: Option<&NSWindow>,
        view: &EditorView,
        content: &Mounted,
        post: fn(UiEvent),
    ) -> Self {
        let style =
            NSWindowStyleMask::Titled | NSWindowStyleMask::Closable | NSWindowStyleMask::Resizable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(760.0, 620.0)),
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { window.setReleasedWhenClosed(false) };
        window.setIdentifier(Some(&NSString::from_str(IDENTIFIER)));
        window.setContentMinSize(NSSize::new(480.0, 320.0));

        let controller = EditorController::new(mtm, post);
        window.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
        let toolbar =
            NSToolbar::initWithIdentifier(NSToolbar::alloc(mtm), &NSString::from_str(FRAME_NAME));
        toolbar.setDisplayMode(NSToolbarDisplayMode::IconOnly);
        toolbar.setAllowsUserCustomization(false);
        toolbar.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
        window.setToolbar(Some(&toolbar));
        window.setToolbarStyle(NSWindowToolbarStyle::UnifiedCompact);

        let host = NSView::new(mtm);
        window.setContentView(Some(&host));
        let mut surface = Surface::new(mtm, host, post);
        surface.set_root(content, super::widgets::even_insets(0.0));

        // The size the user left the editor at, centered over the main
        // window every time.
        window.setFrameUsingName(&NSString::from_str(FRAME_NAME));
        match over {
            Some(over) => center_over(&window, over),
            None => window.center(),
        }
        window.setFrameAutosaveName(&NSString::from_str(FRAME_NAME));

        let this = Self {
            window,
            controller,
            _toolbar: toolbar,
            surface,
        };
        this.update(view);
        this.window.makeKeyAndOrderFront(None);
        this
    }

    pub fn update(&self, view: &EditorView) {
        self.window.setTitle(&NSString::from_str(&view.title));
        self.window.setDocumentEdited(view.edited);
        let ivars = self.controller.ivars();
        style_command(&ivars.revert, &view.revert);
        style_command(&ivars.save, &view.save);
        ivars.can_revert.set(view.revert.enabled);
        ivars.can_save.set(view.save.enabled);
    }

    pub fn bring_to_front(&self) {
        #[allow(deprecated)]
        NSApplication::sharedApplication(MainThreadMarker::from(&*self.window))
            .activateIgnoringOtherApps(true);
        self.window.makeKeyAndOrderFront(None);
    }

    pub fn reveal(&self, index: usize) {
        if let Some(view) = self.surface.text_editor() {
            text_editor::reveal(&view, index);
        }
    }

    pub fn close(self) {
        self.window.orderOut(None);
        // Free the autosave name for the next editor window.
        self.window.setFrameAutosaveName(&NSString::from_str(""));
    }
}
