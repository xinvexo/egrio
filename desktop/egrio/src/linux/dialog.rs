//! A dialog over the main window: an `AdwDialog` floating in the window,
//! whose content is the dialog's component tree. It has no buttons of its
//! own; the tree's buttons act, and the interface closes the dialog. Esc,
//! which `AdwDialog` answers with a close attempt while it may not close
//! (`can-close`), presses the tree's cancel button instead, and Return in a
//! field presses its default button, which is the tree's button for Return.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::ButtonKey;
use egrio_ui::reconcile::{Mounted, Patch};

use super::widgets::{Post, Surface};

/// The space around a dialog's content.
const INSET: i32 = 24;

pub struct Dialog {
    dialog: adw::Dialog,
    surface: Rc<RefCell<Surface>>,
    /// Set while the interface closes the dialog, which then may close.
    closing: Rc<Cell<bool>>,
}

impl Dialog {
    pub fn open(parent: &adw::ApplicationWindow, tree: &Mounted, post: Post) -> Self {
        let dialog = adw::Dialog::new();
        dialog.set_presentation_mode(adw::DialogPresentationMode::Floating);
        dialog.set_can_close(false);
        let host = gtk::Box::new(gtk::Orientation::Vertical, 0);
        host.set_margin_start(INSET);
        host.set_margin_end(INSET);
        host.set_margin_top(INSET);
        host.set_margin_bottom(INSET);
        let mut surface = Surface::new(host.clone(), post);
        surface.set_root(tree);
        if let Some(width) = tree.attrs.width {
            dialog.set_content_width(width.round() as i32 + 2 * INSET);
        }
        dialog.set_child(Some(&host));
        let surface = Rc::new(RefCell::new(surface));
        let closing = Rc::new(Cell::new(false));
        {
            let surface = Rc::downgrade(&surface);
            let closing = closing.clone();
            dialog.connect_close_attempt(move |_| {
                if closing.get() {
                    return;
                }
                let cancel = surface.upgrade().and_then(|surface| {
                    surface
                        .try_borrow()
                        .ok()?
                        .button_with_key(ButtonKey::Escape)
                });
                if let Some((id, button)) = cancel {
                    if button.is_sensitive() {
                        post(UiEvent::Node {
                            id,
                            event: Event::Press,
                        });
                    }
                }
            });
        }
        let this = Self {
            dialog,
            surface,
            closing,
        };
        this.find_default();
        this.dialog.present(Some(parent));
        // The keyboard starts in the first field, as a sheet's does, rather
        // than in a selectable explanation, which would select its text.
        if let Some(field) = first_field(host.upcast_ref()) {
            this.dialog.set_focus(Some(&field));
        }
        this
    }

    pub fn apply(&self, patches: Vec<Patch>) {
        let changed = {
            let mut surface = self.surface.borrow_mut();
            surface.apply(patches);
            surface.take_changed()
        };
        if changed {
            self.find_default();
        }
    }

    /// Makes the tree's button for Return the dialog's default widget.
    fn find_default(&self) {
        let button = self
            .surface
            .borrow()
            .button_with_key(ButtonKey::Return)
            .map(|(_, button)| button);
        self.dialog.set_default_widget(button.as_ref());
    }

    pub fn settle(&self) {
        self.surface.borrow().settle();
    }

    pub fn close(self) {
        self.closing.set(true);
        self.dialog.force_close();
    }
}

/// The first text field under `root`, in view order.
fn first_field(root: &gtk::Widget) -> Option<gtk::Widget> {
    if root.is::<gtk::Text>() || root.is::<gtk::TextView>() {
        return Some(root.clone());
    }
    let mut child = root.first_child();
    while let Some(widget) = child {
        if let Some(field) = first_field(&widget) {
            return Some(field);
        }
        child = widget.next_sibling();
    }
    None
}
