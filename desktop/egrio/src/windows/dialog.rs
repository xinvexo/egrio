//! A dialog over the main window: a `ContentDialog` in the window's XAML
//! root, whose content is the dialog's component tree ("Dialog controls").
//! The dialog has none of `ContentDialog`'s own buttons; the tree's buttons
//! act, and the interface closes the dialog. Esc, which `ContentDialog`
//! answers by closing itself, presses the tree's cancel button instead, and
//! the interface decides.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result};

use egrio_ui::backend::{Appearance, Event, UiEvent};
use egrio_ui::node::ButtonKey;
use egrio_ui::reconcile::{Mounted, Patch};

use super::bindings::{Border, ContentDialog, ElementTheme, Grid, IContentControl};
use super::widgets::{check, Post, Surface};
use super::xaml::{self, Element};

/// The space around a dialog's content, inside the dialog's own margin.
const DIALOG_INSET: f64 = 4.0;

pub struct Dialog {
    dialog: ContentDialog,
    surface: Rc<RefCell<Surface>>,
    /// Set while the interface closes the dialog, which then may close.
    closing: Rc<Cell<bool>>,
    _events: Vec<EventRevoker>,
}

impl Dialog {
    pub fn open(root: &Grid, tree: &Mounted, appearance: Appearance, post: Post) -> Result<Self> {
        let dialog = ContentDialog::new()?;
        dialog.ui().SetXamlRoot(&root.ui().XamlRoot()?)?;
        let host = Border::new()?;
        host.SetPadding(xaml::uniform(DIALOG_INSET))?;
        dialog.cast::<IContentControl>()?.SetContent(&host)?;
        let mut surface = Surface::new(host, post);
        surface.set_root(tree);
        let surface = Rc::new(RefCell::new(surface));
        let closing = Rc::new(Cell::new(false));
        let close_requested = {
            let surface = Rc::downgrade(&surface);
            let closing = closing.clone();
            dialog.Closing(move |_, args| {
                if closing.get() {
                    return;
                }
                if let Ok(args) = args.ok() {
                    check(args.SetCancel(true), "keep the dialog open");
                }
                let cancel = surface.upgrade().and_then(|surface| {
                    surface
                        .try_borrow()
                        .ok()?
                        .button_with_key(ButtonKey::Escape)
                });
                if let Some(id) = cancel {
                    post(UiEvent::Node {
                        id,
                        event: Event::Press,
                    });
                }
            })?
        };
        let this = Self {
            dialog,
            surface,
            closing,
            _events: vec![close_requested],
        };
        this.set_appearance(appearance)?;
        // The operation completes when the dialog closes; nothing waits on it.
        this.dialog.ShowAsync()?;
        Ok(this)
    }

    /// The surface its content tree realizes, for the test control
    /// channel's scope.
    #[cfg(feature = "test-control")]
    pub fn surface(&self) -> &Rc<RefCell<Surface>> {
        &self.surface
    }

    pub fn apply(&self, patches: Vec<Patch>) {
        self.surface.borrow_mut().apply(patches);
    }

    pub fn settle(&self) {
        self.surface.borrow().settle();
    }

    pub fn set_appearance(&self, appearance: Appearance) -> Result<()> {
        self.dialog.fe().SetRequestedTheme(match appearance {
            Appearance::System => ElementTheme::Default,
            Appearance::Light => ElementTheme::Light,
            Appearance::Dark => ElementTheme::Dark,
        })
    }

    pub fn close(self) {
        self.closing.set(true);
        check(self.dialog.Hide(), "close the dialog");
    }
}
