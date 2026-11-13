//! Asks for one existing file with `GtkFileDialog`, which uses the desktop's
//! file chooser portal where there is one ("GtkFileDialog" in the GTK
//! documentation). The answer comes back as a [`UiEvent::FileChosen`].

use std::cell::Cell;
use std::rc::Rc;

use gtk::gio;
use gtk::prelude::*;

use egrio_ui::backend::{FileRequest, UiEvent};

use super::widgets::Post;

pub fn choose_file(parent: Option<&gtk::Window>, request: &FileRequest, post: Post) {
    let dialog = gtk::FileDialog::new();
    dialog.set_modal(true);
    if !request.extensions.is_empty() {
        let filter = gtk::FileFilter::new();
        for extension in &request.extensions {
            filter.add_suffix(extension);
        }
        let patterns: Vec<String> = request
            .extensions
            .iter()
            .map(|extension| format!("*.{extension}"))
            .collect();
        filter.set_name(Some(&patterns.join(" ")));
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        dialog.set_filters(Some(&filters));
        dialog.set_default_filter(Some(&filter));
    }
    let purpose = request.purpose;
    let cancellable = gio::Cancellable::new();
    // Set once the request has its answer, from the dialog or the test control.
    let answered = Rc::new(Cell::new(false));
    #[cfg(feature = "test-control")]
    test::wait(purpose, cancellable.clone(), answered.clone());
    dialog.open(parent, Some(&cancellable), move |result| {
        if answered.replace(true) {
            return;
        }
        let path = result.ok().and_then(|file| file.path());
        post(UiEvent::FileChosen { purpose, path });
    });
}

/// The test control's answer in place of the user's.
#[cfg(feature = "test-control")]
pub mod test {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use gtk::gio;
    use gtk::prelude::*;

    use egrio_ui::backend::{FilePurpose, UiEvent};

    use super::Post;

    /// The request waiting for its answer.
    struct Pending {
        purpose: FilePurpose,
        cancellable: gio::Cancellable,
        answered: Rc<Cell<bool>>,
    }

    thread_local! {
        static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
    }

    pub fn wait(purpose: FilePurpose, cancellable: gio::Cancellable, answered: Rc<Cell<bool>>) {
        PENDING.with(|pending| {
            *pending.borrow_mut() = Some(Pending {
                purpose,
                cancellable,
                answered,
            })
        });
    }

    /// Answers the waiting request and closes the file dialog.
    pub fn answer(path: Option<std::path::PathBuf>, post: Post) -> Result<(), String> {
        let pending = PENDING
            .with(|pending| pending.borrow_mut().take())
            .ok_or("no file was asked for")?;
        if pending.answered.replace(true) {
            return Err("the file request was answered already".into());
        }
        pending.cancellable.cancel();
        post(UiEvent::FileChosen {
            purpose: pending.purpose,
            path,
        });
        Ok(())
    }
}
