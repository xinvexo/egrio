//! What the main window asks the user over itself: a dialog as a sheet,
//! whose content is a component tree, and the open panel for a file.

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSBackingStoreType, NSModalResponse, NSModalResponseOK, NSOpenPanel, NSView, NSWindow,
    NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSPoint, NSRect, NSSize, NSString};
use objc2_uniform_type_identifiers::UTType;

use egrio_ui::backend::{FileRequest, UiEvent};
use egrio_ui::reconcile::Mounted;

use super::widgets::Surface;

/// The space around a dialog's content.
const DIALOG_INSET: f64 = 20.0;

/// An open dialog: the sheet and the views of its tree.
pub struct Dialog {
    sheet: Retained<NSWindow>,
    pub surface: Surface,
}

impl Dialog {
    /// Builds the sheet for `tree` and shows it over `parent`.
    pub fn open(
        mtm: MainThreadMarker,
        parent: &NSWindow,
        tree: &Mounted,
        post: fn(UiEvent),
    ) -> Self {
        let sheet = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(480.0, 200.0)),
                NSWindowStyleMask::Titled,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { sheet.setReleasedWhenClosed(false) };
        let host = NSView::new(mtm);
        sheet.setContentView(Some(&host));
        let mut surface = Surface::new(mtm, host.clone(), post);
        surface.set_root(tree, super::widgets::even_insets(DIALOG_INSET));
        // As large as its content asks.
        host.layoutSubtreeIfNeeded();
        sheet.setContentSize(host.fittingSize());
        parent.beginSheet_completionHandler(&sheet, None);
        Self { sheet, surface }
    }

    pub fn window(&self) -> &NSWindow {
        &self.sheet
    }

    pub fn close(self, parent: &NSWindow) {
        parent.endSheet(&self.sheet);
        self.sheet.orderOut(None);
    }
}

#[cfg(feature = "test-control")]
thread_local! {
    /// What the last open panel asked for, which test control answers.
    static ASKED: std::cell::Cell<egrio_ui::backend::FilePurpose> =
        const { std::cell::Cell::new(egrio_ui::backend::FilePurpose::ImportProfile) };
}

/// What the last open panel asked for.
#[cfg(feature = "test-control")]
pub fn asked() -> egrio_ui::backend::FilePurpose {
    ASKED.with(std::cell::Cell::get)
}

/// Asks for one existing file of the request's types over `parent`; the
/// answer comes back as a [`UiEvent::FileChosen`].
pub fn choose_file(
    mtm: MainThreadMarker,
    parent: &NSWindow,
    request: &FileRequest,
    post: fn(UiEvent),
) {
    #[cfg(feature = "test-control")]
    ASKED.with(|asked| asked.set(request.purpose));
    let panel = NSOpenPanel::openPanel(mtm);
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(false);
    let types: Vec<Retained<UTType>> = request
        .extensions
        .iter()
        .filter_map(|extension| UTType::typeWithFilenameExtension(&NSString::from_str(extension)))
        .collect();
    if !types.is_empty() {
        panel.setAllowedContentTypes(&NSArray::from_retained_slice(&types));
    }
    let purpose = request.purpose;
    let answered = panel.clone();
    let handler = RcBlock::new(move |response: NSModalResponse| {
        let path = (response == NSModalResponseOK)
            .then(|| answered.URL())
            .flatten()
            .and_then(|url| url.path())
            .map(|path| std::path::PathBuf::from(path.to_string()));
        post(UiEvent::FileChosen { purpose, path });
    });
    panel.beginSheetModalForWindow_completionHandler(parent, &handler);
}
