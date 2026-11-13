//! Asks for one existing file with the Windows App SDK's `FileOpenPicker`
//! (`Microsoft.Windows.Storage.Pickers`), which an unpackaged app opens over
//! one of its windows by the window's id. The answer comes back on the main
//! thread as a [`UiEvent::FileChosen`].

use windows_core::Result;
#[cfg(not(feature = "test-control"))]
use windows_future::{AsyncOperationCompletedHandler, AsyncStatus, IAsyncOperation};

use egrio_ui::backend::{FilePurpose, FileRequest, UiEvent};

use super::bindings::WindowId;
#[cfg(not(feature = "test-control"))]
use super::bindings::{FileOpenPicker, PickFileResult};

#[cfg(feature = "test-control")]
pub fn choose_file(owner: WindowId, request: &FileRequest) -> Result<()> {
    // A test has no user at the picker, which is the shell's own dialog, so
    // the request waits for the control channel's `answer-file`.
    let _ = owner;
    test::requested(request.purpose);
    Ok(())
}

#[cfg(not(feature = "test-control"))]
pub fn choose_file(owner: WindowId, request: &FileRequest) -> Result<()> {
    let picker = FileOpenPicker::CreateInstance(owner)?;
    let filter = picker.FileTypeFilter()?;
    for extension in &request.extensions {
        filter.Append(&windows_core::HSTRING::from(format!(".{extension}")))?;
    }
    // Any file, when no kind is asked for: the picker takes no empty filter.
    if request.extensions.is_empty() {
        filter.Append(&windows_core::HSTRING::from("*"))?;
    }
    let purpose = request.purpose;
    let operation = picker.PickSingleFileAsync()?;
    operation.SetCompleted(&AsyncOperationCompletedHandler::new(
        move |operation: windows_core::Ref<IAsyncOperation<PickFileResult>>, status| {
            let path = match (operation.ok(), status) {
                (Ok(operation), AsyncStatus::Completed) => operation
                    .GetResults()
                    .ok()
                    .and_then(|result| result.Path().ok())
                    .filter(|path| !path.is_empty())
                    .map(|path| std::path::PathBuf::from(path)),
                _ => None,
            };
            answer(purpose, path);
            Ok(())
        },
    ))
}

/// What the test control channel answers in the picker's place.
#[cfg(feature = "test-control")]
pub mod test {
    use std::cell::Cell;

    use egrio_ui::backend::FilePurpose;

    thread_local! {
        /// The request the interface made, waiting for its answer.
        static PENDING: Cell<Option<FilePurpose>> = const { Cell::new(None) };
    }

    pub(super) fn requested(purpose: FilePurpose) {
        PENDING.set(Some(purpose));
    }

    /// Answers the open request as the picker would, with a file or with
    /// nothing.
    pub fn answer(path: Option<std::path::PathBuf>) -> Result<(), String> {
        let purpose = PENDING.replace(None).ok_or("no file request")?;
        super::answer(purpose, path);
        Ok(())
    }
}

/// Delivers the answer on the main thread, whichever thread completed the
/// picker's operation.
fn answer(purpose: FilePurpose, path: Option<std::path::PathBuf>) {
    super::on_main(move || super::post(UiEvent::FileChosen { purpose, path }));
}
