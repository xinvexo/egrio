//! Where the main window and the editor window were, saved when a window
//! closes or the app quits and used when it opens again (`window-state.json`
//! in the app data directory): a window's restored bounds and whether it was
//! maximized, read and set through its placement (`GetWindowPlacement`,
//! `SetWindowPlacement`, which moves a window that would lie off every
//! display back onto one). The bounds are workspace coordinates in device
//! pixels, as the placement keeps them.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::bindings::{
    GetWindowPlacement, SetWindowPlacement, Window, HWND, RECT, SW_HIDE, SW_SHOWMAXIMIZED,
    SW_SHOWMINIMIZED, WINDOWPLACEMENT, WPF_RESTORETOMAXIMIZED,
};

const FILE: &str = "window-state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    #[serde(default)]
    pub maximized: bool,
}

impl Placement {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    main: Option<Placement>,
    editor: Option<Placement>,
}

#[derive(Debug, Clone, Copy)]
pub enum Which {
    Main,
    Editor,
}

fn path() -> Option<PathBuf> {
    egrio_desktop::app_paths::app_data_dir()
        .ok()
        .map(|directory| directory.join(FILE))
}

fn load() -> Saved {
    path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// The window's last place, if it had one with a size.
pub fn saved(which: Which) -> Option<Placement> {
    let saved = load();
    match which {
        Which::Main => saved.main,
        Which::Editor => saved.editor,
    }
    .filter(|placement| placement.width() > 0 && placement.height() > 0)
}

/// Saves where `window` is now.
pub fn remember(window: &Window, which: Which) {
    if let Ok(hwnd) = super::hwnd::handle(window) {
        remember_handle(hwnd, which);
    }
}

/// Saves where the window with the handle `hwnd` is now.
pub fn remember_handle(hwnd: HWND, which: Which) {
    let Some(placement) = placement(hwnd) else {
        return;
    };
    let Some(path) = path() else { return };
    let mut saved = load();
    match which {
        Which::Main => saved.main = Some(placement),
        Which::Editor => saved.editor = Some(placement),
    }
    let written = serde_json::to_vec_pretty(&saved)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            // A new data directory exists only once something is saved in it.
            if let Some(directory) = path.parent() {
                std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
            }
            std::fs::write(&path, bytes).map_err(|error| error.to_string())
        });
    if let Err(error) = written {
        log::warn!("couldn't remember the window's place: {error}");
    }
}

fn placement(hwnd: HWND) -> Option<Placement> {
    let mut placement = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    // SAFETY: a window of this process and a placement of the given length.
    if !unsafe { GetWindowPlacement(hwnd, &mut placement) }.as_bool() {
        return None;
    }
    let bounds = placement.rcNormalPosition;
    // A minimized window remembers whether it comes back maximized.
    let maximized = placement.showCmd == SW_SHOWMAXIMIZED as u32
        || (placement.showCmd == SW_SHOWMINIMIZED as u32
            && placement.flags & WPF_RESTORETOMAXIMIZED as u32 != 0);
    Some(Placement {
        left: bounds.left,
        top: bounds.top,
        right: bounds.right,
        bottom: bounds.bottom,
        maximized,
    })
}

/// Puts the hidden `window` back where `placement` says, on a display; the
/// window shows when it is activated, and maximizes then if it was.
pub fn restore(window: &Window, placement: Placement) {
    let Ok(hwnd) = super::hwnd::handle(window) else {
        return;
    };
    let placement = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        showCmd: SW_HIDE as u32,
        rcNormalPosition: RECT {
            left: placement.left,
            top: placement.top,
            right: placement.right,
            bottom: placement.bottom,
        },
        ..Default::default()
    };
    // SAFETY: a window of this process and a filled placement.
    if !unsafe { SetWindowPlacement(hwnd, &placement) }.as_bool() {
        log::warn!(
            "couldn't put the window back: {}",
            std::io::Error::last_os_error()
        );
    }
}
