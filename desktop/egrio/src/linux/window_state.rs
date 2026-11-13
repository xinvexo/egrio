//! The main window's and the editor window's size, and whether the main
//! window was maximized, saved when a window closes and used when it opens
//! again (`window-state.json` in the app data directory). Wayland does not
//! tell an app where its windows are, so no position is kept.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const FILE: &str = "window-state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSize {
    pub width: i32,
    pub height: i32,
    #[serde(default)]
    pub maximized: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    main: Option<WindowSize>,
    editor: Option<WindowSize>,
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

fn store(change: impl FnOnce(&mut Saved)) {
    let Some(path) = path() else { return };
    let mut saved = load();
    change(&mut saved);
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
        log::warn!("couldn't remember the window size: {error}");
    }
}

/// A size the window can open at: never below the least it takes.
fn usable(size: WindowSize) -> Option<WindowSize> {
    (size.width > 0 && size.height > 0).then_some(size)
}

pub fn main() -> Option<WindowSize> {
    load().main.and_then(usable)
}

pub fn editor() -> Option<WindowSize> {
    load().editor.and_then(usable)
}

pub fn save_main(size: WindowSize) {
    store(|saved| saved.main = Some(size));
}

pub fn save_editor(size: WindowSize) {
    store(|saved| saved.editor = Some(size));
}
