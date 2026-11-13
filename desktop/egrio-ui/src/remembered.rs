//! What the interface remembers between launches: the section it showed and
//! the entry the nodes page listed, in `interface.json` in the app data
//! directory. A missing or unreadable file starts from the defaults. Writes
//! run off the main thread, one at a time, each taking the newest value, so
//! the file ends with the last change.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::state::Section;

const FILE: &str = "interface.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Remembered {
    pub section: Section,
    /// The nodes page's entry, by its key (`crate::pages::nodes::Entry`).
    pub nodes_entry: Option<String>,
}

impl Default for Remembered {
    fn default() -> Self {
        Self {
            section: Section::Activity,
            nodes_entry: None,
        }
    }
}

/// The value waiting to be written; the lock is held while writing.
static PENDING: Mutex<Option<Remembered>> = Mutex::new(None);

fn path() -> Option<PathBuf> {
    egrio_desktop::app_paths::app_data_dir()
        .ok()
        .map(|directory| directory.join(FILE))
}

/// What the last launch left, or the defaults.
pub fn load() -> Remembered {
    path().map(|path| read(&path)).unwrap_or_default()
}

/// Writes `remembered` in the background.
pub fn save(remembered: Remembered) {
    *PENDING.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(remembered);
    egrio_desktop::async_runtime::spawn_blocking(|| {
        let mut pending = PENDING.lock().unwrap_or_else(|poison| poison.into_inner());
        if let (Some(remembered), Some(path)) = (pending.take(), path()) {
            if let Err(error) = write(&path, remembered) {
                log::warn!("couldn't remember the interface state: {error}");
            }
        }
    });
}

fn read(path: &Path) -> Remembered {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Replaces the file whole, so a reader never sees half of it.
fn write(path: &Path, remembered: Remembered) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(&remembered).map_err(std::io::Error::other)?;
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, json)?;
    std::fs::rename(&partial, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("egrio-ui-remembered-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        directory.join(FILE)
    }

    #[test]
    fn the_section_and_the_nodes_entry_come_back() {
        let path = scratch("round-trip");
        let remembered = Remembered {
            section: Section::Nodes,
            nodes_entry: Some("group:group-1".into()),
        };
        write(&path, remembered.clone()).unwrap();
        assert_eq!(read(&path), remembered);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains(r#""nodes-entry": "group:group-1""#));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_missing_or_unreadable_file_starts_from_the_defaults() {
        let path = scratch("unreadable");
        assert_eq!(
            read(&path.with_file_name("missing.json")),
            Remembered::default()
        );
        std::fs::write(&path, b"{ not json").unwrap();
        assert_eq!(read(&path), Remembered::default());
        std::fs::write(&path, br#"{"section": "somewhere", "nodes-entry": "all"}"#).unwrap();
        assert_eq!(read(&path), Remembered::default(), "an unknown value");
        std::fs::write(&path, br#"{"section": "logs"}"#).unwrap();
        assert_eq!(read(&path).section, Section::Logs, "a missing field");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
