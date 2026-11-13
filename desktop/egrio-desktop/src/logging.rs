//! The desktop's logging: the level the user chose, the line every record is
//! written as, the rotating log file and the Logs page's history. The app
//! installs [`install`]'s logger for the whole process.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const LOG_LEVEL_KEY: &str = "log_level";
/// Records the Logs page can show; older ones remain only in the log file.
const HISTORY_CAPACITY: usize = 500;
/// The size at which the log file is renamed with its time and a new one
/// begins, and how many renamed files stay.
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;
const ROTATED_KEPT: usize = 2;
/// How much more a file that could not be renamed takes before the rename is
/// tried again.
const RENAME_RETRY: u64 = 64 * 1024;
const FILE_NAME: &str = "egrio";

static ACTIVE_LEVEL: AtomicU8 = AtomicU8::new(log::LevelFilter::Info as u8);

/// The level is an application preference, never a profile override.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn filter(self) -> log::LevelFilter {
        match self {
            Self::Off => log::LevelFilter::Off,
            Self::Error => log::LevelFilter::Error,
            Self::Warn => log::LevelFilter::Warn,
            Self::Info => log::LevelFilter::Info,
            Self::Debug => log::LevelFilter::Debug,
            Self::Trace => log::LevelFilter::Trace,
        }
    }

    fn apply(self) {
        ACTIVE_LEVEL.store(self.filter() as u8, Ordering::Release);
        log::set_max_level(self.filter());
    }
}

/// The stored level.
pub fn load() -> Result<LogLevel, String> {
    let value = crate::profile_store::ProfileStore::open()
        .and_then(|store| store.app_setting(LOG_LEVEL_KEY))
        .map_err(|error| error.to_string())?;
    value
        .map(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))
        .transpose()
        .map(|value| value.unwrap_or_default())
}

/// Applies the stored level.
pub fn initialize() -> Result<(), String> {
    load()?.apply();
    Ok(())
}

/// Stores `level` and applies it at once.
pub fn save(level: LogLevel) -> Result<LogLevel, String> {
    let value = serde_json::to_string(&level).map_err(|error| error.to_string())?;
    crate::profile_store::ProfileStore::open()
        .and_then(|store| store.set_app_setting(LOG_LEVEL_KEY, &value))
        .map_err(|error| error.to_string())?;
    level.apply();
    Ok(level)
}

/// Whether a record at `level` passes the chosen level. Debug and trace are
/// Egrio's own diagnostics (`own`); dependencies stay at info and above.
/// Their internals at those levels (every HTTP or TLS frame) would bury the
/// app's records, and each record that passes also goes to the Logs page.
pub fn passes(level: log::Level, own: bool) -> bool {
    passes_at(level, own, ACTIVE_LEVEL.load(Ordering::Acquire))
}

fn passes_at(level: log::Level, own: bool, active: u8) -> bool {
    level as u8 <= active && (level <= log::Level::Info || own)
}

/// The Egrio crates' module paths and the categories the app logs under.
pub fn is_own_target(target: &str) -> bool {
    target.starts_with("egrio") || matches!(target, "network" | "rule-providers")
}

/// A record as a line of the log file and standard output: local date and
/// time, level, target and message.
pub fn line(level: log::Level, target: &str, message: &str) -> String {
    let now = chrono::Local::now();
    format!(
        "[{}][{}][{level}][{target}] {message}",
        now.format("%Y-%m-%d"),
        now.format("%H:%M:%S")
    )
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRecordLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<log::Level> for LogRecordLevel {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => Self::Error,
            log::Level::Warn => Self::Warn,
            log::Level::Info => Self::Info,
            log::Level::Debug => Self::Debug,
            log::Level::Trace => Self::Trace,
        }
    }
}

/// A record the Logs page shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogRecord {
    /// One more than the record before it, across clears.
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub at: u64,
    pub level: LogRecordLevel,
    /// The module or category that logged it, such as `network`.
    pub target: String,
    pub message: String,
}

struct History {
    next_seq: u64,
    records: VecDeque<LogRecord>,
}

static HISTORY: Mutex<History> = Mutex::new(History {
    next_seq: 0,
    records: VecDeque::new(),
});

/// Keeps a record that passed the filter in the history and returns its
/// sequence number.
pub fn keep(level: log::Level, target: &str, message: String) -> u64 {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64);
    let mut history = HISTORY.lock().unwrap_or_else(PoisonError::into_inner);
    let seq = history.next_seq;
    history.next_seq += 1;
    if history.records.len() == HISTORY_CAPACITY {
        history.records.pop_front();
    }
    history.records.push_back(LogRecord {
        seq,
        at,
        level: level.into(),
        target: target.to_owned(),
        message,
    });
    seq
}

/// The kept records after sequence number `seq`, oldest first; all of them
/// for `None`.
pub fn history_after(seq: Option<u64>) -> Vec<LogRecord> {
    let history = HISTORY.lock().unwrap_or_else(PoisonError::into_inner);
    history
        .records
        .iter()
        .filter(|record| seq.is_none_or(|seq| record.seq > seq))
        .cloned()
        .collect()
}

/// Forgets the kept records; the sequence keeps counting.
pub fn clear_history() {
    HISTORY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .records
        .clear();
}

/// `egrio.log` in a directory: renamed `egrio_<date>_<time>.log` once it
/// would pass [`MAX_FILE_SIZE`], keeping the [`ROTATED_KEPT`] newest renamed
/// files.
///
/// Records go on being written whatever happens to the renaming. A file that
/// cannot be renamed -- another program holds it open in a way that forbids
/// it, the directory refuses -- is written on past its size and the rename
/// tried again every [`RENAME_RETRY`]; a directory that was removed is made
/// again when the file is next opened. A failed rename that left the file
/// closed would cost every record after it.
struct LogFile {
    directory: PathBuf,
    file: Option<File>,
    size: u64,
    /// The size the file is renamed at: [`MAX_FILE_SIZE`], or further on
    /// after a rename that failed.
    rename_at: u64,
}

impl LogFile {
    fn open(directory: PathBuf) -> std::io::Result<Self> {
        let mut this = Self {
            directory,
            file: None,
            size: 0,
            rename_at: MAX_FILE_SIZE,
        };
        this.reopen()?;
        if this.size >= MAX_FILE_SIZE {
            this.rotate();
        }
        // Old files left over cost only their room.
        let _ = remove_old(&this.directory, ROTATED_KEPT);
        Ok(this)
    }

    fn path(&self) -> PathBuf {
        self.directory.join(format!("{FILE_NAME}.log"))
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path())?;
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let length = line.len() as u64 + 1;
        if self.size > 0 && self.size + length > self.rename_at {
            self.rotate();
        }
        if self.file.is_none() {
            self.reopen()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        writeln!(file, "{line}")?;
        self.size += length;
        Ok(())
    }

    /// Renames the file and begins a new one, or leaves the file to be
    /// written on when it cannot be renamed.
    fn rotate(&mut self) {
        self.file = None;
        match self.rename() {
            Ok(()) => {
                self.size = 0;
                self.rename_at = MAX_FILE_SIZE;
            }
            Err(_) => self.rename_at = self.size + RENAME_RETRY,
        }
    }

    fn rename(&self) -> std::io::Result<()> {
        // Room for the file about to be renamed.
        remove_old(&self.directory, ROTATED_KEPT - 1)?;
        let stamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
        let rotated = self.directory.join(format!("{FILE_NAME}_{stamp}.log"));
        if rotated.is_file() {
            fs::rename(&rotated, rotated.with_extension("log.bak"))?;
        }
        fs::rename(self.path(), rotated)
    }
}

/// Removes the oldest renamed files until `keep` remain.
fn remove_old(directory: &Path, keep: usize) -> std::io::Result<()> {
    let mut rotated: Vec<(String, PathBuf)> = fs::read_dir(directory)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let stamp = path
                .file_name()?
                .to_str()?
                .strip_prefix(FILE_NAME)?
                .strip_prefix('_')?
                .strip_suffix(".log")?
                .to_owned();
            Some((stamp, path))
        })
        .collect();
    rotated.sort();
    let excess = rotated.len().saturating_sub(keep);
    for (_, path) in rotated.into_iter().take(excess) {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// The native app's process logger: every record that passes goes to
/// standard output, the log file and the history.
struct Logger {
    file: Mutex<Option<LogFile>>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        passes(metadata.level(), is_own_target(metadata.target()))
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        let line = line(record.level(), record.target(), &message);
        let _ = writeln!(std::io::stdout(), "{line}");
        if let Some(file) = self
            .file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            let _ = file.write_line(&line);
        }
        keep(record.level(), record.target(), message);
    }

    fn flush(&self) {}
}

/// Installs the process logger at the stored level, writing the log file in
/// the app's log directory. Without a readable level or a writable directory
/// it still logs, at the default level or without the file, and says why.
pub fn install() {
    let level = load();
    let file = crate::app_paths::app_log_dir().and_then(|directory| {
        LogFile::open(directory.clone())
            .map_err(|error| format!("cannot write logs in {}: {error}", directory.display()))
    });
    let (file, file_error) = match file {
        Ok(file) => (Some(file), None),
        Err(error) => (None, Some(error)),
    };
    if log::set_boxed_logger(Box::new(Logger {
        file: Mutex::new(file),
    }))
    .is_err()
    {
        return;
    }
    match level {
        Ok(level) => level.apply(),
        Err(error) => {
            LogLevel::default().apply();
            log::warn!("the log level stays at the default: {error}");
        }
    }
    if let Some(error) = file_error {
        log::warn!("{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;

    fn passes_with(active: LogLevel, level: Level, target: &str) -> bool {
        passes_at(level, is_own_target(target), active.filter() as u8)
    }

    #[test]
    fn verbose_levels_cover_only_egrio_records() {
        assert!(passes_with(
            LogLevel::Trace,
            Level::Trace,
            "egrio_core::dns"
        ));
        assert!(passes_with(LogLevel::Debug, Level::Debug, "network"));
        assert!(!passes_with(LogLevel::Trace, Level::Trace, "h2::codec"));
        assert!(!passes_with(LogLevel::Trace, Level::Debug, "hyper::proto"));
        assert!(passes_with(LogLevel::Trace, Level::Info, "hyper::proto"));
        assert!(!passes_with(LogLevel::Warn, Level::Info, "egrio_core::dns"));
        assert!(passes_with(LogLevel::Warn, Level::Warn, "rustls::conn"));
        assert!(!passes_with(LogLevel::Off, Level::Error, "egrio_lib"));
    }

    #[test]
    fn a_full_file_is_renamed_and_only_the_newest_renamed_files_stay() {
        let directory = std::env::temp_dir().join(format!("egrio-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        for stamp in [
            "2026-01-01_00-00-00",
            "2026-01-02_00-00-00",
            "2026-01-03_00-00-00",
        ] {
            fs::write(directory.join(format!("egrio_{stamp}.log")), "old").unwrap();
        }
        fs::write(
            directory.join("egrio.log"),
            vec![b'x'; MAX_FILE_SIZE as usize],
        )
        .unwrap();
        let mut file = LogFile::open(directory.clone()).unwrap();
        file.write_line("fresh").unwrap();

        let mut names: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 1 + ROTATED_KEPT, "{names:?}");
        assert!(names.contains(&"egrio.log".to_string()));
        assert!(
            names.contains(&"egrio_2026-01-03_00-00-00.log".to_string()),
            "{names:?}"
        );
        assert!(!names.contains(&"egrio_2026-01-01_00-00-00.log".to_string()));
        assert_eq!(
            fs::read_to_string(directory.join("egrio.log")).unwrap(),
            "fresh\n"
        );
        fs::remove_dir_all(&directory).unwrap();
    }

    /// Whatever keeps the full file from being renamed, records go on being
    /// written to it, and it is renamed once it can be.
    #[test]
    fn a_file_that_cannot_be_renamed_is_written_on() {
        let directory =
            std::env::temp_dir().join(format!("egrio-log-held-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let full = vec![b'x'; MAX_FILE_SIZE as usize];
        fs::write(directory.join("egrio.log"), &full).unwrap();
        // The names the file would be renamed to in the next seconds are
        // taken by directories, which no file can be renamed onto.
        let now = chrono::Local::now();
        let blocked: Vec<PathBuf> = (0..5)
            .map(|second| {
                let stamp = (now + chrono::Duration::seconds(second)).format("%Y-%m-%d_%H-%M-%S");
                let path = directory.join(format!("egrio_{stamp}.log"));
                fs::create_dir_all(path.join("held")).unwrap();
                path
            })
            .collect();

        let mut file = LogFile::open(directory.clone()).unwrap();
        file.write_line("one").unwrap();
        file.write_line("two").unwrap();
        let written = fs::read(directory.join("egrio.log")).unwrap();
        assert_eq!(written.len(), full.len() + 8);
        assert!(written.ends_with(b"one\ntwo\n"));
        assert_eq!(file.rename_at, MAX_FILE_SIZE + RENAME_RETRY);

        // The rename goes through once nothing is in its way and the file
        // has grown by the retry step.
        for path in blocked {
            fs::remove_dir_all(path).unwrap();
        }
        file.write_line(&"y".repeat(RENAME_RETRY as usize)).unwrap();
        assert_eq!(file.rename_at, MAX_FILE_SIZE);
        assert_eq!(
            fs::read(directory.join("egrio.log")).unwrap().len(),
            RENAME_RETRY as usize + 1
        );

        // A directory that was removed is made again.
        fs::remove_dir_all(&directory).unwrap();
        file.file = None;
        file.write_line("after").unwrap();
        assert!(fs::read_to_string(directory.join("egrio.log"))
            .unwrap()
            .ends_with("after\n"));
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn the_history_hands_out_what_came_after_a_sequence_number() {
        clear_history();
        let first = keep(Level::Info, "egrio", "one".into());
        let second = keep(Level::Warn, "network", "two".into());
        let after: Vec<u64> = history_after(Some(first))
            .iter()
            .map(|record| record.seq)
            .collect();
        assert_eq!(after, [second]);
        assert!(history_after(None).len() >= 2);
        clear_history();
        assert!(history_after(None).is_empty());
        assert!(
            keep(Level::Info, "egrio", "three".into()) > second,
            "the sequence survives a clear"
        );
    }
}
