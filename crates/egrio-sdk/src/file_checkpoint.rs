use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use egrio_runtime::{
    CheckpointFuture, CheckpointId, CheckpointRevision, CheckpointStore, CheckpointStoreError,
    CheckpointStoreErrorCode, RecoveryCheckpoint, StoredCheckpoint,
};

#[derive(Clone, Debug)]
pub struct FileCheckpointStore {
    directory: Arc<PathBuf>,
    gate: Arc<Mutex<()>>,
}

impl FileCheckpointStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: Arc::new(directory.into()),
            gate: Arc::new(Mutex::new(())),
        }
    }

    fn path(directory: &Path, id: CheckpointId) -> PathBuf {
        directory.join(format!("{}.json", id.as_uuid()))
    }

    /// Moves every record this build cannot decode out of the store and
    /// returns where each went (`<id>.json.unreadable`, beside the records).
    ///
    /// [`CheckpointStore::list_unresolved`] reports such a record as
    /// `Corrupt` and returns nothing, because a store that skipped it would
    /// hide OS changes nobody will restore. That is the right answer to a
    /// caller that can act on it, and a dead end for a host that lists at
    /// every start: the record stays, so every later start fails the same
    /// way. A record is undecodable when its bytes are damaged or when
    /// another build wrote it in a schema this one does not read; neither
    /// gets better by waiting, and nothing can be restored from either. A
    /// host that would rather run than stop there calls this first and
    /// reports what it set aside. A record that cannot be read at all (an
    /// I/O error) is left alone and fails the call.
    pub fn set_aside_unreadable(&self) -> Result<Vec<PathBuf>, CheckpointStoreError> {
        let _guard = self.gate.lock().expect("file checkpoint mutex");
        let directory = self.directory.as_ref();
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut set_aside = Vec::new();
        for path in record_paths(directory)? {
            match read_record(&path) {
                Ok(_) => {}
                Err(error) if error.code == CheckpointStoreErrorCode::Corrupt => {
                    let aside = path.with_extension("json.unreadable");
                    fs::rename(&path, &aside).map_err(io_error)?;
                    set_aside.push(aside);
                }
                Err(error) => return Err(error),
            }
        }
        if !set_aside.is_empty() {
            sync_directory(directory)?;
        }
        set_aside.sort();
        Ok(set_aside)
    }
}

impl CheckpointStore for FileCheckpointStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        let directory = self.directory.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            run_blocking(move || {
                let _guard = gate.lock().expect("file checkpoint mutex");
                create_private_directory(directory.as_ref())?;
                let path = Self::path(directory.as_ref(), checkpoint.id);
                if path.exists() {
                    return Err(store_error(
                        CheckpointStoreErrorCode::AlreadyExists,
                        "checkpoint already exists",
                    ));
                }
                let stored = StoredCheckpoint {
                    checkpoint,
                    revision: CheckpointRevision::new(0),
                };
                write_atomic(&path, &stored)?;
                Ok(stored)
            })
            .await
        })
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        let directory = self.directory.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            run_blocking(move || {
                let _guard = gate.lock().expect("file checkpoint mutex");
                let path = Self::path(directory.as_ref(), id);
                if !path.exists() {
                    return Ok(None);
                }
                read_record(&path).map(Some)
            })
            .await
        })
    }

    fn replace<'a>(
        &'a self,
        expected: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        let directory = self.directory.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            run_blocking(move || {
                let _guard = gate.lock().expect("file checkpoint mutex");
                let path = Self::path(directory.as_ref(), checkpoint.id);
                if !path.exists() {
                    return Err(store_error(
                        CheckpointStoreErrorCode::NotFound,
                        "checkpoint not found",
                    ));
                }
                let current = read_record(&path)?;
                if current.revision != expected {
                    return Err(store_error(
                        CheckpointStoreErrorCode::RevisionConflict,
                        "checkpoint revision does not match",
                    ));
                }
                let stored = StoredCheckpoint {
                    checkpoint,
                    revision: expected.next(),
                };
                write_atomic(&path, &stored)?;
                Ok(stored)
            })
            .await
        })
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        let directory = self.directory.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            run_blocking(move || {
                let _guard = gate.lock().expect("file checkpoint mutex");
                if !directory.exists() {
                    return Ok(Vec::new());
                }
                let mut records = record_paths(directory.as_ref())?
                    .iter()
                    .map(|path| read_record(path))
                    .collect::<Result<Vec<_>, _>>()?;
                records.sort_by_key(|stored| stored.checkpoint.id);
                Ok(records)
            })
            .await
        })
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        expected: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        let directory = self.directory.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            run_blocking(move || {
                let _guard = gate.lock().expect("file checkpoint mutex");
                let path = Self::path(directory.as_ref(), id);
                if !path.exists() {
                    return Err(store_error(
                        CheckpointStoreErrorCode::NotFound,
                        "checkpoint not found",
                    ));
                }
                let current = read_record(&path)?;
                if current.revision != expected {
                    return Err(store_error(
                        CheckpointStoreErrorCode::RevisionConflict,
                        "checkpoint revision does not match",
                    ));
                }
                fs::remove_file(path).map_err(io_error)?;
                sync_directory(directory.as_ref())
            })
            .await
        })
    }
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, CheckpointStoreError> + Send + 'static,
) -> Result<T, CheckpointStoreError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            store_error(
                CheckpointStoreErrorCode::Unavailable,
                format!("checkpoint file task failed: {error}"),
            )
        })?
}

/// The records in `directory`: its `.json` files. What a write left behind
/// when the process died before its rename (`.json.tmp`) and what
/// [`FileCheckpointStore::set_aside_unreadable`] moved away are not records.
fn record_paths(directory: &Path) -> Result<Vec<PathBuf>, CheckpointStoreError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn read_record(path: &Path) -> Result<StoredCheckpoint, CheckpointStoreError> {
    let bytes = fs::read(path).map_err(io_error)?;
    let corrupt = |error: &dyn std::fmt::Display| {
        store_error(
            CheckpointStoreErrorCode::Corrupt,
            format!("checkpoint {} cannot be read: {error}", path.display()),
        )
    };
    let stored =
        serde_json::from_slice::<StoredCheckpoint>(&bytes).map_err(|error| corrupt(&error))?;
    stored
        .checkpoint
        .validate()
        .map_err(|error| corrupt(&error))?;
    Ok(stored)
}

/// Replaces the record at `path` so that a crash or a power loss at any point
/// leaves either the record that was there or the new one, whole. The bytes
/// reach the disk before the rename publishes them: a rename is metadata,
/// which the file system journals at once, while the bytes wait in the cache,
/// so without the flush a power loss can leave the record's name on an empty
/// or zero-filled file. The record is what the next start restores the
/// system from, and it is written before the OS is changed.
fn write_atomic(path: &Path, stored: &StoredCheckpoint) -> Result<(), CheckpointStoreError> {
    let bytes = serde_json::to_vec_pretty(stored)
        .map_err(|error| store_error(CheckpointStoreErrorCode::Corrupt, error.to_string()))?;
    let temporary = path.with_extension("json.tmp");
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, path).map_err(io_error)?;
    match path.parent() {
        Some(directory) => sync_directory(directory),
        None => Ok(()),
    }
}

/// Makes the renames and removals done in `directory` survive a power loss.
/// A Unix file system keeps a directory's entries in the directory, and only
/// a sync of the directory itself writes them out; a file system that cannot
/// sync a directory says so with one of the two kinds ignored here, and then
/// there is nothing more to do. Windows journals the entries with the rest of
/// the volume's metadata and has no directory handle to flush.
fn sync_directory(directory: &Path) -> Result<(), CheckpointStoreError> {
    #[cfg(unix)]
    match fs::File::open(directory).and_then(|directory| directory.sync_all()) {
        Err(error)
            if !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            return Err(io_error(error))
        }
        _ => {}
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), CheckpointStoreError> {
    fs::create_dir_all(path).map_err(io_error)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    Ok(())
}

/// Writes `bytes` to a file only its owner reads and flushes them to the
/// disk. On Windows the file takes the access list of the user's data
/// directory it is created in.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CheckpointStoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(io_error)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn io_error(error: io::Error) -> CheckpointStoreError {
    store_error(CheckpointStoreErrorCode::Unavailable, error.to_string())
}

fn store_error(code: CheckpointStoreErrorCode, message: impl Into<String>) -> CheckpointStoreError {
    CheckpointStoreError::new(code, message)
}
