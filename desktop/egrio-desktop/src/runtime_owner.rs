//! One desktop Runtime owner per user: the app data directory's lock is held
//! for the process's lifetime, so a second process the desktop did not route
//! to the running one cannot drive the same service and checkpoints. macOS
//! takes it after LaunchServices has had its say; Linux takes it because a
//! session without a bus leaves GApplication's uniqueness with nothing to
//! register against.

use std::os::fd::AsRawFd;

/// Holds the lock until dropped.
pub struct RuntimeOwnerLock {
    _file: std::fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeOwnerError {
    /// Another process of this user holds the lock: the app runs already.
    Held(String),
    /// The lock could not be taken for another reason.
    Unavailable(String),
}

impl std::fmt::Display for RuntimeOwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(message) | Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RuntimeOwnerError {}

pub fn acquire() -> Result<RuntimeOwnerLock, RuntimeOwnerError> {
    let data_directory =
        crate::app_paths::app_data_dir().map_err(RuntimeOwnerError::Unavailable)?;
    std::fs::create_dir_all(&data_directory).map_err(|error| {
        RuntimeOwnerError::Unavailable(format!(
            "create app data directory for the Runtime lock: {error}"
        ))
    })?;
    let lock_path = data_directory.join("runtime-owner.lock");
    // The file's contents are irrelevant (flock is the lock); never truncate,
    // so racing openers cannot clobber each other before flock decides.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            RuntimeOwnerError::Unavailable(format!(
                "open the Runtime lock {}: {error}",
                lock_path.display()
            ))
        })?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let message = format!(
            "another Runtime owner already holds {}: {error}",
            lock_path.display()
        );
        // flock(2): a non-blocking request on a held lock fails with EWOULDBLOCK.
        return Err(if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            RuntimeOwnerError::Held(message)
        } else {
            RuntimeOwnerError::Unavailable(message)
        });
    }
    Ok(RuntimeOwnerLock { _file: file })
}
