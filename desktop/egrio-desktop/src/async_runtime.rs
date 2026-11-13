//! The process's tokio runtime for desktop work: Runtime transitions, profile
//! operations, background downloads and the history poll. A host whose event
//! loop owns the main thread gives this runtime's handle to anything else
//! that spawns tasks, so all of the process's async work shares one runtime.

use std::future::Future;
use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// The runtime, built on first use and kept for the process's lifetime.
pub fn handle() -> &'static tokio::runtime::Handle {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build the desktop tokio runtime")
        })
        .handle()
}

pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    handle().spawn(future)
}

pub fn spawn_blocking<F, R>(function: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    handle().spawn_blocking(function)
}
