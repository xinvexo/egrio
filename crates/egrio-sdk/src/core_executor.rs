//! The threads the SDK's Runtimes run their Core on.
//!
//! Tokio runtimes with one worker each. The Core's packet pump, its relays and
//! the upstream tasks hand data to each other all the time; with a worker per
//! core each handoff parks one thread and wakes another. On one worker
//! those handoffs are queue pushes. A capture that spreads flows over
//! several queues gets an executor
//! per queue, so several flows use several cores while each flow's handoffs
//! stay on one thread; the first executor also runs the Runtime's own work.
//! Blocking work still goes to the runtimes' blocking pools, and the host's
//! own runtime (a GUI's IPC, for one) never shares the Core's threads.

use std::io;
use std::num::NonZeroUsize;

/// Executors at most, whatever the cores and the capture's queues.
const MAX_CORE_EXECUTORS: usize = 8;

pub(crate) struct CoreExecutors(Vec<tokio::runtime::Runtime>);

impl CoreExecutors {
    /// An executor per queue the capture can spread flows over, no more than
    /// the cores the process may use, and at least one.
    pub(crate) fn new(queues: usize) -> io::Result<Self> {
        let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let count = queues.min(cores).clamp(1, MAX_CORE_EXECUTORS);
        (0..count)
            .map(|index| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name(format!("egrio-core-{index}"))
                    .enable_all()
                    .build()
            })
            .collect::<io::Result<Vec<_>>>()
            .map(Self)
    }

    pub(crate) fn handles(&self) -> Vec<tokio::runtime::Handle> {
        self.0
            .iter()
            .map(|runtime| runtime.handle().clone())
            .collect()
    }
}

impl Drop for CoreExecutors {
    fn drop(&mut self) {
        // Dropping a runtime waits for its blocking pool, which an async
        // context forbids; what still runs on them ends with the SDK.
        for runtime in self.0.drain(..) {
            runtime.shutdown_background();
        }
    }
}
