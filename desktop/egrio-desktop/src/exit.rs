//! The single quit path. An explicit quit first stops the Runtime, which
//! restores what the capture layers changed in the OS, while the host's main
//! loop stays available; only then does it hand the host its process exit.
//! Window closes never quit: the tray process outlives its last window.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::runtime::DesktopRuntime;

const RUNNING: u8 = 0;
const STOPPING: u8 = 1;
const READY_TO_EXIT: u8 = 2;

#[derive(Default)]
struct QuitCoordinator(AtomicU8);

impl QuitCoordinator {
    fn begin(&self) -> bool {
        self.0
            .compare_exchange(RUNNING, STOPPING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn is_quitting(&self) -> bool {
        self.0.load(Ordering::SeqCst) != RUNNING
    }
    fn is_ready(&self) -> bool {
        self.0.load(Ordering::SeqCst) == READY_TO_EXIT
    }
    fn finish(&self) {
        self.0.store(READY_TO_EXIT, Ordering::SeqCst);
    }
}

static QUIT: QuitCoordinator = QuitCoordinator(AtomicU8::new(RUNNING));

/// A quit has begun; revealing a window cannot cancel it.
pub fn is_quitting() -> bool {
    QUIT.is_quitting()
}

/// The quit's cleanup has finished, so the process may exit now.
pub fn is_ready_to_exit() -> bool {
    QUIT.is_ready()
}

/// Begins the quit: stops the Runtime, then calls `exit` once, whether or not
/// the cleanup succeeded (a failed cleanup keeps its recovery checkpoint).
/// Repeated requests join the first one and their `exit` is never called.
pub fn request_quit(runtime: &DesktopRuntime, exit: impl FnOnce() + Send + 'static) {
    if !QUIT.begin() {
        return;
    }
    let runtime = runtime.clone();
    crate::async_runtime::spawn(async move {
        finish_quit(&QUIT, runtime.shutdown(), exit).await;
    });
}

async fn finish_quit(
    coordinator: &QuitCoordinator,
    cleanup: impl std::future::Future<Output = Result<(), String>>,
    exit: impl FnOnce(),
) {
    log::info!("exit network teardown started");
    match cleanup.await {
        Ok(()) => log::info!("exit network teardown finished"),
        Err(error) => {
            log::error!("exit network teardown failed; recovery checkpoint retained: {error}")
        }
    }
    coordinator.finish();
    exit();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, Arc};

    #[test]
    fn concurrent_quit_requests_accept_one_cleanup_and_never_reset_intent() {
        let coordinator = Arc::new(QuitCoordinator::default());
        let workers = (0..16)
            .map(|_| {
                let coordinator = coordinator.clone();
                std::thread::spawn(move || coordinator.begin())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|accepted| *accepted)
                .count(),
            1
        );
        assert!(coordinator.is_quitting());
        assert!(!coordinator.is_ready());
        coordinator.finish();
        assert!(coordinator.is_ready());
        assert!(!coordinator.begin());
    }

    #[tokio::test]
    async fn process_exit_waits_for_async_cleanup_even_when_recovery_fails() {
        for successful in [false, true] {
            let coordinator = Arc::new(QuitCoordinator::default());
            assert!(coordinator.begin());
            let exited = Arc::new(AtomicBool::new(false));
            let (release, wait) = tokio::sync::oneshot::channel();
            let task_coordinator = coordinator.clone();
            let task_exited = exited.clone();
            let task = tokio::spawn(async move {
                finish_quit(
                    &task_coordinator,
                    async {
                        wait.await.unwrap();
                        if successful {
                            Ok(())
                        } else {
                            Err("mock recovery failure".into())
                        }
                    },
                    || task_exited.store(true, Ordering::SeqCst),
                )
                .await;
            });
            tokio::task::yield_now().await;
            assert!(!exited.load(Ordering::SeqCst));
            assert!(!coordinator.is_ready());
            release.send(()).unwrap();
            task.await.unwrap();
            assert!(coordinator.is_ready());
            assert!(exited.load(Ordering::SeqCst));
        }
    }
}
