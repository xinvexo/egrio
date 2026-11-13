//! Shared ownership of the packet worker. Completion and an explicit
//! stop request are serialized in one state cell; requesting stop never rewrites
//! an outcome that was already published. No lifecycle operation waits on the
//! completion callback, which may itself need the Runtime operation lock.

use std::any::Any;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TaskId(u64);

#[derive(Debug, Clone)]
pub(super) enum TaskFailure {
    Operation(String),
    Panic(String),
}

impl std::fmt::Display for TaskFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(message) => message.fmt(f),
            Self::Panic(message) => write!(f, "worker panicked: {message}"),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Completion<R> {
    pub result: Result<R, TaskFailure>,
    pub expected_stop: bool,
}

#[derive(Debug)]
struct State<R> {
    stop_requested: bool,
    completion: Option<Completion<R>>,
}

#[derive(Debug)]
pub(super) struct ManagedTask<R> {
    id: TaskId,
    state: Arc<Mutex<State<R>>>,
    started: Option<oneshot::Receiver<()>>,
    join: JoinHandle<()>,
}

impl<R: Clone + Send + 'static> ManagedTask<R> {
    /// Spawns `future` on `executor`, or on the calling runtime without one.
    pub fn spawn(
        executor: Option<&tokio::runtime::Handle>,
        future: impl Future<Output = Result<R, String>> + Send + 'static,
        completed: impl FnOnce(TaskId) + Send + 'static,
    ) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let state = Arc::new(Mutex::new(State {
            stop_requested: false,
            completion: None,
        }));
        let worker_state = state.clone();
        let (started_tx, started) = oneshot::channel();
        let worker = async move {
            let mut started_tx = Some(started_tx);
            let mut future = Box::pin(future);
            let (result, expected_stop) = poll_fn(|cx| {
                // Catch the worker's panic at its polling boundary so its
                // owner receives the same completion event as an ordinary Err.
                let polled = match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                    Ok(Poll::Ready(result)) => Poll::Ready(result.map_err(TaskFailure::Operation)),
                    Ok(Poll::Pending) => Poll::Pending,
                    Err(payload) => Poll::Ready(Err(TaskFailure::Panic(panic_message(payload)))),
                };
                match polled {
                    Poll::Pending => {
                        if let Some(started) = started_tx.take() {
                            let _ = started.send(());
                        }
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        // The worker result precedes resource destruction. A
                        // stop racing with Drop must not relabel an earlier
                        // failure as cancellation collateral. Keep this fact
                        // private until Drop releases the exit barrier below.
                        let expected_stop = worker_state
                            .lock()
                            .expect("managed task state")
                            .stop_requested;
                        Poll::Ready((result, expected_stop))
                    }
                }
            })
            .await;
            let result = match catch_unwind(AssertUnwindSafe(|| drop(future))) {
                Ok(()) => result,
                Err(payload) => Err(TaskFailure::Panic(panic_message(payload))),
            };
            {
                let mut state = worker_state.lock().expect("managed task state");
                state.completion = Some(Completion {
                    result,
                    expected_stop,
                });
            }
            // A worker that finishes on its first poll publishes completion
            // before releasing startup, without a yield/is_finished heuristic.
            if let Some(started) = started_tx.take() {
                let _ = started.send(());
            }
            completed(id);
        };
        let join = match executor {
            Some(executor) => executor.spawn(worker),
            None => tokio::spawn(worker),
        };
        Self {
            id,
            state,
            started: Some(started),
            join,
        }
    }

    pub fn id(&self) -> TaskId {
        self.id
    }

    pub fn completion(&self) -> Option<Completion<R>> {
        self.state
            .lock()
            .expect("managed task state")
            .completion
            .clone()
    }

    pub fn request_stop(&self) {
        self.state
            .lock()
            .expect("managed task state")
            .stop_requested = true;
    }

    pub async fn started(&mut self) -> Result<(), String> {
        if let Some(started) = self.started.take() {
            started
                .await
                .map_err(|_| "worker ended before first poll".to_string())?;
        }
        Ok(())
    }

    pub async fn join(&mut self) -> Result<Completion<R>, String> {
        (&mut self.join)
            .await
            .map_err(|error| format!("worker task failed: {error}"))?;
        self.completion()
            .ok_or_else(|| "worker exited without a completion result".into())
    }
}

impl<R> Drop for ManagedTask<R> {
    fn drop(&mut self) {
        self.join.abort();
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).into()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn first_poll_failure_is_published_before_startup_and_cannot_be_reclassified() {
        let mut worker =
            ManagedTask::<()>::spawn(None, async { Err("startup failed".into()) }, |_| {});
        worker.started().await.unwrap();
        assert!(worker.completion().is_some());
        worker.request_stop();
        let completion = worker.join().await.unwrap();
        assert!(!completion.expected_stop);
        assert!(
            matches!(completion.result, Err(TaskFailure::Operation(error)) if error == "startup failed")
        );
    }

    #[tokio::test]
    async fn a_worker_panic_has_a_completion_fact_and_notifies_its_owner() {
        let (finish, waiting) = oneshot::channel();
        let (notify, notified) = oneshot::channel();
        let mut worker = ManagedTask::<()>::spawn(
            None,
            async move {
                waiting.await.unwrap();
                panic!("packet worker panic");
            },
            move |id| {
                notify.send(id).unwrap();
            },
        );
        worker.started().await.unwrap();
        finish.send(()).unwrap();
        assert_eq!(notified.await.unwrap(), worker.id());
        let completion = worker.join().await.unwrap();
        assert!(!completion.expected_stop);
        assert!(
            matches!(completion.result, Err(TaskFailure::Panic(error)) if error == "packet worker panic")
        );
    }

    #[tokio::test]
    async fn joining_a_worker_does_not_wait_for_its_lifecycle_notification() {
        let operation = Arc::new(tokio::sync::Mutex::new(()));
        let guard = operation.lock().await;
        let callback_operation = operation.clone();
        let (finish, waiting) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let mut worker = ManagedTask::spawn(
            None,
            async move { waiting.await.map_err(|error| error.to_string()) },
            move |_| {
                tokio::spawn(async move {
                    let _guard = callback_operation.lock().await;
                    done.send(()).unwrap();
                });
            },
        );
        worker.started().await.unwrap();
        worker.request_stop();
        finish.send(()).unwrap();
        let completion = tokio::time::timeout(Duration::from_secs(1), worker.join())
            .await
            .unwrap()
            .unwrap();
        assert!(completion.expected_stop);
        drop(guard);
        finished.await.unwrap();
    }

    #[tokio::test]
    async fn stop_racing_with_resource_drop_does_not_reclassify_the_worker_result() {
        struct BlockingDrop {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
            panic: bool,
        }
        impl Future for BlockingDrop {
            type Output = Result<(), String>;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<Self::Output> {
                Poll::Ready(Err("worker failed before stop".into()))
            }
        }
        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                assert!(!self.panic, "resource drop panic");
            }
        }
        for panic in [false, true] {
            let (entered, dropping) = std::sync::mpsc::channel();
            let (release, waiting) = std::sync::mpsc::channel();
            let (notify, notified) = oneshot::channel();
            let worker = Arc::new(ManagedTask::spawn(
                None,
                BlockingDrop {
                    entered,
                    release: waiting,
                    panic,
                },
                move |_| {
                    notify.send(()).unwrap();
                },
            ));
            let stopping = worker.clone();
            // Use an actual second OS thread: Drop blocks the async worker,
            // precisely separating poll Ready from the resource exit barrier.
            let requester = std::thread::spawn(move || {
                dropping.recv().unwrap();
                stopping.request_stop();
                assert!(
                    stopping.completion().is_none(),
                    "poll Ready alone is not a released-resource fact"
                );
                release.send(()).unwrap();
            });
            notified.await.unwrap();
            requester.join().unwrap();
            let mut worker = Arc::try_unwrap(worker).expect("requester released task handle");
            worker.started().await.unwrap();
            let completion = worker.join().await.unwrap();
            assert!(
                !completion.expected_stop,
                "stop during Drop cannot rewrite the earlier result"
            );
            if panic {
                assert!(
                    matches!(completion.result, Err(TaskFailure::Panic(error)) if error == "resource drop panic")
                );
            } else {
                assert!(
                    matches!(completion.result, Err(TaskFailure::Operation(error)) if error == "worker failed before stop")
                );
            }
        }
    }

    #[tokio::test]
    async fn dropping_the_owner_cancels_the_worker_and_releases_its_resources() {
        struct OnDrop(Option<oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let (dropped, received) = oneshot::channel();
        let mut worker = ManagedTask::<()>::spawn(
            None,
            async move {
                let _resource = OnDrop(Some(dropped));
                std::future::pending().await
            },
            |_| {},
        );
        worker.started().await.unwrap();
        drop(worker);
        tokio::time::timeout(Duration::from_secs(1), received)
            .await
            .unwrap()
            .unwrap();
    }
}
