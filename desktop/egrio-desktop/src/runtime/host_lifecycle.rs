use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Debug)]
struct State<A> {
    closing: bool,
    /// The platform's background activity, held while a capture layer is
    /// active.
    activity: Option<A>,
}

/// One admission boundary for host transitions and shutdown. The latch is
/// changed only while holding this same mutex, so a queued transition cannot
/// start after a shutdown that has already acquired ownership. The background
/// activity lives behind the same mutex: whoever holds the transition owns it.
#[derive(Debug)]
pub(super) struct HostLifecycle<A> {
    state: Arc<Mutex<State<A>>>,
}

impl<A> Default for HostLifecycle<A> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                closing: false,
                activity: None,
            })),
        }
    }
}

impl<A> Clone for HostLifecycle<A> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct HostTransition<A> {
    owner: Arc<Mutex<State<A>>>,
    state: OwnedMutexGuard<State<A>>,
}

impl<A> HostLifecycle<A> {
    /// Admits a transition; a closing host rejects it before any
    /// configuration or OS work.
    pub(super) async fn admit(&self) -> Result<HostTransition<A>, String> {
        let transition = self.lock().await;
        if transition.state.closing {
            return Err("the Runtime host is shutting down".into());
        }
        Ok(transition)
    }

    /// Serializes with transitions and shutdown without the admission check:
    /// stopping stays possible while the host shuts down.
    pub(super) async fn lock(&self) -> HostTransition<A> {
        HostTransition {
            owner: self.state.clone(),
            state: self.state.clone().lock_owned().await,
        }
    }

    pub(super) async fn shutdown(&self) -> HostTransition<A> {
        let mut transition = self.lock().await;
        // A failed cleanup never reopens admission. A second shutdown still
        // acquires the mutex and retries the Runtime restoration.
        transition.state.closing = true;
        transition
    }

    pub(super) fn validate(&self, transition: &HostTransition<A>) -> Result<(), String> {
        if !Arc::ptr_eq(&self.state, &transition.owner) {
            return Err("host transition belongs to another Runtime host".into());
        }
        if transition.state.closing {
            return Err("the Runtime host is shutting down".into());
        }
        Ok(())
    }
}

impl<A> HostTransition<A> {
    pub(super) fn begin_background_activity(&mut self, begin: impl FnOnce() -> A) {
        if self.state.activity.is_none() {
            self.state.activity = Some(begin());
        }
    }

    pub(super) fn end_background_activity(&mut self) {
        self.state.activity = None;
    }

    #[cfg(test)]
    pub(super) fn holds_background_activity(&self) -> bool {
        self.state.activity.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn shutdown_waits_for_admitted_work_and_rejects_the_next_operation() {
        let lifecycle = HostLifecycle::<()>::default();
        let admitted = lifecycle.admit().await.unwrap();
        lifecycle.validate(&admitted).unwrap();
        let mut shutdown = Box::pin(lifecycle.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err()
        );
        let mut queued = Box::pin(lifecycle.admit());
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut queued)
            .await
            .is_err());
        drop(admitted);
        let closing = shutdown.await;
        assert!(lifecycle.validate(&closing).is_err());
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut queued)
            .await
            .is_err());
        drop(closing);
        assert!(queued.await.is_err());
        // Stopping stays possible after shutdown.
        drop(lifecycle.lock().await);
    }

    #[tokio::test]
    async fn failed_shutdown_keeps_admission_closed_and_allows_cleanup_retry() {
        let lifecycle = HostLifecycle::<()>::default();
        let attempts = AtomicUsize::new(0);
        {
            let _closing = lifecycle.shutdown().await;
            attempts.fetch_add(1, Ordering::SeqCst);
            let failure: Result<(), &str> = Err("restore remains incomplete");
            assert!(failure.is_err());
        }
        assert!(lifecycle.admit().await.is_err());
        {
            let _retry = lifecycle.shutdown().await;
            attempts.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(lifecycle.admit().await.is_err());
    }

    #[tokio::test]
    async fn another_hosts_guard_cannot_authorize_a_mutation() {
        let first = HostLifecycle::<()>::default();
        let second = HostLifecycle::<()>::default();
        let guard = first.admit().await.unwrap();
        assert!(second.validate(&guard).is_err());
    }

    #[tokio::test]
    async fn the_background_activity_outlives_the_transition_that_began_it() {
        let lifecycle = HostLifecycle::<u8>::default();
        let mut begun = 0;
        let mut transition = lifecycle.admit().await.unwrap();
        transition.begin_background_activity(|| {
            begun += 1;
            7
        });
        drop(transition);
        let mut transition = lifecycle.admit().await.unwrap();
        assert!(transition.holds_background_activity());
        transition.begin_background_activity(|| {
            begun += 1;
            8
        });
        assert_eq!(begun, 1, "a held activity is not begun again");
        transition.end_background_activity();
        assert!(!transition.holds_background_activity());
    }
}
