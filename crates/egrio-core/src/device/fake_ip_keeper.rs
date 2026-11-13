//! The fake-IP mappings a Core keeps for the next one. A client can hold a
//! fake IP beyond its answer's one-second TTL, across a new Core generation
//! or an app restart; the next Core takes the mappings back before it answers
//! anything, so such a client still reaches the name it asked for instead of
//! whichever name the address would have gone to. The host names the file
//! (`CoreStartInputs::fake_ip_mappings`); the Core reads it at start, writes
//! it every `SAVE_INTERVAL` when mappings were made since and at close. A Core
//! that ends without closing leaves the last save.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::dns::fake_ip::FakeDnsStore;
use crate::dns::fake_ip_file;

const SAVE_INTERVAL: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub(super) struct FakeIpKeeper {
    path: PathBuf,
    /// The store's count of mappings made at the last save.
    saved: AtomicU64,
    /// One save at a time.
    saving: Mutex<()>,
}

impl FakeIpKeeper {
    /// Takes back into `store` the mappings the file at `path` holds; a file
    /// that cannot be read holds none.
    pub(super) fn restore(path: PathBuf, store: &FakeDnsStore) -> Arc<Self> {
        if let Ok(mappings) = fake_ip_file::load(&path) {
            store.restore(mappings);
        }
        Arc::new(Self {
            path,
            saved: AtomicU64::new(store.changes()),
            saving: Mutex::new(()),
        })
    }

    /// Writes the store's mappings when some were made since the last save.
    /// A failed write is retried by the next save.
    pub(super) fn save(&self, store: &FakeDnsStore) {
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        if store.changes() == self.saved.load(Ordering::Relaxed) {
            return;
        }
        let (changes, mappings) = store.mappings();
        if fake_ip_file::save(&self.path, &mappings).is_ok() {
            self.saved.store(changes, Ordering::Relaxed);
        }
    }

    /// Saves every `SAVE_INTERVAL` off the async workers until `lifetime`
    /// ends; nothing without a Tokio runtime.
    pub(super) fn spawn_saver(self: &Arc<Self>, store: FakeDnsStore, lifetime: CancellationToken) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let keeper = Arc::clone(self);
        handle.spawn(async move {
            let mut ticks = tokio::time::interval(SAVE_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick is immediate; the restore just read the file.
            ticks.tick().await;
            loop {
                tokio::select! {
                    () = lifetime.cancelled() => return,
                    _ = ticks.tick() => {}
                }
                let keeper = Arc::clone(&keeper);
                let store = store.clone();
                let _ = tokio::task::spawn_blocking(move || keeper.save(&store)).await;
            }
        });
    }
}
