use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use egrio_runtime::{
    CheckpointFuture, CheckpointId, CheckpointRevision, CheckpointStore, CheckpointStoreError,
    CheckpointStoreErrorCode, RecoveryCheckpoint, StoredCheckpoint,
};

#[derive(Clone, Debug, Default)]
pub struct InMemoryCheckpointStore {
    inner: Arc<Mutex<BTreeMap<CheckpointId, StoredCheckpoint>>>,
}

impl InMemoryCheckpointStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl CheckpointStore for InMemoryCheckpointStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        Box::pin(async move {
            let mut records = self.inner.lock().expect("checkpoint store mutex");
            if records.contains_key(&checkpoint.id) {
                return Err(store_error(
                    CheckpointStoreErrorCode::AlreadyExists,
                    "checkpoint already exists",
                ));
            }
            let stored = StoredCheckpoint {
                checkpoint,
                revision: CheckpointRevision::new(0),
            };
            records.insert(stored.checkpoint.id, stored.clone());
            Ok(stored)
        })
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        Box::pin(async move {
            Ok(self
                .inner
                .lock()
                .expect("checkpoint store mutex")
                .get(&id)
                .cloned())
        })
    }

    fn replace<'a>(
        &'a self,
        expected: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        Box::pin(async move {
            let mut records = self.inner.lock().expect("checkpoint store mutex");
            let current = records.get(&checkpoint.id).ok_or_else(|| {
                store_error(CheckpointStoreErrorCode::NotFound, "checkpoint not found")
            })?;
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
            records.insert(stored.checkpoint.id, stored.clone());
            Ok(stored)
        })
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        Box::pin(async move {
            Ok(self
                .inner
                .lock()
                .expect("checkpoint store mutex")
                .values()
                .cloned()
                .collect())
        })
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        expected: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        Box::pin(async move {
            let mut records = self.inner.lock().expect("checkpoint store mutex");
            let current = records.get(&id).ok_or_else(|| {
                store_error(CheckpointStoreErrorCode::NotFound, "checkpoint not found")
            })?;
            if current.revision != expected {
                return Err(store_error(
                    CheckpointStoreErrorCode::RevisionConflict,
                    "checkpoint revision does not match",
                ));
            }
            records.remove(&id);
            Ok(())
        })
    }
}

fn store_error(code: CheckpointStoreErrorCode, message: impl Into<String>) -> CheckpointStoreError {
    CheckpointStoreError::new(code, message)
}
