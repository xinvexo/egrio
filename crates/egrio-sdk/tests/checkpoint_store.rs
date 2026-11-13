use egrio_runtime::{
    CapabilityCheckpoint, CheckpointId, CheckpointOperation, CheckpointPhase, CheckpointRevision,
    CheckpointStore, CheckpointStoreErrorCode, PlatformLeaseKey, RecoveryCheckpoint,
    RuntimeGeneration, RuntimeId,
};
use egrio_sdk::InMemoryCheckpointStore;
use serde_json::json;
use uuid::Uuid;

fn checkpoint(value: u128, phase: CheckpointPhase) -> RecoveryCheckpoint {
    RecoveryCheckpoint::new(
        CheckpointId::from_uuid(Uuid::from_u128(value)),
        RuntimeId::from_uuid(Uuid::from_u128(value + 100)),
        RuntimeGeneration::new(1),
        CheckpointOperation::Start,
        phase,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 1,
            payload: json!({"value": value}),
            rollback_payload: None,
        }],
    )
    .unwrap()
}

#[tokio::test]
async fn create_starts_at_revision_zero_and_rejects_duplicates() {
    let store = InMemoryCheckpointStore::new();
    let stored = store
        .create(checkpoint(1, CheckpointPhase::Prepared))
        .await
        .unwrap();
    assert_eq!(stored.revision, CheckpointRevision::new(0));
    let error = store
        .create(checkpoint(1, CheckpointPhase::Prepared))
        .await
        .unwrap_err();
    assert_eq!(error.code, CheckpointStoreErrorCode::AlreadyExists);
}

#[tokio::test]
async fn replace_and_delete_require_the_expected_revision() {
    let store = InMemoryCheckpointStore::new();
    let created = store
        .create(checkpoint(2, CheckpointPhase::Prepared))
        .await
        .unwrap();
    let updated = store
        .replace(created.revision, checkpoint(2, CheckpointPhase::Committed))
        .await
        .unwrap();
    assert_eq!(updated.revision, CheckpointRevision::new(1));
    let stale_replace = store
        .replace(created.revision, checkpoint(2, CheckpointPhase::Restoring))
        .await
        .unwrap_err();
    assert_eq!(
        stale_replace.code,
        CheckpointStoreErrorCode::RevisionConflict
    );
    let stale = store
        .delete(updated.checkpoint.id, CheckpointRevision::new(0))
        .await
        .unwrap_err();
    assert_eq!(stale.code, CheckpointStoreErrorCode::RevisionConflict);
    store
        .delete(updated.checkpoint.id, updated.revision)
        .await
        .unwrap();
    assert!(store.get(updated.checkpoint.id).await.unwrap().is_none());
}

#[tokio::test]
async fn committed_checkpoints_remain_unresolved_until_deleted() {
    let store = InMemoryCheckpointStore::new();
    store
        .create(checkpoint(4, CheckpointPhase::Committed))
        .await
        .unwrap();
    store
        .create(checkpoint(3, CheckpointPhase::Prepared))
        .await
        .unwrap();
    let unresolved = store.list_unresolved().await.unwrap();
    assert_eq!(
        unresolved
            .iter()
            .map(|entry| entry.checkpoint.id.as_uuid())
            .collect::<Vec<_>>(),
        vec![Uuid::from_u128(3), Uuid::from_u128(4)]
    );
}

#[tokio::test]
async fn clones_share_the_same_store_state() {
    let store = InMemoryCheckpointStore::new();
    let second_handle = store.clone();
    let created = store
        .create(checkpoint(5, CheckpointPhase::RecoveryRequired))
        .await
        .unwrap();
    assert_eq!(
        second_handle
            .get(created.checkpoint.id)
            .await
            .unwrap()
            .unwrap(),
        created
    );
}
