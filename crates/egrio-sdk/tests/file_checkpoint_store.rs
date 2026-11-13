use std::sync::Arc;

use egrio_runtime::{
    CapabilityCheckpoint, CheckpointId, CheckpointOperation, CheckpointPhase, CheckpointStore,
    PlatformLeaseKey, RecoveryCheckpoint, RuntimeGeneration, RuntimeId,
};
use egrio_sdk::FileCheckpointStore;
use serde_json::json;

fn checkpoint(id: CheckpointId) -> RecoveryCheckpoint {
    RecoveryCheckpoint::new(
        id,
        RuntimeId::new(),
        RuntimeGeneration::new(1),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 1,
            payload: json!(null),
            rollback_payload: None,
        }],
    )
    .unwrap()
}

#[tokio::test]
async fn file_store_persists_revisioned_checkpoints_across_instances() {
    let directory =
        std::env::temp_dir().join(format!("egrio-checkpoints-{}", uuid::Uuid::new_v4()));
    let first = Arc::new(FileCheckpointStore::new(&directory));
    let id = CheckpointId::new();
    let created = first.create(checkpoint(id)).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let checkpoint_path = directory.join(format!("{}.json", id.as_uuid()));
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(checkpoint_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let second = FileCheckpointStore::new(&directory);
    assert_eq!(
        second.list_unresolved().await.unwrap(),
        vec![created.clone()]
    );
    let mut next = created.checkpoint.clone();
    next.phase = CheckpointPhase::Committed;
    let replaced = second.replace(created.revision, next).await.unwrap();
    assert_eq!(replaced.revision.get(), 1);
    second.delete(id, replaced.revision).await.unwrap();
    assert!(first.list_unresolved().await.unwrap().is_empty());

    let _ = std::fs::remove_dir_all(directory);
}

/// A record no build can decode -- damaged bytes, or another build's schema --
/// fails every listing for as long as it stays, which is every start of a
/// host that lists at startup. Setting it aside leaves the records that can
/// be read, and the listing works again.
#[tokio::test]
async fn unreadable_records_fail_the_listing_until_they_are_set_aside() {
    let directory =
        std::env::temp_dir().join(format!("egrio-checkpoints-{}", uuid::Uuid::new_v4()));
    let store = FileCheckpointStore::new(&directory);
    let kept = store.create(checkpoint(CheckpointId::new())).await.unwrap();

    // What a power loss leaves of a record whose bytes never reached the disk.
    let damaged = directory.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&damaged, [0_u8; 64]).unwrap();
    // A record a build with another checkpoint schema wrote.
    let foreign_id = CheckpointId::new();
    let mut foreign = serde_json::to_value(egrio_runtime::StoredCheckpoint {
        checkpoint: checkpoint(foreign_id),
        revision: egrio_runtime::CheckpointRevision::new(0),
    })
    .unwrap();
    foreign["checkpoint"]["schema_version"] = json!(1);
    let foreign_path = directory.join(format!("{}.json", foreign_id.as_uuid()));
    std::fs::write(&foreign_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
    // What a write leaves when the process dies before its rename.
    std::fs::write(directory.join("interrupted.json.tmp"), b"{").unwrap();

    let error = store.list_unresolved().await.unwrap_err();
    assert_eq!(error.code, egrio_runtime::CheckpointStoreErrorCode::Corrupt);
    assert!(
        error.message.contains(".json"),
        "the error names the record: {error}"
    );

    let mut expected = vec![
        damaged.with_extension("json.unreadable"),
        foreign_path.with_extension("json.unreadable"),
    ];
    expected.sort();
    assert_eq!(store.set_aside_unreadable().unwrap(), expected);
    assert!(expected.iter().all(|path| path.exists()));
    assert!(!damaged.exists() && !foreign_path.exists());
    assert_eq!(store.list_unresolved().await.unwrap(), vec![kept.clone()]);
    // Nothing is left to set aside, and the readable record is untouched.
    assert!(store.set_aside_unreadable().unwrap().is_empty());
    store
        .delete(kept.checkpoint.id, kept.revision)
        .await
        .unwrap();
    assert!(store.list_unresolved().await.unwrap().is_empty());

    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn setting_aside_in_a_store_that_was_never_written_finds_nothing() {
    let directory =
        std::env::temp_dir().join(format!("egrio-checkpoints-{}", uuid::Uuid::new_v4()));
    assert!(FileCheckpointStore::new(&directory)
        .set_aside_unreadable()
        .unwrap()
        .is_empty());
    assert!(!directory.exists());
}
