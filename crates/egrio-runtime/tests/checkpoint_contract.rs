use egrio_runtime::{
    CapabilityCheckpoint, CheckpointId, CheckpointOperation, CheckpointPhase, CheckpointRevision,
    CheckpointStoreErrorCode, PlatformLeaseKey, RecoveryCheckpoint, RuntimeGeneration, RuntimeId,
    RECOVERY_CHECKPOINT_SCHEMA_VERSION,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn checkpoint_contract_has_exact_json_vocabulary() {
    assert_eq!(
        serde_json::to_string(&CheckpointOperation::Recover).unwrap(),
        r#""recover""#
    );
    assert_eq!(
        serde_json::to_string(&CheckpointPhase::RecoveryRequired).unwrap(),
        r#""recovery-required""#
    );
    assert_eq!(
        serde_json::to_string(&CheckpointStoreErrorCode::RevisionConflict).unwrap(),
        r#""revision-conflict""#
    );
}

#[test]
fn checkpoint_revision_preserves_value() {
    assert_eq!(CheckpointRevision::new(7).get(), 7);
    assert_eq!(CheckpointRevision::new(7).next().get(), 8);
}

#[test]
fn recovery_checkpoint_round_trips() {
    let checkpoint = RecoveryCheckpoint::new(
        CheckpointId::from_uuid(Uuid::from_u128(10)),
        RuntimeId::from_uuid(Uuid::from_u128(11)),
        RuntimeGeneration::new(3),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 1,
            payload: json!({"enabled": false}),
            rollback_payload: None,
        }],
    )
    .unwrap();
    assert_eq!(
        checkpoint.schema_version,
        RECOVERY_CHECKPOINT_SCHEMA_VERSION
    );
    assert_eq!(checkpoint.leases, vec![PlatformLeaseKey::system_proxy()]);
    let json = serde_json::to_string(&checkpoint).unwrap();
    assert!(!json.contains("rollback_payload"));
    assert_eq!(
        serde_json::from_str::<RecoveryCheckpoint>(&json).unwrap(),
        checkpoint
    );
}

#[test]
fn checkpoint_rejects_empty_capability_entries() {
    assert!(RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(0),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        Vec::new()
    )
    .is_err());
}

#[test]
fn checkpoint_rejects_duplicate_or_unversioned_capability_contracts() {
    let entry = CapabilityCheckpoint {
        lease_key: PlatformLeaseKey::system_proxy(),
        schema_version: 1,
        payload: json!({"enabled": false}),
        rollback_payload: None,
    };
    assert!(RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(0),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        vec![entry.clone(), entry],
    )
    .is_err());

    let mut checkpoint = RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(0),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 1,
            payload: json!({}),
            rollback_payload: None,
        }],
    )
    .unwrap();
    checkpoint.capabilities[0].schema_version = 0;
    assert!(checkpoint.validate().is_err());
}

#[test]
fn checkpoint_accepts_adapter_owned_capability_schema_versions() {
    let checkpoint = RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(1),
        CheckpointOperation::Reload,
        CheckpointPhase::Prepared,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::system_proxy(),
            schema_version: 2,
            payload: json!({"baseline": {}, "expected": {}}),
            rollback_payload: None,
        }],
    )
    .unwrap();

    checkpoint.validate().unwrap();
    assert_eq!(checkpoint.capabilities[0].schema_version, 2);
}

#[test]
fn checkpoint_accepts_secondary_leases_owned_by_a_capability() {
    let checkpoint = RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(1),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        vec![CapabilityCheckpoint {
            lease_key: PlatformLeaseKey::packet_capture(),
            schema_version: 1,
            payload: json!(null),
            rollback_payload: None,
        }],
    )
    .unwrap()
    .with_leases(vec![
        PlatformLeaseKey::packet_capture(),
        PlatformLeaseKey::default_route(),
    ])
    .unwrap();

    assert_eq!(checkpoint.leases.len(), 2);
    checkpoint.validate().unwrap();
}

#[test]
fn recovery_checkpoint_preserves_capability_transaction_order() {
    let ordered_keys = vec![
        PlatformLeaseKey::packet_capture(),
        PlatformLeaseKey::kill_switch(),
        PlatformLeaseKey::default_route(),
        PlatformLeaseKey::system_dns(),
    ];
    let checkpoint = RecoveryCheckpoint::new(
        CheckpointId::new(),
        RuntimeId::new(),
        RuntimeGeneration::new(1),
        CheckpointOperation::Start,
        CheckpointPhase::Prepared,
        ordered_keys
            .iter()
            .cloned()
            .map(|lease_key| CapabilityCheckpoint {
                lease_key,
                schema_version: 1,
                payload: json!(null),
                rollback_payload: None,
            })
            .collect(),
    )
    .unwrap();

    assert_eq!(
        checkpoint
            .capabilities
            .iter()
            .map(|capability| capability.lease_key.clone())
            .collect::<Vec<_>>(),
        ordered_keys
    );
    assert_eq!(
        checkpoint
            .capabilities
            .iter()
            .rev()
            .map(|capability| capability.lease_key.clone())
            .collect::<Vec<_>>(),
        [
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::packet_capture(),
        ]
    );
}
