use std::net::SocketAddr;
use std::sync::Arc;

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityKind, CheckpointFuture, CheckpointId, CheckpointOperation,
    CheckpointPhase, CheckpointRevision, CheckpointStore, CheckpointStoreError,
    CheckpointStoreErrorCode, PlatformLeaseKey, PlatformLeaseState, RecoveryCheckpoint,
    RecoveryCheckpointError, RuntimeGeneration, RuntimeId, RuntimePlatformSpec, RuntimeSpec,
    SystemProxyControl, SystemProxySettings, SystemProxySpec, RECOVERY_CHECKPOINT_SCHEMA_VERSION,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, RecoveryBootstrapError};
use serde_json::json;
use uuid::Uuid;

fn checkpoint(id: u128, runtime: u128, keys: Vec<PlatformLeaseKey>) -> RecoveryCheckpoint {
    checkpoint_in_phase(id, runtime, keys, CheckpointPhase::Committed)
}

fn proxy_spec(id: u128) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 7890))),
                https_proxy: None,
                bypass: Vec::new(),
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn checkpoint_in_phase(
    id: u128,
    runtime: u128,
    keys: Vec<PlatformLeaseKey>,
    phase: CheckpointPhase,
) -> RecoveryCheckpoint {
    RecoveryCheckpoint::new(
        CheckpointId::from_uuid(Uuid::from_u128(id)),
        RuntimeId::from_uuid(Uuid::from_u128(runtime)),
        RuntimeGeneration::new(1),
        CheckpointOperation::Recover,
        phase,
        keys.into_iter()
            .map(|lease_key| CapabilityCheckpoint {
                lease_key,
                schema_version: 1,
                payload: json!({"baseline": "persisted"}),
                rollback_payload: None,
            })
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn every_unresolved_phase_rebuilds_a_recovery_required_lease() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let phases = [
        CheckpointPhase::Prepared,
        CheckpointPhase::Applying,
        CheckpointPhase::Committed,
        CheckpointPhase::Restoring,
        CheckpointPhase::RecoveryRequired,
    ];
    let mut keys = Vec::new();
    for (index, phase) in phases.into_iter().enumerate() {
        let key = PlatformLeaseKey::new("test-capability", format!("phase-{index}")).unwrap();
        store
            .create(checkpoint_in_phase(
                100 + index as u128,
                200 + index as u128,
                vec![key.clone()],
                phase,
            ))
            .await
            .unwrap();
        keys.push(key);
    }
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    sdk.bootstrap_recovery().await.unwrap();
    for key in keys {
        assert_eq!(
            sdk.lease_status(&key).state,
            PlatformLeaseState::RecoveryRequired
        );
    }
}

#[tokio::test]
async fn builder_requires_a_checkpoint_store() {
    assert!(EgrioSdk::builder().build().is_err());
}

#[tokio::test]
async fn bootstrap_reserves_every_unresolved_lease_as_recovery_required() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    store
        .create(checkpoint(
            1,
            10,
            vec![
                PlatformLeaseKey::system_proxy(),
                PlatformLeaseKey::default_route(),
            ],
        ))
        .await
        .unwrap();
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    let report = sdk.bootstrap_recovery().await.unwrap();
    assert_eq!(report.checkpoints.len(), 1);
    assert_eq!(report.blocked_leases.len(), 2);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
}

#[tokio::test]
async fn bootstrap_can_execute_checkpoint_driven_recovery_and_release_leases() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    {
        let sdk = EgrioSdk::builder()
            .checkpoint_store(store.clone())
            .platform(platform.clone())
            .build()
            .unwrap();
        let runtime = sdk.create_runtime(proxy_spec(900)).await.unwrap();
        runtime.start().await.unwrap();
    }
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );

    let recovered = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    platform.fail_next_restore(CapabilityKind::SystemProxy, "injected recovery failure");
    assert!(recovered.recover_unresolved().await.is_err());
    assert_eq!(
        recovered
            .lease_status(&PlatformLeaseKey::system_proxy())
            .state,
        PlatformLeaseState::RecoveryRequired
    );
    assert_eq!(store.list_unresolved().await.unwrap().len(), 1);

    let reports = recovered.recover_unresolved().await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].restored);
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        recovered
            .lease_status(&PlatformLeaseKey::system_proxy())
            .state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn unverified_recovery_returns_checkpoint_and_lease_to_recovery_required() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    {
        let sdk = EgrioSdk::builder()
            .checkpoint_store(store.clone())
            .platform(platform.clone())
            .build()
            .unwrap();
        let runtime = sdk.create_runtime(proxy_spec(901)).await.unwrap();
        runtime.start().await.unwrap();
    }

    let recovered = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    platform.unverify_next_restore(CapabilityKind::SystemProxy);

    assert!(recovered.recover_unresolved().await.is_err());
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .phase,
        CheckpointPhase::RecoveryRequired
    );
    assert_eq!(
        recovered
            .lease_status(&PlatformLeaseKey::system_proxy())
            .state,
        PlatformLeaseState::RecoveryRequired
    );

    let reports = recovered.recover_unresolved().await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].restored);
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        recovered
            .lease_status(&PlatformLeaseKey::system_proxy())
            .state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn bootstrap_is_idempotent_and_does_not_change_checkpoint_phase() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let created = store
        .create(checkpoint(2, 20, vec![PlatformLeaseKey::system_dns()]))
        .await
        .unwrap();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .build()
        .unwrap();
    assert_eq!(
        sdk.bootstrap_recovery().await.unwrap(),
        sdk.bootstrap_recovery().await.unwrap()
    );
    assert_eq!(
        store
            .get(created.checkpoint.id)
            .await
            .unwrap()
            .unwrap()
            .checkpoint
            .phase,
        CheckpointPhase::Committed
    );
}

#[tokio::test]
async fn conflicting_checkpoint_batch_fails_without_partial_reservations() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    store
        .create(checkpoint(3, 30, vec![PlatformLeaseKey::system_proxy()]))
        .await
        .unwrap();
    store
        .create(checkpoint(
            4,
            40,
            vec![
                PlatformLeaseKey::default_route(),
                PlatformLeaseKey::system_proxy(),
            ],
        ))
        .await
        .unwrap();
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    assert!(matches!(
        sdk.bootstrap_recovery().await.unwrap_err(),
        RecoveryBootstrapError::Reservation(_)
    ));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::RecoveryRequired
    );
}

#[derive(Debug)]
struct FailingStore;
impl CheckpointStore for FailingStore {
    fn create<'a>(
        &'a self,
        _: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, egrio_runtime::StoredCheckpoint> {
        Box::pin(async { Err(unavailable()) })
    }
    fn get<'a>(
        &'a self,
        _: CheckpointId,
    ) -> CheckpointFuture<'a, Option<egrio_runtime::StoredCheckpoint>> {
        Box::pin(async { Err(unavailable()) })
    }
    fn replace<'a>(
        &'a self,
        _: CheckpointRevision,
        _: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, egrio_runtime::StoredCheckpoint> {
        Box::pin(async { Err(unavailable()) })
    }
    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<egrio_runtime::StoredCheckpoint>> {
        Box::pin(async { Err(unavailable()) })
    }
    fn delete<'a>(&'a self, _: CheckpointId, _: CheckpointRevision) -> CheckpointFuture<'a, ()> {
        Box::pin(async { Err(unavailable()) })
    }
}
fn unavailable() -> CheckpointStoreError {
    CheckpointStoreError::new(
        CheckpointStoreErrorCode::Unavailable,
        "injected store failure",
    )
}

#[tokio::test]
async fn store_failure_keeps_bootstrap_unready() {
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(FailingStore))
        .build()
        .unwrap();
    assert_eq!(
        sdk.bootstrap_recovery()
            .await
            .unwrap_err()
            .store_error()
            .unwrap()
            .code,
        CheckpointStoreErrorCode::Unavailable
    );
}

#[tokio::test]
async fn invalid_checkpoints_fail_before_reserving_leases() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let mut unsupported = checkpoint(5, 50, vec![PlatformLeaseKey::kill_switch()]);
    unsupported.schema_version = RECOVERY_CHECKPOINT_SCHEMA_VERSION + 1;
    store.create(unsupported).await.unwrap();
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    assert!(matches!(
        sdk.bootstrap_recovery().await.unwrap_err(),
        RecoveryBootstrapError::UnsupportedSchema { .. }
    ));

    let store = Arc::new(InMemoryCheckpointStore::new());
    let mut inconsistent = checkpoint(7, 70, vec![PlatformLeaseKey::system_proxy()]);
    inconsistent.leases = vec![PlatformLeaseKey::default_route()];
    store.create(inconsistent).await.unwrap();
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    assert!(matches!(
        sdk.bootstrap_recovery().await.unwrap_err(),
        RecoveryBootstrapError::InvalidCheckpoint {
            error: RecoveryCheckpointError::LeaseSetMismatch,
            ..
        }
    ));
}

#[tokio::test]
async fn nil_runtime_id_is_rejected_before_reserving_leases() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let mut invalid = checkpoint(8, 80, vec![PlatformLeaseKey::kill_switch()]);
    invalid.runtime_id = RuntimeId::from_uuid(Uuid::nil());
    store.create(invalid).await.unwrap();
    let sdk = EgrioSdk::builder().checkpoint_store(store).build().unwrap();
    assert!(matches!(
        sdk.bootstrap_recovery().await.unwrap_err(),
        RecoveryBootstrapError::InvalidCheckpoint {
            error: RecoveryCheckpointError::NilRuntimeId,
            ..
        }
    ));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::kill_switch()).state,
        PlatformLeaseState::Available
    );
}
