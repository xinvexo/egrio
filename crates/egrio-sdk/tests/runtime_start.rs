use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityErrorCode, CapabilityFuture, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, CapabilitySupport, CheckpointFuture,
    CheckpointId, CheckpointPhase, CheckpointRevision, CheckpointStore, CheckpointStoreError,
    CheckpointStoreErrorCode, LeaseCoordinator, LeaseExpandError, LeaseGrant, LeaseReleaseEvidence,
    LeaseRequestSet, LeaseTransitionError, LeaseTransitionErrorCode, PlatformLeaseConflict,
    PlatformLeaseKey, PlatformLeaseState, RecoveryCheckpoint, RouteControl, RouteSettings, Runtime,
    RuntimeId, RuntimePlatformSpec, RuntimePorts, RuntimeReloadError, RuntimeSpec,
    RuntimeStartError, RuntimeState, RuntimeStopError, StoredCheckpoint, SystemProxyControl,
    SystemProxySettings, SystemProxySpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, PlatformLeaseCoordinator};
use uuid::Uuid;

fn spec(id: u128, port: u16) -> RuntimeSpec {
    RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(id)),
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec::from_settings(SystemProxySettings {
                http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], port))),
                https_proxy: None,
                bypass: Vec::new(),
            })),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap()
}

fn spec_with_route(id: u128, port: u16) -> RuntimeSpec {
    let mut value = spec(id, port);
    value.platform.route = Some(RouteSettings {
        default_route: true,
        excluded_prefixes: Vec::new(),
    });
    value
}

#[derive(Debug)]
struct SchemaTwoSystemProxy {
    inner: Arc<InMemoryPlatform>,
}

#[derive(Clone, Copy, Debug)]
enum InvalidCheckpointContract {
    Unversioned,
    ForeignLease,
}

#[derive(Debug)]
struct InvalidCheckpointSystemProxy {
    inner: Arc<InMemoryPlatform>,
    contract: InvalidCheckpointContract,
}

#[derive(Debug)]
struct ToggleInvalidSystemProxy {
    inner: Arc<InMemoryPlatform>,
    invalid: AtomicBool,
}

#[derive(Debug)]
struct InvalidCheckpointRoute {
    inner: Arc<InMemoryPlatform>,
}

impl SystemProxyControl for InvalidCheckpointSystemProxy {
    fn support(&self) -> CapabilitySupport {
        SystemProxyControl::support(self.inner.as_ref())
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let mut checkpoint = SystemProxyControl::prepare(self.inner.as_ref(), settings).await?;
            match self.contract {
                InvalidCheckpointContract::Unversioned => checkpoint.schema_version = 0,
                InvalidCheckpointContract::ForeignLease => {
                    checkpoint.lease_key = PlatformLeaseKey::system_dns();
                }
            }
            Ok(checkpoint)
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        SystemProxyControl::apply(self.inner.as_ref(), settings)
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        SystemProxyControl::observe(self.inner.as_ref())
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        SystemProxyControl::restore(self.inner.as_ref(), checkpoint)
    }
}

impl SystemProxyControl for ToggleInvalidSystemProxy {
    fn support(&self) -> CapabilitySupport {
        SystemProxyControl::support(self.inner.as_ref())
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let mut checkpoint = SystemProxyControl::prepare(self.inner.as_ref(), settings).await?;
            if self.invalid.load(Ordering::SeqCst) {
                checkpoint.schema_version = 0;
            }
            Ok(checkpoint)
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        SystemProxyControl::apply(self.inner.as_ref(), settings)
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        SystemProxyControl::observe(self.inner.as_ref())
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        SystemProxyControl::restore(self.inner.as_ref(), checkpoint)
    }
}

impl RouteControl for InvalidCheckpointRoute {
    fn support(&self) -> CapabilitySupport {
        RouteControl::support(self.inner.as_ref())
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a RouteSettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let mut checkpoint = RouteControl::prepare(self.inner.as_ref(), settings).await?;
            checkpoint.schema_version = 0;
            Ok(checkpoint)
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a RouteSettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        RouteControl::apply(self.inner.as_ref(), settings)
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        RouteControl::observe(self.inner.as_ref())
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        RouteControl::restore(self.inner.as_ref(), checkpoint)
    }
}

impl SystemProxyControl for SchemaTwoSystemProxy {
    fn support(&self) -> CapabilitySupport {
        SystemProxyControl::support(self.inner.as_ref())
    }

    fn prepare<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityCheckpoint> {
        Box::pin(async move {
            let mut checkpoint = SystemProxyControl::prepare(self.inner.as_ref(), settings).await?;
            checkpoint.schema_version = 2;
            Ok(checkpoint)
        })
    }

    fn apply<'a>(
        &'a self,
        settings: &'a SystemProxySettings,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        SystemProxyControl::apply(self.inner.as_ref(), settings)
    }

    fn observe<'a>(&'a self) -> CapabilityFuture<'a, CapabilityObservation> {
        SystemProxyControl::observe(self.inner.as_ref())
    }

    fn restore<'a>(
        &'a self,
        checkpoint: &'a CapabilityCheckpoint,
    ) -> CapabilityFuture<'a, CapabilityOperationReport> {
        let mut checkpoint = checkpoint.clone();
        checkpoint.schema_version = 1;
        Box::pin(async move { SystemProxyControl::restore(self.inner.as_ref(), &checkpoint).await })
    }
}

#[derive(Debug)]
struct FailingReplaceStore {
    inner: InMemoryCheckpointStore,
}

#[derive(Debug)]
struct FailOnReplaceCallStore {
    inner: InMemoryCheckpointStore,
    replace_calls: AtomicUsize,
    fail_on: usize,
}

#[derive(Debug)]
struct FailOnceDeleteStore {
    inner: InMemoryCheckpointStore,
    delete_calls: AtomicUsize,
}

#[derive(Debug)]
struct FailOnCreateCallStore {
    inner: InMemoryCheckpointStore,
    create_calls: AtomicUsize,
    fail_on: usize,
}

#[derive(Debug, Default)]
struct FaultLeaseCoordinator {
    inner: PlatformLeaseCoordinator,
    fail_next_release: AtomicBool,
    fail_next_shrink: AtomicBool,
}

impl FaultLeaseCoordinator {
    fn status(&self, key: &PlatformLeaseKey) -> egrio_sdk::PlatformLeaseStatus {
        self.inner.status(key)
    }
}

impl LeaseCoordinator for FaultLeaseCoordinator {
    fn acquire_all(&self, request: LeaseRequestSet) -> Result<LeaseGrant, PlatformLeaseConflict> {
        self.inner.acquire_all(request)
    }

    fn expand(
        &self,
        grant: &LeaseGrant,
        request: LeaseRequestSet,
    ) -> Result<LeaseGrant, LeaseExpandError> {
        self.inner.expand(grant, request)
    }

    fn begin_release(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.begin_release(grant)
    }

    fn mark_recovery_required(
        &self,
        grant: &LeaseGrant,
        checkpoint_id: CheckpointId,
    ) -> Result<(), LeaseTransitionError> {
        self.inner.mark_recovery_required(grant, checkpoint_id)
    }

    fn begin_recovery(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.begin_recovery(grant)
    }

    fn resume(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        self.inner.resume(grant)
    }

    fn shrink(
        &self,
        grant: &LeaseGrant,
        retained_keys: Vec<PlatformLeaseKey>,
        evidence: LeaseReleaseEvidence,
    ) -> Result<LeaseGrant, LeaseTransitionError> {
        if self.fail_next_shrink.swap(false, Ordering::SeqCst) {
            return Err(LeaseTransitionError {
                code: LeaseTransitionErrorCode::InvalidState,
                message: "injected lease shrink failure".into(),
            });
        }
        self.inner.shrink(grant, retained_keys, evidence)
    }

    fn release(
        &self,
        grant: &LeaseGrant,
        evidence: LeaseReleaseEvidence,
    ) -> Result<(), LeaseTransitionError> {
        if self.fail_next_release.swap(false, Ordering::SeqCst) {
            return Err(LeaseTransitionError {
                code: LeaseTransitionErrorCode::InvalidState,
                message: "injected lease release failure".into(),
            });
        }
        self.inner.release(grant, evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointBlockPoint {
    Replace(usize),
    Delete,
}

#[derive(Debug)]
struct BlockingCheckpointStore {
    inner: InMemoryCheckpointStore,
    replace_calls: AtomicUsize,
    block: CheckpointBlockPoint,
    entered: Notify,
    release: Notify,
}

impl BlockingCheckpointStore {
    fn new(block: CheckpointBlockPoint) -> Self {
        Self {
            inner: InMemoryCheckpointStore::new(),
            replace_calls: AtomicUsize::new(0),
            block,
            entered: Notify::new(),
            release: Notify::new(),
        }
    }
}

impl CheckpointStore for BlockingCheckpointStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.create(checkpoint)
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }

    fn replace<'a>(
        &'a self,
        revision: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        let call = self.replace_calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            if self.block == CheckpointBlockPoint::Replace(call) {
                // Registered before the entry is signalled: the Runtime runs
                // on its own executor, so the test's release can come first.
                let release = self.release.notified();
                self.entered.notify_waiters();
                release.await;
            }
            self.inner.replace(revision, checkpoint).await
        })
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        Box::pin(async move {
            if self.block == CheckpointBlockPoint::Delete {
                // Registered before the entry is signalled: the Runtime runs
                // on its own executor, so the test's release can come first.
                let release = self.release.notified();
                self.entered.notify_waiters();
                release.await;
            }
            self.inner.delete(id, revision).await
        })
    }
}

async fn wait_for_state(runtime: &egrio_runtime::Runtime, expected: RuntimeState) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if runtime.status().state == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Runtime transaction reached its terminal state");
}

impl CheckpointStore for FailOnReplaceCallStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.create(checkpoint)
    }
    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }
    fn replace<'a>(
        &'a self,
        revision: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        let call = self.replace_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_on {
            Box::pin(async {
                Err(CheckpointStoreError::new(
                    CheckpointStoreErrorCode::Unavailable,
                    "injected replace failure",
                ))
            })
        } else {
            self.inner.replace(revision, checkpoint)
        }
    }
    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }
    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        self.inner.delete(id, revision)
    }
}

impl CheckpointStore for FailOnceDeleteStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.create(checkpoint)
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }

    fn replace<'a>(
        &'a self,
        revision: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.replace(revision, checkpoint)
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        if self.delete_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Box::pin(async {
                Err(CheckpointStoreError::new(
                    CheckpointStoreErrorCode::Unavailable,
                    "injected delete failure",
                ))
            })
        } else {
            self.inner.delete(id, revision)
        }
    }
}

impl CheckpointStore for FailOnCreateCallStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        let call = self.create_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_on {
            Box::pin(async {
                Err(CheckpointStoreError::new(
                    CheckpointStoreErrorCode::Unavailable,
                    "injected create failure",
                ))
            })
        } else {
            self.inner.create(checkpoint)
        }
    }

    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }

    fn replace<'a>(
        &'a self,
        revision: CheckpointRevision,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.replace(revision, checkpoint)
    }

    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }

    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        self.inner.delete(id, revision)
    }
}

async fn current_proxy(platform: &InMemoryPlatform) -> Option<SystemProxySettings> {
    let settings = spec(999, 9999)
        .platform
        .system_proxy
        .unwrap()
        .resolve(None)
        .unwrap();
    let checkpoint = SystemProxyControl::prepare(platform, &settings)
        .await
        .unwrap();
    serde_json::from_value(checkpoint.payload).unwrap()
}

impl CheckpointStore for FailingReplaceStore {
    fn create<'a>(
        &'a self,
        checkpoint: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        self.inner.create(checkpoint)
    }
    fn get<'a>(&'a self, id: CheckpointId) -> CheckpointFuture<'a, Option<StoredCheckpoint>> {
        self.inner.get(id)
    }
    fn replace<'a>(
        &'a self,
        _: CheckpointRevision,
        _: RecoveryCheckpoint,
    ) -> CheckpointFuture<'a, StoredCheckpoint> {
        Box::pin(async {
            Err(CheckpointStoreError::new(
                CheckpointStoreErrorCode::Unavailable,
                "injected replace failure",
            ))
        })
    }
    fn list_unresolved<'a>(&'a self) -> CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        self.inner.list_unresolved()
    }
    fn delete<'a>(
        &'a self,
        id: CheckpointId,
        revision: CheckpointRevision,
    ) -> CheckpointFuture<'a, ()> {
        self.inner.delete(id, revision)
    }
}

#[tokio::test]
async fn start_acquires_lease_prewrites_checkpoint_and_is_idempotent() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(1, 7890)).await.unwrap();

    let first = runtime.start().await.unwrap();
    assert!(first.changed);
    assert_eq!(first.generation.get(), 1);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(store.list_unresolved().await.unwrap().len(), 1);
    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );

    let second = runtime.start().await.unwrap();
    assert!(!second.changed);
    assert_eq!(store.list_unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn conflicting_start_fails_before_writing_a_second_checkpoint() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform)
        .build()
        .unwrap();
    let first = sdk.create_runtime(spec(2, 7890)).await.unwrap();
    let second = sdk.create_runtime(spec(3, 7891)).await.unwrap();
    first.start().await.unwrap();

    assert!(matches!(
        second.start().await.unwrap_err(),
        RuntimeStartError::LeaseConflict(_)
    ));
    assert_eq!(second.status().state, RuntimeState::Created);
    assert_eq!(store.list_unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn store_transition_failure_is_fail_closed_and_retains_recovery_ownership() {
    let store = Arc::new(FailingReplaceStore {
        inner: InMemoryCheckpointStore::new(),
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store)
        .platform(platform)
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(4, 7890)).await.unwrap();

    assert!(matches!(
        runtime.start().await.unwrap_err(),
        RuntimeStartError::Store(_)
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
}

#[tokio::test]
async fn stop_restores_proxy_releases_lease_and_deletes_checkpoint_idempotently() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(5, 7890)).await.unwrap();
    runtime.start().await.unwrap();

    let first = runtime.stop().await.unwrap();
    assert!(first.changed);
    assert!(first.restored);
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );

    assert!(!runtime.stop().await.unwrap().changed);
}

#[tokio::test]
async fn stop_retries_after_checkpoint_delete_failure() {
    let store = Arc::new(FailOnceDeleteStore {
        inner: InMemoryCheckpointStore::new(),
        delete_calls: AtomicUsize::new(0),
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(50, 7890)).await.unwrap();
    runtime.start().await.unwrap();

    assert!(matches!(
        runtime.stop().await.unwrap_err(),
        RuntimeStopError::Store(_)
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    assert!(current_proxy(platform.as_ref()).await.is_none());
    assert_eq!(store.list_unresolved().await.unwrap().len(), 1);

    assert!(runtime.stop().await.unwrap().restored);
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn reload_retries_after_checkpoint_delete_failure() {
    let store = Arc::new(FailOnceDeleteStore {
        inner: InMemoryCheckpointStore::new(),
        delete_calls: AtomicUsize::new(0),
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(51, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    let empty_spec = RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(51)),
        RuntimePlatformSpec::default(),
    )
    .unwrap();

    assert!(matches!(
        runtime.reload(empty_spec.clone()).await.unwrap_err(),
        RuntimeReloadError::Store { .. }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    assert!(current_proxy(platform.as_ref()).await.is_none());

    let retry = runtime.reload(empty_spec).await.unwrap();
    assert!(retry.committed);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());

    assert!(runtime.stop().await.unwrap().restored);
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn reload_commits_next_generation_but_stop_keeps_the_original_baseline() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(6, 7890)).await.unwrap();
    runtime.start().await.unwrap();

    let report = runtime.reload(spec(6, 7891)).await.unwrap();
    assert!(report.committed);
    assert_eq!(report.generation.get(), 2);
    assert_eq!(runtime.status().generation.get(), 2);
    assert_eq!(
        runtime.spec().platform.system_proxy,
        spec(6, 7891).platform.system_proxy
    );
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    let ownership = serde_json::from_value::<Option<SystemProxySettings>>(
        checkpoints[0].checkpoint.capabilities[0]
            .rollback_payload
            .clone()
            .expect("committed reload ownership descriptor"),
    )
    .unwrap();
    assert_eq!(
        ownership,
        spec(6, 7890)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );

    runtime.reload(spec(6, 7892)).await.unwrap();
    let checkpoints = store.list_unresolved().await.unwrap();
    let ownership = serde_json::from_value::<Option<SystemProxySettings>>(
        checkpoints[0].checkpoint.capabilities[0]
            .rollback_payload
            .clone()
            .expect("latest committed reload ownership descriptor"),
    )
    .unwrap();
    assert_eq!(
        ownership,
        spec(6, 7891)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );

    runtime.stop().await.unwrap();
    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

/// A Running runtime with no capabilities holds no checkpoint. Reloading it
/// (same empty topology — the only reload its topology guard permits) must be
/// a clean no-op, not an `unwrap` on the absent checkpoint that panics while
/// holding the control mutex and bricks the runtime for the process lifetime.
#[tokio::test]
async fn reload_of_an_empty_capability_runtime_is_a_clean_no_op() {
    fn empty_spec(id: u128) -> RuntimeSpec {
        RuntimeSpec::new(
            RuntimeId::from_uuid(Uuid::from_u128(id)),
            RuntimePlatformSpec::default(),
        )
        .unwrap()
    }
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(Arc::new(InMemoryPlatform::new()))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(empty_spec(42)).await.unwrap();
    runtime.start().await.unwrap();

    let report = runtime.reload(empty_spec(42)).await.unwrap();
    assert!(
        !report.committed,
        "an empty-topology reload applies nothing"
    );
    assert!(!report.recovery_required);
    // The runtime stays usable — a poisoned control mutex would panic here.
    assert_eq!(runtime.status().state, RuntimeState::Running);
    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[tokio::test]
async fn reload_accepts_an_adapter_owned_capability_schema_version() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .system_proxy(Arc::new(SchemaTwoSystemProxy {
            inner: platform.clone(),
        }))
        .build()
        .unwrap();
    let id = RuntimeId::from_uuid(Uuid::from_u128(43));
    let runtime = sdk
        .create_runtime(RuntimeSpec::new(id, RuntimePlatformSpec::default()).unwrap())
        .await
        .unwrap();
    runtime.start().await.unwrap();

    let report = runtime.reload(spec(43, 7890)).await.unwrap();

    assert!(report.committed);
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].checkpoint.capabilities[0].schema_version, 2);
    runtime.stop().await.unwrap();
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_adapter_checkpoints_do_not_strand_start_or_reload_transactions() {
    for (index, contract) in [
        InvalidCheckpointContract::Unversioned,
        InvalidCheckpointContract::ForeignLease,
    ]
    .into_iter()
    .enumerate()
    {
        let start_store = Arc::new(InMemoryCheckpointStore::new());
        let start_platform = Arc::new(InMemoryPlatform::new());
        let start_sdk = EgrioSdk::builder()
            .checkpoint_store(start_store.clone())
            .system_proxy(Arc::new(InvalidCheckpointSystemProxy {
                inner: start_platform.clone(),
                contract,
            }))
            .build()
            .unwrap();
        let start_runtime = start_sdk
            .create_runtime(spec(440 + index as u128, 7890))
            .await
            .unwrap();

        let error = start_runtime.start().await.unwrap_err();
        let RuntimeStartError::Capability(error) = error else {
            panic!("invalid adapter checkpoint must be a capability error: {error}");
        };
        assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        assert_eq!(start_runtime.status().state, RuntimeState::Created);
        assert_eq!(
            start_sdk
                .lease_status(&PlatformLeaseKey::system_proxy())
                .state,
            PlatformLeaseState::Available
        );
        assert_eq!(
            start_sdk
                .lease_status(&PlatformLeaseKey::system_dns())
                .state,
            PlatformLeaseState::Available
        );
        assert!(start_store.list_unresolved().await.unwrap().is_empty());
        assert!(current_proxy(start_platform.as_ref()).await.is_none());

        let reload_store = Arc::new(InMemoryCheckpointStore::new());
        let reload_platform = Arc::new(InMemoryPlatform::new());
        let reload_sdk = EgrioSdk::builder()
            .checkpoint_store(reload_store.clone())
            .system_proxy(Arc::new(InvalidCheckpointSystemProxy {
                inner: reload_platform.clone(),
                contract,
            }))
            .build()
            .unwrap();
        let runtime_id = RuntimeId::from_uuid(Uuid::from_u128(450 + index as u128));
        let reload_runtime = reload_sdk
            .create_runtime(RuntimeSpec::new(runtime_id, RuntimePlatformSpec::default()).unwrap())
            .await
            .unwrap();
        reload_runtime.start().await.unwrap();

        let error = reload_runtime
            .reload(spec(450 + index as u128, 7890))
            .await
            .unwrap_err();
        let RuntimeReloadError::Capability { error, .. } = error else {
            panic!("invalid adapter checkpoint must be a capability error: {error}");
        };
        assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
        assert_eq!(reload_runtime.status().state, RuntimeState::Running);
        assert_eq!(reload_runtime.status().generation.get(), 1);
        assert!(reload_runtime.spec().platform.system_proxy.is_none());
        assert_eq!(
            reload_sdk
                .lease_status(&PlatformLeaseKey::system_proxy())
                .state,
            PlatformLeaseState::Available
        );
        assert_eq!(
            reload_sdk
                .lease_status(&PlatformLeaseKey::system_dns())
                .state,
            PlatformLeaseState::Available
        );
        assert!(reload_store.list_unresolved().await.unwrap().is_empty());
        assert!(current_proxy(reload_platform.as_ref()).await.is_none());
        reload_runtime.stop().await.unwrap();
    }
}

#[tokio::test]
async fn invalid_start_checkpoint_release_failure_retains_grant_for_stop_retry() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let coordinator = Arc::new(FaultLeaseCoordinator::default());
    coordinator.fail_next_release.store(true, Ordering::SeqCst);
    let runtime = Arc::new(
        Runtime::from_parts(
            spec(460, 7890),
            coordinator.clone(),
            store.clone(),
            RuntimePorts {
                system_proxy: Some(Arc::new(InvalidCheckpointSystemProxy {
                    inner: platform.clone(),
                    contract: InvalidCheckpointContract::Unversioned,
                })),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );

    let error = runtime.start().await.unwrap_err();

    assert!(matches!(error, RuntimeStartError::Cleanup(_)));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert!(runtime.domain_status().checkpoint.is_none());
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert!(current_proxy(platform.as_ref()).await.is_none());

    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
}

#[tokio::test]
async fn reload_retry_recreates_a_checkpoint_lost_after_release_failure() {
    let store = Arc::new(FailOnCreateCallStore {
        inner: InMemoryCheckpointStore::new(),
        create_calls: AtomicUsize::new(0),
        fail_on: 2,
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let coordinator = Arc::new(FaultLeaseCoordinator::default());
    let runtime_id = RuntimeId::from_uuid(Uuid::from_u128(463));
    let runtime = Arc::new(
        Runtime::from_parts(
            spec(463, 7890),
            coordinator.clone(),
            store.clone(),
            RuntimePorts {
                system_proxy: Some(platform.clone()),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    runtime.start().await.unwrap();
    coordinator.fail_next_release.store(true, Ordering::SeqCst);
    let empty = RuntimeSpec::new(runtime_id, RuntimePlatformSpec::default()).unwrap();

    let error = runtime.reload(empty.clone()).await.unwrap_err();

    let RuntimeReloadError::LeaseTransition { error, .. } = error else {
        panic!("release failure must remain a lease transition error");
    };
    assert!(error
        .message
        .contains("failed to recreate recovery checkpoint"));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );

    let recovered = runtime.reload(empty.clone()).await.unwrap();

    assert!(recovered.committed);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.spec(), empty);
    assert!(store.list_unresolved().await.unwrap().is_empty());
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(current_proxy(platform.as_ref()).await.is_none());
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn invalid_reload_checkpoint_keeps_existing_grant_and_original_checkpoint() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let system_proxy = Arc::new(ToggleInvalidSystemProxy {
        inner: platform.clone(),
        invalid: AtomicBool::new(false),
    });
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .system_proxy(system_proxy.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(461, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    let original = store.list_unresolved().await.unwrap().pop().unwrap();
    system_proxy.invalid.store(true, Ordering::SeqCst);

    let error = runtime.reload(spec(461, 7891)).await.unwrap_err();

    assert!(matches!(error, RuntimeReloadError::Capability { .. }));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), spec(461, 7890));
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        store.list_unresolved().await.unwrap(),
        vec![original.clone()]
    );
    assert_eq!(
        runtime.domain_status().checkpoint.unwrap().id,
        original.checkpoint.id
    );

    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn invalid_reload_checkpoint_shrink_failure_retains_union_grant_and_original_checkpoint() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let coordinator = Arc::new(FaultLeaseCoordinator::default());
    let runtime = Arc::new(
        Runtime::from_parts(
            spec(462, 7890),
            coordinator.clone(),
            store.clone(),
            RuntimePorts {
                system_proxy: Some(platform.clone()),
                route: Some(Arc::new(InvalidCheckpointRoute {
                    inner: platform.clone(),
                })),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    runtime.start().await.unwrap();
    let original = store.list_unresolved().await.unwrap().pop().unwrap();
    coordinator.fail_next_shrink.store(true, Ordering::SeqCst);

    let error = runtime
        .reload(spec_with_route(462, 7890))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeReloadError::LeaseTransition {
            error: LeaseTransitionError {
                code: LeaseTransitionErrorCode::InvalidState,
                ..
            },
            ..
        }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(runtime.spec(), spec(462, 7890));
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Held
    );
    assert_eq!(
        store.list_unresolved().await.unwrap(),
        vec![original.clone()]
    );
    assert_eq!(
        runtime.domain_status().checkpoint.unwrap().id,
        original.checkpoint.id
    );

    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn reload_rejects_non_running_and_foreign_runtime_specs_without_mutation() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(7, 7890)).await.unwrap();

    assert!(matches!(
        runtime.reload(spec(7, 7891)).await.unwrap_err(),
        RuntimeReloadError::InvalidState(RuntimeState::Created)
    ));
    assert_eq!(runtime.status().generation.get(), 0);
    assert!(current_proxy(platform.as_ref()).await.is_none());
    assert!(store.list_unresolved().await.unwrap().is_empty());

    runtime.start().await.unwrap();
    assert!(matches!(
        runtime.reload(spec(8, 7891)).await.unwrap_err(),
        RuntimeReloadError::InvalidRuntimeId
    ));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(
        current_proxy(platform.as_ref()).await,
        spec(7, 7890)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );
}

#[tokio::test]
async fn reload_apply_failure_rolls_back_and_keeps_the_committed_generation() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(9, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    platform.fail_next_apply(CapabilityKind::SystemProxy, "injected uncertain apply");

    let error = runtime.reload(spec(9, 7891)).await.unwrap_err();
    assert!(matches!(&error, RuntimeReloadError::Capability { .. }));
    assert!(error
        .report()
        .unwrap()
        .resources
        .iter()
        .any(|change| { change.outcome == egrio_runtime::RuntimeResourceOutcome::RolledBack }));
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(
        runtime.spec().platform.system_proxy,
        spec(9, 7890).platform.system_proxy
    );
    assert_eq!(
        current_proxy(platform.as_ref()).await,
        spec(9, 7890)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].checkpoint.phase, CheckpointPhase::Committed);
    assert!(checkpoints[0].checkpoint.capabilities[0]
        .rollback_payload
        .is_none());
}

#[tokio::test]
async fn reload_rollback_failure_retains_recovery_checkpoint_and_lease() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(10, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    platform.fail_next_apply(CapabilityKind::SystemProxy, "injected uncertain apply");
    platform.fail_next_restore(CapabilityKind::SystemProxy, "injected rollback failure");

    let error = runtime.reload(spec(10, 7891)).await.unwrap_err();
    assert!(matches!(
        &error,
        RuntimeReloadError::RecoveryRequired { .. }
    ));
    assert!(error.report().unwrap().resources.iter().any(|change| {
        change.outcome == egrio_runtime::RuntimeResourceOutcome::RecoveryRequired
    }));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(
        runtime.spec().platform.system_proxy,
        spec(10, 7890).platform.system_proxy
    );
    assert_eq!(
        current_proxy(platform.as_ref()).await,
        spec(10, 7891)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(
        checkpoints[0].checkpoint.phase,
        CheckpointPhase::RecoveryRequired
    );
    assert!(checkpoints[0].checkpoint.capabilities[0]
        .rollback_payload
        .is_some());
}

#[tokio::test]
async fn reload_checkpoint_transition_failure_is_fail_closed() {
    let store = Arc::new(FailOnReplaceCallStore {
        inner: InMemoryCheckpointStore::new(),
        replace_calls: AtomicUsize::new(0),
        fail_on: 4,
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(11, 7890)).await.unwrap();
    runtime.start().await.unwrap();

    assert!(matches!(
        runtime.reload(spec(11, 7891)).await.unwrap_err(),
        RuntimeReloadError::Store { .. }
    ));
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(runtime.status().generation.get(), 1);
    assert_eq!(
        runtime.spec().platform.system_proxy,
        spec(11, 7890).platform.system_proxy
    );
    assert_eq!(
        current_proxy(platform.as_ref()).await,
        spec(11, 7890)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::RecoveryRequired
    );
    let checkpoints = store.list_unresolved().await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].checkpoint.phase, CheckpointPhase::Prepared);
}

#[tokio::test]
async fn cancelled_start_future_does_not_abort_the_started_transaction() {
    let store = Arc::new(BlockingCheckpointStore::new(CheckpointBlockPoint::Replace(
        1,
    )));
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(20, 7890)).await.unwrap();
    let entered = store.entered.notified();
    let caller = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.start().await }
    });

    entered.await;
    caller.abort();
    store.release.notify_waiters();
    wait_for_state(runtime.as_ref(), RuntimeState::Running).await;

    assert!(
        SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .phase,
        CheckpointPhase::Committed
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn cancelled_reload_future_does_not_abort_the_started_transaction() {
    let store = Arc::new(BlockingCheckpointStore::new(CheckpointBlockPoint::Replace(
        3,
    )));
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(21, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    let entered = store.entered.notified();
    let caller = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.reload(spec(21, 7891)).await }
    });

    entered.await;
    caller.abort();
    store.release.notify_waiters();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if runtime.status().generation.get() == 2
                && runtime.status().state == RuntimeState::Running
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reload transaction committed after caller cancellation");

    assert_eq!(
        current_proxy(platform.as_ref()).await,
        spec(21, 7891)
            .platform
            .system_proxy
            .map(|value| value.resolve(None).unwrap())
    );
    assert_eq!(
        store
            .list_unresolved()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .checkpoint
            .phase,
        CheckpointPhase::Committed
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn cancelled_stop_future_does_not_abort_the_started_transaction() {
    let store = Arc::new(BlockingCheckpointStore::new(CheckpointBlockPoint::Delete));
    let platform = Arc::new(InMemoryPlatform::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(platform.clone())
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(spec(22, 7890)).await.unwrap();
    runtime.start().await.unwrap();
    let entered = store.entered.notified();
    let caller = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.stop().await }
    });

    entered.await;
    caller.abort();
    store.release.notify_waiters();
    wait_for_state(runtime.as_ref(), RuntimeState::Stopped).await;

    assert!(
        !SystemProxyControl::observe(platform.as_ref())
            .await
            .unwrap()
            .active
    );
    assert_eq!(
        sdk.lease_status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert!(store.list_unresolved().await.unwrap().is_empty());
}
