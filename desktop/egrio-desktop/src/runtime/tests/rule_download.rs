//! A start whose profile still lacks rule sets: the prepared Core downloads
//! them and only then takes traffic.
use super::*;
use crate::configuration::EffectiveConfigSnapshot;

/// A host whose download of the profile's rule sets ends when the test lets
/// it, with the outcome the test chose.
struct Fixture {
    host: TestSdk,
    platform: Arc<SnapshotAdapter>,
    /// What the active profile reads as.
    profile: Arc<std::sync::Mutex<Result<EffectiveConfigSnapshot, String>>>,
    downloads: Arc<AtomicUsize>,
    /// Each permit lets one download end.
    release: Arc<tokio::sync::Semaphore>,
    fail: Arc<AtomicBool>,
}

fn awaiting(profile_id: &str) -> EffectiveConfigSnapshot {
    let mut snapshot = excluding_snapshot(&[]);
    snapshot.profile.id = profile_id.into();
    snapshot.source_revision = profile_id.into();
    snapshot.awaiting_rule_sets = true;
    snapshot
}

fn fixture() -> Fixture {
    let platform = Arc::new(SnapshotAdapter::default());
    let host = test_host(Arc::new(InMemoryCheckpointStore::new()), platform.clone());
    fixture_over(host, platform)
}

fn fixture_over(mut host: TestSdk, platform: Arc<SnapshotAdapter>) -> Fixture {
    let profile = Arc::new(std::sync::Mutex::new(Ok(awaiting("a"))));
    let downloads = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    host.configuration = Arc::new({
        let profile = profile.clone();
        move || {
            Box::pin(std::future::ready(
                profile.lock().unwrap().clone().map(Some),
            ))
        }
    });
    host.rule_sets = Arc::new({
        let (profile, downloads, release, fail) = (
            profile.clone(),
            downloads.clone(),
            release.clone(),
            fail.clone(),
        );
        move |_, _| {
            let (profile, downloads, release, fail) = (
                profile.clone(),
                downloads.clone(),
                release.clone(),
                fail.clone(),
            );
            Box::pin(async move {
                downloads.fetch_add(1, Ordering::SeqCst);
                release.acquire().await.unwrap().forget();
                if fail.load(Ordering::SeqCst) {
                    return Err("the node did not answer".into());
                }
                if let Ok(snapshot) = profile.lock().unwrap().as_mut() {
                    snapshot.awaiting_rule_sets = false;
                }
                Ok(())
            })
        }
    });
    Fixture {
        host,
        platform,
        profile,
        downloads,
        release,
        fail,
    }
}

async fn until(what: &str, mut reached: impl FnMut() -> bool) {
    for _ in 0..600 {
        if reached() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("timed out waiting until {what}");
}

fn state(host: &TestSdk) -> RuntimeState {
    host.domain_status().unwrap().runtime.state
}

const SYSTEM_PROXY: CaptureLayers = CaptureLayers {
    system_proxy: true,
    tun: false,
};

#[tokio::test]
async fn capture_waits_for_the_rule_sets_and_starts_on_the_core_that_fetched_them() {
    let fixture = fixture();
    let host = &fixture.host;
    apply_test_layers(host, true, false).await.unwrap();

    assert_eq!(state(host), RuntimeState::Preparing);
    assert_eq!(host.capture_layers(), CaptureLayers::NONE);
    assert_eq!(host.requested_capture_layers(), SYSTEM_PROXY);
    assert!(host.core_preparation().unwrap().error.is_none());
    assert!(host.rule_download_running());
    assert!(!fixture.platform.active.load(Ordering::SeqCst));
    assert!(!holds_background_activity(host).await);
    let prepared = sdk_core_generation(host);

    // Asking for the same layers again leaves the download alone.
    apply_test_layers(host, true, false).await.unwrap();
    assert_eq!(fixture.downloads.load(Ordering::SeqCst), 1);
    assert_eq!(sdk_core_generation(host), prepared);

    fixture.release.add_permits(1);
    until("capture starts", || state(host) == RuntimeState::Running).await;
    until("the download is over", || !host.rule_download_running()).await;
    assert_eq!(host.capture_layers(), SYSTEM_PROXY);
    assert!(host.core_preparation().is_none());
    assert!(fixture.platform.active.load(Ordering::SeqCst));
    assert!(holds_background_activity(host).await);
    assert_eq!(sdk_core_generation(host), prepared);
    assert_eq!(fixture.downloads.load(Ordering::SeqCst), 1);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn a_failed_download_keeps_its_core_and_runs_again_after_a_node_change() {
    let fixture = fixture();
    let host = &fixture.host;
    fixture.fail.store(true, Ordering::SeqCst);
    apply_test_layers(host, true, false).await.unwrap();
    let prepared = sdk_core_generation(host);
    fixture.release.add_permits(1);
    until("the download fails", || {
        host.core_preparation()
            .is_some_and(|preparing| preparing.error.is_some())
    })
    .await;

    assert_eq!(state(host), RuntimeState::Preparing);
    assert!(!host.rule_download_running());
    assert_eq!(host.requested_capture_layers(), SYSTEM_PROXY);
    assert_eq!(
        host.core_preparation().unwrap().error.as_deref(),
        Some("the node did not answer")
    );

    fixture.fail.store(false, Ordering::SeqCst);
    let runtime = host.existing_desktop_runtime().unwrap();
    host.retry_rule_download(&runtime);
    assert!(host.rule_download_running());
    assert!(host.core_preparation().unwrap().error.is_none());
    fixture.release.add_permits(1);
    until("capture starts", || state(host) == RuntimeState::Running).await;
    assert_eq!(sdk_core_generation(host), prepared);
    assert_eq!(fixture.downloads.load(Ordering::SeqCst), 2);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn a_prepared_core_never_serves_a_profile_it_was_not_made_from() {
    let fixture = fixture();
    let host = &fixture.host;
    apply_test_layers(host, true, false).await.unwrap();
    let first = sdk_core_generation(host);

    // Another source that waits for rule sets too: its own Core fetches them.
    *fixture.profile.lock().unwrap() = Ok(awaiting("b"));
    assert!(host.restart_running_runtime().await.unwrap());
    assert_eq!(state(host), RuntimeState::Preparing);
    let second = sdk_core_generation(host);
    assert!(second > first);
    assert!(host.rule_download_running());
    until("the second Core downloads", || {
        fixture.downloads.load(Ordering::SeqCst) == 2
    })
    .await;

    // A complete profile starts afresh instead of being applied onto the
    // Core prepared from the other one.
    let mut complete = awaiting("c");
    complete.awaiting_rule_sets = false;
    *fixture.profile.lock().unwrap() = Ok(complete);
    assert!(host.restart_running_runtime().await.unwrap());
    assert_eq!(state(host), RuntimeState::Running);
    assert!(sdk_core_generation(host) > second);
    assert!(!host.rule_download_running());
    assert_eq!(host.prepared_configuration.get().unwrap().profile_id, "c");
    assert!(holds_background_activity(host).await);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn a_profile_that_cannot_be_read_leaves_the_download_running() {
    let fixture = fixture();
    let host = &fixture.host;
    apply_test_layers(host, true, false).await.unwrap();
    let prepared = sdk_core_generation(host);
    let readable = fixture.profile.lock().unwrap().clone();

    *fixture.profile.lock().unwrap() = Err("the profile names an undeclared provider".into());
    let error = host.restart_running_runtime().await.unwrap_err();
    assert!(error.contains("undeclared provider"), "{error}");
    assert_eq!(state(host), RuntimeState::Preparing);
    assert!(host.rule_download_running());
    assert!(host.core_preparation().unwrap().error.is_none());

    *fixture.profile.lock().unwrap() = readable;
    fixture.release.add_permits(1);
    until("capture starts", || state(host) == RuntimeState::Running).await;
    assert_eq!(sdk_core_generation(host), prepared);
    host.stop_user_runtime().await.unwrap();
}

#[tokio::test]
async fn turning_capture_off_ends_the_download_with_its_core() {
    let fixture = fixture();
    let host = &fixture.host;
    apply_test_layers(host, true, false).await.unwrap();
    assert!(host.rule_download_running());

    apply_test_layers(host, false, false).await.unwrap();
    assert_eq!(state(host), RuntimeState::Stopped);
    assert!(host.core_preparation().is_none());
    assert!(!host.rule_download_running());
    assert!(host.domain_status().unwrap().core.is_none());

    // The download was dropped: nothing takes the permit or starts capture.
    fixture.release.add_permits(1);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(fixture.release.available_permits(), 1);
    assert_eq!(state(host), RuntimeState::Stopped);
    assert!(!fixture.platform.active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn connections_the_prepared_core_dialed_are_renewed_once_its_tun_opens() {
    let checkpoints = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(checkpoints.clone())
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCore))
        .build()
        .unwrap();
    let fixture = fixture_over(host_over(sdk, checkpoints), Arc::default());
    let host = &fixture.host;
    apply_test_layers(host, false, true).await.unwrap();
    assert_eq!(state(host), RuntimeState::Preparing);

    // The download and the node probes dial while the tunnel is closed.
    host.host.unprotected.store(true, Ordering::SeqCst);
    apply_test_layers(host, false, true).await.unwrap();
    assert!(
        host.host.unprotected.load(Ordering::SeqCst),
        "nothing is renewed before the TUN opens"
    );

    fixture.release.add_permits(1);
    until("TUN starts", || host.capture_layers().tun).await;
    until("the download is over", || !host.rule_download_running()).await;
    assert!(!host.host.unprotected.load(Ordering::SeqCst));
    host.stop_user_runtime().await.unwrap();
}
