use super::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct StoreFixture {
    root: PathBuf,
    store: ProfileStore,
}
impl StoreFixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("egrio-provider-refresh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        Self {
            store: ProfileStore::open_at(&root).unwrap(),
            root,
        }
    }
    fn profile(&self, origin: &str, failed_target: bool) -> String {
        let failed = if failed_target {
            format!("  Broken:\n    type: http\n    behavior: domain\n    url: {origin}/broken\n")
        } else {
            String::new()
        };
        self.store.create_profile("Provider refresh".into(), format!(
            "mode: direct\nrule-providers:\n  One:\n    type: http\n    behavior: domain\n    url: {origin}/one\n  Two:\n    type: http\n    behavior: domain\n    url: {origin}/two\n{failed}rules: ['RULE-SET,One,DIRECT','RULE-SET,Two,DIRECT','MATCH,DIRECT']\n"
        )).unwrap().id
    }
}
impl Drop for StoreFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn request_path(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut header = Vec::new();
    loop {
        let byte = stream.read_u8().await.ok()?;
        header.push(byte);
        assert!(header.len() < 16_384);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Some(
        String::from_utf8(header)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned(),
    )
}

fn client(address: std::net::SocketAddr) -> RuleSetClient {
    // A public-shaped test hostname passes the production URL checks while
    // this injected resolver sends only to the test-owned loopback listener.
    RuleSetClient::System(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("provider.egrio.test", address)
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap(),
    )
}

#[tokio::test]
async fn batch_reuses_its_http_pool_and_classifies_unchanged_and_failed_results() {
    let fixture = StoreFixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://provider.egrio.test:{}", address.port());
    let profile_id = fixture.profile(&origin, true);
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        let mut connections = 0;
        while requests.len() < 9 {
            let (mut stream, _) = listener.accept().await.unwrap();
            connections += 1;
            while let Some(path) = request_path(&mut stream).await {
                let (status, body) = if requests.len() >= 6 {
                    ("503 Service Unavailable", "")
                } else {
                    match path.as_str() {
                        "/one" => ("200 OK", "payload: [one.example]\n"),
                        "/two" => ("200 OK", "payload: [two.example]\n"),
                        "/broken" => ("503 Service Unavailable", ""),
                        _ => panic!("unexpected fixture request"),
                    }
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                requests.push(path);
                if requests.len() == 9 {
                    return (connections, requests);
                }
            }
        }
        unreachable!()
    });
    let refresh = RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || {
        Ok(client(address))
    })
    .unwrap();
    let first = refresh.update_all().await.unwrap();
    assert_eq!(first.updated.len(), 2);
    assert!(first.unchanged.is_empty());
    assert_eq!(first.failures.len(), 1);
    assert!(first.failures[0].contains("Broken") && first.failures[0].contains("503"));
    let revision = fixture
        .store
        .profile_summary_by_id(&profile_id)
        .unwrap()
        .revision;
    let second = refresh.update_all().await.unwrap();
    assert!(second.updated.is_empty());
    assert_eq!(second.unchanged.len(), 2);
    assert_eq!(second.failures.len(), 1);
    assert_eq!(
        fixture
            .store
            .profile_summary_by_id(&profile_id)
            .unwrap()
            .revision,
        revision
    );
    let all_failed = refresh.update_all().await.unwrap();
    assert!(all_failed.updated.is_empty());
    assert!(
        all_failed.unchanged.is_empty(),
        "cached content must not turn a failed download into an unchanged success"
    );
    assert_eq!(all_failed.failures.len(), 3);
    assert_eq!(
        fixture
            .store
            .profile_summary_by_id(&profile_id)
            .unwrap()
            .revision,
        revision
    );
    assert_eq!(
        fixture
            .store
            .active_configuration_snapshot()
            .unwrap()
            .unwrap()
            .profile
            .rule_sets
            .len(),
        2,
        "the old usable contents remain available without being counted as refreshed"
    );
    let (connections, paths) = tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paths.len(), 9);
    assert_eq!(
        connections, 1,
        "sequential providers on one origin must share a single HTTP pool"
    );
    assert!(fixture
        .store
        .rule_provider_fetch_target(&profile_id, "Broken")
        .unwrap()
        .fetched_at_unix
        .is_none());
}

#[tokio::test]
async fn profile_admission_covers_an_inflight_download_and_releases_on_cancellation() {
    let fixture = StoreFixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let profile_id = fixture.profile(
        &format!("http://provider.egrio.test:{}", address.port()),
        false,
    );
    let (received, ready) = oneshot::channel();
    let (release, released) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(request_path(&mut stream).await.as_deref(), Some("/one"));
        received.send(()).unwrap();
        let _ = released.await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\npayload: [late.example]\n")
            .await;
    });
    let refresh = RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || {
        Ok(client(address))
    })
    .unwrap();
    let worker = tokio::spawn(async move { refresh.update_one("One").await });
    ready.await.unwrap();
    assert!(
        RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || Ok(client(
            address
        )))
        .is_err(),
        "batch, single and preparation share the same per-profile gate"
    );
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    server.await.unwrap();
    let replacement = RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || {
        Ok(client(address))
    })
    .unwrap();
    assert!(
        fixture
            .store
            .rule_provider_fetch_target(&profile_id, "One")
            .unwrap()
            .fetched_at_unix
            .is_none(),
        "a cancelled response must never become a late cache write"
    );
    drop(replacement);
}

#[tokio::test]
async fn preparing_dependencies_uses_the_existing_admission_without_recursive_locking() {
    let fixture = StoreFixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let profile_id = fixture.profile(
        &format!("http://provider.egrio.test:{}", address.port()),
        false,
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = seen.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let path = request_path(&mut stream).await.unwrap();
            observed.lock().unwrap().push(path);
            let body = "payload: [prepared.example]\n";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    let refresh = RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || {
        Ok(client(address))
    })
    .unwrap();
    refresh.prepare_required().await.unwrap();
    let revision = fixture
        .store
        .profile_summary_by_id(&profile_id)
        .unwrap()
        .revision;
    refresh.prepare_required().await.unwrap();
    assert_eq!(
        fixture
            .store
            .profile_summary_by_id(&profile_id)
            .unwrap()
            .revision,
        revision
    );
    assert!(fixture
        .store
        .missing_rule_provider_fetch_targets(&profile_id)
        .unwrap()
        .is_empty());
    server.await.unwrap();
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "prepared caches must not be downloaded a second time"
    );
}

#[tokio::test]
async fn ready_cache_preparation_bypasses_a_busy_refresh_but_missing_content_does_not() {
    let fixture = StoreFixture::new();
    let profile_id = fixture.profile("https://provider.egrio.test", false);
    for target in fixture
        .store
        .rule_provider_fetch_targets(&profile_id)
        .unwrap()
    {
        fixture
            .store
            .save_rule_provider_content(&profile_id, &target, "payload: [cached.example]\n", 1)
            .unwrap();
    }
    let revision = fixture
        .store
        .profile_summary_by_id(&profile_id)
        .unwrap()
        .revision;
    let refresh = RuleProviderRefresh::begin(profile_id.clone(), fixture.store.clone(), || {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .map(RuleSetClient::System)
            .map_err(|error| error.to_string())
    })
    .unwrap();
    prepare_profile_rule_providers_in(profile_id.clone(), fixture.store.clone(), || {
        panic!("a complete cache must not construct a client or acquire refresh admission")
    })
    .await
    .unwrap();
    assert_eq!(
        fixture
            .store
            .profile_summary_by_id(&profile_id)
            .unwrap()
            .revision,
        revision
    );

    let source = fixture.store.get_profile_source(&profile_id).unwrap();
    fixture
        .store
        .save_profile_source(
            &profile_id,
            source.yaml.replace("/one", "/new-one"),
            &source.source_revision,
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .missing_rule_provider_fetch_targets(&profile_id)
            .unwrap()
            .len(),
        1
    );
    let error =
        prepare_profile_rule_providers_in(profile_id.clone(), fixture.store.clone(), || {
            panic!("missing dependencies must obtain admission before constructing a client")
        })
        .await
        .unwrap_err();
    assert!(error.contains("already updating"));
    assert_eq!(
        fixture
            .store
            .missing_rule_provider_fetch_targets(&profile_id)
            .unwrap()
            .len(),
        1
    );
    drop(refresh);
}

mod startup;
