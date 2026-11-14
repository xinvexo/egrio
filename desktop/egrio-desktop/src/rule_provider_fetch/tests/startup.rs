use super::*;
use egrio_core::{CoreStartInputs, RuntimeProfile};
use egrio_runtime::{
    CoreConfigSource, RuntimeCoreGeneration, RuntimeCoreSpec, RuntimeId, RuntimeSpec, RuntimeState,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct Source {
    profile: RuntimeProfile,
    loads: Arc<AtomicUsize>,
}
impl CoreConfigSource for Source {
    fn load(&self) -> Result<CoreStartInputs, String> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(CoreStartInputs {
            profile: self.profile.clone(),
            egress: Default::default(),
            capture: Default::default(),
            egress_socket_guard: None,
            flow_scanner: None,
            fake_ip_mappings: None,
        })
    }
}

async fn prepare(
    mut profile: RuntimeProfile,
) -> (
    EgrioSdk,
    Arc<Runtime>,
    RuntimeCoreGeneration,
    Arc<AtomicUsize>,
    std::net::SocketAddr,
) {
    profile.rules = Default::default();
    let loads = Arc::new(AtomicUsize::new(0));
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(Source {
            profile,
            loads: loads.clone(),
        }))
        .build()
        .unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let spec = RuntimeSpec::with_core(
        RuntimeId::new(),
        Some(RuntimeCoreSpec {
            listen_addr: Some(address),
            ..Default::default()
        }),
        Default::default(),
    )
    .unwrap();
    let runtime = sdk.create_runtime(spec.clone()).await.unwrap();
    let generation = runtime.prepare_core(spec).await.unwrap();
    (sdk, runtime, generation, loads, address)
}

fn node_profile(
    fixture: &StoreFixture,
    good: std::net::SocketAddr,
    selected: &str,
) -> (String, String) {
    let id = fixture.profile("http://provider.egrio.test", false);
    let source = fixture.store.get_profile_source(&id).unwrap();
    let yaml = format!("{}\nproxies:\n  - {{name: Broken, type: http, server: 127.0.0.1, port: 0}}\n  - {{name: Working, type: http, server: {}, port: {}}}\nproxy-groups:\n  - {{name: Exit, type: select, proxies: [Broken, Working]}}\n",
        source.yaml.replace("mode: direct", "mode: rule").replace("RULE-SET,One,DIRECT", "RULE-SET,One,REJECT"), good.ip(), good.port());
    fixture
        .store
        .save_profile_source(&id, yaml, &source.source_revision)
        .unwrap();
    let group = fixture
        .store
        .profile_configuration_snapshot(&id)
        .unwrap()
        .profile
        .groups[0]
        .id
        .clone();
    fixture
        .store
        .set_group_selection(&id, &group, selected)
        .unwrap();
    (id, group)
}

async fn proxy(responses: Vec<String>) -> (std::net::SocketAddr, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut responses = responses.into_iter();
        let mut connections = 0;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            connections += 1;
            assert_eq!(
                request_path(&mut stream).await.as_deref(),
                Some("provider.egrio.test:80")
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            while request_path(&mut stream).await.is_some() {
                let response = responses.next().expect("one response per request");
                stream.write_all(response.as_bytes()).await.unwrap();
                if responses.len() == 0 {
                    return connections;
                }
            }
        }
    });
    (address, task)
}

fn body(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn cold_providers_use_the_selected_node_then_activate_the_same_core() {
    let fixture = StoreFixture::new();
    let (address, server) = proxy(vec![
        body("payload: [one.example]\n"),
        body("payload: [two.example]\n"),
    ])
    .await;
    let (id, _) = node_profile(&fixture, address, "Working");
    let partial = fixture
        .store
        .profile_configuration_snapshot(&id)
        .unwrap()
        .profile;
    let (_sdk, runtime, generation, loads, listener) = prepare(partial).await;
    assert_eq!(runtime.status().state, RuntimeState::Preparing);
    assert!(tokio::net::TcpStream::connect(listener).await.is_err());
    assert!(runtime.core_status().dns_listen_addr.is_none());
    assert!(
        runtime.start().await.is_err(),
        "normal start cannot bypass preparation"
    );
    let refresh = RuleProviderRefresh::begin(id.clone(), fixture.store.clone(), || {
        RuleSetClient::new(Some(runtime.clone()))
    })
    .unwrap();
    refresh.prepare_required().await.unwrap();
    drop(refresh);
    assert_eq!(
        server.await.unwrap(),
        1,
        "providers share their HTTP connection pool"
    );
    assert!(
        tokio::net::TcpStream::connect(listener).await.is_err(),
        "downloading alone does not open ordinary ingress"
    );
    let full = fixture
        .store
        .active_configuration_snapshot()
        .unwrap()
        .unwrap()
        .profile;
    runtime
        .activate_prepared_core(generation, full)
        .await
        .unwrap();
    assert_eq!(runtime.domain_status().core.unwrap().generation, generation);
    assert_eq!(
        loads.load(Ordering::SeqCst),
        1,
        "activation must not compile a second device"
    );
    let mut ordinary = tokio::net::TcpStream::connect(listener).await.unwrap();
    ordinary
        .write_all(b"CONNECT one.example:443 HTTP/1.1\r\nHost: one.example:443\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 128];
    let count = ordinary.read(&mut response).await.unwrap();
    assert!(
        response[..count].starts_with(b"HTTP/1.1 403"),
        "the first ordinary request must see the downloaded rule"
    );
    drop(ordinary);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn failed_preparation_can_change_nodes_and_retry_without_recreating_core() {
    let fixture = StoreFixture::new();
    let (address, server) = proxy(vec![
        body("payload: [one.example]\n"),
        body("payload: [two.example]\n"),
    ])
    .await;
    let (id, group) = node_profile(&fixture, address, "Broken");
    let partial = fixture
        .store
        .profile_configuration_snapshot(&id)
        .unwrap()
        .profile;
    let (_sdk, runtime, generation, loads, listener) = prepare(partial).await;
    let failed = RuleProviderRefresh::begin(id.clone(), fixture.store.clone(), || {
        RuleSetClient::new(Some(runtime.clone()))
    })
    .unwrap();
    let error = failed.prepare_required().await.unwrap_err();
    drop(failed);
    assert!(error.contains("One"), "{error}");
    assert_eq!(runtime.status().state, RuntimeState::Preparing);
    assert!(tokio::net::TcpStream::connect(listener).await.is_err());
    let store = fixture.store.clone();
    let profile_id = id.clone();
    let saved_group = group.clone();
    let report = runtime
        .configure(
            egrio_runtime::RuntimeConfigurationChange::Policy(
                egrio_core::CorePolicyUpdate::SelectGroup {
                    group: "Exit".into(),
                    member: "Working".into(),
                },
            ),
            move || {
                store
                    .set_group_selection(&profile_id, &saved_group, "Working")
                    .map_err(|error| error.to_string())
            },
        )
        .await;
    assert_eq!(
        report.phase,
        egrio_runtime::ConfigurationPhase::Applied,
        "{:?}",
        report.error
    );
    let retried = RuleProviderRefresh::begin(id, fixture.store.clone(), || {
        RuleSetClient::new(Some(runtime.clone()))
    })
    .unwrap();
    retried.prepare_required().await.unwrap();
    drop(retried);
    server.await.unwrap();
    assert_eq!(runtime.domain_status().core.unwrap().generation, generation);
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn core_download_rejects_local_redirects_and_truncated_bodies() {
    for response in [
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n"
            .to_string(),
        "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\npayload: [partial]\n".to_string(),
    ] {
        let fixture = StoreFixture::new();
        let (address, server) = proxy(vec![response]).await;
        let (id, _) = node_profile(&fixture, address, "Working");
        let partial = fixture
            .store
            .profile_configuration_snapshot(&id)
            .unwrap()
            .profile;
        let (_sdk, runtime, _, _, _) = prepare(partial).await;
        let refresh = RuleProviderRefresh::begin(id.clone(), fixture.store.clone(), || {
            RuleSetClient::new(Some(runtime.clone()))
        })
        .unwrap();
        assert!(refresh.prepare_required().await.is_err());
        assert!(fixture
            .store
            .rule_provider_fetch_target(&id, "One")
            .unwrap()
            .entry_count
            .is_none());
        drop(refresh);
        server.await.unwrap();
        runtime.stop().await.unwrap();
    }
}

#[tokio::test]
async fn stopping_preparation_cancels_a_download_waiting_for_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (requested, request_seen) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request_path(&mut stream).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        request_path(&mut stream).await.unwrap();
        requested.send(()).unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let fixture = StoreFixture::new();
    let (id, _) = node_profile(&fixture, address, "Working");
    let (_sdk, runtime, _, _, _) = prepare(
        fixture
            .store
            .profile_configuration_snapshot(&id)
            .unwrap()
            .profile,
    )
    .await;
    let download_runtime = runtime.clone();
    let download = tokio::spawn(async move {
        RuleSetClient::new(Some(download_runtime))
            .unwrap()
            .get(reqwest::Url::parse("http://provider.egrio.test/one").unwrap())
            .await
    });
    request_seen.await.unwrap();
    runtime.stop().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), download)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}
