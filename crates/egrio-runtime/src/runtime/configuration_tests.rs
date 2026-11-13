//! Configuration coordinator tests use only an in-memory owner and loopback
//! listeners; no OS capability, application store, or persistent checkpoint is
//! involved.
use super::tests::{SelectorCoreConfig, UnusedCheckpointStore, UnusedLeaseCoordinator};
use super::*;
use crate::RuntimePlatformSpec;
use egrio_core::{CorePolicyUpdate, TrafficPolicyMode};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Debug, Default)]
struct CountingSource(AtomicUsize);
impl CoreConfigSource for CountingSource {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        SelectorCoreConfig.load()
    }
}

fn runtime() -> (Arc<Runtime>, Arc<CountingSource>) {
    runtime_listening_on("127.0.0.1:0".parse().unwrap(), false)
}

fn runtime_listening_on(
    listen_addr: std::net::SocketAddr,
    listen_port_fallback: bool,
) -> (Arc<Runtime>, Arc<CountingSource>) {
    let source = Arc::new(CountingSource::default());
    let runtime = Arc::new(
        Runtime::from_parts(
            RuntimeSpec::with_core(
                RuntimeId::new(),
                Some(crate::RuntimeCoreSpec {
                    listen_addr: Some(listen_addr),
                    dns_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                    listen_port_fallback,
                }),
                RuntimePlatformSpec::default(),
            )
            .unwrap(),
            Arc::new(UnusedLeaseCoordinator),
            Arc::new(UnusedCheckpointStore),
            RuntimePorts {
                core_config: Some(source.clone()),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    (runtime, source)
}

fn policy(update: CorePolicyUpdate) -> RuntimeConfigurationChange {
    RuntimeConfigurationChange::Policy(update)
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("state did not converge");
}

fn park<F: Future>(future: Pin<&mut F>) {
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.poll(&mut context), Poll::Pending));
}

#[tokio::test]
async fn live_policy_changes_reuse_loaded_core_and_listener() {
    let (runtime, source) = runtime();
    let start = runtime.start().await.unwrap();
    let device = runtime.core.packet_device().unwrap();
    let listener = runtime.core_listener_addr().unwrap();
    let saved = Arc::new(AtomicUsize::new(0));
    for update in [
        CorePolicyUpdate::SelectGroup {
            group: "Choice".into(),
            member: "REJECT".into(),
        },
        CorePolicyUpdate::TrafficPolicy {
            mode: TrafficPolicyMode::Direct,
            global_outbound: None,
        },
        CorePolicyUpdate::Ipv6Enabled(true),
    ] {
        let count = saved.clone();
        let result = runtime
            .configure(policy(update), move || {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert_eq!(result.phase, ConfigurationPhase::Applied, "{result:?}");
        assert_eq!(result.generation, start.generation);
        assert_eq!(runtime.core_listener_addr(), Some(listener));
    }
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    assert_eq!(saved.load(Ordering::SeqCst), 3);
    assert_eq!(
        device.observe_policy(),
        runtime.effective_core_policy().unwrap()
    );
    assert_eq!(device.observe_policy().selected_members["Choice"], "REJECT");
    assert_eq!(device.observe_policy().profile_id, "selector-report");
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn invalid_and_failed_persistence_leave_live_policy_untouched() {
    let (runtime, _) = runtime();
    runtime.start().await.unwrap();
    let device = runtime.core.packet_device().unwrap();
    let original = device.observe_policy();
    let listener = runtime.core_listener_addr().unwrap();
    let rejected = runtime
        .configure(
            policy(CorePolicyUpdate::SelectGroup {
                group: "Choice".into(),
                member: "missing".into(),
            }),
            || panic!("invalid update must be rejected before persistence"),
        )
        .await;
    assert_eq!(rejected.phase, ConfigurationPhase::Rejected);
    let failed = runtime
        .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), || {
            Err("disk full".into())
        })
        .await;
    assert_eq!(failed.phase, ConfigurationPhase::Rejected);
    assert_eq!(device.observe_policy(), original);
    assert_eq!(runtime.status().state, RuntimeState::Running);
    let socket = tokio::net::TcpStream::connect(listener).await.unwrap();
    drop(socket);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn stopped_configuration_only_persists_without_loading_core() {
    let (runtime, source) = runtime();
    runtime.stop().await.unwrap();
    let saved = Arc::new(AtomicBool::new(false));
    let record = saved.clone();
    let report = runtime
        .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), move || {
            record.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert_eq!(report.phase, ConfigurationPhase::SavedStopped);
    assert!(saved.load(Ordering::SeqCst));
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
    assert!(runtime.core.packet_device().is_none());
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[tokio::test]
async fn abandoning_response_keeps_the_admitted_operation_owned() {
    let (runtime, _) = runtime();
    runtime.start().await.unwrap();
    let gate = runtime.operation.lock().await;
    let saved = Arc::new(AtomicUsize::new(0));
    let record = saved.clone();
    let mut response = Box::pin(runtime.configure(
        policy(CorePolicyUpdate::Ipv6Enabled(true)),
        move || {
            record.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    ));
    park(response.as_mut());
    drop(response);
    drop(gate);
    eventually(|| {
        runtime
            .configuration_status()
            .is_some_and(|r| r.phase == ConfigurationPhase::Applied)
    })
    .await;
    assert_eq!(saved.load(Ordering::SeqCst), 1);
    assert!(runtime.effective_core_policy().unwrap().ipv6_enabled);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn persistence_panic_is_fenced_before_later_stop_and_start() {
    let (runtime, _) = runtime();
    let initial = runtime.start().await.unwrap();
    let report = runtime
        .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), || {
            panic!("injected persistence panic")
        })
        .await;
    assert_eq!(report.phase, ConfigurationPhase::Degraded);
    let observed = runtime.configuration_status().unwrap();
    assert_eq!(observed.phase, ConfigurationPhase::Degraded);
    assert_eq!(observed.operation_id, report.operation_id);
    assert_eq!(observed.generation, initial.generation);
    assert!(!runtime.effective_core_policy().unwrap().ipv6_enabled);
    let blocked = runtime
        .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), || {
            panic!("partial persistence cannot admit another update")
        })
        .await;
    assert_eq!(blocked.phase, ConfigurationPhase::Rejected);
    runtime.stop().await.unwrap();
    let restarted = runtime.start().await.unwrap();
    assert_ne!(restarted.generation, initial.generation);
    assert_eq!(
        runtime.configuration_status().unwrap().phase,
        ConfigurationPhase::SavedStopped
    );
    assert_eq!(
        runtime
            .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), || Ok(()))
            .await
            .phase,
        ConfigurationPhase::Applied
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn configuration_queue_rejects_overflow_before_persistence() {
    let (runtime, _) = runtime();
    runtime.start().await.unwrap();
    let gate = runtime.operation.lock().await;
    let capacity = runtime.configuration_admission.available_permits();
    let saved = Arc::new(AtomicUsize::new(0));
    let mut requests = Vec::new();
    for _ in 0..capacity {
        let record = saved.clone();
        let mut request = Box::pin(runtime.configure(
            policy(CorePolicyUpdate::Ipv6Enabled(false)),
            move || {
                record.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ));
        park(request.as_mut());
        requests.push(request);
    }
    let overflow = runtime
        .configure(policy(CorePolicyUpdate::Ipv6Enabled(true)), || {
            panic!("overflow must not persist")
        })
        .await;
    assert_eq!(overflow.phase, ConfigurationPhase::Rejected);
    assert_eq!(saved.load(Ordering::SeqCst), 0);
    drop(gate);
    for request in requests {
        assert_eq!(request.await.phase, ConfigurationPhase::NoChange);
    }
    assert_eq!(saved.load(Ordering::SeqCst), capacity);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn queued_operation_is_rejected_after_stop_and_start_replace_generation() {
    let (runtime, source) = runtime();
    let initial = runtime.start().await.unwrap();
    let gate = runtime.operation.lock().await;
    // Register these two FIFO mutex waiters before admitting the configuration
    // task; it must never reinterpret the old request against the new Core.
    let mut stop = Box::pin(runtime.stop_transaction());
    park(stop.as_mut());
    let mut start = Box::pin(runtime.start_transaction(None));
    park(start.as_mut());
    let saved = Arc::new(AtomicUsize::new(0));
    let record = saved.clone();
    let mut change = Box::pin(runtime.configure(
        policy(CorePolicyUpdate::Ipv6Enabled(true)),
        move || {
            record.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    ));
    park(change.as_mut());
    drop(gate);
    let (stopped, started, changed) = tokio::join!(stop, start, change);
    stopped.unwrap();
    let started = started.unwrap();
    assert_ne!(initial.generation, started.generation);
    assert_eq!(changed.phase, ConfigurationPhase::Rejected, "{changed:?}");
    assert_eq!(saved.load(Ordering::SeqCst), 0);
    assert!(!runtime.effective_core_policy().unwrap().ipv6_enabled);
    assert_eq!(source.0.load(Ordering::SeqCst), 2);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn listener_scope_reload_uses_only_loopback_and_keeps_core() {
    let (runtime, source) = runtime();
    let initial = runtime.start().await.unwrap();
    let before = runtime.core_listener_addr().unwrap();
    let device = runtime.core.packet_device().unwrap();
    let policy_before = device.observe_policy();
    let requested = std::net::SocketAddr::new("::1".parse().unwrap(), before.port());
    let applied = runtime
        .configure(RuntimeConfigurationChange::ListenerScope(requested), || {
            Ok(())
        })
        .await;
    assert_eq!(applied.phase, ConfigurationPhase::Applied, "{applied:?}");
    assert_eq!(runtime.core_listener_addr(), Some(requested));
    assert_eq!(runtime.spec().core.unwrap().listen_addr, Some(requested));
    assert_eq!(applied.generation, initial.generation);
    assert_eq!(device.observe_policy(), policy_before);
    let client = tokio::net::TcpStream::connect(requested).await.unwrap();
    drop(client);
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    let rejected = runtime
        .configure(
            RuntimeConfigurationChange::ListenerScope(std::net::SocketAddr::new(
                requested.ip(),
                if requested.port() == 65535 {
                    1
                } else {
                    requested.port() + 1
                },
            )),
            || panic!("changing port must reject before persistence"),
        )
        .await;
    assert_eq!(rejected.phase, ConfigurationPhase::Rejected);
    assert_eq!(runtime.core_listener_addr(), Some(requested));
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn a_scope_change_for_the_requested_port_moves_the_stand_in_port() {
    let holder = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = holder.local_addr().unwrap();
    let (runtime, _source) = runtime_listening_on(taken, true);
    runtime.start().await.unwrap();
    let stand_in = runtime.core_listener_addr().unwrap();
    assert_ne!(stand_in.port(), taken.port());

    // The host asks for the profile's port in the new scope.
    let requested = std::net::SocketAddr::new("::1".parse().unwrap(), taken.port());
    let applied = runtime
        .configure(RuntimeConfigurationChange::ListenerScope(requested), || {
            Ok(())
        })
        .await;
    assert_eq!(applied.phase, ConfigurationPhase::Applied, "{applied:?}");
    let moved = std::net::SocketAddr::new(requested.ip(), stand_in.port());
    assert_eq!(runtime.core_listener_addr(), Some(moved));
    assert_eq!(
        runtime
            .core_status()
            .listener_fallback
            .map(|fallback| fallback.requested),
        Some(requested.to_string())
    );
    // The spec keeps asking for the requested port.
    assert_eq!(runtime.spec().core.unwrap().listen_addr, Some(requested));
    runtime.stop().await.unwrap();
}
