use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use super::*;
use crate::{PacketCaptureSource, RuntimePlatformSpec};

#[derive(Debug)]
pub(super) struct UnusedLeaseCoordinator;

impl LeaseCoordinator for UnusedLeaseCoordinator {
    fn acquire_all(&self, _request: LeaseRequestSet) -> Result<LeaseGrant, PlatformLeaseConflict> {
        panic!("core-only test must not acquire leases")
    }

    fn expand(
        &self,
        _grant: &LeaseGrant,
        _request: LeaseRequestSet,
    ) -> Result<LeaseGrant, LeaseExpandError> {
        panic!("core-only test must not expand leases")
    }

    fn begin_release(&self, _grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        panic!("core-only test must not begin lease release")
    }

    fn mark_recovery_required(
        &self,
        _grant: &LeaseGrant,
        _checkpoint_id: CheckpointId,
    ) -> Result<(), LeaseTransitionError> {
        panic!("core-only test must not mark lease recovery")
    }

    fn begin_recovery(&self, _grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        panic!("core-only test must not begin lease recovery")
    }

    fn resume(&self, _grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        panic!("core-only test must not resume a lease")
    }

    fn shrink(
        &self,
        _grant: &LeaseGrant,
        _retained_keys: Vec<PlatformLeaseKey>,
        _evidence: LeaseReleaseEvidence,
    ) -> Result<LeaseGrant, LeaseTransitionError> {
        panic!("core-only test must not shrink leases")
    }

    fn release(
        &self,
        _grant: &LeaseGrant,
        _evidence: LeaseReleaseEvidence,
    ) -> Result<(), LeaseTransitionError> {
        panic!("core-only test must not release leases")
    }
}

#[derive(Debug)]
pub(super) struct UnusedCheckpointStore;

impl CheckpointStore for UnusedCheckpointStore {
    fn create<'a>(
        &'a self,
        _checkpoint: RecoveryCheckpoint,
    ) -> crate::CheckpointFuture<'a, StoredCheckpoint> {
        panic!("core-only test must not create checkpoints")
    }

    fn get<'a>(
        &'a self,
        _id: CheckpointId,
    ) -> crate::CheckpointFuture<'a, Option<StoredCheckpoint>> {
        panic!("core-only test must not read checkpoints")
    }

    fn replace<'a>(
        &'a self,
        _expected: crate::CheckpointRevision,
        _checkpoint: RecoveryCheckpoint,
    ) -> crate::CheckpointFuture<'a, StoredCheckpoint> {
        panic!("core-only test must not replace checkpoints")
    }

    fn list_unresolved<'a>(&'a self) -> crate::CheckpointFuture<'a, Vec<StoredCheckpoint>> {
        panic!("core-only test must not list checkpoints")
    }

    fn delete<'a>(
        &'a self,
        _id: CheckpointId,
        _expected: crate::CheckpointRevision,
    ) -> crate::CheckpointFuture<'a, ()> {
        panic!("core-only test must not delete checkpoints")
    }
}

#[derive(Debug)]
struct TestCoreConfig;

impl CoreConfigSource for TestCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        Ok(test_inputs("core-stop-failure"))
    }
}

#[derive(Debug)]
pub(super) struct SelectorCoreConfig;

impl CoreConfigSource for SelectorCoreConfig {
    fn load(&self) -> Result<egrio_core::CoreStartInputs, String> {
        let mut inputs = test_inputs("selector-report");
        inputs.profile.groups.push(egrio_core::PolicyGroup {
            id: "choice".into(),
            name: "Choice".into(),
            kind: egrio_core::PolicyGroupKind::Select,
            members: vec!["DIRECT".into(), "REJECT".into()],
            interval_seconds: None,
            test_url: None,
            selected: Some("DIRECT".into()),
        });
        Ok(inputs)
    }
}

#[test]
fn stop_error_distinguishes_platform_restore_from_metadata_cleanup() {
    let before_restore = RuntimeStopError::Cleanup {
        message: "capability restore failed".into(),
        capabilities_restored: false,
    };
    let after_restore = RuntimeStopError::Cleanup {
        message: "lease release failed".into(),
        capabilities_restored: true,
    };

    assert!(!before_restore.capabilities_restored());
    assert!(after_restore.capabilities_restored());
    assert!(!RuntimeStopError::Task("join failed".into()).capabilities_restored());
}

#[tokio::test]
async fn connection_cutover_closes_sessions_and_keeps_the_core_accepting() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    async fn connect_through(
        listener: std::net::SocketAddr,
        target: std::net::SocketAddr,
    ) -> tokio::net::TcpStream {
        let mut client = tokio::net::TcpStream::connect(listener).await.unwrap();
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reply = [0; 128];
        let read = timeout(Duration::from_secs(3), client.read(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply[..read].starts_with(b"HTTP/1.1 200"));
        client
    }

    let runtime = test_core_runtime();
    runtime.start().await.unwrap();
    let device = runtime.core.packet_device().unwrap();
    let listener: std::net::SocketAddr = runtime
        .core
        .status()
        .listen_addr
        .expect("listener address")
        .parse()
        .unwrap();
    let target = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target_addr = target.local_addr().unwrap();
    let mut client = connect_through(listener, target_addr).await;
    let (_upstream, _) = timeout(Duration::from_secs(3), target.accept())
        .await
        .unwrap()
        .unwrap();

    let report = runtime.cutover_core_sessions().await.unwrap();
    assert_eq!(report.tcp_relay_sessions, 1);
    let mut eof = [0; 1];
    let read = timeout(Duration::from_secs(3), client.read(&mut eof))
        .await
        .expect("cutover closes the old client");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert_eq!(
        device.status().state,
        egrio_core::NativeCoreDeviceState::Running
    );
    let _client = connect_through(listener, target_addr).await;
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn quiesced_core_stays_closed_when_stop_fails_and_rejects_updates() {
    let runtime = test_core_runtime();
    runtime.start().await.unwrap();
    let device = runtime.core.packet_device().unwrap();
    runtime.quiesce_core().await.unwrap();
    *runtime.core_stop_failure.lock().unwrap() = Some("injected Core cleanup failure".into());

    assert!(runtime.stop().await.is_err());
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        device.status().state,
        egrio_core::NativeCoreDeviceState::Closed
    );
    assert!(runtime
        .apply_core_with(|| panic!("quiesced Core must not load a new profile"))
        .await
        .is_err());
    let selection = runtime
        .configure(
            RuntimeConfigurationChange::Policy(egrio_core::CorePolicyUpdate::SelectGroup {
                group: "Choice".into(),
                member: "DIRECT".into(),
            }),
            || panic!("quiesced Core must not persist a selection"),
        )
        .await;
    assert_eq!(selection.phase, ConfigurationPhase::Rejected);
    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert_eq!(
        device.status().state,
        egrio_core::NativeCoreDeviceState::Closed
    );
}

#[tokio::test]
async fn delayed_old_packet_exit_cannot_degrade_a_replacement_worker() {
    let runtime = test_core_runtime();
    runtime.start().await.unwrap();
    let operation = runtime.operation.lock().await;
    let weak = Arc::downgrade(&runtime);
    let mut old = ManagedTask::<egrio_core::NativeCoreDeviceRunReport>::spawn(
        None,
        async { Err("old packet worker failed".into()) },
        move |id| {
            if let Some(runtime) = weak.upgrade() {
                runtime.notify_task_exit(id);
            }
        },
    );
    old.started().await.unwrap();
    let old_id = old.id();
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    let mut replacement = ManagedTask::spawn(
        None,
        async move {
            stopping.cancelled().await;
            Ok(egrio_core::NativeCoreDeviceRunReport {
                shutdown_requested: true,
                ..Default::default()
            })
        },
        |_| {},
    );
    replacement.started().await.unwrap();
    let replacement_id = replacement.id();
    *runtime.packet_task.lock().unwrap() = Some(ActivePacketTask {
        settings: PacketCaptureSettings {
            mtu: 1500,
            source: PacketCaptureSource::Tun,
            install_default_route: false,
            install_dns: false,
            excluded_prefixes: Vec::new(),
            fake_ip_prefixes: Vec::new(),
        },
        stop,
        worker: replacement,
    });
    drop(old);
    drop(operation);
    // Exercise the exact delayed completion path, independently of the
    // executor's scheduling order for the already-queued notification.
    runtime.degrade_after_task_exit(old_id).await;
    assert_eq!(runtime.status().state, RuntimeState::Running);
    assert_eq!(
        runtime
            .packet_task
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .worker
            .id(),
        replacement_id
    );
    assert!(runtime.take_packet_report().is_none());
    runtime.stop_packet_task().await.unwrap();
    runtime.stop().await.unwrap();
}

fn test_core_runtime() -> Arc<Runtime> {
    core_runtime_listening_on("127.0.0.1:0".parse().unwrap(), false)
}

fn core_runtime_listening_on(listen_addr: SocketAddr, listen_port_fallback: bool) -> Arc<Runtime> {
    Arc::new(
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
                core_config: Some(Arc::new(TestCoreConfig)),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn outbound_probes_reuse_the_active_core_and_refuse_recovery_fallback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let runtime = test_core_runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/generate_204",
        listener.local_addr().unwrap().port()
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    assert!(runtime
        .probe_outbound("DIRECT", &url)
        .await
        .unwrap()
        .is_none());
    runtime.start().await.unwrap();
    assert!(runtime
        .probe_outbound("DIRECT", &url)
        .await
        .unwrap()
        .is_some());
    server.await.unwrap();
    runtime.control.lock().unwrap().state = RuntimeState::Degraded;
    assert!(runtime.probe_outbound("DIRECT", &url).await.is_err());
    runtime.control.lock().unwrap().state = RuntimeState::Running;
    runtime.stop().await.unwrap();
    assert!(runtime
        .probe_outbound("DIRECT", &url)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn route_evaluation_reads_only_an_existing_running_core() {
    let runtime = test_core_runtime();
    let input = egrio_core::RouteMatchInput {
        host: Some("google.com".into()),
        destination_port: Some(443),
        ..Default::default()
    };
    assert!(runtime.evaluate_core_route(&input).await.unwrap().is_none());
    assert_eq!(runtime.status().state, RuntimeState::Created);
    runtime.start().await.unwrap();
    assert_eq!(
        runtime
            .evaluate_core_route(&input)
            .await
            .unwrap()
            .unwrap()
            .resolved_outbound,
        "DIRECT"
    );
    runtime.stop().await.unwrap();
    assert!(runtime.evaluate_core_route(&input).await.unwrap().is_none());
}

#[tokio::test]
async fn core_stop_failure_does_not_create_platform_recovery_ownership() {
    let runtime = Arc::new(
        Runtime::from_parts(
            RuntimeSpec::with_core(
                RuntimeId::new(),
                Some(crate::RuntimeCoreSpec::default()),
                RuntimePlatformSpec::default(),
            )
            .unwrap(),
            Arc::new(UnusedLeaseCoordinator),
            Arc::new(UnusedCheckpointStore),
            RuntimePorts {
                core_config: Some(Arc::new(TestCoreConfig)),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );
    runtime.start().await.unwrap();
    *runtime
        .core_stop_failure
        .lock()
        .expect("core stop failure mutex") = Some("injected Core cleanup failure".into());

    let error = runtime.stop().await.unwrap_err();

    assert!(error.capabilities_restored());
    assert_eq!(runtime.status().state, RuntimeState::Degraded);
    assert_eq!(
        runtime.core_status().state,
        egrio_core::NativeCoreState::Running
    );
    {
        let control = runtime.control.lock().expect("runtime control mutex");
        assert!(control.checkpoint.is_none());
        assert!(control.lease_grant.is_none());
    }

    runtime.stop().await.unwrap();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[tokio::test]
async fn core_listener_accepts_ephemeral_requested_ports() {
    let runtime = Arc::new(
        Runtime::from_parts(
            RuntimeSpec::with_core(
                RuntimeId::new(),
                Some(crate::RuntimeCoreSpec {
                    listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                    dns_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                    listen_port_fallback: false,
                }),
                RuntimePlatformSpec::default(),
            )
            .unwrap(),
            Arc::new(UnusedLeaseCoordinator),
            Arc::new(UnusedCheckpointStore),
            RuntimePorts {
                core_config: Some(Arc::new(TestCoreConfig)),
                ..RuntimePorts::default()
            },
        )
        .unwrap(),
    );

    runtime.start().await.unwrap();
    let status = runtime.core_status();
    assert!(status
        .listen_addr
        .as_deref()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .is_some_and(|value| value.port() != 0));
    assert!(status
        .dns_listen_addr
        .as_deref()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .is_some_and(|value| value.port() != 0));
    runtime.stop().await.unwrap();
}

#[test]
fn mutable_capabilities_follow_windows_fail_closed_order() {
    let spec = RuntimeSpec::with_core(
        RuntimeId::new(),
        Some(crate::RuntimeCoreSpec::default()),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            system_proxy: Some(crate::SystemProxySpec {
                http_proxy: Some(crate::SystemProxyEndpoint::Socket(SocketAddr::from((
                    [127, 0, 0, 1],
                    7890,
                )))),
                https_proxy: None,
                bypass: Vec::new(),
            }),
            route: Some(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            dns: Some(DnsSettings {
                servers: vec![IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))],
                search_domains: Vec::new(),
            }),
            firewall: Some(FirewallSettings {
                kill_switch: true,
                allow_lan: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
        },
    )
    .unwrap();
    let keys = MutableCapabilityPlan::from_spec(&spec, None)
        .unwrap()
        .iter()
        .map(MutableCapabilityPlan::lease_key)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            PlatformLeaseKey::packet_capture(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::system_proxy(),
        ]
    );
    assert_eq!(
        keys.into_iter().rev().collect::<Vec<_>>(),
        [
            PlatformLeaseKey::system_proxy(),
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::kill_switch(),
            PlatformLeaseKey::packet_capture(),
        ]
    );
}

fn test_inputs(id: &str) -> egrio_core::CoreStartInputs {
    egrio_core::CoreStartInputs {
        flow_scanner: None,
        capture: Default::default(),
        profile: egrio_core::RuntimeProfile::new(id),
        egress: egrio_core::NativeCoreEgressConfig::default(),
        egress_socket_guard: None,
        fake_ip_mappings: None,
    }
}

#[tokio::test]
async fn a_taken_listener_port_fails_the_start_unless_the_spec_lets_another_stand_in() {
    let holder = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = holder.local_addr().unwrap();

    let strict = core_runtime_listening_on(taken, false);
    let error = strict.start().await.unwrap_err().to_string();
    assert!(
        error.contains("another program already uses this port"),
        "{error}"
    );

    let lenient = core_runtime_listening_on(taken, true);
    lenient.start().await.unwrap();
    let status = lenient.core_status();
    let bound: SocketAddr = status.listen_addr.as_deref().unwrap().parse().unwrap();
    assert_eq!(bound.ip(), taken.ip());
    assert_ne!(bound.port(), taken.port());
    assert_eq!(
        status.listener_fallback.map(|fallback| fallback.requested),
        Some(taken.to_string())
    );
    lenient.stop().await.unwrap();
}
