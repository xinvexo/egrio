use std::sync::Arc;
use std::time::Duration;

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityError, CapabilityErrorCode, CapabilityKind,
    CapabilityObservation, CapabilityOperationReport, DnsControl, DnsSettings, FirewallControl,
    FirewallSettings, PlatformLeaseKey, RouteControl, RouteSettings, RuntimeId,
};
use egrio_service::client::ControlClient;
use egrio_service::protocol::{
    protocol_version, ControlEnvelope, ControlErrorCode, ControlRequest, ControlResponse,
};
use egrio_service::transport::{
    ControlConnection, ControlFuture, ControlTransport, TransportError, TransportErrorKind,
};
use egrio_service::ServicePlatform;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use uuid::Uuid;

#[derive(Debug)]
struct FakeConnection {
    requests: mpsc::UnboundedSender<ControlEnvelope<ControlRequest>>,
    responses: Mutex<mpsc::UnboundedReceiver<ControlEnvelope<ControlResponse>>>,
}

impl ControlConnection for FakeConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        Box::pin(async move {
            let envelope = self
                .responses
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| TransportError::disconnected("fake server stopped"))?;
            let encoded = serde_json::to_vec(&envelope).map_err(|error| {
                TransportError::new(TransportErrorKind::Protocol, error.to_string())
            })?;
            serde_json::from_slice(&encoded).map_err(|error| {
                TransportError::new(TransportErrorKind::Protocol, error.to_string())
            })
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        Box::pin(async move {
            let encoded = serde_json::to_vec(envelope).map_err(|error| {
                TransportError::new(TransportErrorKind::Protocol, error.to_string())
            })?;
            let envelope = serde_json::from_slice(&encoded).map_err(|error| {
                TransportError::new(TransportErrorKind::Protocol, error.to_string())
            })?;
            self.requests
                .send(envelope)
                .map_err(|_| TransportError::disconnected("fake server stopped"))
        })
    }

    fn close_now(&self) {}
}

#[derive(Debug)]
struct FakeTransport(Arc<FakeConnection>);

impl ControlTransport for FakeTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        let connection: Arc<dyn ControlConnection> = self.0.clone();
        Box::pin(async move { Ok(connection) })
    }
}

fn platform_for(client: Arc<ControlClient>) -> ServicePlatform {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return ServicePlatform::new(client, Arc::default());
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return ServicePlatform::new(client);
}

fn checkpoint(kind: CapabilityKind) -> CapabilityCheckpoint {
    let lease_key = match kind {
        CapabilityKind::Route => PlatformLeaseKey::default_route(),
        CapabilityKind::Dns => PlatformLeaseKey::system_dns(),
        CapabilityKind::Firewall => PlatformLeaseKey::kill_switch(),
        _ => panic!("unsupported fake capability"),
    };
    CapabilityCheckpoint {
        lease_key,
        schema_version: 7,
        payload: serde_json::json!({"opaque": kind, "baseline": ["before"]}),
        rollback_payload: Some(serde_json::json!({"keep": "verbatim"})),
    }
}

fn response(
    request: &ControlEnvelope<ControlRequest>,
    session_id: Uuid,
    body: ControlResponse,
) -> ControlEnvelope<ControlResponse> {
    ControlEnvelope {
        protocol: protocol_version(),
        request_id: request.request_id,
        runtime_id: request.runtime_id,
        session_id: Some(session_id),
        body,
    }
}

async fn run_contract(kind: CapabilityKind, settings: serde_json::Value) {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let expected_checkpoint = checkpoint(kind);
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let connection = Arc::new(FakeConnection {
        requests: request_tx,
        responses: Mutex::new(response_rx),
    });
    let server_checkpoint = expected_checkpoint.clone();
    let server_settings = settings.clone();
    let server = tokio::spawn(async move {
        let mut observed_requests = Vec::new();
        while let Some(request) = request_rx.recv().await {
            let body = match &request.body {
                ControlRequest::Hello { .. } => ControlResponse::Hello {
                    service_version: "test".into(),
                    session_id,
                    capabilities: vec![kind],
                },
                ControlRequest::Prepare {
                    capability,
                    settings: actual,
                } => {
                    assert_eq!(*capability, kind);
                    assert_eq!(actual, &server_settings);
                    observed_requests.push(request.body.clone());
                    ControlResponse::Checkpoint(server_checkpoint.clone())
                }
                ControlRequest::Apply {
                    capability,
                    settings: actual,
                } => {
                    assert_eq!(*capability, kind);
                    assert_eq!(actual, &server_settings);
                    observed_requests.push(request.body.clone());
                    ControlResponse::Operation(CapabilityOperationReport {
                        capability: kind,
                        changed: true,
                        verified: true,
                    })
                }
                ControlRequest::Observe { capability } => {
                    assert_eq!(*capability, kind);
                    let active = observed_requests.len() == 2;
                    observed_requests.push(request.body.clone());
                    ControlResponse::Observation(CapabilityObservation {
                        capability: kind,
                        active,
                        verified: true,
                    })
                }
                ControlRequest::Restore { checkpoint } => {
                    assert_eq!(checkpoint, &server_checkpoint);
                    observed_requests.push(request.body.clone());
                    ControlResponse::Operation(CapabilityOperationReport {
                        capability: kind,
                        changed: true,
                        verified: true,
                    })
                }
                request => panic!("unexpected fake request: {request:?}"),
            };
            response_tx
                .send(response(&request, session_id, body))
                .expect("fake client remains connected");
            if observed_requests.len() == 5 {
                let json = serde_json::to_string(&observed_requests).unwrap();
                assert!(!json.contains("desired_state"));
                assert!(!json.contains("profile"));
                assert!(!json.contains("command"));
                return observed_requests;
            }
        }
        observed_requests
    });

    let client = Arc::new(
        timeout(
            Duration::from_secs(5),
            ControlClient::connect_with_request_id(
                Arc::new(FakeTransport(connection)),
                runtime_id,
                "test",
                hello_id,
            ),
        )
        .await
        .expect("fake client handshake timed out")
        .unwrap(),
    );
    let platform = platform_for(client);
    let prepared_checkpoint = adapter_prepare(&platform, kind, settings.clone())
        .await
        .unwrap();
    assert_eq!(prepared_checkpoint, expected_checkpoint);
    let applied = adapter_apply(&platform, kind, settings).await.unwrap();
    assert_eq!(
        applied,
        CapabilityOperationReport {
            capability: kind,
            changed: true,
            verified: true,
        }
    );
    let active = adapter_observe(&platform, kind).await.unwrap();
    assert_eq!(
        active,
        CapabilityObservation {
            capability: kind,
            active: true,
            verified: true,
        }
    );
    let restored = adapter_restore(&platform, kind, &prepared_checkpoint)
        .await
        .unwrap();
    assert_eq!(
        restored,
        CapabilityOperationReport {
            capability: kind,
            changed: true,
            verified: true,
        }
    );
    let inactive = adapter_observe(&platform, kind).await.unwrap();
    assert_eq!(
        inactive,
        CapabilityObservation {
            capability: kind,
            active: false,
            verified: true,
        }
    );

    let requests = server.await.unwrap();
    assert!(matches!(requests[0], ControlRequest::Prepare { .. }));
    assert!(matches!(requests[1], ControlRequest::Apply { .. }));
    assert!(matches!(requests[2], ControlRequest::Observe { .. }));
    assert!(matches!(requests[3], ControlRequest::Restore { .. }));
    assert!(matches!(requests[4], ControlRequest::Observe { .. }));
}

async fn adapter_prepare(
    platform: &ServicePlatform,
    kind: CapabilityKind,
    settings: serde_json::Value,
) -> Result<CapabilityCheckpoint, CapabilityError> {
    match kind {
        CapabilityKind::Route => {
            RouteControl::prepare(platform, &serde_json::from_value(settings).unwrap()).await
        }
        CapabilityKind::Dns => {
            DnsControl::prepare(platform, &serde_json::from_value(settings).unwrap()).await
        }
        CapabilityKind::Firewall => {
            FirewallControl::prepare(platform, &serde_json::from_value(settings).unwrap()).await
        }
        _ => panic!("unsupported fake capability"),
    }
}

async fn adapter_apply(
    platform: &ServicePlatform,
    kind: CapabilityKind,
    settings: serde_json::Value,
) -> Result<CapabilityOperationReport, CapabilityError> {
    match kind {
        CapabilityKind::Route => {
            RouteControl::apply(platform, &serde_json::from_value(settings).unwrap()).await
        }
        CapabilityKind::Dns => {
            DnsControl::apply(platform, &serde_json::from_value(settings).unwrap()).await
        }
        CapabilityKind::Firewall => {
            FirewallControl::apply(platform, &serde_json::from_value(settings).unwrap()).await
        }
        _ => panic!("unsupported fake capability"),
    }
}

async fn adapter_observe(
    platform: &ServicePlatform,
    kind: CapabilityKind,
) -> Result<CapabilityObservation, CapabilityError> {
    match kind {
        CapabilityKind::Route => RouteControl::observe(platform).await,
        CapabilityKind::Dns => DnsControl::observe(platform).await,
        CapabilityKind::Firewall => FirewallControl::observe(platform).await,
        _ => panic!("unsupported fake capability"),
    }
}

async fn adapter_restore(
    platform: &ServicePlatform,
    kind: CapabilityKind,
    checkpoint: &CapabilityCheckpoint,
) -> Result<CapabilityOperationReport, CapabilityError> {
    match kind {
        CapabilityKind::Route => RouteControl::restore(platform, checkpoint).await,
        CapabilityKind::Dns => DnsControl::restore(platform, checkpoint).await,
        CapabilityKind::Firewall => FirewallControl::restore(platform, checkpoint).await,
        _ => panic!("unsupported fake capability"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_mutable_capabilities_follow_the_transaction_contract() {
    timeout(
        Duration::from_secs(5),
        run_contract(
            CapabilityKind::Route,
            serde_json::to_value(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            })
            .unwrap(),
        ),
    )
    .await
    .expect("route contract timed out");
    timeout(
        Duration::from_secs(5),
        run_contract(
            CapabilityKind::Dns,
            serde_json::to_value(DnsSettings {
                servers: vec!["198.18.0.1".parse().unwrap()],
                search_domains: Vec::new(),
            })
            .unwrap(),
        ),
    )
    .await
    .expect("DNS contract timed out");
    timeout(
        Duration::from_secs(5),
        run_contract(
            CapabilityKind::Firewall,
            serde_json::to_value(FirewallSettings {
                kill_switch: true,
                allow_lan: true,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            })
            .unwrap(),
        ),
    )
    .await
    .expect("firewall contract timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_capability_errors_remain_structured() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let connection = Arc::new(FakeConnection {
        requests: request_tx,
        responses: Mutex::new(response_rx),
    });
    let server = tokio::spawn(async move {
        let mut capability_requests = 0_u8;
        while let Some(request) = request_rx.recv().await {
            let body = match &request.body {
                ControlRequest::Hello { .. } => ControlResponse::Hello {
                    service_version: "test".into(),
                    session_id,
                    capabilities: vec![CapabilityKind::Firewall],
                },
                ControlRequest::Prepare {
                    capability: CapabilityKind::Firewall,
                    ..
                }
                | ControlRequest::Apply {
                    capability: CapabilityKind::Firewall,
                    ..
                }
                | ControlRequest::Observe {
                    capability: CapabilityKind::Firewall,
                }
                | ControlRequest::Restore { .. } => {
                    capability_requests += 1;
                    ControlResponse::Error {
                        code: ControlErrorCode::CapabilityFailed,
                        message: "WFP operation failed".into(),
                    }
                }
                request => panic!("unexpected fake request: {request:?}"),
            };
            response_tx
                .send(response(&request, session_id, body))
                .expect("fake client remains connected");
            if capability_requests == 4 {
                break;
            }
        }
    });
    let client = Arc::new(
        timeout(
            Duration::from_secs(5),
            ControlClient::connect_with_request_id(
                Arc::new(FakeTransport(connection)),
                runtime_id,
                "test",
                hello_id,
            ),
        )
        .await
        .expect("fake error client handshake timed out")
        .unwrap(),
    );
    let platform = platform_for(client);
    let settings = FirewallSettings {
        kill_switch: true,
        allow_lan: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    assert_capability_error(
        FirewallControl::prepare(&platform, &settings)
            .await
            .unwrap_err(),
        CapabilityErrorCode::ObserveFailed,
    );
    assert_capability_error(
        FirewallControl::apply(&platform, &settings)
            .await
            .unwrap_err(),
        CapabilityErrorCode::ApplyFailed,
    );
    assert_capability_error(
        FirewallControl::observe(&platform).await.unwrap_err(),
        CapabilityErrorCode::ObserveFailed,
    );
    assert_capability_error(
        FirewallControl::restore(&platform, &checkpoint(CapabilityKind::Firewall))
            .await
            .unwrap_err(),
        CapabilityErrorCode::RestoreFailed,
    );
    timeout(Duration::from_secs(5), server)
        .await
        .expect("fake error server timed out")
        .unwrap();
}

fn assert_capability_error(error: CapabilityError, code: CapabilityErrorCode) {
    assert_eq!(
        error,
        CapabilityError::new(CapabilityKind::Firewall, code, "WFP operation failed",)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_adapter_rejects_mismatched_success_identity() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let connection = Arc::new(FakeConnection {
        requests: request_tx,
        responses: Mutex::new(response_rx),
    });
    let server = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            let body = match &request.body {
                ControlRequest::Hello { .. } => ControlResponse::Hello {
                    service_version: "test".into(),
                    session_id,
                    capabilities: vec![CapabilityKind::Firewall],
                },
                ControlRequest::Observe {
                    capability: CapabilityKind::Firewall,
                } => ControlResponse::Observation(CapabilityObservation {
                    capability: CapabilityKind::Route,
                    active: true,
                    verified: true,
                }),
                request => panic!("unexpected fake request: {request:?}"),
            };
            let done = matches!(request.body, ControlRequest::Observe { .. });
            response_tx
                .send(response(&request, session_id, body))
                .expect("fake client remains connected");
            if done {
                break;
            }
        }
    });
    let client = Arc::new(
        timeout(
            Duration::from_secs(5),
            ControlClient::connect_with_request_id(
                Arc::new(FakeTransport(connection)),
                runtime_id,
                "test",
                hello_id,
            ),
        )
        .await
        .expect("mismatch client handshake timed out")
        .unwrap(),
    );
    let platform = platform_for(client);
    let error = FirewallControl::observe(&platform).await.unwrap_err();
    assert_eq!(error.capability, CapabilityKind::Firewall);
    assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
    timeout(Duration::from_secs(5), server)
        .await
        .expect("mismatch server timed out")
        .unwrap();
    let wrong_checkpoint = checkpoint(CapabilityKind::Route);
    let error = FirewallControl::restore(&platform, &wrong_checkpoint)
        .await
        .unwrap_err();
    assert_eq!(error.capability, CapabilityKind::Firewall);
    assert_eq!(error.code, CapabilityErrorCode::InvalidRequest);
}

/// The Linux packet channel names a TUN the desktop attaches to; an open that
/// cannot attach fails, and Core egress never sees the TUN's resolvers.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linux_open_that_cannot_attach_fails_without_activating_egress() {
    use egrio_runtime::{PacketCapture, PacketCaptureSettings, PacketCaptureSource};
    use egrio_service::{OwnedTunChannel, PacketChannel};

    let session_id = Uuid::new_v4();
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let connection = Arc::new(FakeConnection {
        requests: request_tx,
        responses: Mutex::new(response_rx),
    });
    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            let body = match &request.body {
                ControlRequest::Hello { .. } => ControlResponse::Hello {
                    service_version: "test".into(),
                    session_id,
                    capabilities: vec![CapabilityKind::PacketCapture],
                },
                ControlRequest::OpenPacketCapture { .. } => {
                    ControlResponse::PacketChannel(PacketChannel::OwnedTun(OwnedTunChannel {
                        interface_name: "egrioabsent0".into(),
                        interface_index: 9999,
                        mtu: 1500,
                        physical_dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
                    }))
                }
                request => panic!("unexpected fake request: {request:?}"),
            };
            if response_tx
                .send(response(&request, session_id, body))
                .is_err()
            {
                return;
            }
        }
    });
    let client = Arc::new(
        ControlClient::connect(
            Arc::new(FakeTransport(connection)),
            RuntimeId::new(),
            "test",
        )
        .await
        .unwrap(),
    );
    let egress = Arc::new(egrio_platform_linux::LinuxTunEgress::default());
    let platform = ServicePlatform::new(client, egress.clone());
    let settings = PacketCaptureSettings {
        source: PacketCaptureSource::Tun,
        mtu: 1500,
        install_default_route: false,
        install_dns: false,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    let error = match timeout(
        Duration::from_secs(5),
        PacketCapture::open(&platform, &settings, 2),
    )
    .await
    .expect("open answers")
    {
        Ok(_) => panic!("a TUN that does not exist cannot be attached"),
        Err(error) => error,
    };
    assert_eq!(error.code, CapabilityErrorCode::ApplyFailed);
    assert!(error.message.contains("egrioabsent0"), "{error}");
    assert!(egress.overlay().is_none());
}
