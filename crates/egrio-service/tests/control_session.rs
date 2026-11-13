use egrio_runtime::{CapabilityKind, CapabilityObservation, RuntimeId};
use egrio_service::protocol::{
    protocol_version, ControlEnvelope, ControlErrorCode, ControlRequest, ControlResponse,
};
use egrio_service::session::{
    ControlRequestHandler, ControlServerSession, ControlSessionError, ResponseRouter,
    ServiceConnectionHealth,
};
use uuid::Uuid;

#[test]
fn router_dispatches_by_request_and_rejects_wrong_session() {
    let runtime_id = RuntimeId::from_uuid(Uuid::from_u128(1));
    let session_id = Uuid::from_u128(2);
    let router = ResponseRouter::new(runtime_id, session_id);
    let request_id = Uuid::from_u128(3);
    let receiver = router.register(request_id).unwrap();
    router
        .dispatch(ControlEnvelope {
            protocol: protocol_version(),
            request_id,
            runtime_id,
            session_id: Some(session_id),
            body: observed(),
        })
        .unwrap();
    assert!(matches!(
        receiver.recv().unwrap().unwrap().body,
        ControlResponse::Observation(_)
    ));

    let wrong_id = Uuid::from_u128(4);
    let wrong = router.register(wrong_id).unwrap();
    assert_eq!(
        router
            .dispatch(ControlEnvelope {
                protocol: protocol_version(),
                request_id: wrong_id,
                runtime_id,
                session_id: Some(Uuid::from_u128(9)),
                body: observed(),
            })
            .unwrap_err(),
        ControlSessionError::InvalidSession
    );
    assert_eq!(
        wrong.recv().unwrap().unwrap_err(),
        ControlSessionError::InvalidSession
    );
}

#[test]
fn disconnect_fails_all_pending_requests() {
    let router = ResponseRouter::new(RuntimeId::new(), Uuid::new_v4());
    let receiver = router.register(Uuid::new_v4()).unwrap();
    router.disconnect();
    assert_eq!(router.health(), ServiceConnectionHealth::Disconnected);
    assert_eq!(
        receiver.recv().unwrap().unwrap_err(),
        ControlSessionError::Disconnected
    );
    assert_eq!(
        router.register(Uuid::new_v4()).unwrap_err(),
        ControlSessionError::Disconnected
    );
}

#[test]
fn duplicate_registration_preserves_the_original_waiter() {
    let runtime_id = RuntimeId::new();
    let session_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let router = ResponseRouter::new(runtime_id, session_id);
    let original = router.register(request_id).unwrap();

    assert_eq!(
        router.register(request_id).unwrap_err(),
        ControlSessionError::DuplicateRequest
    );
    router
        .dispatch(ControlEnvelope {
            protocol: protocol_version(),
            request_id,
            runtime_id,
            session_id: Some(session_id),
            body: observed(),
        })
        .unwrap();

    assert!(matches!(
        original.recv().unwrap().unwrap().body,
        ControlResponse::Observation(_)
    ));
}

fn observed() -> ControlResponse {
    ControlResponse::Observation(CapabilityObservation {
        capability: CapabilityKind::PacketCapture,
        active: false,
        verified: true,
    })
}

fn observe() -> ControlRequest {
    ControlRequest::Observe {
        capability: CapabilityKind::PacketCapture,
    }
}

#[derive(Debug)]
struct ObserveHandler;

impl ControlRequestHandler for ObserveHandler {
    fn handle(
        &self,
        request: ControlRequest,
    ) -> Result<ControlResponse, (ControlErrorCode, String)> {
        match request {
            ControlRequest::Observe {
                capability: CapabilityKind::PacketCapture,
            } => Ok(observed()),
            _ => Err((ControlErrorCode::UnsupportedMethod, "unsupported".into())),
        }
    }
}

#[test]
fn server_session_binds_hello_then_rejects_wrong_identity() {
    let runtime_id = RuntimeId::new();
    let hello_id = Uuid::new_v4();
    let server = ControlServerSession::new("0.1.0", vec![CapabilityKind::PacketCapture]);
    let hello = server.handle(
        ControlEnvelope {
            protocol: protocol_version(),
            request_id: hello_id,
            runtime_id,
            session_id: None,
            body: ControlRequest::Hello {
                app_version: "0.1.0".into(),
            },
        },
        &ObserveHandler,
    );
    let session_id = match hello.body {
        ControlResponse::Hello { session_id, .. } => session_id,
        body => panic!("unexpected hello response: {body:?}"),
    };
    assert_eq!(hello.session_id, Some(session_id));

    let observed_response = server.handle(
        ControlEnvelope {
            protocol: protocol_version(),
            request_id: Uuid::new_v4(),
            runtime_id,
            session_id: Some(session_id),
            body: observe(),
        },
        &ObserveHandler,
    );
    assert!(matches!(
        observed_response.body,
        ControlResponse::Observation(_)
    ));

    let rejected = server.handle(
        ControlEnvelope {
            protocol: protocol_version(),
            request_id: Uuid::new_v4(),
            runtime_id: RuntimeId::new(),
            session_id: Some(session_id),
            body: observe(),
        },
        &ObserveHandler,
    );
    assert!(matches!(
        rejected.body,
        ControlResponse::Error {
            code: ControlErrorCode::InvalidSession,
            ..
        }
    ));
}
