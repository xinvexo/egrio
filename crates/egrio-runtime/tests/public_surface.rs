use egrio_runtime::{
    CapabilityKind, CheckpointId, CheckpointOperation, CheckpointPhase, RuntimeCheckpointStatus,
    RuntimeCoreDomainStatus, RuntimeCoreGeneration, RuntimeDomainReport, RuntimeDomainStatus,
    RuntimeGeneration, RuntimeId, RuntimeResource, RuntimeResourceChange, RuntimeResourceOutcome,
    RuntimeSpec, RuntimeState, RuntimeStatus,
};
use uuid::Uuid;

#[test]
fn runtime_id_round_trips_uuid() {
    let raw = Uuid::from_u128(42);
    let id = RuntimeId::from_uuid(raw);
    assert_eq!(id.as_uuid(), raw);
    assert_eq!(id.to_string(), raw.to_string());
}

#[test]
fn generated_runtime_ids_are_distinct() {
    assert_ne!(RuntimeId::new(), RuntimeId::new());
}

#[test]
fn runtime_generation_preserves_value() {
    assert_eq!(RuntimeGeneration::new(7).get(), 7);
}

#[test]
fn lifecycle_states_are_instance_values() {
    assert_ne!(RuntimeState::Created, RuntimeState::Running);
    assert_ne!(RuntimeState::Degraded, RuntimeState::Stopped);
}

#[test]
fn runtime_id_has_an_exact_json_representation_and_round_trips() {
    let id = RuntimeId::from_uuid(Uuid::from_u128(42));
    let json = r#""00000000-0000-0000-0000-00000000002a""#;

    assert_eq!(serde_json::to_string(&id).unwrap(), json);
    assert_eq!(serde_json::from_str::<RuntimeId>(json).unwrap(), id);
}

#[test]
fn runtime_generation_has_an_exact_json_representation_and_round_trips() {
    let generation = RuntimeGeneration::new(7);
    let json = "7";

    assert_eq!(serde_json::to_string(&generation).unwrap(), json);
    assert_eq!(
        serde_json::from_str::<RuntimeGeneration>(json).unwrap(),
        generation
    );
}

#[test]
fn runtime_states_have_exact_json_representations_and_round_trip() {
    let cases = [
        (RuntimeState::Created, r#""created""#),
        (RuntimeState::Starting, r#""starting""#),
        (RuntimeState::Running, r#""running""#),
        (RuntimeState::Reloading, r#""reloading""#),
        (RuntimeState::Degraded, r#""degraded""#),
        (RuntimeState::Stopping, r#""stopping""#),
        (RuntimeState::Stopped, r#""stopped""#),
    ];

    for (state, json) in cases {
        assert_eq!(serde_json::to_string(&state).unwrap(), json);
        assert_eq!(serde_json::from_str::<RuntimeState>(json).unwrap(), state);
    }
}

#[test]
fn runtime_domain_reports_distinguish_core_and_platform_resources() {
    let report = RuntimeDomainReport::new(vec![
        RuntimeResourceChange::new(RuntimeResource::Core, RuntimeResourceOutcome::Retained),
        RuntimeResourceChange::new(
            RuntimeResource::Platform {
                capability: CapabilityKind::SystemProxy,
            },
            RuntimeResourceOutcome::RecoveryRequired,
        ),
    ]);

    let json = serde_json::to_string(&report).unwrap();

    assert!(json.contains(r#""domain":"core""#));
    assert!(json.contains(r#""domain":"platform""#));
    assert_eq!(
        serde_json::from_str::<RuntimeDomainReport>(&json).unwrap(),
        report
    );
}

#[test]
fn runtime_domain_status_round_trips_without_product_types() {
    let id = RuntimeId::from_uuid(Uuid::from_u128(42));
    let status = RuntimeDomainStatus {
        runtime: RuntimeStatus {
            id,
            generation: RuntimeGeneration::new(3),
            state: RuntimeState::Degraded,
            degradation_error: Some("restore pending".into()),
        },
        spec: RuntimeSpec::new(id, Default::default()).unwrap(),
        core: Some(RuntimeCoreDomainStatus {
            generation: RuntimeCoreGeneration::new(9),
            listen_addr: Some("127.0.0.1:7890".into()),
        }),
        checkpoint: Some(RuntimeCheckpointStatus {
            id: CheckpointId::from_uuid(Uuid::from_u128(7)),
            operation: CheckpointOperation::Stop,
            phase: CheckpointPhase::RecoveryRequired,
        }),
    };

    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(
        serde_json::from_str::<RuntimeDomainStatus>(&json).unwrap(),
        status
    );
    assert!(json.contains(r#""listen_addr":"127.0.0.1:7890""#));
}
