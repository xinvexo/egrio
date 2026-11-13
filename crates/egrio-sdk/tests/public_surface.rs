use egrio_sdk::{RuntimeGeneration, RuntimeId, RuntimeState};

#[test]
fn sdk_exposes_runtime_identity_types() {
    let id = RuntimeId::new();
    assert_eq!(RuntimeGeneration::new(3).get(), 3);
    assert_eq!(RuntimeState::Created, RuntimeState::Created);
    assert_eq!(id, id);
}
