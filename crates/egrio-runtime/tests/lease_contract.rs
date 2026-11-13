use egrio_runtime::{
    CheckpointId, LeaseReleaseEvidence, LeaseRequestSet, PlatformLeaseKey, PlatformLeaseState,
    RuntimeId,
};
use uuid::Uuid;

fn runtime(value: u128) -> RuntimeId {
    RuntimeId::from_uuid(Uuid::from_u128(value))
}

#[test]
fn built_in_lease_keys_have_stable_components() {
    assert_eq!(
        PlatformLeaseKey::system_proxy().capability(),
        "system-proxy"
    );
    assert_eq!(PlatformLeaseKey::system_proxy().scope(), "global");
    assert_eq!(PlatformLeaseKey::default_route().capability(), "route");
    assert_eq!(PlatformLeaseKey::default_route().scope(), "default");
    assert_eq!(PlatformLeaseKey::system_dns().capability(), "dns");
    assert_eq!(PlatformLeaseKey::system_dns().scope(), "system");
    assert_eq!(PlatformLeaseKey::kill_switch().capability(), "firewall");
    assert_eq!(PlatformLeaseKey::kill_switch().scope(), "kill-switch");
}

#[test]
fn lease_key_rejects_empty_components() {
    assert!(PlatformLeaseKey::new("", "global").is_err());
    assert!(PlatformLeaseKey::new("system-proxy", " ").is_err());
}

#[test]
fn lease_key_deserialization_cannot_bypass_validation() {
    assert!(
        serde_json::from_str::<PlatformLeaseKey>(r#"{"capability":" ","scope":"global"}"#).is_err()
    );
}

#[test]
fn request_set_is_sorted_deduplicated_and_inert_data() {
    let owner = runtime(1);
    let request = LeaseRequestSet::new(
        owner,
        [
            PlatformLeaseKey::system_proxy(),
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_proxy(),
        ],
    )
    .unwrap();
    assert_eq!(request.owner(), owner);
    assert_eq!(
        request.keys(),
        &[
            PlatformLeaseKey::default_route(),
            PlatformLeaseKey::system_proxy()
        ]
    );
}

#[test]
fn empty_request_set_is_rejected() {
    assert!(LeaseRequestSet::new(runtime(1), []).is_err());
}

#[test]
fn lease_contract_json_is_exact() {
    assert_eq!(
        serde_json::to_string(&PlatformLeaseKey::system_proxy()).unwrap(),
        r#"{"capability":"system-proxy","scope":"global"}"#
    );
    assert_eq!(
        serde_json::to_string(&PlatformLeaseState::RecoveryRequired).unwrap(),
        r#""recovery-required""#
    );
    assert_eq!(
        serde_json::to_string(&LeaseReleaseEvidence::VerifiedRestore).unwrap(),
        r#""verified-restore""#
    );
    let id = CheckpointId::from_uuid(Uuid::from_u128(9));
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        r#""00000000-0000-0000-0000-000000000009""#
    );
}
