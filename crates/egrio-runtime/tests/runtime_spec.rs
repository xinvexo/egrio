use egrio_runtime::{
    PacketCaptureSettings, PacketCaptureSource, RouteSettings, RuntimeId, RuntimePlatformSpec,
    RuntimeSpec, RuntimeSpecErrorCode, SystemProxyEndpoint, SystemProxySpec,
};
use std::net::SocketAddr;
use uuid::Uuid;

#[test]
fn lease_requests_are_inert_sorted_runtime_owned_data() {
    let id = RuntimeId::from_uuid(Uuid::from_u128(1));
    let spec = RuntimeSpec::new(
        id,
        RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec {
                http_proxy: Some(SystemProxyEndpoint::Socket(SocketAddr::from((
                    [127, 0, 0, 1],
                    7890,
                )))),
                https_proxy: None,
                bypass: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap();
    let request = spec.lease_request().unwrap().unwrap();
    assert_eq!(request.owner(), id);
    assert_eq!(request.keys().len(), 1);
    assert_eq!(request.keys()[0].capability(), "system-proxy");
}

#[test]
fn specs_without_exclusive_platform_state_need_no_lease() {
    let spec = RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(2)),
        RuntimePlatformSpec::default(),
    )
    .unwrap();
    assert!(spec.lease_request().unwrap().is_none());
}

#[test]
fn duplicate_default_route_ownership_is_rejected_statically() {
    let error = RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::from_u128(3)),
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: true,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            route: Some(RouteSettings {
                default_route: true,
                excluded_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, RuntimeSpecErrorCode::DuplicateLeaseScope);
}

#[test]
fn nil_runtime_id_is_rejected() {
    let error = RuntimeSpec::new(
        RuntimeId::from_uuid(Uuid::nil()),
        RuntimePlatformSpec::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, RuntimeSpecErrorCode::NilRuntimeId);
}
