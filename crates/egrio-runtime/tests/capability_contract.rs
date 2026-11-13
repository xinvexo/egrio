use egrio_runtime::{
    CapabilityError, CapabilityErrorCode, CapabilityKind, CapabilitySupport, DnsControl,
    FirewallControl, PacketCapture, RouteControl, SystemProxyControl,
};

#[test]
fn capability_json_vocabulary_is_stable() {
    assert_eq!(
        serde_json::to_string(&CapabilityKind::SystemProxy).unwrap(),
        r#""system-proxy""#
    );
    assert_eq!(
        serde_json::to_string(&CapabilityErrorCode::Unsupported).unwrap(),
        r#""unsupported""#
    );
    assert_eq!(
        serde_json::to_string(&CapabilitySupport::Unsupported {
            reason: "not available".into()
        })
        .unwrap(),
        r#"{"status":"unsupported","reason":"not available"}"#
    );
}

#[test]
fn unsupported_is_a_structured_capability_error() {
    let error = CapabilityError::unsupported(CapabilityKind::Firewall, "no firewall backend");
    assert_eq!(error.capability, CapabilityKind::Firewall);
    assert_eq!(error.code, CapabilityErrorCode::Unsupported);
    assert_eq!(error.message, "no firewall backend");
}

#[test]
fn all_mutable_ports_are_object_safe() {
    fn packet(_: &dyn PacketCapture) {}
    fn proxy(_: &dyn SystemProxyControl) {}
    fn route(_: &dyn RouteControl) {}
    fn dns(_: &dyn DnsControl) {}
    fn firewall(_: &dyn FirewallControl) {}

    let _ = (packet, proxy, route, dns, firewall);
}
