//! An in-process Hysteria2 server for tests: the acceptor behind a
//! self-signed certificate for [`SNI`], one user, and a device that relays
//! everything DIRECT, plus the proxy node a client profile names it by.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use serde_json::json;

use super::acceptor::{Hysteria2Acceptor, Hysteria2UserTable};
use crate::capture::NativeCoreCaptureConfig;
use crate::certificate::server_config_from_pem;
use crate::egress::NativeCoreEgressConfig;
use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
use crate::NativeCoreDevice;

/// The one user the acceptor knows.
pub(crate) const USER: &str = "alice";
/// The name the certificate is issued for.
pub(crate) const SNI: &str = "localhost";

/// A started device whose only rule sends everything DIRECT.
pub(crate) fn match_direct_device() -> NativeCoreDevice {
    let mut profile = RuntimeProfile::new("hysteria2-test-server");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    let device = NativeCoreDevice::compile_with_egress_and_capture(
        &profile,
        NativeCoreEgressConfig::default(),
        NativeCoreCaptureConfig::default(),
    );
    device.start();
    device
}

/// A self-signed cert + key (PEM) for [`SNI`], the material an operator
/// would hand the certificate subsystem.
pub(crate) fn self_signed_pem() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec![SNI.into()])
        .expect("params")
        .self_signed(&key_pair)
        .expect("self-signed cert");
    (cert.pem(), key_pair.serialize_pem())
}

/// An acceptor where [`USER`] authenticates with `auth`.
pub(crate) fn acceptor(auth: &str) -> Arc<Hysteria2Acceptor> {
    Arc::new(build_acceptor(auth))
}

/// The same acceptor serving at most `connections` at once, so a test can
/// fill it without standing up the production number of clients.
pub(crate) fn acceptor_serving_at_most(auth: &str, connections: usize) -> Arc<Hysteria2Acceptor> {
    Arc::new(build_acceptor(auth).serving_at_most(connections))
}

fn build_acceptor(auth: &str) -> Hysteria2Acceptor {
    let (cert_pem, key_pem) = self_signed_pem();
    let tls = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), &[b"h3"])
        .expect("server tls config");
    let users = Hysteria2UserTable::new().with_user(USER, auth);
    Hysteria2Acceptor::new(tls, users).expect("acceptor")
}

/// Serves `acceptor` on a loopback endpoint, relaying through `device`.
pub(crate) async fn spawn(
    acceptor: Arc<Hysteria2Acceptor>,
    device: NativeCoreDevice,
) -> SocketAddr {
    let endpoint = acceptor
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind quic endpoint");
    let addr = endpoint.local_addr().expect("endpoint addr");
    tokio::spawn(async move { acceptor.serve(endpoint, device).await });
    addr
}

/// The proxy node `name` for the server at `server`, authenticating with
/// `auth`.
pub(crate) fn proxy_node(name: &str, server: SocketAddr, auth: &str) -> ProxyNode {
    ProxyNode {
        id: name.to_ascii_lowercase(),
        name: name.into(),
        protocol: ProxyProtocol::Hysteria2,
        server: Some(server.ip().to_string()),
        port: Some(server.port()),
        options: json!({ "password": auth, "skip-cert-verify": true, "sni": SNI }),
    }
}
