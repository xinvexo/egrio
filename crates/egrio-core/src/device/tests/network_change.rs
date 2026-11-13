use super::*;
use crate::egress::EgressNetwork;
use crate::{EgressBinding, EgressSocketContext, EgressSocketDescriptor};

/// A guard whose network the test changes.
#[derive(Debug)]
struct NetworkGuard(tokio::sync::watch::Sender<EgressNetwork>);

impl EgressSocketGuard for NetworkGuard {
    fn protect_socket(
        &self,
        _: EgressSocketDescriptor,
        _: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        Ok(EgressBinding::unbound())
    }

    fn network(&self) -> Option<tokio::sync::watch::Receiver<EgressNetwork>> {
        Some(self.0.subscribe())
    }
}

fn network(addresses: &[(u32, &str)]) -> EgressNetwork {
    EgressNetwork {
        ipv4_uplink: addresses.first().map(|(index, _)| *index),
        ipv6_uplink: None,
        addresses: addresses
            .iter()
            .map(|(index, ip)| (*index, ip.parse().unwrap()))
            .collect(),
    }
}

#[tokio::test]
async fn a_published_network_change_ends_stranded_connections_and_resets_health() {
    let feed = tokio::sync::watch::Sender::new(network(&[(2, "192.0.2.10"), (3, "198.51.100.20")]));
    let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
        profile: select_group_profile(),
        egress: Default::default(),
        egress_socket_guard: Some(Arc::new(NetworkGuard(feed.clone()))),
        capture: Default::default(),
        flow_scanner: None,
        fake_ip_mappings: None,
    });
    let registry = &core.inner.sessions.registry;
    let session = |target: &str, interface: u32, local: &str| {
        let session = registry.register("test", None, target.into()).unwrap();
        session.set_egress(EgressBinding {
            interface_index: Some(interface),
            local_address: Some(local.parse().unwrap()),
        });
        session
    };
    let wired = session("a.example:443", 2, "192.0.2.10");
    let wifi = session("b.example:443", 3, "198.51.100.20");
    let state = &core.inner.sessions.group_state;
    state.record_probe_success("NodeB", Duration::from_millis(42));
    let handle = core.spawn_health_probe_loop().expect("probe loop");
    timeout(Duration::from_secs(2), async {
        while feed.receiver_count() == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the probe loop takes the network feed");

    // Wi-Fi moves to the top: nothing is stranded, the uplink moved.
    feed.send_modify(|network| network.ipv4_uplink = Some(3));
    timeout(Duration::from_secs(2), async {
        while state.probe_ewma_micros("NodeB").is_some() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("old-network latency history is cleared");
    assert!(!wired.cancellation().is_cancelled());

    // The cable comes out.
    feed.send_replace(network(&[(3, "198.51.100.20")]));
    timeout(Duration::from_secs(2), wired.cancellation().cancelled())
        .await
        .expect("the connection on the lost link ends");
    assert!(!wifi.cancellation().is_cancelled());

    core.close();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("probe loop exits after close")
        .expect("probe task joins cleanly");
}
