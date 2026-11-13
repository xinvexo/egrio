use egrio_runtime::{
    CapabilityErrorCode, CapabilityKind, DnsControl, DnsSettings, PacketCapture,
    PacketCaptureSettings, PacketCaptureSource, SystemProxyControl, SystemProxySettings,
};
use egrio_sdk::InMemoryPlatform;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn proxy(port: u16) -> SystemProxySettings {
    SystemProxySettings {
        http_proxy: Some(SocketAddr::from(([127, 0, 0, 1], port))),
        https_proxy: None,
        bypass: vec!["localhost".into()],
    }
}

#[tokio::test]
async fn checkpoint_restores_the_exact_preexisting_baseline() {
    let platform = InMemoryPlatform::new();
    SystemProxyControl::apply(&platform, &proxy(7000))
        .await
        .unwrap();
    let checkpoint = SystemProxyControl::prepare(&platform, &proxy(7890))
        .await
        .unwrap();
    SystemProxyControl::apply(&platform, &proxy(7890))
        .await
        .unwrap();
    assert!(
        SystemProxyControl::restore(&platform, &checkpoint)
            .await
            .unwrap()
            .changed
    );

    let next = SystemProxyControl::prepare(&platform, &proxy(8000))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_value::<Option<SystemProxySettings>>(next.payload).unwrap(),
        Some(proxy(7000))
    );
}

#[tokio::test]
async fn capability_states_and_instances_are_isolated() {
    let first = InMemoryPlatform::new();
    let second = InMemoryPlatform::new();
    SystemProxyControl::apply(&first, &proxy(7890))
        .await
        .unwrap();
    DnsControl::apply(
        &first,
        &DnsSettings {
            servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            search_domains: Vec::new(),
        },
    )
    .await
    .unwrap();
    assert!(SystemProxyControl::observe(&first).await.unwrap().active);
    assert!(DnsControl::observe(&first).await.unwrap().active);
    assert!(!SystemProxyControl::observe(&second).await.unwrap().active);
}

#[tokio::test]
async fn packet_capture_opens_a_duplex_packet_device() {
    let platform = InMemoryPlatform::new();
    let settings = PacketCaptureSettings {
        mtu: 1500,
        source: PacketCaptureSource::Tun,
        install_default_route: true,
        install_dns: false,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    let checkpoint = PacketCapture::prepare(&platform, &settings).await.unwrap();
    let mut opened = PacketCapture::open(&platform, &settings, 1).await.unwrap();
    let interest = egrio_core::PacketInterest {
        read: true,
        write: false,
    };
    let waiting = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        opened.queues[0].ready(interest),
    )
    .await;
    assert!(
        waiting.is_err(),
        "an empty device parks until a packet arrives"
    );
    assert_eq!(platform.emit_packets(vec![vec![1, 2, 3]]).unwrap(), 1);
    opened.queues[0].ready(interest).await.unwrap();
    let packet = opened.queues[0].try_recv().unwrap().unwrap().bytes;
    assert_eq!(packet, vec![1, 2, 3]);
    assert_eq!(
        opened.queues[0].try_send(&packet).unwrap(),
        egrio_core::PacketSend::Sent
    );
    assert_eq!(platform.written_packets(), vec![packet]);
    PacketCapture::restore(&platform, &checkpoint)
        .await
        .unwrap();
    assert!(platform.emit_packets(Vec::new()).is_err());
}

#[tokio::test]
async fn active_packet_capture_baseline_restores_exact_settings() {
    let platform = InMemoryPlatform::new();
    let settings = PacketCaptureSettings {
        mtu: 1500,
        source: PacketCaptureSource::Tun,
        install_default_route: true,
        install_dns: false,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    let _original = PacketCapture::open(&platform, &settings, 1).await.unwrap();
    let checkpoint = PacketCapture::prepare(&platform, &settings).await.unwrap();
    let changed = PacketCaptureSettings {
        mtu: 1500,
        source: PacketCaptureSource::PacketTunnel,
        install_default_route: false,
        install_dns: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    let _changed = PacketCapture::open(&platform, &changed, 1).await.unwrap();

    PacketCapture::restore(&platform, &checkpoint)
        .await
        .unwrap();
    let restored = PacketCapture::prepare(&platform, &settings).await.unwrap();
    assert_eq!(
        serde_json::from_value::<Option<PacketCaptureSettings>>(restored.payload).unwrap(),
        Some(settings)
    );
}

#[tokio::test]
async fn unsupported_capability_is_structured_and_does_not_mutate_state() {
    let platform = InMemoryPlatform::new();
    platform.set_unsupported(CapabilityKind::SystemProxy, "not installed");
    let error = SystemProxyControl::prepare(&platform, &proxy(7890))
        .await
        .unwrap_err();
    assert_eq!(error.code, CapabilityErrorCode::Unsupported);
    assert_eq!(error.capability, CapabilityKind::SystemProxy);
}
