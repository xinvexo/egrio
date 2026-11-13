//! Public capture replacement is fallible; profile-only updates retain the
//! immutable link contract. These tests create no OS capture or network state.
use super::*;

fn capture(mtu: u32) -> NativeCoreCaptureConfig {
    NativeCoreCaptureConfig {
        mtu,
        ..NativeCoreCaptureConfig::default()
    }
}

fn assert_unchanged(core: &NativeCoreDevice, original: &Arc<RuntimeSnapshot>, epoch: u64) {
    assert!(Arc::ptr_eq(&core.inner.snapshot.load_full(), original));
    assert_eq!(core.capture_mtu(), 1420);
    assert_eq!(core.policy_epoch(), epoch);
}

#[test]
fn public_apply_config_rejects_bad_or_changed_mtu_before_plain_core_publication() {
    let device = NativeCoreDevice::compile_with_capture(&direct_profile(), capture(1420));
    let facade = crate::CoreRuntime::from_device(device.clone());
    let original = device.inner.snapshot.load_full();
    let epoch = device.policy_epoch();
    let mut next = direct_profile();
    next.id = "must-not-publish".into();
    for mtu in [0, 1279, 65536, 1280, 1500] {
        let error = facade
            .apply_config(crate::CoreRuntimeConfig {
                profile: next.clone(),
                egress: NativeCoreEgressConfig::default(),
                capture: capture(mtu),
            })
            .expect_err("public facade must return rejected capture configuration");
        assert!(error.contains("MTU"));
        if (1280..=65535).contains(&mtu) {
            assert!(error.contains("new Core device"));
        }
        assert_unchanged(&device, &original, epoch);
        assert!(device.packet_tcp_engine().is_none());
    }
    next.id = "same-mtu-published".into();
    facade
        .apply_config(crate::CoreRuntimeConfig {
            profile: next,
            egress: NativeCoreEgressConfig::default(),
            capture: capture(1420),
        })
        .expect("same-MTU configuration remains replaceable");
    assert_eq!(
        device.inner.snapshot.load().profile_id,
        "same-mtu-published"
    );
    assert_eq!(device.capture_mtu(), 1420);
    assert_eq!(device.policy_epoch(), epoch + 1);
    device.close();
}

#[tokio::test]
async fn public_apply_config_cannot_diverge_from_an_already_running_tcp_engine() {
    let core = NativeCoreDevice::compile_with_capture(&reject_all_profile(), capture(1420));
    let tcp = core
        .ensure_packet_tcp(PacketQueue::ONLY)
        .expect("create the TCP engine");
    // Drive a SYN into the engine and observe its SYN|ACK, rather than
    // treating a created engine as a running stack. The profile rejects
    // every route, so this creates no OS egress socket.
    core.inject_captured_tcp_packet(crate::packet::CapturedPacket::from_bytes(
        captured_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(198, 51, 100, 7),
            54321,
            443,
            1234,
            0,
            0x02,
            &[],
        ),
    ));
    let emitted = core.drain_captured_tcp_packets(8);
    assert_eq!(emitted.len(), 1, "the engine answers the SYN");
    assert!(emitted[0].len() <= 1420);
    let original = core.inner.snapshot.load_full();
    let epoch = core.policy_epoch();
    for mtu in [0, 1279, 65536, 1280, 1500] {
        assert!(core
            .apply_config(&reject_all_profile(), Default::default(), capture(mtu))
            .is_err());
        assert_unchanged(&core, &original, epoch);
        let active = core.ensure_packet_tcp(PacketQueue::ONLY).unwrap();
        assert!(
            Arc::ptr_eq(&active, &tcp),
            "rejected MTU must not retire the running TCP engine"
        );
    }
    let mut next = direct_profile();
    next.id = "running-stack-same-mtu".into();
    core.apply_config(&next, Default::default(), capture(1420))
        .unwrap();
    assert_eq!(core.capture_mtu(), 1420);
    assert_eq!(core.inner.snapshot.load().profile_id, next.id);
    assert_eq!(core.policy_epoch(), epoch + 1);
    assert!(core.ensure_packet_tcp(PacketQueue::ONLY).is_some());
    core.close();
}
