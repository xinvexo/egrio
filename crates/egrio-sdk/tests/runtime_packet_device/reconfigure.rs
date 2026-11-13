//! A full profile apply replaces the packet TCP stack without replacing the
//! Runtime's Core or packet task. Fresh handshakes must use its new queue.
use egrio_core::{NativeCoreEgressConfig, RuntimeProfile, TrafficPolicyMode};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    captured_ipv4_tcp_packet, captured_tcp_acknowledgment_number, captured_tcp_flags,
    captured_tcp_payload, captured_tcp_sequence_number, emit_packet, packet_spec,
    wait_for_written_packet, FixedCoreConfig,
};

fn matches_flow(packet: &[u8], server: u16, client: u16) -> bool {
    packet.len() >= 40
        && packet[0] == 0x45
        && packet[9] == 6
        && u16::from_be_bytes([packet[20], packet[21]]) == server
        && u16::from_be_bytes([packet[22], packet[23]]) == client
}

async fn tcp_exchange(
    platform: &InMemoryPlatform,
    cursor: &mut usize,
    server_port: u16,
    client_port: u16,
    body: &[u8],
) {
    let source = Ipv4Addr::new(10, 23, 0, 2);
    let destination = Ipv4Addr::LOCALHOST;
    let isn = 1000 + u32::from(client_port);
    emit_packet(
        platform,
        "profile-syn",
        captured_ipv4_tcp_packet(
            source,
            destination,
            client_port,
            server_port,
            isn,
            0,
            0x02,
            &[],
        ),
    );
    let syn_ack = wait_for_written_packet(platform, cursor, |packet| {
        matches_flow(&packet, server_port, client_port)
            && captured_tcp_flags(&packet) & 0x12 == 0x12
    })
    .await;
    assert_eq!(captured_tcp_acknowledgment_number(&syn_ack), isn + 1);
    let server_isn = captured_tcp_sequence_number(&syn_ack);
    emit_packet(
        platform,
        "profile-ack",
        captured_ipv4_tcp_packet(
            source,
            destination,
            client_port,
            server_port,
            isn + 1,
            server_isn + 1,
            0x10,
            &[],
        ),
    );
    let mut message = (body.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(body);
    emit_packet(
        platform,
        "profile-data",
        captured_ipv4_tcp_packet(
            source,
            destination,
            client_port,
            server_port,
            isn + 1,
            server_isn + 1,
            0x18,
            &message,
        ),
    );
    let response = wait_for_written_packet(platform, cursor, |packet| {
        matches_flow(&packet, server_port, client_port) && captured_tcp_payload(&packet) == message
    })
    .await;
    assert_eq!(
        captured_tcp_acknowledgment_number(&response),
        isn + 1 + message.len() as u32
    );
    emit_packet(
        platform,
        "profile-response-ack",
        captured_ipv4_tcp_packet(
            source,
            destination,
            client_port,
            server_port,
            isn + 1 + message.len() as u32,
            captured_tcp_sequence_number(&response) + message.len() as u32,
            0x10,
            &[],
        ),
    );
}

#[tokio::test]
async fn profile_hot_apply_keeps_new_tcp_handshakes_and_data_on_the_existing_packet_pump() {
    let target = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut message = vec![0; usize::from(length)];
            stream.read_exact(&mut message).await.unwrap();
            let mut framed = length.to_be_bytes().to_vec();
            framed.extend_from_slice(&message);
            stream.write_all(&framed).await.unwrap();
        }
    });
    let platform = Arc::new(InMemoryPlatform::new());
    let mut profile = RuntimeProfile::new("packet-profile-reconfigure");
    profile.traffic_policy_mode = TrafficPolicyMode::Direct;
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .platform(platform.clone())
        .core_config(Arc::new(FixedCoreConfig::new(profile.clone())))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();
    let generation = runtime.status().generation;
    let core = runtime.domain_status().core.unwrap().generation;
    let mut cursor = 0;
    // This first echo proves the pump already owns the original stack; an
    // apply before its initial creation would not expose the stale-Arc bug.
    tcp_exchange(&platform, &mut cursor, port, 54101, b"before-profile-apply").await;
    profile.name = "updated-in-place".into();
    assert!(runtime
        .apply_core_with(|| Ok((profile, NativeCoreEgressConfig::default())))
        .await
        .unwrap());
    assert_eq!(runtime.status().generation, generation);
    assert_eq!(runtime.domain_status().core.unwrap().generation, core);
    assert!(
        runtime.take_packet_report().is_none(),
        "profile apply retains the original packet task"
    );
    tcp_exchange(&platform, &mut cursor, port, 54102, b"after-profile-apply").await;
    tokio::time::timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    runtime.stop().await.unwrap();
    let report = runtime.take_packet_report().unwrap();
    assert!(report.packets_captured_tcp >= 6);
    assert_eq!(report.packets_failed, 0);
    assert_eq!(report.fatal_error, None);
}
