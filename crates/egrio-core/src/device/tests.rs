use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::dns_contract_tests::configure_local_dns;
use super::*;
use crate::policy_group::{now_unix, OUTBOUND_FALL_THRESHOLD};
use crate::profile::{
    PolicyGroup, PolicyGroupKind, ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile,
    TrafficPolicyMode,
};
use crate::runtime::tcp_route_match_input;
use crate::self_test::{
    serve_http_connect_proxies, serve_one_echo, serve_one_http_connect_proxy, SlowDns,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

#[path = "../../examples/support/fd_limit.rs"]
mod fd_limit;

async fn send_udp_and_drain(
    core: &NativeCoreDevice,
    datagram: NativeUdpFlowDatagram,
) -> (NativeUdpFlowSendReport, NativeUdpFlowPendingDatagram) {
    let flow_id = datagram
        .flow_id
        .clone()
        .expect("test UDP datagram carries a flow id");
    let report = core
        .send_udp_flow_datagram(datagram)
        .await
        .expect("UDP flow send succeeds");
    assert!(report.enqueued, "test UDP datagram is enqueued");
    let response = core
        .drain_pending_udp_flow_responses(32, Duration::from_secs(5))
        .await
        .expect("drain pending UDP flow responses")
        .into_iter()
        .find(|response| response.flow_id == flow_id)
        .expect("UDP flow response arrives");
    (report, response)
}

#[tokio::test]
async fn invalid_public_capture_mtu_is_reported_before_the_tcp_engine_exists() {
    let capture = NativeCoreCaptureConfig {
        mtu: 0,
        ..NativeCoreCaptureConfig::default()
    };
    let core = NativeCoreDevice::compile_with_egress_and_capture(
        &dns_capture_profile(),
        Default::default(),
        capture,
    );
    let packet = ipv4_udp_packet(
        "10.0.0.2".parse().unwrap(),
        "198.18.0.1".parse().unwrap(),
        53123,
        53,
        &dns_query(0x1234, "example.com", 1),
    );
    assert!(core
        .ingest_packet(packet.clone())
        .await
        .unwrap_err()
        .contains("MTU"));
    assert!(core.ensure_packet_tcp(PacketQueue::ONLY).is_none());
    let mut device = MemoryPacketDevice::new(vec![packet]);
    let stop = device.stop.clone();
    let report = core
        .run_packet_queue(PacketQueue::ONLY, &mut device, stop)
        .await;
    assert_eq!(report.packets_received, 0);
    assert!(report.fatal_error.unwrap().contains("MTU"));
    assert!(device.written.is_empty());
    core.close();
}

#[tokio::test]
async fn core_device_runs_packet_device_and_writes_emitted_packets() {
    let query = dns_query(0x1234, "example.com", 1);
    let request = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        53123,
        53,
        &query,
    );
    let mut packet_device = MemoryPacketDevice::new(vec![request]).stop_after_writes(1);
    let stop = packet_device.stop.clone();
    let core = NativeCoreDevice::compile(&dns_capture_profile());

    let report = timeout(
        Duration::from_secs(5),
        core.run_packet_queue(PacketQueue::ONLY, &mut packet_device, stop),
    )
    .await
    .expect("device loop answers and stops");

    assert_eq!(report.packets_received, 1);
    assert_eq!(report.packets_written, 1);
    assert_eq!(report.packets_action_dns_capture, 1);
    assert!(report.shutdown_requested);
    assert_eq!(packet_device.written.len(), 1);
}

/// A slow DNS upstream must not stall the pump: while a captured query is
/// still resolving, a later packet is executed, and the answer is written
/// once the upstream replies.
#[tokio::test]
async fn captured_dns_resolution_does_not_block_other_packets() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mut profile = dns_capture_profile();
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::RedirHost;
    profile.dns.nameservers = vec![crate::dns::config::DnsUpstream {
        transport: crate::dns::config::DnsTransport::Udp,
        host: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        path: String::new(),
        server_name: None,
        route: Some(crate::dns::config::DnsRoute::Direct),
    }];
    let core = NativeCoreDevice::compile(&profile);
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let resolver = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (length, peer) = upstream.recv_from(&mut buffer).await.unwrap();
        let _ = release_rx.await;
        let query = crate::dns::wire::decode(&buffer[..length]).unwrap();
        let response =
            crate::dns::wire::response(&query, hickory_proto::op::ResponseCode::NXDomain);
        upstream
            .send_to(&crate::dns::wire::encode(&response).unwrap(), peer)
            .await
            .unwrap();
    });
    let query = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        53123,
        53,
        &dns_query(0x4321, "slow.example", 1),
    );
    let multicast = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(224, 0, 0, 251),
        5353,
        5353,
        b"mdns",
    );
    let mut device = MemoryPacketDevice::new(vec![query, multicast]).stop_after_writes(1);
    let stop = device.stop.clone();
    let run = core.run_packet_queue(PacketQueue::ONLY, &mut device, stop);
    tokio::pin!(run);
    // The pump keeps running while the DNS query is outstanding.
    assert!(timeout(Duration::from_millis(300), &mut run).await.is_err());
    release_tx.send(()).unwrap();
    let report = timeout(Duration::from_secs(5), run)
        .await
        .expect("answer is written once the upstream replies");
    assert_eq!(report.packets_received, 2);
    assert_eq!(report.packets_action_dns_capture, 1);
    assert_eq!(report.packets_action_multicast_drop, 1);
    assert_eq!(report.packets_written, 1);
    resolver.await.unwrap();
    core.close();
}

/// A transient adapter write failure must be isolated to that packet, not tear
/// the whole capture loop down: the failed write is counted and its error
/// recorded, and the DNS capture action still ran.
#[tokio::test]
async fn core_device_survives_a_transient_adapter_write_failure() {
    let query = dns_query(0x1234, "example.com", 1);
    let request = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        53123,
        53,
        &query,
    );
    let mut packet_device = MemoryPacketDevice::new(vec![request])
        .fail_writes("adapter send ring full")
        .stop_after_writes(1);
    let stop = packet_device.stop.clone();
    let core = NativeCoreDevice::compile(&dns_capture_profile());

    let report = timeout(
        Duration::from_secs(5),
        core.run_packet_queue(PacketQueue::ONLY, &mut packet_device, stop),
    )
    .await
    .expect("write failure must not abort the device loop");

    assert_eq!(report.packets_received, 1);
    assert_eq!(report.packets_written, 0);
    assert!(
        report.packets_failed >= 1,
        "the failed write must be counted"
    );
    assert_eq!(report.packets_action_dns_capture, 1);
    assert_eq!(
        report.last_error.as_deref(),
        Some("adapter send ring full"),
        "the write error is recorded for diagnostics"
    );
    assert_eq!(report.fatal_error, None);
}

/// A fatal device read (the shared ring cancelled out from under the pump on
/// Windows session teardown, a dead adapter) must not discard the run report:
/// the loop exits with the accumulated counters and records the failure in
/// `fatal_error`, so the session's stop report still carries the run's totals.
#[tokio::test]
async fn core_device_keeps_the_run_report_when_the_device_read_fails() {
    let query = dns_query(0x1234, "example.com", 1);
    let request = ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        53123,
        53,
        &query,
    );
    let mut packet_device = MemoryPacketDevice::new(vec![request])
        .fail_reads_when_drained("shared packet ring failed: Cancelled");
    let stop = packet_device.stop.clone();
    let core = NativeCoreDevice::compile(&dns_capture_profile());

    let report = core
        .run_packet_queue(PacketQueue::ONLY, &mut packet_device, stop)
        .await;

    assert_eq!(
        report.packets_received, 1,
        "counters before the failure survive"
    );
    assert_eq!(report.packets_action_dns_capture, 1);
    assert_eq!(
        report.fatal_error.as_deref(),
        Some("shared packet ring failed: Cancelled"),
        "the terminating error is recorded on the report"
    );
    assert_eq!(report.last_error.as_deref(), report.fatal_error.as_deref());
    assert!(
        !report.shutdown_requested,
        "a fatal exit is distinguishable from a requested shutdown"
    );
}

/// An idle pump parks on readiness and cancellation instead of polling.
#[tokio::test]
async fn idle_pump_parks_until_cancelled() {
    let core = NativeCoreDevice::compile(&dns_capture_profile());
    let mut device = MemoryPacketDevice::new(Vec::new());
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let canceller = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;
        cancel.cancel();
    });
    let report = timeout(
        Duration::from_secs(5),
        core.run_packet_queue(PacketQueue::ONLY, &mut device, stop),
    )
    .await
    .expect("cancellation wakes the parked pump");
    assert!(report.shutdown_requested);
    // One wait per wakeup source firing (the reassembly sweep's first tick
    // and the final cancellation), never a busy loop over 200 ms.
    assert!(
        device.ready_calls <= 3,
        "ready calls: {}",
        device.ready_calls
    );
    canceller.await.unwrap();
    core.close();
}

#[test]
fn heartbeat_event_is_one_json_line_with_stall_gated_destinations() {
    let core = NativeCoreDevice::compile(&RuntimeProfile::new("heartbeat"));

    let line = core.heartbeat_event("test-heartbeat", 3);

    let event: serde_json::Value = serde_json::from_str(&line).expect("heartbeat line is JSON");
    assert_eq!(event["event"], "test-heartbeat");
    assert_eq!(event["status"]["state"], "running");
    assert!(
        event["audit"]["tcp_relay_sessions"]["phases"]["dialing"].is_number(),
        "audit carries the per-phase population: {event}"
    );
    assert_eq!(
        event["stalled"].as_array().map(Vec::len),
        Some(0),
        "healthy device logs no destinations"
    );
    assert!(!line.contains('\n'), "hosts print the event as one line");
}

#[tokio::test]
async fn closing_core_device_clears_sessions_and_rejects_new_packets() {
    let core = NativeCoreDevice::compile(&RuntimeProfile::new("empty"));
    assert_eq!(core.status().state, NativeCoreDeviceState::Running);

    let status = core.close();

    assert_eq!(status.state, NativeCoreDeviceState::Closed);
    assert_eq!(
        core.close().state,
        NativeCoreDeviceState::Closed,
        "repeated close remains idempotent and cannot deadlock"
    );
    assert!(core
        .drain_pending_packets()
        .await
        .expect_err("closed device rejects work")
        .contains("closed"));
}

#[tokio::test]
async fn core_device_routes_tcp_flow_over_os_socket_path() {
    assert_os_socket_tcp_flow(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn core_device_routes_literal_ipv6_when_dns_ipv6_is_disabled() {
    assert_os_socket_tcp_flow(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

async fn assert_os_socket_tcp_flow(target_ip: IpAddr) {
    let request = b"os-socket-flow-request";
    let response = b"os-socket-flow-response";
    let target_listener = TcpListener::bind((target_ip, 0))
        .await
        .expect("bind target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.expect("accept target");
        let mut buffer = [0_u8; 64];
        let read = stream.read(&mut buffer).await.expect("read target");
        assert_eq!(&buffer[..read], request);
        stream.write_all(response).await.expect("write response");
    });

    let inbound_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind inbound");
    let inbound_addr = inbound_listener.local_addr().expect("inbound addr");
    let mut app_stream = TcpStream::connect(inbound_addr)
        .await
        .expect("connect inbound");
    let (flow_stream, _) = inbound_listener.accept().await.expect("accept inbound");
    let core = NativeCoreDevice::compile(&direct_profile());
    assert!(!core.ipv6_enabled());
    let snapshot_core = core.clone();
    let flow_task = tokio::spawn(async move {
        core.route_tcp_flow(
            flow_stream,
            NativeTcpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: Some("Google Chrome".into()),
                process_path: Some("/Applications/Google Chrome.app".into()),
            },
        )
        .await
    });

    app_stream
        .write_all(request)
        .await
        .expect("write app request");
    timeout(Duration::from_secs(2), async {
        loop {
            let connections = snapshot_core.connections_snapshot();
            if connections
                .iter()
                .any(|connection| connection.process_name.as_deref() == Some("Google Chrome"))
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connection snapshot includes process metadata");
    app_stream.shutdown().await.expect("shutdown app write");
    let mut received = Vec::new();
    app_stream
        .read_to_end(&mut received)
        .await
        .expect("read app response");

    assert_eq!(received, response);
    let outcome = flow_task
        .await
        .expect("flow task joins")
        .expect("flow routes");
    assert_eq!(outcome.outbound, "DIRECT");
    target_task.await.expect("target joins");
}

#[tokio::test]
async fn platform_tcp_flow_preserves_reject_as_an_error() {
    let (_app_stream, flow_stream) = loopback_stream_pair().await;
    let core = NativeCoreDevice::compile(&reject_all_profile());

    let error = core
        .route_tcp_flow(
            flow_stream,
            NativeTcpFlowTarget {
                host: "example.com".into(),
                port: 443,
                process_name: None,
                process_path: None,
            },
        )
        .await
        .expect_err("platform flow keeps the public REJECT error contract");

    assert!(matches!(error.cause, crate::TcpFlowFailure::RouteRejected));
    assert_eq!(error.context.outbound.as_deref(), Some("REJECT"));
    assert!(error.is_expected_close());
    let finished = core.finished_connections_snapshot();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].state, TrafficConnectionState::Rejected);
    assert_eq!(
        finished[0].termination,
        Some(crate::ConnectionTermination::RouteRejected)
    );
}

#[tokio::test]
async fn platform_policy_denial_reaches_telemetry_as_rejection_with_reason() {
    let (_client, stream) = loopback_stream_pair().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let error = timeout(
        Duration::from_secs(2),
        core.route_tcp_flow(
            stream,
            NativeTcpFlowTarget {
                host: "fe80::1%test-interface".into(),
                port: 9,
                process_name: None,
                process_path: None,
            },
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        error.cause,
        crate::TcpFlowFailure::PolicyRejected(crate::EgressPolicyRejection::UnresolvedIpv6Scope)
    ));
    let telemetry = core.traffic_telemetry_snapshot();
    let row = telemetry
        .connections
        .iter()
        .find(|row| row.closed_at_unix.is_some())
        .unwrap();
    assert_eq!(row.state, TrafficConnectionState::Rejected);
    assert_eq!(
        row.termination,
        Some(crate::ConnectionTermination::PolicyRejected {
            reason: crate::EgressPolicyRejection::UnresolvedIpv6Scope
        })
    );
    assert_eq!(
        (
            telemetry.completed_connections,
            telemetry.failed_connections
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn a_fake_ip_handed_out_before_a_restart_still_names_its_domain() {
    let directory = std::env::temp_dir().join(format!(
        "egrio-fake-ip-keeper-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("fake-ip-mappings");
    let mut profile = direct_profile();
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    let inputs = || crate::CoreStartInputs {
        profile: profile.clone(),
        egress: Default::default(),
        egress_socket_guard: None,
        capture: Default::default(),
        flow_scanner: None,
        fake_ip_mappings: Some(path.clone()),
    };

    let first = NativeCoreDevice::from_start_inputs(inputs());
    let held = first
        .pinned_runtime()
        .fake_dns()
        .allocate_ipv4("held.example")
        .unwrap();
    first.close();

    let second = NativeCoreDevice::from_start_inputs(inputs());
    let runtime = second.pinned_runtime();
    assert_eq!(
        runtime.fake_dns_domain_for_ip(IpAddr::V4(held)).as_deref(),
        Some("held.example"),
        "the next Core knows the address before any answer"
    );
    assert_ne!(
        runtime.fake_dns().allocate_ipv4("other.example").unwrap(),
        held
    );
    second.close();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[tokio::test]
async fn connect_to_unmapped_fake_range_target_is_refused() {
    let mut profile = direct_profile();
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    let core = NativeCoreDevice::compile(&profile);
    let (mut app_stream, server_stream) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server_stream, &runtime).await
    });

    // Inside the fake pool, never allocated by this session: the stale
    // resolver-cache shape after a capture restart.
    app_stream
        .write_all(b"CONNECT 198.18.9.9:443 HTTP/1.1\r\nHost: 198.18.9.9:443\r\n\r\n")
        .await
        .expect("send CONNECT");

    let refused = timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler exits")
        .expect("handler joins")
        .expect_err("stale fake target must be refused");
    assert!(refused.contains("stale fake-IP"), "{refused}");
    drop(app_stream);
}

#[tokio::test]
async fn core_device_routes_tcp_flow_through_configured_http_proxy() {
    assert_http_proxy_tcp_flow(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn core_device_dials_literal_ipv6_proxy_with_dns_ipv6_disabled() {
    assert_http_proxy_tcp_flow(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

async fn assert_http_proxy_tcp_flow(proxy_ip: IpAddr) {
    let payload = b"core-device-http-proxy-ipv4";
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });

    let proxy_listener = TcpListener::bind((proxy_ip, 0))
        .await
        .expect("bind HTTP proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let (connect_tx, connect_rx) = oneshot::channel();
    let proxy_task =
        tokio::spawn(async move { serve_one_http_connect_proxy(proxy_listener, connect_tx).await });

    let inbound_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind inbound");
    let inbound_addr = inbound_listener.local_addr().expect("inbound addr");
    let mut app_stream = TcpStream::connect(inbound_addr)
        .await
        .expect("connect inbound");
    let (flow_stream, _) = inbound_listener.accept().await.expect("accept inbound");
    let core = NativeCoreDevice::compile(&http_proxy_profile("HttpProxy", proxy_addr));
    assert!(!core.ipv6_enabled());
    assert_eq!(core.status().state, NativeCoreDeviceState::Running);

    let flow_task = tokio::spawn(async move {
        core.route_tcp_flow(
            flow_stream,
            NativeTcpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: None,
                process_path: None,
            },
        )
        .await
    });

    app_stream
        .write_all(payload)
        .await
        .expect("write app payload");
    app_stream.shutdown().await.expect("shutdown app write");
    let mut received = Vec::new();
    app_stream
        .read_to_end(&mut received)
        .await
        .expect("read app response");

    let proxied_authority = timeout(Duration::from_secs(3), connect_rx)
        .await
        .expect("proxy observes CONNECT")
        .expect("proxy sends CONNECT authority");
    let outcome = flow_task
        .await
        .expect("flow task joins")
        .expect("flow routes through HTTP proxy");

    assert_eq!(received, payload);
    assert_eq!(proxied_authority, target_addr.to_string());
    assert_eq!(outcome.outbound, "HttpProxy");
    assert_eq!(outcome.matched_rule.as_deref(), Some("MATCH,HttpProxy"));
    assert_eq!(outcome.matched_kind, Some(RouteMatchKind::Match));
    assert_eq!(outcome.target, target_addr.to_string());
    echo_task.await.expect("echo join").expect("echo completes");
    proxy_task
        .await
        .expect("proxy join")
        .expect("proxy completes");
}

#[tokio::test]
async fn core_device_relays_udp_flow_datagram_over_os_socket_path() {
    let payload = b"os-socket-udp-flow";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task =
        tokio::spawn(async move { crate::self_test::serve_one_udp_echo(target_socket).await });
    let core = NativeCoreDevice::compile(&direct_profile());

    let (outcome, response) = send_udp_and_drain(
        &core,
        NativeUdpFlowDatagram {
            flow_id: Some("udp-flow-test".into()),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53123)),
            target: NativeUdpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: None,
                process_path: None,
            },
            payload: payload.to_vec(),
        },
    )
    .await;

    assert!(outcome.enqueued);
    assert_eq!(
        core.inner
            .sessions
            .udp_sessions
            .session_for_flow("udp-flow-test")
            .unwrap()
            .outbound,
        "DIRECT"
    );
    assert_eq!(response.source_endpoint, target_addr.to_string());
    assert_eq!(response.payload, payload);
    assert_eq!(core.status().udp_sessions, 1);
    let sessions = core.inner.sessions.udp_sessions.snapshot_for_test();
    assert_eq!(sessions.len(), 1);
    let session = sessions.first().expect("UDP flow session recorded");
    assert_eq!(session.flow_id.as_deref(), Some("udp-flow-test"));
    // The flow API is the capture data plane, so the session — and the row it
    // projects — is tagged as entering through the TUN.
    assert_eq!(session.inbound, "tun");
    let connection = core
        .connections_snapshot()
        .into_iter()
        .find(|connection| connection.id.starts_with("udp-"))
        .expect("UDP connection row projected");
    assert_eq!(connection.inbound, "tun");
    echo_task.await.expect("echo join").expect("echo completes");
}

#[tokio::test]
async fn core_device_sends_udp_flow_datagram_and_drains_responses() {
    let first_response = b"udp-flow-first-response";
    let second_response = b"udp-flow-second-response";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        let (_, peer) = target_socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        target_socket
            .send_to(first_response, peer)
            .await
            .map_err(|error| error.to_string())?;
        target_socket
            .send_to(second_response, peer)
            .await
            .map_err(|error| error.to_string())?;
        Ok::<_, String>(())
    });
    let core = NativeCoreDevice::compile(&direct_profile());

    let report = core
        .send_udp_flow_datagram(NativeUdpFlowDatagram {
            flow_id: Some("udp-flow-drain".into()),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53124)),
            target: NativeUdpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: None,
                process_path: None,
            },
            payload: b"udp-flow-request".to_vec(),
        })
        .await
        .expect("UDP flow send succeeds");
    assert!(report.enqueued);
    assert_eq!(
        core.inner.sessions.udp_sessions.sessions_snapshot()[0].outbound,
        "DIRECT"
    );
    assert_eq!(report.bytes_sent, b"udp-flow-request".len());

    // Both responses reach the flow through the parked all-flow drain; no
    // polling loop is needed because the drain wakes on arrival.
    let mut drained = Vec::new();
    while drained.len() < 2 {
        let batch = core
            .drain_pending_udp_flow_responses(32, Duration::from_secs(5))
            .await
            .expect("drain pending UDP flow responses");
        assert!(!batch.is_empty(), "drain timed out before both responses");
        drained.extend(batch);
    }

    assert_eq!(drained.len(), 2);
    assert!(drained
        .iter()
        .all(|datagram| datagram.flow_id == "udp-flow-drain"));
    assert!(drained
        .iter()
        .all(|datagram| datagram.source_endpoint == target_addr.to_string()));
    assert_eq!(
        drained
            .iter()
            .map(|d| d.payload.clone())
            .collect::<Vec<_>>(),
        vec![first_response.to_vec(), second_response.to_vec()]
    );
    let sessions = core.inner.sessions.udp_sessions.snapshot_for_test();
    let session = sessions.first().expect("UDP flow session recorded");
    assert_eq!(session.packets_sent, 1);
    assert_eq!(session.packets_received, 2);
    assert_eq!(
        session.bytes_received,
        (first_response.len() + second_response.len()) as u64
    );
    echo_task.await.expect("echo join").expect("echo completes");
}

#[tokio::test]
async fn apply_profile_cuts_udp_preserves_fake_ips_and_releases_old_snapshot() {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task =
        tokio::spawn(async move { crate::self_test::serve_one_udp_echo(target_socket).await });
    let core = NativeCoreDevice::compile(&direct_profile());

    // Establish durable state under the first snapshot: one UDP flow
    // session and one fake-IP mapping a client could already hold.
    let (report, response) = send_udp_and_drain(
        &core,
        NativeUdpFlowDatagram {
            flow_id: Some("swap-survivor".into()),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53126)),
            target: NativeUdpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: None,
                process_path: None,
            },
            payload: b"pre-swap".to_vec(),
        },
    )
    .await;
    assert!(report.enqueued);
    assert_eq!(response.payload, b"pre-swap");
    let fake_ip = core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4("swap.example")
        .expect("fake IP allocates");
    let old_weak = Arc::downgrade(&core.inner.snapshot.load_full());
    let old_rules = Arc::downgrade(&core.inner.snapshot.load_full().rule_engine);
    let previous = core.pinned_runtime();

    core.apply_profile(&reject_all_profile());

    // New decisions use the new snapshot immediately.
    let pinned = core.pinned_runtime();
    let route_input = tcp_route_match_input(
        &ConnectTarget {
            host: "post-swap.example".into(),
            port: 443,
        },
        None,
    );
    assert_eq!(pinned.rule_engine().route(&route_input).outbound, "REJECT");
    assert_eq!(
        previous.rule_engine().route(&route_input).outbound,
        "DIRECT"
    );
    let dns_query = crate::DnsQueryInput {
        query_class: 1,
        domain: "post-swap.example".into(),
        record_type: crate::DnsRecordType::A,
        process_name: None,
        process_path: None,
    };
    assert_eq!(
        pinned.dns_service().evaluate(&dns_query).action,
        crate::DnsDecisionAction::Block
    );
    assert_eq!(
        previous.dns_service().evaluate(&dns_query).action,
        crate::DnsDecisionAction::Resolve
    );
    drop(pinned);

    // Rejected UDP sessions are removed; durable fake-IP state survives.
    assert_eq!(core.status().udp_sessions, 0);
    assert_eq!(
        core.inner
            .sessions
            .udp_sessions
            .session_socket_count_for_test(),
        0
    );
    assert_eq!(
        core.inner.sessions.fake_dns.lookup_ipv4(fake_ip).as_deref(),
        Some("swap.example")
    );

    // With no session pinning it, the replaced snapshot is released.
    assert!(old_weak.upgrade().is_some());
    drop(previous);
    assert!(
        old_weak.upgrade().is_none(),
        "swapped-out snapshot must drop once nothing pins it"
    );
    assert!(
        old_rules.upgrade().is_none(),
        "old rules must also be freed"
    );
    echo_task.await.expect("echo join").expect("echo completes");
}

#[test]
fn apply_profile_and_egress_swaps_egress_and_keeps_capture() {
    let capture = NativeCoreCaptureConfig::with_dns_hijack(
        crate::capture::NativeCoreDnsHijackConfig::disabled(),
    );
    let core = NativeCoreDevice::compile_with_egress_and_capture(
        &direct_profile(),
        NativeCoreEgressConfig::default(),
        capture.clone(),
    );
    let previous = core.pinned_runtime();
    assert!(!core.ipv6_enabled());

    core.apply_profile_and_egress(
        &direct_profile(),
        NativeCoreEgressConfig {
            ipv6_enabled: true,
            refuse_private_destinations: false,
            ..NativeCoreEgressConfig::default()
        },
    );

    let pinned = core.pinned_runtime();
    assert!(core.ipv6_enabled());
    assert!(!previous.egress().ipv6_enabled());
    assert!(pinned.egress().ipv6_enabled());
    assert_eq!(*pinned.capture(), capture);
}

#[tokio::test]
async fn dns_aaaa_follows_the_single_global_ipv6_policy_across_updates() {
    let mut profile = direct_profile();
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    let core = NativeCoreDevice::compile(&profile);
    let query = crate::dns::wire::query("ipv6-policy.example", hickory_proto::rr::RecordType::AAAA)
        .unwrap();
    for enabled in [false, true, false] {
        let egress = NativeCoreEgressConfig {
            ipv6_enabled: enabled,
            ..Default::default()
        };
        core.apply_profile_and_egress(&profile, egress.clone());
        let reply = core
            .resolve_dns_query_payload(&crate::dns::wire::encode(&query).unwrap(), None, None)
            .await
            .unwrap();
        let reply = crate::dns::wire::decode(&reply).unwrap();
        assert_eq!(reply.answers().len(), usize::from(enabled));
        let projected =
            crate::DnsEngine::compile(&profile, egress).evaluate(&crate::DnsQueryInput {
                query_class: 1,
                domain: "ipv6-policy.example".into(),
                record_type: crate::DnsRecordType::Aaaa,
                process_name: None,
                process_path: None,
            });
        assert_eq!(
            projected.action,
            if enabled {
                crate::DnsDecisionAction::FakeIp
            } else {
                crate::DnsDecisionAction::Empty
            }
        );
    }
    core.close();
}

/// The egress socket guard is device-durable, so a profile hot-apply
/// recompiles the snapshot with the guard still attached instead of
/// publishing an unguarded egress runtime.
#[test]
fn apply_profile_keeps_device_socket_guard() {
    #[derive(Debug)]
    struct NoopGuard;
    impl crate::egress::EgressSocketGuard for NoopGuard {
        fn protect_socket(
            &self,
            _descriptor: crate::egress::EgressSocketDescriptor,
            _context: crate::egress::EgressSocketContext,
        ) -> Result<crate::egress::EgressBinding, String> {
            Ok(crate::egress::EgressBinding::unbound())
        }
    }

    let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
        profile: direct_profile(),
        egress: NativeCoreEgressConfig::default(),
        egress_socket_guard: Some(Arc::new(NoopGuard)),
        capture: NativeCoreCaptureConfig::default(),
        flow_scanner: None,
        fake_ip_mappings: None,
    });
    assert!(core.pinned_runtime().egress().socket_guard().is_some());

    core.apply_profile(&reject_all_profile());

    assert!(
        core.pinned_runtime().egress().socket_guard().is_some(),
        "hot-applied snapshot must re-attach the device socket guard"
    );
}

/// Churn drain: a burst of concurrent TCP relays plus UDP
/// flows must leave zero live registry entries when they finish — the
/// guard-drop model makes "task ended" and "ledger entry gone" the same
/// event — and closing the device must drain every remaining table.
/// (This is the in-tree, per-commit stand-in for the long `soak_churn`
/// example run described in `bench/README.md`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_churn_drains_registry_and_tables() {
    // A hundred concurrent sessions hold some 400 descriptors, past the 256
    // macOS gives a process; raise the limit as every host does.
    fd_limit::raise_fd_soft_limit();
    let (echo_addr, echo_server) = spawn_echo_server().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let payload = b"churn-payload";

    for _round in 0..2 {
        let mut sessions = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let core = core.clone();
            sessions.spawn(async move {
                let (mut app_stream, flow_stream) = loopback_stream_pair().await;
                let flow_task = tokio::spawn(async move {
                    core.route_tcp_flow(
                        flow_stream,
                        NativeTcpFlowTarget {
                            host: echo_addr.ip().to_string(),
                            port: echo_addr.port(),
                            process_name: None,
                            process_path: None,
                        },
                    )
                    .await
                });
                app_stream.write_all(payload).await.expect("write payload");
                app_stream.shutdown().await.expect("shutdown app write");
                let mut received = Vec::new();
                app_stream
                    .read_to_end(&mut received)
                    .await
                    .expect("read echoed payload");
                assert_eq!(received, payload);
                flow_task
                    .await
                    .expect("flow task joins")
                    .expect("flow relays");
            });
        }
        while let Some(session) = sessions.join_next().await {
            session.expect("churn session completes");
        }
    }

    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP echo");
    let udp_addr = target_socket.local_addr().expect("udp addr");
    let udp_echo = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        for _ in 0..20 {
            let Ok((read, peer)) = target_socket.recv_from(&mut buffer).await else {
                return;
            };
            let _ = target_socket.send_to(&buffer[..read], peer).await;
        }
    });
    for flow in 0..20 {
        let report = core
            .send_udp_flow_datagram(NativeUdpFlowDatagram {
                flow_id: Some(format!("churn-udp-{flow}")),
                source: SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000 + flow as u16)),
                target: NativeUdpFlowTarget {
                    host: udp_addr.ip().to_string(),
                    port: udp_addr.port(),
                    process_name: None,
                    process_path: None,
                },
                payload: b"churn-udp".to_vec(),
            })
            .await
            .expect("UDP churn datagram sends");
        assert!(report.enqueued);
    }

    let audit = core.state_audit();
    assert_eq!(
        audit.tcp_relay_sessions.active, 0,
        "all TCP relay guards deregistered after churn"
    );
    assert_eq!(audit.tcp_relay_sessions.accepted_total, 200);
    assert_eq!(audit.tcp_relay_sessions.rejected_total, 0);
    assert_eq!(
        audit.udp_sessions, 20,
        "UDP sessions linger only until idle sweep by design"
    );
    assert_eq!(audit.packet_tcp_sessions, 0);

    core.close();
    let drained = core.state_audit();
    assert_eq!(drained.tcp_relay_sessions.active, 0);
    assert_eq!(drained.udp_sessions, 0, "close drains the UDP table");
    assert_eq!(drained.udp_session_sockets, 0);
    assert_eq!(drained.packet_tcp_sessions, 0);
    echo_server.abort();
    udp_echo.abort();
}

/// Kill-switch correctness: with two live tunnels through two
/// different proxy nodes, killing one outbound must terminate exactly
/// its session — the other keeps relaying bytes afterwards. The two
/// tunnels are split by destination-port rules so the kill switch is
/// exercised independently from full connection cutover.
#[tokio::test]
async fn kill_switch_terminates_only_sessions_on_the_killed_outbound() {
    let (target_a, echo_a) = spawn_echo_server().await;
    let (target_b, echo_b) = spawn_echo_server().await;

    let proxy_a_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind proxy A");
    let proxy_a_addr = proxy_a_listener.local_addr().expect("proxy A addr");
    let (connect_a_tx, _connect_a_rx) = oneshot::channel();
    let proxy_a =
        tokio::spawn(
            async move { serve_one_http_connect_proxy(proxy_a_listener, connect_a_tx).await },
        );
    let proxy_b_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind proxy B");
    let proxy_b_addr = proxy_b_listener.local_addr().expect("proxy B addr");
    let (connect_b_tx, _connect_b_rx) = oneshot::channel();
    let proxy_b =
        tokio::spawn(
            async move { serve_one_http_connect_proxy(proxy_b_listener, connect_b_tx).await },
        );

    let core = NativeCoreDevice::compile(&dst_port_split_profile(
        proxy_a_addr,
        proxy_b_addr,
        target_a.port(),
        target_b.port(),
    ));

    // Session 1 through ProxyA (target A's port rule).
    let (mut app_a, flow_a) = loopback_stream_pair().await;
    let core_a = core.clone();
    let flow_a_task = tokio::spawn(async move {
        core_a
            .route_tcp_flow(
                flow_a,
                NativeTcpFlowTarget {
                    host: target_a.ip().to_string(),
                    port: target_a.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app_a.write_all(b"ping-a").await.expect("write via A");
    let mut pong = [0_u8; 6];
    app_a.read_exact(&mut pong).await.expect("echo via A");
    assert_eq!(&pong, b"ping-a");

    // Session 2 through ProxyB (target B's port rule).
    let (mut app_b, flow_b) = loopback_stream_pair().await;
    let core_b = core.clone();
    let flow_b_task = tokio::spawn(async move {
        core_b
            .route_tcp_flow(
                flow_b,
                NativeTcpFlowTarget {
                    host: target_b.ip().to_string(),
                    port: target_b.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app_b.write_all(b"ping-b").await.expect("write via B");
    app_b.read_exact(&mut pong).await.expect("echo via B");
    assert_eq!(&pong, b"ping-b");

    let sessions = core.inner.sessions.registry.snapshot();
    assert_eq!(sessions.len(), 2);
    assert!(sessions
        .iter()
        .all(|session| session.phase == crate::session_registry::SessionPhase::Established));
    let outbounds: Vec<Option<&str>> = sessions
        .iter()
        .map(|session| session.outbound.as_deref())
        .collect();
    assert!(outbounds.contains(&Some("ProxyA")));
    assert!(outbounds.contains(&Some("ProxyB")));

    // Kill everything on ProxyA: exactly one session dies, promptly.
    let report = core.kill_sessions_by_outbound("ProxyA");
    assert_eq!(report.tcp_relay_sessions, 1);
    assert_eq!(report.udp_sessions, 0);
    let killed = timeout(Duration::from_secs(2), flow_a_task)
        .await
        .expect("killed relay ends promptly")
        .expect("flow task joins")
        .expect_err("killed relay reports cancellation");
    assert!(
        matches!(killed.cause, crate::TcpFlowFailure::Cancelled),
        "{killed}"
    );
    assert!(killed.is_expected_close());
    let finished = core.finished_connections_snapshot();
    let cancelled = finished
        .iter()
        .find(|row| &*row.outbound == "ProxyA")
        .unwrap();
    assert_eq!(cancelled.state, TrafficConnectionState::Cancelled);
    assert_eq!(
        cancelled.termination,
        Some(crate::ConnectionTermination::Cancelled)
    );

    // The survivor keeps relaying bytes after the kill.
    app_b.write_all(b"ping-2").await.expect("write after kill");
    app_b.read_exact(&mut pong).await.expect("echo after kill");
    assert_eq!(&pong, b"ping-2");
    let audit = core.state_audit();
    assert_eq!(audit.tcp_relay_sessions.active, 1);
    assert_eq!(audit.tcp_relay_sessions.killed_total, 1);
    let connections = core.connections_snapshot();
    assert_eq!(connections.len(), 1);
    assert_eq!(&*connections[0].outbound, "ProxyB");

    drop(app_b);
    let _ = timeout(Duration::from_secs(2), flow_b_task)
        .await
        .expect("survivor drains after client close");
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 0);
    echo_a.abort();
    echo_b.abort();
    proxy_a.abort();
    proxy_b.abort();
}

/// Switching a Select group ends the sessions it re-routes and leaves the
/// rest running: a connection a rule sends DIRECT goes on moving bytes
/// across the switch, which is what a remote desktop or an SSH session over
/// the tunnel needs. A later new connection uses the newly selected node.
#[tokio::test]
async fn selector_switch_ends_the_sessions_it_reroutes_and_keeps_the_rest() {
    let (proxied_target, proxied_echo) = spawn_echo_server().await;
    let (direct_target, direct_echo) = spawn_echo_server().await;

    let proxy_a_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind proxy A");
    let proxy_a_addr = proxy_a_listener.local_addr().expect("proxy A addr");
    let (connect_a_tx, _connect_a_rx) = oneshot::channel();
    let proxy_a =
        tokio::spawn(
            async move { serve_one_http_connect_proxy(proxy_a_listener, connect_a_tx).await },
        );
    let proxy_b_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind proxy B");
    let proxy_b_addr = proxy_b_listener.local_addr().expect("proxy B addr");
    let (connect_b_tx, _connect_b_rx) = oneshot::channel();
    let proxy_b =
        tokio::spawn(
            async move { serve_one_http_connect_proxy(proxy_b_listener, connect_b_tx).await },
        );

    let mut profile = RuntimeProfile::new("select-with-direct-escape");
    profile.proxies = two_http_proxies(proxy_a_addr, proxy_b_addr);
    profile.groups = vec![policy_group(
        "Choice",
        PolicyGroupKind::Select,
        &["ProxyA", "ProxyB"],
    )];
    profile.rules = vec![
        dst_port_rule(&direct_target.port().to_string(), "DIRECT"),
        match_rule("Choice"),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);

    // Session through the group's current pick (ProxyA, first member).
    let (mut app_p, flow_p) = loopback_stream_pair().await;
    let core_p = core.clone();
    let flow_p_task = tokio::spawn(async move {
        core_p
            .route_tcp_flow(
                flow_p,
                NativeTcpFlowTarget {
                    host: proxied_target.ip().to_string(),
                    port: proxied_target.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    let mut pong = [0_u8; 6];
    app_p.write_all(b"ping-p").await.expect("write proxied");
    app_p.read_exact(&mut pong).await.expect("echo proxied");
    assert_eq!(&pong, b"ping-p");

    // Session outside the group (port rule → DIRECT).
    let (mut app_d, flow_d) = loopback_stream_pair().await;
    let core_d = core.clone();
    let flow_d_task = tokio::spawn(async move {
        core_d
            .route_tcp_flow(
                flow_d,
                NativeTcpFlowTarget {
                    host: direct_target.ip().to_string(),
                    port: direct_target.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app_d.write_all(b"ping-d").await.expect("write direct");
    app_d.read_exact(&mut pong).await.expect("echo direct");
    assert_eq!(&pong, b"ping-d");

    // The selection moves the group's sessions and nothing else.
    core.select_group_member("Choice", "ProxyB")
        .expect("select ProxyB");

    let killed = timeout(Duration::from_secs(2), flow_p_task)
        .await
        .expect("re-routed session ends promptly")
        .expect("flow task joins")
        .expect_err("re-routed session reports cancellation");
    assert!(
        matches!(killed.cause, crate::TcpFlowFailure::Cancelled),
        "{killed}"
    );
    assert!(killed.is_expected_close());

    app_d.write_all(b"ping-2").await.expect("write direct");
    app_d
        .read_exact(&mut pong)
        .await
        .expect("the DIRECT session still moves bytes after the switch");
    assert_eq!(&pong, b"ping-2");
    assert!(!flow_d_task.is_finished(), "its route did not change");
    let audit = core.state_audit();
    assert_eq!(audit.tcp_relay_sessions.killed_total, 1);
    assert_eq!(audit.tcp_relay_sessions.active, 1);

    // The app's reconnect resolves through the newly selected node.
    let (mut app_r, flow_r) = loopback_stream_pair().await;
    let core_r = core.clone();
    let flow_r_task = tokio::spawn(async move {
        core_r
            .route_tcp_flow(
                flow_r,
                NativeTcpFlowTarget {
                    host: proxied_target.ip().to_string(),
                    port: proxied_target.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app_r.write_all(b"ping-r").await.expect("write reconnect");
    app_r.read_exact(&mut pong).await.expect("echo reconnect");
    assert_eq!(&pong, b"ping-r");
    let outbounds: Vec<Arc<str>> = core
        .connections_snapshot()
        .into_iter()
        .map(|connection| connection.outbound)
        .collect();
    assert!(outbounds.contains(&"ProxyB".into()), "{outbounds:?}");
    assert!(!outbounds.contains(&"ProxyA".into()), "{outbounds:?}");

    drop(app_d);
    let _ = timeout(Duration::from_secs(2), flow_d_task).await;
    drop(app_r);
    let _ = timeout(Duration::from_secs(2), flow_r_task)
        .await
        .expect("reconnected session drains after client close");
    proxied_echo.abort();
    direct_echo.abort();
    proxy_a.abort();
    proxy_b.abort();
}

/// A captured flow the selection does not re-route keeps running on the
/// engine it was accepted by: the engine is not replaced, the flow is not
/// reset, and its bytes keep going both ways. This is the TUN side of what a
/// node switch must not disturb.
#[tokio::test]
async fn a_captured_flow_the_selection_keeps_runs_on_the_same_engine() {
    let (echo_target, echo) = spawn_echo_server().await;
    let mut profile = RuntimeProfile::new("captured-across-selection");
    profile.proxies = vec![direct_node("NodeA"), direct_node("NodeB")];
    profile.groups = vec![policy_group(
        "Choice",
        PolicyGroupKind::Select,
        &["NodeA", "NodeB"],
    )];
    profile.rules = vec![
        dst_port_rule(&echo_target.port().to_string(), "DIRECT"),
        match_rule("Choice"),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: Ipv4Addr::LOCALHOST,
        server_port: echo_target.port(),
        client_port: 54320,
    };
    let (server_isn, _) = client.handshake(1000).await;
    client
        .execute("data", 1001, server_isn + 1, 0x18, b"ping-c")
        .await;
    client
        .drain_until(|packet| packet.ends_with(b"ping-c"))
        .await;
    client
        .execute("ack-echo", 1007, server_isn + 7, 0x10, &[])
        .await;
    let engine = core.packet_tcp_engine().expect("the queue has an engine");

    core.select_group_member("Choice", "NodeB")
        .expect("select NodeB");

    assert!(
        Arc::ptr_eq(
            &engine,
            &core.packet_tcp_engine().expect("the engine is still there")
        ),
        "a selection does not replace the engine"
    );
    assert_eq!(
        core.state_audit().packet_tcp_sessions,
        1,
        "and does not end the flow its rule routes DIRECT"
    );

    client
        .execute("data-2", 1007, server_isn + 7, 0x18, b"ping-d")
        .await;
    client
        .drain_until(|packet| packet.ends_with(b"ping-d"))
        .await;
    core.close();
    echo.abort();
}

/// A session a switch keeps belongs to the epoch the switch opened, not the
/// one it left: the completion ticket of the epoch left behind reports done
/// while that session still runs. Otherwise every switch would tell the host
/// its connections are still draining, and the retired-epoch budget would be
/// spent on sessions that may last hours.
#[tokio::test]
async fn a_session_a_switch_keeps_leaves_the_epoch_it_left_complete() {
    let (direct_target, direct_echo) = spawn_echo_server().await;
    let mut profile = RuntimeProfile::new("keep-direct-across-switch");
    profile.groups = vec![policy_group(
        "Choice",
        PolicyGroupKind::Select,
        &["DIRECT", "REJECT"],
    )];
    profile.rules = vec![
        dst_port_rule(&direct_target.port().to_string(), "DIRECT"),
        match_rule("Choice"),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);

    let (mut app, flow) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let flow_task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow(
                flow,
                NativeTcpFlowTarget {
                    host: direct_target.ip().to_string(),
                    port: direct_target.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    let mut pong = [0_u8; 6];
    app.write_all(b"ping-k").await.expect("write direct");
    app.read_exact(&mut pong).await.expect("echo direct");

    let prepared = core
        .prepare_policy_update(&[crate::CorePolicyUpdate::SelectGroup {
            group: "Choice".into(),
            member: "REJECT".into(),
        }])
        .expect("prepare the selection");
    let report = core.apply_policy_update(prepared).expect("apply it");
    assert!(report.changed);
    assert!(
        report.retirement.wait(Duration::from_secs(2)).await,
        "the epoch left behind completes with the kept session still running"
    );

    app.write_all(b"ping-2").await.expect("write direct again");
    app.read_exact(&mut pong)
        .await
        .expect("the kept session moves bytes after the switch");
    assert_eq!(&pong, b"ping-2");

    drop(app);
    let _ = timeout(Duration::from_secs(2), flow_task).await;
    direct_echo.abort();
}

/// Every configuration publication cuts off old connections, even when their
/// concrete outbound would remain unchanged.
#[tokio::test]
async fn apply_profile_cuts_off_both_changed_and_unchanged_tcp_routes() {
    let (target_a, echo_a) = spawn_echo_server().await;
    let (target_b, echo_b) = spawn_echo_server().await;
    let core = NativeCoreDevice::compile(&direct_profile());

    let spawn_flow = |target: SocketAddr| {
        let core = core.clone();
        async move {
            let (app, flow) = loopback_stream_pair().await;
            let task = tokio::spawn(async move {
                core.route_tcp_flow(
                    flow,
                    NativeTcpFlowTarget {
                        host: target.ip().to_string(),
                        port: target.port(),
                        process_name: None,
                        process_path: None,
                    },
                )
                .await
            });
            (app, task)
        }
    };
    let (mut app_a, flow_a_task) = spawn_flow(target_a).await;
    let (mut app_b, flow_b_task) = spawn_flow(target_b).await;
    let mut pong = [0_u8; 6];
    app_a.write_all(b"ping-a").await.expect("write via A");
    app_a.read_exact(&mut pong).await.expect("echo via A");
    app_b.write_all(b"ping-b").await.expect("write via B");
    app_b.read_exact(&mut pong).await.expect("echo via B");

    // The new profile rejects target A's port; target B stays DIRECT.
    let mut rejecting = RuntimeProfile::new("reject-port-a");
    rejecting.rules = vec![
        dst_port_rule(&target_a.port().to_string(), "REJECT"),
        match_rule("DIRECT"),
    ]
    .into();
    core.apply_profile(&rejecting);

    let killed = timeout(Duration::from_secs(2), flow_a_task)
        .await
        .expect("rejected session ends promptly")
        .expect("flow task joins")
        .expect_err("rejected session reports cancellation");
    assert!(
        matches!(killed.cause, crate::TcpFlowFailure::Cancelled),
        "{killed}"
    );
    assert!(killed.is_expected_close());
    timeout(Duration::from_secs(2), flow_b_task)
        .await
        .expect("unchanged route also closes")
        .expect("flow joins")
        .expect_err("all old connections are cancelled");
    assert_eq!(core.state_audit().tcp_relay_sessions.killed_total, 2);
    assert_eq!(app_b.read(&mut pong).await.expect("read closed flow"), 0);
    echo_a.abort();
    echo_b.abort();
}

/// Kill switch, UDP: killing an outbound tears down its UDP
/// session sockets; the flow's next datagram re-resolves and rebuilds.
#[tokio::test]
async fn kill_by_outbound_closes_udp_sessions_and_flow_rebuilds() {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        for _ in 0..2 {
            let Ok((read, peer)) = target_socket.recv_from(&mut buffer).await else {
                return;
            };
            let _ = target_socket.send_to(&buffer[..read], peer).await;
        }
    });
    let core = NativeCoreDevice::compile(&two_direct_nodes_fallback_profile());
    let datagram = |payload: &[u8]| NativeUdpFlowDatagram {
        flow_id: Some("kill-udp".into()),
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53300)),
        target: NativeUdpFlowTarget {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            process_name: None,
            process_path: None,
        },
        payload: payload.to_vec(),
    };

    let (first, first_response) = send_udp_and_drain(&core, datagram(b"before-kill")).await;
    assert!(first.enqueued);
    assert_eq!(first_response.payload, b"before-kill");
    assert_eq!(core.state_audit().udp_session_sockets, 1);

    let report = core.kill_sessions_by_outbound("NodeA");

    assert_eq!(report.udp_sessions, 1);
    assert_eq!(report.tcp_relay_sessions, 0);
    let audit = core.state_audit();
    assert_eq!(audit.udp_sessions, 0);
    assert_eq!(audit.udp_session_sockets, 0);

    // Kill is not ejection: the flow re-resolves (still NodeA) and
    // rebuilds a fresh session socket.
    let (_outcome, response) = send_udp_and_drain(&core, datagram(b"after-kill")).await;
    assert_eq!(response.payload, b"after-kill");
    assert_eq!(core.state_audit().udp_session_sockets, 1);
    echo_task.await.expect("echo join");
}

/// Cancellation tree: closing the device cancels the registry
/// root, which reaches every live relay leaf — no lingering tasks.
#[tokio::test]
async fn device_close_cancels_active_flow_relays() {
    let (echo_addr, echo_server) = spawn_echo_server().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let (mut app_stream, flow_stream) = loopback_stream_pair().await;
    let core_flow = core.clone();
    let flow_task = tokio::spawn(async move {
        core_flow
            .route_tcp_flow(
                flow_stream,
                NativeTcpFlowTarget {
                    host: echo_addr.ip().to_string(),
                    port: echo_addr.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app_stream.write_all(b"warmup").await.expect("write warmup");
    let mut echoed = [0_u8; 6];
    app_stream.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 1);

    core.close();

    let cancelled = timeout(Duration::from_secs(2), flow_task)
        .await
        .expect("relay unwinds promptly on close")
        .expect("flow task joins")
        .expect_err("closed device cancels the relay");
    assert!(
        matches!(cancelled.cause, crate::TcpFlowFailure::Cancelled),
        "{cancelled}"
    );
    assert!(cancelled.is_expected_close());
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 0);
    echo_server.abort();
}

/// Admission: with the registry at its global cap, a new
/// SOCKS5 session is refused fail-fast with a proper reply and a
/// rejection counter, and the ledger does not grow.
#[tokio::test]
async fn admission_cap_refuses_new_sessions_fail_fast() {
    use crate::session_registry::MAX_ACTIVE_SESSIONS;

    let core = NativeCoreDevice::compile(&direct_profile());
    let runtime = core.pinned_runtime();
    let mut fillers = Vec::with_capacity(MAX_ACTIVE_SESSIONS);
    for index in 0..MAX_ACTIVE_SESSIONS {
        fillers.push(
            runtime
                .session_registry()
                .register("test-fill", None, format!("fill-{index}:1"))
                .expect("filler admitted"),
        );
    }

    let (mut app_stream, server_stream) = loopback_stream_pair().await;
    let handler_runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server_stream, &handler_runtime).await
    });
    app_stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send greeting");
    let mut method = [0_u8; 2];
    app_stream.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x00]);
    app_stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .await
        .expect("send CONNECT");
    let mut reply = [0_u8; 10];
    app_stream.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0x05, "SOCKS5 'connection refused' on admission");

    let refused = handler
        .await
        .expect("handler joins")
        .expect_err("admission refuses the session");
    assert!(refused.contains("session limit"), "{refused}");
    let counters = core.inner.sessions.registry.counters();
    assert_eq!(counters.rejected_total, 1);
    assert_eq!(counters.active as usize, MAX_ACTIVE_SESSIONS);
    drop(fillers);
    assert_eq!(core.inner.sessions.registry.counters().active, 0);
}

/// Watchdog: a blocked executor shows up as a scheduling
/// stall with the measured delay; a healthy loop records none.
#[tokio::test]
async fn watchdog_counts_scheduling_stalls() {
    let core = NativeCoreDevice::compile(&direct_profile());
    let handle =
        core.spawn_event_loop_watchdog_with(Duration::from_millis(10), Duration::from_millis(150));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let calm = core.watchdog_stats();
    assert!(calm.ticks >= 3, "heartbeat ticks, got {calm:?}");
    assert_eq!(calm.stalls, 0, "healthy loop has no stalls: {calm:?}");

    // Block the (current-thread) executor: the watchdog's next wake is
    // late by roughly the blocked time.
    std::thread::sleep(Duration::from_millis(400));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stalled = core.watchdog_stats();
    assert!(
        stalled.stalls >= 1,
        "blocked executor detected: {stalled:?}"
    );
    assert!(
        stalled.max_scheduling_delay_micros >= 150_000,
        "delay magnitude recorded: {stalled:?}"
    );

    core.close();
    timeout(Duration::from_secs(2), handle)
        .await
        .expect("watchdog exits after close")
        .expect("watchdog joins");
}

/// Sniff short-circuit: with no reachable domain rule the sniff
/// stage never arms — structurally, `attempted` stays zero — so a
/// server-speaks-first flow on a sniffable port gets its first byte
/// with zero added wait even though the client never sends a byte.
#[tokio::test]
async fn sniff_short_circuits_without_domain_rules_for_server_first_flow() {
    let banner = b"server-first-banner";
    let (proxy_addr, authority_rx, _captured_rx, proxy_task) =
        spawn_sink_proxy(Some(banner.to_vec()), 0).await;
    let core = NativeCoreDevice::compile(&sniff_cidr_only_profile(proxy_addr));

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    socks5_connect_ipv4(&mut app, [203, 0, 113, 5], 443).await;

    let mut received = vec![0_u8; banner.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut received))
        .await
        .expect("server-first byte arrives without a sniff wait")
        .expect("banner read");
    assert_eq!(received, banner);
    assert_eq!(
        core.state_audit().sniff.attempted,
        0,
        "no domain rule can use a sniffed host, so the stage must never arm"
    );
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "203.0.113.5:443"
    );

    drop(app);
    let routed = timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("session relays");
    assert_eq!(routed, "SinkProxy");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

/// Sniff hit: a bare-IP CONNECT whose first flight is a TLS
/// ClientHello routes by the SNI — the DOMAIN-SUFFIX rule wins over the
/// MATCH→REJECT fallback — while the dial keeps the original IP and the
/// consumed bytes reach the outbound intact and in order.
#[tokio::test]
async fn sniffed_sni_routes_bare_ip_connect_to_domain_rule_outbound() {
    let hello = crate::sniff::build_tls_client_hello(Some("target.sni.example"));
    let (proxy_addr, authority_rx, captured_rx, proxy_task) =
        spawn_sink_proxy(None, hello.len()).await;
    let core = NativeCoreDevice::compile(&sniff_domain_profile(proxy_addr));

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    socks5_connect_ipv4(&mut app, [203, 0, 113, 7], 443).await;
    app.write_all(&hello).await.expect("send first flight");

    let mut echoed = vec![0_u8; hello.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("echo read");
    assert_eq!(echoed, hello, "early data echoes back byte-exact");
    assert_eq!(
        timeout(Duration::from_secs(3), captured_rx)
            .await
            .expect("tunnel bytes captured")
            .expect("captured"),
        hello,
        "the sniffed prefix reaches the outbound intact"
    );
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "203.0.113.7:443",
        "sniff refines routing but the dial keeps the client's IP"
    );
    let connections = core.connections_snapshot();
    assert_eq!(connections.len(), 1);
    assert_eq!(
        connections[0].host.as_deref(),
        Some("target.sni.example"),
        "the ledger records the sniffed host"
    );
    assert_eq!(&*connections[0].outbound, "SinkProxy");
    let counters = core.state_audit().sniff;
    assert_eq!(counters.attempted, 1);
    assert_eq!(counters.hits, 1);
    assert_eq!(counters.misses, 0);

    drop(app);
    let routed = timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("session relays");
    assert_eq!(routed, "SinkProxy");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

/// Sniff budget: a silent client on a sniffable port pays exactly
/// the first-data budget, then the session degrades to IP routing — it
/// is never failed by the sniff.
#[tokio::test]
async fn sniff_timeout_degrades_to_ip_routing_within_budget() {
    let (unused_proxy, _guard) = refused_local_addr();
    let core = NativeCoreDevice::compile(&sniff_domain_profile(unused_proxy));

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    let started = std::time::Instant::now();
    socks5_connect_ipv4(&mut app, [203, 0, 113, 9], 443).await;

    // The client never speaks; with no domain the MATCH→REJECT fallback
    // applies and the inbound closes the tunnel.
    let mut buffer = [0_u8; 1];
    let read = timeout(Duration::from_secs(5), app.read(&mut buffer))
        .await
        .expect("session ends within bounds")
        .expect("read EOF");
    let elapsed = started.elapsed();
    assert_eq!(read, 0, "rejected session closes cleanly");
    assert!(
        elapsed >= crate::sniff::SNIFF_FIRST_DATA_TIMEOUT,
        "the sniff waited out its budget, elapsed {elapsed:?}"
    );
    let routed = timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("handler completes");
    assert_eq!(routed, "REJECT");
    let counters = core.state_audit().sniff;
    assert_eq!(counters.attempted, 1);
    assert_eq!(counters.misses, 1);
}

/// Sniff port gate: domain rules exist, but a target port that is
/// not a first-flight port skips the stage — server-first protocols on
/// bare IPs never wait.
#[tokio::test]
async fn sniff_skips_non_first_flight_ports() {
    let banner = b"port-2222-banner";
    let (proxy_addr, _authority_rx, _captured_rx, proxy_task) =
        spawn_sink_proxy(Some(banner.to_vec()), 0).await;
    let core = NativeCoreDevice::compile(&sniff_domain_or_cidr_profile(proxy_addr));

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    socks5_connect_ipv4(&mut app, [203, 0, 113, 5], 2222).await;

    let mut received = vec![0_u8; banner.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut received))
        .await
        .expect("server-first byte arrives without a sniff wait")
        .expect("banner read");
    assert_eq!(received, banner);
    assert_eq!(core.state_audit().sniff.attempted, 0);

    drop(app);
    timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("session relays");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

/// Conclusive sniff miss: an unrecognized first flight ends the
/// sniff immediately, routing degrades to the IP rule, and the consumed
/// bytes are still forwarded — nothing is lost or reordered.
#[tokio::test]
async fn sniff_miss_forwards_consumed_bytes_and_routes_by_ip() {
    let garbage = vec![0x8f_u8; 64];
    let (proxy_addr, authority_rx, captured_rx, proxy_task) =
        spawn_sink_proxy(None, garbage.len()).await;
    let core = NativeCoreDevice::compile(&sniff_domain_or_cidr_profile(proxy_addr));

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    socks5_connect_ipv4(&mut app, [203, 0, 113, 5], 443).await;
    app.write_all(&garbage).await.expect("send garbage");

    let mut echoed = vec![0_u8; garbage.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("echo read");
    assert_eq!(echoed, garbage);
    assert_eq!(
        timeout(Duration::from_secs(3), captured_rx)
            .await
            .expect("tunnel bytes captured")
            .expect("captured"),
        garbage
    );
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "203.0.113.5:443"
    );
    let counters = core.state_audit().sniff;
    assert_eq!(counters.attempted, 1);
    assert_eq!(counters.misses, 1);

    drop(app);
    timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("session relays");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

/// Enrichment order: a fake-IP hit is the cheaper link and wins —
/// no sniff runs, and unlike a sniffed real IP the unroutable fake IP is
/// restored to its domain for routing and dialing; the proxy is handed the
/// domain, not an address the configured DNS gives for it.
#[tokio::test]
async fn fake_ip_reverse_preempts_sniff_and_rewrites_dial_target() {
    let payload = b"fake-ip-tunnel-payload";
    let (proxy_addr, authority_rx, _captured_rx, proxy_task) =
        spawn_sink_proxy(None, payload.len()).await;
    let mut profile = sniff_domain_profile(proxy_addr);
    let _dns = configure_local_dns(&mut profile).await;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    let core = NativeCoreDevice::compile(&profile);
    let fake_ip = core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4("portal.sni.example")
        .expect("fake IP allocates");

    let (mut app, server) = loopback_stream_pair().await;
    let runtime = core.pinned_runtime();
    let handler = tokio::spawn(async move {
        crate::inbound::dispatch::handle_connect_client(server, &runtime).await
    });
    socks5_connect_ipv4(&mut app, fake_ip.octets(), 443).await;
    app.write_all(payload).await.expect("send payload");

    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("echo read");
    assert_eq!(echoed, payload);
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "portal.sni.example:443",
        "the fake IP is restored to its domain before entering the outbound protocol"
    );
    assert_eq!(
        core.state_audit().sniff.attempted,
        0,
        "the fake-IP reverse hit preempts the sniff"
    );

    drop(app);
    let routed = timeout(Duration::from_secs(3), handler)
        .await
        .expect("handler ends")
        .expect("handler joins")
        .expect("session relays");
    assert_eq!(routed, "SinkProxy");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

#[tokio::test]
async fn unmapped_fake_ip_recovers_http_and_tls_dial_targets_in_rule_and_global_modes() {
    let flights = [
        (
            80,
            b"GET / HTTP/1.1\r\nHost: recovered.sni.example\r\n\r\n".to_vec(),
        ),
        (
            443,
            crate::sniff::build_tls_client_hello(Some("recovered.sni.example")),
        ),
    ];
    for mode in [TrafficPolicyMode::Rule, TrafficPolicyMode::Global] {
        for (port, payload) in &flights {
            for fake_ip in ["198.18.9.9", "fd11:5ca1:ab1e:1::c612:909"] {
                let (proxy_addr, authority_rx, captured_rx, proxy_task) =
                    spawn_sink_proxy(None, payload.len()).await;
                let mut profile = sniff_domain_profile(proxy_addr);
                profile.traffic_policy_mode = mode;
                profile.global_outbound = Some("SinkProxy".into());
                let _dns = configure_local_dns(&mut profile).await;
                profile.dns.enabled = true;
                profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
                let core = NativeCoreDevice::compile(&profile);
                assert!(core
                    .pinned_runtime()
                    .is_stale_fake_target(fake_ip.parse().unwrap()));

                let (mut app, server) = loopback_stream_pair().await;
                let handler = tokio::spawn(core.route_tcp_flow(
                    server,
                    NativeTcpFlowTarget {
                        host: fake_ip.into(),
                        port: *port,
                        process_name: None,
                        process_path: None,
                    },
                ));
                app.write_all(payload).await.expect("send first flight");
                let mut echoed = vec![0; payload.len()];
                timeout(Duration::from_secs(3), app.read_exact(&mut echoed))
                    .await
                    .expect("recovered flow responds")
                    .expect("read echo");
                assert_eq!(&echoed, payload);
                assert_eq!(
                    captured_rx.await.expect("proxy receives first flight"),
                    *payload
                );
                assert_eq!(
                    authority_rx.await.expect("proxy receives CONNECT"),
                    format!("recovered.sni.example:{port}"),
                    "the outbound receives the recovered domain, never the fake IP"
                );
                let connection = core.connections_snapshot().pop().expect("live connection");
                assert_eq!(connection.host.as_deref(), Some("recovered.sni.example"));
                assert_eq!(&*connection.outbound, "SinkProxy");
                assert_eq!(core.state_audit().sniff.hits, 1);

                drop(app);
                let outcome = timeout(Duration::from_secs(3), handler)
                    .await
                    .expect("flow ends")
                    .expect("flow joins")
                    .expect("flow relays");
                assert_eq!(outcome.outbound, "SinkProxy");
                assert_eq!(
                    outcome.matched_rule.as_deref(),
                    (mode == TrafficPolicyMode::Rule)
                        .then_some("DOMAIN-SUFFIX,sni.example,SinkProxy")
                );
                proxy_task.await.expect("proxy joins").expect("proxy ok");
                core.close();
            }
        }
    }
}

#[tokio::test]
async fn global_real_ip_preserves_dial_target_without_sniffing() {
    let banner = b"server-first-banner";
    let (proxy_addr, authority_rx, _captured_rx, proxy_task) =
        spawn_sink_proxy(Some(banner.to_vec()), 0).await;
    let mut profile = sniff_domain_profile(proxy_addr);
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("SinkProxy".into());
    let core = NativeCoreDevice::compile(&profile);
    let (mut app, server) = loopback_stream_pair().await;
    let handler = tokio::spawn(core.route_tcp_flow(
        server,
        NativeTcpFlowTarget {
            host: "203.0.113.7".into(),
            port: 443,
            process_name: None,
            process_path: None,
        },
    ));
    let mut received = vec![0; banner.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut received))
        .await
        .expect("server speaks without client data")
        .expect("read banner");
    assert_eq!(received, banner);
    assert_eq!(
        authority_rx.await.expect("proxy CONNECT"),
        "203.0.113.7:443"
    );
    assert_eq!(core.state_audit().sniff.attempted, 0);
    drop(app);
    timeout(Duration::from_secs(3), handler)
        .await
        .expect("flow ends")
        .expect("flow joins")
        .expect("flow relays");
    proxy_task.await.expect("proxy joins").expect("proxy ok");
    core.close();
}

#[tokio::test]
async fn unmapped_fake_ip_without_sniffable_domain_is_refused_before_dial() {
    let cases = [
        (443, crate::sniff::build_tls_client_hello(None), 1),
        (
            80,
            b"GET / HTTP/1.1\r\nHost: 198.18.9.9\r\n\r\n".to_vec(),
            1,
        ),
        (22, b"SSH-2.0-test\r\n".to_vec(), 0),
    ];
    for (port, payload, sniff_attempts) in cases {
        let proxy =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind unused proxy");
        proxy.set_nonblocking(true).expect("nonblocking proxy");
        let mut profile = sniff_domain_profile(proxy.local_addr().expect("proxy address"));
        profile.traffic_policy_mode = TrafficPolicyMode::Global;
        profile.global_outbound = Some("SinkProxy".into());
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        let core = NativeCoreDevice::compile(&profile);
        let (mut app, server) = loopback_stream_pair().await;
        let handler = tokio::spawn(core.route_tcp_flow(
            server,
            NativeTcpFlowTarget {
                host: "198.18.9.9".into(),
                port,
                process_name: None,
                process_path: None,
            },
        ));
        app.write_all(&payload).await.expect("send first flight");
        let error = timeout(Duration::from_secs(3), handler)
            .await
            .expect("flow ends")
            .expect("flow joins")
            .expect_err("fake target is refused");
        assert!(
            matches!(&error.cause, crate::TcpFlowFailure::Message(message) if message.contains("stale fake-IP")),
            "{error}"
        );
        assert_eq!(core.state_audit().sniff.attempted, sniff_attempts);
        assert_eq!(
            proxy.accept().expect_err("no outbound was dialed").kind(),
            std::io::ErrorKind::WouldBlock
        );
        core.close();
    }
}

/// Sniffing on the platform flow path: the injected-flow entrypoint sniffs the
/// app's first flight directly — no inbound protocol reply exists — and
/// its outcome reports the sniffed decision.
#[tokio::test]
async fn platform_flow_sniffs_first_flight_and_reports_domain_route() {
    let hello = crate::sniff::build_tls_client_hello(Some("flow.sni.example"));
    let (proxy_addr, authority_rx, captured_rx, proxy_task) =
        spawn_sink_proxy(None, hello.len()).await;
    let core = NativeCoreDevice::compile(&sniff_domain_profile(proxy_addr));

    let (mut app, flow_stream) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let flow_task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow_io(
                flow_stream,
                None,
                NativeTcpFlowTarget {
                    host: "203.0.113.7".into(),
                    port: 443,
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app.write_all(&hello).await.expect("send first flight");

    let mut echoed = vec![0_u8; hello.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("echo read");
    assert_eq!(echoed, hello);
    assert_eq!(
        timeout(Duration::from_secs(3), captured_rx)
            .await
            .expect("tunnel bytes captured")
            .expect("captured"),
        hello
    );
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "203.0.113.7:443"
    );

    drop(app);
    let outcome = timeout(Duration::from_secs(3), flow_task)
        .await
        .expect("flow ends")
        .expect("flow task joins")
        .expect("flow relays");
    assert_eq!(outcome.outbound, "SinkProxy");
    assert_eq!(
        outcome.matched_rule.as_deref(),
        Some("DOMAIN-SUFFIX,sni.example,SinkProxy"),
        "the outcome reports the sniffed domain decision"
    );
    let counters = core.state_audit().sniff;
    assert_eq!(counters.attempted, 1);
    assert_eq!(counters.hits, 1);
    proxy_task.await.expect("proxy joins").expect("proxy ok");
}

/// Passive ejection: with a Fallback group whose primary is
/// unreachable, passive dial evidence must eject the primary after
/// exactly `OUTBOUND_FALL_THRESHOLD` failed dials and the very next
/// connection must land on the backup — failover latency is bounded by
/// the fall threshold times one refused dial, no probe required.
#[tokio::test]
async fn fallback_group_fails_over_to_backup_within_fall_threshold_dials() {
    let scenario_started = std::time::Instant::now();
    // The primary accepts and instantly closes: the SOCKS5 handshake
    // fails in milliseconds, deterministically (a refused port would work
    // too, but Windows retries refused connects for seconds).
    let (dead_primary, dead_primary_task) = serve_reset_primary().await;

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo target");
    let target_addr = target_listener.local_addr().expect("target addr");

    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind backup proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

    let core = NativeCoreDevice::compile(&fallback_group_profile(dead_primary, proxy_addr));
    let flow_target = NativeTcpFlowTarget {
        host: target_addr.ip().to_string(),
        port: target_addr.port(),
        process_name: None,
        process_path: None,
    };

    for attempt in 0..OUTBOUND_FALL_THRESHOLD {
        let (_app_stream, flow_stream) = loopback_stream_pair().await;
        let result = core.route_tcp_flow(flow_stream, flow_target.clone()).await;
        assert!(
            result.is_err(),
            "attempt {attempt} must dial the dead primary and fail"
        );
    }
    let health = core
        .inner
        .sessions
        .group_state
        .health_snapshot("Primary")
        .expect("primary accumulated health evidence");
    assert!(
        health.ejected_until_unix > now_unix(),
        "fall threshold must eject the primary"
    );

    // Backends spawn after the failure phase so their accept timeouts
    // start counting only when the failover connection is due.
    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
    let (connect_tx, connect_rx) = oneshot::channel();
    let proxy_task =
        tokio::spawn(async move { serve_one_http_connect_proxy(proxy_listener, connect_tx).await });

    let payload = b"failover-payload";
    let (mut app_stream, flow_stream) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let flow_target_after = flow_target.clone();
    let flow_task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow(flow_stream, flow_target_after)
            .await
    });

    app_stream.write_all(payload).await.expect("write payload");
    app_stream.shutdown().await.expect("shutdown app write");
    let mut received = Vec::new();
    app_stream
        .read_to_end(&mut received)
        .await
        .expect("read echoed payload");

    assert_eq!(received, payload, "backup path relays end to end");
    let proxied_authority = timeout(Duration::from_secs(3), connect_rx)
        .await
        .expect("backup proxy observes CONNECT")
        .expect("proxy sends CONNECT authority");
    assert_eq!(
        proxied_authority,
        target_addr.to_string(),
        "the post-ejection connection went through the backup proxy"
    );
    let outcome = flow_task
        .await
        .expect("flow task joins")
        .expect("post-ejection flow succeeds");
    assert_eq!(outcome.outbound, "Auto", "decision reports the group");
    assert!(
        scenario_started.elapsed() < Duration::from_secs(5),
        "failover must complete promptly, took {:?}",
        scenario_started.elapsed()
    );
    echo_task.await.expect("echo join").expect("echo completes");
    proxy_task
        .await
        .expect("proxy join")
        .expect("proxy completes");
    dead_primary_task.abort();
}

/// UDP failover: the UDP session key excludes the outbound, so
/// when ejection re-resolves the group to another node the cached
/// session socket must be rebuilt for it, not reused.
#[tokio::test]
async fn udp_group_failover_rebuilds_session_socket_on_ejection() {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        for _ in 0..2 {
            let (read, peer) = target_socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            target_socket
                .send_to(&buffer[..read], peer)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<_, String>(())
    });
    let core = NativeCoreDevice::compile(&two_direct_nodes_fallback_profile());
    let datagram = |payload: &[u8]| NativeUdpFlowDatagram {
        flow_id: Some("udp-failover".into()),
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53200)),
        target: NativeUdpFlowTarget {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            process_name: None,
            process_path: None,
        },
        payload: payload.to_vec(),
    };

    let (_first, first_response) = send_udp_and_drain(&core, datagram(b"before-ejection")).await;
    assert_eq!(first_response.payload, b"before-ejection");
    let sessions = core.inner.sessions.udp_sessions.snapshot_for_test();
    assert_eq!(
        sessions.first().expect("session recorded").outbound,
        "NodeA",
        "session stats carry the concrete node"
    );

    core.inner
        .sessions
        .group_state
        .set_ejected_until_for_test("NodeA", now_unix() + 300);

    let (_second, second_response) = send_udp_and_drain(&core, datagram(b"after-ejection")).await;
    assert_eq!(second_response.payload, b"after-ejection");
    let sessions = core.inner.sessions.udp_sessions.snapshot_for_test();
    assert_eq!(sessions.len(), 1, "same flow keeps one session entry");
    assert_eq!(
        sessions.first().expect("session").outbound,
        "NodeB",
        "ejection re-resolved the group mid-flow"
    );
    assert_eq!(
        core.inner
            .sessions
            .udp_sessions
            .session_socket_count_for_test(),
        1,
        "the session socket was rebuilt, not duplicated"
    );
    echo_task.await.expect("echo join").expect("echo completes");
}

#[tokio::test]
async fn route_evaluation_resolves_nested_selection_and_preserves_the_matched_rule() {
    let mut profile = select_group_profile();
    profile.groups[0].selected = Some("NodeB".into());
    profile
        .groups
        .push(policy_group("Outer", PolicyGroupKind::Select, &["Choice"]));
    profile.rules = vec![RouteRule {
        kind: RuleKind::DomainSuffix,
        payload: Some("google.com"),
        outbound: "Outer",
        no_resolve: false,
    }]
    .into();
    let core = NativeCoreDevice::compile(&profile);
    let input = crate::RouteMatchInput {
        host: Some("www.google.com".into()),
        destination_port: Some(443),
        network: Some(crate::rule_engine::TransportNetwork::Tcp),
        ..Default::default()
    };
    let initial = core.evaluate_route(&input).await.unwrap();
    assert_eq!(initial.resolved_outbound, "NodeB");
    assert_eq!(initial.decision.outbound, "Outer");
    assert_eq!(
        initial.decision.matched_rule.as_deref(),
        Some("DOMAIN-SUFFIX,google.com,Outer")
    );
    assert_eq!(
        initial.decision.matched_kind,
        Some(RouteMatchKind::DomainSuffix)
    );
    assert_eq!(
        initial.decision.matched_payload.as_deref(),
        Some("google.com")
    );

    core.select_group_member("Choice", "NodeA").unwrap();
    assert_eq!(
        core.evaluate_route(&input).await.unwrap().resolved_outbound,
        "NodeA"
    );
    assert!(core.connections_snapshot().is_empty());
}

#[tokio::test]
async fn route_preview_does_not_start_probe_tasks() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let profile = url_test_probe_profile(listener.local_addr().unwrap());
    let input = crate::RouteMatchInput {
        host: Some("google.com".into()),
        destination_port: Some(443),
        ..Default::default()
    };
    let result = NativeCoreDevice::preview_route(&profile, &input).unwrap();
    assert_eq!(result.resolved_outbound, "NodeA");
    assert!(timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn route_evaluation_uses_live_health_and_handles_terminal_outbounds() {
    let profile = two_direct_nodes_fallback_profile();
    let core = NativeCoreDevice::compile(&profile);
    let input = crate::RouteMatchInput {
        host: Some("google.com".into()),
        destination_port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        core.evaluate_route(&input).await.unwrap().resolved_outbound,
        "NodeA"
    );
    for _ in 0..OUTBOUND_FALL_THRESHOLD {
        core.inner
            .sessions
            .group_state
            .record_failure("NodeA", now_unix());
    }
    assert_eq!(
        core.evaluate_route(&input).await.unwrap().resolved_outbound,
        "NodeB"
    );

    for outbound in ["DIRECT", "REJECT", "missing-node"] {
        let mut profile = RuntimeProfile::new("terminal-preview");
        profile.rules = vec![match_rule(outbound)].into();
        let core = NativeCoreDevice::compile(&profile);
        let result = core.evaluate_route(&input).await;
        if outbound == "missing-node" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().resolved_outbound, outbound);
        }
        assert!(core.connections_snapshot().is_empty());
    }
}

#[test]
fn group_selection_survives_swap_and_prunes_with_the_group() {
    let core = NativeCoreDevice::compile(&select_group_profile());
    assert!(
        core.select_group_member("Choice", "NodeZ").is_err(),
        "non-member selection is rejected"
    );
    assert!(
        core.select_group_member("Nope", "NodeB").is_err(),
        "unknown group is rejected"
    );
    core.select_group_member("Choice", "NodeB")
        .expect("valid selection");

    let resolved = |core: &NativeCoreDevice| {
        core.pinned_runtime()
            .resolve_outbound(
                "Choice",
                &ConnectTarget {
                    host: "x.example".into(),
                    port: 443,
                },
            )
            .map(|resolved| resolved.name)
    };
    assert_eq!(resolved(&core).as_deref(), Some("NodeB"));

    core.inner
        .sessions
        .group_state
        .record_failure("NodeA", now_unix());
    core.apply_profile(&select_group_profile());
    assert_eq!(
        resolved(&core).as_deref(),
        Some("NodeB"),
        "selection survives the snapshot swap"
    );
    assert_eq!(
        core.inner
            .sessions
            .group_state
            .health_snapshot("NodeA")
            .expect("health survives the swap")
            .consecutive_failures,
        1,
        "a swap must not amnesty failure evidence"
    );

    core.apply_profile(&direct_profile());
    assert_eq!(
        core.inner.sessions.group_state.selection("Choice"),
        None,
        "selection for a removed group is pruned"
    );
    assert!(
        core.inner
            .sessions
            .group_state
            .health_snapshot("NodeA")
            .is_none(),
        "health for a removed node is pruned"
    );
}

#[test]
fn group_selection_rejects_non_select_groups() {
    let core = NativeCoreDevice::compile(&two_direct_nodes_fallback_profile());
    assert_eq!(
        core.select_group_member("Auto", "NodeB")
            .expect_err("fallback group must reject manual selection"),
        "policy group 'Auto' is not selectable"
    );
}

#[test]
fn network_change_resets_health_and_restores_primary() {
    let core = NativeCoreDevice::compile(&two_direct_nodes_fallback_profile());
    let state = &core.inner.sessions.group_state;
    for _ in 0..OUTBOUND_FALL_THRESHOLD {
        state.record_failure("NodeA", now_unix());
    }
    state.record_probe_success("NodeB", Duration::from_millis(42));

    let resolved = |core: &NativeCoreDevice| {
        core.pinned_runtime()
            .resolve_outbound(
                "Auto",
                &ConnectTarget {
                    host: "x.example".into(),
                    port: 443,
                },
            )
            .map(|resolved| resolved.name)
    };
    assert_eq!(
        resolved(&core).as_deref(),
        Some("NodeB"),
        "ejected primary fails over"
    );

    core.apply_network_change(&crate::egress::NetworkChange::default());

    assert_eq!(
        resolved(&core).as_deref(),
        Some("NodeA"),
        "old-network ejection evidence is cleared"
    );
    assert_eq!(
        core.inner.sessions.group_state.probe_ewma_micros("NodeB"),
        None,
        "old-network latency history is cleared"
    );
}

#[tokio::test]
async fn probe_outbound_records_latency_ewma_and_failure_evidence() {
    let (probe_addr, probe_server) = serve_http_204_probe_target().await;
    let core = NativeCoreDevice::compile(&two_direct_nodes_fallback_profile());
    let url = format!("http://127.0.0.1:{}/generate_204", probe_addr.port());

    // Probing a group probes what it resolves to right now.
    core.probe_outbound("Auto", &url)
        .await
        .expect("group probe resolves and succeeds");
    assert!(
        core.inner
            .sessions
            .group_state
            .health_snapshot("NodeA")
            .is_some_and(|health| health.ewma_probe_micros.is_some()),
        "group probe recorded against the resolved concrete node"
    );

    let latency = core
        .probe_outbound("NodeB", &url)
        .await
        .expect("node probe succeeds");
    let health = core
        .inner
        .sessions
        .group_state
        .health_snapshot("NodeB")
        .expect("probe recorded health");
    assert_eq!(
        health.ewma_probe_micros,
        Some(u64::try_from(latency.as_micros()).expect("micros fit")),
        "first probe seeds the EWMA with the measured latency"
    );
    assert_eq!(health.consecutive_successes, 1);

    let (dead, _dead_port_guard) = refused_local_addr();
    let dead_url = format!("http://127.0.0.1:{}/", dead.port());
    core.probe_outbound("NodeB", &dead_url)
        .await
        .expect_err("dead probe target fails");
    let health = core
        .inner
        .sessions
        .group_state
        .health_snapshot("NodeB")
        .expect("failure recorded");
    assert_eq!(health.consecutive_failures, 1);
    assert_eq!(health.consecutive_successes, 0);

    core.probe_outbound("NoSuchNode", &url)
        .await
        .expect_err("unknown outbound is rejected");
    core.probe_outbound("NodeB", "ftp://unsupported")
        .await
        .expect_err("unsupported probe URL is rejected");
    probe_server.abort();
}

/// A node's latency is the round trip through it. Looking up its server's
/// address is not part of it: every later connection takes the address
/// from the cache, and a node tested once would show the resolver's delay
/// on top of its own.
#[tokio::test]
async fn a_node_s_latency_leaves_out_the_lookup_of_its_server() {
    let (target, target_task) = serve_http_204_probe_target().await;
    let (proxy, proxy_task) = serve_http_connect_proxies().await;
    let dns = SlowDns::start(Duration::from_millis(300)).await;
    let mut profile = RuntimeProfile::new("probe-lookup");
    profile.proxies = vec![ProxyNode {
        id: "node-named".into(),
        name: "Named".into(),
        protocol: ProxyProtocol::Http,
        server: Some("probe-node.test".into()),
        port: Some(proxy.port()),
        options: serde_json::Value::Null,
    }];
    profile.dns.enabled = true;
    profile.dns.proxy_nameservers = vec![dns.upstream()];
    let url = format!("http://127.0.0.1:{}/generate_204", target.port());

    let alone = crate::probe_profile_node(
        profile.clone(),
        "Named",
        &url,
        NativeCoreEgressConfig::default(),
        None,
    )
    .await
    .expect("a test without a Core");
    let core = NativeCoreDevice::compile(&profile);
    let in_core = core
        .probe_outbound("Named", &url)
        .await
        .expect("a Core's first test of the node");
    // Each test waited for the address.
    assert_eq!(dns.a_questions(), 2);
    for latency in [alone, in_core] {
        assert!(
            latency < Duration::from_millis(250),
            "{latency:?} counts the lookup"
        );
    }
    core.close();
    proxy_task.abort();
    target_task.abort();
}

/// Probe loop: the spawned scheduler runs a first jittered probe
/// on its own, and exits promptly when the device closes.
#[tokio::test]
async fn health_probe_loop_probes_group_members_and_exits_on_close() {
    let (probe_addr, probe_server) = serve_http_204_probe_target().await;
    let core = NativeCoreDevice::compile(&url_test_probe_profile(probe_addr));
    let handle = core
        .spawn_health_probe_loop()
        .expect("first spawn owns the probe loop");
    assert!(
        core.spawn_health_probe_loop().is_none(),
        "a second spawn while the loop lives must be a no-op"
    );

    let mut probed = false;
    for _ in 0..100 {
        if core
            .inner
            .sessions
            .group_state
            .probe_ewma_micros("NodeA")
            .is_some()
        {
            probed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        probed,
        "probe loop must run a first jittered probe within the interval"
    );

    core.close();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("probe loop exits after close")
        .expect("probe task joins cleanly");
    probe_server.abort();
}

/// A profile swap reaches the running loop: the new profile's node is probed
/// and the retired node's probe in flight is aborted, without a restart.
#[tokio::test]
async fn a_profile_swap_enrolls_new_nodes_and_aborts_retired_probes() {
    let (blackhole, connections, blackhole_server) = serve_blackhole_probe_target().await;
    let (target, target_server) = serve_http_204_probe_target().await;
    let probed_against = |node: &str, at: SocketAddr| {
        let mut profile = RuntimeProfile::new("swap-probes");
        profile.proxies = vec![direct_node(node)];
        let mut group = policy_group("Auto", PolicyGroupKind::UrlTest, &[node]);
        group.interval_seconds = Some(1);
        group.test_url = Some(format!("http://127.0.0.1:{}/generate_204", at.port()));
        profile.groups = vec![group];
        profile.rules = vec![match_rule("Auto")].into();
        profile
    };
    let core = NativeCoreDevice::compile(&probed_against("Old", blackhole));
    core.apply_network_change(&crate::egress::NetworkChange::default());
    let handle = core.spawn_health_probe_loop().expect("probe loop");
    timeout(Duration::from_secs(2), async {
        while connections.open.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the old node's probe is in flight");

    core.apply_profile(&probed_against("New", target));
    timeout(Duration::from_secs(3), async {
        while core
            .inner
            .sessions
            .group_state
            .probe_ewma_micros("New")
            .is_none()
            || connections.open.load(Ordering::SeqCst) > 0
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the new node is probed and the retired probe aborted");

    core.close();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("probe loop exits after close")
        .expect("probe task joins cleanly");
    blackhole_server.abort();
    target_server.abort();
}

/// After a network change every node is due at once. Blackholed nodes queued
/// ahead of a healthy one no longer delay its probe by a whole budget each:
/// with fewer of them than probe slots, it is probed at once.
#[tokio::test]
async fn blackholed_nodes_do_not_delay_a_healthy_probe_after_a_network_change() {
    let (blackhole, _, blackhole_server) = serve_blackhole_probe_target().await;
    let (target, target_server) = serve_http_204_probe_target().await;
    let core = NativeCoreDevice::compile(&blackholed_nodes_profile(
        health::MAX_CONCURRENT_PROBES - 1,
        blackhole,
        target,
    ));
    core.apply_network_change(&crate::egress::NetworkChange::default());
    let handle = core.spawn_health_probe_loop().expect("probe loop");

    timeout(Duration::from_secs(2), async {
        while core
            .inner
            .sessions
            .group_state
            .probe_ewma_micros("Healthy")
            .is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the healthy node is probed without waiting behind blackholed ones");

    core.close();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("probe loop exits after close")
        .expect("probe task joins cleanly");
    blackhole_server.abort();
    target_server.abort();
}

/// Many blackholed nodes due at once hold at most the probe slots, and
/// closing the device ends the probes in flight.
#[tokio::test]
async fn blackholed_probes_stay_within_the_concurrency_cap_and_end_on_close() {
    let (blackhole, connections, blackhole_server) = serve_blackhole_probe_target().await;
    let (target, target_server) = serve_http_204_probe_target().await;
    let core = NativeCoreDevice::compile(&blackholed_nodes_profile(
        3 * health::MAX_CONCURRENT_PROBES,
        blackhole,
        target,
    ));
    core.apply_network_change(&crate::egress::NetworkChange::default());
    let handle = core.spawn_health_probe_loop().expect("probe loop");

    let open = || connections.open.load(Ordering::SeqCst);
    timeout(Duration::from_secs(2), async {
        while open() < health::MAX_CONCURRENT_PROBES {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("blackholed probes fill every slot");
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        connections.peak.load(Ordering::SeqCst),
        health::MAX_CONCURRENT_PROBES,
        "blackholed probes never exceed the cap"
    );

    core.close();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("probe loop exits after close")
        .expect("probe task joins cleanly");
    timeout(Duration::from_secs(2), async {
        while open() > 0 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("closing ends the probes in flight");
    blackhole_server.abort();
    target_server.abort();
}

/// Probe wiring: driving the capture serve entry (`run_packet_queue`) is
/// what lights up the health-probe scheduler in production — nothing else
/// spawns it. The serve loop returns after its idle budget having spawned the
/// (detached) loop, which then runs the first jittered probe on its own.
#[tokio::test]
async fn run_packet_queue_spawns_the_health_probe_loop() {
    let (probe_addr, probe_server) = serve_http_204_probe_target().await;
    let core = NativeCoreDevice::compile(&url_test_probe_profile(probe_addr));
    let mut packet_device = MemoryPacketDevice::new(vec![]);
    let stop = CancellationToken::new();
    stop.cancel();

    // Return at once; the probe loop it spawned keeps running detached, so
    // the probe fires after this returns.
    core.run_packet_queue(PacketQueue::ONLY, &mut packet_device, stop)
        .await;

    let mut probed = false;
    for _ in 0..100 {
        if core
            .inner
            .sessions
            .group_state
            .probe_ewma_micros("NodeA")
            .is_some()
        {
            probed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        probed,
        "the capture serve entry must spawn the health-probe loop"
    );

    core.close();
    probe_server.abort();
}

#[tokio::test]
async fn core_device_closes_udp_flow_sessions_by_flow_id() {
    let payload = b"udp-flow-close";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task =
        tokio::spawn(async move { crate::self_test::serve_one_udp_echo(target_socket).await });
    let core = NativeCoreDevice::compile(&direct_profile());

    let (report, response) = send_udp_and_drain(
        &core,
        NativeUdpFlowDatagram {
            flow_id: Some("udp-flow-close".into()),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53125)),
            target: NativeUdpFlowTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                process_name: None,
                process_path: None,
            },
            payload: payload.to_vec(),
        },
    )
    .await;
    assert!(report.enqueued);
    assert_eq!(response.payload, payload);
    assert_eq!(core.status().udp_sessions, 1);
    assert_eq!(
        core.inner
            .sessions
            .udp_sessions
            .session_socket_count_for_test(),
        1
    );

    let closed = core
        .close_udp_flow_sessions("udp-flow-close")
        .expect("close UDP flow sessions");

    assert_eq!(closed, 1);
    assert_eq!(core.status().udp_sessions, 0);
    assert_eq!(
        core.inner
            .sessions
            .udp_sessions
            .session_socket_count_for_test(),
        0
    );
    echo_task.await.expect("echo join").expect("echo completes");
}

/// In-memory capture device. It serves its queued packets, records writes,
/// and cancels `stop` once the scenario is complete so `run_packet_queue`
/// returns on its own.
#[derive(Debug)]
struct MemoryPacketDevice {
    unread: VecDeque<Vec<u8>>,
    written: Vec<Vec<u8>>,
    write_attempts: usize,
    stop_after_writes: Option<usize>,
    write_error: Option<String>,
    read_error_when_drained: Option<String>,
    ready_calls: usize,
    stop: CancellationToken,
}

impl MemoryPacketDevice {
    fn new(packets: Vec<Vec<u8>>) -> Self {
        Self {
            unread: packets.into(),
            written: Vec::new(),
            write_attempts: 0,
            stop_after_writes: None,
            write_error: None,
            read_error_when_drained: None,
            ready_calls: 0,
            stop: CancellationToken::new(),
        }
    }

    fn stop_after_writes(mut self, writes: usize) -> Self {
        self.stop_after_writes = Some(writes);
        self
    }

    fn fail_writes(mut self, error: &str) -> Self {
        self.write_error = Some(error.into());
        self
    }

    fn fail_reads_when_drained(mut self, error: &str) -> Self {
        self.read_error_when_drained = Some(error.into());
        self
    }
}

impl crate::packet::PacketDevice for MemoryPacketDevice {
    fn name(&self) -> &str {
        "memory-tun"
    }

    fn try_recv(&mut self) -> Result<Option<crate::packet::ReceivedPacket>, String> {
        match self.unread.pop_front() {
            Some(packet) => Ok(Some(packet.into())),
            None => match &self.read_error_when_drained {
                Some(error) => Err(error.clone()),
                None => Ok(None),
            },
        }
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<crate::packet::PacketSend, String> {
        self.write_attempts += 1;
        if self
            .stop_after_writes
            .is_some_and(|writes| self.write_attempts >= writes)
        {
            self.stop.cancel();
        }
        if let Some(error) = &self.write_error {
            return Err(error.clone());
        }
        self.written.push(packet.to_vec());
        Ok(crate::packet::PacketSend::Sent)
    }

    fn ready(&mut self, _: crate::packet::PacketInterest) -> crate::packet::PacketReady<'_> {
        self.ready_calls += 1;
        Box::pin(std::future::pending())
    }
}

fn dns_capture_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("dns-capture");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn reject_all_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("reject-all");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "REJECT",
        no_resolve: false,
    }]
    .into();
    profile
}

async fn loopback_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind pair listener");
    let addr = listener.local_addr().expect("pair addr");
    let client = TcpStream::connect(addr).await.expect("connect pair");
    let (server, _) = listener.accept().await.expect("accept pair");
    (client, server)
}

/// A loopback address that refuses connections for as long as the
/// returned guard lives: the socket stays bound without ever listening,
/// so connects are refused and no parallel test can rebind the port into
/// a live listener mid-scenario.
fn refused_local_addr() -> (SocketAddr, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().expect("create refused-port socket");
    socket
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind refused-port socket");
    let addr = socket.local_addr().expect("refused addr");
    (addr, socket)
}

/// Accepts and immediately closes every connection: a "broken" upstream
/// whose handshake fails fast and deterministically.
async fn serve_reset_primary() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind reset primary");
    let addr = listener.local_addr().expect("reset primary addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            drop(stream);
        }
    });
    (addr, task)
}

/// Echoes every accepted connection until client EOF; serves until
/// aborted.
async fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo server addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, task)
}

/// Spawns a `serve_one_sink_proxy` and returns its address plus the
/// authority/captured-tunnel receivers.
async fn spawn_sink_proxy(
    banner: Option<Vec<u8>>,
    capture_len: usize,
) -> (
    SocketAddr,
    oneshot::Receiver<String>,
    oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind sink proxy");
    let addr = listener.local_addr().expect("sink proxy addr");
    let (authority_tx, authority_rx) = oneshot::channel();
    let (captured_tx, captured_rx) = oneshot::channel();
    let task = tokio::spawn(crate::self_test::serve_one_sink_proxy(
        listener,
        authority_tx,
        captured_tx,
        banner,
        capture_len,
    ));
    (addr, authority_rx, captured_rx, task)
}

/// Drives a SOCKS5 no-auth CONNECT to an IPv4 target and asserts the
/// success reply.
async fn socks5_connect_ipv4(app: &mut TcpStream, ip: [u8; 4], port: u16) {
    app.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("send greeting");
    let mut method = [0_u8; 2];
    app.read_exact(&mut method).await.expect("method reply");
    assert_eq!(method, [0x05, 0x00]);
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&port.to_be_bytes());
    app.write_all(&request).await.expect("send CONNECT");
    let mut reply = [0_u8; 10];
    timeout(Duration::from_secs(3), app.read_exact(&mut reply))
        .await
        .expect("CONNECT replied")
        .expect("reply read");
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT succeeds");
}

fn sink_proxy_node(proxy_addr: SocketAddr) -> ProxyNode {
    ProxyNode {
        id: "node-sink-proxy".into(),
        name: "SinkProxy".into(),
        protocol: ProxyProtocol::Http,
        server: Some(proxy_addr.ip().to_string()),
        port: Some(proxy_addr.port()),
        options: serde_json::Value::Null,
    }
}

fn domain_sni_rule() -> RouteRule<'static> {
    RouteRule {
        kind: RuleKind::DomainSuffix,
        payload: Some("sni.example"),
        outbound: "SinkProxy",
        no_resolve: false,
    }
}

fn test_net_cidr_rule() -> RouteRule<'static> {
    RouteRule {
        kind: RuleKind::IpCidr,
        payload: Some("203.0.113.0/24"),
        outbound: "SinkProxy",
        no_resolve: false,
    }
}

/// DOMAIN-SUFFIX sni.example → SinkProxy, MATCH → REJECT: only a
/// sniffed (or fake-IP) domain can save a bare-IP session.
fn sniff_domain_profile(proxy_addr: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("sniff-domain");
    profile.proxies = vec![sink_proxy_node(proxy_addr)];
    profile.rules = vec![domain_sni_rule(), match_rule("REJECT")].into();
    profile
}

/// Adds an IP-CIDR route for the TEST-NET targets, so IP routing still
/// reaches the sink proxy when the sniff misses.
fn sniff_domain_or_cidr_profile(proxy_addr: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("sniff-domain-or-cidr");
    profile.proxies = vec![sink_proxy_node(proxy_addr)];
    profile.rules = vec![
        domain_sni_rule(),
        test_net_cidr_rule(),
        match_rule("REJECT"),
    ]
    .into();
    profile
}

/// No domain rules at all: the compile-time short-circuit applies.
fn sniff_cidr_only_profile(proxy_addr: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("sniff-cidr-only");
    profile.proxies = vec![sink_proxy_node(proxy_addr)];
    profile.rules = vec![test_net_cidr_rule(), match_rule("DIRECT")].into();
    profile
}

fn two_http_proxies(proxy_a: SocketAddr, proxy_b: SocketAddr) -> Vec<ProxyNode> {
    vec![
        ProxyNode {
            id: "node-proxy-a".into(),
            name: "ProxyA".into(),
            protocol: ProxyProtocol::Http,
            server: Some(proxy_a.ip().to_string()),
            port: Some(proxy_a.port()),
            options: serde_json::Value::Null,
        },
        ProxyNode {
            id: "node-proxy-b".into(),
            name: "ProxyB".into(),
            protocol: ProxyProtocol::Http,
            server: Some(proxy_b.ip().to_string()),
            port: Some(proxy_b.port()),
            options: serde_json::Value::Null,
        },
    ]
}

fn dst_port_rule<'a>(port: &'a str, outbound: &'a str) -> RouteRule<'a> {
    RouteRule {
        kind: RuleKind::DstPort,
        payload: Some(port),
        outbound,
        no_resolve: false,
    }
}

/// Routes target A's port through ProxyA and target B's port through
/// ProxyB, with no policy group in between.
fn dst_port_split_profile(
    proxy_a: SocketAddr,
    proxy_b: SocketAddr,
    port_a: u16,
    port_b: u16,
) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("dst-port-split");
    profile.proxies = two_http_proxies(proxy_a, proxy_b);
    profile.rules = vec![
        dst_port_rule(&port_a.to_string(), "ProxyA"),
        dst_port_rule(&port_b.to_string(), "ProxyB"),
        match_rule("DIRECT"),
    ]
    .into();
    profile
}

/// Serves `HTTP/1.1 204` to every connection until aborted.
async fn serve_http_204_probe_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind probe target");
    let addr = listener.local_addr().expect("probe target addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, task)
}

/// Connections a blackhole probe target holds open now and at most.
#[derive(Debug, Default)]
struct BlackholeConnections {
    open: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

/// A probe target that reads requests and never answers, so every probe of
/// it holds its connection until the probe budget runs out or the probe is
/// aborted.
async fn serve_blackhole_probe_target() -> (
    SocketAddr,
    Arc<BlackholeConnections>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind blackhole probe target");
    let addr = listener.local_addr().expect("blackhole probe target addr");
    let connections = Arc::new(BlackholeConnections::default());
    let counts = Arc::clone(&connections);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let open = counts.open.fetch_add(1, Ordering::SeqCst) + 1;
            counts.peak.fetch_max(open, Ordering::SeqCst);
            let counts = Arc::clone(&counts);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                while matches!(stream.read(&mut buffer).await, Ok(read) if read > 0) {}
                counts.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, connections, task)
}

/// UrlTest groups probing `blackholed` nodes against a target that never
/// answers and one healthy node against a 204 target. The healthy node's name
/// sorts after the others, so among nodes due at once it is queued last.
fn blackholed_nodes_profile(
    blackholed: usize,
    blackhole: SocketAddr,
    healthy_target: SocketAddr,
) -> RuntimeProfile {
    let names: Vec<String> = (0..blackholed)
        .map(|index| format!("Blackholed{index:02}"))
        .collect();
    let mut profile = RuntimeProfile::new("blackholed-probes");
    profile.proxies = names
        .iter()
        .map(|name| direct_node(name))
        .chain([direct_node("Healthy")])
        .collect();
    let members: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut dead = policy_group("Dead", PolicyGroupKind::UrlTest, &members);
    dead.test_url = Some(format!(
        "http://127.0.0.1:{}/generate_204",
        blackhole.port()
    ));
    let mut live = policy_group("Live", PolicyGroupKind::UrlTest, &["Healthy"]);
    live.test_url = Some(format!(
        "http://127.0.0.1:{}/generate_204",
        healthy_target.port()
    ));
    profile.groups = vec![dead, live];
    profile.rules = vec![match_rule("Live")].into();
    profile
}

fn policy_group(name: &str, kind: PolicyGroupKind, members: &[&str]) -> PolicyGroup {
    PolicyGroup {
        id: format!("group-{name}"),
        name: name.into(),
        kind,
        members: members.iter().map(|member| (*member).to_string()).collect(),
        interval_seconds: None,
        test_url: None,
        selected: None,
    }
}

/// Direct-protocol node: dials the target directly; `server`/`port` are
/// required for endpoint compilation but unused when dialing.
fn direct_node(name: &str) -> ProxyNode {
    ProxyNode {
        id: format!("node-{name}"),
        name: name.into(),
        protocol: ProxyProtocol::Direct,
        server: Some(Ipv4Addr::LOCALHOST.to_string()),
        port: Some(1),
        options: serde_json::Value::Null,
    }
}

fn match_rule(outbound: &str) -> RouteRule<'_> {
    RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound,
        no_resolve: false,
    }
}

fn fallback_group_profile(primary: SocketAddr, backup: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("fallback-group");
    profile.proxies = vec![
        ProxyNode {
            id: "node-primary".into(),
            name: "Primary".into(),
            protocol: ProxyProtocol::Socks5,
            server: Some(primary.ip().to_string()),
            port: Some(primary.port()),
            options: serde_json::Value::Null,
        },
        ProxyNode {
            id: "node-backup".into(),
            name: "Backup".into(),
            protocol: ProxyProtocol::Http,
            server: Some(backup.ip().to_string()),
            port: Some(backup.port()),
            options: serde_json::Value::Null,
        },
    ];
    profile.groups = vec![policy_group(
        "Auto",
        PolicyGroupKind::Fallback,
        &["Primary", "Backup"],
    )];
    profile.rules = vec![match_rule("Auto")].into();
    profile
}

fn two_direct_nodes_fallback_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("two-direct-fallback");
    profile.proxies = vec![direct_node("NodeA"), direct_node("NodeB")];
    profile.groups = vec![policy_group(
        "Auto",
        PolicyGroupKind::Fallback,
        &["NodeA", "NodeB"],
    )];
    profile.rules = vec![match_rule("Auto")].into();
    profile
}

fn select_group_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("select-group");
    profile.proxies = vec![direct_node("NodeA"), direct_node("NodeB")];
    profile.groups = vec![policy_group(
        "Choice",
        PolicyGroupKind::Select,
        &["NodeA", "NodeB"],
    )];
    profile.rules = vec![match_rule("Choice")].into();
    profile
}

fn url_test_probe_profile(probe_target: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("url-test-probe");
    profile.proxies = vec![direct_node("NodeA")];
    let mut group = policy_group("Auto", PolicyGroupKind::UrlTest, &["NodeA"]);
    group.interval_seconds = Some(1);
    group.test_url = Some(format!(
        "http://127.0.0.1:{}/generate_204",
        probe_target.port()
    ));
    profile.groups = vec![group];
    profile.rules = vec![match_rule("Auto")].into();
    profile
}

fn http_proxy_profile(name: &str, proxy_addr: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("http-proxy-device");
    profile.proxies = vec![ProxyNode {
        id: format!("proxy-{name}"),
        name: name.into(),
        protocol: ProxyProtocol::Http,
        server: Some(proxy_addr.ip().to_string()),
        port: Some(proxy_addr.port()),
        options: serde_json::Value::Null,
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: name,
        no_resolve: false,
    }]
    .into();
    profile
}

fn dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

fn ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let udp_len = 8 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The enhanced-mode "global policy + direct node" shape: traffic policy is
/// Global, the global outbound is a Select group, and the group's durable
/// choice is DIRECT. A flow arriving on a fake IP (its client resolved
/// through the hijacked DNS) must reverse-map the fake IP and relay through
/// the DIRECT connector to the real target.
#[tokio::test]
async fn global_mode_flow_with_group_selected_direct_relays_to_the_target() {
    let request = b"global-direct-request";
    let response = b"global-direct-response";
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.expect("accept target");
        let mut buffer = [0_u8; 64];
        let read = stream.read(&mut buffer).await.expect("read target");
        assert_eq!(&buffer[..read], request);
        stream.write_all(response).await.expect("write response");
    });

    let mut profile = RuntimeProfile::new("global-direct");
    profile.proxies.push(ProxyNode {
        id: "node-unreachable".into(),
        name: "UnreachableProxy".into(),
        protocol: ProxyProtocol::Http,
        // TEST-NET-1: dialing the proxy instead of DIRECT hangs the relay,
        // so a pass proves the group resolved to DIRECT.
        server: Some("192.0.2.9".into()),
        port: Some(9),
        options: serde_json::Value::Null,
    });
    profile.groups.push(PolicyGroup {
        id: "group-select".into(),
        name: "节点选择".into(),
        kind: PolicyGroupKind::Select,
        members: vec!["DIRECT".into(), "UnreachableProxy".into()],
        interval_seconds: None,
        test_url: None,
        selected: None,
    });
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("节点选择".into());
    let core = NativeCoreDevice::compile(&profile);
    core.select_group_member("节点选择", "DIRECT")
        .expect("select DIRECT in the group");

    // The client dials the fake IP its hijacked DNS answer carried; the
    // reverse map names the real target (an IP-literal "domain" keeps the
    // egress resolver out of this test).
    let fake_ip = core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4(&target_addr.ip().to_string())
        .expect("fake IP allocates");

    let (mut app, flow_stream) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let flow_task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow(
                flow_stream,
                NativeTcpFlowTarget {
                    host: fake_ip.to_string(),
                    port: target_addr.port(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    app.write_all(request).await.expect("send request");

    let mut relayed = vec![0_u8; response.len()];
    timeout(Duration::from_secs(3), app.read_exact(&mut relayed))
        .await
        .expect("response arrives")
        .expect("response read");
    assert_eq!(relayed, response);

    drop(app);
    let outcome = timeout(Duration::from_secs(3), flow_task)
        .await
        .expect("flow ends")
        .expect("flow task joins")
        .expect("flow relays");
    assert_eq!(outcome.outbound, "节点选择");
    target_task.await.expect("target joins");
}

// ---- Captured-TCP engine data plane ---------------------------------------
//
// These drive the single-packet API (`execute_packet` + `drain_pending_packets`,
// the macOS batch shape) against the TCP engine: handshake, relay through
// the ordinary flow pipeline, virtual-DNS service on the stream, and the sniff
// stage.

use crate::packet::ipv4_tcp_checksum;

/// One synthetic captured flow against a device: builds client-side segments
/// and reads the engine emissions off the pending-packet drain.
struct CapturedTcpClient<'a> {
    core: &'a NativeCoreDevice,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    client_port: u16,
    server_port: u16,
}

impl CapturedTcpClient<'_> {
    async fn execute(&self, _label: &str, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        self.core
            .ingest_packet(captured_ipv4_tcp_packet(
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
                seq,
                ack,
                flags,
                payload,
            ))
            .await
            .expect("captured packet executes");
    }

    /// Performs SYN -> SYN-ACK -> ACK and returns the server ISN plus the
    /// SYN-ACK's advertised receive window (the flow's initial send grant).
    async fn handshake(&self, client_isn: u32) -> (u32, u16) {
        self.execute("syn", client_isn, 0, 0x02, &[]).await;
        let syn_ack = self
            .drain_until(|packet| captured_tcp_flags(packet) & 0x12 == 0x12)
            .await;
        let server_isn = captured_tcp_sequence_number(&syn_ack);
        let window = captured_tcp_window(&syn_ack);
        self.execute("ack", client_isn + 1, server_isn + 1, 0x10, &[])
            .await;
        (server_isn, window)
    }

    /// Polls the drain until an emitted packet satisfies `pred`.
    async fn drain_until(&self, pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            loop {
                for packet in self
                    .core
                    .drain_pending_packets()
                    .await
                    .expect("pending packets drain")
                {
                    if pred(&packet) {
                        return packet;
                    }
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("expected a TCP engine emission before timeout")
    }
}

#[allow(clippy::too_many_arguments)]
fn captured_ipv4_tcp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 40 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let ip_checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence_number.to_be_bytes());
    packet[28..32].copy_from_slice(&acknowledgment_number.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
    packet[40..].copy_from_slice(payload);
    let tcp_checksum = ipv4_tcp_checksum(source_ip, destination_ip, &packet[20..]);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

fn captured_tcp_flags(packet: &[u8]) -> u8 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    packet.get(header_len + 13).copied().unwrap_or(0)
}

fn captured_tcp_sequence_number(packet: &[u8]) -> u32 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    u32::from_be_bytes([
        packet[header_len + 4],
        packet[header_len + 5],
        packet[header_len + 6],
        packet[header_len + 7],
    ])
}

fn captured_tcp_payload(packet: &[u8]) -> &[u8] {
    let ip_header_len = ((packet[0] & 0x0f) as usize) * 4;
    let tcp_header_len = ((packet[ip_header_len + 12] >> 4) as usize) * 4;
    &packet[ip_header_len + tcp_header_len..]
}

/// A captured SYN answers with a SYN-ACK on the asynchronous drain (the
/// macOS `execute_packet` + `drain_pending_packets` shape).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_tcp_syn_answers_syn_ack_on_the_drain() {
    let core = NativeCoreDevice::compile(&direct_profile());
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: Ipv4Addr::new(93, 184, 216, 34),
        client_port: 53123,
        server_port: 443,
    };

    client.execute("syn", 1000, 0, 0x02, &[]).await;
    let syn_ack = client
        .drain_until(|packet| captured_tcp_flags(packet) & 0x12 == 0x12)
        .await;

    let (flow, _) = crate::packet::attribution_flow(&syn_ack).expect("SYN-ACK parses");
    assert_eq!(
        flow.destination_ip,
        std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(flow.destination_port, 53123);
    assert_eq!(core.status().tcp_sessions, 1, "one live captured flow");
    core.close();
}

/// End-to-end: a captured flow relays through the ordinary pipeline to a
/// DIRECT loopback upstream, the response segments come back on the drain,
/// and the session registry carries the flow (inbound `tun`) -- the connection
/// table, kill switch, and accounting all see it without a parallel ledger.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_tcp_flow_relays_direct_and_registers_a_tun_session() {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.expect("accept target");
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).await.expect("read target");
        assert_eq!(&buffer[..read], b"captured-request");
        stream
            .write_all(b"captured-response")
            .await
            .expect("write target");
    });

    let core = NativeCoreDevice::compile(&direct_profile());
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: Ipv4Addr::new(127, 0, 0, 1),
        client_port: 53124,
        server_port: target_addr.port(),
    };

    let client_isn = 1000;
    let (server_isn, _) = client.handshake(client_isn).await;
    client
        .execute(
            "payload",
            client_isn + 1,
            server_isn + 1,
            0x18,
            b"captured-request",
        )
        .await;

    let response = client
        .drain_until(|packet| captured_tcp_payload(packet) == b"captured-response")
        .await;
    assert_eq!(captured_tcp_payload(&response), b"captured-response");
    target_task.await.expect("target joins");

    let sessions = core.inner.sessions.registry.snapshot();
    assert_eq!(sessions.len(), 1, "the captured flow rides the registry");
    assert_eq!(sessions[0].inbound, "tun");
    assert_eq!(sessions[0].outbound.as_deref(), Some("DIRECT"));
    assert_eq!(
        sessions[0].source.as_deref(),
        Some("10.0.0.2:53124"),
        "the ledger records the captured client endpoint"
    );
    core.close();
}

/// Packet ingress keeps the original virtual destination in its ledger while
/// the shared enrichment stage restores the domain used for routing/dialing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_fake_ip_keeps_raw_destination_and_shared_enrichment_route() {
    let payload = b"captured-fake-ip";
    let (proxy_addr, authority_rx, captured_rx, proxy_task) =
        spawn_sink_proxy(None, payload.len()).await;
    let mut profile = sniff_domain_profile(proxy_addr);
    let _dns = configure_local_dns(&mut profile).await;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    let core = NativeCoreDevice::compile(&profile);
    let fake_ip = core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4("portal.sni.example")
        .unwrap();
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: fake_ip,
        client_port: 53127,
        server_port: 443,
    };
    let client_isn = 1600;
    let (server_isn, _) = client.handshake(client_isn).await;
    client
        .execute(
            "fake-payload",
            client_isn + 1,
            server_isn + 1,
            0x18,
            payload,
        )
        .await;
    assert_eq!(
        timeout(Duration::from_secs(3), captured_rx)
            .await
            .unwrap()
            .unwrap(),
        payload
    );
    assert_eq!(
        timeout(Duration::from_secs(3), authority_rx)
            .await
            .unwrap()
            .unwrap(),
        "portal.sni.example:443"
    );
    let sessions = core.inner.sessions.registry.snapshot();
    assert_eq!(sessions.len(), 1);
    assert_eq!(&*sessions[0].target, format!("{fake_ip}:443"));
    assert_eq!(sessions[0].host.as_deref(), Some("portal.sni.example"));
    assert_eq!(sessions[0].outbound.as_deref(), Some("SinkProxy"));
    assert_eq!(core.state_audit().sniff.attempted, 0);
    proxy_task.abort();
    core.close();
}

/// A captured TCP/53 flow to a virtual DNS target answers framed queries from
/// the core DNS engine on the stream itself -- no upstream dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_tcp_dns_answers_framed_queries_on_the_stream() {
    let virtual_dns = Ipv4Addr::new(10, 255, 255, 2);
    let core = NativeCoreDevice::compile_with_egress_and_capture(
        &dns_capture_profile(),
        crate::NativeCoreEgressConfig::default(),
        crate::NativeCoreCaptureConfig::with_dns_hijack(
            crate::NativeCoreDnsHijackConfig::capture_virtual_dns_targets([std::net::IpAddr::V4(
                virtual_dns,
            )]),
        ),
    );
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: virtual_dns,
        client_port: 53125,
        server_port: 53,
    };

    let client_isn = 4000;
    let (server_isn, _) = client.handshake(client_isn).await;
    let dns_payload = dns_query(0x4567, "example.com", 1);
    let mut framed = Vec::with_capacity(2 + dns_payload.len());
    framed.extend_from_slice(&(dns_payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(&dns_payload);
    client
        .execute("dns-query", client_isn + 1, server_isn + 1, 0x18, &framed)
        .await;

    let response_packet = client
        .drain_until(|packet| {
            let payload = captured_tcp_payload(packet);
            payload.len() > 2
                && u16::from_be_bytes([payload[0], payload[1]]) as usize == payload.len() - 2
        })
        .await;
    let response_payload = captured_tcp_payload(&response_packet)[2..].to_vec();
    assert_eq!(
        response_payload[0..2],
        0x4567_u16.to_be_bytes(),
        "the engine answers the query id it was asked"
    );
    core.close();
}

/// Sniffing on the captured path: a TLS ClientHello split across two segments
/// is reassembled by the shared pipeline sniff stage, which holds the dial
/// until the SNI decides the route, then dials the domain-rule outbound and
/// delivers the flight whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_tcp_flow_sniffs_split_client_hello_and_reroutes() {
    let hello = crate::sniff::build_tls_client_hello(Some("target.sni.example"));
    let split = hello.len() / 2;
    let (proxy_addr, authority_rx, captured_rx, proxy_task) =
        spawn_sink_proxy(None, hello.len()).await;

    let core = NativeCoreDevice::compile(&sniff_domain_or_cidr_profile(proxy_addr));
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: Ipv4Addr::new(203, 0, 113, 7),
        client_port: 53126,
        server_port: 443,
    };

    let client_isn = 9000;
    let (server_isn, _) = client.handshake(client_isn).await;
    client
        .execute(
            "hello-1",
            client_isn + 1,
            server_isn + 1,
            0x18,
            &hello[..split],
        )
        .await;
    client
        .execute(
            "hello-2",
            client_isn + 1 + split as u32,
            server_isn + 1,
            0x18,
            &hello[split..],
        )
        .await;

    assert_eq!(
        timeout(Duration::from_secs(5), captured_rx)
            .await
            .expect("tunnel bytes captured")
            .expect("captured"),
        hello,
        "the outbound receives the exact reassembled flight"
    );
    assert_eq!(
        timeout(Duration::from_secs(5), authority_rx)
            .await
            .expect("proxy sees CONNECT")
            .expect("authority"),
        "203.0.113.7:443"
    );
    let counters = core.inner.sessions.sniff_stats.counters();
    assert_eq!(counters.attempted, 1);
    assert_eq!(counters.hits, 1);
    let sessions = core.inner.sessions.registry.snapshot();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].outbound.as_deref(),
        Some("SinkProxy"),
        "the sniffed SNI re-routed the dial to the domain outbound"
    );
    proxy_task.abort();
    core.close();
}

// ---- Captured-TCP bulk-upload backpressure ---------------------------------
//
// The upload direction under sustained receiver backpressure: the client
// outruns the upstream, the socket buffers and stream rings fill, the
// advertised window closes, and every grant afterwards must round-trip
// through drain -> relay read -> driver transfer -> window-update emission.
// A lost wakeup anywhere in that chain stalls the upload permanently, which
// is invisible to the request/response tests above.

fn captured_tcp_ack_number(packet: &[u8]) -> u32 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    u32::from_be_bytes([
        packet[header_len + 8],
        packet[header_len + 9],
        packet[header_len + 10],
        packet[header_len + 11],
    ])
}

fn captured_tcp_window(packet: &[u8]) -> u16 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    u16::from_be_bytes([packet[header_len + 14], packet[header_len + 15]])
}

impl CapturedTcpClient<'_> {
    /// Sends `total` bytes inside the advertised receive window, consuming
    /// ACKs off the drain, and returns once every byte is acknowledged.
    /// Progress is any ACK advance, window movement, or in-window send; no
    /// progress within `stall_budget` fails the upload — the repro signal
    /// for a dead window-reopen path. Returns the final `snd_nxt`.
    async fn bulk_upload(
        &self,
        client_isn: u32,
        server_isn: u32,
        initial_window: u16,
        total: usize,
        stall_budget: Duration,
    ) -> Result<u32, String> {
        const CHUNK: usize = 1200;
        let base = client_isn.wrapping_add(1);
        let mut snd_nxt = base;
        let mut highest_ack = base;
        // Seeded from the SYN-ACK; every later ACK replaces it.
        let mut window: u16 = initial_window;
        let mut sent = 0_usize;
        let mut sequence = 0_u64;
        let mut last_movement = tokio::time::Instant::now();

        while (highest_ack.wrapping_sub(base) as usize) < total {
            let mut moved = false;
            for packet in self
                .core
                .drain_pending_packets()
                .await
                .map_err(|error| format!("drain failed: {error}"))?
            {
                let payload = packet;
                let flags = captured_tcp_flags(&payload);
                if flags & 0x04 != 0 {
                    return Err(format!("stack RST the flow after {sent} bytes"));
                }
                if flags & 0x01 != 0 {
                    return Err(format!("stack FIN'd the flow after {sent} bytes"));
                }
                let ack = captured_tcp_ack_number(&payload);
                let win = captured_tcp_window(&payload);
                // A window update repeats the highest ACK, so `>=` keeps the
                // window tied to the newest cumulative position.
                if ack.wrapping_sub(base) >= highest_ack.wrapping_sub(base) {
                    if ack != highest_ack || win != window {
                        moved = true;
                    }
                    highest_ack = ack;
                    window = win;
                }
            }

            let in_flight = snd_nxt.wrapping_sub(highest_ack) as usize;
            let usable = (window as usize).saturating_sub(in_flight);
            if sent < total && usable > 0 {
                let chunk = CHUNK.min(usable).min(total - sent);
                let payload = vec![0xA5_u8; chunk];
                sequence += 1;
                self.execute(
                    &format!("bulk-{sequence}"),
                    snd_nxt,
                    server_isn.wrapping_add(1),
                    0x10,
                    &payload,
                )
                .await;
                snd_nxt = snd_nxt.wrapping_add(chunk as u32);
                sent += chunk;
                moved = true;
            }

            if moved {
                last_movement = tokio::time::Instant::now();
            } else {
                if last_movement.elapsed() > stall_budget {
                    let acked = highest_ack.wrapping_sub(base) as usize;
                    return Err(format!(
                        "upload stalled: sent={sent} acked={acked} window={window} in_flight={in_flight}"
                    ));
                }
                sleep(Duration::from_millis(2)).await;
            }
        }
        Ok(snd_nxt)
    }
}

/// A loopback sink that reads slowly — `chunk` bytes then `pause` — so the
/// relay's upstream write path backpressures all the way into the TCP engine.
/// Resolves with the total byte count once the client's FIN arrives.
async fn spawn_throttled_sink(
    chunk: usize,
    pause: Duration,
) -> (SocketAddr, oneshot::Receiver<usize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind throttled sink");
    let addr = listener.local_addr().expect("sink addr");
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept sink");
        let mut buffer = vec![0_u8; chunk];
        let mut total = 0_usize;
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    total += read;
                    sleep(pause).await;
                }
            }
        }
        let _ = done_tx.send(total);
    });
    (addr, done_rx)
}

/// Control shape: DIRECT to the throttled sink. The kernel socket to the
/// sink absorbs almost nothing, so the window closes and reopens for the
/// whole transfer — the pure engine/relay backpressure cycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn captured_tcp_bulk_upload_direct_survives_receiver_backpressure() {
    const TOTAL: usize = 768 * 1024;
    let (sink_addr, done) = spawn_throttled_sink(8192, Duration::from_millis(2)).await;

    let core = NativeCoreDevice::compile(&direct_profile());
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        client_port: 53170,
        server_ip: Ipv4Addr::new(127, 0, 0, 1),
        server_port: sink_addr.port(),
    };

    let client_isn = 42_000;
    let (server_isn, initial_window) = client.handshake(client_isn).await;
    let snd_nxt = client
        .bulk_upload(
            client_isn,
            server_isn,
            initial_window,
            TOTAL,
            Duration::from_secs(10),
        )
        .await
        .expect("bulk upload sustains progress under backpressure");
    client
        .execute("fin", snd_nxt, server_isn.wrapping_add(1), 0x11, &[])
        .await;

    let received = timeout(Duration::from_secs(15), done)
        .await
        .expect("sink sees the FIN")
        .expect("sink count");
    assert_eq!(received, TOTAL, "every uploaded byte reached the sink");
    core.close();
}

/// The Trojan shape of the same upload: the captured flow dials the in-tree
/// Trojan server over TLS on loopback, whose dispatcher relays DIRECT to the
/// throttled sink. The upstream write path is now `TlsStream<TcpStream>` —
/// the exact pair the TUN Trojan upload rides in production.
#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn captured_tcp_bulk_upload_through_trojan_sustains_progress() {
    use std::sync::Arc;

    use crate::certificate::server_config_from_pem;
    use crate::inbound::acceptor::{InboundAcceptor, InboundSession};
    use crate::inbound::dispatch::dispatch_accepted_stream;
    use crate::protocols::trojan::acceptor::{TrojanAcceptor, TrojanUserTable};
    use crate::runtime::NativeCoreRuntime;

    const TOTAL: usize = 768 * 1024;
    const PASSWORD: &str = "bulk-upload-preshared-key";
    let (sink_addr, done) = spawn_throttled_sink(8192, Duration::from_millis(2)).await;

    // In-tree Trojan server: TLS-terminating acceptor into the unmodified
    // dispatcher, MATCH -> DIRECT (the gate.rs assembly).
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .expect("params")
        .self_signed(&key_pair)
        .expect("self-signed cert");
    let tls = server_config_from_pem(
        cert.pem().as_bytes(),
        key_pair.serialize_pem().as_bytes(),
        &[],
    )
    .expect("server config builds");
    let acceptor = Arc::new(TrojanAcceptor::new(
        tls,
        TrojanUserTable::new().with_user("bulk", PASSWORD),
    ));
    let server_runtime = NativeCoreRuntime::compile_with_egress_and_capture(
        &direct_profile(),
        crate::NativeCoreEgressConfig::default(),
        crate::NativeCoreCaptureConfig::default(),
    );
    let trojan_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind trojan server");
    let trojan_addr = trojan_listener.local_addr().expect("trojan server addr");
    tokio::spawn(async move {
        while let Ok((client, _)) = trojan_listener.accept().await {
            let runtime = server_runtime.clone();
            let acceptor = Arc::clone(&acceptor);
            let source = client.peer_addr().ok().map(|addr| addr.to_string());
            tokio::spawn(async move {
                let Ok(InboundSession::Stream(accepted)) = acceptor.accept(Box::new(client)).await
                else {
                    return;
                };
                let _ = dispatch_accepted_stream(&runtime, source, accepted).await;
            });
        }
    });

    // The captured client's profile: everything routes through the Trojan hop.
    let mut profile = RuntimeProfile::new("bulk-upload-trojan");
    profile.proxies.push(ProxyNode {
        id: "trojan-hop".into(),
        name: "TrojanHop".into(),
        protocol: ProxyProtocol::Trojan,
        server: Some(trojan_addr.ip().to_string()),
        port: Some(trojan_addr.port()),
        options: serde_json::json!({
            "password": PASSWORD,
            "sni": "localhost",
            "skip-cert-verify": true,
        }),
    });
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "TrojanHop",
        no_resolve: false,
    }]
    .into();

    let core = NativeCoreDevice::compile(&profile);
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        client_port: 53171,
        server_ip: Ipv4Addr::new(127, 0, 0, 1),
        server_port: sink_addr.port(),
    };

    let client_isn = 47_000;
    let (server_isn, initial_window) = client.handshake(client_isn).await;
    let snd_nxt = client
        .bulk_upload(
            client_isn,
            server_isn,
            initial_window,
            TOTAL,
            Duration::from_secs(10),
        )
        .await
        .expect("bulk upload through the Trojan hop sustains progress");
    client
        .execute("fin", snd_nxt, server_isn.wrapping_add(1), 0x11, &[])
        .await;

    let received = timeout(Duration::from_secs(15), done)
        .await
        .expect("sink sees the FIN")
        .expect("sink count");
    assert_eq!(received, TOTAL, "every uploaded byte survived the TLS hop");
    core.close();
}

/// A closed device must not create a TCP engine. `close()` clears the slot
/// exactly once, so an engine created afterwards would never be shut down
/// and its accept loop would run for the device's remaining life, silently —
/// the closed registry refuses every flow it accepts.
#[tokio::test]
async fn a_closed_device_refuses_to_create_a_tcp_engine() {
    let core = NativeCoreDevice::compile(&direct_profile());
    core.start();

    // First use spawns it; the slot is live.
    assert!(
        core.ensure_packet_tcp(PacketQueue::ONLY).is_some(),
        "a running device serves its TCP engine"
    );

    core.close();

    // The pump's TCP branch reaches this without a state check, so the refusal
    // has to live here rather than at the call site.
    assert!(
        core.ensure_packet_tcp(PacketQueue::ONLY).is_none(),
        "a closed device must not resurrect the TCP engine"
    );
    assert!(
        core.packet_tcp_engine().is_none(),
        "no engine remains after close"
    );
}

/// `close()` is terminal. `SessionRegistry::close` latches `closed` and
/// cancels a one-shot root token with no reopen, so a restarted device would
/// admit UDP and dial upstream while refusing every TCP session — half-alive
/// in a way no caller can detect from the state alone.
#[tokio::test]
async fn a_closed_device_stays_closed() {
    let core = NativeCoreDevice::compile(&direct_profile());
    assert_eq!(core.status().state, NativeCoreDeviceState::Running);

    core.close();
    assert_eq!(core.status().state, NativeCoreDeviceState::Closed);

    core.start();
    assert_eq!(
        core.status().state,
        NativeCoreDeviceState::Closed,
        "start() must not resurrect a closed device"
    );
}

mod routing_switch;

mod capture_config;

mod listener_attribution;

mod http_forward;
mod listener_fallback;
mod network_change;
/// What one queue holds for another's engine is bounded in count and in
/// bytes: a write-blocked holder parks on writability and does not wake for
/// the notify these come with, so a foreign queue that keeps reading one
/// flow's upload would otherwise grow this at the link's rate, each entry
/// pinning a whole captured packet.
#[test]
fn forwarded_segments_are_bounded_in_count_and_in_bytes() {
    let owner = || crate::attribution::ClientOwner::Known(None);
    let mut by_count = Forwarded::default();
    for _ in 0..Forwarded::MAX_PACKETS + 10 {
        by_count.push(bytes::Bytes::from_static(&[0; 64]), owner());
    }
    let (held, dropped) = by_count.take();
    assert_eq!(held.len(), Forwarded::MAX_PACKETS);
    assert_eq!(dropped, 10, "the rest were dropped and counted");

    let mut by_bytes = Forwarded::default();
    let big = bytes::Bytes::from(vec![0; Forwarded::MAX_BYTES / 4]);
    for _ in 0..6 {
        by_bytes.push(big.clone(), owner());
    }
    let (held, dropped) = by_bytes.take();
    assert_eq!(held.len(), 4, "four fit the byte bound");
    assert_eq!(dropped, 2);

    // A take gives the bound back for the next hold.
    by_bytes.push(big, owner());
    assert_eq!(by_bytes.take().0.len(), 1);
}

mod pump_tcp;
mod pump_udp;
mod queues;
