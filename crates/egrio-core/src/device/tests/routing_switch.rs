use super::*;
use crate::inbound::{CoreSessionManager, CoreSessionStartConfig};
use crate::outbound::DatagramFuture;
use crate::udp::{send_udp_flow_datagram, UdpDatagram};

fn global_profile(outbound: &str) -> RuntimeProfile {
    let mut profile = direct_profile();
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some(outbound.into());
    profile
}

fn flow_datagram(target: SocketAddr, source_port: u16, payload: &[u8]) -> NativeUdpFlowDatagram {
    NativeUdpFlowDatagram {
        flow_id: Some(format!("routing-{source_port}")),
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, source_port)),
        target: NativeUdpFlowTarget {
            host: target.ip().to_string(),
            port: target.port(),
            process_name: None,
            process_path: None,
        },
        payload: payload.to_vec(),
    }
}

async fn udp_round_trip(core: &NativeCoreDevice, peer: &UdpSocket, source_port: u16) {
    udp_round_trip_from(core, peer, source_port).await;
}

/// One datagram out and its echo back, returning the address the peer saw it
/// come from: the session's egress port, which is what the peer tracks the
/// flow by.
async fn udp_round_trip_from(
    core: &NativeCoreDevice,
    peer: &UdpSocket,
    source_port: u16,
) -> SocketAddr {
    let target = peer.local_addr().unwrap();
    core.send_udp_flow_datagram(flow_datagram(target, source_port, b"request"))
        .await
        .unwrap();
    let mut buffer = [0; 32];
    let (read, client) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    peer.send_to(&buffer[..read], client).await.unwrap();
    let replies = core
        .drain_pending_udp_flow_responses(32, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].payload, b"request");
    client
}

#[tokio::test]
async fn direct_to_global_reject_removes_udp_and_discards_old_responses() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = peer.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    udp_round_trip(&core, &peer, 54301).await;
    let stale_runtime = core.pinned_runtime();
    let fake = core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4("keep.example")
        .unwrap();

    core.send_udp_flow_datagram(flow_datagram(target, 54301, b"old-buffer"))
        .await
        .unwrap();
    let mut buffer = [0; 32];
    let (_, client) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    peer.send_to(b"old-buffer", client).await.unwrap();
    core.apply_profile(&global_profile("REJECT"));

    assert_eq!(core.status().udp_sessions, 0);
    assert_eq!(core.state_audit().udp_session_sockets, 0);
    assert_eq!(
        core.inner.sessions.fake_dns.lookup_ipv4(fake).as_deref(),
        Some("keep.example")
    );
    assert!(core
        .drain_pending_udp_flow_responses(32, Duration::from_millis(30))
        .await
        .unwrap()
        .is_empty());
    let error = core
        .send_udp_flow_datagram(flow_datagram(target, 54301, b"new"))
        .await
        .unwrap_err();
    assert!(error.contains("rejected"), "{error}");
    let error = send_udp_flow_datagram(
        &stale_runtime,
        UdpDatagram {
            flow_id: Some("stale-admission".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54302)),
            target: ConnectTarget {
                host: target.ip().to_string(),
                port: target.port(),
            },
            payload: b"stale".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("routing changed"), "{error}");
    assert!(
        timeout(Duration::from_millis(30), peer.recv_from(&mut buffer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn every_profile_refresh_cuts_off_udp_even_when_the_route_is_unchanged() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = peer.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    udp_round_trip(&core, &peer, 54303).await;
    core.apply_profile(&direct_profile());
    assert_eq!(core.status().udp_sessions, 0);
    udp_round_trip(&core, &peer, 54303).await;
    let mut profile = direct_profile();
    profile.rules = vec![
        dst_port_rule(&target.port().to_string(), "REJECT"),
        match_rule("DIRECT"),
    ]
    .into();
    core.apply_profile(&profile);
    assert_eq!(core.status().udp_sessions, 0);
    assert!(core
        .send_udp_flow_datagram(flow_datagram(target, 54303, b"rejected"))
        .await
        .is_err());
}

/// Both members dial out the same way, but they are different outbounds
/// with their own sockets and health, so the session is re-routed and ends.
#[tokio::test]
async fn selector_switch_removes_old_udp_even_when_both_nodes_are_direct() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut profile = two_direct_nodes_fallback_profile();
    profile.groups[0].kind = PolicyGroupKind::Select;
    let group = profile.groups[0].name.clone();
    let core = NativeCoreDevice::compile(&profile);
    udp_round_trip(&core, &peer, 54304).await;
    core.select_group_member(&group, "NodeB").unwrap();
    assert_eq!(core.status().udp_sessions, 0);
    let target = peer.local_addr().unwrap();
    core.send_udp_flow_datagram(flow_datagram(target, 54304, b"new-node"))
        .await
        .unwrap();
    assert_eq!(
        core.inner.sessions.udp_sessions.sessions_snapshot()[0].outbound,
        "NodeB"
    );
    let mut buffer = [0; 32];
    let (read, _) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..read], b"new-node");
    core.close();
}

#[tokio::test]
async fn mode_change_cuts_off_tcp_even_when_the_concrete_route_stays_direct() {
    let (target, echo) = spawn_echo_server().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let (mut app, flow) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow(
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
    app.write_all(b"before").await.unwrap();
    let mut buffer = [0; 6];
    app.read_exact(&mut buffer).await.unwrap();
    core.apply_profile(&global_profile("DIRECT"));
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        timeout(Duration::from_secs(2), app.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    echo.abort();
}

#[tokio::test]
async fn mode_change_closes_pre_handshake_connections_and_new_handshakes_use_new_policy() {
    let manager = CoreSessionManager::default();
    let status = manager
        .start_with_config(CoreSessionStartConfig {
            profile: direct_profile(),
            listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            egress: NativeCoreEgressConfig::default(),
            dns_listen_addr: None,
            inbound: crate::CoreInbound::Mixed,
            hysteria2: None,
            socket_guard: None,
        })
        .await
        .unwrap();
    let address: SocketAddr = status.listen_addr.unwrap().parse().unwrap();
    let mut old = TcpStream::connect(address).await.unwrap();
    // Complete only SOCKS authentication, leaving the target request pending.
    old.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0; 2];
    old.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [5, 0]);
    manager.apply_profile(&global_profile("REJECT")).unwrap();
    let mut buffer = [0; 32];
    assert_eq!(
        timeout(Duration::from_secs(2), old.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let mut new = TcpStream::connect(address).await.unwrap();
    new.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await
        .unwrap();
    let read = timeout(Duration::from_secs(2), new.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert!(std::str::from_utf8(&buffer[..read])
        .unwrap()
        .contains("403"));
    manager.stop();
}

#[tokio::test(start_paused = true)]
async fn mode_change_cancels_an_enriching_platform_flow_before_old_route_can_commit() {
    let mut profile = direct_profile();
    profile.rules = [RouteRule {
        kind: RuleKind::Domain,
        payload: Some("sniff.example"),
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into_iter()
    .chain(&profile.rules)
    .collect();
    let core = NativeCoreDevice::compile(&profile);
    let (_app, flow) = tokio::io::duplex(256);
    let flow_core = core.clone();
    let task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow_io(
                flow,
                None,
                NativeTcpFlowTarget {
                    host: "127.0.0.1".into(),
                    port: 443,
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .inner
                .sessions
                .registry
                .snapshot()
                .iter()
                .any(|session| session.phase == crate::SessionPhase::Enriching)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    core.apply_profile(&global_profile("REJECT"));
    let error = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error.cause, crate::TcpFlowFailure::Cancelled),
        "{error}"
    );
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 0);
}

#[tokio::test]
async fn explicit_cutover_fences_old_runtime_and_keeps_device_available() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    udp_round_trip(&core, &peer, 54305).await;
    let old = core.pinned_runtime();
    let report = core.cutover_sessions();
    assert_eq!(report.udp_sessions, 1);
    assert!(old.connection_cancellation().is_cancelled());
    assert!(old.with_route_admission(|| ()).is_err());
    udp_round_trip(&core, &peer, 54305).await;
    assert_eq!(core.status().udp_sessions, 1);
    core.close();
    core.cutover_sessions();
    assert!(core.inner.sessions.udp_sessions.admission_epoch().is_none());
}

#[tokio::test]
async fn direct_to_global_proxy_closes_old_tcp_and_only_new_connections_use_the_proxy() {
    let (target, echo) = spawn_echo_server().await;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let (observed_tx, observed_rx) = oneshot::channel();
    let proxy =
        tokio::spawn(
            async move { serve_one_http_connect_proxy(proxy_listener, observed_tx).await },
        );
    let core = NativeCoreDevice::compile(&direct_profile());
    let open_flow = |core: NativeCoreDevice| async move {
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
    };
    let (mut old_app, old_task) = open_flow(core.clone()).await;
    old_app.write_all(b"before").await.unwrap();
    let mut reply = [0; 6];
    old_app.read_exact(&mut reply).await.unwrap();
    let mut profile = http_proxy_profile("GlobalProxy", proxy_address);
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("GlobalProxy".into());
    core.apply_profile(&profile);
    timeout(Duration::from_secs(2), old_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let (mut new_app, new_task) = open_flow(core.clone()).await;
    new_app.write_all(b"after!").await.unwrap();
    new_app.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"after!");
    assert_eq!(
        timeout(Duration::from_secs(2), observed_rx)
            .await
            .unwrap()
            .unwrap(),
        target.to_string()
    );
    assert!(core
        .connections_snapshot()
        .iter()
        .any(|entry| &*entry.outbound == "GlobalProxy"));
    core.cutover_sessions();
    timeout(Duration::from_secs(2), new_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    echo.abort();
    proxy.abort();
}

#[tokio::test]
async fn mode_change_cancels_a_live_proxy_handshake_and_closes_its_socket() {
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&http_proxy_profile("PendingProxy", address));
    let (_app, flow) = loopback_stream_pair().await;
    let flow_core = core.clone();
    let task = tokio::spawn(async move {
        flow_core
            .route_tcp_flow(
                flow,
                NativeTcpFlowTarget {
                    host: "127.0.0.1".into(),
                    port: 9,
                    process_name: None,
                    process_path: None,
                },
            )
            .await
    });
    let (mut upstream, _) = timeout(Duration::from_secs(2), proxy.accept())
        .await
        .unwrap()
        .unwrap();
    let mut buffer = [0; 512];
    assert!(
        timeout(Duration::from_secs(2), upstream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap()
            > 0
    );
    core.apply_profile(&global_profile("REJECT"));
    let error = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error.cause, crate::TcpFlowFailure::Cancelled),
        "{error}"
    );
    assert_eq!(error.stage, crate::TcpFlowStage::Dial);
    assert_eq!(
        timeout(Duration::from_secs(2), upstream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_waiting_for_admission_cannot_commit_after_cutover() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = peer.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    let old = core.pinned_runtime();
    let gate = core.inner.sessions.route_admission.clone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let sender_barrier = barrier.clone();
    let sender = {
        let mut admission = gate.write().unwrap();
        let sender = tokio::spawn(async move {
            sender_barrier.wait();
            send_udp_flow_datagram(
                &old,
                UdpDatagram {
                    flow_id: Some("waiting-old-admission".into()),
                    pump_queue: None,
                    inbound: "tun",
                    user: None,
                    source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54306)),
                    target: ConnectTarget {
                        host: target.ip().to_string(),
                        port: target.port(),
                    },
                    payload: b"old".to_vec(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
        });
        barrier.wait();
        admission.advance();
        core.cutover_sessions_locked();
        sender
    };
    let error = timeout(Duration::from_secs(2), sender)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("routing changed"), "{error}");
    assert_eq!(core.status().udp_sessions, 0);
    let mut buffer = [0; 16];
    assert!(
        timeout(Duration::from_millis(30), peer.recv_from(&mut buffer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn selector_and_explicit_cutover_close_unregistered_handshakes() {
    for selector in [true, false] {
        let core = NativeCoreDevice::compile(&select_group_profile());
        let manager = CoreSessionManager::default();
        let status = manager
            .start_on_device(
                core.clone(),
                Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                None,
                false,
            )
            .await
            .unwrap();
        let address: SocketAddr = status.listen_addr.unwrap().parse().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(core.state_audit().tcp_relay_sessions.active, 0);
        if selector {
            core.select_group_member("Choice", "NodeB").unwrap();
        } else {
            core.cutover_sessions();
        }
        assert_eq!(
            timeout(Duration::from_secs(2), client.read(&mut response))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        manager.stop();
        core.close();
    }
}

#[tokio::test]
async fn async_cutover_returns_only_after_old_tcp_socket_and_registry_are_closed() {
    let (target, echo) = spawn_echo_server().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let (mut app, flow) = loopback_stream_pair().await;
    let task = tokio::spawn(core.route_tcp_flow(
        flow,
        NativeTcpFlowTarget {
            host: target.ip().to_string(),
            port: target.port(),
            process_name: None,
            process_path: None,
        },
    ));
    app.write_all(b"before").await.unwrap();
    let mut reply = [0; 6];
    app.read_exact(&mut reply).await.unwrap();
    let report = core
        .cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(report.tcp_relay_sessions, 1);
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 0);
    assert_eq!(app.read(&mut reply).await.unwrap(), 0);
    task.await.unwrap().unwrap_err();
    echo.abort();
}

#[tokio::test]
async fn unpolled_old_flow_is_in_the_completion_ticket_and_timeout_is_reported() {
    let core = NativeCoreDevice::compile(&direct_profile());
    let (mut app, flow) = loopback_stream_pair().await;
    let unpolled = core.route_tcp_flow(
        flow,
        NativeTcpFlowTarget {
            host: "127.0.0.1".into(),
            port: 9,
            process_name: None,
            process_path: None,
        },
    );
    let error = core
        .cutover_sessions_and_wait(Duration::from_millis(20))
        .await
        .unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    core.close();
    drop(unpolled);
    core.cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(app.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(core.inner.sessions.udp_sessions.admission_epoch().is_none());
}

#[tokio::test]
async fn async_cutover_waits_prior_sync_cutover_but_not_new_connections() {
    let core = NativeCoreDevice::compile(&direct_profile());
    let (cancelled_tx, cancelled_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let retiring = tokio::spawn(core.tracked_session(move |runtime| async move {
        runtime.connection_cancellation().cancelled().await;
        cancelled_tx.send(()).unwrap();
        release_rx.await.unwrap();
    }));
    core.apply_profile(&direct_profile());
    cancelled_rx.await.unwrap();
    let second_epoch = core.pinned_runtime().connection_cancellation();
    let wait_core = core.clone();
    let waiting = tokio::spawn(async move {
        wait_core
            .cutover_sessions_and_wait(Duration::from_secs(2))
            .await
    });
    second_epoch.cancelled().await;
    assert!(
        !waiting.is_finished(),
        "prior generation has not released its resources"
    );

    let (target, echo) = spawn_echo_server().await;
    let (mut app, flow) = loopback_stream_pair().await;
    let new_flow = tokio::spawn(core.route_tcp_flow(
        flow,
        NativeTcpFlowTarget {
            host: target.ip().to_string(),
            port: target.port(),
            process_name: None,
            process_path: None,
        },
    ));
    app.write_all(b"new").await.unwrap();
    let mut reply = [0; 3];
    app.read_exact(&mut reply).await.unwrap();
    release_tx.send(()).unwrap();
    waiting.await.unwrap().unwrap();
    retiring.await.unwrap();
    assert_eq!(core.state_audit().tcp_relay_sessions.active, 1);
    app.write_all(b"new").await.unwrap();
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"new");
    core.cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
    new_flow.await.unwrap().unwrap_err();
    echo.abort();
}

#[tokio::test]
async fn async_cutover_waits_for_the_udp_transport_destructor() {
    use crate::egress::EgressRuntime;
    use crate::outbound::{
        BoxedOutboundStream, OutboundConnector, OutboundDatagramReceiver, OutboundDatagramSender,
        OutboundDatagramTransport, OutboundFuture,
    };
    use crate::runtime::RuntimeSnapshot;

    #[derive(Debug)]
    struct DropConnector {
        dropped: Arc<AtomicBool>,
        connected: Arc<Notify>,
    }
    struct DropSender(Arc<AtomicBool>);
    impl Drop for DropSender {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl OutboundDatagramSender for DropSender {
        fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
            crate::outbound::DatagramSendCancellation::AtomicDatagram
        }

        fn send<'a>(&'a self, _: &'a ConnectTarget, _: &'a [u8]) -> DatagramFuture<'a, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
    }
    struct PendingReceiver;
    impl OutboundDatagramReceiver for PendingReceiver {
        fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
            Box::pin(std::future::pending())
        }
    }
    impl OutboundConnector for DropConnector {
        fn connect_stream<'a>(
            &'a self,
            _: &'a EgressRuntime,
            _: &'a ConnectTarget,
            _: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(std::future::ready(Err(
                crate::outbound::OutboundError::new(
                    crate::outbound::OutboundStage::Config,
                    "UDP-only fixture",
                ),
            )))
        }
        fn supports_udp(&self) -> bool {
            true
        }
        fn connect_datagram<'a>(
            &'a self,
            _: &'a EgressRuntime,
            _: &'a ConnectTarget,
        ) -> OutboundFuture<'a, OutboundDatagramTransport> {
            Box::pin(async move {
                let transport = OutboundDatagramTransport {
                    sender: Box::new(DropSender(self.dropped.clone())),
                    receiver: Box::new(PendingReceiver),
                };
                self.connected.notify_one();
                Ok(transport)
            })
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let connected = Arc::new(Notify::new());
    let mut profile = direct_profile();
    profile.rules = vec![match_rule("TrackedUdp")].into();
    let mut snapshot = RuntimeSnapshot::compile(
        &profile,
        NativeCoreEgressConfig::default(),
        NativeCoreCaptureConfig::default(),
        None,
        crate::policy_group::GroupStateTable::default(),
    );
    snapshot.insert_outbound_for_test(
        "TrackedUdp",
        Arc::new(DropConnector {
            dropped: dropped.clone(),
            connected: connected.clone(),
        }),
    );
    let core = NativeCoreDevice::from_snapshot(snapshot, None, None);
    core.start();
    core.send_udp_flow_datagram(flow_datagram(
        "127.0.0.1:9".parse().unwrap(),
        54307,
        b"probe",
    ))
    .await
    .unwrap();
    connected.notified().await;
    assert!(!dropped.load(Ordering::SeqCst));
    let report = core
        .cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(report.udp_sessions, 1);
    assert!(
        dropped.load(Ordering::SeqCst),
        "actor transport must be destroyed before success"
    );
}

#[tokio::test]
async fn async_cutover_retires_the_old_tcp_engine_and_pending_syn_state() {
    let core = NativeCoreDevice::compile(&direct_profile());
    let client = CapturedTcpClient {
        core: &core,
        client_ip: Ipv4Addr::new(10, 0, 0, 2),
        server_ip: Ipv4Addr::LOCALHOST,
        client_port: 54308,
        server_port: 9,
    };
    client.execute("old-syn", 1000, 0, 0x02, &[]).await;
    client
        .drain_until(|packet| captured_tcp_flags(packet) & 0x12 == 0x12)
        .await;
    let old = core.packet_tcp_engine().unwrap();
    core.cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(core.state_audit().packet_tcp_sessions, 0);
    assert!(core.packet_tcp_engine().is_none());
    let new = core.ensure_packet_tcp(PacketQueue::ONLY).unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    core.close();
    core.cutover_sessions_and_wait(Duration::from_secs(2))
        .await
        .unwrap();
}

/// A session an IP rule claimed after its name was resolved keeps its route
/// across a selection: the question is asked again with the address the
/// rules were given, so the same rule answers. Asked without it, the IP
/// rules could not match and the session would look re-routed and end --
/// which is every name's session under a profile with a GEOIP rule.
#[test]
fn a_session_an_ip_rule_claimed_keeps_its_route_across_a_selection() {
    use crate::rule_engine::{RuleAddress, TransportNetwork};
    use crate::session_registry::RouteQuestion;

    let mut profile = RuntimeProfile::new("ip-rule-then-group");
    profile.groups = vec![policy_group(
        "Choice",
        PolicyGroupKind::Select,
        &["REJECT", "DIRECT"],
    )];
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::IpCidr,
            payload: Some("203.0.113.0/24"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        match_rule("Choice"),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);
    let question = RouteQuestion {
        input: crate::RouteMatchInput {
            host: Some("named.example".into()),
            destination_port: Some(443),
            network: Some(TransportNetwork::Tcp),
            ..Default::default()
        },
        address: Some(RuleAddress {
            from_rule: 0,
            ip: Some("203.0.113.7".parse().unwrap()),
        }),
        dial_target: crate::target::ConnectTarget {
            host: "named.example".into(),
            port: 443,
        },
    };
    let runtime = core.pinned_runtime();
    assert!(
        super::keeps_its_route(&runtime, &question, "DIRECT"),
        "the IP rule still claims it"
    );
    assert!(
        !super::keeps_its_route(
            &runtime,
            &RouteQuestion {
                address: None,
                ..question.clone()
            },
            "DIRECT"
        ),
        "without the address the rules fall through to the group"
    );

    core.select_group_member("Choice", "DIRECT")
        .expect("select DIRECT");
    let runtime = core.pinned_runtime();
    assert!(
        super::keeps_its_route(&runtime, &question, "DIRECT"),
        "and the selection the rule never reads cannot move it"
    );
    core.close();
}

/// A selection leaves the UDP sessions it does not re-route alone, egress
/// port included: a flow a rule sends DIRECT keeps the four-tuple its peer
/// tracks it by, which is what a QUIC connection or a game session is.
#[tokio::test]
async fn selector_switch_keeps_a_udp_session_it_does_not_reroute() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = peer.local_addr().unwrap();
    let mut profile = two_direct_nodes_fallback_profile();
    profile.groups[0].kind = PolicyGroupKind::Select;
    let group = profile.groups[0].name.clone();
    profile.rules = vec![
        dst_port_rule(&target.port().to_string(), "DIRECT"),
        match_rule(&group),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);
    let before = udp_round_trip_from(&core, &peer, 54309).await;

    let prepared = core
        .prepare_policy_update(&[crate::CorePolicyUpdate::SelectGroup {
            group: group.clone(),
            member: "NodeB".into(),
        }])
        .expect("prepare the selection");
    let report = core.apply_policy_update(prepared).expect("apply it");
    assert!(
        report.retirement.wait(Duration::from_secs(2)).await,
        "the kept session took its place in the epoch the switch opened"
    );

    assert_eq!(
        core.status().udp_sessions,
        1,
        "the rule that routes it never reads the group"
    );
    let after = udp_round_trip_from(&core, &peer, 54309).await;
    assert_eq!(before, after, "and it kept the session, so also its port");
    core.close();
}

/// Changing the mode gives the Core a new DNS generation and retires the one
/// its live UDP sessions resolve their targets through, so they end with it
/// even where the route they end up with is the same one; the next datagram
/// rebuilds the session. Selecting a node leaves that generation alone, which
/// is what lets those sessions keep their port.
#[tokio::test]
async fn a_mode_change_ends_the_udp_sessions_with_their_dns_generation() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    udp_round_trip(&core, &peer, 54310).await;
    assert_eq!(core.status().udp_sessions, 1);

    let prepared = core
        .prepare_policy_update(&[crate::CorePolicyUpdate::TrafficPolicy {
            mode: TrafficPolicyMode::Global,
            global_outbound: Some("DIRECT".into()),
        }])
        .expect("prepare the mode change");
    core.apply_policy_update(prepared).expect("apply it");

    assert_eq!(
        core.status().udp_sessions,
        0,
        "the generation they resolved through is gone"
    );
    udp_round_trip(&core, &peer, 54310).await;
    core.close();
}

/// A kept UDP session goes on resolving its targets: it does that through the
/// DNS generation that admitted it, and a selection leaves that generation --
/// with its cache -- in place, because what the service reads of the policy
/// is the mode and the global outbound, and selections it reads live.
#[tokio::test]
async fn a_kept_udp_session_still_resolves_its_name_after_a_selection() {
    use crate::dns::config::DnsHost;

    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = peer.local_addr().unwrap().port();
    let mut profile = two_direct_nodes_fallback_profile();
    profile.groups[0].kind = PolicyGroupKind::Select;
    let group = profile.groups[0].name.clone();
    profile.dns.enabled = true;
    profile.dns.hosts = vec![DnsHost {
        pattern: "named.example".parse().unwrap(),
        addresses: vec![Ipv4Addr::LOCALHOST.into()],
    }];
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::Domain,
            payload: Some("named.example"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        match_rule(&group),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);
    let before = named_udp_round_trip(&core, &peer, port, 54311).await;

    core.select_group_member(&group, "NodeB")
        .expect("select NodeB");

    assert_eq!(
        core.status().udp_sessions,
        1,
        "its rule never read the group"
    );
    let after = named_udp_round_trip(&core, &peer, port, 54311).await;
    assert_eq!(
        before, after,
        "the name resolved again through the generation it was admitted in"
    );
    core.close();
}

/// [`udp_round_trip_from`] for a target the client named, which the session
/// resolves on every datagram.
async fn named_udp_round_trip(
    core: &NativeCoreDevice,
    peer: &UdpSocket,
    port: u16,
    source_port: u16,
) -> SocketAddr {
    core.send_udp_flow_datagram(NativeUdpFlowDatagram {
        flow_id: Some(format!("named-{source_port}")),
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, source_port)),
        target: NativeUdpFlowTarget {
            host: "named.example".into(),
            port,
            process_name: None,
            process_path: None,
        },
        payload: b"request".to_vec(),
    })
    .await
    .unwrap();
    let mut buffer = [0; 32];
    let (read, client) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    peer.send_to(&buffer[..read], client).await.unwrap();
    let replies = core
        .drain_pending_udp_flow_responses(32, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(replies.len(), 1);
    client
}

/// Selecting a node leaves the DNS generation answering: it is the same
/// generation, so a name resolved after the selection still reaches the
/// upstream. Retiring it here would take the cache and the connections to
/// the servers with it -- and the live service is the one the new policy
/// uses, because a selection does not rebuild it.
#[tokio::test]
async fn a_selection_leaves_the_dns_generation_answering() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mut profile = two_direct_nodes_fallback_profile();
    profile.groups[0].kind = PolicyGroupKind::Select;
    let group = profile.groups[0].name.clone();
    profile.dns.enabled = true;
    profile.dns.nameservers = vec![crate::dns::config::DnsUpstream {
        transport: crate::dns::config::DnsTransport::Udp,
        host: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        path: String::new(),
        server_name: None,
        route: Some(crate::dns::config::DnsRoute::Direct),
    }];
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::Domain,
            payload: Some("named.example"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        match_rule(&group),
    ]
    .into();
    let core = NativeCoreDevice::compile(&profile);

    core.select_group_member(&group, "NodeB")
        .expect("select NodeB");

    let sender = core.clone();
    let send = tokio::spawn(async move {
        sender
            .send_udp_flow_datagram(NativeUdpFlowDatagram {
                flow_id: Some("named-after-switch".into()),
                source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54313)),
                target: NativeUdpFlowTarget {
                    host: "named.example".into(),
                    port: 9,
                    process_name: None,
                    process_path: None,
                },
                payload: b"request".to_vec(),
            })
            .await
    });
    let mut buffer = [0_u8; 1500];
    let (length, asked_from) = timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
        .await
        .expect("the name is asked of the upstream after the selection")
        .unwrap();
    let query = crate::dns::wire::decode(&buffer[..length]).unwrap();
    let answer = crate::dns::wire::response(&query, hickory_proto::op::ResponseCode::NXDomain);
    upstream
        .send_to(&crate::dns::wire::encode(&answer).unwrap(), asked_from)
        .await
        .unwrap();
    let _ = timeout(Duration::from_secs(2), send).await;
    core.close();
}
