//! A capture with several queues: each queue's pump runs on an executor of
//! its own, a TCP flow stays with the queue whose engine holds it, and a
//! client socket keeps one UDP association whichever queue carries its
//! datagrams.

use tokio::sync::mpsc;

use super::pump_udp::{datagram_to, echo_once, ChannelPacketDevice, CLIENT};
use super::*;

/// The queues' executors, one worker each as the SDK runs them; shut down
/// without blocking, since a test drops them inside its own runtime.
struct Executors(Vec<tokio::runtime::Runtime>);

impl Drop for Executors {
    fn drop(&mut self) {
        for runtime in self.0.drain(..) {
            runtime.shutdown_background();
        }
    }
}

struct QueuesHarness {
    core: NativeCoreDevice,
    inject: Vec<mpsc::UnboundedSender<crate::packet::ReceivedPacket>>,
    written: Vec<mpsc::UnboundedReceiver<Vec<u8>>>,
    stop: CancellationToken,
    run: tokio::task::JoinHandle<NativeCoreDeviceRunReport>,
    _executors: Executors,
}

impl QueuesHarness {
    /// Serves `count` queues, returning once every queue's pump is up with
    /// its TCP engine.
    async fn start(profile: &RuntimeProfile, count: usize) -> Self {
        let executors = Executors(
            (0..count)
                .map(|_| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(1)
                        .enable_all()
                        .build()
                        .unwrap()
                })
                .collect(),
        );
        let core = NativeCoreDevice::compile(profile);
        let mut inject = Vec::new();
        let mut written = Vec::new();
        let mut queues = Vec::new();
        for executor in &executors.0 {
            let (device, feed, writes) = ChannelPacketDevice::new();
            inject.push(feed);
            written.push(writes);
            let device: Box<dyn crate::packet::PacketDevice> = Box::new(device);
            queues.push((device, executor.handle().clone()));
        }
        let stop = CancellationToken::new();
        let run = tokio::spawn({
            let core = core.clone();
            let stop = stop.clone();
            async move { core.run_packet_queues(queues, stop).await }
        });
        timeout(Duration::from_secs(5), async {
            while core.packet_tcp_engines_up() < count {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("every queue's pump starts");
        Self {
            core,
            inject,
            written,
            stop,
            run,
            _executors: executors,
        }
    }

    /// The next packet queue `queue`'s device writes that `wanted` accepts.
    async fn next_written(&mut self, queue: usize, wanted: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            loop {
                let packet = self.written[queue]
                    .recv()
                    .await
                    .expect("the pump is running");
                if wanted(&packet) {
                    return packet;
                }
            }
        })
        .await
        .expect("the queue writes the packet")
    }

    async fn stop(self) -> NativeCoreDeviceRunReport {
        self.stop.cancel();
        let report = self.run.await.unwrap();
        self.core.close();
        report
    }
}

fn is_udp(packet: &[u8]) -> bool {
    crate::packet::udp_endpoints(packet).is_some()
}

fn is_tcp_reset(packet: &[u8]) -> bool {
    packet.get(9) == Some(&6) && captured_tcp_flags(packet) & 0x04 != 0
}

#[tokio::test]
async fn a_client_socket_keeps_one_association_across_queues() {
    let first_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let second_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut harness = QueuesHarness::start(&direct_profile(), 2).await;
    let client = SocketAddr::from((CLIENT, 40_000));

    // The client socket's first datagram arrives on queue 0, which opens the
    // association and takes its replies.
    let first_addr = first_peer.local_addr().unwrap();
    harness.inject[0]
        .send(datagram_to(first_addr, 40_000, b"one").into())
        .unwrap();
    let mapped = echo_once(&first_peer).await;
    let reply = harness.next_written(0, is_udp).await;
    let (source, destination, payload) = crate::packet::udp_endpoints(&reply).unwrap();
    assert_eq!((source, destination), (first_addr, client));
    assert_eq!(&reply[payload], b"echo:one");

    // The same socket's datagram to another remote hashes to queue 1: the
    // remote sees the same mapping (EIM), and the reply still comes back
    // through queue 0.
    let second_addr = second_peer.local_addr().unwrap();
    harness.inject[1]
        .send(datagram_to(second_addr, 40_000, b"two").into())
        .unwrap();
    assert_eq!(
        echo_once(&second_peer).await,
        mapped,
        "one mapping for every remote, whichever queue carries the datagram"
    );
    let reply = harness.next_written(0, is_udp).await;
    let (source, destination, payload) = crate::packet::udp_endpoints(&reply).unwrap();
    assert_eq!((source, destination), (second_addr, client));
    assert_eq!(&reply[payload], b"echo:two");
    assert!(
        harness.written[1].try_recv().is_err(),
        "queue 1 owns no reply"
    );

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
    assert_eq!(report.packets_received, 2);
}

#[tokio::test]
async fn a_tcp_segment_on_another_queue_reaches_the_engine_holding_its_flow() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let mut harness = QueuesHarness::start(&direct_profile(), 2).await;
    let segment = |seq, ack, flags, payload: &[u8]| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            53_123,
            server_port,
            seq,
            ack,
            flags,
            payload,
        )
    };

    // The SYN lands on queue 0, whose engine takes the flow.
    harness.inject[0]
        .send(segment(1000, 0, 0x02, &[]).into())
        .unwrap();
    let syn_ack = harness
        .next_written(0, |packet| captured_tcp_flags(packet) & 0x12 == 0x12)
        .await;
    let server = captured_tcp_sequence_number(&syn_ack).wrapping_add(1);

    // The rest of the handshake and the request land on queue 1, as when the
    // flow's hash collides with one that queue writes: queue 0's engine gets
    // them, and the bytes reach the remote instead of the client a reset.
    harness.inject[1]
        .send(segment(1001, server, 0x10, &[]).into())
        .unwrap();
    harness.inject[1]
        .send(segment(1001, server, 0x18, b"hello").into())
        .unwrap();
    let (mut upstream, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the flow dials the remote")
        .unwrap();
    let mut request = [0_u8; 5];
    timeout(Duration::from_secs(5), upstream.read_exact(&mut request))
        .await
        .expect("the request arrives")
        .unwrap();
    assert_eq!(&request, b"hello");

    // The remote's answer goes out through the queue holding the flow.
    upstream.write_all(b"world").await.unwrap();
    let answer = harness
        .next_written(0, |packet| {
            packet.get(9) == Some(&6) && !captured_tcp_payload(packet).is_empty()
        })
        .await;
    assert_eq!(captured_tcp_payload(&answer), b"world");
    for queue in 0..2 {
        while let Ok(packet) = harness.written[queue].try_recv() {
            assert!(!is_tcp_reset(&packet), "queue {queue} reset the flow");
        }
    }

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
    assert_eq!(report.packets_captured_tcp, 3);
}

#[tokio::test]
async fn a_new_flow_goes_to_the_queue_holding_the_fewest_flows() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let mut harness = QueuesHarness::start(&direct_profile(), 2).await;
    let syn = |client_port| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            client_port,
            server_port,
            1000,
            0,
            0x02,
            &[],
        )
    };
    let syn_ack_to = |client_port: u16| {
        move |packet: &[u8]| {
            captured_tcp_flags(packet) & 0x12 == 0x12
                && packet.get(22..24) == Some(&client_port.to_be_bytes()[..])
        }
    };

    // Both flows' SYNs land on queue 0. The first stays there; queue 1 holds
    // no flow, so it takes the second and writes its SYN|ACK, which is what
    // keeps the flow on queue 1 in a Linux multi-queue TUN.
    harness.inject[0].send(syn(53_001).into()).unwrap();
    harness.next_written(0, syn_ack_to(53_001)).await;
    harness.inject[0].send(syn(53_002).into()).unwrap();
    harness.next_written(1, syn_ack_to(53_002)).await;

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
}

#[cfg(feature = "server")]
#[tokio::test]
async fn a_new_flow_through_a_shared_carrier_goes_to_the_queue_running_it() {
    use crate::protocols::hysteria2::test_server;

    const AUTH: &str = "queues-hysteria2-auth";
    let server = test_server::spawn(
        test_server::acceptor(AUTH),
        test_server::match_direct_device(),
    )
    .await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let mut profile = RuntimeProfile::new("queues-hysteria2");
    profile.proxies = vec![test_server::proxy_node("Hy2", server, AUTH)];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Hy2",
        no_resolve: false,
    }]
    .into();
    let mut harness = QueuesHarness::start(&profile, 2).await;
    let segment = |client_port, seq, ack, flags, payload: &[u8]| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            client_port,
            server_port,
            seq,
            ack,
            flags,
            payload,
        )
    };
    let syn_ack_to = |client_port: u16| {
        move |packet: &[u8]| {
            captured_tcp_flags(packet) & 0x12 == 0x12
                && packet.get(22..24) == Some(&client_port.to_be_bytes()[..])
        }
    };

    // The first flow stays on queue 0, and its request dials the Hysteria2
    // carrier there.
    harness.inject[0]
        .send(segment(53_001, 1000, 0, 0x02, &[]).into())
        .unwrap();
    let syn_ack = harness.next_written(0, syn_ack_to(53_001)).await;
    let server_seq = captured_tcp_sequence_number(&syn_ack).wrapping_add(1);
    harness.inject[0]
        .send(segment(53_001, 1001, server_seq, 0x10, &[]).into())
        .unwrap();
    harness.inject[0]
        .send(segment(53_001, 1001, server_seq, 0x18, b"hello").into())
        .unwrap();
    let (mut upstream, _) = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the flow reaches its target through the carrier")
        .unwrap();
    let mut request = [0_u8; 5];
    upstream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"hello");

    // The second flow's SYN lands on queue 1, which holds no flow, yet queue 0
    // takes it: the carrier its route leads through runs there.
    harness.inject[1]
        .send(segment(53_002, 5000, 0, 0x02, &[]).into())
        .unwrap();
    harness.next_written(0, syn_ack_to(53_002)).await;

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
}

#[tokio::test]
async fn a_new_flow_through_a_vpn_goes_to_the_queue_running_its_session() {
    use crate::protocols::openvpn::test_server::{self, Behavior, PASSWORD, SERVER_IP};

    let server = test_server::start(Behavior::default()).await;
    let mut profile = RuntimeProfile::new("queues-openvpn");
    profile.proxies = vec![test_server::proxy_node(&server.config, PASSWORD)];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "vpn",
        no_resolve: false,
    }]
    .into();
    let mut harness = QueuesHarness::start(&profile, 2).await;
    let segment = |client_port, seq, ack, flags, payload: &[u8]| {
        captured_ipv4_tcp_packet(CLIENT, SERVER_IP, client_port, 7, seq, ack, flags, payload)
    };
    let syn_ack_to = |client_port: u16| {
        move |packet: &[u8]| {
            captured_tcp_flags(packet) & 0x12 == 0x12
                && packet.get(22..24) == Some(&client_port.to_be_bytes()[..])
        }
    };

    // The first flow stays on queue 0, and its request opens the node's
    // session there; the server behind the VPN echoes it.
    harness.inject[0]
        .send(segment(53_001, 1000, 0, 0x02, &[]).into())
        .unwrap();
    let syn_ack = harness.next_written(0, syn_ack_to(53_001)).await;
    let server_seq = captured_tcp_sequence_number(&syn_ack).wrapping_add(1);
    harness.inject[0]
        .send(segment(53_001, 1001, server_seq, 0x10, &[]).into())
        .unwrap();
    harness.inject[0]
        .send(segment(53_001, 1001, server_seq, 0x18, b"hello").into())
        .unwrap();
    let echo = harness
        .next_written(0, |packet| {
            packet.get(9) == Some(&6) && !captured_tcp_payload(packet).is_empty()
        })
        .await;
    assert_eq!(captured_tcp_payload(&echo), b"hello");

    // The second flow's SYN lands on queue 1, which holds no flow, yet queue 0
    // takes it: every flow through the node goes through the session there.
    harness.inject[1]
        .send(segment(53_002, 5000, 0, 0x02, &[]).into())
        .unwrap();
    harness.next_written(0, syn_ack_to(53_002)).await;

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
}

#[cfg(feature = "server")]
#[tokio::test]
async fn a_udp_flow_through_a_shared_carrier_is_answered_by_the_queue_running_it() {
    use crate::protocols::hysteria2::test_server;

    const AUTH: &str = "queues-hysteria2-udp-auth";
    let server = test_server::spawn(
        test_server::acceptor(AUTH),
        test_server::match_direct_device(),
    )
    .await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut profile = RuntimeProfile::new("queues-hysteria2-udp");
    profile.proxies = vec![test_server::proxy_node("Hy2", server, AUTH)];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Hy2",
        no_resolve: false,
    }]
    .into();
    let mut harness = QueuesHarness::start(&profile, 2).await;

    // A TCP flow on queue 0 dials the carrier there.
    let segment = |seq, ack, flags, payload: &[u8]| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            53_001,
            server_port,
            seq,
            ack,
            flags,
            payload,
        )
    };
    harness.inject[0]
        .send(segment(1000, 0, 0x02, &[]).into())
        .unwrap();
    let syn_ack = harness
        .next_written(0, |packet| captured_tcp_flags(packet) & 0x12 == 0x12)
        .await;
    let server_seq = captured_tcp_sequence_number(&syn_ack).wrapping_add(1);
    harness.inject[0]
        .send(segment(1001, server_seq, 0x18, b"hello").into())
        .unwrap();
    timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the flow reaches its target through the carrier")
        .unwrap();

    // A UDP flow whose first datagram lands on queue 1 rides the same carrier,
    // so queue 0 answers it.
    harness.inject[1]
        .send(datagram_to(peer_addr, 40_000, b"one").into())
        .unwrap();
    echo_once(&peer).await;
    let reply = harness.next_written(0, is_udp).await;
    let (source, _, payload) = crate::packet::udp_endpoints(&reply).unwrap();
    assert_eq!(source, peer_addr);
    assert_eq!(&reply[payload], b"echo:one");

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
}

#[tokio::test]
async fn after_a_cutover_new_flows_stay_off_queues_without_an_engine() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let mut harness = QueuesHarness::start(&direct_profile(), 2).await;
    let syn = |client_port| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            client_port,
            server_port,
            1000,
            0,
            0x02,
            &[],
        )
    };
    let syn_ack_to = |client_port: u16| {
        move |packet: &[u8]| {
            captured_tcp_flags(packet) & 0x12 == 0x12
                && packet.get(22..24) == Some(&client_port.to_be_bytes()[..])
        }
    };

    // A cutover retires both engines, and each is made again on its queue's
    // next TCP packet. Until queue 1 sees one, queue 0 keeps the new flows
    // whose SYNs land on it: a flow handed to queue 1 would be lost.
    harness.core.apply_profile(&direct_profile());
    harness.inject[0].send(syn(53_001).into()).unwrap();
    harness.next_written(0, syn_ack_to(53_001)).await;
    harness.inject[0].send(syn(53_002).into()).unwrap();
    harness.next_written(0, syn_ack_to(53_002)).await;

    // A SYN on queue 1 brings its engine up, and it takes new flows again.
    harness.inject[1].send(syn(53_003).into()).unwrap();
    harness.next_written(1, syn_ack_to(53_003)).await;
    harness.inject[0].send(syn(53_004).into()).unwrap();
    harness.next_written(1, syn_ack_to(53_004)).await;

    let report = harness.stop().await;
    assert!(report.shutdown_requested, "{report:?}");
}
