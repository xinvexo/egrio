//! The packet pump's own I/O for established captured flows: once an
//! association's transport is up (a DIRECT socket, a Hysteria2 session), the
//! pump sends the flow's datagrams on it and reads the replies itself.

use tokio::sync::mpsc;

use super::*;

/// A device fed and drained through channels, so a test can answer what the
/// pump wrote before handing it the next packet.
#[derive(Debug)]
pub(super) struct ChannelPacketDevice {
    incoming: mpsc::UnboundedReceiver<crate::packet::ReceivedPacket>,
    pending: Option<crate::packet::ReceivedPacket>,
    written: mpsc::UnboundedSender<Vec<u8>>,
}

impl ChannelPacketDevice {
    /// The device, the sender that feeds it and the receiver of what it
    /// writes.
    pub(super) fn new() -> (
        Self,
        mpsc::UnboundedSender<crate::packet::ReceivedPacket>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (inject, incoming) = mpsc::unbounded_channel();
        let (written, written_rx) = mpsc::unbounded_channel();
        let device = Self {
            incoming,
            pending: None,
            written,
        };
        (device, inject, written_rx)
    }
}

impl crate::packet::PacketDevice for ChannelPacketDevice {
    fn name(&self) -> &str {
        "channel-tun"
    }

    fn try_recv(&mut self) -> Result<Option<crate::packet::ReceivedPacket>, String> {
        Ok(self
            .pending
            .take()
            .or_else(|| self.incoming.try_recv().ok()))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<crate::packet::PacketSend, String> {
        let _ = self.written.send(packet.to_vec());
        Ok(crate::packet::PacketSend::Sent)
    }

    fn ready(&mut self, interest: crate::packet::PacketInterest) -> crate::packet::PacketReady<'_> {
        Box::pin(async move {
            if interest.read && self.pending.is_none() {
                self.pending = self.incoming.recv().await;
                if self.pending.is_none() {
                    std::future::pending::<()>().await;
                }
            } else if !interest.write {
                std::future::pending::<()>().await;
            }
            Ok(())
        })
    }
}

struct PumpHarness {
    core: Arc<NativeCoreDevice>,
    inject: mpsc::UnboundedSender<crate::packet::ReceivedPacket>,
    written: mpsc::UnboundedReceiver<Vec<u8>>,
    stop: CancellationToken,
    pump: tokio::task::JoinHandle<NativeCoreDeviceRunReport>,
}

impl PumpHarness {
    fn start(profile: &RuntimeProfile) -> Self {
        Self::on(NativeCoreDevice::compile(profile))
    }

    fn on(core: NativeCoreDevice) -> Self {
        let core = Arc::new(core);
        let (mut device, inject, written) = ChannelPacketDevice::new();
        let stop = CancellationToken::new();
        let pump = tokio::spawn({
            let core = Arc::clone(&core);
            let stop = stop.clone();
            async move {
                core.run_packet_queue(PacketQueue::ONLY, &mut device, stop)
                    .await
            }
        });
        Self {
            core,
            inject,
            written,
            stop,
            pump,
        }
    }

    /// The next UDP packet the pump writes: its source, destination and payload.
    async fn next_udp(&mut self) -> (SocketAddr, SocketAddr, Vec<u8>) {
        loop {
            let packet = timeout(Duration::from_secs(5), self.written.recv())
                .await
                .expect("the pump writes a reply")
                .expect("the pump is running");
            if let Some((source, destination, payload)) = crate::packet::udp_endpoints(&packet) {
                return (source, destination, packet[payload].to_vec());
            }
        }
    }

    async fn stop(self) -> NativeCoreDeviceRunReport {
        self.stop.cancel();
        let report = self.pump.await.unwrap();
        self.core.close();
        report
    }
}

/// Echoes each datagram back with a prefix and reports the source it came from.
pub(super) async fn echo_once(peer: &UdpSocket) -> SocketAddr {
    let mut buffer = [0_u8; 2048];
    let (read, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buffer))
        .await
        .expect("the peer gets the datagram")
        .unwrap();
    let mut reply = b"echo:".to_vec();
    reply.extend_from_slice(&buffer[..read]);
    peer.send_to(&reply, from).await.unwrap();
    from
}

pub(super) const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

pub(super) fn datagram_to(peer: SocketAddr, source_port: u16, payload: &[u8]) -> Vec<u8> {
    let IpAddr::V4(peer_ip) = peer.ip() else {
        unreachable!("the peer listens on IPv4");
    };
    ipv4_udp_packet(CLIENT, peer_ip, source_port, peer.port(), payload)
}

#[tokio::test]
async fn an_established_direct_flow_is_sent_and_read_by_the_pump() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut harness = PumpHarness::start(&direct_profile());
    let client = SocketAddr::from((CLIENT, 40_000));

    // The first datagram opens the association through the session actor.
    harness
        .inject
        .send(datagram_to(peer_addr, 40_000, b"one").into())
        .unwrap();
    let mapped = echo_once(&peer).await;
    assert_eq!(
        harness.next_udp().await,
        (peer_addr, client, b"echo:one".to_vec())
    );
    assert_eq!(
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test(),
        0
    );

    // Once the transport is up, the pump sends on the same mapping itself
    // and frames the replies it reads.
    for payload in [&b"two"[..], b"three", b"four"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_000, payload).into())
            .unwrap();
        assert_eq!(
            echo_once(&peer).await,
            mapped,
            "one mapping serves the flow"
        );
        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(harness.next_udp().await, (peer_addr, client, expected));
    }
    assert!(
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test()
            >= 2
    );
    let session = &harness.core.inner.sessions.udp_sessions.snapshot_for_test()[0];
    assert_eq!(
        session.packets_sent, 4,
        "the pump's sends count with the session's"
    );
    assert_eq!(session.packets_received, 4);

    let report = harness.stop().await;
    assert_eq!(report.packets_action_direct_udp, 4);
}

#[tokio::test]
async fn a_configuration_change_takes_the_flow_from_the_pump() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut harness = PumpHarness::start(&direct_profile());
    let client = SocketAddr::from((CLIENT, 40_001));

    for payload in [&b"a"[..], b"b"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_001, payload).into())
            .unwrap();
        echo_once(&peer).await;
        harness.next_udp().await;
    }
    harness
        .inject
        .send(datagram_to(peer_addr, 40_001, b"c").into())
        .unwrap();
    let old_mapping = echo_once(&peer).await;
    harness.next_udp().await;

    // The cutover closes the old association: the next datagram opens a new
    // one instead of leaving on the closed one's socket.
    harness.core.apply_profile(&direct_profile());
    harness
        .inject
        .send(datagram_to(peer_addr, 40_001, b"d").into())
        .unwrap();
    let new_mapping = echo_once(&peer).await;
    assert_ne!(new_mapping, old_mapping);
    assert_eq!(
        harness.next_udp().await,
        (peer_addr, client, b"echo:d".to_vec())
    );
    harness.stop().await;
}

#[cfg(feature = "server")]
#[tokio::test]
async fn an_established_hysteria2_flow_is_sent_and_read_by_the_pump() {
    use crate::protocols::hysteria2::test_server;

    const AUTH: &str = "pump-hysteria2-auth";
    let server = test_server::spawn(
        test_server::acceptor(AUTH),
        test_server::match_direct_device(),
    )
    .await;
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut profile = RuntimeProfile::new("pump-hysteria2");
    profile.proxies = vec![test_server::proxy_node("Hy2", server, AUTH)];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Hy2",
        no_resolve: false,
    }]
    .into();
    let mut harness = PumpHarness::start(&profile);
    let client = SocketAddr::from((CLIENT, 40_002));

    // The first datagram opens the session through the session actor.
    harness
        .inject
        .send(datagram_to(peer_addr, 40_002, b"one").into())
        .unwrap();
    let relay = echo_once(&peer).await;
    assert_eq!(
        harness.next_udp().await,
        (peer_addr, client, b"echo:one".to_vec())
    );

    // Once the session is up, the pump sends the flow's datagrams into it
    // itself and frames the replies it reads.
    for payload in [&b"two"[..], b"three", b"four"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_002, payload).into())
            .unwrap();
        assert_eq!(echo_once(&peer).await, relay, "one session serves the flow");
        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(harness.next_udp().await, (peer_addr, client, expected));
    }
    assert!(
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test()
            >= 2
    );

    let report = harness.stop().await;
    assert_eq!(report.packets_action_proxy_udp, 4);
    assert_eq!(report.packets_action_direct_udp, 0);
}

/// Strict global mode with no server but the local resolver: the proxy
/// resolves the name, the pump sends to it by name, and it frames the
/// replies, which come from wherever the name led, from the fake IP the
/// client addressed, as the session actor does.
#[cfg(feature = "server")]
#[tokio::test]
async fn replies_to_a_name_the_proxy_resolves_come_from_the_fake_ip() {
    use crate::device::dns_contract_tests::configure_local_dns_answer;
    use crate::protocols::hysteria2::test_server;

    const AUTH: &str = "pump-hysteria2-auth";
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    // The node resolves every name to the echo peer's address.
    let mut node_profile = RuntimeProfile::new("pump-hysteria2-node");
    node_profile.rules = direct_profile().rules;
    let _node_dns = configure_local_dns_answer(&mut node_profile, Ipv4Addr::LOCALHOST).await;
    let node = NativeCoreDevice::compile(&node_profile);
    node.start();
    let server = test_server::spawn(test_server::acceptor(AUTH), node).await;

    // The client's DNS is off: only the local resolver answers, which strict
    // global mode never asks, so the node resolves the name.
    let mut profile = RuntimeProfile::new("pump-hysteria2-strict-global");
    profile.proxies = vec![test_server::proxy_node("Hy2", server, AUTH)];
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("Hy2".into());
    let mut harness = PumpHarness::start(&profile);
    let fake_ip = harness
        .core
        .inner
        .sessions
        .fake_dns
        .allocate_ipv4("echo.pump.test")
        .expect("fake IP allocates");
    let addressed = SocketAddr::from((fake_ip, peer_addr.port()));
    let client = SocketAddr::from((CLIENT, 40_003));

    for payload in [&b"one"[..], b"two", b"three"] {
        harness
            .inject
            .send(datagram_to(addressed, 40_003, payload).into())
            .unwrap();
        echo_once(&peer).await;
        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(harness.next_udp().await, (addressed, client, expected));
    }
    assert!(
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test()
            >= 1,
        "the pump sends to a name the proxy resolves"
    );
    let report = harness.stop().await;
    assert_eq!(report.packets_action_proxy_udp, 3);
}

/// Says every flow belongs to one process and counts the flows it scans.
#[derive(Debug, Default)]
struct OwnEveryFlow {
    scanned: std::sync::atomic::AtomicUsize,
}

impl crate::attribution::FlowScanner for OwnEveryFlow {
    fn scan(
        &self,
        flows: &[crate::attribution::FlowKey],
        _: Duration,
        _: &std::sync::atomic::AtomicBool,
    ) -> Vec<Option<crate::attribution::ProcessInfo>> {
        self.scanned.fetch_add(flows.len(), Ordering::SeqCst);
        flows
            .iter()
            .map(|_| {
                Some(crate::attribution::ProcessInfo {
                    name: Some("Probe".into()),
                    path: None,
                })
            })
            .collect()
    }
}

/// While a rule reads the process, a learned flow's route is pinned: its
/// datagrams go out on the pump without asking for their owner again, even
/// after the owner's cached answer has aged out.
#[tokio::test]
async fn a_learned_flow_needs_no_owner_while_routing_reads_the_process() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut profile = RuntimeProfile::new("process-routed-udp");
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::ProcessName,
            payload: Some("Probe"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        },
    ]
    .into();
    let scanner = Arc::new(OwnEveryFlow::default());
    let mut harness = PumpHarness::on(NativeCoreDevice::from_start_inputs(
        crate::CoreStartInputs {
            profile,
            egress: Default::default(),
            egress_socket_guard: None,
            capture: Default::default(),
            flow_scanner: Some(scanner.clone()),
            fake_ip_mappings: None,
        },
    ));
    let client = SocketAddr::from((CLIENT, 40_004));
    for payload in [&b"one"[..], b"two"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_004, payload).into())
            .unwrap();
        echo_once(&peer).await;
        assert_eq!(harness.next_udp().await.1, client);
    }
    let scanned = scanner.scanned.load(Ordering::SeqCst);
    assert!(scanned >= 1, "the flow's owner was looked up once");

    // Past the owner's cached answer (250 ms), a datagram of the learned flow
    // still goes out at once and asks for no scan.
    sleep(Duration::from_millis(400)).await;
    harness
        .inject
        .send(datagram_to(peer_addr, 40_004, b"three").into())
        .unwrap();
    echo_once(&peer).await;
    assert_eq!(harness.next_udp().await.2, b"echo:three");
    assert_eq!(scanner.scanned.load(Ordering::SeqCst), scanned);
    harness.stop().await;
}

/// A train never overtakes a datagram of its flow read before it in the
/// same batch: the peer gets them in the order the client sent them.
#[tokio::test]
async fn a_train_keeps_its_place_behind_its_flows_earlier_datagram() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut harness = PumpHarness::start(&direct_profile());
    for payload in [&b"one"[..], b"two"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_005, payload).into())
            .unwrap();
        echo_once(&peer).await;
        harness.next_udp().await;
    }
    // Both queued before the pump runs again, so it reads them together.
    harness
        .inject
        .send(datagram_to(peer_addr, 40_005, b"first").into())
        .unwrap();
    let train: Vec<u8> = (0..1500_u32).map(|i| i as u8).collect();
    harness
        .inject
        .send(crate::packet::ReceivedPacket {
            bytes: datagram_to(peer_addr, 40_005, &train),
            udp_segment: Some(1000),
        })
        .unwrap();
    let mut buffer = [0_u8; 2048];
    for expected in [&b"first"[..], &train[..1000], &train[1000..]] {
        let (read, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buffer))
            .await
            .expect("the peer gets each datagram")
            .unwrap();
        assert_eq!(&buffer[..read], expected);
    }
    harness.stop().await;
}

/// A turn reads at most [`PUMP_BATCH`] times and at most
/// [`PUMP_DATAGRAM_BATCH`] datagrams, because a read the platform glued
/// together carries many and each costs the pipeline a packet's work. The
/// bound ends a turn; it loses nothing.
#[tokio::test]
async fn trains_past_a_turns_datagram_bound_all_arrive() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    // The pump sends every train before this test reads the first datagram,
    // so the peer's buffer has to hold them all: what a socket's own buffer
    // drops is not the pump's loss. Windows gives a UDP socket 64 KiB, less
    // than the trains carry.
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(4 << 20)
        .unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut harness = PumpHarness::start(&direct_profile());
    // Learn the flow first, so its trains go out on its association instead
    // of through the session's mailbox.
    for payload in [&b"one"[..], b"two"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_009, payload).into())
            .unwrap();
        echo_once(&peer).await;
        harness.next_udp().await;
    }

    let segment = 100;
    let per_train = 64;
    let trains = 2 * super::super::pump::PUMP_DATAGRAM_BATCH / per_train;
    let payload: Vec<u8> = (0..(segment * per_train) as u32)
        .map(|index| index as u8)
        .collect();
    for _ in 0..trains {
        harness
            .inject
            .send(crate::packet::ReceivedPacket {
                bytes: datagram_to(peer_addr, 40_009, &payload),
                udp_segment: Some(segment),
            })
            .unwrap();
    }

    let mut buffer = [0_u8; 2048];
    for _ in 0..trains * per_train {
        timeout(Duration::from_secs(5), peer.recv_from(&mut buffer))
            .await
            .expect("every datagram of every train arrives")
            .unwrap();
    }
    let report = harness.stop().await;
    assert_eq!(
        report.packets_received as usize,
        2 + trains * per_train,
        "every datagram was read, across as many turns as the bound took"
    );
}

#[tokio::test]
async fn a_learned_flows_train_goes_out_whole_on_its_association() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut harness = PumpHarness::start(&direct_profile());
    let client = SocketAddr::from((CLIENT, 40_002));
    for payload in [&b"one"[..], b"two"] {
        harness
            .inject
            .send(datagram_to(peer_addr, 40_002, payload).into())
            .unwrap();
        echo_once(&peer).await;
        assert_eq!(harness.next_udp().await.1, client);
    }

    // Three datagrams the client's socket sent as one train (a TUN's
    // GSO_UDP_L4 frame): the peer gets each one, in order, from the flow's
    // mapping.
    let payload: Vec<u8> = (0..2500_u32).map(|i| i as u8).collect();
    harness
        .inject
        .send(crate::packet::ReceivedPacket {
            bytes: datagram_to(peer_addr, 40_002, &payload),
            udp_segment: Some(1000),
        })
        .unwrap();
    let mut buffer = [0_u8; 2048];
    for chunk in payload.chunks(1000) {
        let (read, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buffer))
            .await
            .expect("the peer gets each datagram of the train")
            .unwrap();
        assert_eq!(&buffer[..read], chunk);
    }

    let report = harness.stop().await;
    assert_eq!(report.packets_received, 5);
    assert_eq!(report.packets_action_direct_udp, 5);
}

const SHADOWSOCKS_PASSWORD: &str = "pump-test-password";

/// A Shadowsocks (aes-128-gcm) UDP server that answers one packet with its
/// payload behind "echo:", sealed for the address the client named, and
/// reports the client's socket.
async fn shadowsocks_echo_once(server: &UdpSocket) -> SocketAddr {
    use crate::protocols::shadowsocks::codec::{
        open_udp_packet, parse_cipher, seal_udp_packet, shadowsocks_key,
    };
    let method = parse_cipher("aes-128-gcm").unwrap();
    let key = shadowsocks_key(method, SHADOWSOCKS_PASSWORD);
    let mut buffer = [0_u8; 2048];
    let (read, from) = timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
        .await
        .expect("the node gets the packet")
        .unwrap();
    let (target, payload) = open_udp_packet(method, &key, &buffer[..read]).unwrap();
    let mut reply = b"echo:".to_vec();
    reply.extend_from_slice(&payload);
    let packet = seal_udp_packet(method, &key, &target, &reply).unwrap();
    server.send_to(&packet, from).await.unwrap();
    from
}

fn shadowsocks_profile(node: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("shadowsocks-pump");
    profile.proxies = vec![ProxyNode {
        id: "node-ss".into(),
        name: "SS".into(),
        protocol: ProxyProtocol::Shadowsocks,
        server: Some(node.ip().to_string()),
        port: Some(node.port()),
        options: serde_json::json!({
            "cipher": "aes-128-gcm",
            "password": SHADOWSOCKS_PASSWORD,
            "udp": true,
        }),
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "SS",
        no_resolve: false,
    }]
    .into();
    profile
}

#[tokio::test]
async fn an_established_shadowsocks_flow_is_sealed_and_opened_by_the_pump() {
    let node = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut harness = PumpHarness::start(&shadowsocks_profile(node.local_addr().unwrap()));
    let client = SocketAddr::from((CLIENT, 40_003));
    let target = SocketAddr::from(([198, 51, 100, 7], 5353));

    let mut mapping = None;
    for (index, payload) in [&b"one"[..], b"two", b"three"].into_iter().enumerate() {
        harness
            .inject
            .send(datagram_to(target, 40_003, payload).into())
            .unwrap();
        let from = shadowsocks_echo_once(&node).await;
        assert_eq!(*mapping.get_or_insert(from), from, "one association");
        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(harness.next_udp().await, (target, client, expected));
        if index == 0 {
            assert_eq!(
                harness
                    .core
                    .inner
                    .sessions
                    .udp_sessions
                    .pump_sent_for_test(),
                0,
                "the first datagram opens the association through its actor"
            );
        }
    }
    assert!(
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test()
            >= 1,
        "the pump seals the flow's later datagrams itself"
    );

    let report = harness.stop().await;
    assert_eq!(report.packets_action_proxy_udp, 3);
}

/// A SOCKS5 proxy that serves UDP ASSOCIATE (RFC 1928 §7) without
/// authentication. Each association gets its own relay, which answers every
/// request with its payload behind "echo<n>:" (n counts associations from
/// 1), from the address the request named. A permit on `close` ends the
/// oldest open association: its control connection and its relay.
struct Socks5Proxy {
    addr: SocketAddr,
    close: mpsc::UnboundedSender<()>,
}

impl Socks5Proxy {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (close, mut closes) = mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            let mut open = VecDeque::new();
            let mut associations = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        associations += 1;
                        let control = accepted.unwrap().0;
                        open.push_back(Self::associate(control, associations).await);
                    }
                    Some(()) = closes.recv() => {
                        // Dropping the control connection is the EOF that
                        // ends the association.
                        if let Some((_control, relay)) = open.pop_front() {
                            relay.abort();
                        }
                    }
                }
            }
        });
        Self { addr, close }
    }

    async fn associate(
        mut control: tokio::net::TcpStream,
        association: u32,
    ) -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
        let mut greeting = [0_u8; 3];
        control.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00], "no-auth greeting");
        control.write_all(&[0x05, 0x00]).await.unwrap();
        let mut request = [0_u8; 10];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(request[..4], [0x05, 0x03, 0x00, 0x01], "UDP ASSOCIATE");
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&reply).await.unwrap();
        let relay = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            loop {
                let (read, client) = relay.recv_from(&mut buffer).await.unwrap();
                // [RSV RSV FRAG] and an IPv4 target: answer from it.
                let mut answer = buffer[..10].to_vec();
                answer.extend_from_slice(format!("echo{association}:").as_bytes());
                answer.extend_from_slice(&buffer[10..read]);
                relay.send_to(&answer, client).await.unwrap();
            }
        });
        (control, relay)
    }
}

fn socks5_profile(proxy: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("socks5-pump");
    profile.proxies = vec![ProxyNode {
        id: "node-socks".into(),
        name: "Socks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy.ip().to_string()),
        port: Some(proxy.port()),
        options: serde_json::json!({ "udp": true }),
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Socks",
        no_resolve: false,
    }]
    .into();
    profile
}

#[tokio::test]
async fn an_established_socks5_flow_is_driven_by_the_pump_until_the_proxy_ends_it() {
    let proxy = Socks5Proxy::start().await;
    let mut harness = PumpHarness::start(&socks5_profile(proxy.addr));
    let client = SocketAddr::from((CLIENT, 40_004));
    let target = SocketAddr::from(([198, 51, 100, 7], 5353));
    let pump_sent = |harness: &PumpHarness| {
        harness
            .core
            .inner
            .sessions
            .udp_sessions
            .pump_sent_for_test()
    };

    for payload in [&b"one"[..], b"two", b"three"] {
        harness
            .inject
            .send(datagram_to(target, 40_004, payload).into())
            .unwrap();
        let mut expected = b"echo1:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(harness.next_udp().await, (target, client, expected));
        if payload == b"one" {
            assert_eq!(
                pump_sent(&harness),
                0,
                "the first datagram opens the association through its actor"
            );
        }
    }
    assert!(
        pump_sent(&harness) >= 1,
        "the pump sends the later datagrams"
    );

    // The proxy ends the association: the flow's next datagram builds a new
    // one rather than going into the closed relay.
    proxy.close.send(()).unwrap();
    let rebuilt = timeout(Duration::from_secs(10), async {
        loop {
            harness
                .inject
                .send(datagram_to(target, 40_004, b"four").into())
                .unwrap();
            if let Ok((_, _, payload)) =
                timeout(Duration::from_millis(200), harness.next_udp()).await
            {
                if payload == b"echo2:four" {
                    break;
                }
            }
        }
    })
    .await;
    assert!(rebuilt.is_ok(), "a new association answers the flow");

    harness.stop().await;
}
