use std::net::SocketAddr;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{mpsc, Semaphore};

use super::frame::{build_udp_packet, parse_udp_datagram};
use super::icmp::EchoRequest;
use super::pipeline::{process_captured_packet, PacketCoreAction, PacketPipelineOutcome};
use crate::dns::resolver::{plan_dns_query, DnsQueryPlan, DnsQueryTransport};
use crate::packet::CapturedPacket;
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;
use crate::udp::{
    drain_pump_replies, send_udp_flow_datagram, PumpReplies, UdpDatagram, UdpTrain,
    PUMP_FLOW_PREFIX,
};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PacketExecutionOutcome {
    pub(crate) pipeline: PacketPipelineOutcome,
    /// Whole IP packets toward the client, before MTU source packetization.
    pub(crate) emitted_packets: Vec<Vec<u8>>,
    pub(crate) bytes_sent: usize,
    pub(crate) bytes_received: usize,
}

/// Packets the Core answers after the packet that asked: a DNS answer from an
/// upstream, a relayed ICMP echo reply.
#[derive(Debug)]
pub(crate) enum Answer {
    /// A UDP datagram the pump fragments to the link MTU.
    Dns(Vec<u8>),
    /// A whole packet no larger than the request that asked for it.
    Echo(Vec<u8>),
}

/// Captured DNS queries the Core answers itself (blocked, Fake-IP, empty,
/// loopback) are answered on the packet pump at once; a query bound for an
/// upstream resolves off the pump, so a slow upstream never stalls other
/// flows, and a relayed echo waits off the pump for its reply. Those answers
/// return through this bounded queue, and at most `IN_FLIGHT` resolve at
/// once; excess requests are dropped like any lost datagram and the client
/// retries.
#[derive(Clone, Debug)]
pub(crate) struct AnswerSink {
    answers: mpsc::Sender<Answer>,
    in_flight: Arc<Semaphore>,
}

impl AnswerSink {
    const IN_FLIGHT: usize = 256;

    pub(crate) fn channel() -> (Self, mpsc::Receiver<Answer>) {
        let (answers, receiver) = mpsc::channel(Self::IN_FLIGHT);
        (
            Self {
                answers,
                in_flight: Arc::new(Semaphore::new(Self::IN_FLIGHT)),
            },
            receiver,
        )
    }
}

/// Executes one packet capture queue `queue` read: the UDP flows it opens
/// hand their replies to that queue's pump.
pub(crate) async fn execute_captured_packet(
    runtime: &NativeCoreRuntime,
    queue: usize,
    packet: &CapturedPacket,
    answers: &AnswerSink,
) -> Result<PacketExecutionOutcome, String> {
    let pipeline = process_captured_packet(runtime, packet)?;

    match pipeline.action {
        PacketCoreAction::DnsCapture if pipeline.transport == "udp" => {
            answer_dns_packet(runtime, packet, pipeline, answers)
        }
        PacketCoreAction::DirectUdp | PacketCoreAction::ProxyUdp if pipeline.transport == "udp" => {
            relay_udp_packet(runtime, queue, packet, pipeline).await
        }
        PacketCoreAction::IcmpEchoReply => Ok(answer_echo(packet, pipeline)),
        PacketCoreAction::IcmpEchoRelay => relay_echo(runtime, packet, pipeline, answers),
        // Captured TCP never reaches this executor: the pump injects it into
        // the TCP engine before packet execution (including TCP/53 —
        // virtual-DNS targets are served on the accepted stream).
        _ => Ok(PacketExecutionOutcome {
            pipeline,
            emitted_packets: Vec::new(),
            bytes_sent: 0,
            bytes_received: 0,
        }),
    }
}

/// How long a relayed echo waits for its reply.
const ECHO_WAIT: std::time::Duration = std::time::Duration::from_secs(4);

/// Answers an echo request to the fake-IP range on the spot: the block is
/// virtual, so there is no host to ask.
fn answer_echo(packet: &CapturedPacket, pipeline: PacketPipelineOutcome) -> PacketExecutionOutcome {
    let emitted_packets: Vec<Vec<u8>> = EchoRequest::parse(&packet.bytes)
        .and_then(|request| request.reply())
        .into_iter()
        .collect();
    let bytes_received = emitted_packets.first().map(Vec::len).unwrap_or(0);
    PacketExecutionOutcome {
        pipeline,
        emitted_packets,
        bytes_sent: 0,
        bytes_received,
    }
}

/// Sends an echo request routed DIRECT over the physical uplink, to the
/// name's address when it was sent to a fake IP; its reply arrives later
/// through `answers`, framed as from the address pinged. A lost or refused
/// echo, or a name that does not resolve, simply gets no reply.
fn relay_echo(
    runtime: &NativeCoreRuntime,
    packet: &CapturedPacket,
    pipeline: PacketPipelineOutcome,
    answers: &AnswerSink,
) -> Result<PacketExecutionOutcome, String> {
    let request = EchoRequest::parse(&packet.bytes).ok_or("ICMP echo request is malformed")?;
    let permit = Arc::clone(&answers.in_flight)
        .try_acquire_owned()
        .map_err(|_| "ICMP echo dropped: answer queue is full".to_string())?;
    let sender = answers.answers.clone();
    let cancel = runtime.connection_cancellation();
    let task_runtime = runtime.clone();
    let bytes_sent = request.payload.len();
    let name = runtime.fake_dns_domain_for_ip(request.destination);
    // Tracked like any Core session, so cutover and close wait for it.
    runtime.task_tracker().spawn(async move {
        let _permit = permit;
        let echo = async {
            let target = match name {
                Some(host) => task_runtime
                    .egress()
                    .udp_direct_addr_for_target(&crate::target::ConnectTarget { host, port: 0 })
                    .await?
                    .ip(),
                None => request.destination,
            };
            task_runtime
                .egress()
                .echo(target, &request.payload, ECHO_WAIT)
                .await
        };
        let echoed = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            echoed = echo => echoed,
        };
        if let Some(reply) = echoed.ok().and_then(|()| request.reply()) {
            let _ = sender.send(Answer::Echo(reply)).await;
        }
    });
    Ok(PacketExecutionOutcome {
        pipeline,
        emitted_packets: Vec::new(),
        bytes_sent,
        bytes_received: 0,
    })
}

fn answer_dns_packet(
    runtime: &NativeCoreRuntime,
    packet: &CapturedPacket,
    pipeline: PacketPipelineOutcome,
    dns: &AnswerSink,
) -> Result<PacketExecutionOutcome, String> {
    let datagram = parse_udp_datagram(&packet.bytes).map_err(|error| error.to_string())?;
    let bytes_sent = datagram.payload.len();
    let plan = plan_dns_query(
        runtime,
        &datagram.payload,
        packet.process_name(),
        packet.process_path(),
        DnsQueryTransport::Udp,
    );
    let query = match plan {
        Ok(DnsQueryPlan::Answered(reply)) => {
            let answer = build_udp_packet(
                datagram.destination_ip,
                datagram.source_ip,
                datagram.destination_port,
                datagram.source_port,
                &reply,
            )
            .map_err(|error| error.to_string());
            let emitted_packets = match answer {
                Ok(answer) => vec![answer],
                Err(_) => {
                    runtime.udp_sessions().record_dns_answer_failure();
                    Vec::new()
                }
            };
            return Ok(PacketExecutionOutcome {
                pipeline,
                bytes_received: emitted_packets.first().map(Vec::len).unwrap_or(0),
                emitted_packets,
                bytes_sent,
            });
        }
        Ok(DnsQueryPlan::Upstream(query)) => query,
        Err(_) => {
            runtime.udp_sessions().record_dns_answer_failure();
            return Ok(PacketExecutionOutcome {
                pipeline,
                emitted_packets: Vec::new(),
                bytes_sent,
                bytes_received: 0,
            });
        }
    };
    let permit = Arc::clone(&dns.in_flight)
        .try_acquire_owned()
        .map_err(|_| "captured DNS query dropped: answer queue is full".to_string())?;
    let answers = dns.answers.clone();
    let cancel = runtime.connection_cancellation();
    let task_runtime = runtime.clone();
    // Tracked like any Core session, so cutover and close wait for it.
    runtime.task_tracker().spawn(async move {
        let _permit = permit;
        let response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            response = query.exchange(&task_runtime) => response,
        };
        let packet = response.and_then(|response| {
            build_udp_packet(
                datagram.destination_ip,
                datagram.source_ip,
                datagram.destination_port,
                datagram.source_port,
                &response,
            )
            .map_err(|error| error.to_string())
        });
        match packet {
            Ok(packet) => {
                let _ = answers.send(Answer::Dns(packet)).await;
            }
            Err(_) => task_runtime.udp_sessions().record_dns_answer_failure(),
        }
    });
    Ok(PacketExecutionOutcome {
        pipeline,
        emitted_packets: Vec::new(),
        bytes_sent,
        bytes_received: 0,
    })
}

async fn relay_udp_packet(
    runtime: &NativeCoreRuntime,
    queue: usize,
    packet: &CapturedPacket,
    pipeline: PacketPipelineOutcome,
) -> Result<PacketExecutionOutcome, String> {
    let datagram = parse_udp_datagram(&packet.bytes).map_err(|error| error.to_string())?;
    // Relay the datagram as a persistent bidirectional flow rather than a
    // one-shot request/response: a UDP application (a media stream, a game,
    // QUIC) sends and receives at rates that are not 1:1.
    // `send_udp_flow_datagram` hands the payload to a persistent per-flow
    // session socket and returns immediately; every upstream datagram comes
    // back through `drain_pending_udp_packets`, so the two directions run
    // independently.
    let source: SocketAddr = (datagram.source_ip, datagram.source_port).into();
    // Preserve the address the client actually used. The shared UDP entry
    // separates this numeric alias from its logical routing/DNS target before
    // building ReplyBinding; pre-enriching here would turn a fake-IP alias
    // into a plain domain association and lose the reply's client-visible IP.
    let target = ConnectTarget {
        host: datagram.destination_ip.to_string(),
        port: datagram.destination_port,
    };
    let payload_len = datagram.payload.len();
    let send = send_udp_flow_datagram(
        runtime,
        UdpDatagram {
            flow_id: Some(packet_udp_flow_id(source)),
            pump_queue: Some(queue),
            // The packet executor is the capture data plane: this datagram
            // entered through the TUN.
            inbound: "tun",
            user: None,
            source,
            target,
            payload: datagram.payload,
            process_name: packet.process_name(),
            process_path: packet.process_path(),
        },
    )
    .await?;

    // The upstream's replies are emitted later by the flow drain, not here, so
    // this call emits nothing and counts only the bytes accepted for send.
    Ok(PacketExecutionOutcome {
        pipeline,
        emitted_packets: Vec::new(),
        bytes_sent: if send.enqueued { payload_len } else { 0 },
        bytes_received: 0,
    })
}

/// Bound on datagrams drained per device-loop sweep ("一切有界").
pub(crate) const PACKET_UDP_DRAIN_MAX_DATAGRAMS: usize = 64;

/// The packet path's flow id for the client socket `source` (the session's
/// client 2-tuple), under the prefix of the flows the packet pumps open (the
/// same session table holds inbound-face flows with their own id scheme). A
/// drained reply goes back to that socket, from the address in its
/// `source_endpoint` (EIF: the real remote, or a fake IP the client
/// addressed) — one 2-tuple session serves every remote, whichever capture
/// queue the datagrams to each arrive on.
fn packet_udp_flow_id(source: SocketAddr) -> String {
    format!("{PUMP_FLOW_PREFIX}{source}")
}

/// Drains upstream UDP replies buffered on the packet path's flow sessions and
/// reframes each as an IP/UDP packet back to the client. Non-blocking (a zero
/// wait), so the device loop calls it every iteration alongside the TCP drain;
/// a reply is framed from its client-facing source (EIF) back to the client's
/// own socket. Flows minted elsewhere (inbound faces) are skipped.
pub(crate) async fn drain_pending_udp_packets(
    runtime: &NativeCoreRuntime,
    queue: usize,
    max_datagrams: usize,
    train_mtu: Option<usize>,
) -> Result<UdpOutput, String> {
    if max_datagrams == 0 {
        return Ok(UdpOutput::default());
    }
    let PumpReplies {
        mut packets,
        trains,
        responses,
    } = drain_pump_replies(
        runtime,
        queue,
        max_datagrams.min(PACKET_UDP_DRAIN_MAX_DATAGRAMS),
        train_mtu,
    )
    .await;
    packets.extend(frame_udp_responses(responses));
    Ok(UdpOutput { packets, trains })
}

/// UDP bound for the device: whole packets, and trains for a device that
/// takes them.
#[derive(Default)]
pub(crate) struct UdpOutput {
    pub(crate) packets: Vec<Vec<u8>>,
    pub(crate) trains: Vec<UdpTrain>,
}

impl UdpOutput {
    pub(crate) fn is_empty(&self) -> bool {
        self.packets.is_empty() && self.trains.is_empty()
    }
}

fn frame_udp_responses(drained: Vec<crate::udp::UdpPendingFlowDatagram>) -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(drained.len());
    for pending in drained {
        let source = pending.source;
        // The reply's client-facing source (EIF): the real remote, or a fake
        // IP the client addressed. A client always addresses an IP, so a
        // non-IP endpoint cannot be framed into a packet and is skipped.
        let Some(remote_ip) = pending.source_endpoint.ip() else {
            continue;
        };
        let Ok(payload) = build_udp_packet(
            remote_ip,
            source.ip(),
            pending.source_endpoint.port,
            source.port(),
            &pending.payload,
        ) else {
            continue;
        };
        packets.push(payload);
    }
    packets
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use serde_json::json;
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, Duration};

    use super::*;
    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::self_test::{self_test_profile, serve_one_udp_echo};
    use crate::target::ConnectTarget;
    use crate::udp::UdpPendingFlowDatagram;

    async fn execute(
        runtime: &NativeCoreRuntime,
        packet: Vec<u8>,
    ) -> Result<PacketExecutionOutcome, String> {
        let (answers, _answers_back) = AnswerSink::channel();
        execute_captured_packet(runtime, 0, &CapturedPacket::from_bytes(packet), &answers).await
    }

    /// Executes a captured DNS query and returns its answer: made on the
    /// spot for the Core's own decisions, from the answer queue otherwise.
    async fn answer(
        runtime: &NativeCoreRuntime,
        packet: Vec<u8>,
    ) -> (PacketExecutionOutcome, Vec<u8>) {
        let (answers, mut answers_back) = AnswerSink::channel();
        let mut outcome =
            execute_captured_packet(runtime, 0, &CapturedPacket::from_bytes(packet), &answers)
                .await
                .expect("DNS packet executes");
        let answer = match outcome.emitted_packets.pop() {
            Some(answer) => answer,
            None => match tokio::time::timeout(Duration::from_secs(5), answers_back.recv())
                .await
                .expect("DNS answer arrives")
                .expect("DNS answer channel open")
            {
                Answer::Dns(answer) => answer,
                Answer::Echo(_) => panic!("a DNS query came back as an echo reply"),
            },
        };
        (outcome, answer)
    }

    #[tokio::test]
    async fn an_echo_to_a_fake_ipv6_address_is_answered_locally() {
        let mut profile = self_test_profile();
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        let runtime = NativeCoreRuntime::compile(&profile);
        let fake = runtime.fake_dns().allocate_ipv6("echo6.example").unwrap();
        let client: IpAddr = "fd00::2".parse().unwrap();
        let message = super::super::icmp::echo_message(true, false, 0x77, 5, b"ping6");
        let request =
            super::super::frame::build_icmp_packet(client, IpAddr::V6(fake), &message).unwrap();

        let outcome = execute(&runtime, request).await.unwrap();

        assert_eq!(outcome.pipeline.action, PacketCoreAction::IcmpEchoReply);
        let reply = super::super::frame::icmp_message(&outcome.emitted_packets[0]).unwrap();
        assert_eq!(
            (reply.source, reply.destination),
            (IpAddr::V6(fake), client)
        );
        assert_eq!(reply.message[0], 129);
        assert_eq!(&reply.message[4..], b"\x00\x77\x00\x05ping6");
    }

    #[tokio::test]
    async fn relays_udp_flow_and_drains_upstream_reply_back_to_client() {
        let payload = b"packet-udp-direct";
        let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP target");
        let target_addr = target_socket.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_udp_echo(target_socket).await });
        let runtime = NativeCoreRuntime::compile(&self_test_profile());
        let request = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            53123,
            target_addr.port(),
            payload,
        )
        .expect("request packet builds");

        let outcome = execute(&runtime, request)
            .await
            .expect("UDP packet executes");

        assert_eq!(outcome.pipeline.action, PacketCoreAction::DirectUdp);
        assert_eq!(outcome.bytes_sent, payload.len());
        // The flow send is fire-and-forget; the upstream reply is delivered by
        // the device drain, not inline, so nothing is emitted here.
        assert!(outcome.emitted_packets.is_empty());

        let emitted = drain_udp_until_response(&runtime)
            .await
            .expect("upstream reply drains back to the client");
        let response = parse_udp_datagram(&emitted).expect("response packet parses");
        assert_eq!(response.source_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            response.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(response.source_port, target_addr.port());
        assert_eq!(response.destination_port, 53123);
        assert_eq!(response.payload, payload);
        echo_task.await.expect("echo join").expect("echo completes");
    }

    /// The bidirectional-relay fix: a UDP upstream that pushes several datagrams
    /// after one client send (a media/screen stream, a game tick) must deliver
    /// every datagram back to the client. The old one-shot relay returned
    /// exactly one reply per send and dropped the rest, which is what cut
    /// UDP-based remote-control and streaming traffic under TUN.
    #[tokio::test]
    async fn udp_flow_delivers_every_upstream_datagram_not_just_one() {
        const BURST: usize = 6;
        let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP target");
        let target_addr = target_socket.local_addr().expect("target addr");
        let push_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            let (_read, from) = target_socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            for index in 0..BURST {
                target_socket
                    .send_to(format!("push-{index}").as_bytes(), from)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            Ok::<(), String>(())
        });
        let runtime = NativeCoreRuntime::compile(&self_test_profile());
        let request = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            53123,
            target_addr.port(),
            b"kick",
        )
        .expect("request packet builds");

        execute(&runtime, request)
            .await
            .expect("UDP packet executes");

        let mut received = Vec::new();
        for _ in 0..300 {
            for packet in
                drain_pending_udp_packets(&runtime, 0, PACKET_UDP_DRAIN_MAX_DATAGRAMS, None)
                    .await
                    .expect("drain")
                    .packets
            {
                let datagram = parse_udp_datagram(&packet).expect("response parses");
                assert_eq!(datagram.destination_port, 53123);
                assert_eq!(datagram.source_port, target_addr.port());
                received.push(datagram.payload);
            }
            if received.len() >= BURST {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            received.len(),
            BURST,
            "every upstream datagram must reach the client, not just the first"
        );
        push_task.await.expect("push join").expect("push completes");
    }

    #[test]
    fn udp_framing_skips_unframeable_reply_and_keeps_valid_batch_items() {
        let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 53123));
        let flow_id = packet_udp_flow_id(source);
        let source_endpoint = ConnectTarget {
            host: Ipv4Addr::LOCALHOST.to_string(),
            port: 53_000,
        };
        // 65,508 bytes exceed IPv4's 16-bit total packet length.
        let packets = frame_udp_responses(vec![
            UdpPendingFlowDatagram {
                flow_id: flow_id.clone(),
                source,
                source_endpoint: source_endpoint.clone(),
                payload: vec![0; 65_508],
            },
            UdpPendingFlowDatagram {
                flow_id,
                source,
                source_endpoint,
                payload: b"valid-reply".to_vec(),
            },
        ]);
        assert_eq!(packets.len(), 1);
        let datagram = parse_udp_datagram(&packets[0]).unwrap();
        assert_eq!(datagram.payload, b"valid-reply");
        assert_eq!(datagram.destination_port, 53_123);
    }

    async fn drain_udp_until_response(runtime: &NativeCoreRuntime) -> Option<Vec<u8>> {
        for _ in 0..300 {
            if let Some(packet) =
                drain_pending_udp_packets(runtime, 0, PACKET_UDP_DRAIN_MAX_DATAGRAMS, None)
                    .await
                    .expect("drain")
                    .packets
                    .pop()
            {
                return Some(packet);
            }
            sleep(Duration::from_millis(10)).await;
        }
        None
    }

    /// R2 EIM+EIF: one client 2-tuple that addresses two different remotes is
    /// served by a single upstream session (endpoint-independent mapping), and
    /// each reply frames back from the remote it actually came from
    /// (endpoint-independent filtering) — not a single pinned target, which is
    /// what the old four-tuple model did.
    #[tokio::test]
    async fn one_client_socket_reaches_two_remotes_and_frames_each_reply_from_its_origin() {
        let target_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target A");
        let addr_a = target_a.local_addr().expect("A addr");
        let target_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target B");
        let addr_b = target_b.local_addr().expect("B addr");
        let echo_a = tokio::spawn(async move { serve_one_udp_echo(target_a).await });
        let echo_b = tokio::spawn(async move { serve_one_udp_echo(target_b).await });

        let runtime = NativeCoreRuntime::compile(&self_test_profile());
        let client_port = 53123;
        for target_port in [addr_a.port(), addr_b.port()] {
            let request = build_udp_packet(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                client_port,
                target_port,
                b"probe",
            )
            .expect("request packet builds");
            execute(&runtime, request)
                .await
                .expect("UDP packet executes");
        }

        // EIM: both remotes ride one upstream session socket.
        assert_eq!(runtime.udp_sessions().session_socket_count(), 1);

        // EIF: each reply frames back to the client from its own origin port.
        let mut reply_ports = std::collections::HashSet::new();
        for _ in 0..300 {
            for packet in
                drain_pending_udp_packets(&runtime, 0, PACKET_UDP_DRAIN_MAX_DATAGRAMS, None)
                    .await
                    .expect("drain")
                    .packets
            {
                let datagram = parse_udp_datagram(&packet).expect("reply parses");
                assert_eq!(
                    datagram.destination_ip,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
                );
                assert_eq!(datagram.destination_port, client_port);
                reply_ports.insert(datagram.source_port);
            }
            if reply_ports.len() >= 2 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            reply_ports.contains(&addr_a.port()),
            "the reply from A must frame from A"
        );
        assert!(
            reply_ports.contains(&addr_b.port()),
            "the reply from B must frame from B"
        );
        echo_a
            .await
            .expect("echo A join")
            .expect("echo A completes");
        echo_b
            .await
            .expect("echo B join")
            .expect("echo B completes");
    }

    #[tokio::test]
    async fn executes_dns_query_to_fake_ip_before_udp_outbound_capability_check() {
        let runtime = NativeCoreRuntime::compile(&proxy_profile(
            "HttpProxy",
            ProxyProtocol::Http,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18080)),
            json!({}),
        ));
        let dns_payload = dns_query(0x2345, "example.com", 1);
        let request = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            53123,
            53,
            &dns_payload,
        )
        .expect("DNS request packet builds");

        let (outcome, answer) = answer(&runtime, request).await;

        assert_eq!(outcome.pipeline.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.bytes_sent, dns_payload.len());
        let response = parse_udp_datagram(&answer).expect("DNS response packet parses");
        let fake_ip = first_dns_a_answer(&response.payload).expect("fake DNS A answer");
        assert!(matches!(fake_ip.octets(), [198, 18 | 19, _, _]));
        assert_eq!(
            runtime.fake_dns().lookup_ipv4(fake_ip).as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn executes_dns_query_to_virtual_dns_target() {
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &proxy_profile(
                "HttpProxy",
                ProxyProtocol::Http,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 18080)),
                json!({}),
            ),
            crate::NativeCoreEgressConfig::default(),
            crate::NativeCoreCaptureConfig::with_dns_hijack(
                crate::NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
                    Ipv4Addr::new(10, 255, 255, 2),
                )]),
            ),
        );
        let dns_payload = dns_query(0x3456, "example.com", 1);
        let request = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)),
            53123,
            53,
            &dns_payload,
        )
        .expect("DNS request packet builds");

        let (outcome, answer) = answer(&runtime, request).await;

        assert_eq!(outcome.pipeline.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.pipeline.destination_ip, "10.255.255.2");
        let response = parse_udp_datagram(&answer).expect("DNS response packet parses");
        assert_eq!(
            response.source_ip,
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2))
        );
        let fake_ip = first_dns_a_answer(&response.payload).expect("fake DNS A answer");
        assert_eq!(
            runtime.fake_dns().lookup_ipv4(fake_ip).as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn packet_udp_preserves_each_fake_alias_for_shared_real_peers_and_all_payload_sizes() {
        use crate::dns::config::{DnsMode, DnsRoute, DnsTransport, DnsUpstream};
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
        use std::net::Ipv6Addr;

        let dns_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dns_addr = dns_socket.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            let mut bytes = [0u8; 4096];
            loop {
                let (length, peer) = dns_socket.recv_from(&mut bytes).await.unwrap();
                let query = crate::dns::wire::decode(&bytes[..length]).unwrap();
                let mut response = crate::dns::wire::response(&query, ResponseCode::NoError);
                let question = query.query().unwrap();
                if question.query_type() == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
                dns_socket
                    .send_to(&crate::dns::wire::encode(&response).unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut bytes = [0u8; 65_535];
            loop {
                let (length, peer) = echo_socket.recv_from(&mut bytes).await.unwrap();
                echo_socket.send_to(&bytes[..length], peer).await.unwrap();
            }
        });
        let mut profile = RuntimeProfile::new("packet-fake-udp-reply-alias");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = DnsMode::FakeIp;
        profile.dns.nameservers = vec![DnsUpstream {
            transport: DnsTransport::Udp,
            host: dns_addr.ip().to_string(),
            port: dns_addr.port(),
            path: String::new(),
            server_name: None,
            route: Some(DnsRoute::Direct),
        }];
        profile.rules = vec![RouteRule {
            kind: RuleKind::DomainSuffix,
            payload: Some("alias.test"),
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        for ipv6 in [false, true] {
            let client_ip = if ipv6 {
                IpAddr::V6("fd00::2".parse::<Ipv6Addr>().unwrap())
            } else {
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
            };
            for domain in ["first.alias.test", "second.alias.test"] {
                let fake = if ipv6 {
                    IpAddr::V6(runtime.fake_dns().allocate_ipv6(domain).unwrap())
                } else {
                    IpAddr::V4(runtime.fake_dns().allocate_ipv4(domain).unwrap())
                };
                for size in [0, 1, 1200, 4096, 8192] {
                    let payload: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
                    let request =
                        build_udp_packet(client_ip, fake, 53123, echo_addr.port(), &payload)
                            .unwrap();
                    let outcome = execute(&runtime, request).await.unwrap();
                    assert_eq!(
                        outcome.pipeline.matched_rule.as_deref(),
                        Some("DOMAIN-SUFFIX,alias.test,DIRECT")
                    );
                    let reply = drain_udp_until_response(&runtime)
                        .await
                        .expect("loopback echo produced a packet");
                    let reply = parse_udp_datagram(&reply).unwrap();
                    assert_eq!(reply.source_ip, fake, "reply must retain the numeric alias for {domain}, ipv6={ipv6}, size={size}");
                    assert_eq!(reply.destination_ip, client_ip);
                    assert_eq!(reply.source_port, echo_addr.port());
                    assert_eq!(reply.destination_port, 53123);
                    assert_eq!(reply.payload, payload);
                }
            }
        }
        crate::udp::close_udp_sessions(&runtime);
        dns_task.abort();
        echo_task.abort();
        let _ = dns_task.await;
        let _ = echo_task.await;
    }

    fn proxy_profile(
        name: &str,
        protocol: ProxyProtocol,
        proxy_addr: SocketAddr,
        options: serde_json::Value,
    ) -> RuntimeProfile {
        let mut profile = RuntimeProfile::new("packet-proxy");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        profile.proxies = vec![ProxyNode {
            id: format!("proxy-{name}"),
            name: name.into(),
            protocol,
            server: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            options,
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

    fn first_dns_a_answer(payload: &[u8]) -> Option<Ipv4Addr> {
        let answer_count = u16::from_be_bytes([payload[6], payload[7]]);
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12;
        while payload.get(offset).copied()? != 0 {
            offset += payload[offset] as usize + 1;
        }
        offset += 1 + 4;
        if payload.get(offset).copied()? != 0xc0 {
            return None;
        }
        let rdata_len = u16::from_be_bytes([payload[offset + 10], payload[offset + 11]]) as usize;
        if rdata_len != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            payload[offset + 12],
            payload[offset + 13],
            payload[offset + 14],
            payload[offset + 15],
        ))
    }

    #[tokio::test]
    async fn executes_ipv6_dns_query_to_virtual_dns_target() {
        use std::net::Ipv6Addr;

        let virtual_dns = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 2);
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &proxy_profile(
                "Proxy",
                ProxyProtocol::Http,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 18080)),
                json!({}),
            ),
            Default::default(),
            crate::NativeCoreCaptureConfig::with_dns_hijack(
                crate::NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V6(
                    virtual_dns,
                )]),
            ),
        );
        let dns_payload = dns_query(0x6666, "example.com", 1);
        let request = build_udp_packet(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9)),
            IpAddr::V6(virtual_dns),
            53123,
            53,
            &dns_payload,
        )
        .expect("IPv6 DNS request packet builds");

        let (outcome, answer) = answer(&runtime, request).await;

        assert_eq!(outcome.pipeline.action, PacketCoreAction::DnsCapture);
        let response = parse_udp_datagram(&answer).expect("IPv6 DNS response packet parses");
        assert_eq!(response.source_ip, IpAddr::V6(virtual_dns));
        assert_eq!(
            response.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9))
        );
        let fake_ip = first_dns_a_answer(&response.payload).expect("fake DNS A answer");
        assert_eq!(
            runtime.fake_dns().lookup_ipv4(fake_ip).as_deref(),
            Some("example.com")
        );
    }
}
