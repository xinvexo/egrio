//! Portable packet-core connection probes for UDP mapping, filtering, and DNS.
//!
//! - **UDP EIM+EIF.** RFC 4787 endpoint-independent mapping and
//!   filtering — the property R2 re-keyed the UDP table to the client 2-tuple
//!   to provide. Checked literally: two loopback remotes see the *same*
//!   reflexive mapping (EIM), each reply frames back from its own origin (EIF),
//!   and a datagram from a remote the client never contacted is still delivered
//!   on the active session (EIF, the STUN hole-punch case). A remote reached
//!   through a fake IP, as a STUN server reached by name is, sees the same
//!   mapping as one reached by address, and its reply comes from the fake IP.
//! - **DNS hijack + fake-IP.** Any datagram to UDP/53 is answered
//!   by the engine instead of relayed, and a proxied A query is answered from
//!   the fake-IP pool whose addresses reverse-map to their domain.
//!
//! These run against an in-process [`NativeCoreRuntime`] with no host network
//! state — loopback UDP peers stand in for remotes and fake-IP answers are
//! synthesized locally — so the probe is deterministic on any host, including
//! the static gate.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

use super::executor::{drain_pending_udp_packets, execute_captured_packet, Answer, AnswerSink};
use super::frame::{
    build_udp_packet, ipv4_header_checksum, ipv4_icmp_checksum, parse_packet_flow,
    parse_udp_datagram,
};
use super::pipeline::PacketCoreAction;
use super::CapturedPacket;
use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
use crate::runtime::NativeCoreRuntime;
use crate::self_test::self_test_profile;

/// How long the probe waits for a remote to observe its reflexive mapping —
/// generous, since it only bounds a genuinely broken run.
const PROBE_OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded drain polling: an upper bound on collecting the framed replies
/// before the row reports what it saw (a wedged flow never hangs the probe).
const PROBE_DRAIN_POLLS: usize = 300;
const PROBE_DRAIN_INTERVAL: Duration = Duration::from_millis(10);
/// The client 2-tuple every row sends from — a private TUN-side source, so it
/// never collides with a loopback peer.
const PROBE_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMatrixCoreReport {
    /// True when every core-observable row passed.
    pub ok: bool,
    pub rows: Vec<ConnectionMatrixCoreRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMatrixCoreRow {
    /// Stable semantic id the daemon slots into the full matrix table.
    pub id: &'static str,
    /// The matrix case this row covers, human-readable.
    pub case: &'static str,
    pub pass: bool,
    /// One-line result: what held, or why it failed.
    pub detail: String,
    /// Structured per-observation evidence for the baseline record.
    pub evidence: Vec<String>,
}

/// Runs the core-observable connection-matrix rows in-process. Never returns
/// `Err` for a behavioral failure — a failing check lands as a `pass: false`
/// row so the table is always complete; `Err` is reserved for a probe harness
/// fault (a loopback socket that will not bind).
pub async fn run_connection_matrix_core_probe() -> Result<ConnectionMatrixCoreReport, String> {
    let rows = vec![
        probe_udp_eim_eif().await,
        probe_udp_eim_named().await,
        probe_dns_packet_hijack().await,
        probe_icmp_echo_fake_ip().await,
    ];
    Ok(ConnectionMatrixCoreReport {
        ok: rows.iter().all(|row| row.pass),
        rows,
    })
}

const UDP_EIM_EIF_ID: &str = "udp-eim-eif";
const UDP_EIM_EIF_CASE: &str =
    "matrix #3/#4 — UDP endpoint-independent mapping + filtering (RFC 4787)";

async fn probe_udp_eim_eif() -> ConnectionMatrixCoreRow {
    match udp_eim_eif_evidence().await {
        Ok((detail, evidence)) => ConnectionMatrixCoreRow {
            id: UDP_EIM_EIF_ID,
            case: UDP_EIM_EIF_CASE,
            pass: true,
            detail,
            evidence,
        },
        Err(error) => ConnectionMatrixCoreRow {
            id: UDP_EIM_EIF_ID,
            case: UDP_EIM_EIF_CASE,
            pass: false,
            detail: error,
            evidence: Vec::new(),
        },
    }
}

async fn udp_eim_eif_evidence() -> Result<(String, Vec<String>), String> {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let client = SocketAddr::from((PROBE_CLIENT_IP, 53123));

    // Two loopback remotes that report the reflexive source they observe and
    // echo the payload back, so the flow produces a client-facing reply.
    let (remote_a, report_a) = spawn_reflexive_udp_echo().await?;
    let (remote_b, report_b) = spawn_reflexive_udp_echo().await?;

    // Same client 2-tuple to both remotes.
    send_client_udp(&runtime, client, remote_a, b"matrix-eim-a").await?;
    let observed_a = observe_reflexive_mapping(report_a, "A").await?;
    send_client_udp(&runtime, client, remote_b, b"matrix-eim-b").await?;
    let observed_b = observe_reflexive_mapping(report_b, "B").await?;

    // EIM (core side): one upstream session socket serves both remotes.
    let sockets = runtime.udp_sessions().session_socket_count();
    if sockets != 1 {
        return Err(format!(
            "EIM violated: {sockets} upstream socket(s) for one client 2-tuple across two remotes (expected 1)"
        ));
    }
    // EIM (remote side): both remotes saw the identical reflexive mapping.
    if observed_a != observed_b {
        return Err(format!(
            "EIM violated: remotes saw different reflexive mappings ({observed_a} vs {observed_b})"
        ));
    }

    // EIF unsolicited: a remote the client never contacted addresses the
    // reflexive mapping and is delivered on the active session (STUN hole
    // punching's requirement, and what the four-tuple model structurally broke).
    let unsolicited = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind the unsolicited-remote socket: {error}"))?;
    let unsolicited_addr = unsolicited
        .local_addr()
        .map_err(|error| format!("failed to read the unsolicited-remote addr: {error}"))?;
    unsolicited
        .send_to(b"matrix-eif-unsolicited", observed_a)
        .await
        .map_err(|error| format!("failed to send the unsolicited datagram: {error}"))?;

    // Drain the framed replies: A's echo, B's echo, and the unsolicited remote,
    // each framed back to the client from its own origin (EIF).
    let origins = drain_client_reply_origins(&runtime, client, 3).await?;
    if !origins.contains(&remote_a) {
        return Err(format!(
            "EIF violated: remote A ({remote_a}) reply was not framed to the client (saw {origins:?})"
        ));
    }
    if !origins.contains(&remote_b) {
        return Err(format!(
            "EIF violated: remote B ({remote_b}) reply was not framed to the client (saw {origins:?})"
        ));
    }
    if !origins.contains(&unsolicited_addr) {
        return Err(format!(
            "EIF violated: the unsolicited remote ({unsolicited_addr}) was filtered instead of delivered (saw {origins:?})"
        ));
    }

    Ok((
        "same reflexive mapping across two remotes; each reply framed from its origin; an unsolicited remote accepted on the active session".into(),
        vec![
            format!(
                "client 2-tuple {client} mapped to one upstream socket for remotes {remote_a} and {remote_b}"
            ),
            format!("both remotes observed the identical reflexive mapping {observed_a}"),
            format!(
                "replies framed back to the client from origins {remote_a}, {remote_b}, and unsolicited {unsolicited_addr}"
            ),
        ],
    ))
}

const UDP_EIM_NAMED_ID: &str = "udp-eim-named";
const UDP_EIM_NAMED_CASE: &str =
    "matrix #4 — a remote reached by name (fake IP) shares the UDP mapping of remotes reached by address";

async fn probe_udp_eim_named() -> ConnectionMatrixCoreRow {
    let (detail, evidence, pass) = match udp_eim_named_evidence().await {
        Ok((detail, evidence)) => (detail, evidence, true),
        Err(error) => (error, Vec::new(), false),
    };
    ConnectionMatrixCoreRow {
        id: UDP_EIM_NAMED_ID,
        case: UDP_EIM_NAMED_CASE,
        pass,
        detail,
        evidence,
    }
}

async fn udp_eim_named_evidence() -> Result<(String, Vec<String>), String> {
    let (resolver, resolver_task) = spawn_loopback_resolver().await?;
    let result = async {
        let runtime = NativeCoreRuntime::compile(&matrix_named_profile(resolver));
        let client = SocketAddr::from((PROBE_CLIENT_IP, 53124));
        let (named, report_named) = spawn_reflexive_udp_echo().await?;
        let (peer, report_peer) = spawn_reflexive_udp_echo().await?;
        let fake = runtime
            .fake_dns()
            .allocate_ipv4("stun.matrix.probe")
            .map_err(|error| format!("fake-IP allocation failed: {error}"))?;
        let by_name = SocketAddr::new(IpAddr::V4(fake), named.port());

        // A STUN server reached by name, then a peer reached by address.
        send_client_udp(&runtime, client, by_name, b"matrix-eim-name").await?;
        let observed_named = observe_reflexive_mapping(report_named, "by name").await?;
        send_client_udp(&runtime, client, peer, b"matrix-eim-address").await?;
        let observed_peer = observe_reflexive_mapping(report_peer, "by address").await?;
        if observed_named != observed_peer {
            return Err(format!(
                "EIM violated: the remote reached by name saw {observed_named}, the one reached by address {observed_peer}"
            ));
        }
        let sockets = runtime.udp_sessions().session_socket_count();
        if sockets != 1 {
            return Err(format!(
                "EIM violated: {sockets} upstream socket(s) for one client 2-tuple across a name and an address (expected 1)"
            ));
        }
        // Both loopback remotes share the address the name resolved to, so
        // both replies come from the fake IP; what matters is the named one.
        let origins = drain_client_reply_origins(&runtime, client, 2).await?;
        if !origins.contains(&by_name) {
            return Err(format!(
                "the reply of the remote reached by name was not framed from its fake IP {by_name} (saw {origins:?})"
            ));
        }
        Ok((
            "a remote reached by name and one reached by address saw the same mapping; the named reply came from its fake IP".into(),
            vec![
                format!("{by_name} (stun.matrix.probe) and {peer} both observed {observed_named}"),
                format!("client 2-tuple {client} mapped to one upstream socket"),
                format!("the named remote's reply framed back from {by_name}"),
            ],
        ))
    }
    .await;
    resolver_task.abort();
    result
}

const DNS_HIJACK_ID: &str = "dns-packet-hijack";
const DNS_HIJACK_CASE: &str =
    "matrix #10 — DNS hijacked on the packet path and answered with fake-IP";

async fn probe_dns_packet_hijack() -> ConnectionMatrixCoreRow {
    match dns_packet_hijack_evidence().await {
        Ok((detail, evidence)) => ConnectionMatrixCoreRow {
            id: DNS_HIJACK_ID,
            case: DNS_HIJACK_CASE,
            pass: true,
            detail,
            evidence,
        },
        Err(error) => ConnectionMatrixCoreRow {
            id: DNS_HIJACK_ID,
            case: DNS_HIJACK_CASE,
            pass: false,
            detail: error,
            evidence: Vec::new(),
        },
    }
}

async fn dns_packet_hijack_evidence() -> Result<(String, Vec<String>), String> {
    let runtime = NativeCoreRuntime::compile_with_egress(
        &matrix_proxy_profile(),
        crate::NativeCoreEgressConfig {
            ipv6_enabled: true,
            ..crate::NativeCoreEgressConfig::default()
        },
    );
    let client = SocketAddr::from((PROBE_CLIENT_IP, 53201));
    // "any dst:53 hijacked" — a public resolver address, not a virtual-DNS one,
    // so the check proves the port hijack, not a target-list match.
    let resolver = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));

    let (a_action, a_answers) =
        dns_over_packet(&runtime, client, resolver, "example.com", 1).await?;
    if a_action != PacketCoreAction::DnsCapture {
        return Err(format!(
            "dst:53 was not hijacked on the packet path: action was {a_action:?}"
        ));
    }
    if a_answers.is_empty() {
        return Err("a proxied A query was hijacked but answered with no fake-IP record".into());
    }

    let (_, aaaa_answers) = dns_over_packet(&runtime, client, resolver, "example.com", 28).await?;
    if aaaa_answers.is_empty() {
        return Err("a proxied AAAA query was hijacked but answered with no fake-v6 record".into());
    }

    for address in a_answers.iter().chain(&aaaa_answers) {
        if runtime.fake_dns_domain_for_ip(*address).as_deref() != Some("example.com") {
            return Err(format!(
                "DNS answer {address} is not owned by this Core's fake-IP store"
            ));
        }
    }

    // Fake IPs reverse-map to their domain, the property the packet path relies
    // on to route a fake-IP destination by the domain it stands for.
    let fake_ip = runtime
        .fake_dns()
        .allocate_ipv4("reverse.example")
        .map_err(|error| format!("fake-IP allocation failed: {error}"))?;
    let reverse = runtime.resolve_packet_destination_host(IpAddr::V4(fake_ip));
    if reverse != "reverse.example" {
        return Err(format!(
            "fake IP {fake_ip} did not reverse-map to its domain (got '{reverse}')"
        ));
    }
    let fake_ipv6 = runtime
        .fake_dns()
        .allocate_ipv6("reverse.example")
        .map_err(|error| format!("fake-v6 allocation failed: {error}"))?;
    let reverse_ipv6 = runtime.resolve_packet_destination_host(IpAddr::V6(fake_ipv6));
    if reverse_ipv6 != "reverse.example" {
        return Err(format!(
            "fake IPv6 {fake_ipv6} did not reverse-map to its domain (got '{reverse_ipv6}')"
        ));
    }

    Ok((
        "any dst:53 hijacked and answered locally; proxied A/AAAA queries answer from paired fake-IP pools; fake IPs reverse-map to their domain".into(),
        vec![
            format!(
                "A query to {resolver} hijacked as DnsCapture and answered with {} fake-IP record(s)", a_answers.len()
            ),
            format!(
                "AAAA query to {resolver} hijacked as DnsCapture and answered with {} fake-v6 record(s)", aaaa_answers.len()
            ),
            format!("fake IP {fake_ip} reverse-maps to reverse.example on the packet path"),
            format!("fake IPv6 {fake_ipv6} reverse-maps to reverse.example on the packet path"),
        ],
    ))
}

/// Sends one UDP DNS query as a captured packet and returns the pipeline action
/// plus the actual answer addresses, so the probe can verify their ownership.
async fn dns_over_packet(
    runtime: &NativeCoreRuntime,
    client: SocketAddr,
    resolver: SocketAddr,
    domain: &str,
    qtype: u16,
) -> Result<(PacketCoreAction, Vec<IpAddr>), String> {
    let query = build_dns_query(domain, qtype);
    let packet = build_udp_packet(
        client.ip(),
        resolver.ip(),
        client.port(),
        resolver.port(),
        &query,
    )?;
    let (answers, mut answers_back) = AnswerSink::channel();
    let mut outcome =
        execute_captured_packet(runtime, 0, &CapturedPacket::from_bytes(packet), &answers).await?;
    // The Core answers its own decisions on the spot; an upstream answer
    // comes back through the answer queue.
    let answer = if outcome.pipeline.action != PacketCoreAction::DnsCapture {
        None
    } else if let Some(answer) = outcome.emitted_packets.pop() {
        Some(answer)
    } else {
        match timeout(PROBE_OBSERVE_TIMEOUT, answers_back.recv())
            .await
            .map_err(|_| "captured DNS query was not answered".to_string())?
        {
            Some(Answer::Dns(answer)) => Some(answer),
            Some(Answer::Echo(_)) => return Err("a DNS query came back as an echo reply".into()),
            None => None,
        }
    };
    let answers = match answer {
        Some(answer) => {
            let datagram = parse_udp_datagram(&answer).map_err(|error| error.to_string())?;
            crate::dns::wire::addresses(&crate::dns::wire::decode(&datagram.payload)?)?
        }
        None => Vec::new(),
    };
    Ok((outcome.pipeline.action, answers))
}

const ICMP_ECHO_ID: &str = "icmp-echo-fake-ip";
const ICMP_ECHO_CASE: &str = "matrix #11 — ICMP echo answered locally for fake-IPs, relayed when \
     routed DIRECT where the platform can, dropped through a proxy";

async fn probe_icmp_echo_fake_ip() -> ConnectionMatrixCoreRow {
    match icmp_echo_fake_ip_evidence().await {
        Ok((detail, evidence)) => ConnectionMatrixCoreRow {
            id: ICMP_ECHO_ID,
            case: ICMP_ECHO_CASE,
            pass: true,
            detail,
            evidence,
        },
        Err(error) => ConnectionMatrixCoreRow {
            id: ICMP_ECHO_ID,
            case: ICMP_ECHO_CASE,
            pass: false,
            detail: error,
            evidence: Vec::new(),
        },
    }
}

async fn icmp_echo_fake_ip_evidence() -> Result<(String, Vec<String>), String> {
    let runtime = NativeCoreRuntime::compile(&matrix_proxy_profile());
    let client = PROBE_CLIENT_IP;
    // A ping to a domain lands on the domain's fake IP; routed through the
    // proxy, the Core answers it itself.
    let fake_ip = runtime
        .fake_dns()
        .allocate_ipv4("icmp.example")
        .map_err(|error| format!("fake-IP allocation failed: {error}"))?;

    let identifier: u16 = 0x4d31;
    let sequence: u16 = 7;
    let payload = b"connection-matrix-icmp";
    let request = build_ipv4_icmp_echo_request(client, fake_ip, identifier, sequence, payload);
    let outcome = execute_captured_packet(
        &runtime,
        0,
        &CapturedPacket::from_bytes(request),
        &AnswerSink::channel().0,
    )
    .await?;

    if outcome.pipeline.action != PacketCoreAction::IcmpEchoReply {
        return Err(format!(
            "ICMP echo to a fake IP was not answered locally: action was {:?}",
            outcome.pipeline.action
        ));
    }
    let reply = outcome
        .emitted_packets
        .first()
        .ok_or("ICMP echo to a fake IP emitted no reply")?;
    let flow = parse_packet_flow(&reply).map_err(|error| error.to_string())?;
    if flow.source_ip != IpAddr::V4(fake_ip) || flow.destination_ip != IpAddr::V4(client) {
        return Err(format!(
            "echo reply addresses were not swapped: {} -> {} (expected {fake_ip} -> {client})",
            flow.source_ip, flow.destination_ip
        ));
    }
    let header_len = ((reply[0] & 0x0f) as usize) * 4;
    let icmp = &reply[header_len..];
    if icmp[0] != 0 {
        return Err(format!("echo reply ICMP type was {} (expected 0)", icmp[0]));
    }
    if ipv4_icmp_checksum(icmp) != 0 || ipv4_header_checksum(&reply[..header_len]) != 0 {
        return Err("echo reply checksums did not verify".into());
    }
    if icmp[4..6] != identifier.to_be_bytes()
        || icmp[6..8] != sequence.to_be_bytes()
        || &icmp[8..] != payload
    {
        return Err("echo reply did not echo the identifier, sequence, and payload".into());
    }

    // An echo to a real IP routed through the proxy is dropped and counted:
    // echo cannot travel through a proxy.
    let real_target = Ipv4Addr::new(1, 1, 1, 1);
    let real_request = build_ipv4_icmp_echo_request(client, real_target, 1, 1, payload);
    let real = execute_captured_packet(
        &runtime,
        0,
        &CapturedPacket::from_bytes(real_request),
        &AnswerSink::channel().0,
    )
    .await?;
    if real.pipeline.action != PacketCoreAction::IcmpDrop || !real.emitted_packets.is_empty() {
        return Err(format!(
            "ICMP echo to a real IP was not dropped: action {:?}, {} packet(s) emitted",
            real.pipeline.action,
            real.emitted_packets.len()
        ));
    }

    // The same echo routed DIRECT is relayed over the physical uplink where
    // the platform has ICMP datagram sockets. Only the decision is checked:
    // relaying would leave the process.
    let direct = NativeCoreRuntime::compile(&matrix_direct_profile());
    let relayed = super::pipeline::process_captured_packet(
        &direct,
        &CapturedPacket::from_bytes(build_ipv4_icmp_echo_request(
            client,
            real_target,
            1,
            1,
            payload,
        )),
    )?;
    let expected = if direct.egress().relays_echo() {
        PacketCoreAction::IcmpEchoRelay
    } else {
        PacketCoreAction::IcmpDrop
    };
    if relayed.action != expected {
        return Err(format!(
            "ICMP echo routed DIRECT got action {:?} (expected {expected:?})",
            relayed.action
        ));
    }

    Ok((
        "an ICMP echo request to a fake IP is answered locally with a verified echo reply; one routed DIRECT is relayed where the platform can; one routed through a proxy is dropped and counted".into(),
        vec![
            format!(
                "echo to fake IP {fake_ip} answered locally: reply {fake_ip} -> {client}, identifier/sequence/payload echoed, ICMP and IPv4 checksums valid"
            ),
            format!("echo to real IP {real_target} through the proxy dropped and counted"),
            format!("echo to real IP {real_target} routed DIRECT: {expected:?}"),
        ],
    ))
}

/// Builds an IPv4 ICMP echo request (type 8) from `source` to `destination`
/// with a valid header and ICMP checksum, for the fake-IP local-echo row.
fn build_ipv4_icmp_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = vec![8_u8, 0, 0, 0];
    icmp.extend_from_slice(&identifier.to_be_bytes());
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(payload);
    let icmp_checksum = ipv4_icmp_checksum(&icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let total_len = (20 + icmp.len()) as u16;
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

/// Binds a loopback UDP peer that reports the reflexive source address it
/// observes (the client's mapping, as seen from the remote) and echoes the
/// payload back, so the flow produces a client-facing reply.
async fn spawn_reflexive_udp_echo() -> Result<(SocketAddr, oneshot::Receiver<SocketAddr>), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind a reflexive UDP remote: {error}"))?;
    let addr = socket
        .local_addr()
        .map_err(|error| format!("failed to read a reflexive UDP remote addr: {error}"))?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        if let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            let _ = tx.send(peer);
            let _ = socket.send_to(&buffer[..read], peer).await;
        }
    });
    Ok((addr, rx))
}

async fn observe_reflexive_mapping(
    report: oneshot::Receiver<SocketAddr>,
    remote: &str,
) -> Result<SocketAddr, String> {
    timeout(PROBE_OBSERVE_TIMEOUT, report)
        .await
        .map_err(|_| format!("remote {remote} never observed the reflexive mapping"))?
        .map_err(|_| format!("remote {remote} reflexive reporter dropped"))
}

/// Executes one client UDP datagram through the packet path (fire-and-forget;
/// upstream replies are collected by [`drain_client_reply_origins`]).
async fn send_client_udp(
    runtime: &NativeCoreRuntime,
    client: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let packet = build_udp_packet(
        client.ip(),
        target.ip(),
        client.port(),
        target.port(),
        payload,
    )?;
    let (dns, _answers) = AnswerSink::channel();
    execute_captured_packet(runtime, 0, &CapturedPacket::from_bytes(packet), &dns).await?;
    Ok(())
}

/// Drains the packet path's framed UDP replies and returns the distinct origins
/// that reached the client: `expected` of them, or what came within the drain
/// bound.
async fn drain_client_reply_origins(
    runtime: &NativeCoreRuntime,
    client: SocketAddr,
    expected: usize,
) -> Result<Vec<SocketAddr>, String> {
    let mut origins: Vec<SocketAddr> = Vec::new();
    for _ in 0..PROBE_DRAIN_POLLS {
        for packet in drain_pending_udp_packets(
            runtime,
            0,
            crate::packet::PACKET_UDP_DRAIN_MAX_DATAGRAMS,
            None,
        )
        .await?
        .packets
        {
            let datagram = parse_udp_datagram(&packet).map_err(|error| error.to_string())?;
            if datagram.destination_ip == client.ip() && datagram.destination_port == client.port()
            {
                let origin = SocketAddr::new(datagram.source_ip, datagram.source_port);
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
        }
        if origins.len() >= expected {
            break;
        }
        sleep(PROBE_DRAIN_INTERVAL).await;
    }
    Ok(origins)
}

/// A loopback resolver answering every A question with 127.0.0.1, so a name
/// the probe gives a fake IP leads to its loopback remote.
async fn spawn_loopback_resolver() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), String> {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind the probe resolver: {error}"))?;
    let addr = socket
        .local_addr()
        .map_err(|error| format!("failed to read the probe resolver addr: {error}"))?;
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            let Ok(request) = crate::dns::wire::decode(&buffer[..read]) else {
                continue;
            };
            let mut answer = crate::dns::wire::response(&request, ResponseCode::NoError);
            for query in request.queries {
                if query.query_type() == RecordType::A {
                    answer.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
            }
            if let Ok(bytes) = crate::dns::wire::encode(&answer) {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    Ok((addr, task))
}

/// Fake-IP DNS from the probe resolver, everything DIRECT.
fn matrix_named_profile(resolver: SocketAddr) -> RuntimeProfile {
    use crate::dns::config::{DnsMode, DnsRoute, DnsTransport, DnsUpstream};

    let mut profile = RuntimeProfile::new("connection-matrix-named-probe");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    profile.dns.nameservers = vec![DnsUpstream {
        transport: DnsTransport::Udp,
        host: resolver.ip().to_string(),
        port: resolver.port(),
        path: String::new(),
        server_name: None,
        route: Some(DnsRoute::Direct),
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

/// Explicit fake-IP configuration for matrix #10, independent of host DNS.
/// The node is never dialed by the probe: fake-IP answers
/// are synthesized locally, and no TCP/UDP relay is exercised on this row.
fn matrix_direct_profile() -> RuntimeProfile {
    let mut profile = matrix_proxy_profile();
    profile.rules = profile
        .rules
        .iter()
        .map(|rule| RouteRule {
            outbound: "DIRECT",
            ..rule
        })
        .collect();
    profile
}

fn matrix_proxy_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("connection-matrix-probe");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    profile.proxies = vec![ProxyNode {
        id: "matrix-proxy".into(),
        name: "MatrixProxy".into(),
        protocol: ProxyProtocol::Http,
        server: Some("127.0.0.1".into()),
        port: Some(1),
        options: json!({}),
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "MatrixProxy",
        no_resolve: false,
    }]
    .into();
    profile
}

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(32 + domain.len());
    query.extend_from_slice(&0x4d41_u16.to_be_bytes()); // transaction id
    query.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD
    query.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    query.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    query.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    query.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connection_matrix_core_probe_rows_pass() {
        let report = run_connection_matrix_core_probe()
            .await
            .expect("connection-matrix core probe runs");

        assert!(report.ok, "rows: {:?}", report.rows);
        let ids: Vec<_> = report.rows.iter().map(|row| row.id).collect();
        assert!(ids.contains(&UDP_EIM_EIF_ID), "missing UDP EIM/EIF row");
        assert!(ids.contains(&UDP_EIM_NAMED_ID), "missing named UDP EIM row");
        assert!(ids.contains(&DNS_HIJACK_ID), "missing DNS hijack row");
        assert!(ids.contains(&ICMP_ECHO_ID), "missing ICMP echo row");
        for row in &report.rows {
            assert!(row.pass, "row {} failed: {}", row.id, row.detail);
            assert!(!row.evidence.is_empty(), "row {} has no evidence", row.id);
        }
    }
}
