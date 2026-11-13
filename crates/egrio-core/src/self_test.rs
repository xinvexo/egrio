#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::{TcpListener, TcpStream, UdpSocket};
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

#[cfg(test)]
use crate::device::NativeCoreDevice;
#[cfg(test)]
use crate::inbound::dispatch::handle_connect_client;
#[cfg(test)]
use crate::packet::{ipv4_header_checksum, ipv4_tcp_checksum, CapturedPacket};
#[cfg(test)]
use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
#[cfg(test)]
use crate::protocols::http::read_http_header;
#[cfg(test)]
use crate::runtime::NativeCoreRuntime;
#[cfg(test)]
use crate::target::parse_connect_authority;
use crate::target::ConnectTarget;
#[cfg(test)]
use crate::udp::{drain_pending_udp_flow_responses, send_udp_flow_datagram, UdpDatagram};

/// How long self-test/test-helper peers wait for their one connection or
/// datagram. Generous on purpose: the unit-test suite runs helpers in
/// parallel under CPU contention, and a helper that times out mid-scenario
/// tears its peer down and turns into an unrelated-looking connection-reset
/// failure elsewhere. The timeout only bounds genuinely broken runs.
pub(crate) const SELF_TEST_PEER_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
struct UdpDirectSelfTestOutcome {
    outbound: String,
    matched_rule: Option<String>,
    bytes_sent: usize,
    bytes_received: usize,
    response_payload: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug)]
struct NativeCoreSelfTestReport {
    ok: bool,
    bytes_sent: usize,
    bytes_received: usize,
    steps: Vec<SelfTestStep>,
}

#[cfg(test)]
#[derive(Debug)]
struct SelfTestStep {
    label: String,
    ok: bool,
    #[allow(dead_code)] // Printed by the failing assertion's Debug output.
    message: String,
}

#[cfg(test)]
fn step(label: &str, ok: bool, message: String) -> SelfTestStep {
    SelfTestStep {
        label: label.into(),
        ok,
        message,
    }
}

/// End-to-end Core exercise: listener CONNECT, HTTP proxy outbound, direct
/// UDP and a captured TCP flow through the TCP engine.
#[cfg(test)]
async fn run_native_core_self_test() -> Result<NativeCoreSelfTestReport, String> {
    let payload = b"egrio-native-core-poc";
    let mut steps = Vec::new();

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind self-test target: {error}"))?;
    let target_addr = target_listener
        .local_addr()
        .map_err(|error| format!("failed to read target addr: {error}"))?;
    steps.push(step(
        "bind-echo-target",
        true,
        format!("target listening on {target_addr}"),
    ));

    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });

    let profile = self_test_profile();
    let runtime = Arc::new(NativeCoreRuntime::compile(&profile));
    let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind native core listener: {error}"))?;
    let listen_addr = core_listener
        .local_addr()
        .map_err(|error| format!("failed to read native core listener addr: {error}"))?;
    steps.push(step(
        "bind-native-core",
        true,
        format!("native core validation listener on {listen_addr}"),
    ));

    let core_task_runtime = runtime.clone();
    let core_task =
        tokio::spawn(
            async move { serve_one_connect_session(core_listener, core_task_runtime).await },
        );

    let received = run_connect_client(listen_addr, target_addr, payload)
        .await
        .map_err(|error| format!("self-test client failed: {error}"))?;
    steps.push(step(
        "tunnel-payload",
        received == payload,
        format!(
            "sent {} bytes, received {} bytes",
            payload.len(),
            received.len()
        ),
    ));

    let routed_outbound = core_task
        .await
        .map_err(|error| format!("native core task join failed: {error}"))??;
    steps.push(step(
        "route-session",
        routed_outbound == "DIRECT",
        format!("session routed to {routed_outbound}"),
    ));

    echo_task
        .await
        .map_err(|error| format!("echo task join failed: {error}"))??;
    steps.push(step("echo-target", true, "target echoed payload".into()));

    let proxy_payload = b"egrio-native-core-http-proxy-poc";
    let proxy_outcome = run_http_proxy_self_test(proxy_payload).await?;
    steps.push(step(
        "tcp-http-proxy-outbound",
        proxy_outcome.routed_outbound == "HttpProxy"
            && proxy_outcome.bytes_received == proxy_payload.len()
            && proxy_outcome.proxied_authority == proxy_outcome.target_addr.to_string(),
        format!(
            "TCP payload routed via {} through proxy {} to {}",
            proxy_outcome.routed_outbound, proxy_outcome.proxy_addr, proxy_outcome.target_addr
        ),
    ));

    let udp_payload = b"egrio-native-core-udp-poc";
    let udp_outcome = run_udp_direct_self_test(&runtime, udp_payload).await?;
    let udp_rule = udp_outcome.matched_rule.as_deref().unwrap_or("fallback");
    steps.push(step(
        "udp-direct-datagram",
        udp_outcome.response_payload == udp_payload,
        format!(
            "UDP {} via rule {} sent {} bytes, received {} bytes",
            udp_outcome.outbound, udp_rule, udp_outcome.bytes_sent, udp_outcome.bytes_received
        ),
    ));

    let tcp_bridge_payload = b"egrio-native-core-packet-tcp-bridge";
    let packet_device = NativeCoreDevice::compile(&profile);
    let tcp_bridge_outcome = run_captured_tcp_self_test(&packet_device, tcp_bridge_payload).await?;
    packet_device.close();
    steps.push(step(
        "packet-tcp-engine",
        tcp_bridge_outcome.bytes_sent == tcp_bridge_payload.len()
            && tcp_bridge_outcome.bytes_received == tcp_bridge_payload.len(),
        format!(
            "captured TCP flow accepted by the TCP engine, relayed to a DIRECT upstream, and echoed {} byte(s)",
            tcp_bridge_outcome.bytes_received
        ),
    ));

    let ok = steps.iter().all(|step| step.ok) && received == payload;

    Ok(NativeCoreSelfTestReport {
        ok,
        bytes_sent: payload.len()
            + proxy_outcome.bytes_sent
            + udp_outcome.bytes_sent
            + tcp_bridge_outcome.bytes_sent,
        bytes_received: received.len()
            + proxy_outcome.bytes_received
            + udp_outcome.bytes_received
            + tcp_bridge_outcome.bytes_received,
        steps,
    })
}

#[cfg(test)]
struct HttpProxySelfTestOutcome {
    routed_outbound: String,
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    proxied_authority: String,
    bytes_sent: usize,
    bytes_received: usize,
}

#[cfg(test)]
async fn run_http_proxy_self_test(payload: &[u8]) -> Result<HttpProxySelfTestOutcome, String> {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind HTTP proxy self-test target: {error}"))?;
    let target_addr = target_listener
        .local_addr()
        .map_err(|error| format!("failed to read HTTP proxy target addr: {error}"))?;
    let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });

    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind HTTP proxy self-test proxy: {error}"))?;
    let proxy_addr = proxy_listener
        .local_addr()
        .map_err(|error| format!("failed to read HTTP proxy addr: {error}"))?;
    let (connect_tx, connect_rx) = oneshot::channel();
    let proxy_task =
        tokio::spawn(async move { serve_one_http_connect_proxy(proxy_listener, connect_tx).await });

    let profile = http_proxy_self_test_profile(proxy_addr);
    let runtime = Arc::new(NativeCoreRuntime::compile(&profile));
    let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind HTTP proxy self-test core listener: {error}"))?;
    let listen_addr = core_listener
        .local_addr()
        .map_err(|error| format!("failed to read HTTP proxy self-test core addr: {error}"))?;
    let core_task_runtime = runtime.clone();
    let core_task =
        tokio::spawn(
            async move { serve_one_connect_session(core_listener, core_task_runtime).await },
        );

    let received = run_connect_client(listen_addr, target_addr, payload)
        .await
        .map_err(|error| format!("HTTP proxy self-test client failed: {error}"))?;
    let proxied_authority = timeout(Duration::from_secs(3), connect_rx)
        .await
        .map_err(|_| "timed out waiting for HTTP proxy CONNECT".to_string())?
        .map_err(|_| "HTTP proxy CONNECT observer dropped".to_string())?;
    let routed_outbound = core_task
        .await
        .map_err(|error| format!("HTTP proxy self-test core task join failed: {error}"))??;
    echo_task
        .await
        .map_err(|error| format!("HTTP proxy self-test echo task join failed: {error}"))??;
    proxy_task
        .await
        .map_err(|error| format!("HTTP proxy self-test proxy task join failed: {error}"))??;

    Ok(HttpProxySelfTestOutcome {
        routed_outbound,
        proxy_addr,
        target_addr,
        proxied_authority,
        bytes_sent: payload.len(),
        bytes_received: received.len(),
    })
}

#[cfg(test)]
struct CapturedTcpOutcome {
    bytes_sent: usize,
    bytes_received: usize,
}

/// Drives one synthetic captured TCP flow end to end through the device:
/// SYN/ACK handshake against the TCP engine, a client payload relayed through
/// the ordinary flow pipeline to a loopback DIRECT upstream, and the echoed
/// response segments back out of the emission queue. This is exactly the
/// batch-API shape the macOS packet fallback uses (`execute_packet` +
/// `drain_pending_packets`).
#[cfg(test)]
async fn run_captured_tcp_self_test(
    device: &NativeCoreDevice,
    payload: &[u8],
) -> Result<CapturedTcpOutcome, String> {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind packet TCP target: {error}"))?;
    let target_addr = target_listener
        .local_addr()
        .map_err(|error| format!("failed to read packet TCP target addr: {error}"))?;
    let expected_payload = payload.to_vec();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener
            .accept()
            .await
            .map_err(|error| error.to_string())?;
        let mut buffer = vec![0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if buffer[..read] != expected_payload {
            return Err("packet TCP target received unexpected payload".into());
        }
        stream
            .write_all(&buffer[..read])
            .await
            .map_err(|error| error.to_string())
    });

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::LOCALHOST;
    let client_port = 53126;
    let server_port = target_addr.port();
    let client_isn = 1000;

    execute_self_test_tcp_packet(
        device,
        "self-test-tcp-syn",
        build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn,
            0,
            0x02,
            &[],
        ),
    )
    .await?;
    let syn_ack = wait_for_self_test_tcp_packet(device, 0x12).await?;
    let server_isn = tcp_sequence_number(&syn_ack);

    execute_self_test_tcp_packet(
        device,
        "self-test-tcp-ack",
        build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn + 1,
            server_isn + 1,
            0x10,
            &[],
        ),
    )
    .await?;
    execute_self_test_tcp_packet(
        device,
        "self-test-tcp-payload",
        build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn + 1,
            server_isn + 1,
            0x18,
            payload,
        ),
    )
    .await?;

    // Collect the echoed response segments, ACKing each so the stack keeps
    // sending; the engine emits them asynchronously as the relay delivers.
    let mut received = 0_usize;
    timeout(SELF_TEST_PEER_TIMEOUT, async {
        while received < payload.len() {
            let packet = wait_for_self_test_tcp_packet(device, 0x10).await?;
            let segment_payload_len = ipv4_tcp_payload_len(&packet);
            if segment_payload_len == 0 {
                continue;
            }
            received += segment_payload_len;
            let ack = build_ipv4_tcp_packet(
                client_ip,
                server_ip,
                client_port,
                server_port,
                client_isn + 1 + payload.len() as u32,
                tcp_sequence_number(&packet).wrapping_add(segment_payload_len as u32),
                0x10,
                &[],
            );
            execute_self_test_tcp_packet(device, "self-test-tcp-response-ack", ack).await?;
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "timed out waiting for the captured TCP echo response".to_string())??;

    target_task
        .await
        .map_err(|error| format!("packet TCP target task join failed: {error}"))??;
    Ok(CapturedTcpOutcome {
        bytes_sent: payload.len(),
        bytes_received: received,
    })
}

#[cfg(test)]
async fn execute_self_test_tcp_packet(
    device: &NativeCoreDevice,
    _label: &str,
    payload: Vec<u8>,
) -> Result<(), String> {
    device.inject_captured_tcp_packet(CapturedPacket::from_bytes(payload));
    Ok(())
}

/// Polls the device's pending-packet drain until an emitted TCP packet
/// carries the wanted flag bits.
#[cfg(test)]
async fn wait_for_self_test_tcp_packet(
    device: &NativeCoreDevice,
    wanted_flags: u8,
) -> Result<Vec<u8>, String> {
    timeout(SELF_TEST_PEER_TIMEOUT, async {
        loop {
            for packet in device.drain_pending_packets().await? {
                if ipv4_tcp_flags(&packet) & wanted_flags == wanted_flags {
                    return Ok::<Vec<u8>, String>(packet);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "timed out waiting for a TCP engine emission".to_string())?
}

#[cfg(test)]
fn ipv4_tcp_flags(packet: &[u8]) -> u8 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    packet.get(header_len + 13).copied().unwrap_or(0)
}

#[cfg(test)]
fn ipv4_tcp_payload_len(packet: &[u8]) -> usize {
    let ip_header_len = ((packet[0] & 0x0f) as usize) * 4;
    let Some(data_offset_byte) = packet.get(ip_header_len + 12) else {
        return 0;
    };
    let tcp_header_len = ((data_offset_byte >> 4) as usize) * 4;
    packet.len().saturating_sub(ip_header_len + tcp_header_len)
}

#[cfg(test)]
pub(crate) async fn serve_one_echo(listener: TcpListener) -> Result<(), String> {
    let (mut stream, _) = timeout(SELF_TEST_PEER_TIMEOUT, listener.accept())
        .await
        .map_err(|_| "timed out waiting for echo connection".to_string())?
        .map_err(|error| error.to_string())?;
    let mut buffer = [0_u8; 1024];
    let read = stream
        .read(&mut buffer)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&buffer[..read])
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// An HTTP proxy that takes CONNECT requests until it is aborted, each in a
/// task of its own: a peer for tests that dial a node more than once.
#[cfg(test)]
pub(crate) async fn serve_http_connect_proxies() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind HTTP proxy");
    let address = listener.local_addr().expect("HTTP proxy address");
    let task = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((header, tunnel_start)) = read_http_header(&mut client).await else {
                    return;
                };
                let authority = header.lines().next().and_then(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    (parts.len() == 3 && parts[0].eq_ignore_ascii_case("CONNECT"))
                        .then(|| parts[1].to_owned())
                });
                let Some(Ok(target)) =
                    authority.map(|authority| parse_connect_authority(&authority))
                else {
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect(target.authority()).await else {
                    return;
                };
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                    || upstream.write_all(&tunnel_start).await.is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (address, task)
}

/// A DNS server on UDP that answers every question after `delay`: an A
/// question with 127.0.0.1, any other with no address. It counts the A
/// questions it was asked.
#[cfg(test)]
pub(crate) struct SlowDns {
    address: SocketAddr,
    a_questions: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
impl SlowDns {
    pub(crate) async fn start(delay: Duration) -> Self {
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
        use std::sync::atomic::Ordering;

        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind DNS server"),
        );
        let address = socket.local_addr().expect("DNS server address");
        let a_questions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = a_questions.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 1500];
            while let Ok((length, sender)) = socket.recv_from(&mut buffer).await {
                let Ok(request) = crate::dns::wire::decode(&buffer[..length]) else {
                    continue;
                };
                let Some(question) = request.queries.first().cloned() else {
                    continue;
                };
                if question.query_type() == RecordType::A {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
                let socket = socket.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let mut response = crate::dns::wire::response(&request, ResponseCode::NoError);
                    if question.query_type() == RecordType::A {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::LOCALHOST)),
                        ));
                    }
                    if let Ok(response) = crate::dns::wire::encode(&response) {
                        let _ = socket.send_to(&response, sender).await;
                    }
                });
            }
        });
        Self {
            address,
            a_questions,
            task,
        }
    }

    /// The server, as a profile names it for the Core to ask directly.
    pub(crate) fn upstream(&self) -> crate::dns::config::DnsUpstream {
        crate::dns::config::DnsUpstream {
            transport: crate::dns::config::DnsTransport::Udp,
            host: self.address.ip().to_string(),
            port: self.address.port(),
            path: String::new(),
            server_name: None,
            route: Some(crate::dns::config::DnsRoute::Direct),
        }
    }

    pub(crate) fn a_questions(&self) -> usize {
        self.a_questions.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
impl Drop for SlowDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
pub(crate) async fn serve_one_http_connect_proxy(
    listener: TcpListener,
    connect_authority: oneshot::Sender<String>,
) -> Result<(), String> {
    let (mut client, _) = timeout(SELF_TEST_PEER_TIMEOUT, listener.accept())
        .await
        .map_err(|_| "timed out waiting for HTTP proxy connection".to_string())?
        .map_err(|error| error.to_string())?;
    let (header, tunnel_start) = read_http_header(&mut client).await?;
    let request_line = header
        .lines()
        .next()
        .ok_or_else(|| "HTTP proxy request missing request line".to_string())?;
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Err(format!("expected proxy CONNECT, got {request_line}"));
    }

    let target = parse_connect_authority(parts[1])?;
    let _ = connect_authority.send(target.authority());
    let mut upstream = TcpStream::connect(target.authority())
        .await
        .map_err(|error| error.to_string())?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| error.to_string())?;
    upstream
        .write_all(&tunnel_start)
        .await
        .map_err(|error| error.to_string())?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// An HTTP CONNECT proxy that never dials the authority — for sniff-stage
/// tests whose targets are unroutable TEST-NET addresses (the sniff happens
/// before the dial, so the "upstream" is this proxy, not the target). After
/// the 200 it optionally speaks first (`banner`, the server-first shape),
/// echoes every tunnel byte back, and reports the first `capture_len` tunnel
/// bytes through `captured_tunnel`.
#[cfg(test)]
pub(crate) async fn serve_one_sink_proxy(
    listener: TcpListener,
    connect_authority: oneshot::Sender<String>,
    captured_tunnel: oneshot::Sender<Vec<u8>>,
    banner: Option<Vec<u8>>,
    capture_len: usize,
) -> Result<(), String> {
    let (mut client, _) = timeout(SELF_TEST_PEER_TIMEOUT, listener.accept())
        .await
        .map_err(|_| "timed out waiting for sink proxy connection".to_string())?
        .map_err(|error| error.to_string())?;
    let (header, tunnel_start) = read_http_header(&mut client).await?;
    let request_line = header
        .lines()
        .next()
        .ok_or_else(|| "sink proxy request missing request line".to_string())?;
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Err(format!("expected proxy CONNECT, got {request_line}"));
    }
    let target = parse_connect_authority(parts[1])?;
    let _ = connect_authority.send(target.authority());
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| error.to_string())?;
    if let Some(banner) = banner {
        client
            .write_all(&banner)
            .await
            .map_err(|error| error.to_string())?;
    }

    client
        .write_all(&tunnel_start)
        .await
        .map_err(|error| error.to_string())?;
    let mut captured = tunnel_start;
    let mut captured_tunnel = Some(captured_tunnel);
    let mut buffer = [0_u8; 4096];
    loop {
        if captured.len() >= capture_len {
            if let Some(sender) = captured_tunnel.take() {
                let _ = sender.send(captured.clone());
            }
        }
        let read = match timeout(SELF_TEST_PEER_TIMEOUT, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => read,
        };
        captured.extend_from_slice(&buffer[..read]);
        if client.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    if let Some(sender) = captured_tunnel.take() {
        let _ = sender.send(captured);
    }
    Ok(())
}

#[cfg(test)]
async fn run_udp_direct_self_test(
    runtime: &NativeCoreRuntime,
    payload: &[u8],
) -> Result<UdpDirectSelfTestOutcome, String> {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind UDP self-test target: {error}"))?;
    let target_addr = target_socket
        .local_addr()
        .map_err(|error| format!("failed to read UDP target addr: {error}"))?;
    let echo_task = tokio::spawn(async move { serve_one_udp_echo(target_socket).await });

    let source_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("failed to bind UDP self-test source: {error}"))?;
    let source_addr = source_socket
        .local_addr()
        .map_err(|error| format!("failed to read UDP source addr: {error}"))?;
    drop(source_socket);

    let flow_id = "native-core-self-test-udp";
    let send = send_udp_flow_datagram(
        runtime,
        UdpDatagram {
            flow_id: Some(flow_id.into()),
            pump_queue: None,
            // The self-test drives the capture relay path end to end.
            inbound: "tun",
            user: None,
            source: source_addr,
            target: ConnectTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
            },
            payload: payload.to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await?;
    if !send.enqueued {
        return Err("UDP self-test datagram was dropped by the session mailbox".into());
    }

    let response = drain_pending_udp_flow_responses(runtime, 16, SELF_TEST_PEER_TIMEOUT)
        .await
        .into_iter()
        .find(|response| response.flow_id == flow_id)
        .ok_or_else(|| "UDP self-test timed out waiting for the flow response".to_string())?;

    echo_task
        .await
        .map_err(|error| format!("UDP echo task join failed: {error}"))??;

    let session = runtime
        .udp_sessions()
        .session_for_flow(&flow_id)
        .ok_or_else(|| "UDP self-test session was not recorded".to_string())?;
    Ok(UdpDirectSelfTestOutcome {
        outbound: session.outbound,
        matched_rule: session.matched_rule,
        bytes_sent: payload.len(),
        bytes_received: response.payload.len(),
        response_payload: response.payload,
    })
}

#[cfg(test)]
pub(crate) async fn serve_one_udp_echo(socket: UdpSocket) -> Result<(), String> {
    let mut buffer = [0_u8; 2048];
    let (read, peer) = timeout(SELF_TEST_PEER_TIMEOUT, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| "timed out waiting for UDP echo packet".to_string())?
        .map_err(|error| error.to_string())?;
    socket
        .send_to(&buffer[..read], peer)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
async fn serve_one_connect_session(
    listener: TcpListener,
    runtime: Arc<NativeCoreRuntime>,
) -> Result<String, String> {
    let (client, _) = timeout(SELF_TEST_PEER_TIMEOUT, listener.accept())
        .await
        .map_err(|_| "timed out waiting for native core client".to_string())?
        .map_err(|error| error.to_string())?;
    handle_connect_client(client, &runtime).await
}

#[cfg(test)]
pub(crate) async fn run_connect_client(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|error| error.to_string())?;
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    let mut received = read_connect_response(&mut stream).await?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;

    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    Ok(received)
}

/// Dials a Shadowsocks server with the in-tree client half (the shipping
/// [`ShadowsocksConnector`](crate::protocols::shadowsocks::connector::ShadowsocksConnector))
/// and relays one payload to `target` through it, returning the bytes echoed
/// back. The server-composition gate (`egrio-daemon`) uses it to drive a
/// live `CoreInbound::Shadowsocks` listener with the real connector instead of
/// reconstructing the AEAD handshake in the test; the connector stays
/// crate-private while this thin wrapper is the public dialing seam.
pub async fn run_shadowsocks_connect_client(
    server_addr: SocketAddr,
    cipher: &str,
    password: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::OutboundConnector;
    use crate::protocols::shadowsocks::connector::ShadowsocksConnector;

    // A throwaway egress with the open-proxy floor off, so the client can dial
    // the loopback test server; the connector is the exact one the outbound
    // resolver builds for a Shadowsocks proxy hop.
    let egress = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
    let connector = ShadowsocksConnector::new(
        server_addr.ip().to_string(),
        server_addr.port(),
        &serde_json::json!({ "cipher": cipher, "password": password }),
    );
    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let mut stream = connector
        .connect_stream(&egress, &target, b"")
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;

    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    Ok(received)
}

/// Dials a Trojan server with the in-tree client half
/// ([`TrojanConnector`](crate::protocols::trojan::TrojanConnector)) and relays
/// one TCP payload to `target` through it, returning the bytes echoed back. The
/// server-composition gate (`egrio-daemon`) uses it to drive a live Trojan
/// inbound with the real connector; the connector stays crate-private while this
/// thin wrapper is the public dialing seam. `skip-cert-verify` is on: the gate
/// presents a self-signed cert for `sni`.
pub async fn run_trojan_connect_client(
    server_addr: SocketAddr,
    password: &str,
    sni: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::OutboundConnector;
    use crate::protocols::trojan::TrojanConnector;

    let egress = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
    let connector = TrojanConnector::new(
        server_addr.ip().to_string(),
        server_addr.port(),
        &serde_json::json!({ "password": password, "sni": sni, "skip-cert-verify": true }),
    );
    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let mut stream = connector
        .connect_stream(&egress, &target, b"")
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;

    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    Ok(received)
}

/// Dials a Hysteria2 server with the in-tree client half
/// ([`Hysteria2Connector`](crate::protocols::hysteria2::Hysteria2Connector))
/// and relays one TCP payload to `target` through it, returning the bytes
/// echoed back. The server-composition gate (`egrio-daemon`) uses it to drive
/// a live Hysteria2 QUIC/H3 listener with the real connector; the connector
/// stays crate-private while this thin wrapper is the public dialing seam.
/// `skip-cert-verify` is on: the gate presents a self-signed cert for `sni`.
pub async fn run_hysteria2_connect_client(
    server_addr: SocketAddr,
    auth: &str,
    sni: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::OutboundConnector;
    use crate::protocols::hysteria2::Hysteria2Connector;

    let egress = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
    let connector = Hysteria2Connector::new(
        server_addr.ip().to_string(),
        server_addr.port(),
        &serde_json::json!({ "password": auth, "sni": sni, "skip-cert-verify": true }),
    );
    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let mut stream = connector
        .connect_stream(&egress, &target, b"")
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;

    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    Ok(received)
}

/// Dials a Hysteria2 server with the in-tree client half and relays one UDP
/// datagram to `target` through it, returning the datagram echoed back. The
/// server-composition gate uses it to exercise the Hysteria2 datagram face of a
/// live QUIC/H3 listener; `skip-cert-verify` is on for the gate's self-signed
/// cert.
pub async fn run_hysteria2_udp_client(
    server_addr: SocketAddr,
    auth: &str,
    sni: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::{OutboundConnector, OutboundDatagramTransport};
    use crate::protocols::hysteria2::Hysteria2Connector;

    let egress = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
    let connector = Hysteria2Connector::new(
        server_addr.ip().to_string(),
        server_addr.port(),
        &serde_json::json!({ "password": auth, "sni": sni, "skip-cert-verify": true }),
    );
    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let OutboundDatagramTransport {
        sender,
        mut receiver,
        ..
    } = connector
        .connect_datagram(&egress, &target)
        .await
        .map_err(|error| error.to_string())?;
    sender.send(&target, payload).await?;
    match timeout(SELF_TEST_PEER_TIMEOUT, receiver.recv()).await {
        Ok(Ok(Some((_from, response)))) => Ok(response),
        Ok(Ok(None)) => Err("hysteria2 UDP transport closed before a response".into()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err("timed out waiting for hysteria2 UDP response".into()),
    }
}

/// Dials a Trojan server's UDP associate by hand — the connector has no UDP half
/// yet — and relays one datagram to `target`, returning the datagram echoed back.
/// The server-composition gate uses it to exercise the Trojan datagram face of a
/// live TLS listener; `skip-cert-verify` is on for the gate's self-signed cert.
#[cfg(feature = "server")]
pub async fn run_trojan_udp_client(
    server_addr: SocketAddr,
    password: &str,
    sni: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use rustls_pki_types::ServerName;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use crate::protocols::trojan::codec::{
        encode_client_preamble, encode_udp_frame, password_hash_hex, read_udp_frame,
        CMD_UDP_ASSOCIATE,
    };

    let tcp = TcpStream::connect(server_addr)
        .await
        .map_err(|error| error.to_string())?;
    let tls = TlsConnector::from(crate::tls::client_config(true, &[]));
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|error| format!("invalid Trojan SNI: {error}"))?;
    let mut stream = tls
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("Trojan TLS handshake failed: {error}"))?;

    // Preamble: authenticate and open the UDP associate. Its own address is a
    // placeholder — each datagram below carries its own target.
    let hash = password_hash_hex(password);
    let placeholder = ConnectTarget {
        host: "0.0.0.0".into(),
        port: 0,
    };
    let preamble = encode_client_preamble(&hash, CMD_UDP_ASSOCIATE, &placeholder)?;
    stream
        .write_all(&preamble)
        .await
        .map_err(|error| error.to_string())?;

    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let frame = encode_udp_frame(&target, payload)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;

    match timeout(SELF_TEST_PEER_TIMEOUT, read_udp_frame(&mut stream)).await {
        Ok(Ok(Some((_from, response)))) => Ok(response),
        Ok(Ok(None)) => Err("trojan UDP transport closed before a response".into()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("timed out waiting for trojan UDP response".into()),
    }
}

/// Dials a Shadowsocks server with the in-tree client half and relays one UDP
/// datagram to `target` through it, returning the datagram echoed back. The
/// server-composition gate uses it to exercise the Shadowsocks UDP server face.
pub async fn run_shadowsocks_udp_client(
    server_addr: SocketAddr,
    cipher: &str,
    password: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::{OutboundConnector, OutboundDatagramTransport};
    use crate::protocols::shadowsocks::ShadowsocksConnector;

    let egress = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
    let connector = ShadowsocksConnector::new(
        server_addr.ip().to_string(),
        server_addr.port(),
        &serde_json::json!({ "cipher": cipher, "password": password }),
    );
    let target = ConnectTarget {
        host: target.ip().to_string(),
        port: target.port(),
    };
    let OutboundDatagramTransport {
        sender,
        mut receiver,
        ..
    } = connector
        .connect_datagram(&egress, &target)
        .await
        .map_err(|error| error.to_string())?;
    sender.send(&target, payload).await?;
    match timeout(SELF_TEST_PEER_TIMEOUT, receiver.recv()).await {
        Ok(Ok(Some((_from, response)))) => Ok(response),
        Ok(Ok(None)) => Err("shadowsocks UDP transport closed before a response".into()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err("timed out waiting for shadowsocks UDP response".into()),
    }
}

#[cfg(test)]
pub(crate) async fn run_socks5_client(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| error.to_string())?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| error.to_string())?;
    if method != [0x05, 0x00] {
        return Err(format!("SOCKS5 no-auth negotiation failed: {method:?}"));
    }

    let SocketAddr::V4(target_v4) = target_addr else {
        return Err("SOCKS5 self-test only uses IPv4 target".into());
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_v4.ip().octets());
    request.extend_from_slice(&target_v4.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| error.to_string())?;
    let mut reply = [0_u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| error.to_string())?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed with status {}", reply[1]));
    }

    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;

    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    Ok(received)
}

#[cfg(test)]
fn build_ipv4_tcp_packet(
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

#[cfg(test)]
fn tcp_sequence_number(packet: &[u8]) -> u32 {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    u32::from_be_bytes([
        packet[header_len + 4],
        packet[header_len + 5],
        packet[header_len + 6],
        packet[header_len + 7],
    ])
}

#[cfg(test)]
/// Returns the tunnel bytes that arrived with the response.
async fn read_connect_response(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let (header, tunnel_start) = read_http_header(stream).await?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| "CONNECT response is empty".to_string())?;
    if status_line.contains(" 200 ") {
        Ok(tunnel_start)
    } else {
        Err(format!("CONNECT failed: {status_line}"))
    }
}

#[cfg(test)]
pub(crate) fn self_test_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("native-core-self-test");
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::IpCidr,
            payload: Some("127.0.0.0/8"),
            outbound: "DIRECT",
            no_resolve: true,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        },
    ]
    .into();
    profile
}

#[cfg(test)]
fn http_proxy_self_test_profile(proxy_addr: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("native-core-http-proxy-self-test");
    profile.proxies = vec![ProxyNode {
        id: "proxy-HttpProxy".into(),
        name: "HttpProxy".into(),
        protocol: ProxyProtocol::Http,
        server: Some(proxy_addr.ip().to_string()),
        port: Some(proxy_addr.port()),
        options: serde_json::Value::Null,
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "HttpProxy",
        no_resolve: false,
    }]
    .into();
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_core_self_test_tunnels_payload() {
        let report = run_native_core_self_test()
            .await
            .expect("self-test should run");

        assert!(report.ok);
        assert_eq!(report.bytes_sent, report.bytes_received);
        assert!(report
            .steps
            .iter()
            .any(|step| step.label == "udp-direct-datagram" && step.ok));
        assert!(report
            .steps
            .iter()
            .any(|step| step.label == "tcp-http-proxy-outbound" && step.ok));
    }
}
