//! Configuration-driven validation flows. Proxy-mode validation proves the
//! local core listener path end
//! to end without touching system state: an upstream stub core (DIRECT
//! profile) stands in for the profile's HTTP/SOCKS5 proxy node, the profile
//! under test is rewritten in memory to dial it, and bounded HTTP-CONNECT
//! and SOCKS5 probes run through the under-test listener to a loopback echo
//! target. The upstream core's accepted-session delta is the proof that the
//! probes used the configured proxy node instead of going direct.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use egrio_core::{CoreSessionManager, NativeCoreEgressConfig, ProxyProtocol, RuntimeProfile};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::profile_handoff::{default_direct_profile, load_profile};

const PROXY_MODE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_MODE_PROBE_PAYLOAD: &[u8] = b"egrio-proxy-mode-validation-probe";

#[derive(Debug, Clone, Serialize)]
pub struct ProxyModeValidationReport {
    pub ok: bool,
    pub runtime_profile_path: String,
    pub profile_id: String,
    pub proxy_node: String,
    pub proxy_protocol: String,
    pub upstream_listen_addr: String,
    pub listen_addr: String,
    pub echo_target_addr: String,
    pub http_inbound_probe: ProxyModeProbeReport,
    pub socks5_inbound_probe: ProxyModeProbeReport,
    /// Sessions the upstream stub accepted while the probes ran. Two probes
    /// through the proxy node yield at least two upstream sessions; zero
    /// means traffic bypassed the node (for example a missing MATCH rule).
    pub upstream_accepted_sessions_delta: u64,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyModeProbeReport {
    pub inbound: &'static str,
    pub success: bool,
    pub elapsed_ms: u128,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub error: Option<String>,
}

/// Synchronous CLI entry: builds a runtime and runs the async flow.
pub fn run_proxy_mode_validation(
    runtime_profile_path: String,
) -> Result<ProxyModeValidationReport, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("egrio-proxy-mode-validation")
        .build()
        .map_err(|error| format!("failed to create validation runtime: {error}"))?;
    runtime.block_on(run_proxy_mode_validation_async(runtime_profile_path))
}

pub async fn run_proxy_mode_validation_async(
    runtime_profile_path: String,
) -> Result<ProxyModeValidationReport, String> {
    let mut profile = load_profile(Some(runtime_profile_path.clone()))?;
    let profile_id = profile.id.clone();
    let (proxy_node, proxy_protocol) = validation_proxy_node(&profile)?;

    let (echo_target_addr, echo_task) = spawn_echo_target().await?;

    // The upstream stub is a second core instance serving a DIRECT profile:
    // its mixed listener speaks both HTTP CONNECT and SOCKS5, so it can stand
    // in for either proxy-node protocol using only product code.
    let upstream = CoreSessionManager::default();
    let upstream_status = upstream.start(default_direct_profile()).await?;
    let upstream_listen_addr = upstream_status
        .listen_addr
        .clone()
        .ok_or_else(|| "upstream stub core started without a listen address".to_string())?;
    let upstream_accepted_before = upstream_status.accepted_sessions;

    let upstream_socket: SocketAddr = upstream_listen_addr
        .parse()
        .map_err(|error| format!("upstream stub listen address is invalid: {error}"))?;
    rewrite_proxy_node_endpoint(&mut profile, &proxy_node, upstream_socket);

    let under_test = CoreSessionManager::default();
    let listen_addr = match under_test.start(profile).await {
        Ok(status) => match status.listen_addr {
            Some(listen_addr) => listen_addr,
            None => {
                upstream.stop();
                echo_task.abort();
                return Err("core under test started without a listen address".into());
            }
        },
        Err(error) => {
            upstream.stop();
            echo_task.abort();
            return Err(format!("core under test failed to start: {error}"));
        }
    };

    let http_inbound_probe = http_connect_probe(&listen_addr, echo_target_addr).await;
    let socks5_inbound_probe = socks5_connect_probe(&listen_addr, echo_target_addr).await;

    let upstream_accepted_after = upstream.status().accepted_sessions;
    under_test.stop();
    upstream.stop();
    echo_task.abort();

    let upstream_accepted_sessions_delta =
        upstream_accepted_after.saturating_sub(upstream_accepted_before);
    let mut blockers = Vec::new();
    if !http_inbound_probe.success {
        blockers.push(format!(
            "HTTP inbound probe failed: {}",
            http_inbound_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    if !socks5_inbound_probe.success {
        blockers.push(format!(
            "SOCKS5 inbound probe failed: {}",
            socks5_inbound_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    if upstream_accepted_sessions_delta < 2 {
        blockers.push(format!(
            "upstream proxy stub accepted {upstream_accepted_sessions_delta} session(s); expected one per probe, so traffic bypassed the configured proxy node"
        ));
    }

    Ok(ProxyModeValidationReport {
        ok: blockers.is_empty(),
        runtime_profile_path,
        profile_id,
        proxy_node,
        proxy_protocol,
        upstream_listen_addr,
        listen_addr,
        echo_target_addr: echo_target_addr.to_string(),
        http_inbound_probe,
        socks5_inbound_probe,
        upstream_accepted_sessions_delta,
        blockers,
    })
}

fn validation_proxy_node(profile: &RuntimeProfile) -> Result<(String, String), String> {
    let [node] = profile.proxies.as_slice() else {
        return Err(format!(
            "proxy-mode validation profiles carry exactly one proxy node; found {}",
            profile.proxies.len()
        ));
    };
    let protocol = match node.protocol {
        ProxyProtocol::Http => "http",
        ProxyProtocol::Socks5 => "socks5",
        ref other => {
            return Err(format!(
                "proxy-mode validation covers HTTP and SOCKS5 proxy nodes; found {other:?}"
            ))
        }
    };
    Ok((node.name.clone(), protocol.into()))
}

fn rewrite_proxy_node_endpoint(
    profile: &mut RuntimeProfile,
    proxy_node: &str,
    upstream: SocketAddr,
) {
    for node in &mut profile.proxies {
        if node.name == proxy_node {
            node.server = Some(upstream.ip().to_string());
            node.port = Some(upstream.port());
        }
    }
}

pub(crate) async fn spawn_echo_target() -> Result<(SocketAddr, JoinHandle<()>), String> {
    spawn_echo_target_on(IpAddr::V4(Ipv4Addr::LOCALHOST)).await
}

async fn spawn_echo_target_on(bind_ip: IpAddr) -> Result<(SocketAddr, JoinHandle<()>), String> {
    let listener = TcpListener::bind((bind_ip, 0))
        .await
        .map_err(|error| format!("failed to bind validation echo target on {bind_ip}: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("failed to read validation echo target addr: {error}"))?;
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok((addr, task))
}

pub(crate) async fn http_connect_probe(
    listen_addr: &str,
    target: SocketAddr,
) -> ProxyModeProbeReport {
    probe_report("http", async move {
        let mut stream = TcpStream::connect(listen_addr)
            .await
            .map_err(|error| format!("connect to listener failed: {error}"))?;
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("CONNECT write failed: {error}"))?;

        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            if response.len() > 4096 {
                return Err("CONNECT response exceeded 4096 bytes".into());
            }
            let read = stream
                .read(&mut byte)
                .await
                .map_err(|error| format!("CONNECT response read failed: {error}"))?;
            if read == 0 {
                return Err("listener closed during CONNECT response".into());
            }
            response.push(byte[0]);
        }
        let status_line = String::from_utf8_lossy(&response);
        if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
            return Err(format!(
                "CONNECT was not accepted: {}",
                status_line.lines().next().unwrap_or_default()
            ));
        }

        echo_roundtrip(stream, request.len()).await
    })
    .await
}

async fn socks5_connect_probe(listen_addr: &str, target: SocketAddr) -> ProxyModeProbeReport {
    probe_report("socks5", async move {
        let mut stream = TcpStream::connect(listen_addr)
            .await
            .map_err(|error| format!("connect to listener failed: {error}"))?;
        let mut sent = 0_usize;

        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|error| format!("SOCKS5 greeting write failed: {error}"))?;
        sent += 3;
        let mut method = [0_u8; 2];
        stream
            .read_exact(&mut method)
            .await
            .map_err(|error| format!("SOCKS5 method read failed: {error}"))?;
        if method != [0x05, 0x00] {
            return Err(format!("SOCKS5 method negotiation failed: {method:?}"));
        }

        let mut request = vec![0x05, 0x01, 0x00];
        match target.ip() {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());
        stream
            .write_all(&request)
            .await
            .map_err(|error| format!("SOCKS5 CONNECT write failed: {error}"))?;
        sent += request.len();

        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|error| format!("SOCKS5 reply read failed: {error}"))?;
        if header[1] != 0x00 {
            return Err(format!("SOCKS5 CONNECT was rejected: REP {}", header[1]));
        }
        let bind_len = match header[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut len = [0_u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|error| format!("SOCKS5 bind addr read failed: {error}"))?;
                len[0] as usize + 2
            }
            other => return Err(format!("SOCKS5 reply has unsupported ATYP {other}")),
        };
        let mut bind = vec![0_u8; bind_len];
        stream
            .read_exact(&mut bind)
            .await
            .map_err(|error| format!("SOCKS5 bind addr read failed: {error}"))?;

        echo_roundtrip(stream, sent).await
    })
    .await
}

async fn echo_roundtrip(
    mut stream: TcpStream,
    handshake_bytes: usize,
) -> Result<(usize, usize), String> {
    stream
        .write_all(PROXY_MODE_PROBE_PAYLOAD)
        .await
        .map_err(|error| format!("probe payload write failed: {error}"))?;
    let mut echoed = vec![0_u8; PROXY_MODE_PROBE_PAYLOAD.len()];
    stream
        .read_exact(&mut echoed)
        .await
        .map_err(|error| format!("probe echo read failed: {error}"))?;
    if echoed != PROXY_MODE_PROBE_PAYLOAD {
        return Err("probe echo did not match the sent payload".into());
    }
    Ok((
        handshake_bytes + PROXY_MODE_PROBE_PAYLOAD.len(),
        echoed.len(),
    ))
}

async fn probe_report(
    inbound: &'static str,
    probe: impl std::future::Future<Output = Result<(usize, usize), String>>,
) -> ProxyModeProbeReport {
    let started = Instant::now();
    let outcome = timeout(PROXY_MODE_PROBE_TIMEOUT, probe).await;
    let elapsed_ms = started.elapsed().as_millis();
    match outcome {
        Ok(Ok((bytes_sent, bytes_received))) => ProxyModeProbeReport {
            inbound,
            success: true,
            elapsed_ms,
            bytes_sent,
            bytes_received,
            error: None,
        },
        Ok(Err(error)) => ProxyModeProbeReport {
            inbound,
            success: false,
            elapsed_ms,
            bytes_sent: 0,
            bytes_received: 0,
            error: Some(error),
        },
        Err(_) => ProxyModeProbeReport {
            inbound,
            success: false,
            elapsed_ms,
            bytes_sent: 0,
            bytes_received: 0,
            error: Some(format!(
                "probe timed out after {} ms",
                PROXY_MODE_PROBE_TIMEOUT.as_millis()
            )),
        },
    }
}

/// End-to-end IPv6 DNS policy check on local Core listeners. Numeric `[::1]`
/// destinations remain reachable through HTTP CONNECT and SOCKS5 with AAAA
/// disabled. Hot-applying IPv6 DNS enables AAAA without changing that numeric
/// connectivity. `localhost` makes the DNS probes deterministic and offline.
#[derive(Debug, Clone, Serialize)]
pub struct Ipv6ClosedLoopValidationReport {
    pub ok: bool,
    pub ipv6_loopback_available: bool,
    pub listen_addr: String,
    pub dns_listen_addr: String,
    pub echo_target_addr: String,
    pub disabled_http_probe: ProxyModeProbeReport,
    pub disabled_socks5_probe: ProxyModeProbeReport,
    pub disabled_aaaa_answers: Option<u16>,
    pub disabled_a_answers: Option<u16>,
    pub enabled_http_probe: ProxyModeProbeReport,
    pub enabled_socks5_probe: ProxyModeProbeReport,
    pub enabled_aaaa_answers: Option<u16>,
    pub blockers: Vec<String>,
}

pub fn run_ipv6_closed_loop_validation() -> Result<Ipv6ClosedLoopValidationReport, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("egrio-ipv6-validation")
        .build()
        .map_err(|error| format!("failed to create validation runtime: {error}"))?;
    runtime.block_on(run_ipv6_closed_loop_validation_async())
}

pub async fn run_ipv6_closed_loop_validation_async(
) -> Result<Ipv6ClosedLoopValidationReport, String> {
    let mut blockers = Vec::new();

    let (echo_target_addr, echo_task) =
        match spawn_echo_target_on(IpAddr::V6(Ipv6Addr::LOCALHOST)).await {
            Ok(bound) => bound,
            Err(error) => {
                return Ok(Ipv6ClosedLoopValidationReport {
                    ok: false,
                    ipv6_loopback_available: false,
                    listen_addr: String::new(),
                    dns_listen_addr: String::new(),
                    echo_target_addr: String::new(),
                    disabled_http_probe: skipped_probe("http"),
                    disabled_socks5_probe: skipped_probe("socks5"),
                    disabled_aaaa_answers: None,
                    disabled_a_answers: None,
                    enabled_http_probe: skipped_probe("http"),
                    enabled_socks5_probe: skipped_probe("socks5"),
                    enabled_aaaa_answers: None,
                    blockers: vec![format!(
                        "IPv6 loopback is unavailable on this host: {error}"
                    )],
                });
            }
        };

    let under_test = CoreSessionManager::default();
    let status = under_test.start(default_direct_profile()).await?;
    let listen_addr = status
        .listen_addr
        .clone()
        .ok_or_else(|| "core under test started without a listen address".to_string())?;
    let dns_listen_addr = status
        .dns_listen_addr
        .clone()
        .ok_or_else(|| "core under test started without a DNS listen address".to_string())?;

    // Phase 1 — IPv6 DNS disabled; numeric IPv6 connections remain usable.
    let disabled_http_probe = http_connect_probe(&listen_addr, echo_target_addr).await;
    if !disabled_http_probe.success {
        blockers.push(format!(
            "disabled-phase HTTP CONNECT relay failed: {}",
            disabled_http_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    let disabled_socks5_probe = socks5_connect_probe(&listen_addr, echo_target_addr).await;
    if !disabled_socks5_probe.success {
        blockers.push(format!(
            "disabled-phase SOCKS5 relay failed: {}",
            disabled_socks5_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    let disabled_aaaa = dns_answer_probe(&dns_listen_addr, "localhost", 28).await;
    let disabled_a = dns_answer_probe(&dns_listen_addr, "localhost", 1).await;
    let disabled_aaaa_answers = record_dns_probe(
        &mut blockers,
        "disabled-phase AAAA",
        &disabled_aaaa,
        |answers| answers == 0,
        "expected zero answers while IPv6 DNS is disabled",
    );
    let disabled_a_answers = record_dns_probe(
        &mut blockers,
        "disabled-phase A",
        &disabled_a,
        |answers| answers >= 1,
        "expected at least one answer (the DNS listener itself must work)",
    );

    // Phase 2 — hot-apply IPv6 DNS onto the running Core.
    under_test.apply_profile_and_egress(
        &default_direct_profile(),
        NativeCoreEgressConfig {
            ipv6_enabled: true,
            refuse_private_destinations: false,
            ..NativeCoreEgressConfig::default()
        },
    )?;

    // Phase 3 — IPv6 DNS enabled.
    let enabled_http_probe = http_connect_probe(&listen_addr, echo_target_addr).await;
    if !enabled_http_probe.success {
        blockers.push(format!(
            "enabled-phase HTTP CONNECT relay failed: {}",
            enabled_http_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    let enabled_socks5_probe = socks5_connect_probe(&listen_addr, echo_target_addr).await;
    if !enabled_socks5_probe.success {
        blockers.push(format!(
            "enabled-phase SOCKS5 relay failed: {}",
            enabled_socks5_probe.error.as_deref().unwrap_or("unknown")
        ));
    }
    let enabled_aaaa = dns_answer_probe(&dns_listen_addr, "localhost", 28).await;
    let enabled_aaaa_answers = record_dns_probe(
        &mut blockers,
        "enabled-phase AAAA",
        &enabled_aaaa,
        |answers| answers >= 1,
        "expected the ::1 answer once IPv6 is enabled",
    );

    under_test.stop();
    echo_task.abort();

    Ok(Ipv6ClosedLoopValidationReport {
        ok: blockers.is_empty(),
        ipv6_loopback_available: true,
        listen_addr,
        dns_listen_addr,
        echo_target_addr: echo_target_addr.to_string(),
        disabled_http_probe,
        disabled_socks5_probe,
        disabled_aaaa_answers,
        disabled_a_answers,
        enabled_http_probe,
        enabled_socks5_probe,
        enabled_aaaa_answers,
        blockers,
    })
}

fn skipped_probe(inbound: &'static str) -> ProxyModeProbeReport {
    ProxyModeProbeReport {
        inbound,
        success: false,
        elapsed_ms: 0,
        bytes_sent: 0,
        bytes_received: 0,
        error: Some("skipped: IPv6 loopback unavailable".into()),
    }
}

fn record_dns_probe(
    blockers: &mut Vec<String>,
    label: &str,
    outcome: &Result<(u8, u16), String>,
    accept: impl Fn(u16) -> bool,
    expectation: &str,
) -> Option<u16> {
    match outcome {
        Ok((0, answers)) if accept(*answers) => Some(*answers),
        Ok((rcode, answers)) => {
            blockers.push(format!(
                "{label} probe returned rcode {rcode} with {answers} answer(s); {expectation}"
            ));
            Some(*answers)
        }
        Err(error) => {
            blockers.push(format!("{label} probe failed: {error}"));
            None
        }
    }
}

/// Sends one UDP DNS query to the core DNS listener and returns
/// `(rcode, answer_count)`.
async fn dns_answer_probe(
    dns_listen_addr: &str,
    domain: &str,
    qtype: u16,
) -> Result<(u8, u16), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind DNS probe socket: {error}"))?;
    socket
        .connect(dns_listen_addr)
        .await
        .map_err(|error| format!("connect DNS probe socket: {error}"))?;

    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&0x4c4c_u16.to_be_bytes());
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
    socket
        .send(&query)
        .await
        .map_err(|error| format!("send DNS probe: {error}"))?;

    let mut response = [0_u8; 512];
    let received = timeout(PROXY_MODE_PROBE_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| "DNS probe timed out".to_string())?
        .map_err(|error| format!("receive DNS probe response: {error}"))?;
    if received < 8 {
        return Err(format!("DNS probe response is too short: {received} bytes"));
    }
    Ok((
        response[3] & 0x0f,
        u16::from_be_bytes([response[6], response[7]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn ipv6_closed_loop_validation_passes_end_to_end() {
        let report = run_ipv6_closed_loop_validation_async()
            .await
            .expect("IPv6 closed-loop validation runs");

        // Machines without an IPv6 loopback cannot exercise this path.
        if !report.ipv6_loopback_available {
            return;
        }
        assert!(report.ok, "blockers: {:?}", report.blockers);
        assert!(report.disabled_http_probe.success);
        assert!(report.disabled_socks5_probe.success);
        assert_eq!(report.disabled_aaaa_answers, Some(0));
        assert!(report.disabled_a_answers.unwrap_or(0) >= 1);
        assert!(report.enabled_http_probe.success);
        assert!(report.enabled_socks5_probe.success);
        assert!(report.enabled_aaaa_answers.unwrap_or(0) >= 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_mode_validation_relays_through_the_sample_profiles() {
        for file in ["http-proxy.json", "socks5-proxy.json"] {
            let path = format!(
                "{}/../../scripts/validation/profiles/{file}",
                env!("CARGO_MANIFEST_DIR")
            );
            let report = run_proxy_mode_validation_async(path)
                .await
                .expect("proxy-mode validation runs");

            assert!(report.ok, "{file} blockers: {:?}", report.blockers);
            assert!(report.http_inbound_probe.success);
            assert!(report.socks5_inbound_probe.success);
            assert!(
                report.upstream_accepted_sessions_delta >= 2,
                "{file} upstream delta {}",
                report.upstream_accepted_sessions_delta
            );
        }
    }
}
