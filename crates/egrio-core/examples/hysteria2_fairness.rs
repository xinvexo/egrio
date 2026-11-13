//! Per-flow stalls of many uploads sharing one Hysteria2 connection.
//!
//! A client Core whose mixed listener routes everything through a Hysteria2
//! node, and a sink. `EGRIO_FLOWS` SOCKS5 connections upload as fast as they
//! can for `EGRIO_SECONDS`; the sink reports each flow's bytes and its
//! longest gap between arriving reads as one JSON object. By default the node
//! is a server Core with a Hysteria2 inbound and the sink listens on loopback,
//! each party on its own Tokio runtime so the client's scheduling is not
//! shared with the apps and the server.
//!
//! Usage:
//!   cargo run --release -p egrio-core --features server --example hysteria2_fairness
//!   EGRIO_FLOWS=16 EGRIO_SECONDS=10 EGRIO_HY2_UP="400 Mbps"
//!
//! Against a real server, which dials the sink back over the network:
//!   EGRIO_HY2_SERVER=host:port EGRIO_HY2_PASSWORD=… [EGRIO_HY2_SNI=name]
//!   EGRIO_SINK=<this host's address>:<port the sink listens on>

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egrio_core::{
    CoreInbound, CoreSessionManager, CoreSessionStartConfig, Hysteria2Inbound,
    NativeCoreEgressConfig, ProxyNode, ProxyProtocol, RouteRule, RouteRules, RuleKind,
    RuntimeProfile,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 256 * 1024;
const PASSWORD: &str = "fairness";

struct FlowReport {
    bytes: u64,
    longest_gap: Duration,
    gaps_over_100ms: u32,
}

/// The Hysteria2 node the client uses.
struct Node {
    server: String,
    port: u16,
    password: String,
    sni: String,
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn runtime(threads: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn match_rule(outbound: &str) -> RouteRules {
    [RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound,
        no_resolve: false,
    }]
    .into()
}

/// Starts a server Core with a Hysteria2 inbound on loopback.
fn local_node(server: &CoreSessionManager, runtime: &tokio::runtime::Runtime) -> Node {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .expect("params")
        .self_signed(&key_pair)
        .expect("self-signed cert");
    let address: SocketAddr = runtime.block_on(async {
        let mut profile = RuntimeProfile::new("hy2-fairness-server");
        profile.rules = match_rule("DIRECT");
        server
            .start_with_config(CoreSessionStartConfig {
                profile,
                egress: NativeCoreEgressConfig::default(),
                listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                dns_listen_addr: None,
                inbound: CoreInbound::Mixed,
                hysteria2: Some(Hysteria2Inbound {
                    listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    cert_pem: cert.pem().into_bytes(),
                    key_pem: key_pair.serialize_pem().into_bytes(),
                    users: vec![("bench".into(), PASSWORD.into())],
                }),
                socket_guard: None,
            })
            .await
            .expect("server starts");
        server
            .hysteria2_listen_addr()
            .expect("hysteria2 listen address")
            .parse()
            .expect("socket address")
    });
    Node {
        server: address.ip().to_string(),
        port: address.port(),
        password: PASSWORD.into(),
        sni: "localhost".into(),
    }
}

fn remote_node(server: &str) -> Node {
    let address: SocketAddr = server.parse().expect("EGRIO_HY2_SERVER is host:port");
    Node {
        server: address.ip().to_string(),
        port: address.port(),
        password: std::env::var("EGRIO_HY2_PASSWORD").expect("EGRIO_HY2_PASSWORD"),
        sni: std::env::var("EGRIO_HY2_SNI").unwrap_or_else(|_| address.ip().to_string()),
    }
}

fn main() {
    let flows: usize = env_or("EGRIO_FLOWS", 16);
    let seconds: u64 = env_or("EGRIO_SECONDS", 10);
    let up = std::env::var("EGRIO_HY2_UP").ok();
    let client_threads: usize = env_or("EGRIO_CLIENT_THREADS", 4);
    let sink: Option<SocketAddr> = std::env::var("EGRIO_SINK")
        .ok()
        .map(|sink| sink.parse().expect("EGRIO_SINK is address:port"));

    let server_runtime = runtime(4);
    let server = CoreSessionManager::default();
    let node = match std::env::var("EGRIO_HY2_SERVER") {
        Ok(remote) => remote_node(&remote),
        Err(_) => local_node(&server, &server_runtime),
    };

    let client_runtime = runtime(client_threads);
    let client = CoreSessionManager::default();
    let proxy_addr: SocketAddr = client_runtime.block_on(async {
        let mut options =
            json!({ "password": node.password, "skip-cert-verify": true, "sni": node.sni });
        if let Some(up) = &up {
            options["up"] = json!(up);
        }
        let mut profile = RuntimeProfile::new("hy2-fairness-client");
        profile.proxies = vec![ProxyNode {
            id: "hy2".into(),
            name: "hy2".into(),
            protocol: ProxyProtocol::Hysteria2,
            server: Some(node.server.clone()),
            port: Some(node.port),
            options,
        }];
        profile.rules = match_rule("hy2");
        let status = client
            .start_with_config(CoreSessionStartConfig {
                profile,
                egress: NativeCoreEgressConfig::default(),
                listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                dns_listen_addr: None,
                inbound: CoreInbound::Mixed,
                hysteria2: None,
                socket_guard: None,
            })
            .await
            .expect("client starts");
        status
            .listen_addr
            .expect("client listen address")
            .parse()
            .expect("socket address")
    });

    let apps = runtime(4);
    apps.block_on(async move {
        let (listener, target) = match sink {
            Some(sink) => (
                TcpListener::bind((Ipv4Addr::UNSPECIFIED, sink.port()))
                    .await
                    .expect("sink"),
                sink,
            ),
            None => {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("sink");
                let address = listener.local_addr().expect("sink address");
                (listener, address)
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let collector = tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..flows {
                let (stream, _) = listener.accept().await.expect("sink accept");
                readers.push(tokio::spawn(read_flow(stream)));
            }
            let mut reports = Vec::new();
            for reader in readers {
                reports.push(reader.await.expect("reader"));
            }
            reports
        });

        let mut writers = Vec::new();
        for _ in 0..flows {
            let stop = stop.clone();
            writers.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(proxy_addr).await.expect("connect proxy");
                stream.set_nodelay(true).ok();
                socks5_handshake(&mut stream, target).await.expect("SOCKS5");
                let chunk = vec![0x5a_u8; CHUNK];
                while !stop.load(Ordering::Relaxed) {
                    if stream.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            }));
        }
        let begin = Instant::now();
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        stop.store(true, Ordering::Relaxed);
        for writer in writers {
            let _ = writer.await;
        }
        let elapsed = begin.elapsed().as_secs_f64();
        let reports = collector.await.expect("collector");
        let total: u64 = reports.iter().map(|report| report.bytes).sum();
        let mut gaps: Vec<u128> = reports
            .iter()
            .map(|report| report.longest_gap.as_millis())
            .collect();
        gaps.sort_unstable();
        let flow_mb: Vec<String> = reports
            .iter()
            .map(|report| format!("{:.1}", report.bytes as f64 / 1e6))
            .collect();
        println!(
            "{{ \"harness\": \"egrio-core hysteria2_fairness\", \"os\": \"{}\", \"flows\": {flows}, \"seconds\": {elapsed:.2}, \"mb_per_s\": {:.1}, \"longest_gap_ms\": {}, \"gaps_over_100ms\": {}, \"flow_longest_gap_ms\": {gaps:?}, \"flow_mb\": [{}] }}",
            std::env::consts::OS,
            total as f64 / elapsed / 1e6,
            gaps.last().copied().unwrap_or(0),
            reports.iter().map(|report| report.gaps_over_100ms).sum::<u32>(),
            flow_mb.join(", "),
        );
    });
    client.stop();
    server.stop();
}

/// Drains one flow at the sink, timing the gaps between reads after the
/// first.
async fn read_flow(mut stream: TcpStream) -> FlowReport {
    let mut buffer = vec![0_u8; CHUNK];
    let mut report = FlowReport {
        bytes: 0,
        longest_gap: Duration::ZERO,
        gaps_over_100ms: 0,
    };
    let mut last: Option<Instant> = None;
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let now = Instant::now();
                if let Some(last) = last {
                    let gap = now - last;
                    report.longest_gap = report.longest_gap.max(gap);
                    if gap > Duration::from_millis(100) {
                        report.gaps_over_100ms += 1;
                    }
                }
                last = Some(now);
                report.bytes += read as u64;
            }
        }
    }
    report
}

async fn socks5_handshake(stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| format!("SOCKS greeting write: {error}"))?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("SOCKS greeting read: {error}"))?;
    let SocketAddr::V4(target) = target else {
        return Err("harness peers are IPv4".into());
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS connect write: {error}"))?;
    let mut reply = [0_u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| format!("SOCKS connect read: {error}"))?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS connect rejected: code {:#04x}", reply[1]));
    }
    Ok(())
}
