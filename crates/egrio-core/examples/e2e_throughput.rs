//! End-to-end throughput harness for the native core local listener.
//!
//! A loopback echo/sink/source peer, inbound handshakes through the running
//! `CoreSessionManager`, and per-direction byte pumps measure the listener
//! and relay paths. The output is a JSON report; compare baseline and
//! candidate reports on the same host (see `bench/README.md`).
//!
//! Usage:
//! The burst scenario is the server-role shape the bulk ones miss: many
//! sessions at once, each a request/response exchange with a pause between,
//! which is when a relay direction gives its buffer back and borrows again.
//! Built with `--features bench-internals` it also reports what the buffer
//! pools handed out, so the retain bounds can be read against the borrowers
//! asking together rather than guessed.
//!
//! Usage:
//!   cargo run --release -p egrio-core --example e2e_throughput [> report.json]
//!   EGRIO_E2E_BYTES=268435456 to override the per-scenario byte count.
//!   EGRIO_E2E_SESSIONS=64 EGRIO_E2E_ROUNDS=64 size the burst scenario.
//!   EGRIO_E2E_WORKERS=4 sets the worker threads the Core and the clients share.
//!   EGRIO_E2E_SETUPS=400 EGRIO_E2E_AT_ONCE=64 size the setup-latency scenario.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use egrio_core::{
    CoreInbound, CoreSessionManager, CoreSessionStartConfig, NativeCoreEgressConfig, RouteRule,
    RuleKind, RuntimeProfile,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_BYTES_PER_SCENARIO: u64 = 256 * 1024 * 1024;
const CHUNK_BYTES: usize = 256 * 1024;
/// The burst scenario: sessions in parallel, each doing this many
/// request/response exchanges of these sizes.
const DEFAULT_BURST_SESSIONS: usize = 64;
const DEFAULT_BURST_ROUNDS: usize = 64;
const BURST_REQUEST_BYTES: usize = 8 * 1024;
const BURST_RESPONSE_BYTES: usize = 32 * 1024;
/// The setup-latency scenario: how many connections it opens, and how many
/// of them it opens together in the second pass.
const DEFAULT_SETUPS: usize = 400;
const DEFAULT_SETUPS_AT_ONCE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inbound {
    HttpConnect,
    Socks5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Upload,
    Download,
}

fn main() {
    // The Core's listener runs on this runtime too, so the worker count is
    // also how many relay directions can be inside a borrow at once -- which
    // is what the buffer pools' retain bounds have to cover.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env_usize("EGRIO_E2E_WORKERS", 4))
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        if let Err(error) = run().await {
            eprintln!("e2e throughput harness failed: {error}");
            std::process::exit(1);
        }
    });
}

async fn run() -> Result<(), String> {
    let bytes_per_scenario = std::env::var("EGRIO_E2E_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_BYTES_PER_SCENARIO);

    let manager = CoreSessionManager::default();
    let status = manager
        .start_with_config(CoreSessionStartConfig {
            profile: direct_profile(),
            egress: NativeCoreEgressConfig::default(),
            listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            dns_listen_addr: None,
            inbound: CoreInbound::Mixed,
            hysteria2: None,
            socket_guard: None,
        })
        .await?;
    let proxy_addr: SocketAddr = status
        .listen_addr
        .ok_or_else(|| "core listener did not report a listen address".to_string())?
        .parse()
        .map_err(|error| format!("core listen address is not a socket address: {error}"))?;

    let mut scenarios = Vec::new();
    for inbound in [Inbound::HttpConnect, Inbound::Socks5] {
        for direction in [Direction::Upload, Direction::Download] {
            let seconds = run_scenario(proxy_addr, inbound, direction, bytes_per_scenario).await?;
            let mbps = (bytes_per_scenario as f64 / (1024.0 * 1024.0)) / seconds;
            scenarios.push(format!(
                "    {{ \"scenario\": \"{}-{}\", \"bytes\": {}, \"seconds\": {:.4}, \"mib_per_s\": {:.1} }}",
                inbound_label(inbound),
                direction_label(direction),
                bytes_per_scenario,
                seconds,
                mbps
            ));
        }
    }
    let sessions = env_usize("EGRIO_E2E_SESSIONS", DEFAULT_BURST_SESSIONS);
    let rounds = env_usize("EGRIO_E2E_ROUNDS", DEFAULT_BURST_ROUNDS);
    let pool_before = pool_borrows();
    let seconds = run_burst_scenario(proxy_addr, Inbound::Socks5, sessions, rounds).await?;
    let exchanges = (sessions * rounds) as f64;
    scenarios.push(format!(
        "    {{ \"scenario\": \"socks5-bursts\", \"sessions\": {}, \"rounds\": {}, \"seconds\": {:.4}, \"exchanges_per_s\": {:.0} }}",
        sessions, rounds, seconds, exchanges / seconds
    ));
    // Setup latency: what a new connection costs before it carries
    // anything, which the byte scenarios cannot see.
    let setups = env_usize("EGRIO_E2E_SETUPS", DEFAULT_SETUPS);
    let at_once = env_usize("EGRIO_E2E_AT_ONCE", DEFAULT_SETUPS_AT_ONCE);
    for (label, together) in [("one-at-a-time", 1), ("together", at_once)] {
        let samples = run_setup_scenario(proxy_addr, Inbound::Socks5, setups, together).await?;
        scenarios.push(setup_line(label, together, &samples));
    }
    let pool_line = pool_borrows_line(pool_before);
    manager.stop();

    println!("{{");
    println!("  \"harness\": \"egrio-core e2e_throughput\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"arch\": \"{}\",", std::env::consts::ARCH);
    println!("  \"scenarios\": [");
    println!("{}", scenarios.join(",\n"));
    println!("  ]{}", if pool_line.is_empty() { "" } else { "," });
    if !pool_line.is_empty() {
        println!("{pool_line}");
    }
    println!("}}");
    Ok(())
}

fn env_usize(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

/// Borrows the two buffer pools have served and had to allocate, when the
/// build carries the counters.
fn pool_borrows() -> Option<((usize, usize), (usize, usize))> {
    #[cfg(feature = "bench-internals")]
    {
        Some((
            egrio_core::bench_internals::relay_buffer_borrows(),
            egrio_core::bench_internals::udp_buffer_borrows(),
        ))
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        None
    }
}

fn pool_borrows_line(before: Option<((usize, usize), (usize, usize))>) -> String {
    let (Some(before), Some(after)) = (before, pool_borrows()) else {
        return String::new();
    };
    let delta =
        |before: (usize, usize), after: (usize, usize)| (after.0 - before.0, after.1 - before.1);
    let (relay_hits, relay_misses) = delta(before.0, after.0);
    let (udp_hits, udp_misses) = delta(before.1, after.1);
    format!(
        "  \"buffer_pools\": {{ \"relay\": {{ \"reused\": {relay_hits}, \"allocated\": {relay_misses} }}, \"udp\": {{ \"reused\": {udp_hits}, \"allocated\": {udp_misses} }} }}"
    )
}

/// Many sessions at once, each exchanging a request for a response `rounds`
/// times: the shape that makes a relay direction go idle and busy again, so
/// the relay buffers are borrowed and returned rather than held.
/// One connection's setup as its client sees it: the proxy handshake
/// answered -- the Core admitted, routed and dialed it -- and then the first
/// byte back from the peer through the relay.
struct Setup {
    handshake: Duration,
    first_byte: Duration,
}

/// Opens `connections` connections through the proxy, `at_once` of them
/// together, each asking the peer for one byte, and returns what each one's
/// setup took.
async fn run_setup_scenario(
    proxy_addr: SocketAddr,
    inbound: Inbound,
    connections: usize,
    at_once: usize,
) -> Result<Vec<Setup>, String> {
    let peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind setup peer listener: {error}"))?;
    let peer_addr = peer_listener
        .local_addr()
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = peer_listener.accept().await {
            tokio::spawn(async move {
                stream.set_nodelay(true).ok();
                let mut byte = [0_u8; 1];
                while stream.read_exact(&mut byte).await.is_ok() {
                    if stream.write_all(&byte).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let mut samples = Vec::with_capacity(connections);
    let mut opened = 0;
    while opened < connections {
        let batch = at_once.min(connections - opened);
        let mut running = Vec::with_capacity(batch);
        for _ in 0..batch {
            running.push(tokio::spawn(async move {
                let started = Instant::now();
                let mut stream = TcpStream::connect(proxy_addr)
                    .await
                    .map_err(|error| format!("setup connect proxy: {error}"))?;
                stream.set_nodelay(true).ok();
                match inbound {
                    Inbound::HttpConnect => http_connect_handshake(&mut stream, peer_addr).await?,
                    Inbound::Socks5 => socks5_handshake(&mut stream, peer_addr).await?,
                }
                let handshake = started.elapsed();
                stream
                    .write_all(b"x")
                    .await
                    .map_err(|error| format!("setup request: {error}"))?;
                let mut byte = [0_u8; 1];
                stream
                    .read_exact(&mut byte)
                    .await
                    .map_err(|error| format!("setup response: {error}"))?;
                Ok::<Setup, String>(Setup {
                    handshake,
                    first_byte: started.elapsed(),
                })
            }));
        }
        for connection in running {
            samples.push(
                connection
                    .await
                    .map_err(|error| format!("setup task: {error}"))??,
            );
        }
        opened += batch;
    }
    Ok(samples)
}

/// The percentiles of one setup pass. Percentiles rather than a mean: what a
/// user feels when a page opens is the slowest of the connections it needs.
fn setup_line(label: &str, at_once: usize, samples: &[Setup]) -> String {
    let micros = |durations: &mut Vec<Duration>, percentile: f64| -> u64 {
        durations.sort_unstable();
        let index = ((durations.len() as f64 - 1.0) * percentile).round() as usize;
        durations[index].as_micros() as u64
    };
    let mut handshake: Vec<Duration> = samples.iter().map(|sample| sample.handshake).collect();
    let mut first_byte: Vec<Duration> = samples.iter().map(|sample| sample.first_byte).collect();
    format!(
        "    {{ \"scenario\": \"socks5-setup-{label}\", \"connections\": {}, \"at_once\": {at_once}, \
\"handshake_p50_micros\": {}, \"handshake_p99_micros\": {}, \
\"first_byte_p50_micros\": {}, \"first_byte_p99_micros\": {}, \"first_byte_max_micros\": {} }}",
        samples.len(),
        micros(&mut handshake, 0.50),
        micros(&mut handshake, 0.99),
        micros(&mut first_byte, 0.50),
        micros(&mut first_byte, 0.99),
        micros(&mut first_byte, 1.0),
    )
}

async fn run_burst_scenario(
    proxy_addr: SocketAddr,
    inbound: Inbound,
    sessions: usize,
    rounds: usize,
) -> Result<f64, String> {
    let peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind burst peer listener: {error}"))?;
    let peer_addr = peer_listener
        .local_addr()
        .map_err(|error| error.to_string())?;
    // The peer answers every request with a response of its own size, for as
    // long as its client keeps asking.
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = peer_listener.accept().await {
            tokio::spawn(async move {
                let mut request = vec![0_u8; BURST_REQUEST_BYTES];
                let response = vec![0xc3_u8; BURST_RESPONSE_BYTES];
                loop {
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    if stream.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let started = Instant::now();
    let mut running = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        running.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(proxy_addr)
                .await
                .map_err(|error| format!("burst connect proxy: {error}"))?;
            stream.set_nodelay(true).ok();
            match inbound {
                Inbound::HttpConnect => http_connect_handshake(&mut stream, peer_addr).await?,
                Inbound::Socks5 => socks5_handshake(&mut stream, peer_addr).await?,
            }
            let request = vec![0x3c_u8; BURST_REQUEST_BYTES];
            let mut response = vec![0_u8; BURST_RESPONSE_BYTES];
            for _ in 0..rounds {
                stream
                    .write_all(&request)
                    .await
                    .map_err(|error| format!("burst request: {error}"))?;
                stream
                    .read_exact(&mut response)
                    .await
                    .map_err(|error| format!("burst response: {error}"))?;
            }
            Ok::<(), String>(())
        }));
    }
    for session in running {
        session
            .await
            .map_err(|error| format!("burst session task: {error}"))??;
    }
    Ok(started.elapsed().as_secs_f64())
}

async fn run_scenario(
    proxy_addr: SocketAddr,
    inbound: Inbound,
    direction: Direction,
    total_bytes: u64,
) -> Result<f64, String> {
    let peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind peer listener: {error}"))?;
    let peer_addr = peer_listener
        .local_addr()
        .map_err(|error| error.to_string())?;

    let peer_task = tokio::spawn(async move {
        let (mut stream, _) = peer_listener
            .accept()
            .await
            .map_err(|error| format!("peer accept: {error}"))?;
        match direction {
            Direction::Upload => {
                // Sink: drain everything the client uploads, then confirm the
                // byte count so the measured window covers full delivery.
                let mut buffer = vec![0_u8; CHUNK_BYTES];
                let mut received: u64 = 0;
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .map_err(|error| format!("peer read: {error}"))?;
                    if read == 0 {
                        break;
                    }
                    received += read as u64;
                }
                stream
                    .write_all(&received.to_be_bytes())
                    .await
                    .map_err(|error| format!("peer confirm: {error}"))?;
                Ok::<(), String>(())
            }
            Direction::Download => {
                // Source: blast the requested byte count, then close.
                let buffer = vec![0xa5_u8; CHUNK_BYTES];
                let mut sent: u64 = 0;
                while sent < total_bytes {
                    let chunk = CHUNK_BYTES.min((total_bytes - sent) as usize);
                    stream
                        .write_all(&buffer[..chunk])
                        .await
                        .map_err(|error| format!("peer write: {error}"))?;
                    sent += chunk as u64;
                }
                stream
                    .shutdown()
                    .await
                    .map_err(|error| format!("peer shutdown: {error}"))?;
                Ok::<(), String>(())
            }
        }
    });

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|error| format!("connect proxy: {error}"))?;
    stream.set_nodelay(true).ok();
    match inbound {
        Inbound::HttpConnect => http_connect_handshake(&mut stream, peer_addr).await?,
        Inbound::Socks5 => socks5_handshake(&mut stream, peer_addr).await?,
    }

    let started = Instant::now();
    match direction {
        Direction::Upload => {
            let buffer = vec![0x5a_u8; CHUNK_BYTES];
            let mut sent: u64 = 0;
            while sent < total_bytes {
                let chunk = CHUNK_BYTES.min((total_bytes - sent) as usize);
                stream
                    .write_all(&buffer[..chunk])
                    .await
                    .map_err(|error| format!("upload write: {error}"))?;
                sent += chunk as u64;
            }
            stream
                .shutdown()
                .await
                .map_err(|error| format!("upload shutdown: {error}"))?;
            let mut confirm = [0_u8; 8];
            stream
                .read_exact(&mut confirm)
                .await
                .map_err(|error| format!("upload confirm: {error}"))?;
            let confirmed = u64::from_be_bytes(confirm);
            if confirmed != total_bytes {
                return Err(format!(
                    "upload confirmation mismatch: sent {total_bytes}, peer saw {confirmed}"
                ));
            }
        }
        Direction::Download => {
            let mut buffer = vec![0_u8; CHUNK_BYTES];
            let mut received: u64 = 0;
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .map_err(|error| format!("download read: {error}"))?;
                if read == 0 {
                    break;
                }
                received += read as u64;
            }
            if received != total_bytes {
                return Err(format!(
                    "download byte mismatch: expected {total_bytes}, received {received}"
                ));
            }
        }
    }
    let seconds = started.elapsed().as_secs_f64();

    peer_task
        .await
        .map_err(|error| format!("peer task join: {error}"))??;
    Ok(seconds)
}

async fn http_connect_handshake(stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("CONNECT write: {error}"))?;

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| format!("CONNECT read: {error}"))?;
        if read == 0 {
            return Err("proxy closed during CONNECT response".into());
        }
        response.push(byte[0]);
        if response.len() > 8 * 1024 {
            return Err("CONNECT response exceeded 8 KiB".into());
        }
    }
    let status_line = String::from_utf8_lossy(&response);
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "CONNECT failed: {}",
            status_line.lines().next().unwrap_or_default()
        ));
    }
    Ok(())
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
    if method != [0x05, 0x00] {
        return Err(format!("SOCKS method rejected: {method:02x?}"));
    }

    let SocketAddr::V4(target) = target else {
        return Err("harness peers are IPv4 loopback".into());
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

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("e2e-throughput-direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn inbound_label(inbound: Inbound) -> &'static str {
    match inbound {
        Inbound::HttpConnect => "http-connect",
        Inbound::Socks5 => "socks5",
    }
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Upload => "upload",
        Direction::Download => "download",
    }
}
