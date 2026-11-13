//! Bounded churn-soak driver with RSS sampling — the wall-clock instrument
//! for repeated session churn and the allocator decision: the soak RSS curve
//! decides whether jemalloc/mimalloc is worth revisiting; the default stays
//! the system allocator.
//!
//! Runs waves of churn against a live `CoreRuntime`: concurrent
//! TCP relays (SOCKS5 CONNECT through the Core listener to an echo peer,
//! varied payload sizes to exercise the allocator) plus UDP datagrams
//! captured through an in-memory TUN on the packet data plane.
//! After every wave it asserts the session ledgers drain to their floors
//! (`state_audit`), samples process RSS and the live heap from a counting
//! allocator, and emits one JSON line. A flat series over a long run is the
//! pass signal, and the two curves together say what a climb is: the live
//! heap climbing with RSS is memory the Core still owns, RSS climbing alone
//! is the allocator holding on to what it freed. A curve that climbs and then
//! stops is a bounded structure filling up; keep enough later waves to
//! distinguish a plateau from continued growth.
//!
//! Usage:
//!   cargo run --release -p egrio-core --example soak_churn
//!   EGRIO_SOAK_SECONDS=86400        wall-clock budget (default 60)
//!   EGRIO_SOAK_TCP_PER_WAVE=100     concurrent TCP relays per wave
//!   EGRIO_SOAK_UDP_PER_WAVE=20      UDP flows per wave (3 datagrams each)
//!   EGRIO_SOAK_WAVE_MILLIS=2000     minimum wave spacing
//!
//! The wave spacing is load-bearing for long runs: every TCP session burns
//! two loopback connections whose ephemeral ports linger in TIME_WAIT, so
//! an unpaced loop exhausts the OS dynamic port range within seconds and
//! stalls in `connect` — an instrument artifact, not a core leak. Sessions
//! are additionally time-boxed so any stall surfaces as a counted failure
//! instead of a hang.
//!
//! Exits nonzero if any wave fails to relay byte-exact or any ledger fails
//! to drain, so unattended runs report through the exit code.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use egrio_core::{CoreRuntime, CoreSessionManager, RouteRule, RuleKind, RuntimeProfile};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

const DEFAULT_SOAK_SECONDS: u64 = 60;
const DEFAULT_TCP_PER_WAVE: usize = 100;
const DEFAULT_UDP_PER_WAVE: usize = 20;
const DEFAULT_WAVE_MILLIS: u64 = 2_000;
const UDP_DATAGRAMS_PER_FLOW: usize = 3;
/// Hard box around one TCP session so an OS-level stall (port exhaustion,
/// dropped SYN) becomes a counted failure instead of hanging the wave.
const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(20);
/// Per-session payloads cycle through these sizes so the relay path churns
/// more than one allocation size class.
const TCP_PAYLOAD_SIZES: [usize; 4] = [1024, 4 * 1024, 16 * 1024, 32 * 1024];

#[path = "support/fd_limit.rs"]
mod fd_limit;
#[path = "support/heap.rs"]
mod heap;
#[path = "support/os_memory.rs"]
mod os_memory;
#[path = "support/udp_tun.rs"]
mod udp_tun;

/// The soak's question is whether a climbing process curve is memory the
/// Core still owns or memory the allocator holds, so it counts both.
#[global_allocator]
static GLOBAL: heap::CountingAllocator = heap::CountingAllocator;

fn main() {
    // Soak waves hold live session sockets; the platform default soft fd
    // limit (256 on macOS) is below the table caps.
    fd_limit::raise_fd_soft_limit();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let failures = runtime.block_on(run());
    if failures > 0 {
        eprintln!("soak_churn finished with {failures} failure(s)");
        std::process::exit(1);
    }
}

async fn run() -> u64 {
    let soak_seconds = env_u64("EGRIO_SOAK_SECONDS", DEFAULT_SOAK_SECONDS);
    let tcp_per_wave = env_u64("EGRIO_SOAK_TCP_PER_WAVE", DEFAULT_TCP_PER_WAVE as u64) as usize;
    let udp_per_wave = env_u64("EGRIO_SOAK_UDP_PER_WAVE", DEFAULT_UDP_PER_WAVE as u64) as usize;
    let wave_interval =
        Duration::from_millis(env_u64("EGRIO_SOAK_WAVE_MILLIS", DEFAULT_WAVE_MILLIS));

    let core = CoreRuntime::from_profile(direct_profile());
    let watchdog = core.spawn_event_loop_watchdog();
    let listener = CoreSessionManager::default();
    let proxy_addr: SocketAddr = listener
        .start_on_device(
            core.device().clone(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            None,
            false,
        )
        .await
        .expect("start Core listener")
        .listen_addr
        .expect("Core listener address")
        .parse()
        .expect("Core listener socket address");
    let (tun, mut tun_replies, tun_pump) = udp_tun::start(core.device());

    let (tcp_echo_addr, _tcp_echo) = spawn_tcp_echo().await.expect("bind TCP echo peer");
    let (udp_echo_addr, _udp_echo) = spawn_udp_echo().await.expect("bind UDP echo peer");
    let SocketAddr::V4(udp_echo_addr) = udp_echo_addr else {
        panic!("UDP echo peer is not IPv4");
    };

    let deadline = Instant::now() + Duration::from_secs(soak_seconds);
    let started = Instant::now();
    let mut wave: u64 = 0;
    let mut failures: u64 = 0;
    let mut rss_first: Option<u64> = None;
    let mut rss_max: u64 = 0;
    let mut heap_first: Option<usize> = None;
    let mut heap_max: usize = 0;

    while Instant::now() < deadline {
        wave += 1;
        let wave_started = Instant::now();
        let mut wave_failures = 0_u64;

        // TCP churn: concurrent full sessions (connect → relay → byte-exact
        // echo → teardown), the registry/relay-buffer allocation shape.
        let mut sessions = JoinSet::new();
        for session in 0..tcp_per_wave {
            let payload_bytes = TCP_PAYLOAD_SIZES[session % TCP_PAYLOAD_SIZES.len()];
            sessions.spawn(async move {
                match tokio::time::timeout(
                    TCP_SESSION_TIMEOUT,
                    tcp_session(proxy_addr, tcp_echo_addr, payload_bytes),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("TCP session timed out".into()),
                }
            });
        }
        while let Some(session) = sessions.join_next().await {
            match session {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => wave_failures += 1,
            }
        }

        // UDP churn through the capture data plane: captured datagrams into
        // the TUN ring, then the reply reader until the wave's echoes stop
        // arriving.
        for flow in 0..udp_per_wave {
            let source = SocketAddrV4::new(
                Ipv4Addr::new(10, 98, (flow >> 8) as u8, flow as u8),
                41_000 + (wave % 1_000) as u16,
            );
            for _ in 0..UDP_DATAGRAMS_PER_FLOW {
                tun.send(source, udp_echo_addr, b"soak-udp-payload").await;
            }
        }
        while let Some(reply) = tun_replies.recv(Duration::from_millis(200)).await {
            if reply.source != udp_echo_addr || reply.payload != b"soak-udp-payload" {
                wave_failures += 1;
            }
        }

        // Drain gate, applied every wave: TCP relay
        // guards must all have deregistered; UDP sessions linger only until
        // the idle sweep by design, but must stay bounded by the table cap.
        let audit = core.state_audit();
        let drained = audit.tcp_relay_sessions.active == 0
            && audit.udp_sessions <= 1024
            && audit.udp_session_sockets <= audit.udp_sessions;
        if !drained {
            wave_failures += 1;
        }

        let rss = process_rss_bytes();
        if let Some(rss) = rss {
            rss_first.get_or_insert(rss);
            rss_max = rss_max.max(rss);
        }
        failures += wave_failures;

        let heap_bytes = heap::live_bytes();
        heap_first.get_or_insert(heap_bytes);
        heap_max = heap_max.max(heap_bytes);
        let row = serde_json::json!({
            "wave": wave,
            "elapsed_s": started.elapsed().as_secs_f64(),
            "rss_bytes": rss,
            "heap_bytes": heap_bytes,
            "drained": drained,
            "wave_failures": wave_failures,
            "audit": audit,
        });
        println!("{row}");

        // Pace the churn so loopback ephemeral-port recycling keeps up
        // (see the module comment); the soak measures long-run residency,
        // not burst throughput — the E2E harnesses own that.
        tokio::time::sleep_until((wave_started + wave_interval).into()).await;
    }

    watchdog.abort();
    let final_watchdog = core.watchdog_stats();
    match tun_pump.stop().await {
        Ok(report) if report.packets_failed == 0 => {}
        Ok(report) => {
            eprintln!(
                "packet pump rejected {} packets: {:?}",
                report.packets_failed, report.last_error
            );
            failures += 1;
        }
        Err(error) => {
            eprintln!("{error}");
            failures += 1;
        }
    }
    listener.stop();
    core.shutdown();
    let drained_after_close = core.state_audit();
    let close_clean = drained_after_close.tcp_relay_sessions.active == 0
        && drained_after_close.udp_sessions == 0
        && drained_after_close.udp_session_sockets == 0
        && drained_after_close.packet_tcp_sessions == 0;
    if !close_clean {
        failures += 1;
    }

    let rss_last = process_rss_bytes();
    let summary = serde_json::json!({
        "summary": {
            "waves": wave,
            "seconds": started.elapsed().as_secs_f64(),
            "failures": failures,
            "close_clean": close_clean,
            "rss_first_bytes": rss_first,
            "rss_max_bytes": rss_max,
            "heap_first_bytes": heap_first,
            "heap_max_bytes": heap_max,
            "heap_last_bytes": heap::live_bytes(),
            "rss_last_bytes": rss_last,
            "watchdog": final_watchdog,
        }
    });
    println!("{summary}");
    failures
}

/// One full TCP relay session: SOCKS5 CONNECT through the Core listener to
/// the echo peer; asserts the echoed payload is byte-exact.
async fn tcp_session(
    proxy_addr: SocketAddr,
    echo_addr: SocketAddr,
    payload_bytes: usize,
) -> Result<(), String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|error| format!("proxy connect: {error}"))?;
    socks5_connect(&mut stream, echo_addr).await?;

    let payload = vec![0x5a_u8; payload_bytes];
    stream
        .write_all(&payload)
        .await
        .map_err(|error| format!("app write: {error}"))?;
    stream
        .shutdown()
        .await
        .map_err(|error| format!("app shutdown: {error}"))?;
    let mut received = Vec::with_capacity(payload_bytes);
    stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| format!("app read: {error}"))?;
    if received != payload {
        return Err(format!(
            "echo mismatch: sent {payload_bytes} bytes, received {}",
            received.len()
        ));
    }
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    let SocketAddr::V4(target) = target else {
        return Err("soak peers are IPv4 loopback".into());
    };
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
        return Err(format!("SOCKS connect rejected: {:02x}", reply[1]));
    }
    Ok(())
}

/// Echo peer: accepts connections for the whole run, echoing each stream
/// until client shutdown.
async fn spawn_tcp_echo() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind TCP echo: {error}"))?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

async fn spawn_udp_echo() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind UDP echo: {error}"))?;
    let addr = socket.local_addr().map_err(|error| error.to_string())?;
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let _ = socket.send_to(&buffer[..read], peer).await;
        }
    });
    Ok((addr, task))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("soak-churn-direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

/// Resident set of the current process, from the OS bookkeeping; `None`
/// where the instrument has no reading.
fn process_rss_bytes() -> Option<u64> {
    let resident = os_memory::os_memory().resident as u64;
    (resident != 0).then_some(resident)
}
