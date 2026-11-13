//! End-to-end UDP relay baseline for the packet capture data plane — the
//! instrument UDP data-plane follow-ups (batch syscalls, session-table
//! sharding) are measured against.
//!
//! Writes captured IPv4/UDP packets into an in-memory TUN ring drained by
//! `run_packet_queue` — packet classification → route decision → session
//! table → session-socket actor → real UDP sockets — against loopback echo
//! peers, and counts the reply packets Core writes back. Like the TCP
//! harness, loopback isolates core overhead from network latency; only
//! same-host deltas are meaningful.
//!
//! Scenarios:
//! - sendpump-1flow: one client source with one reply reader;
//! - sendpump-64flows: one serial TUN writer across 64 client sources with
//!   one reply reader;
//! - fulltable-sendpump-1flow: one measured flow taking the last entry of a
//!   session table pre-filled by real relays to its 1024-entry cap (1024
//!   live session sockets) — worst-case per-datagram sweep cost by
//!   construction.
//!
//! The TUN ring holds the writer back when full, so `send_seconds` is the
//! time Core took to ingest every packet; session-mailbox overflow drops are
//! reported alongside response completion.
//!
//! Usage:
//!   cargo run --release -p egrio-core --example e2e_udp_throughput [> report.json]
//!   EGRIO_E2E_UDP_DATAGRAMS overrides the per-flow datagram count.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use egrio_core::{CoreRuntime, RouteRule, RuleKind, RuntimeProfile};
use tokio::net::UdpSocket;
use tokio::sync::watch;

const DEFAULT_DATAGRAMS_PER_FLOW: u64 = 10_000;
const AGGREGATE_FLOWS: u32 = 64;
/// The UDP session-table cap (`udp.rs`); the full-table scenario fills the
/// table so the measured flow takes its last entry (a full table rejects a
/// new source rather than evicting a live mapping).
const SESSION_TABLE_CAP: u32 = 1024;
const PAYLOAD_SIZES: [usize; 2] = [64, 1200];

#[path = "support/fd_limit.rs"]
mod fd_limit;
#[path = "support/udp_tun.rs"]
mod udp_tun;

fn main() {
    // The fulltable scenario alone holds 1024 UDP session sockets; the
    // platform default soft fd limit (256 on macOS) is far below that.
    fd_limit::raise_fd_soft_limit();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        if let Err(error) = run().await {
            eprintln!("e2e UDP throughput harness failed: {error}");
            std::process::exit(1);
        }
    });
}

async fn run() -> Result<(), String> {
    let datagrams_per_flow = std::env::var("EGRIO_E2E_UDP_DATAGRAMS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DATAGRAMS_PER_FLOW);

    let mut scenarios = Vec::new();
    for payload_bytes in PAYLOAD_SIZES {
        scenarios.push(
            run_send_pump_scenario("sendpump-1flow", 1, 0, payload_bytes, datagrams_per_flow)
                .await?,
        );
    }
    for payload_bytes in PAYLOAD_SIZES {
        scenarios.push(
            run_send_pump_scenario(
                "sendpump-64flows",
                AGGREGATE_FLOWS,
                0,
                payload_bytes,
                datagrams_per_flow,
            )
            .await?,
        );
    }
    scenarios.push(
        run_send_pump_scenario(
            "fulltable-sendpump-1flow",
            1,
            SESSION_TABLE_CAP - 1,
            1200,
            datagrams_per_flow,
        )
        .await?,
    );

    println!("{{");
    println!("  \"harness\": \"egrio-core e2e_udp_throughput\",");
    println!("  \"data_plane\": \"packet\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"arch\": \"{}\",", std::env::consts::ARCH);
    println!("  \"scenarios\": [");
    println!("{}", scenarios.join(",\n"));
    println!("  ]");
    println!("}}");
    Ok(())
}

/// One serial TUN writer across `flows` client sources and one reply reader.
/// Session-mailbox overflow drops datagrams by design; the report carries
/// the drop count and how many echoes came back so regressions in either
/// direction are visible.
async fn run_send_pump_scenario(
    name: &str,
    flows: u32,
    prefill_sessions: u32,
    payload_bytes: usize,
    datagrams_per_flow: u64,
) -> Result<String, String> {
    let core = CoreRuntime::from_profile(direct_profile());
    let (writer, mut reader, pump) = udp_tun::start(core.device());
    if prefill_sessions > 0 {
        prefill_session_table(&writer, &mut reader, prefill_sessions).await?;
        let audit = core.state_audit();
        if audit.udp_sessions != prefill_sessions as usize {
            return Err(format!(
                "prefill expected {prefill_sessions} resident sessions, audit shows {}",
                audit.udp_sessions
            ));
        }
    }
    let mut echo_peers = Vec::new();
    for _ in 0..flows {
        echo_peers.push(spawn_echo_peer_until_closed().await?);
    }

    let expected = flows as u64 * datagrams_per_flow;
    let (sender_done_tx, sender_done_rx) = watch::channel(false);
    let audit_core = core.clone();
    let reply_pump = tokio::spawn(async move {
        let mut received = 0_u64;
        loop {
            if reader.recv(Duration::from_millis(500)).await.is_some() {
                received += 1;
            } else if *sender_done_rx.borrow() {
                // The writer is finished and the reader observed a quiet
                // window: everything still missing was dropped.
                break;
            }
            if *sender_done_rx.borrow()
                && received + audit_core.state_audit().udp_send_drops >= expected
            {
                break;
            }
        }
        received
    });

    let payload = vec![0x5a_u8; payload_bytes];
    let started = Instant::now();
    for _round in 0..datagrams_per_flow {
        for (flow, (echo_addr, _)) in echo_peers.iter().enumerate() {
            writer
                .send(flow_source(97, flow as u32), *echo_addr, &payload)
                .await;
        }
    }
    let _ = sender_done_tx.send(true);
    let send_seconds = started.elapsed().as_secs_f64();
    let received = reply_pump.await.map_err(|error| error.to_string())?;
    let total_seconds = started.elapsed().as_secs_f64();

    let audit = core.state_audit();
    let send_drops = audit.udp_send_drops;
    let enqueued = expected - send_drops;
    let resident_sessions = audit.udp_sessions;
    let pump_report = pump.stop().await?;
    core.shutdown();
    if pump_report.packets_failed != 0 {
        return Err(format!(
            "{name}: Core rejected {} captured packets: {:?}",
            pump_report.packets_failed, pump_report.last_error
        ));
    }
    for (_, echo_task) in echo_peers {
        echo_task.abort();
    }

    let attempts_per_s = expected as f64 / send_seconds;
    let enqueued_per_s = enqueued as f64 / send_seconds;
    let responses_per_s = received as f64 / total_seconds;
    let completion_ratio = if enqueued == 0 {
        0.0
    } else {
        received as f64 / enqueued as f64
    };
    let drain_seconds = total_seconds - send_seconds;
    Ok(format!(
        "    {{ \"scenario\": \"{name}-{payload_bytes}B\", \"flows\": {flows}, \"resident_sessions\": {resident_sessions}, \"payload_bytes\": {payload_bytes}, \"datagrams\": {expected}, \"enqueued\": {enqueued}, \"send_seconds\": {send_seconds:.4}, \"drain_seconds\": {drain_seconds:.4}, \"seconds\": {total_seconds:.4}, \"attempts_per_s\": {attempts_per_s:.0}, \"enqueued_per_s\": {enqueued_per_s:.0}, \"responses_per_s\": {responses_per_s:.0}, \"responses_received\": {received}, \"completion_ratio\": {completion_ratio:.4}, \"send_drops\": {send_drops} }}"
    ))
}

/// A distinct client source per flow: Core keys one UDP session per source.
fn flow_source(subnet: u8, flow: u32) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::new(10, subnet, (flow >> 8) as u8, flow as u8),
        40_000 + (flow % 20_000) as u16,
    )
}

/// An echo peer that answers until its task is aborted (the pump scenario
/// cannot pre-commit to a datagram count because mailbox overflow drops are
/// legal there).
async fn spawn_echo_peer_until_closed(
) -> Result<(SocketAddrV4, tokio::task::JoinHandle<Result<(), String>>), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind echo peer: {error}"))?;
    let SocketAddr::V4(addr) = socket.local_addr().map_err(|error| error.to_string())? else {
        return Err("echo peer is not IPv4".into());
    };
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| format!("echo recv: {error}"))?;
            socket
                .send_to(&buffer[..read], peer)
                .await
                .map_err(|error| format!("echo send: {error}"))?;
        }
    });
    Ok((addr, task))
}

/// Fills the session table with `sessions` distinct live flows (one relayed
/// datagram each against a shared echo peer), leaving their session sockets
/// and background readers resident — what a table at cap looks like in
/// production.
async fn prefill_session_table(
    writer: &udp_tun::UdpTunWriter,
    reader: &mut udp_tun::UdpTunReader,
    sessions: u32,
) -> Result<(), String> {
    let (echo_addr, echo_task) = spawn_echo_peer(sessions as u64).await?;
    for flow in 0..sessions {
        writer
            .send(flow_source(99, flow), echo_addr, &[0x5a_u8; 64])
            .await;
        let response = reader
            .recv(Duration::from_secs(5))
            .await
            .ok_or_else(|| format!("prefill flow {flow} did not receive its echo"))?;
        if response.source != echo_addr || response.payload.len() != 64 {
            return Err(format!(
                "prefill flow {flow} received {} bytes from {}",
                response.payload.len(),
                response.source
            ));
        }
    }
    echo_task.await.map_err(|error| error.to_string())??;
    Ok(())
}

async fn spawn_echo_peer(
    datagrams: u64,
) -> Result<(SocketAddrV4, tokio::task::JoinHandle<Result<(), String>>), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind echo peer: {error}"))?;
    let SocketAddr::V4(addr) = socket.local_addr().map_err(|error| error.to_string())? else {
        return Err("echo peer is not IPv4".into());
    };
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        for _ in 0..datagrams {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| format!("echo recv: {error}"))?;
            socket
                .send_to(&buffer[..read], peer)
                .await
                .map_err(|error| format!("echo send: {error}"))?;
        }
        Ok(())
    });
    Ok((addr, task))
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("e2e-udp-throughput-direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}
