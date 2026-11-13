//! Packet-path (TUN / captured TCP engine) throughput harness — the capture
//! data plane measurement instrument (see `bench/README.md`).
//!
//! Unlike `e2e_throughput`, which drives the local SOCKS5/HTTP CONNECT listener
//! (`CoreSessionManager` → `copy_bidirectional`), this drives
//! `NativeCoreDevice::run_packet_queues`: the pumps driving the captured TCP
//! engines, whose accepted flows relay through the ordinary session pipeline.
//!
//! Model: each flow is an independent client (its own smoltcp stack and driver
//! task, modelling one app's kernel TCP), so the client side never serializes
//! the way a single driver would; the flows share in-memory capture queues
//! (one by default, like a Wintun ring) into ONE `NativeCoreDevice`, which
//! DIRECT-dials real loopback peers. With several queues each flow stays on
//! one, as a Linux multi-queue TUN keeps it there by its hash. The Core's
//! pumps are therefore the only serialization point under test — the
//! aggregate scenarios measure whether they scale with concurrent flows.
//!
//! It is a loopback upper bound isolating the core packet data plane's CPU
//! throughput (parse → engine → route → relay), so build-vs-build deltas on
//! the SAME host are the meaningful signal — not the absolute
//! numbers, and not a substitute for the interactive-host real-link exit gate
//! (download ≥ 70 % of the system-proxy path on the same node).
//!
//! Each queue's pump runs on a runtime of its own with one worker thread, as
//! the SDK runs the Core in the product; the clients and peers, standing in
//! for the kernel and the remote hosts, run on a separate four-worker
//! runtime.
//!
//! Usage:
//!   cargo run --release -p egrio-core --example e2e_packet_throughput [> report.json]
//!   EGRIO_PKT_FLOWS=8         concurrent flows for the aggregate scenarios
//!   EGRIO_PKT_BYTES=16777216  bytes moved per flow (per direction)
//!   EGRIO_PKT_QUEUES=1        capture queues, each with its own Core runtime
//!   EGRIO_PKT_CORE_WORKERS=1  worker threads of each queue's runtime; 0 runs
//!                             the Core on the clients' runtime instead

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use egrio_core::{
    NativeCoreDevice, PacketDevice, PacketInterest, PacketReady, PacketSend, RouteRule, RuleKind,
    RuntimeProfile,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const DEFAULT_FLOWS: usize = 8;
const DEFAULT_BYTES_PER_FLOW: u64 = 32 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
/// Client socket buffers, generous so the client is never the bottleneck over
/// a loopback round trip.
const CLIENT_RX_BUFFER: usize = 256 * 1024;
const CLIENT_TX_BUFFER: usize = 256 * 1024;
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Client source-port base; flow `i` uses `BASE_PORT + i`, which the adapter
/// demuxes core→client packets back to.
const BASE_PORT: u16 = 40_000;
/// The download request that primes the upstream dial. The accepted flow
/// dials upstream on its first client bytes (a request), mirroring a real
/// HTTP GET → response download; a flow that never sends would never dial.
const DOWNLOAD_REQUEST: &[u8] = b"GET /throughput\r\n\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Upload,
    Download,
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let queues = env_usize("EGRIO_PKT_QUEUES", 1).max(1);
    let core_workers = env_usize("EGRIO_PKT_CORE_WORKERS", 1);
    let core_runtimes = (0..queues)
        .filter(|_| core_workers > 0)
        .map(|queue| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(core_workers)
                .thread_name(format!("egrio-core-{queue}"))
                .enable_all()
                .build()
                .expect("Core runtime")
        })
        .collect::<Vec<_>>();
    let executors = if core_runtimes.is_empty() {
        vec![runtime.handle().clone(); queues]
    } else {
        core_runtimes
            .iter()
            .map(|core| core.handle().clone())
            .collect()
    };
    runtime.block_on(async {
        if let Err(error) = run(&executors).await {
            eprintln!("e2e packet throughput harness failed: {error}");
            std::process::exit(1);
        }
    });
}

async fn run(executors: &[Handle]) -> Result<(), String> {
    let flows = env_usize("EGRIO_PKT_FLOWS", DEFAULT_FLOWS);
    let bytes_per_flow = env_u64("EGRIO_PKT_BYTES", DEFAULT_BYTES_PER_FLOW);

    let mut scenarios = Vec::new();
    for direction in [Direction::Download, Direction::Upload] {
        for &flow_count in &[1usize, flows] {
            let seconds = run_scenario(executors, direction, flow_count, bytes_per_flow).await?;
            let moved = flow_count as u64 * bytes_per_flow;
            let mib_per_s = (moved as f64 / (1024.0 * 1024.0)) / seconds;
            scenarios.push(format!(
                "    {{ \"scenario\": \"{}-{}flow\", \"flows\": {}, \"bytes\": {}, \"seconds\": {:.4}, \"mib_per_s\": {:.1} }}",
                direction_label(direction),
                flow_count,
                flow_count,
                moved,
                seconds,
                mib_per_s
            ));
        }
    }

    println!("{{");
    println!("  \"harness\": \"egrio-core e2e_packet_throughput\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"arch\": \"{}\",", std::env::consts::ARCH);
    println!("  \"data_plane\": \"packet\",");
    println!("  \"queues\": {},", executors.len());
    println!("  \"scenarios\": [");
    println!("{}", scenarios.join(",\n"));
    println!("  ]");
    println!("}}");
    Ok(())
}

async fn run_scenario(
    executors: &[Handle],
    direction: Direction,
    flow_count: usize,
    bytes_per_flow: u64,
) -> Result<f64, String> {
    // One loopback peer per flow: a source (download) or sink (upload).
    let mut peer_addrs = Vec::with_capacity(flow_count);
    let mut peer_tasks = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        let (addr, task) = spawn_peer(direction, bytes_per_flow).await?;
        peer_addrs.push(addr);
        peer_tasks.push(task);
    }

    // One virtual capture queue per executor (client→core, the flows the
    // queue's pump serves push into it) and one demuxed outbound per flow
    // (core→client).
    let inbounds = executors
        .iter()
        .map(|_| Arc::new(Ring::default()))
        .collect::<Vec<_>>();
    let mut outbounds = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        outbounds.push(Arc::new(Mutex::new(VecDeque::new())));
    }

    // Compiled on the first queue's runtime, so the tasks it spawns land on a
    // Core runtime.
    let core = {
        let _core_context = executors[0].enter();
        NativeCoreDevice::compile(&direct_profile())
    };
    let shutdown = CancellationToken::new();
    let queues = inbounds
        .iter()
        .zip(executors)
        .map(|(inbound, executor)| {
            let adapter: Box<dyn PacketDevice> = Box::new(HarnessAdapter {
                inbound: Arc::clone(inbound),
                outbounds: outbounds.clone(),
            });
            (adapter, executor.clone())
        })
        .collect::<Vec<_>>();
    let core_loop = core.clone();
    let core_shutdown = shutdown.clone();
    let core_task =
        tokio::spawn(async move { core_loop.run_packet_queues(queues, core_shutdown).await });

    let started = Instant::now();
    let mut flow_tasks = Vec::with_capacity(flow_count);
    for index in 0..flow_count {
        // The flow's queue, as a multi-queue TUN keeps a flow on one.
        let inbound = Arc::clone(&inbounds[index % inbounds.len()]);
        let outbound = Arc::clone(&outbounds[index]);
        let peer = peer_addrs[index];
        flow_tasks.push(tokio::spawn(async move {
            run_flow(index, peer, inbound, outbound, direction, bytes_per_flow).await
        }));
    }
    for task in flow_tasks {
        task.await
            .map_err(|error| format!("flow join: {error}"))??;
    }
    let seconds = started.elapsed().as_secs_f64();

    shutdown.cancel();
    let report = core_task
        .await
        .map_err(|error| format!("core loop join: {error}"))?;
    if let Some(error) = report.fatal_error {
        return Err(format!("core loop: {error}"));
    }
    core.close();
    for task in peer_tasks {
        task.await
            .map_err(|error| format!("peer join: {error}"))??;
    }
    Ok(seconds)
}

/// One client→core capture queue: its flows push, the queue's adapter pops
/// and is woken by the push, like a TUN read-wait event.
#[derive(Default)]
struct Ring {
    queue: Mutex<VecDeque<Vec<u8>>>,
    pushed: Notify,
}

impl Ring {
    fn push(&self, packet: Vec<u8>) {
        self.queue
            .lock()
            .expect("harness inbound queue")
            .push_back(packet);
        self.pushed.notify_one();
    }
}

/// One core-side capture queue: reads client packets off its `inbound`, and
/// demuxes each emitted packet to the destination flow's outbound by its TCP
/// destination port (the client's source port, `BASE_PORT + flow`).
struct HarnessAdapter {
    inbound: Arc<Ring>,
    outbounds: Vec<Arc<Mutex<VecDeque<Vec<u8>>>>>,
}

impl std::fmt::Debug for HarnessAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HarnessAdapter")
    }
}

impl PacketDevice for HarnessAdapter {
    fn name(&self) -> &str {
        "harness-tun"
    }

    /// Hands over the buffer the client wrote, which no real capture can do:
    /// a TUN read or a ring pop copies the bytes into a buffer of its own
    /// and allocates it (see [`egrio_core::ReceivedPacket`], where what that
    /// costs is measured). So the read side of these numbers is a packet's
    /// pipeline without its capture read.
    fn try_recv(&mut self) -> Result<Option<egrio_core::ReceivedPacket>, String> {
        Ok(self
            .inbound
            .queue
            .lock()
            .expect("harness inbound queue")
            .pop_front()
            .map(Into::into))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        let Some(destination_port) = ipv4_destination_port(packet) else {
            return Ok(PacketSend::Sent);
        };
        let Some(index) = destination_port
            .checked_sub(BASE_PORT)
            .map(usize::from)
            .filter(|index| *index < self.outbounds.len())
        else {
            return Ok(PacketSend::Sent);
        };
        self.outbounds[index]
            .lock()
            .expect("harness outbound queue")
            .push_back(packet.to_vec());
        Ok(PacketSend::Sent)
    }

    fn ready(&mut self, _: PacketInterest) -> PacketReady<'_> {
        let inbound = Arc::clone(&self.inbound);
        Box::pin(async move {
            // notify_one stores a permit, so a push racing this check wakes us.
            if inbound
                .queue
                .lock()
                .expect("harness inbound queue")
                .is_empty()
            {
                inbound.pushed.notified().await;
            }
            Ok(())
        })
    }
}

/// Drives one independent client flow to completion: a single-socket smoltcp
/// stack that transmits into its queue's `inbound` and receives from its own
/// `outbound`, yielding between core packets.
async fn run_flow(
    index: usize,
    peer: SocketAddr,
    inbound: Arc<Ring>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    direction: Direction,
    bytes: u64,
) -> Result<(), String> {
    let SocketAddr::V4(peer) = peer else {
        return Err("harness peers are IPv4 loopback".into());
    };

    let mut device = ClientDevice {
        rx: outbound,
        tx: inbound,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x00c1_1e27 ^ index as u64;
    let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(client_ip()), 24))
            .expect("client address fits");
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(gateway_ip())
        .expect("client default route");

    let mut sockets = SocketSet::new(vec![]);
    let rx = tcp::SocketBuffer::new(vec![0; CLIENT_RX_BUFFER]);
    let tx = tcp::SocketBuffer::new(vec![0; CLIENT_TX_BUFFER]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    let handle = sockets.add(socket);
    let peer_octets = peer.ip().octets();
    let peer_ip = Ipv4Address::new(
        peer_octets[0],
        peer_octets[1],
        peer_octets[2],
        peer_octets[3],
    );
    let local = IpListenEndpoint {
        addr: Some(IpAddress::Ipv4(client_ip())),
        port: BASE_PORT + index as u16,
    };
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(peer_ip), peer.port()),
            local,
        )
        .map_err(|error| format!("client connect: {error}"))?;

    let payload = vec![0x5a_u8; CHUNK_BYTES];
    let mut sink = vec![0_u8; CHUNK_BYTES];
    let mut clock = 0_i64;
    let mut moved = 0_u64;
    let mut primed = false;
    let mut closing = false;
    loop {
        clock += 1;
        iface.poll(SmolInstant::from_millis(clock), &mut device, &mut sockets);

        let socket = sockets.get_mut::<tcp::Socket>(handle);
        let done = match direction {
            Direction::Upload => {
                while moved < bytes && socket.can_send() {
                    let remaining = (bytes - moved) as usize;
                    let chunk = remaining.min(CHUNK_BYTES);
                    match socket.send_slice(&payload[..chunk]) {
                        Ok(0) => break,
                        Ok(sent) => moved += sent as u64,
                        Err(_) => break,
                    }
                }
                // Done once every byte is handed to smoltcp AND fully acked
                // (send buffer drained) — acked means the peer received it.
                let acked = moved >= bytes && socket.send_queue() == 0;
                if acked && !closing {
                    socket.close();
                    closing = true;
                }
                acked
            }
            Direction::Download => {
                if !primed && socket.can_send() && socket.send_slice(DOWNLOAD_REQUEST).is_ok() {
                    primed = true;
                }
                while socket.can_recv() {
                    match socket.recv_slice(&mut sink) {
                        Ok(0) => break,
                        Ok(read) => moved += read as u64,
                        Err(_) => break,
                    }
                }
                moved >= bytes
            }
        };
        if done {
            return Ok(());
        }

        // Cooperative hot loop: yield so the shared core loop (and the other
        // flow tasks) run, then re-poll immediately. Parking on a timer here
        // would put the OS timer's coarse (~1 ms) granularity on the ACK
        // critical path and collapse throughput; yielding keeps the flow ready
        // to react the instant the core emits its next packet.
        tokio::task::yield_now().await;
    }
}

struct ClientDevice {
    rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx: Arc<Ring>,
}

impl Device for ClientDevice {
    type RxToken<'a>
        = ClientRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ClientTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.lock().expect("client rx queue").pop_front()?;
        Some((ClientRxToken { packet }, ClientTxToken { tx: &self.tx }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ClientTxToken { tx: &self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

struct ClientRxToken {
    packet: Vec<u8>,
}

impl RxToken for ClientRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct ClientTxToken<'a> {
    tx: &'a Arc<Ring>,
}

impl<'a> TxToken for ClientTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.tx.push(packet);
        result
    }
}

/// The TCP destination port of an IPv4 packet, used to demux core→client
/// packets to the flow whose client source port they target.
fn ipv4_destination_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len + 4 {
        return None;
    }
    Some(u16::from_be_bytes([
        packet[header_len + 2],
        packet[header_len + 3],
    ]))
}

/// Spawns one loopback peer: a source that reads the priming request then
/// blasts `bytes` and closes (download), or a sink that drains to EOF (upload).
async fn spawn_peer(
    direction: Direction,
    bytes: u64,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), String>>), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind peer: {error}"))?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("peer accept: {error}"))?;
        stream.set_nodelay(true).ok();
        match direction {
            Direction::Download => {
                // Request → response: the core dials this peer only after the
                // client's first flight, so wait for the priming request.
                let mut request = vec![0_u8; DOWNLOAD_REQUEST.len()];
                stream
                    .read_exact(&mut request)
                    .await
                    .map_err(|error| format!("peer source request: {error}"))?;
                let buffer = vec![0xa5_u8; CHUNK_BYTES];
                let mut sent = 0_u64;
                while sent < bytes {
                    let chunk = CHUNK_BYTES.min((bytes - sent) as usize);
                    stream
                        .write_all(&buffer[..chunk])
                        .await
                        .map_err(|error| format!("peer source write: {error}"))?;
                    sent += chunk as u64;
                }
                stream
                    .shutdown()
                    .await
                    .map_err(|error| format!("peer source shutdown: {error}"))?;
            }
            Direction::Upload => {
                let mut buffer = vec![0_u8; CHUNK_BYTES];
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .map_err(|error| format!("peer sink read: {error}"))?;
                    if read == 0 {
                        break;
                    }
                }
            }
        }
        Ok::<(), String>(())
    });
    Ok((addr, task))
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("e2e-packet-throughput-direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn client_ip() -> Ipv4Address {
    let octets = CLIENT_IP.octets();
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

fn gateway_ip() -> Ipv4Address {
    let octets = CLIENT_GATEWAY.octets();
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Upload => "upload",
        Direction::Download => "download",
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
