//! Idle-flow memory instrument: what the Core keeps per TCP connection once
//! the connection has moved data and gone quiet — the keep-alive case that
//! dominates a desktop's resident memory.
//!
//! `EGRIO_IDLE_PATH=tun` (the default) drives the packet data plane: N
//! independent client flows (each its own small smoltcp stack, modelling one
//! app's kernel TCP) share one in-memory TUN into one `NativeCoreDevice`.
//! `EGRIO_IDLE_PATH=socks5` drives the local listener with N SOCKS5 CONNECT
//! sessions instead. Either way the Core DIRECT-dials a loopback peer; every
//! flow uploads a request plus `EGRIO_IDLE_UPLOAD` bytes, downloads
//! `EGRIO_IDLE_DOWNLOAD` bytes, then stays open without traffic.
//! `EGRIO_IDLE_PATH=udp` opens N captured UDP flows instead, each one
//! datagram to a loopback echo peer and its echo back. The instrument samples
//! the live heap (a counting global allocator) and the OS view of the process
//! before the flows open, once all of them are idle, and after they closed
//! (UDP flows end with the packet device).
//!
//! TUN clients live in the same process; each keeps its smoltcp socket
//! buffers (`CLIENT_RX_BUFFER + CLIENT_TX_BUFFER`) plus a few KiB, which the
//! report subtracts from the per-flow heap figure. SOCKS5 clients are kernel
//! sockets.
//!
//! Usage:
//!   cargo run --release -p egrio-core --example idle_flow_memory
//!   EGRIO_IDLE_PATH=socks5|udp    measure listener sessions or UDP flows instead
//!   EGRIO_IDLE_FLOWS=200          concurrent idle flows
//!   EGRIO_IDLE_DOWNLOAD=1048576   bytes each flow downloads before idling
//!   EGRIO_IDLE_UPLOAD=65536       bytes each flow uploads before idling

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egrio_core::{
    CoreInbound, CoreSessionManager, CoreSessionStartConfig, NativeCoreDevice,
    NativeCoreEgressConfig, PacketDevice, PacketInterest, PacketQueue, PacketReady, PacketSend,
    RouteRule, RuleKind, RuntimeProfile,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const DEFAULT_FLOWS: usize = 200;
const DEFAULT_DOWNLOAD: u64 = 1024 * 1024;
const DEFAULT_UPLOAD: u64 = 64 * 1024;
const CLIENT_RX_BUFFER: usize = 64 * 1024;
const CLIENT_TX_BUFFER: usize = 16 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const BASE_PORT: u16 = 40_000;
const REQUEST: &[u8] = b"GET /idle\r\n\r\n";
/// Idle clients poll at this cadence: enough to answer keep-alives and the
/// close handshake without spinning.
const IDLE_POLL: Duration = Duration::from_millis(50);
const SETTLE: Duration = Duration::from_secs(3);

#[path = "support/heap.rs"]
mod heap;
#[path = "support/os_memory.rs"]
mod os_memory;
use os_memory::{os_memory, OsMemory};

#[global_allocator]
static GLOBAL: heap::CountingAllocator = heap::CountingAllocator;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(error) = runtime.block_on(run()) {
        eprintln!("idle flow memory instrument failed: {error}");
        std::process::exit(1);
    }
}

#[derive(Clone, Copy)]
struct Sample {
    heap: usize,
    classes: [usize; 32],
    os: OsMemory,
}

fn sample() -> Sample {
    Sample {
        heap: heap::live_bytes(),
        classes: std::array::from_fn(heap::live_in_class),
        os: os_memory(),
    }
}

#[path = "support/udp_tun.rs"]
mod udp_tun;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Path {
    Tcp(TcpPath),
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpPath {
    Tun,
    Socks5,
}

/// The Core under measurement and what its flows need to reach it.
enum CoreUnderTest {
    Tun {
        core: NativeCoreDevice,
        shutdown: CancellationToken,
        task: JoinHandle<Option<String>>,
        inbound: Arc<Ring>,
        outbounds: Vec<Arc<Mutex<VecDeque<Vec<u8>>>>>,
    },
    Socks5 {
        manager: CoreSessionManager,
        proxy: SocketAddr,
    },
}

impl CoreUnderTest {
    async fn start(path: TcpPath, flows: usize) -> Result<Self, String> {
        match path {
            TcpPath::Tun => {
                let inbound = Arc::new(Ring::default());
                let outbounds: Vec<_> = (0..flows)
                    .map(|_| Arc::new(Mutex::new(VecDeque::new())))
                    .collect();
                let core = NativeCoreDevice::compile(&direct_profile());
                let shutdown = CancellationToken::new();
                let mut adapter = HarnessAdapter {
                    inbound: Arc::clone(&inbound),
                    outbounds: outbounds.clone(),
                };
                let core_loop = core.clone();
                let core_shutdown = shutdown.clone();
                let task = tokio::spawn(async move {
                    core_loop
                        .run_packet_queue(PacketQueue::ONLY, &mut adapter, core_shutdown)
                        .await
                        .fatal_error
                });
                Ok(Self::Tun {
                    core,
                    shutdown,
                    task,
                    inbound,
                    outbounds,
                })
            }
            TcpPath::Socks5 => {
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
                let proxy = status
                    .listen_addr
                    .ok_or("the listener reported no address")?
                    .parse()
                    .map_err(|error| format!("listener address: {error}"))?;
                Ok(Self::Socks5 { manager, proxy })
            }
        }
    }

    fn spawn_flow(&self, index: usize, plan: FlowPlan) -> JoinHandle<Result<(), String>> {
        match self {
            Self::Tun {
                inbound, outbounds, ..
            } => tokio::spawn(
                TunFlow {
                    index,
                    inbound: Arc::clone(inbound),
                    outbound: Arc::clone(&outbounds[index]),
                    plan,
                }
                .run(),
            ),
            Self::Socks5 { proxy, .. } => tokio::spawn(socks5_flow(*proxy, plan)),
        }
    }

    async fn stop(self) -> Result<(), String> {
        match self {
            Self::Tun {
                core,
                shutdown,
                task,
                ..
            } => {
                shutdown.cancel();
                let fatal = task
                    .await
                    .map_err(|error| format!("core loop join: {error}"))?;
                core.close();
                fatal.map_or(Ok(()), |error| Err(format!("core loop: {error}")))
            }
            Self::Socks5 { manager, .. } => {
                manager.stop();
                Ok(())
            }
        }
    }
}

/// What one flow does and how it reports going idle.
#[derive(Clone)]
struct FlowPlan {
    peer: SocketAddr,
    download: u64,
    upload: u64,
    idle: Arc<AtomicUsize>,
    idle_reached: Arc<Notify>,
    close: watch::Receiver<bool>,
}

impl FlowPlan {
    fn went_idle(&self) {
        self.idle.fetch_add(1, Ordering::AcqRel);
        self.idle_reached.notify_one();
    }
}

async fn run() -> Result<(), String> {
    let path = match std::env::var("EGRIO_IDLE_PATH").as_deref() {
        Ok("socks5") => Path::Tcp(TcpPath::Socks5),
        Ok("udp") => Path::Udp,
        Ok("tun") | Err(_) => Path::Tcp(TcpPath::Tun),
        Ok(other) => {
            return Err(format!(
                "EGRIO_IDLE_PATH must be tun, socks5 or udp, not {other}"
            ))
        }
    };
    let flows = env_u64("EGRIO_IDLE_FLOWS", DEFAULT_FLOWS as u64) as usize;
    let download = env_u64("EGRIO_IDLE_DOWNLOAD", DEFAULT_DOWNLOAD);
    let upload = env_u64("EGRIO_IDLE_UPLOAD", DEFAULT_UPLOAD);
    if flows == 0 || flows > usize::from(u16::MAX - BASE_PORT) {
        return Err("EGRIO_IDLE_FLOWS must be between 1 and 25535".into());
    }

    let (before, idle_sample, closed) = match path {
        Path::Udp => measure_udp(flows).await?,
        Path::Tcp(tcp) => measure_tcp(tcp, flows, download, upload).await?,
    };

    let client_heap_per_flow = match path {
        Path::Tcp(TcpPath::Tun) => CLIENT_RX_BUFFER + CLIENT_TX_BUFFER,
        Path::Tcp(TcpPath::Socks5) | Path::Udp => 0,
    };

    let heap_per_flow = idle_sample.heap.saturating_sub(before.heap) / flows;
    println!("{{");
    println!("  \"harness\": \"egrio-core idle_flow_memory\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!(
        "  \"path\": \"{}\",",
        match path {
            Path::Tcp(TcpPath::Tun) => "tun",
            Path::Tcp(TcpPath::Socks5) => "socks5",
            Path::Udp => "udp",
        }
    );
    println!("  \"flows\": {flows},");
    println!("  \"download_bytes\": {download},");
    println!("  \"upload_bytes\": {upload},");
    println!("  \"before\": {},", sample_json(before));
    println!("  \"idle\": {},", sample_json(idle_sample));
    println!("  \"closed\": {},", sample_json(closed));
    println!(
        "  \"core_heap_per_idle_flow_kib\": {:.1},",
        heap_per_flow.saturating_sub(client_heap_per_flow) as f64 / 1024.0
    );
    println!(
        "  \"os_private_per_idle_flow_kib\": {:.1},",
        idle_sample.os.private.saturating_sub(before.os.private) as f64 / flows as f64 / 1024.0
    );
    let classes: Vec<String> = (0..32)
        .filter_map(|class| {
            let added = idle_sample.classes[class].saturating_sub(before.classes[class]);
            (added >= flows / 2).then(|| {
                format!(
                    "\"<= {} B\": {:.2}",
                    1_usize << class,
                    added as f64 / flows as f64
                )
            })
        })
        .collect();
    println!(
        "  \"live_allocations_per_idle_flow\": {{ {} }}",
        classes.join(", ")
    );
    println!("}}");
    Ok(())
}

async fn measure_tcp(
    path: TcpPath,
    flows: usize,
    download: u64,
    upload: u64,
) -> Result<(Sample, Sample, Sample), String> {
    let (peer, peer_task) = spawn_peer(download, upload).await?;
    let core = CoreUnderTest::start(path, flows).await?;
    tokio::time::sleep(SETTLE).await;
    let before = sample();

    let idle = Arc::new(AtomicUsize::new(0));
    let idle_reached = Arc::new(Notify::new());
    let (close_tx, close_rx) = watch::channel(false);
    let plan = FlowPlan {
        peer,
        download,
        upload,
        idle: Arc::clone(&idle),
        idle_reached: Arc::clone(&idle_reached),
        close: close_rx,
    };
    let tasks: Vec<_> = (0..flows)
        .map(|index| core.spawn_flow(index, plan.clone()))
        .collect();
    drop(plan);
    while idle.load(Ordering::Acquire) < flows {
        let reached = idle_reached.notified();
        if idle.load(Ordering::Acquire) >= flows {
            break;
        }
        tokio::time::timeout(Duration::from_secs(120), reached)
            .await
            .map_err(|_| {
                format!(
                    "only {} of {flows} flows went idle",
                    idle.load(Ordering::Acquire)
                )
            })?;
    }
    tokio::time::sleep(SETTLE).await;
    let idle_sample = sample();

    close_tx
        .send(true)
        .map_err(|_| "close signal".to_string())?;
    for task in tasks {
        task.await
            .map_err(|error| format!("flow join: {error}"))??;
    }
    tokio::time::sleep(SETTLE).await;
    let closed = sample();
    core.stop().await?;
    peer_task.abort();

    Ok((before, idle_sample, closed))
}

/// N captured UDP flows from distinct client ports, each one datagram to a
/// loopback echo peer answered through the Core.
async fn measure_udp(flows: usize) -> Result<(Sample, Sample, Sample), String> {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind the echo peer: {error}"))?;
    let SocketAddr::V4(peer) = echo.local_addr().map_err(|error| error.to_string())? else {
        return Err("the echo peer is IPv4".into());
    };
    let echo_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 2048];
        while let Ok((read, from)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..read], from).await;
        }
    });
    let core = NativeCoreDevice::compile(&direct_profile());
    let (writer, mut reader, pump) = udp_tun::start(&core);
    tokio::time::sleep(SETTLE).await;
    let before = sample();

    for index in 0..flows {
        let source = std::net::SocketAddrV4::new(CLIENT_IP, BASE_PORT + index as u16);
        writer.send(source, peer, REQUEST).await;
    }
    let mut echoed = 0;
    while echoed < flows {
        match reader.recv(Duration::from_secs(10)).await {
            Some(reply) if reply.source == peer && reply.payload == REQUEST => echoed += 1,
            Some(_) => {}
            None => return Err(format!("only {echoed} of {flows} UDP flows were answered")),
        }
    }
    tokio::time::sleep(SETTLE).await;
    let idle = sample();

    pump.stop().await?;
    core.close();
    drop(writer);
    drop(reader);
    tokio::time::sleep(SETTLE).await;
    let closed = sample();
    echo_task.abort();
    Ok((before, idle, closed))
}

fn sample_json(sample: Sample) -> String {
    format!(
        "{{ \"heap_mib\": {:.1}, \"resident_mib\": {:.1}, \"private_mib\": {:.1} }}",
        mib(sample.heap),
        mib(sample.os.resident),
        mib(sample.os.private)
    )
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

struct TunFlow {
    index: usize,
    inbound: Arc<Ring>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    plan: FlowPlan,
}

impl TunFlow {
    async fn run(mut self) -> Result<(), String> {
        let SocketAddr::V4(peer) = self.plan.peer else {
            return Err("the peer is IPv4 loopback".into());
        };
        let mut device = ClientDevice {
            rx: Arc::clone(&self.outbound),
            tx: Arc::clone(&self.inbound),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1d1e ^ self.index as u64;
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(ipv4(CLIENT_IP)), 24))
                .expect("client address fits");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(ipv4(CLIENT_GATEWAY))
            .expect("client default route");

        let mut sockets = SocketSet::new(vec![]);
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; CLIENT_RX_BUFFER]),
            tcp::SocketBuffer::new(vec![0; CLIENT_TX_BUFFER]),
        );
        let handle = sockets.add(socket);
        let local = IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(ipv4(CLIENT_IP))),
            port: BASE_PORT + self.index as u16,
        };
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                iface.context(),
                (IpAddress::Ipv4(ipv4(*peer.ip())), peer.port()),
                local,
            )
            .map_err(|error| format!("client connect: {error}"))?;

        // Transfer scratch, dropped once the flow is idle so the idle sample
        // holds only the client stack itself.
        let mut payload = vec![0x5a_u8; CHUNK_BYTES];
        let mut sink = vec![0_u8; CHUNK_BYTES];
        let mut request_sent = 0_usize;
        let mut uploaded = 0_u64;
        let mut downloaded = 0_u64;
        let mut clock = 0_i64;
        let mut idle = false;
        loop {
            clock += 1;
            iface.poll(SmolInstant::from_millis(clock), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            while request_sent < REQUEST.len() && socket.can_send() {
                match socket.send_slice(&REQUEST[request_sent..]) {
                    Ok(0) | Err(_) => break,
                    Ok(sent) => request_sent += sent,
                }
            }
            while request_sent == REQUEST.len() && uploaded < self.plan.upload && socket.can_send()
            {
                let chunk = CHUNK_BYTES.min((self.plan.upload - uploaded) as usize);
                match socket.send_slice(&payload[..chunk]) {
                    Ok(0) | Err(_) => break,
                    Ok(sent) => uploaded += sent as u64,
                }
            }
            while socket.can_recv() {
                match socket.recv_slice(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => downloaded += read as u64,
                }
            }
            if !socket.is_open() {
                return Err(format!("flow {} closed early", self.index));
            }
            let done = downloaded >= self.plan.download
                && uploaded >= self.plan.upload
                && socket.send_queue() == 0;
            if done && !idle {
                idle = true;
                payload = Vec::new();
                sink = vec![0_u8; 64];
                self.plan.went_idle();
            }
            if idle {
                if *self.plan.close.borrow() {
                    break;
                }
                tokio::select! {
                    _ = self.plan.close.changed() => {}
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                }
            } else {
                tokio::task::yield_now().await;
            }
        }

        sockets.get_mut::<tcp::Socket>(handle).close();
        for _ in 0..200 {
            clock += 1;
            iface.poll(SmolInstant::from_millis(clock), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() {
                if socket.recv_slice(&mut sink).unwrap_or(0) == 0 {
                    break;
                }
            }
            if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

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
        "idle-flow-tun"
    }

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
        let Some(index) = ipv4_destination_port(packet)
            .and_then(|port| port.checked_sub(BASE_PORT))
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

impl TxToken for ClientTxToken<'_> {
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

fn ipv4_destination_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 4 {
        return None;
    }
    Some(u16::from_be_bytes([
        packet[header_len + 2],
        packet[header_len + 3],
    ]))
}

/// One SOCKS5 CONNECT session through the listener: the same request,
/// upload and download as a TUN flow, then idle until the close signal.
async fn socks5_flow(proxy: SocketAddr, mut plan: FlowPlan) -> Result<(), String> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|error| format!("connect the listener: {error}"))?;
    socks5_connect(&mut stream, plan.peer).await?;
    stream
        .write_all(REQUEST)
        .await
        .map_err(|error| format!("request: {error}"))?;
    let (mut reader, mut writer) = stream.split();
    let upload = async {
        let payload = vec![0x5a_u8; CHUNK_BYTES];
        let mut uploaded = 0_u64;
        while uploaded < plan.upload {
            let chunk = CHUNK_BYTES.min((plan.upload - uploaded) as usize);
            writer
                .write_all(&payload[..chunk])
                .await
                .map_err(|error| format!("upload: {error}"))?;
            uploaded += chunk as u64;
        }
        Ok::<_, String>(())
    };
    let download = async {
        let mut sink = vec![0_u8; CHUNK_BYTES];
        let mut downloaded = 0_u64;
        while downloaded < plan.download {
            match reader.read(&mut sink).await {
                Ok(0) => return Err("the session closed early".to_string()),
                Ok(read) => downloaded += read as u64,
                Err(error) => return Err(format!("download: {error}")),
            }
        }
        Ok(())
    };
    let (uploaded, downloaded) = tokio::join!(upload, download);
    uploaded?;
    downloaded?;
    plan.went_idle();
    while !*plan.close.borrow() {
        if plan.close.changed().await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    let SocketAddr::V4(target) = target else {
        return Err("the peer is IPv4 loopback".into());
    };
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| format!("SOCKS greeting: {error}"))?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("SOCKS method: {error}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("SOCKS method rejected: {method:02x?}"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS connect: {error}"))?;
    let mut reply = [0_u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| format!("SOCKS reply: {error}"))?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS connect rejected: code {:#04x}", reply[1]));
    }
    Ok(())
}

/// One loopback peer for every flow: per connection it reads the request,
/// sends `download` bytes while draining `upload` bytes, then holds the
/// connection open until the client closes it.
async fn spawn_peer(
    download: u64,
    upload: u64,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("bind peer: {error}"))?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let mut request = vec![0_u8; REQUEST.len()];
                if reader.read_exact(&mut request).await.is_err() {
                    return;
                }
                let drain = async move {
                    // Small and inline: the peer is in this process, and a
                    // heap buffer held while idle would count as Core memory.
                    let mut buffer = [0_u8; 512];
                    let mut drained = 0_u64;
                    while let Ok(read) = reader.read(&mut buffer).await {
                        if read == 0 {
                            break;
                        }
                        drained += read as u64;
                    }
                    drained >= upload
                };
                let send = async move {
                    let buffer = vec![0xa5_u8; CHUNK_BYTES];
                    let mut sent = 0_u64;
                    while sent < download {
                        let chunk = CHUNK_BYTES.min((download - sent) as usize);
                        if writer.write_all(&buffer[..chunk]).await.is_err() {
                            return writer;
                        }
                        sent += chunk as u64;
                    }
                    writer
                };
                // The writer stays alive until the client closes, so the
                // relay sits established and idle in between.
                let (_, _writer) = tokio::join!(drain, send);
            });
        }
    });
    Ok((addr, task))
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("idle-flow-memory-direct");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

fn ipv4(address: Ipv4Addr) -> Ipv4Address {
    let [a, b, c, d] = address.octets();
    Ipv4Address::new(a, b, c, d)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
