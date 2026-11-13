//! Example-local in-memory TUN for the UDP harnesses. Datagrams enter Core
//! as captured IPv4/UDP packets through `NativeCoreDevice::run_packet_queue`
//! — the production capture data plane every platform adapter feeds — and
//! Core's reply packets come back parsed. Like a TUN ring, the inbound queue
//! is bounded: a full ring holds the writer back until the pump drains it.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egrio_core::{
    NativeCoreDevice, NativeCoreDeviceRunReport, PacketDevice, PacketInterest, PacketQueue,
    PacketReady, PacketSend,
};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const RING_PACKETS: usize = 4096;
const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const PROTOCOL_UDP: u8 = 17;

/// One Core → client UDP packet.
pub struct UdpReply {
    pub source: SocketAddrV4,
    pub payload: Vec<u8>,
}

#[derive(Default)]
struct Ring {
    queue: Mutex<VecDeque<Vec<u8>>>,
    pushed: Notify,
    popped: Notify,
}

/// Client side of the TUN: writes captured datagrams into the ring.
#[derive(Clone)]
pub struct UdpTunWriter {
    ring: Arc<Ring>,
}

/// Client side of the TUN: the reply packets Core wrote back.
pub struct UdpTunReader {
    replies: mpsc::UnboundedReceiver<UdpReply>,
}

/// The running packet pump.
pub struct UdpTunPump {
    cancel: CancellationToken,
    task: JoinHandle<NativeCoreDeviceRunReport>,
}

pub fn start(core: &NativeCoreDevice) -> (UdpTunWriter, UdpTunReader, UdpTunPump) {
    let ring = Arc::new(Ring::default());
    let (replies_tx, replies) = mpsc::unbounded_channel();
    let mut device = RingDevice {
        ring: Arc::clone(&ring),
        replies: replies_tx,
    };
    let cancel = CancellationToken::new();
    let pump_core = core.clone();
    let pump_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        pump_core
            .run_packet_queue(PacketQueue::ONLY, &mut device, pump_cancel)
            .await
    });
    (
        UdpTunWriter { ring },
        UdpTunReader { replies },
        UdpTunPump { cancel, task },
    )
}

impl UdpTunWriter {
    pub async fn send(&self, source: SocketAddrV4, target: SocketAddrV4, payload: &[u8]) {
        let mut packet = Some(build_ipv4_udp(source, target, payload));
        loop {
            let popped = self.ring.popped.notified();
            {
                let mut queue = self.ring.queue.lock().expect("TUN ring");
                if queue.len() < RING_PACKETS {
                    queue.push_back(packet.take().expect("packet pending"));
                    drop(queue);
                    self.ring.pushed.notify_one();
                    return;
                }
            }
            popped.await;
        }
    }
}

impl UdpTunReader {
    /// The next reply, or `None` once `wait` passes without one.
    pub async fn recv(&mut self, wait: Duration) -> Option<UdpReply> {
        tokio::time::timeout(wait, self.replies.recv())
            .await
            .ok()
            .flatten()
    }
}

impl UdpTunPump {
    pub async fn stop(self) -> Result<NativeCoreDeviceRunReport, String> {
        self.cancel.cancel();
        let report = self
            .task
            .await
            .map_err(|error| format!("packet pump join: {error}"))?;
        match report.fatal_error {
            Some(error) => Err(format!("packet pump: {error}")),
            None => Ok(report),
        }
    }
}

struct RingDevice {
    ring: Arc<Ring>,
    replies: mpsc::UnboundedSender<UdpReply>,
}

impl std::fmt::Debug for RingDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RingDevice")
    }
}

impl PacketDevice for RingDevice {
    fn name(&self) -> &str {
        "example-udp-tun"
    }

    fn try_recv(&mut self) -> Result<Option<egrio_core::ReceivedPacket>, String> {
        let packet = self.ring.queue.lock().expect("TUN ring").pop_front();
        if packet.is_some() {
            self.ring.popped.notify_one();
        }
        Ok(packet.map(Into::into))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        if let Some(reply) = parse_ipv4_udp(packet) {
            let _ = self.replies.send(reply);
        }
        Ok(PacketSend::Sent)
    }

    fn ready(&mut self, _: PacketInterest) -> PacketReady<'_> {
        let ring = Arc::clone(&self.ring);
        Box::pin(async move {
            // notify_one stores a permit, so a push racing this check wakes us.
            if ring.queue.lock().expect("TUN ring").is_empty() {
                ring.pushed.notified().await;
            }
            Ok(())
        })
    }
}

fn build_ipv4_udp(source: SocketAddrV4, target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER + payload.len();
    let total_len = IPV4_HEADER + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTOCOL_UDP;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&target.ip().octets());
    let header_checksum = checksum(0, &packet[..IPV4_HEADER]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp = &mut packet[IPV4_HEADER..];
    udp[0..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&target.port().to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HEADER..].copy_from_slice(payload);
    let mut pseudo = [0_u8; 12];
    pseudo[0..4].copy_from_slice(&source.ip().octets());
    pseudo[4..8].copy_from_slice(&target.ip().octets());
    pseudo[9] = PROTOCOL_UDP;
    pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let udp_checksum = match checksum(sum(0, &pseudo), udp) {
        // RFC 768: a computed zero is transmitted as all ones.
        0 => 0xffff,
        value => value,
    };
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());
    packet
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpReply> {
    if packet.len() < IPV4_HEADER || packet[0] >> 4 != 4 || packet[9] != PROTOCOL_UDP {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    let udp = packet.get(header_len..total_len)?;
    if udp.len() < UDP_HEADER {
        return None;
    }
    let source = SocketAddrV4::new(
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
    );
    Some(UdpReply {
        source,
        payload: udp[UDP_HEADER..].to_vec(),
    })
}

fn sum(mut acc: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        acc += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn checksum(acc: u32, bytes: &[u8]) -> u16 {
    let mut acc = sum(acc, bytes);
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}
