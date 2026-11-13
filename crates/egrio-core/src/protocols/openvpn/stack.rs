//! What answers at the tunnel's address: the Core's TCP engine
//! (`packet::tcp`), opening the connections the Core makes through the node
//! and refusing any the VPN tries to open, and UDP associations framed here,
//! one local port each. The tunnel task owns the engine; associations
//! register their ports in a table they share with it.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::attribution::ClientOwner;
use crate::packet::tcp::{CapturedTcpStream, EngineWake, TcpEngine};
use crate::packet::{build_udp_packet, udp_endpoints};

/// The largest IP packet the tunnel carries for this host: with OpenVPN's
/// data channel (24 bytes) and UDP over IPv4 (28 bytes) around it, a packet
/// still fits a 1500-byte path. The TCP engine's MSS follows from it.
pub(super) const TUNNEL_MTU: usize = 1400;
/// Replies queued for one UDP association before newer ones are dropped.
const UDP_QUEUE: usize = 256;
const FIRST_EPHEMERAL: u16 = 49152;
const EPHEMERAL_PORTS: u16 = 16384;
/// Segments taken from the engine per turn of the tunnel task.
const SEGMENTS_PER_TURN: usize = 256;

type Replies = mpsc::Sender<(SocketAddr, Vec<u8>)>;

/// The UDP associations' local ports.
#[derive(Clone, Default)]
pub(super) struct UdpPorts(Arc<Mutex<HashMap<u16, Replies>>>);

impl UdpPorts {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u16, Replies>> {
        self.0.lock().expect("OpenVPN UDP ports")
    }

    /// Opens an association on a free local port.
    pub(super) fn open(&self) -> io::Result<UdpPort> {
        let (sender, replies) = mpsc::channel(UDP_QUEUE);
        let mut ports = self.lock();
        let start = rand::random::<u16>() % EPHEMERAL_PORTS;
        let port = (0..EPHEMERAL_PORTS)
            .map(|step| FIRST_EPHEMERAL + (start + step) % EPHEMERAL_PORTS)
            .find(|port| !ports.contains_key(port))
            .ok_or(io::ErrorKind::AddrInUse)?;
        ports.insert(port, sender);
        Ok(UdpPort {
            ports: self.clone(),
            port,
            replies,
        })
    }

    fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Hands a datagram to its association; false when none has the port.
    fn deliver(&self, from: SocketAddr, port: u16, payload: &[u8]) -> bool {
        let ports = self.lock();
        let Some(replies) = ports.get(&port) else {
            return false;
        };
        // A full queue loses the datagram, as a full socket buffer would.
        let _ = replies.try_send((from, payload.to_vec()));
        true
    }
}

/// One UDP association's local port and its replies; closing it frees the
/// port.
pub(crate) struct UdpPort {
    ports: UdpPorts,
    port: u16,
    replies: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
}

impl UdpPort {
    pub(super) fn port(&self) -> u16 {
        self.port
    }

    pub(super) async fn recv(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.replies.recv().await
    }
}

impl Drop for UdpPort {
    fn drop(&mut self) {
        self.ports.lock().remove(&self.port);
    }
}

/// The tunnel's addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Addresses {
    pub(super) ipv4: Option<Ipv4Addr>,
    pub(super) ipv6: Option<Ipv6Addr>,
}

impl Addresses {
    /// This end's address for a peer at `ip`.
    pub(super) fn local_for(&self, ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(_) => self.ipv4.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6.map(IpAddr::V6),
        }
    }

    /// A UDP datagram from `port` to `to`, as an IP packet.
    pub(super) fn udp_packet(
        &self,
        port: u16,
        to: SocketAddr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let local = self.local_for(to.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the tunnel has no address of the destination's family",
            )
        })?;
        let packet =
            build_udp_packet(local, to.ip(), port, to.port(), payload).map_err(io::Error::other)?;
        if packet.len() > TUNNEL_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the datagram exceeds the tunnel's MTU",
            ));
        }
        Ok(packet)
    }
}

pub(super) struct Stack {
    engine: TcpEngine,
    addresses: Addresses,
    udp: UdpPorts,
}

impl Stack {
    pub(super) fn new(addresses: Addresses, udp: UdpPorts) -> Self {
        Self {
            engine: TcpEngine::opening(TUNNEL_MTU as u32),
            addresses,
            udp,
        }
    }

    /// What wakes the tunnel task when a connection's relay needs the engine.
    pub(super) fn wake(&self) -> Arc<EngineWake> {
        self.engine.wake()
    }

    /// Opens a TCP connection to `peer`; usable once established.
    pub(super) fn connect(
        &mut self,
        peer: SocketAddr,
        now: Instant,
    ) -> io::Result<CapturedTcpStream> {
        let local = self.addresses.local_for(peer.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the tunnel has no address of the destination's family",
            )
        })?;
        self.engine.connect(local, peer, now)
    }

    /// Takes one IP packet from the tunnel.
    pub(super) fn input(&mut self, packet: Vec<u8>, now: Instant) {
        let protocol = match packet.first().map(|byte| byte >> 4) {
            Some(4) if packet.len() >= 20 => packet[9],
            Some(6) if packet.len() >= 40 => packet[6],
            _ => return,
        };
        match protocol {
            6 => self
                .engine
                .on_packet(Bytes::from(packet), ClientOwner::Known(None), None, now),
            17 => {
                if let Some((from, to, payload)) = udp_endpoints(&packet) {
                    if self.addresses.local_for(to.ip()) == Some(to.ip()) {
                        self.udp.deliver(from, to.port(), &packet[payload]);
                    }
                }
            }
            1 | 58 => {
                if let Some((local, peer)) = unreachable_tcp(&packet) {
                    self.engine.unreachable(local, peer, now);
                }
            }
            _ => {}
        }
    }

    /// Runs the engine and returns the packets it sends.
    pub(super) fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.engine.attend(now);
        if self.engine.next_deadline().is_some_and(|due| due <= now) {
            self.engine.on_timers(now);
        }
        let mut packets = Vec::new();
        loop {
            let sent = self
                .engine
                .emit(now, SEGMENTS_PER_TURN, &mut |mut segment| {
                    segment.finish_checksum();
                    let mut packet = Vec::with_capacity(segment.len());
                    for part in segment.parts() {
                        packet.extend_from_slice(part);
                    }
                    packets.push(packet);
                });
            if sent < SEGMENTS_PER_TURN {
                break;
            }
        }
        packets
    }

    pub(super) fn next_deadline(&mut self) -> Option<Instant> {
        self.engine.next_deadline()
    }

    /// No connection or association uses the tunnel.
    pub(super) fn is_idle(&self) -> bool {
        self.engine.flow_count() == 0 && self.udp.is_empty()
    }
}

/// The TCP connection an ICMP or ICMPv6 destination-unreachable names, as
/// this end and the peer: the quoted packet's source and destination.
fn unreachable_tcp(packet: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    // ICMP type 3 or ICMPv6 type 1, the original packet 8 bytes in.
    let (icmp, unreachable) = match packet[0] >> 4 {
        4 => (packet.get(usize::from(packet[0] & 0x0f) * 4..)?, 3),
        _ => (packet.get(40..)?, 1),
    };
    if *icmp.first()? != unreachable {
        return None;
    }
    let quoted = icmp.get(8..)?;
    let (source, destination, transport) = match quoted.first()? >> 4 {
        4 => {
            let header = usize::from(quoted[0] & 0x0f) * 4;
            (quoted.get(9) == Some(&6)).then_some(())?;
            let source: [u8; 4] = quoted.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = quoted.get(16..20)?.try_into().ok()?;
            (
                IpAddr::from(source),
                IpAddr::from(destination),
                quoted.get(header..header + 4)?,
            )
        }
        6 => {
            (quoted.get(6) == Some(&6)).then_some(())?;
            let source: [u8; 16] = quoted.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = quoted.get(24..40)?.try_into().ok()?;
            (
                IpAddr::from(source),
                IpAddr::from(destination),
                quoted.get(40..44)?,
            )
        }
        _ => return None,
    };
    let ports = |at: usize| u16::from_be_bytes([transport[at], transport[at + 1]]);
    Some((
        SocketAddr::new(source, ports(0)),
        SocketAddr::new(destination, ports(2)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses() -> Addresses {
        Addresses {
            ipv4: Some(Ipv4Addr::new(10, 8, 0, 2)),
            ipv6: None,
        }
    }

    #[tokio::test]
    async fn udp_associations_take_the_datagrams_for_their_port() {
        let ports = UdpPorts::default();
        let mut stack = Stack::new(addresses(), ports.clone());
        let mut association = ports.open().unwrap();
        let server: SocketAddr = "10.8.0.1:53".parse().unwrap();
        let query = addresses()
            .udp_packet(association.port(), server, b"query")
            .unwrap();
        assert_eq!(
            udp_endpoints(&query).map(|(from, to, _)| (from.port(), to)),
            Some((association.port(), server))
        );
        let reply = build_udp_packet(
            server.ip(),
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            53,
            association.port(),
            b"answer",
        )
        .unwrap();
        stack.input(reply.clone(), Instant::now());
        assert_eq!(association.recv().await, Some((server, b"answer".to_vec())));
        assert!(!stack.is_idle());
        let port = association.port();
        drop(association);
        assert!(stack.is_idle());
        // Nobody holds the port now: the datagram goes nowhere.
        let stray = build_udp_packet(
            server.ip(),
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            53,
            port,
            b"late",
        )
        .unwrap();
        stack.input(stray, Instant::now());
        assert!(addresses()
            .udp_packet(1, server, &vec![0; TUNNEL_MTU])
            .is_err());
    }

    #[test]
    fn an_icmp_unreachable_names_the_tcp_connection_it_quotes() {
        // ICMP type 3 quoting 10.8.0.2:50000 -> 192.168.1.9:80 (TCP).
        let mut quoted = vec![
            0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 8, 0, 2, 192, 168, 1, 9,
        ];
        quoted.extend_from_slice(&[0xc3, 0x50, 0, 80, 0, 0, 0, 0]);
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 8, 0, 1, 10, 8, 0, 2,
        ];
        packet.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&quoted);
        assert_eq!(
            unreachable_tcp(&packet),
            Some((
                "10.8.0.2:50000".parse().unwrap(),
                "192.168.1.9:80".parse().unwrap()
            ))
        );
        packet[20] = 0;
        assert_eq!(
            unreachable_tcp(&packet),
            None,
            "an echo reply quotes nothing"
        );
    }
}
