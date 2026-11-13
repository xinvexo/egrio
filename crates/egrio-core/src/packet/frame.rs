use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::attribution::{ClientOwner, FlowKey, FlowProtocol};

/// One whole captured IP packet plus the attribution its flow carried.
#[derive(Debug)]
pub(crate) struct CapturedPacket {
    pub(crate) bytes: Vec<u8>,
    pub(crate) process: ClientOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IpTransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PacketFlow {
    pub(super) source_ip: IpAddr,
    pub(super) destination_ip: IpAddr,
    pub(super) source_port: Option<u16>,
    pub(super) destination_port: Option<u16>,
    pub(super) protocol: IpTransportProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UdpDatagramView {
    pub(super) source_ip: IpAddr,
    pub(super) destination_ip: IpAddr,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PacketParseError {
    TruncatedIpHeader {
        actual: usize,
    },
    UnsupportedIpVersion {
        version: u8,
    },
    InvalidIpv4HeaderLength {
        header_len: usize,
    },
    InvalidIpv4TotalLength {
        total_len: usize,
        packet_len: usize,
    },
    FragmentedIpv4Packet,
    InvalidIpv6PayloadLength {
        payload_len: usize,
        packet_len: usize,
    },
    FragmentedIpv6Packet,
    UnsupportedIpv6ExtensionHeader {
        next_header: u8,
    },
    MissingTransportHeader {
        protocol: IpTransportProtocol,
    },
    NotUdpPacket {
        protocol: IpTransportProtocol,
    },
    InvalidUdpLength {
        udp_len: usize,
        transport_len: usize,
    },
}

impl CapturedPacket {
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            process: ClientOwner::Known(None),
        }
    }

    pub(crate) fn process_name(&self) -> Option<String> {
        self.process
            .known()
            .and_then(|process| process.name.clone())
    }

    pub(crate) fn process_path(&self) -> Option<String> {
        self.process
            .known()
            .and_then(|process| process.path.clone())
    }
}

/// The client's raw TCP/UDP five-tuple for socket attribution, plus whether
/// the packet opens a new TCP connection (SYN without ACK). Port-zero and
/// non-TCP/UDP traffic has no attributable socket.
pub(crate) fn attribution_flow(packet: &[u8]) -> Option<(FlowKey, bool)> {
    let (source_ip, destination_ip, protocol, transport) = match ip_version(packet).ok()? {
        4 => {
            let view = parse_ipv4_packet(packet).ok()?;
            (
                IpAddr::V4(view.source_ip),
                IpAddr::V4(view.destination_ip),
                view.protocol,
                &packet[view.header_len..view.total_len],
            )
        }
        6 => {
            let view = parse_ipv6_packet(packet).ok()?;
            (
                IpAddr::V6(view.source_ip),
                IpAddr::V6(view.destination_ip),
                view.protocol,
                &packet[view.transport_offset..view.transport_end],
            )
        }
        _ => return None,
    };
    let (protocol, minimum) = match protocol {
        IpTransportProtocol::Tcp => (FlowProtocol::Tcp, 20),
        IpTransportProtocol::Udp => (FlowProtocol::Udp, 8),
        _ => return None,
    };
    if transport.len() < minimum {
        return None;
    }
    let source_port = u16::from_be_bytes([transport[0], transport[1]]);
    if source_port == 0 {
        return None;
    }
    let fresh_tcp_syn = protocol == FlowProtocol::Tcp && transport[13] & 0x12 == 0x02;
    Some((
        FlowKey {
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port: u16::from_be_bytes([transport[2], transport[3]]),
        },
        fresh_tcp_syn,
    ))
}

impl fmt::Display for PacketParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedIpHeader { actual } => {
                write!(
                    formatter,
                    "packet is too short for an IP header: {actual} bytes"
                )
            }
            Self::UnsupportedIpVersion { version } => {
                write!(formatter, "unsupported IP version {version}")
            }
            Self::InvalidIpv4HeaderLength { header_len } => {
                write!(formatter, "invalid IPv4 header length {header_len}")
            }
            Self::InvalidIpv4TotalLength {
                total_len,
                packet_len,
            } => write!(
                formatter,
                "invalid IPv4 total length {total_len} for packet length {packet_len}"
            ),
            Self::FragmentedIpv4Packet => {
                write!(
                    formatter,
                    "fragmented IPv4 packets require reassembly before stateless parsing"
                )
            }
            Self::InvalidIpv6PayloadLength {
                payload_len,
                packet_len,
            } => write!(
                formatter,
                "invalid IPv6 payload length {payload_len} for packet length {packet_len}"
            ),
            Self::FragmentedIpv6Packet => {
                write!(
                    formatter,
                    "fragmented IPv6 packets require reassembly before stateless parsing"
                )
            }
            Self::UnsupportedIpv6ExtensionHeader { next_header } => {
                write!(formatter, "unsupported IPv6 extension header {next_header}")
            }
            Self::MissingTransportHeader { protocol } => {
                write!(formatter, "missing {:?} transport header", protocol)
            }
            Self::NotUdpPacket { protocol } => {
                write!(formatter, "expected UDP packet, got {:?}", protocol)
            }
            Self::InvalidUdpLength {
                udp_len,
                transport_len,
            } => write!(
                formatter,
                "invalid UDP length {udp_len} for transport length {transport_len}"
            ),
        }
    }
}

pub(super) fn parse_packet_flow(packet: &[u8]) -> Result<PacketFlow, PacketParseError> {
    match ip_version(packet)? {
        4 => {
            let view = parse_ipv4_packet(packet)?;
            Ok(PacketFlow {
                source_ip: IpAddr::V4(view.source_ip),
                destination_ip: IpAddr::V4(view.destination_ip),
                source_port: view.source_port,
                destination_port: view.destination_port,
                protocol: view.protocol,
            })
        }
        6 => {
            let view = parse_ipv6_packet(packet)?;
            Ok(PacketFlow {
                source_ip: IpAddr::V6(view.source_ip),
                destination_ip: IpAddr::V6(view.destination_ip),
                source_port: view.source_port,
                destination_port: view.destination_port,
                protocol: view.protocol,
            })
        }
        version => Err(PacketParseError::UnsupportedIpVersion { version }),
    }
}

/// Where a whole (unfragmented) IP packet's transport header and payload lie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TransportView {
    pub(super) source_ip: IpAddr,
    pub(super) destination_ip: IpAddr,
    pub(super) protocol: IpTransportProtocol,
    /// The transport header and payload, past any IPv6 extension headers and
    /// short of any link-layer padding beyond the IP length.
    pub(super) transport: std::ops::Range<usize>,
}

pub(super) fn parse_transport(packet: &[u8]) -> Result<TransportView, PacketParseError> {
    match ip_version(packet)? {
        4 => {
            let view = parse_ipv4_packet(packet)?;
            Ok(TransportView {
                source_ip: IpAddr::V4(view.source_ip),
                destination_ip: IpAddr::V4(view.destination_ip),
                protocol: view.protocol,
                transport: view.header_len..view.total_len,
            })
        }
        6 => {
            let view = parse_ipv6_packet(packet)?;
            Ok(TransportView {
                source_ip: IpAddr::V6(view.source_ip),
                destination_ip: IpAddr::V6(view.destination_ip),
                protocol: view.protocol,
                transport: view.transport_offset..view.transport_end,
            })
        }
        version => Err(PacketParseError::UnsupportedIpVersion { version }),
    }
}

fn ip_version(packet: &[u8]) -> Result<u8, PacketParseError> {
    // No IP header (v4 minimum 20, v6 fixed 40) fits in fewer than 20 bytes,
    // so report truncation before reading a version nibble out of garbage.
    if packet.len() < 20 {
        return Err(PacketParseError::TruncatedIpHeader {
            actual: packet.len(),
        });
    }
    Ok(packet[0] >> 4)
}

pub(super) fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagramView, PacketParseError> {
    let (source_ip, destination_ip, protocol, transport) = match ip_version(packet)? {
        4 => {
            let view = parse_ipv4_packet(packet)?;
            (
                IpAddr::V4(view.source_ip),
                IpAddr::V4(view.destination_ip),
                view.protocol,
                &packet[view.header_len..view.total_len],
            )
        }
        6 => {
            let view = parse_ipv6_packet(packet)?;
            (
                IpAddr::V6(view.source_ip),
                IpAddr::V6(view.destination_ip),
                view.protocol,
                &packet[view.transport_offset..view.transport_end],
            )
        }
        version => return Err(PacketParseError::UnsupportedIpVersion { version }),
    };
    if protocol != IpTransportProtocol::Udp {
        return Err(PacketParseError::NotUdpPacket { protocol });
    }

    if transport.len() < 8 {
        return Err(PacketParseError::MissingTransportHeader {
            protocol: IpTransportProtocol::Udp,
        });
    }

    let udp_len = u16::from_be_bytes([transport[4], transport[5]]) as usize;
    if udp_len < 8 || udp_len > transport.len() {
        return Err(PacketParseError::InvalidUdpLength {
            udp_len,
            transport_len: transport.len(),
        });
    }

    Ok(UdpDatagramView {
        source_ip,
        destination_ip,
        source_port: u16::from_be_bytes([transport[0], transport[1]]),
        destination_port: u16::from_be_bytes([transport[2], transport[3]]),
        payload: transport[8..udp_len].to_vec(),
    })
}

/// A whole UDP packet's client and destination endpoints and where its
/// payload lies, without copying it; `None` for anything else.
pub(crate) fn udp_endpoints(
    packet: &[u8],
) -> Option<(SocketAddr, SocketAddr, std::ops::Range<usize>)> {
    let view = parse_transport(packet).ok()?;
    if view.protocol != IpTransportProtocol::Udp {
        return None;
    }
    let header = packet.get(view.transport.start..view.transport.start + 8)?;
    let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if udp_len < 8 || udp_len > view.transport.len() {
        return None;
    }
    let source = SocketAddr::new(view.source_ip, u16::from_be_bytes([header[0], header[1]]));
    let destination = SocketAddr::new(
        view.destination_ip,
        u16::from_be_bytes([header[2], header[3]]),
    );
    Some((
        source,
        destination,
        view.transport.start + 8..view.transport.start + udp_len,
    ))
}

/// Hands each datagram of a train ([`ReceivedPacket`](super::ReceivedPacket))
/// to `out`: `segment` payload bytes each, the last one fewer, behind the
/// train's IP and UDP header with its own lengths. Their UDP checksum is zero:
/// the Core takes the payload and never forwards the datagram as it is.
pub(crate) fn split_udp_train(
    packet: &[u8],
    segment: usize,
    mut out: impl FnMut(Vec<u8>),
) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("UDP train refused: {why}"));
    let (ip_len, ipv4) = match packet.first().map(|byte| byte >> 4) {
        Some(4) => (usize::from(packet[0] & 0x0f) * 4, true),
        Some(6) => (40, false),
        _ => return refuse("not IPv4 or IPv6"),
    };
    let protocol = if ipv4 { packet.get(9) } else { packet.get(6) };
    if protocol != Some(&17) {
        return refuse("not UDP right after the IP header");
    }
    let payload_start = ip_len + 8;
    if ip_len < 20 || packet.len() < payload_start || segment == 0 {
        return refuse("truncated");
    }
    for chunk in packet[payload_start..].chunks(segment) {
        let mut datagram = Vec::with_capacity(payload_start + chunk.len());
        datagram.extend_from_slice(&packet[..payload_start]);
        datagram.extend_from_slice(chunk);
        let udp_len = (8 + chunk.len()) as u16;
        if ipv4 {
            datagram[2..4].copy_from_slice(&(ip_len as u16 + udp_len).to_be_bytes());
            datagram[10..12].fill(0);
            let checksum = ipv4_header_checksum(&datagram[..ip_len]);
            datagram[10..12].copy_from_slice(&checksum.to_be_bytes());
        } else {
            datagram[4..6].copy_from_slice(&udp_len.to_be_bytes());
        }
        datagram[ip_len + 4..ip_len + 6].copy_from_slice(&udp_len.to_be_bytes());
        datagram[ip_len + 6..ip_len + 8].fill(0);
        out(datagram);
    }
    Ok(())
}

/// How many link frames the largest UDP datagram becomes at `mtu`, counted
/// for IPv6 (40-byte header plus an 8-byte fragment header, payload in 8-byte
/// units), which needs more fragments than IPv4. It is the place the packet
/// output keeps for one datagram, and so the places a train may take: a
/// train of more than this is cut into several, because what the output
/// guarantees a drain is room for one datagram.
pub(crate) fn datagram_frames(mtu: usize) -> usize {
    let per_fragment = mtu.saturating_sub(48) / 8 * 8;
    (u16::MAX as usize).div_ceil(per_fragment.max(8))
}

/// The IP and UDP header of a train of datagrams sharing one source and
/// destination, with `payload` bytes behind it in all: lengths cover the
/// whole train and the UDP checksum field holds only the pseudo-header sum,
/// so the OS cuts the train into datagrams and finishes each one's checksum
/// (Linux UDP segmentation offload, `CHECKSUM_PARTIAL`).
pub(crate) fn udp_train_header(
    source: SocketAddr,
    destination: SocketAddr,
    payload: usize,
) -> Result<Vec<u8>, String> {
    let udp_len = u16::try_from(8 + payload)
        .map_err(|_| format!("UDP train of {payload} bytes exceeds a UDP length"))?;
    let mut pseudo = super::tcp::checksum::Checksum::default();
    let mut header = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            let total = u16::try_from(20 + 8 + payload)
                .map_err(|_| format!("IPv4 UDP train of {payload} bytes exceeds an IP length"))?;
            let mut header = vec![0_u8; 28];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&total.to_be_bytes());
            header[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            header[8] = 64;
            header[9] = 17;
            header[12..16].copy_from_slice(&source_ip.octets());
            header[16..20].copy_from_slice(&destination_ip.octets());
            let checksum = ipv4_header_checksum(&header[..20]);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            pseudo.add(&source_ip.octets());
            pseudo.add(&destination_ip.octets());
            header
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            let mut header = vec![0_u8; 48];
            header[0] = 0x60;
            header[4..6].copy_from_slice(&udp_len.to_be_bytes());
            header[6] = 17;
            header[7] = 64;
            header[8..24].copy_from_slice(&source_ip.octets());
            header[24..40].copy_from_slice(&destination_ip.octets());
            pseudo.add(&source_ip.octets());
            pseudo.add(&destination_ip.octets());
            header
        }
        (source, destination) => {
            return Err(format!(
                "UDP train address families differ: {source} -> {destination}"
            ))
        }
    };
    pseudo.add(&[0, 17]);
    pseudo.add(&udp_len.to_be_bytes());
    let udp = header.len() - 8;
    header[udp..udp + 2].copy_from_slice(&source.port().to_be_bytes());
    header[udp + 2..udp + 4].copy_from_slice(&destination.port().to_be_bytes());
    header[udp + 4..udp + 6].copy_from_slice(&udp_len.to_be_bytes());
    header[udp + 6..udp + 8].copy_from_slice(&pseudo.folded().to_be_bytes());
    Ok(header)
}

pub(crate) fn build_udp_packet(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match (source_ip, destination_ip) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => build_ipv4_udp_packet(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            payload,
        ),
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => build_ipv6_udp_packet(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            payload,
        ),
        (source_ip, destination_ip) => Err(format!(
            "UDP packet address families differ: {source_ip} -> {destination_ip}"
        )),
    }
}

pub(super) fn build_ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    if total_len > u16::MAX as usize {
        return Err(format!("IPv4 UDP packet too large: {total_len} bytes"));
    }

    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[26..28].copy_from_slice(&0_u16.to_be_bytes());
    packet[28..].copy_from_slice(payload);

    Ok(packet)
}

fn build_ipv6_udp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_len = 8 + payload.len();
    if udp_len > u16::MAX as usize {
        return Err(format!("IPv6 UDP payload too large: {udp_len} bytes"));
    }

    let mut packet = vec![0_u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17; // next header: UDP
    packet[7] = 64; // hop limit
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    // Unlike IPv4, the UDP checksum is mandatory in IPv6 (RFC 8200 §8.1).
    let checksum = ipv6_transport_checksum(source_ip, destination_ip, 17, &packet[40..]);
    // An all-zero computed checksum is transmitted as 0xffff.
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    packet[46..48].copy_from_slice(&checksum.to_be_bytes());

    Ok(packet)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv6PacketView {
    /// Offset of the transport header (after any extension headers).
    transport_offset: usize,
    /// End of the IPv6 payload (fixed header + payload length).
    transport_end: usize,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: IpTransportProtocol,
}

/// Parses the fixed IPv6 header and walks the extension-header chain to the
/// transport header. Hop-by-Hop (0), Routing (43), and Destination Options
/// (60) are skipped; a Fragment header (44) is rejected like IPv4 fragments;
/// any other unknown extension is refused instead of misparsed.
fn parse_ipv6_packet(packet: &[u8]) -> Result<Ipv6PacketView, PacketParseError> {
    if packet.len() < 40 {
        return Err(PacketParseError::TruncatedIpHeader {
            actual: packet.len(),
        });
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let transport_end = 40 + payload_len;
    if transport_end > packet.len() {
        return Err(PacketParseError::InvalidIpv6PayloadLength {
            payload_len,
            packet_len: packet.len(),
        });
    }

    let mut source = [0_u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    let source_ip = Ipv6Addr::from(source);
    let destination_ip = Ipv6Addr::from(destination);

    let mut next_header = packet[6];
    let mut offset = 40_usize;
    loop {
        match next_header {
            // Hop-by-Hop Options, Routing, Destination Options: skip by their
            // shared TLV shape (next header, length in 8-byte units minus 1).
            0 | 43 | 60 => {
                if offset + 8 > transport_end {
                    return Err(PacketParseError::MissingTransportHeader {
                        protocol: IpTransportProtocol::Other(next_header),
                    });
                }
                let extension_len = 8 + (packet[offset + 1] as usize) * 8;
                next_header = packet[offset];
                offset += extension_len;
                if offset > transport_end {
                    return Err(PacketParseError::MissingTransportHeader {
                        protocol: IpTransportProtocol::Other(next_header),
                    });
                }
            }
            44 => return Err(PacketParseError::FragmentedIpv6Packet),
            58 => {
                // ICMPv6 terminates the chain like a transport header.
                return Ok(Ipv6PacketView {
                    transport_offset: offset,
                    transport_end,
                    source_ip,
                    destination_ip,
                    source_port: None,
                    destination_port: None,
                    protocol: IpTransportProtocol::Icmp,
                });
            }
            6 | 17 => {
                let protocol = if next_header == 6 {
                    IpTransportProtocol::Tcp
                } else {
                    IpTransportProtocol::Udp
                };
                let transport = &packet[offset..transport_end];
                if transport.len() < 4 {
                    return Err(PacketParseError::MissingTransportHeader { protocol });
                }
                return Ok(Ipv6PacketView {
                    transport_offset: offset,
                    transport_end,
                    source_ip,
                    destination_ip,
                    source_port: Some(u16::from_be_bytes([transport[0], transport[1]])),
                    destination_port: Some(u16::from_be_bytes([transport[2], transport[3]])),
                    protocol,
                });
            }
            // 59: no next header — nothing follows.
            59 => {
                return Ok(Ipv6PacketView {
                    transport_offset: transport_end,
                    transport_end,
                    source_ip,
                    destination_ip,
                    source_port: None,
                    destination_port: None,
                    protocol: IpTransportProtocol::Other(59),
                });
            }
            other => {
                return Err(PacketParseError::UnsupportedIpv6ExtensionHeader { next_header: other })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4PacketView {
    header_len: usize,
    total_len: usize,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: IpTransportProtocol,
}

fn parse_ipv4_packet(packet: &[u8]) -> Result<Ipv4PacketView, PacketParseError> {
    if packet.len() < 20 {
        return Err(PacketParseError::TruncatedIpHeader {
            actual: packet.len(),
        });
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(PacketParseError::InvalidIpv4HeaderLength { header_len });
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return Err(PacketParseError::InvalidIpv4TotalLength {
            total_len,
            packet_len: packet.len(),
        });
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = fragment & 0x2000 != 0;
    let fragment_offset = fragment & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err(PacketParseError::FragmentedIpv4Packet);
    }

    let protocol = match packet[9] {
        1 => IpTransportProtocol::Icmp,
        6 => IpTransportProtocol::Tcp,
        17 => IpTransportProtocol::Udp,
        other => IpTransportProtocol::Other(other),
    };
    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (source_port, destination_port) = match protocol {
        IpTransportProtocol::Tcp | IpTransportProtocol::Udp => {
            let transport = &packet[header_len..total_len];
            if transport.len() < 4 {
                return Err(PacketParseError::MissingTransportHeader { protocol });
            }
            (
                Some(u16::from_be_bytes([transport[0], transport[1]])),
                Some(u16::from_be_bytes([transport[2], transport[3]])),
            )
        }
        IpTransportProtocol::Icmp | IpTransportProtocol::Other(_) => (None, None),
    };

    Ok(Ipv4PacketView {
        header_len,
        total_len,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
    })
}

#[cfg(test)]
pub(crate) fn ipv4_tcp_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    sum = add_checksum_bytes(sum, &source_ip.octets());
    sum = add_checksum_bytes(sum, &destination_ip.octets());
    sum += 6;
    sum += tcp_segment.len() as u32;
    sum = add_checksum_bytes(sum, tcp_segment);
    finalize_checksum(sum)
}

/// RFC 8200 pseudo-header checksum over an IPv6 transport segment
/// (TCP next-header 6, UDP next-header 17).
pub(crate) fn ipv6_transport_checksum(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    next_header: u8,
    segment: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    sum = add_checksum_bytes(sum, &source_ip.octets());
    sum = add_checksum_bytes(sum, &destination_ip.octets());
    sum += segment.len() as u32;
    sum += next_header as u32;
    sum = add_checksum_bytes(sum, segment);
    finalize_checksum(sum)
}

pub(crate) fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = add_checksum_bytes(sum, header);
    finalize_checksum(sum)
}

/// The ICMP or ICMPv6 message of an unfragmented packet, with its addresses.
pub(super) struct IcmpMessage<'a> {
    pub(super) source: IpAddr,
    pub(super) destination: IpAddr,
    pub(super) message: &'a [u8],
}

pub(super) fn icmp_message(packet: &[u8]) -> Option<IcmpMessage<'_>> {
    match packet.first()? >> 4 {
        4 => {
            let view = parse_ipv4_packet(packet).ok()?;
            (view.protocol == IpTransportProtocol::Icmp).then(|| IcmpMessage {
                source: IpAddr::V4(view.source_ip),
                destination: IpAddr::V4(view.destination_ip),
                message: &packet[view.header_len..view.total_len],
            })
        }
        6 => {
            let view = parse_ipv6_packet(packet).ok()?;
            (view.protocol == IpTransportProtocol::Icmp).then(|| IcmpMessage {
                source: IpAddr::V6(view.source_ip),
                destination: IpAddr::V6(view.destination_ip),
                message: &packet[view.transport_offset..view.transport_end],
            })
        }
        _ => None,
    }
}

/// An IP packet carrying `message` as ICMP (IPv4, protocol 1) or ICMPv6
/// (next header 58), with a hop limit of 64. The caller supplies the ICMPv4
/// checksum; the ICMPv6 one covers the pseudo-header and is filled in here.
pub(super) fn build_icmp_packet(
    source: IpAddr,
    destination: IpAddr,
    message: &[u8],
) -> Option<Vec<u8>> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_len = u16::try_from(20 + message.len()).ok()?;
            let mut packet = vec![0_u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            packet[8] = 64;
            packet[9] = 1;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let checksum = ipv4_header_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet.extend_from_slice(message);
            Some(packet)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let payload_len = u16::try_from(message.len()).ok()?;
            let mut packet = vec![0_u8; 40];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
            packet[6] = 58;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet.extend_from_slice(message);
            if message.len() >= 4 {
                packet[42..44].fill(0);
                let checksum = ipv6_transport_checksum(source, destination, 58, &packet[40..]);
                packet[42..44].copy_from_slice(&checksum.to_be_bytes());
            }
            Some(packet)
        }
        _ => None,
    }
}

/// ICMPv4 uses the plain internet checksum over the ICMP message with no
/// pseudo-header (RFC 792) — the same ones-complement sum as the IPv4 header.
/// The checksum of a message carrying its own valid checksum is zero, which
/// callers use to verify a reply.
pub(super) fn ipv4_icmp_checksum(message: &[u8]) -> u16 {
    finalize_checksum(add_checksum_bytes(0, message))
}

fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += (*byte as u32) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 UDP packet from 10.0.0.2:5000 to 1.1.1.1:443 with `payload`.
    fn udp4(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1, 0x13, 0x88,
            0x01, 0xbb, 0, 0, 0xab, 0xcd,
        ];
        packet.extend_from_slice(payload);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[24..26].copy_from_slice(&(total - 20).to_be_bytes());
        packet
    }

    fn split(packet: &[u8], segment: usize) -> Result<Vec<Vec<u8>>, String> {
        let mut datagrams = Vec::new();
        split_udp_train(packet, segment, |datagram| datagrams.push(datagram))?;
        Ok(datagrams)
    }

    #[test]
    fn a_udp_train_splits_into_its_datagrams() {
        let payload: Vec<u8> = (0..2500_u32).map(|i| i as u8).collect();
        let datagrams = split(&udp4(&payload), 1200).unwrap();
        assert_eq!(datagrams.len(), 3);
        for (datagram, chunk) in datagrams.iter().zip(payload.chunks(1200)) {
            assert_eq!(datagram, &{
                let mut expected = udp4(chunk);
                expected[26..28].fill(0);
                let checksum = ipv4_header_checksum(&expected[..20]);
                expected[10..12].copy_from_slice(&checksum.to_be_bytes());
                expected
            });
            assert_eq!(ipv4_header_checksum(&datagram[..20]), 0, "header verifies");
        }
    }

    #[test]
    fn an_ipv6_udp_train_sets_each_payload_length() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        packet.extend_from_slice(&[0xfd; 32]);
        packet.extend_from_slice(&[0x13, 0x88, 0x01, 0xbb, 0, 0, 0xab, 0xcd]);
        packet.extend_from_slice(&[7; 1000]);
        let datagrams = split(&packet, 600).unwrap();
        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0][4..6], 608_u16.to_be_bytes());
        assert_eq!(datagrams[1][4..6], 408_u16.to_be_bytes());
        assert_eq!(datagrams[1][44..46], 408_u16.to_be_bytes());
        assert_eq!(datagrams[1].len(), 40 + 408);
    }

    #[test]
    fn a_train_that_is_not_udp_is_refused() {
        let udp = udp4(&[1; 100]);
        assert!(split(&udp, 0).is_err());
        let mut tcp = udp.clone();
        tcp[9] = 6;
        assert!(split(&tcp, 50).is_err());
        assert!(split(&udp[..24], 50).is_err());
    }

    /// A one-segment train completed the way the OS completes it (adding the
    /// UDP header and payload to the pseudo-header sum the field holds) is
    /// a datagram whose checksum verifies.
    #[test]
    fn a_udp_train_header_leaves_only_the_pseudo_header_sum() {
        use super::super::tcp::checksum::Checksum;
        let payload = b"three datagrams of a train";
        for (source, destination) in [
            ("203.0.113.7:443", "10.0.0.2:40000"),
            ("[2001:db8::7]:443", "[fd00::2]:40000"),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            let mut packet = udp_train_header(source, destination, payload.len()).unwrap();
            packet.extend_from_slice(payload);
            let udp = if source.is_ipv4() { 20 } else { 40 };
            assert_eq!(parse_udp_datagram(&packet).unwrap().payload, payload);
            let mut completed = Checksum::default();
            completed.add(&packet[udp..]);
            packet[udp + 6..udp + 8].copy_from_slice(&completed.finish().to_be_bytes());
            let mut verify = Checksum::default();
            match (source.ip(), destination.ip()) {
                (IpAddr::V4(from), IpAddr::V4(to)) => {
                    verify.add(&from.octets());
                    verify.add(&to.octets());
                }
                (IpAddr::V6(from), IpAddr::V6(to)) => {
                    verify.add(&from.octets());
                    verify.add(&to.octets());
                }
                _ => unreachable!(),
            }
            verify.add(&[0, 17]);
            verify.add(&((8 + payload.len()) as u16).to_be_bytes());
            verify.add(&packet[udp..]);
            assert_eq!(
                verify.finish(),
                0,
                "{source}: the completed checksum verifies"
            );
        }
        assert!(udp_train_header(
            "203.0.113.7:443".parse().unwrap(),
            "[fd00::2]:40000".parse().unwrap(),
            10
        )
        .is_err());
    }

    #[test]
    fn parses_ipv4_tcp_flow() {
        let packet = ipv4_packet(6, 49152, 443);

        let flow = parse_packet_flow(&packet).expect("packet parses");

        assert_eq!(flow.source_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(flow.destination_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(flow.source_port, Some(49152));
        assert_eq!(flow.destination_port, Some(443));
        assert_eq!(flow.protocol, IpTransportProtocol::Tcp);
    }

    #[test]
    fn rejects_fragmented_ipv4_packet() {
        let mut packet = ipv4_packet(17, 53000, 53);
        packet[6] = 0x20;

        let error = parse_packet_flow(&packet).expect_err("fragment rejected");

        assert_eq!(error, PacketParseError::FragmentedIpv4Packet);
    }

    #[test]
    fn icmp_packets_carry_their_message_both_ways() {
        let message = [
            0_u8, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x03, b'p', b'i', b'n', b'g',
        ];
        let source: IpAddr = "fd00::5".parse().unwrap();
        let destination: IpAddr = "fd00::2".parse().unwrap();
        let packet = build_icmp_packet(source, destination, &message).unwrap();
        let parsed = icmp_message(&packet).expect("ICMPv6 parses");
        assert_eq!((parsed.source, parsed.destination), (source, destination));
        assert_eq!(&parsed.message[4..], &message[4..]);
        let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) else {
            unreachable!()
        };
        assert_eq!(
            ipv6_transport_checksum(source, destination, 58, &packet[40..]),
            0
        );

        let packet = build_icmp_packet(
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            &message,
        )
        .unwrap();
        assert_eq!(ipv4_header_checksum(&packet[..20]), 0);
        assert_eq!(icmp_message(&packet).unwrap().message, &message);
        assert!(icmp_message(&ipv4_packet(17, 53000, 53)).is_none());
    }

    #[test]
    fn parses_ipv4_udp_payload() {
        let packet = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53000,
            53,
            b"dns",
        )
        .expect("packet builds");

        let datagram = parse_udp_datagram(&packet).expect("UDP packet parses");

        assert_eq!(datagram.source_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(
            datagram.destination_ip,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        );
        assert_eq!(datagram.source_port, 53000);
        assert_eq!(datagram.destination_port, 53);
        assert_eq!(datagram.payload, b"dns");
    }

    #[test]
    fn builds_ipv4_udp_response_packet() {
        let packet = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            53,
            53000,
            b"dns",
        )
        .expect("packet builds");

        let datagram = parse_udp_datagram(&packet).expect("response parses");

        assert_eq!(datagram.source_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            datagram.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(datagram.source_port, 53);
        assert_eq!(datagram.destination_port, 53000);
        assert_eq!(datagram.payload, b"dns");
    }

    #[test]
    fn parses_ipv6_tcp_flow_with_hop_by_hop_extension() {
        // Fixed header (next: hop-by-hop) + 8-byte hop-by-hop (next: TCP)
        // + minimal TCP header start.
        let mut packet = vec![0_u8; 40 + 8 + 4];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(12_u16).to_be_bytes());
        packet[6] = 0; // hop-by-hop
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[40] = 6; // extension: next header TCP
        packet[41] = 0; // extension length: 8 bytes
        packet[48..50].copy_from_slice(&49152_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443_u16.to_be_bytes());

        let flow = parse_packet_flow(&packet).expect("IPv6 packet parses");

        assert_eq!(
            flow.source_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            flow.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(flow.source_port, Some(49152));
        assert_eq!(flow.destination_port, Some(443));
        assert_eq!(flow.protocol, IpTransportProtocol::Tcp);
    }

    #[test]
    fn rejects_ipv6_fragment_header() {
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(8_u16).to_be_bytes());
        packet[6] = 44; // fragment header
        packet[7] = 64;

        let error = parse_packet_flow(&packet).expect_err("fragment rejected");

        assert_eq!(error, PacketParseError::FragmentedIpv6Packet);
    }

    #[test]
    fn builds_and_parses_ipv6_udp_datagram_with_mandatory_checksum() {
        let source = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let destination = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let packet = build_udp_packet(
            IpAddr::V6(source),
            IpAddr::V6(destination),
            53000,
            53,
            b"dns-v6",
        )
        .expect("packet builds");

        // RFC 8200: the UDP checksum must not be transmitted as zero.
        let checksum = u16::from_be_bytes([packet[46], packet[47]]);
        assert_ne!(checksum, 0);

        let datagram = parse_udp_datagram(&packet).expect("UDP packet parses");
        assert_eq!(datagram.source_ip, IpAddr::V6(source));
        assert_eq!(datagram.destination_ip, IpAddr::V6(destination));
        assert_eq!(datagram.source_port, 53000);
        assert_eq!(datagram.destination_port, 53);
        assert_eq!(datagram.payload, b"dns-v6");
    }

    #[test]
    fn rejects_mixed_family_udp_build() {
        let error = build_udp_packet(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            1,
            2,
            b"x",
        )
        .expect_err("family mismatch rejected");

        assert!(error.contains("address families differ"));
    }

    fn attributable_v4(tcp: bool) -> Vec<u8> {
        let mut bytes = vec![0_u8; if tcp { 40 } else { 28 }];
        bytes[0] = 0x45;
        let size = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&size.to_be_bytes());
        bytes[9] = if tcp { 6 } else { 17 };
        bytes[12..16].copy_from_slice(&[10, 255, 255, 1]);
        bytes[16..20].copy_from_slice(&[198, 18, 55, 239]);
        bytes[20..22].copy_from_slice(&54123_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
        if tcp {
            bytes[33] = 0x02;
        } else {
            bytes[24..26].copy_from_slice(&8_u16.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn attribution_flow_keeps_the_raw_fake_tuple_and_flags_only_initial_syns() {
        let mut tcp = attributable_v4(true);
        let (flow, fresh) = attribution_flow(&tcp).unwrap();
        assert_eq!(flow.protocol, FlowProtocol::Tcp);
        assert_eq!(flow.source_ip.to_string(), "10.255.255.1");
        assert_eq!(flow.destination_ip.to_string(), "198.18.55.239");
        assert_eq!((flow.source_port, flow.destination_port), (54123, 443));
        assert!(fresh);
        tcp[33] = 0x12;
        assert!(
            !attribution_flow(&tcp).unwrap().1,
            "SYN-ACK is not a new flow"
        );
        for length in 0..tcp.len() {
            assert!(attribution_flow(&tcp[..length]).is_none());
        }
        let udp = attributable_v4(false);
        let (flow, fresh) = attribution_flow(&udp).unwrap();
        assert_eq!(flow.protocol, FlowProtocol::Udp);
        assert!(!fresh);
    }

    #[test]
    fn attribution_flow_ignores_port_zero_and_non_socket_traffic() {
        let mut udp = attributable_v4(false);
        udp[20..22].fill(0);
        assert!(attribution_flow(&udp).is_none());
        let icmp = ipv4_packet(1, 0, 0);
        assert!(attribution_flow(&icmp).is_none());
    }

    pub(super) fn ipv4_packet(protocol: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 24];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }
}
