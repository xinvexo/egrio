//! TCP segments on the capture interface: reading the ones the client sends
//! and writing the headers of the ones the stack sends back (RFC 9293
//! section 3.1, IPv4 per RFC 791, IPv6 per RFC 8200).

use std::net::{IpAddr, SocketAddr};
use std::ops::Range;

use super::checksum::Checksum;
use super::seq::Seq;
use crate::packet::frame::{parse_transport, IpTransportProtocol};

pub(crate) const FIN: u8 = 0x01;
pub(crate) const SYN: u8 = 0x02;
pub(crate) const RST: u8 = 0x04;
pub(crate) const PSH: u8 = 0x08;
pub(crate) const ACK: u8 = 0x10;

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_HEADER: usize = 20;
/// Offset of the checksum in the TCP header (RFC 9293 section 3.1).
pub(crate) const TCP_CHECKSUM: usize = 16;
/// TCP options fit in 40 bytes (a 4-bit data offset in 32-bit words).
const MAX_TCP_OPTIONS: usize = 40;
/// The largest header the stack writes: IPv6 plus TCP with full options.
pub(crate) const MAX_HEADER: usize = IPV6_HEADER + TCP_HEADER + MAX_TCP_OPTIONS;
/// TTL and hop limit of the segments the stack writes; they cross only the
/// capture interface into the local stack.
const HOP_LIMIT: u8 = 64;

/// The IP and TCP header length of a segment without options between
/// `local` and its client, which the MSS leaves out (RFC 9293 section 3.7.1).
pub(crate) fn base_header_len(local: &SocketAddr) -> usize {
    match local {
        SocketAddr::V4(_) => IPV4_HEADER + TCP_HEADER,
        SocketAddr::V6(_) => IPV6_HEADER + TCP_HEADER,
    }
}

/// Up to four SACK blocks (RFC 2018 section 3), each `[left, right)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SackBlocks {
    blocks: [(Seq, Seq); 4],
    len: u8,
}

impl SackBlocks {
    pub(crate) fn push(&mut self, left: Seq, right: Seq) -> bool {
        if usize::from(self.len) == self.blocks.len() {
            return false;
        }
        self.blocks[usize::from(self.len)] = (left, right);
        self.len += 1;
        true
    }

    pub(crate) fn as_slice(&self) -> &[(Seq, Seq)] {
        &self.blocks[..usize::from(self.len)]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes the option takes when written: two NOPs, kind, length and
    /// eight bytes per block, keeping 32-bit alignment.
    fn option_len(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            4 + 8 * usize::from(self.len)
        }
    }
}

/// The options of a received segment the stack acts on; others are skipped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReceivedOptions {
    pub(crate) mss: Option<u16>,
    pub(crate) window_scale: Option<u8>,
    pub(crate) sack_permitted: bool,
    pub(crate) sack: SackBlocks,
}

/// A TCP segment from a client: its addressing and header fields, and where
/// its payload lies in the packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Received {
    pub(crate) client: SocketAddr,
    pub(crate) target: SocketAddr,
    pub(crate) seq: Seq,
    pub(crate) ack: Seq,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    pub(crate) options: ReceivedOptions,
    pub(crate) payload: Range<usize>,
}

impl Received {
    pub(crate) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Sequence space the segment occupies: payload plus SYN and FIN.
    pub(crate) fn seq_len(&self) -> usize {
        self.payload.len() + usize::from(self.has(SYN)) + usize::from(self.has(FIN))
    }

    /// Whether the segment overlaps what may arrive: it must not end before
    /// `rcv_nxt` or start beyond the advertised edge. Trimming to the window
    /// follows; a FIN at `rcv_nxt` passes even into a zero window.
    pub(crate) fn acceptable(&self, rcv_nxt: Seq, rcv_edge: Seq) -> bool {
        let ends_in_time = if self.seq_len() == 0 {
            !self.seq.is_before(rcv_nxt)
        } else {
            self.seq.add(self.seq_len()).is_after(rcv_nxt)
        };
        ends_in_time && !self.seq.is_after(rcv_edge)
    }
}

/// Reads a captured packet as a TCP segment. `None` for anything else or a
/// malformed header. Checksums are not verified: captured packets come from
/// the local stack and never cross a wire.
pub(crate) fn parse(packet: &[u8]) -> Option<Received> {
    let view = parse_transport(packet).ok()?;
    if view.protocol != IpTransportProtocol::Tcp {
        return None;
    }
    let tcp = packet.get(view.transport.clone())?;
    if tcp.len() < TCP_HEADER {
        return None;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < TCP_HEADER || data_offset > tcp.len() {
        return None;
    }
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if source_port == 0 || destination_port == 0 {
        return None;
    }
    Some(Received {
        client: SocketAddr::new(view.source_ip, source_port),
        target: SocketAddr::new(view.destination_ip, destination_port),
        seq: Seq(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]])),
        ack: Seq(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]])),
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        options: parse_options(&tcp[TCP_HEADER..data_offset]),
        payload: view.transport.start + data_offset..view.transport.end,
    })
}

/// Option kinds per RFC 9293 section 3.2, RFC 7323 and RFC 2018. A
/// malformed option ends parsing; what was read so far stands.
fn parse_options(mut options: &[u8]) -> ReceivedOptions {
    let mut parsed = ReceivedOptions::default();
    while let Some(&kind) = options.first() {
        match kind {
            0 => break,
            1 => {
                options = &options[1..];
                continue;
            }
            _ => {}
        }
        let Some(&length) = options.get(1) else {
            break;
        };
        let length = usize::from(length);
        if length < 2 || length > options.len() {
            break;
        }
        let body = &options[2..length];
        match (kind, body.len()) {
            (2, 2) => parsed.mss = Some(u16::from_be_bytes([body[0], body[1]])),
            // RFC 7323 section 2.3: a shift above 14 is used as 14.
            (3, 1) => parsed.window_scale = Some(body[0].min(14)),
            (4, 0) => parsed.sack_permitted = true,
            (5, n) if n % 8 == 0 => {
                for block in body.chunks_exact(8) {
                    parsed.sack.push(
                        Seq(u32::from_be_bytes([block[0], block[1], block[2], block[3]])),
                        Seq(u32::from_be_bytes([block[4], block[5], block[6], block[7]])),
                    );
                }
            }
            _ => {}
        }
        options = &options[length..];
    }
    parsed
}

/// The header fields of one segment the stack sends to a client.
#[derive(Clone, Debug)]
pub(crate) struct Outgoing {
    /// The captured destination, the segment's source.
    pub(crate) local: SocketAddr,
    pub(crate) client: SocketAddr,
    pub(crate) seq: Seq,
    pub(crate) ack: Seq,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    /// SYN|ACK only.
    pub(crate) mss: Option<u16>,
    /// SYN|ACK only, when the client offered scaling.
    pub(crate) window_scale: Option<u8>,
    /// SYN|ACK only, when the client offered SACK.
    pub(crate) sack_permitted: bool,
    pub(crate) sack: SackBlocks,
}

impl Outgoing {
    /// Bytes of TCP options this segment carries.
    pub(crate) fn options_len(&self) -> usize {
        let mut length = self.sack.option_len();
        if self.mss.is_some() {
            length += 4;
        }
        if self.window_scale.is_some() {
            length += 4;
        }
        if self.sack_permitted {
            length += 4;
        }
        length
    }
}

/// The IP and TCP header that goes in front of a segment's payload. Its TCP
/// checksum holds only the pseudo-header sum until [`Header::finish_checksum`]
/// or the device's OS adds the rest.
#[derive(Clone)]
pub(crate) struct Header {
    bytes: [u8; MAX_HEADER],
    len: u8,
}

impl Header {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Where the TCP header starts: the IP header's length.
    pub(crate) fn tcp_offset(&self) -> usize {
        if self.bytes[0] >> 4 == 4 {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        }
    }

    /// Completes the TCP checksum over the header and `payload`: the field's
    /// pseudo-header sum is summed with them.
    pub(crate) fn finish_checksum<'a>(&mut self, payload: impl Iterator<Item = &'a [u8]>) {
        let start = self.tcp_offset();
        let mut checksum = Checksum::default();
        checksum.add(&self.bytes[start..usize::from(self.len)]);
        for piece in payload {
            checksum.add(piece);
        }
        let field = start + TCP_CHECKSUM;
        self.bytes[field..field + 2].copy_from_slice(&checksum.finish().to_be_bytes());
    }
}

impl std::fmt::Debug for Header {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Header")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Writes the IP and TCP header of `segment` for a payload of `payload_len`
/// bytes: the IPv4 header checksum complete, the TCP checksum holding the
/// pseudo-header sum (RFC 9293 section 3.1) for the rest to be added over the
/// header and payload.
pub(crate) fn write_header(segment: &Outgoing, payload_len: usize) -> Header {
    let options_len = segment.options_len();
    debug_assert!(options_len <= MAX_TCP_OPTIONS);
    let tcp_len = TCP_HEADER + options_len;
    let mut bytes = [0u8; MAX_HEADER];
    let ip_len = match (segment.local.ip(), segment.client.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total = (IPV4_HEADER + tcp_len + payload_len) as u16;
            let ip = &mut bytes[..IPV4_HEADER];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            // Don't Fragment, so the identification field is unused (RFC 6864
            // section 4.1).
            ip[6] = 0x40;
            ip[8] = HOP_LIMIT;
            ip[9] = 6;
            ip[12..16].copy_from_slice(&source.octets());
            ip[16..20].copy_from_slice(&destination.octets());
            let mut checksum = Checksum::default();
            checksum.add(ip);
            ip[10..12].copy_from_slice(&checksum.finish().to_be_bytes());
            IPV4_HEADER
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let ip = &mut bytes[..IPV6_HEADER];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&((tcp_len + payload_len) as u16).to_be_bytes());
            ip[6] = 6;
            ip[7] = HOP_LIMIT;
            ip[8..24].copy_from_slice(&source.octets());
            ip[24..40].copy_from_slice(&destination.octets());
            IPV6_HEADER
        }
        _ => unreachable!("a flow's two ends share an address family"),
    };

    let tcp = &mut bytes[ip_len..ip_len + tcp_len];
    tcp[0..2].copy_from_slice(&segment.local.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&segment.client.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&segment.seq.0.to_be_bytes());
    tcp[8..12].copy_from_slice(&segment.ack.0.to_be_bytes());
    tcp[12] = ((tcp_len / 4) as u8) << 4;
    tcp[13] = segment.flags;
    tcp[14..16].copy_from_slice(&segment.window.to_be_bytes());
    write_options(segment, &mut tcp[TCP_HEADER..]);

    let mut checksum = Checksum::default();
    match (segment.local.ip(), segment.client.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            checksum.add(&source.octets());
            checksum.add(&destination.octets());
            checksum.add(&[0, 6]);
            checksum.add(&((tcp_len + payload_len) as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            checksum.add(&source.octets());
            checksum.add(&destination.octets());
            checksum.add(&((tcp_len + payload_len) as u32).to_be_bytes());
            checksum.add(&[0, 0, 0, 6]);
        }
        _ => unreachable!("a flow's two ends share an address family"),
    }
    tcp[TCP_CHECKSUM..TCP_CHECKSUM + 2].copy_from_slice(&checksum.folded().to_be_bytes());

    Header {
        bytes,
        len: (ip_len + tcp_len) as u8,
    }
}

/// Writes the options `options_len` counted, NOP-padded to 32-bit words.
fn write_options(segment: &Outgoing, out: &mut [u8]) {
    let mut at = 0;
    if let Some(mss) = segment.mss {
        out[at..at + 4].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        at += 4;
    }
    if segment.sack_permitted {
        out[at..at + 4].copy_from_slice(&[1, 1, 4, 2]);
        at += 4;
    }
    if let Some(shift) = segment.window_scale {
        out[at..at + 4].copy_from_slice(&[1, 3, 3, shift]);
        at += 4;
    }
    if !segment.sack.is_empty() {
        let blocks = segment.sack.as_slice();
        out[at..at + 4].copy_from_slice(&[1, 1, 5, (2 + 8 * blocks.len()) as u8]);
        at += 4;
        for (left, right) in blocks {
            out[at..at + 4].copy_from_slice(&left.0.to_be_bytes());
            out[at + 4..at + 8].copy_from_slice(&right.0.to_be_bytes());
            at += 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::frame::{ipv4_tcp_checksum, ipv6_transport_checksum};

    fn outgoing(local: &str, client: &str) -> Outgoing {
        Outgoing {
            local: local.parse().unwrap(),
            client: client.parse().unwrap(),
            seq: Seq(0x0102_0304),
            ack: Seq(0x0a0b_0c0d),
            flags: ACK | PSH,
            window: 4096,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: SackBlocks::default(),
        }
    }

    /// The segment as a device without checksum offload sends it.
    fn packet(header: &Header, payload: &[&[u8]]) -> Vec<u8> {
        let mut header = header.clone();
        header.finish_checksum(payload.iter().copied());
        let mut packet = header.as_slice().to_vec();
        for piece in payload {
            packet.extend_from_slice(piece);
        }
        packet
    }

    #[test]
    fn an_ipv4_segment_round_trips_with_valid_checksums() {
        let segment = outgoing("93.184.216.34:443", "10.0.0.2:53123");
        let payload: [&[u8]; 2] = [b"hello, ", b"world"];
        let header = write_header(&segment, 12);
        // Until finished, the field holds the pseudo-header sum alone, as
        // Linux expects of a CHECKSUM_PARTIAL segment.
        let mut pseudo = Checksum::default();
        pseudo.add(&[93, 184, 216, 34, 10, 0, 0, 2, 0, 6, 0, 32]);
        assert_eq!(header.as_slice()[36..38], pseudo.folded().to_be_bytes());
        let bytes = packet(&header, &payload);
        assert_eq!(header.as_slice().len(), 40);
        let mut ip = Checksum::default();
        ip.add(&bytes[..20]);
        assert_eq!(ip.finish(), 0, "IPv4 header checksum verifies");
        let mut tcp = bytes[20..].to_vec();
        let stored = u16::from_be_bytes([tcp[16], tcp[17]]);
        tcp[16..18].fill(0);
        let expected = ipv4_tcp_checksum(
            "93.184.216.34".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            &tcp,
        );
        assert_eq!(stored, expected);

        // The stack's own reader sees the segment from the other side.
        let received = parse(&bytes).expect("parses");
        assert_eq!(received.client, segment.local);
        assert_eq!(received.target, segment.client);
        assert_eq!(received.seq, segment.seq);
        assert_eq!(received.ack, segment.ack);
        assert_eq!(received.flags, ACK | PSH);
        assert_eq!(received.window, 4096);
        assert_eq!(&bytes[received.payload.clone()], b"hello, world");
    }

    #[test]
    fn an_ipv6_syn_ack_carries_its_options() {
        let mut segment = outgoing("[2001:db8::1]:443", "[fd00::2]:40000");
        segment.flags = SYN | ACK;
        segment.mss = Some(65475);
        segment.window_scale = Some(5);
        segment.sack_permitted = true;
        let header = write_header(&segment, 0);
        assert_eq!(header.as_slice().len(), 40 + 20 + 12);
        let bytes = packet(&header, &[]);
        let mut tcp = bytes[40..].to_vec();
        let stored = u16::from_be_bytes([tcp[16], tcp[17]]);
        tcp[16..18].fill(0);
        let expected = ipv6_transport_checksum(
            "2001:db8::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            6,
            &tcp,
        );
        assert_eq!(stored, expected);
        let received = parse(&bytes).expect("parses");
        assert_eq!(
            received.options,
            ReceivedOptions {
                mss: Some(65475),
                window_scale: Some(5),
                sack_permitted: true,
                sack: SackBlocks::default(),
            }
        );
        assert!(received.payload.is_empty());
    }

    #[test]
    fn sack_blocks_survive_a_round_trip_and_odd_options_are_skipped() {
        let mut segment = outgoing("93.184.216.34:443", "10.0.0.2:53123");
        segment.sack.push(Seq(100), Seq(200));
        segment.sack.push(Seq(300), Seq(400));
        let header = write_header(&segment, 1);
        let bytes = packet(&header, &[b"x"]);
        let received = parse(&bytes).expect("parses");
        assert_eq!(
            received.options.sack.as_slice(),
            &[(Seq(100), Seq(200)), (Seq(300), Seq(400))]
        );

        // Timestamps and an unknown option are skipped; a truncated option
        // ends parsing without discarding what came before.
        let options = [8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 2, 4, 5, 180, 99, 3, 0, 3];
        let parsed = parse_options(&options);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.window_scale, None);
        assert_eq!(parse_options(&[3, 3, 20]).window_scale, Some(14));
    }

    #[test]
    fn non_tcp_and_malformed_packets_are_refused() {
        let segment = outgoing("93.184.216.34:443", "10.0.0.2:53123");
        let mut bytes = packet(&write_header(&segment, 0), &[]);
        bytes[32] = 0x40; // data offset 16 bytes, below the minimum
        assert!(parse(&bytes).is_none());
        bytes[32] = 0xf0; // data offset 60 bytes, past the packet
        assert!(parse(&bytes).is_none());
        bytes[32] = 0x50;
        bytes[9] = 17; // UDP
        assert!(parse(&bytes).is_none());
        assert!(parse(&bytes[..30]).is_none());
    }
}
