//! Hysteria2 wire primitives: the QUIC varint codec, the
//! auth/frame constants, the anti-fingerprint padding, and the UDP datagram
//! frame both halves speak. Written once here so the connector (client half)
//! and the acceptor (server half) build their opposite directions of the same
//! wire on one vocabulary.
//!
//! Always compiled: the connector links it in every build, and the acceptor
//! (server feature) reuses the same items, so the frame format has a single
//! source of truth.

use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

/// HTTP/3 status the server returns on a successful `Hysteria-Auth` (the
/// protocol's chosen "authenticated" code).
pub(crate) const AUTH_OK_STATUS: u16 = 233;
/// QUIC varint frame type prefixing a proxied-TCP request on a bi stream.
pub(crate) const HYSTERIA2_TCP_REQUEST_FRAME_TYPE: u64 = 0x401;
/// Upper bound on a request address / response message length (anti-abuse).
pub(crate) const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Upper bound on frame padding length.
pub(crate) const MAX_PADDING_LENGTH: u64 = 4096;
pub(crate) const TCP_PADDING_MIN: usize = 64;
pub(crate) const TCP_PADDING_MAX: usize = 512;
/// Datagram frame budget: the fallback max datagram size and the buffer sizing
/// both halves negotiate the QUIC datagram extension on.
pub(crate) const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
/// Datagrams one connection's QUIC datagram queues hold, each way.
///
/// The send queue drops its oldest to make room (quinn's `send_datagram`),
/// so its depth is not a bound on loss: it is how stale the datagram at the
/// front may be when it finally goes out. A thousand of them is 1.2 MB,
/// about a second of a client's share of a 10 Mbit/s link, and a UDP relay
/// that holds a second of datagrams is the bufferbloat this Core refuses
/// everywhere else -- the reply queue stops its reader rather than queue
/// past a burst, so the loss lands at the source where a UDP peer's own
/// congestion control can read it. A receive queue past a burst is as
/// pointless, and on the server's side it is also memory a connection that
/// has not authenticated can park.
///
/// A hundred and twenty-eight is a burst for the UDP sessions of one client,
/// which share these queues, and it leaves what quinn advertises for the
/// extension untouched: `max_datagram_frame_size` is capped at 65535, which
/// this and the thousand it replaces both exceed.
pub(crate) const HYSTERIA2_QUEUED_DATAGRAMS: usize = 128;
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Appends `value` as a QUIC variable-length integer (RFC 9000 §16).
pub(crate) fn put_varint(buffer: &mut BytesMut, value: u64) {
    if value <= 63 {
        buffer.put_u8(value as u8);
    } else if value <= 16_383 {
        buffer.put_u8((value >> 8) as u8 | 0x40);
        buffer.put_u8(value as u8);
    } else if value <= 1_073_741_823 {
        buffer.put_u8((value >> 24) as u8 | 0x80);
        buffer.put_u8((value >> 16) as u8);
        buffer.put_u8((value >> 8) as u8);
        buffer.put_u8(value as u8);
    } else {
        buffer.put_u8((value >> 56) as u8 | 0xc0);
        buffer.put_u8((value >> 48) as u8);
        buffer.put_u8((value >> 40) as u8);
        buffer.put_u8((value >> 32) as u8);
        buffer.put_u8((value >> 24) as u8);
        buffer.put_u8((value >> 16) as u8);
        buffer.put_u8((value >> 8) as u8);
        buffer.put_u8(value as u8);
    }
}

/// Reads a QUIC variable-length integer, returning its value and byte length,
/// or `None` when `buffer` does not yet hold the whole integer.
pub(crate) fn get_varint(buffer: &[u8]) -> Option<(u64, usize)> {
    let first = *buffer.first()?;
    let length = 1_usize << (first >> 6);
    if buffer.len() < length {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &buffer[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// Encoded byte length of `value` as a QUIC varint.
fn varint_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Random ASCII padding of a length in `[min, max)`, the anti-fingerprinting
/// filler the TCP request/response frames carry.
pub(crate) fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let length = if max > min {
        rng.random_range(min..max)
    } else {
        min
    };
    (0..length)
        .map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())])
        .collect()
}

/// [`random_padding`] as a UTF-8 string, for header values (the auth request's
/// `Hysteria-Padding`). The alphabet is ASCII, so the conversion never fails.
pub(crate) fn random_padding_string(min: usize, max: usize) -> String {
    String::from_utf8(random_padding(min, max)).expect("padding alphabet is ASCII")
}

/// One Hysteria2 UDP datagram frame: a per-session id, a per-datagram packet
/// id its fragments share, the fragment index/count, the proxied target
/// authority, and the payload. Both halves frame and deframe UDP flows on this
/// one type.
#[derive(Clone, Debug)]
pub(super) struct Hysteria2UdpMessage {
    pub(super) session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    pub(super) addr: String,
    pub(super) data: Vec<u8>,
}

impl Hysteria2UdpMessage {
    fn header_size(&self) -> usize {
        4 + 2 + 1 + 1 + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    fn to_bytes(&self) -> Bytes {
        encode_udp_message(
            self.session_id,
            self.packet_id,
            self.frag_id,
            self.frag_count,
            &self.addr,
            &self.data,
        )
    }

    pub(super) fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < 8 {
            return None;
        }
        let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
        let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
        let frag_id = datagram[6];
        let frag_count = datagram[7];
        let (address_length, used) = get_varint(&datagram[8..])?;
        if address_length == 0 || address_length > MAX_MESSAGE_LENGTH {
            return None;
        }
        let address_start = 8 + used;
        let address_end = address_start + address_length as usize;
        if datagram.len() <= address_end {
            return None;
        }
        let addr = String::from_utf8(datagram[address_start..address_end].to_vec()).ok()?;
        Some(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data: datagram[address_end..].to_vec(),
        })
    }
}

/// How many packet ids past a fragmented datagram the defragger waits for
/// its missing fragments. A sender sends a datagram's fragments one after
/// another; a datagram kept until the 16-bit id comes round again would take
/// the fragments of the one that reuses its id.
const STALE_PACKET_IDS: u16 = 256;

/// Reassembles the fragments of one Hysteria2 UDP datagram (they share a
/// `packet_id`): an unfragmented message passes straight through, and a
/// fragmented one is buffered until every index arrives, then reordered. A
/// datagram still missing fragments is given up when another fragmented one
/// begins or the packet ids move `STALE_PACKET_IDS` past it.
#[derive(Default)]
pub(super) struct Hysteria2UdpDefragger {
    packet_id: u16,
    /// A slot per fragment of the datagram being reassembled; empty when
    /// there is none.
    fragments: Vec<Option<Hysteria2UdpMessage>>,
    count: u8,
    size: usize,
}

impl Hysteria2UdpDefragger {
    pub(super) fn feed(&mut self, message: Hysteria2UdpMessage) -> Option<Hysteria2UdpMessage> {
        let ahead = message.packet_id.wrapping_sub(self.packet_id);
        if !self.fragments.is_empty() && ahead > STALE_PACKET_IDS && ahead < 0x8000 {
            self.fragments.clear();
        }
        if message.frag_count <= 1 {
            return Some(message);
        }
        if message.frag_id >= message.frag_count {
            return None;
        }
        if message.packet_id != self.packet_id
            || message.frag_count as usize != self.fragments.len()
        {
            self.packet_id = message.packet_id;
            self.fragments = vec![None; message.frag_count as usize];
            self.size = message.data.len();
            self.count = 1;
            let fragment_id = message.frag_id as usize;
            self.fragments[fragment_id] = Some(message);
            return None;
        }
        if self.fragments[message.frag_id as usize].is_some() {
            return None;
        }

        self.size += message.data.len();
        self.count += 1;
        let fragment_id = message.frag_id as usize;
        self.fragments[fragment_id] = Some(message);
        if self.count as usize != self.fragments.len() {
            return None;
        }

        let mut data = Vec::with_capacity(self.size);
        let mut first = None;
        for fragment in std::mem::take(&mut self.fragments).into_iter().flatten() {
            data.extend_from_slice(&fragment.data);
            if first.is_none() {
                first = Some(fragment);
            }
        }
        let mut message = first?;
        message.data = data;
        message.frag_id = 0;
        message.frag_count = 1;
        Some(message)
    }
}

/// One message framed into an exactly-sized buffer: `freeze` hands the
/// allocation to quinn without a second copy, so a send is one allocation and
/// one fill.
fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    data: &[u8],
) -> Bytes {
    let size = 4 + 2 + 1 + 1 + varint_len(addr.len() as u64) + addr.len() + data.len();
    let mut buffer = BytesMut::with_capacity(size);
    buffer.put_u32(session_id);
    buffer.put_u16(packet_id);
    buffer.put_u8(frag_id);
    buffer.put_u8(frag_count);
    put_varint(&mut buffer, addr.len() as u64);
    buffer.put_slice(addr.as_bytes());
    buffer.put_slice(data);
    buffer.freeze()
}

/// Frames one UDP payload for `session_id`/`target` onto the QUIC connection,
/// fragmenting only when a whole datagram exceeds what QUIC will carry. All
/// fragments inherit `packet_id`, so the peer's defragger regroups them.
pub(super) fn send_udp_message(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<(), String> {
    // Try the whole datagram first; only fragment if QUIC rejects it as too
    // large. All fragments inherit `packet_id`, so the peer regroups them.
    match connection.send_datagram(encode_udp_message(
        session_id, packet_id, 0, 1, target, payload,
    )) {
        Ok(()) => return Ok(()),
        Err(quinn::SendDatagramError::TooLarge) => {}
        Err(error) => return Err(error.to_string()),
    }
    let message = Hysteria2UdpMessage {
        session_id,
        packet_id,
        frag_id: 0,
        frag_count: 1,
        addr: target.to_string(),
        data: payload.to_vec(),
    };

    let max_size = connection
        .max_datagram_size()
        .unwrap_or(MAX_DATAGRAM_FRAME_SIZE);
    let fragments = fragment_udp_message(&message, max_size);
    if fragments.is_empty() {
        return Err(format!(
            "payload for {target} is too large for Hysteria2 UDP datagram framing"
        ));
    }
    for fragment in fragments {
        connection
            .send_datagram(fragment.to_bytes())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn fragment_udp_message(
    message: &Hysteria2UdpMessage,
    max_size: usize,
) -> Vec<Hysteria2UdpMessage> {
    if message.size() <= max_size {
        return vec![message.clone()];
    }
    let max_payload = max_size.saturating_sub(message.header_size());
    if max_payload == 0 {
        return Vec::new();
    }

    let fragment_count = message.data.len().div_ceil(max_payload);
    if fragment_count > u8::MAX as usize {
        return Vec::new();
    }
    let mut fragments = Vec::with_capacity(fragment_count);
    for (index, payload) in message.data.chunks(max_payload).enumerate() {
        fragments.push(Hysteria2UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            frag_id: index as u8,
            frag_count: fragment_count as u8,
            addr: message.addr.clone(),
            data: payload.to_vec(),
        });
    }
    fragments
}

/// Bench-only handle over the Hysteria2 UDP datagram frame (`--features
/// bench-internals`). The `outbound_hot_paths` criterion bench measures the
/// per-datagram framing cost without a QUIC connection: the message
/// build+serialize [`send_udp_message`] hands quinn on the whole-datagram
/// path, and the peer's parse back into frame fields.
#[cfg(feature = "bench-internals")]
pub mod bench {
    use bytes::Bytes;

    use super::Hysteria2UdpMessage;

    /// One UDP session's framing identity: the session id and the proxied
    /// target authority every datagram of the flow carries.
    pub struct BenchHysteria2UdpFrame {
        session_id: u32,
        packet_id: u16,
        addr: String,
    }

    impl BenchHysteria2UdpFrame {
        /// `addr` is the proxied target authority (`host:port`) carried
        /// verbatim in every datagram.
        pub fn new(addr: &str) -> Self {
            Self {
                session_id: 7,
                packet_id: 42,
                addr: addr.into(),
            }
        }

        /// The uplink per-datagram seal, exactly [`send_udp_message`]'s
        /// unfragmented path: build the message (authority clone + payload
        /// copy), then serialize into the exactly-sized buffer quinn takes.
        pub fn seal(&self, payload: &[u8]) -> Bytes {
            Hysteria2UdpMessage {
                session_id: self.session_id,
                packet_id: self.packet_id,
                frag_id: 0,
                frag_count: 1,
                addr: self.addr.clone(),
                data: payload.to_vec(),
            }
            .to_bytes()
        }

        /// The downlink per-datagram parse ([`Hysteria2UdpMessage::parse`]):
        /// header fields, authority UTF-8 check, payload copy. Returns the
        /// payload the relay would forward.
        pub fn parse(&self, datagram: &[u8]) -> Vec<u8> {
            Hysteria2UdpMessage::parse(datagram)
                .expect("bench datagram parses")
                .data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteria2_fragments_share_one_packet_id() {
        let message = Hysteria2UdpMessage {
            session_id: 3,
            packet_id: 4242,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:53".into(),
            data: vec![7_u8; 300],
        };
        let fragments = fragment_udp_message(&message, message.header_size() + 100);

        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|fragment| fragment.packet_id == 4242));
        let ordered: Vec<u8> = (0..fragments.len() as u8).collect();
        assert_eq!(
            fragments
                .iter()
                .map(|fragment| fragment.frag_id)
                .collect::<Vec<_>>(),
            ordered
        );
    }

    #[test]
    fn hysteria2_udp_message_roundtrips() {
        let message = Hysteria2UdpMessage {
            session_id: 7,
            packet_id: 9,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:53".into(),
            data: b"dns-query".to_vec(),
        };
        let buffer = message.to_bytes();
        assert_eq!(buffer.len(), message.size());

        let parsed = Hysteria2UdpMessage::parse(&buffer).expect("parses");

        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_id, 9);
        assert_eq!(parsed.addr, "example.com:53");
        assert_eq!(parsed.data, b"dns-query");
    }

    #[test]
    fn hysteria2_udp_fragments_reassemble_in_order() {
        let message = Hysteria2UdpMessage {
            session_id: 7,
            packet_id: 99,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:53".into(),
            data: vec![42_u8; 200],
        };
        let fragments = fragment_udp_message(&message, message.header_size() + 80);
        let mut defragger = Hysteria2UdpDefragger::default();

        let mut reassembled = None;
        for fragment in fragments {
            reassembled = defragger.feed(fragment);
        }

        assert_eq!(reassembled.expect("reassembled").data, vec![42_u8; 200]);
    }

    fn unfragmented(packet_id: u16, data: Vec<u8>) -> Hysteria2UdpMessage {
        Hysteria2UdpMessage {
            session_id: 1,
            packet_id,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:53".into(),
            data,
        }
    }

    #[test]
    fn a_datagram_missing_a_fragment_never_takes_a_later_ones() {
        let mut defragger = Hysteria2UdpDefragger::default();
        let first = unfragmented(5, vec![1; 300]);
        let size = first.header_size() + 100;
        // The first datagram loses its last fragment.
        let mut fragments = fragment_udp_message(&first, size);
        fragments.pop();
        for fragment in fragments {
            assert!(defragger.feed(fragment).is_none());
        }
        // Whole datagrams follow until the 16-bit packet id comes round.
        let mut packet_id = 5_u16;
        for _ in 0..u16::MAX {
            packet_id = packet_id.wrapping_add(1);
            assert!(defragger
                .feed(unfragmented(packet_id, vec![0; 10]))
                .is_some());
        }
        // A datagram with the same id and as many fragments arrives whole.
        let second = unfragmented(packet_id.wrapping_add(1), vec![2; 300]);
        assert_eq!(second.packet_id, 5);
        let mut whole = None;
        for fragment in fragment_udp_message(&second, size) {
            whole = whole.or(defragger.feed(fragment));
        }
        assert_eq!(whole.expect("the second datagram").data, vec![2; 300]);
    }

    /// Fragments lost, duplicated and reordered among neighbors: whatever
    /// comes out is one whole datagram as sent.
    #[test]
    fn reassembled_datagrams_are_whole() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(0x4879);
        let mut defragger = Hysteria2UdpDefragger::default();
        let mut sent = std::collections::HashSet::new();
        let mut packet_id = rng.random::<u16>();
        let mut delivered = 0;
        for round in 0..5_000_u32 {
            packet_id = packet_id.wrapping_add(1);
            let length = rng.random_range(1..1_500);
            let data: Vec<u8> = round
                .to_be_bytes()
                .into_iter()
                .chain((0..length).map(|_| rng.random()))
                .collect();
            sent.insert(data.clone());
            let message = unfragmented(packet_id, data);
            let size = message.header_size() + rng.random_range(100..1_600);
            let mut fragments = fragment_udp_message(&message, size);
            if rng.random_bool(0.1) {
                fragments.remove(rng.random_range(0..fragments.len()));
            }
            if rng.random_bool(0.1) && !fragments.is_empty() {
                let copy = fragments[rng.random_range(0..fragments.len())].clone();
                fragments.push(copy);
            }
            if rng.random_bool(0.1) && fragments.len() > 1 {
                let at = rng.random_range(1..fragments.len());
                fragments.swap(at - 1, at);
            }
            for fragment in fragments {
                if let Some(whole) = defragger.feed(fragment) {
                    assert!(sent.contains(&whole.data), "a datagram as sent");
                    delivered += 1;
                }
            }
        }
        assert!(delivered > 4_000, "{delivered} delivered");
    }
}
