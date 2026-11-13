//! Per-pump IP reassembly. Protocol basis: RFC 791 §3.2, RFC 8200 §4.5,
//! RFC 5722 §4 and RFC 815's ordered missing-range model. Overlaps are rejected
//! for both families; RFC 3168 §5.3 preserves CE and rejects Not-ECT mixtures.
//!
//! Limits cover entries (including rejected-ID tombstones), payload/header
//! bytes and conservative per-piece metadata charges. No timer/task survives
//! the owning pump: callers expire idle state and drop the assembler on stop.
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use super::frame::ipv4_header_checksum;

const LIFETIME: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 128;
const MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
const MAX_PIECES: usize = 256;
const ENTRY_CHARGE: usize = 256;
const PIECE_CHARGE: usize = 64;
const MAX_EXTENSION_HEADERS: usize = 32;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Identity {
    V4 {
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        id: u16,
    },
    V6 {
        source: [u8; 16],
        destination: [u8; 16],
        id: u32,
    },
}
/// One pump serves one capture interface, so the IP identity alone keys a
/// datagram (RFC 791 §3.2 / RFC 8200 §4.5 without the interface qualifier).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    identity: Identity,
}
impl Key {
    fn charge(&self) -> usize {
        ENTRY_CHARGE
    }
}
#[derive(Clone, Copy, Debug)]
enum Family {
    V4,
    V6,
}
#[derive(Debug)]
struct Header {
    packet: Vec<u8>,
    family: Family,
}
impl Header {
    fn charge(&self) -> usize {
        self.packet.len()
    }
    fn max_data(&self) -> usize {
        match self.family {
            Family::V4 => 65_535 - self.packet.len(),
            Family::V6 => 65_535 - (self.packet.len() - 40),
        }
    }
    fn finish(mut self, pieces: BTreeMap<usize, Vec<u8>>, ecn_seen: u8) -> Vec<u8> {
        for (_, bytes) in pieces {
            self.packet.extend_from_slice(&bytes);
        }
        let bytes = &mut self.packet;
        match self.family {
            Family::V4 => {
                let length = bytes.len() as u16;
                bytes[2..4].copy_from_slice(&length.to_be_bytes());
                bytes[6..8].fill(0);
                if ecn_seen & (1 << 3) != 0 {
                    bytes[1] = (bytes[1] & !3) | 3;
                }
                bytes[10..12].fill(0);
                let ihl = usize::from(bytes[0] & 15) * 4;
                let checksum = ipv4_header_checksum(&bytes[..ihl]);
                bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            Family::V6 => {
                let length = (bytes.len() - 40) as u16;
                bytes[4..6].copy_from_slice(&length.to_be_bytes());
                if ecn_seen & (1 << 3) != 0 {
                    bytes[1] = (bytes[1] & !0x30) | 0x30;
                }
            }
        }
        self.packet
    }
}
#[derive(Debug)]
struct Fragment {
    key: Key,
    offset: usize,
    more: bool,
    bytes: Vec<u8>,
    header: Option<Header>,
    ecn: u8,
}
#[derive(Debug, Default)]
struct Partial {
    pieces: BTreeMap<usize, Vec<u8>>,
    header: Option<Header>,
    total: Option<usize>,
    received: usize,
    max_end: usize,
    ecn_seen: u8,
}
impl Partial {
    fn charge(&self) -> usize {
        self.received
            + self.pieces.len() * PIECE_CHARGE
            + self.header.as_ref().map_or(0, Header::charge)
    }
    fn add(&mut self, fragment: Fragment) -> Result<(), String> {
        let end = fragment.offset + fragment.bytes.len();
        if self.pieces.len() >= MAX_PIECES {
            return Err("IP reassembly fragment-count limit exceeded".into());
        }
        if self
            .pieces
            .range(..=fragment.offset)
            .next_back()
            .is_some_and(|(start, bytes)| start + bytes.len() > fragment.offset)
            || self
                .pieces
                .range(fragment.offset..)
                .next()
                .is_some_and(|(start, _)| end > *start)
        {
            return Err("overlapping IP fragments discard the entire datagram".into());
        }
        if self
            .total
            .is_some_and(|total| end > total || (fragment.more && end >= total))
        {
            return Err("IP fragment exceeds the established final length".into());
        }
        if !fragment.more {
            if self.total.is_some_and(|total| total != end) || self.max_end > end {
                return Err("conflicting IP last-fragment lengths".into());
            }
            self.total = Some(end);
        }
        let ecn_seen = self.ecn_seen | (1 << fragment.ecn);
        if ecn_seen & 1 != 0 && ecn_seen != 1 {
            return Err("conflicting Not-ECT and ECN-capable IP fragments".into());
        }
        let max_data = fragment
            .header
            .as_ref()
            .or(self.header.as_ref())
            .map(Header::max_data);
        if max_data.is_some_and(|limit| end.max(self.max_end) > limit) {
            return Err("reassembled IP datagram exceeds its protocol length limit".into());
        }
        self.ecn_seen = ecn_seen;
        self.max_end = self.max_end.max(end);
        self.received += fragment.bytes.len();
        if let Some(header) = fragment.header {
            self.header = Some(header);
        }
        self.pieces.insert(fragment.offset, fragment.bytes);
        Ok(())
    }
    fn complete(&self) -> bool {
        self.header.is_some() && self.total == Some(self.received)
    }
}
#[derive(Debug)]
struct Entry {
    first_seen: Instant,
    partial: Option<Partial>,
}
impl Entry {
    fn charge(&self, key: &Key) -> usize {
        key.charge() + self.partial.as_ref().map_or(0, Partial::charge)
    }
}

/// A fresh assembler belongs to one packet pump run. Rejected identities are
/// held until their original deadline so late fragments cannot revive them.
#[derive(Debug, Default)]
pub(crate) struct PacketReassembler {
    entries: HashMap<Key, Entry>,
    buffered_bytes: usize,
    /// When the oldest held datagram expires, so a packet that can expire
    /// nothing pays nothing: the pump pushes every captured packet through
    /// here, fragment or not, and a scan of the held entries on each of them
    /// is charged to every flow the queue carries. `None` while none is held.
    earliest: Option<Instant>,
}
impl PacketReassembler {
    pub(crate) fn push(&mut self, packet: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        self.push_at(packet, Instant::now())
    }
    pub(crate) fn push_at(
        &mut self,
        packet: Vec<u8>,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, String> {
        self.expire_at(now);
        let parsed = match inspect(&packet) {
            Ok(parsed) => parsed,
            Err(error) => {
                if let Some(key) = error.key {
                    self.reject(key, now);
                }
                return Err(error.message);
            }
        };
        match parsed {
            Parsed::Pass(flush) => {
                // RFC 791: a non-atomic whole IPv4 datagram supersedes queued
                // fragments. RFC 6864 atomic IDs are ignored and never flush.
                if let Some(key) = flush {
                    self.remove(&key);
                }
                Ok(Some(packet))
            }
            Parsed::Atomic(packet) => Ok(Some(packet)),
            Parsed::Fragment(fragment) => {
                let key = fragment.key.clone();
                let mut entry = if let Some(entry) = self.entries.remove(&key) {
                    self.buffered_bytes -= entry.charge(&key);
                    entry
                } else {
                    if self.entries.len() >= MAX_ENTRIES
                        || self.buffered_bytes + key.charge() > MAX_BUFFERED_BYTES
                    {
                        return Err("IP reassembly entry/byte budget exhausted".into());
                    }
                    self.earliest.get_or_insert(now + LIFETIME);
                    Entry {
                        first_seen: now,
                        partial: Some(Partial::default()),
                    }
                };
                let result = match entry.partial.as_mut() {
                    Some(partial) => partial.add(fragment),
                    None => Err("IP fragment belongs to a rejected datagram".into()),
                };
                if let Err(error) = result {
                    entry.partial = None;
                    self.buffered_bytes += entry.charge(&key);
                    self.entries.insert(key, entry);
                    return Err(error);
                }
                if self.buffered_bytes + entry.charge(&key) > MAX_BUFFERED_BYTES {
                    entry.partial = None;
                    self.buffered_bytes += entry.charge(&key);
                    self.entries.insert(key, entry);
                    return Err("IP reassembly byte budget exhausted".into());
                }
                if entry.partial.as_ref().is_some_and(Partial::complete) {
                    let partial = entry.partial.take().unwrap();
                    return Ok(Some(
                        partial
                            .header
                            .unwrap()
                            .finish(partial.pieces, partial.ecn_seen),
                    ));
                }
                self.buffered_bytes += entry.charge(&key);
                self.entries.insert(key, entry);
                Ok(None)
            }
        }
    }
    pub(crate) fn expire(&mut self) -> usize {
        self.expire_at(Instant::now())
    }
    /// When the oldest held datagram expires; `None` while none is held, so
    /// an idle pump keeps no timer for reassembly.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.earliest
    }
    pub(crate) fn expire_at(&mut self, now: Instant) -> usize {
        if self.earliest.is_none_or(|at| now < at) {
            return 0;
        }
        let before = self.entries.len();
        self.entries.retain(|key, entry| {
            if now.saturating_duration_since(entry.first_seen) >= LIFETIME {
                self.buffered_bytes -= entry.charge(key);
                false
            } else {
                true
            }
        });
        self.earliest = self
            .entries
            .values()
            .map(|entry| entry.first_seen + LIFETIME)
            .min();
        before - self.entries.len()
    }
    fn remove(&mut self, key: &Key) {
        if let Some(entry) = self.entries.remove(key) {
            self.buffered_bytes -= entry.charge(key);
        }
        if self.entries.is_empty() {
            self.earliest = None;
        }
    }
    fn reject(&mut self, key: Key, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&key) {
            self.buffered_bytes -= entry.partial.as_ref().map_or(0, Partial::charge);
            entry.partial = None;
        } else if self.entries.len() < MAX_ENTRIES
            && self.buffered_bytes + key.charge() <= MAX_BUFFERED_BYTES
        {
            self.buffered_bytes += key.charge();
            self.earliest.get_or_insert(now + LIFETIME);
            self.entries.insert(
                key,
                Entry {
                    first_seen: now,
                    partial: None,
                },
            );
        }
    }
}

#[derive(Debug)]
struct Invalid {
    key: Option<Key>,
    message: String,
}
impl Invalid {
    fn new(key: Option<&Key>, message: impl Into<String>) -> Self {
        Self {
            key: key.cloned(),
            message: message.into(),
        }
    }
}
enum Parsed {
    Pass(Option<Key>),
    Atomic(Vec<u8>),
    Fragment(Fragment),
}
fn header(packet: &[u8], length: usize, family: Family) -> Header {
    Header {
        packet: packet[..length].to_vec(),
        family,
    }
}
fn inspect(packet: &[u8]) -> Result<Parsed, Invalid> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => ipv4(packet),
        Some(6) => ipv6(packet),
        _ => Err(Invalid::new(None, "IP reassembly received a non-IP packet")),
    }
}
fn ipv4(bytes: &[u8]) -> Result<Parsed, Invalid> {
    if bytes.len() < 20 {
        return Err(Invalid::new(None, "truncated IPv4 fragment header"));
    }
    let key = Key {
        identity: Identity::V4 {
            source: bytes[12..16].try_into().unwrap(),
            destination: bytes[16..20].try_into().unwrap(),
            protocol: bytes[9],
            id: u16::from_be_bytes([bytes[4], bytes[5]]),
        },
    };
    let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
    let fragmented = flags & 0x3fff != 0;
    let key_ref = fragmented.then_some(&key);
    let ihl = usize::from(bytes[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if !(20..=60).contains(&ihl) || ihl > bytes.len() || total < ihl || total > bytes.len() {
        return Err(Invalid::new(
            key_ref,
            "invalid IPv4 fragment header/total length",
        ));
    }
    if !fragmented {
        // RFC 6864 section 4.1: DF=1/MF=0/offset=0 is atomic. Its ID has
        // no reassembly meaning, including for an existing rejected group.
        return Ok(Parsed::Pass((flags & 0x4000 == 0).then_some(key)));
    }
    if flags & 0xc000 != 0 {
        return Err(Invalid::new(
            Some(&key),
            "IPv4 fragment has reserved/Don't-Fragment flags",
        ));
    }
    if ipv4_header_checksum(&bytes[..ihl]) != 0 {
        return Err(Invalid::new(
            Some(&key),
            "invalid IPv4 fragment header checksum",
        ));
    }
    validate_ipv4_options(&bytes[20..ihl], flags & 0x1fff != 0)
        .map_err(|error| Invalid::new(Some(&key), error))?;
    let offset = usize::from(flags & 0x1fff) * 8;
    let more = flags & 0x2000 != 0;
    let data = &bytes[ihl..total];
    validate_extent(offset, data.len(), more, 65_535 - 20)
        .map_err(|error| Invalid::new(Some(&key), error))?;
    let first = if offset == 0 {
        Some(header(bytes, ihl, Family::V4))
    } else {
        None
    };
    Ok(Parsed::Fragment(Fragment {
        key,
        offset,
        more,
        bytes: data.to_vec(),
        header: first,
        ecn: bytes[1] & 3,
    }))
}
fn validate_ipv4_options(options: &[u8], non_first: bool) -> Result<(), &'static str> {
    let mut cursor = 0;
    while cursor < options.len() {
        match options[cursor] {
            0 => return Ok(()),
            1 => cursor += 1,
            kind => {
                let length = usize::from(
                    *options
                        .get(cursor + 1)
                        .ok_or("truncated IPv4 fragment option")?,
                );
                if length < 2 || cursor + length > options.len() {
                    return Err("invalid IPv4 fragment option length");
                }
                if non_first && kind & 0x80 == 0 {
                    return Err("non-first IPv4 fragment carries a non-copied option");
                }
                cursor += length;
            }
        }
    }
    Ok(())
}
fn validate_extent(
    offset: usize,
    length: usize,
    more: bool,
    maximum: usize,
) -> Result<(), &'static str> {
    if length == 0 || (more && length % 8 != 0) {
        return Err("invalid IP fragment payload length/alignment");
    }
    if offset.checked_add(length).is_none_or(|end| end > maximum) {
        return Err("IP fragment offset/length exceeds maximum datagram size");
    }
    Ok(())
}
fn ipv6(bytes: &[u8]) -> Result<Parsed, Invalid> {
    if bytes.len() < 40 {
        return Err(Invalid::new(None, "truncated IPv6 fragment header"));
    }
    let total = 40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if total > bytes.len() {
        return Err(Invalid::new(None, "invalid IPv6 payload length"));
    }
    if total == 40 && bytes.len() != 40 {
        return Err(Invalid::new(
            None,
            "IPv6 jumbograms are not supported for reassembly",
        ));
    }
    let mut next = bytes[6];
    let mut cursor = 40;
    let mut previous_next = 6;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            44 => {
                if cursor + 8 > total {
                    return Err(Invalid::new(None, "truncated IPv6 Fragment header"));
                }
                let key = Key {
                    identity: Identity::V6 {
                        source: bytes[8..24].try_into().unwrap(),
                        destination: bytes[24..40].try_into().unwrap(),
                        id: u32::from_be_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()),
                    },
                };
                let field = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
                // RFC 8200 reserved fields are ignored on reception.
                let offset = usize::from(field & 0xfff8);
                let more = field & 1 != 0;
                let data = &bytes[cursor + 8..total];
                let protocol = bytes[cursor];
                let atomic = offset == 0 && !more;
                let rejected_key = (!atomic).then_some(&key);
                if offset == 0 {
                    complete_first_header(protocol, data)
                        .map_err(|error| Invalid::new(rejected_key, error))?;
                }
                let mut first = (offset == 0).then(|| header(bytes, cursor, Family::V6));
                if let Some(header) = &mut first {
                    header.packet[previous_next] = protocol;
                }
                if offset == 0 && !more {
                    // RFC 8200/RFC 6946: atomic fragments never share state
                    // with ordinary fragments, including rejected identities.
                    let packet = first.unwrap().finish(
                        BTreeMap::from([(0, data.to_vec())]),
                        1 << ((bytes[1] >> 4) & 3),
                    );
                    return Ok(Parsed::Atomic(packet));
                }
                validate_extent(offset, data.len(), more, 65_535 - (cursor - 40))
                    .map_err(|error| Invalid::new(Some(&key), error))?;
                return Ok(Parsed::Fragment(Fragment {
                    key,
                    offset,
                    more,
                    bytes: data.to_vec(),
                    header: first,
                    ecn: (bytes[1] >> 4) & 3,
                }));
            }
            0 | 43 | 60 => {
                if next == 0 && cursor != 40 {
                    return Err(Invalid::new(None, "IPv6 Hop-by-Hop header is not first"));
                }
                if cursor + 8 > total {
                    return Err(Invalid::new(
                        None,
                        "truncated IPv6 extension before Fragment header",
                    ));
                }
                let length = 8 + usize::from(bytes[cursor + 1]) * 8;
                if cursor + length > total {
                    return Err(Invalid::new(None, "IPv6 extension length exceeds payload"));
                }
                previous_next = cursor;
                next = bytes[cursor];
                cursor += length;
            }
            _ => return Ok(Parsed::Pass(None)),
        }
    }
    Err(Invalid::new(
        None,
        "IPv6 extension-header count limit exceeded",
    ))
}
fn complete_first_header(mut next: u8, bytes: &[u8]) -> Result<(), &'static str> {
    let mut cursor = 0;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            44 => return Err("nested IPv6 Fragment header is not permitted"),
            0 => return Err("IPv6 Hop-by-Hop header follows a Fragment header"),
            43 | 60 => {
                if cursor + 8 > bytes.len() {
                    return Err("IPv6 first fragment lacks a complete extension header");
                }
                let length = 8 + usize::from(bytes[cursor + 1]) * 8;
                if cursor + length > bytes.len() {
                    return Err("IPv6 first fragment splits an extension header");
                }
                next = bytes[cursor];
                cursor += length;
            }
            6 => {
                if cursor + 20 > bytes.len() {
                    return Err("IPv6 first fragment lacks a complete TCP header");
                }
                let length = usize::from(bytes[cursor + 12] >> 4) * 4;
                if !(20..=60).contains(&length) || cursor + length > bytes.len() {
                    return Err("IPv6 first fragment splits a TCP header");
                }
                return Ok(());
            }
            17 => {
                return if cursor + 8 <= bytes.len() {
                    Ok(())
                } else {
                    Err("IPv6 first fragment lacks a complete UDP header")
                }
            }
            58 => {
                return if cursor + 4 <= bytes.len() {
                    Ok(())
                } else {
                    Err("IPv6 first fragment lacks a complete ICMPv6 header")
                }
            }
            59 => return Ok(()),
            _ => return Err("unsupported IPv6 fragmented upper-layer protocol"),
        }
    }
    Err("IPv6 fragmentable extension-header count limit exceeded")
}

#[cfg(test)]
mod tests;
