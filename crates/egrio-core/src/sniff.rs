//! Sniff stage: recover a routable domain from the first
//! client bytes when the target is a bare IP, rules need a domain, and the
//! fake-IP reverse lookup missed (the enrichment chain's last and most
//! expensive link).
//!
//! Discipline over mechanism: the stage is compile-time short-circuited
//! (`RuleEngine::wants_sniffed_host`), port-gated to first-flight protocols
//! (server-speaks-first protocols like SSH/SMTP must not pay the wait), and
//! budgeted — a hard byte cap plus a wall-clock timeout. A sniff that fails
//! degrades to IP-based routing; it never fails the session.
//!
//! The parsers are pure and incremental over a byte prefix: `NeedMoreData`
//! means the prefix is a valid truncation of a sniffable protocol,
//! `Unrecognized` is conclusive (stop waiting immediately — garbage never
//! pays the full timeout).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Wall-clock budget for the client's first data on stream inbounds: a hard
/// cap of tens of milliseconds. Local first
/// flights arrive in well under a millisecond; the budget only bounds the
/// damage when a client on a sniffable port never speaks first.
pub(crate) const SNIFF_FIRST_DATA_TIMEOUT: Duration = Duration::from_millis(50);

/// Hard cap on buffered prefix bytes. Covers post-quantum TLS ClientHellos
/// (~1.8 KiB) with headroom; anything still inconclusive at the cap is
/// treated as a miss.
pub(crate) const SNIFF_MAX_PREFIX_BYTES: usize = 4096;

/// Ports whose first client flight is plausibly TLS or HTTP. Everything else
/// skips the sniff stage outright so server-speaks-first protocols never
/// wait out the timeout. A profile-level override can arrive when the
/// profile schema grows sniffer options; the gate itself is the point.
pub(crate) fn is_sniffable_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

/// One incremental parse over a prefix of the client's first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SniffStatus {
    /// A syntactically valid domain was extracted.
    Domain(String),
    /// The prefix is a valid truncation of a sniffable protocol; more bytes
    /// could still decide it.
    NeedMoreData,
    /// Conclusively not sniffable (or sniffable but carrying no domain).
    Unrecognized,
}

/// Outcome of sniffing a stream: the consumed prefix must be forwarded to
/// the outbound before the relay starts — sniffing reads, it never eats.
#[derive(Debug)]
pub(crate) struct StreamSniffOutcome {
    pub(crate) domain: Option<String>,
    pub(crate) prefix: Vec<u8>,
}

/// Counters for the sniff stage, exposed through the state audit. The
/// zero-latency gate asserts `attempted == 0` for profiles without domain
/// rules — the short-circuit is structural, not a timing accident.
#[derive(Debug, Clone, Default)]
pub(crate) struct SniffStats {
    inner: Arc<SniffStatsInner>,
}

#[derive(Debug, Default)]
struct SniffStatsInner {
    attempted: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct SniffCounters {
    pub attempted: u64,
    pub hits: u64,
    pub misses: u64,
}

impl SniffStats {
    pub(crate) fn record_attempt(&self) {
        self.inner.attempted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_outcome(&self, domain: Option<&str>) {
        if domain.is_some() {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn counters(&self) -> SniffCounters {
        SniffCounters {
            attempted: self.inner.attempted.load(Ordering::Relaxed),
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
        }
    }
}

/// Reads the client's first data under the sniff budget and tries to extract
/// a domain. Returns whatever was consumed so the caller can forward it;
/// read errors and EOF end the sniff quietly (the relay surfaces them).
pub(crate) async fn sniff_stream_first_data<S: AsyncRead + Unpin + ?Sized>(
    client: &mut S,
    stats: &SniffStats,
) -> StreamSniffOutcome {
    stats.record_attempt();
    let deadline = tokio::time::Instant::now() + SNIFF_FIRST_DATA_TIMEOUT;
    let mut prefix = Vec::new();
    let mut chunk = [0_u8; 2048];
    let domain = loop {
        let read = match tokio::time::timeout_at(deadline, client.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 => read,
            // Timeout, EOF, or a read error: give up on the domain and let
            // the ordinary relay path observe the same condition.
            _ => break None,
        };
        prefix.extend_from_slice(&chunk[..read]);
        match sniff_stream_prefix(&prefix) {
            SniffStatus::Domain(domain) => break Some(domain),
            SniffStatus::NeedMoreData if prefix.len() < SNIFF_MAX_PREFIX_BYTES => {}
            _ => break None,
        }
    };
    stats.record_outcome(domain.as_deref());
    StreamSniffOutcome { domain, prefix }
}

/// Tries the sniffable protocols over one prefix: TLS first (conclusive by
/// the first byte), then HTTP/1.x.
pub(crate) fn sniff_stream_prefix(data: &[u8]) -> SniffStatus {
    if data.is_empty() {
        return SniffStatus::NeedMoreData;
    }
    match sniff_tls_client_hello(data) {
        SniffStatus::Unrecognized => sniff_http_request(data),
        conclusive => conclusive,
    }
}

/// Extracts the SNI host name from a TLS ClientHello prefix. The walk stays
/// inside the first record; a ClientHello fragmented across records is rare
/// enough to count as a miss rather than buy reassembly.
fn sniff_tls_client_hello(data: &[u8]) -> SniffStatus {
    // Record header: handshake(0x16), version 0x03,0x00-0x04, u16 length.
    const RECORD_HEADER: usize = 5;
    if data[0] != 0x16 {
        return SniffStatus::Unrecognized;
    }
    if data.len() < RECORD_HEADER {
        return SniffStatus::NeedMoreData;
    }
    if data[1] != 0x03 || data[2] > 0x04 {
        return SniffStatus::Unrecognized;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if record_len < 4 {
        return SniffStatus::Unrecognized;
    }
    // Only bytes of the first record are trustworthy handshake bytes.
    let record = &data[RECORD_HEADER..data.len().min(RECORD_HEADER + record_len)];
    let record_complete = data.len() >= RECORD_HEADER + record_len;
    let mut walk = TruncatedWalk::new(record);

    let outcome = (|| {
        // Handshake header: client_hello(0x01) + u24 body length.
        if walk.take(1)?[0] != 0x01 {
            return Some(SniffStatus::Unrecognized);
        }
        walk.take(3)?;
        // legacy_version + random.
        walk.take(2 + 32)?;
        let session_id_len = walk.take(1)?[0] as usize;
        if session_id_len > 32 {
            return Some(SniffStatus::Unrecognized);
        }
        walk.take(session_id_len)?;
        let cipher_suites_len = walk.take_u16()? as usize;
        if cipher_suites_len == 0 || !cipher_suites_len.is_multiple_of(2) {
            return Some(SniffStatus::Unrecognized);
        }
        walk.take(cipher_suites_len)?;
        let compression_len = walk.take(1)?[0] as usize;
        walk.take(compression_len)?;
        let extensions_len = walk.take_u16()? as usize;
        let mut remaining = extensions_len;
        while remaining >= 4 {
            let extension_type = walk.take_u16()?;
            let extension_len = walk.take_u16()? as usize;
            remaining = remaining.saturating_sub(4 + extension_len);
            if extension_type != 0x0000 {
                walk.take(extension_len)?;
                continue;
            }
            // server_name extension: u16 list length, then entries of
            // u8 name_type + u16 length + bytes; host_name is type 0.
            let extension = walk.take(extension_len)?;
            let mut names = TruncatedWalk::new(extension);
            names.take_u16()?;
            while let Some(name_type) = names.take(1).map(|bytes| bytes[0]) {
                let name_len = names.take_u16()? as usize;
                let name = names.take(name_len)?;
                if name_type == 0 {
                    return Some(match validate_domain(name) {
                        Some(domain) => SniffStatus::Domain(domain),
                        None => SniffStatus::Unrecognized,
                    });
                }
            }
            return Some(SniffStatus::Unrecognized);
        }
        // Walked every extension without finding an SNI: a ClientHello with
        // no server name is conclusive.
        Some(SniffStatus::Unrecognized)
    })();

    match outcome {
        Some(status) => status,
        // The walk ran out of bytes. If the record itself is complete the
        // structure continues in a second record; give up instead of
        // reassembling.
        None if record_complete => SniffStatus::Unrecognized,
        None => SniffStatus::NeedMoreData,
    }
}

/// Sequential reader over a prefix: `take` returns `None` when the prefix
/// runs out, which the caller maps to "truncated" or "malformed" depending
/// on whether the record was complete.
struct TruncatedWalk<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TruncatedWalk<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let taken = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(taken)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

const HTTP_METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// Extracts the Host header from an HTTP/1.x request prefix.
fn sniff_http_request(data: &[u8]) -> SniffStatus {
    // METHOD followed by a space; a prefix of a method keeps waiting.
    let method_plausible = HTTP_METHODS.iter().find_map(|method| {
        let method = method.as_bytes();
        if data.len() <= method.len() {
            (*data == method[..data.len()]).then_some(false)
        } else {
            (data[..method.len()] == *method && data[method.len()] == b' ').then_some(true)
        }
    });
    match method_plausible {
        None => return SniffStatus::Unrecognized,
        Some(false) => return SniffStatus::NeedMoreData,
        Some(true) => {}
    }

    // Everything before the last '\n' is complete lines; the tail is still
    // being received and is not judged.
    let Some(last_newline) = data.iter().rposition(|&byte| byte == b'\n') else {
        return SniffStatus::NeedMoreData;
    };
    let mut lines = data[..last_newline]
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));

    let request_line = lines.next().unwrap_or(&[]);
    if !request_line.ends_with(b"HTTP/1.1") && !request_line.ends_with(b"HTTP/1.0") {
        return SniffStatus::Unrecognized;
    }

    for header in lines {
        if header.is_empty() {
            // End of headers without a Host: conclusive miss.
            return SniffStatus::Unrecognized;
        }
        let Some((name, value)) = split_header(header) else {
            return SniffStatus::Unrecognized;
        };
        if name.eq_ignore_ascii_case(b"host") {
            return match validate_domain(strip_host_port(value)) {
                Some(domain) => SniffStatus::Domain(domain),
                None => SniffStatus::Unrecognized,
            };
        }
    }
    SniffStatus::NeedMoreData
}

fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&byte| byte == b':')?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    Some((name, &line[colon + 1..]))
}

/// `example.com:8443` → `example.com`; `[::1]:80` → `::1` (rejected later as
/// an IP, not a domain).
fn strip_host_port(value: &[u8]) -> &[u8] {
    let value = trim_ascii(value);
    if let Some(end) = value.iter().position(|&byte| byte == b']') {
        return value.get(1..end).unwrap_or(&[]);
    }
    match value.iter().rposition(|&byte| byte == b':') {
        Some(colon) => &value[..colon],
        None => value,
    }
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &value[start..end]
}

/// A sniffed name is only useful if it is a plausible DNS name and not an IP
/// literal (an IP adds nothing over the destination we already have).
fn validate_domain(name: &[u8]) -> Option<String> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    if !name
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return None;
    }
    let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
    if name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name)
}

#[cfg(test)]
pub(crate) fn build_tls_client_hello(server_name: Option<&str>) -> Vec<u8> {
    let mut extensions = Vec::new();
    // A non-SNI extension first, so the walk is exercised.
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    if let Some(name) = server_name {
        let name = name.as_bytes();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xab; 32]);
    body.push(32);
    body.extend_from_slice(&[0xcd; 32]);
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    let body_len = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = build_tls_client_hello(Some("Example.COM"));

        assert_eq!(
            sniff_stream_prefix(&hello),
            SniffStatus::Domain("example.com".into())
        );
    }

    #[test]
    fn truncated_client_hello_needs_more_data_at_every_boundary() {
        let hello = build_tls_client_hello(Some("example.com"));

        // The SNI extension sits at the tail of the test hello, so every
        // proper prefix must keep asking for more instead of concluding.
        for len in 1..hello.len() {
            assert_eq!(
                sniff_stream_prefix(&hello[..len]),
                SniffStatus::NeedMoreData,
                "prefix of {len} bytes"
            );
        }
    }

    #[test]
    fn client_hello_without_sni_is_conclusive() {
        let hello = build_tls_client_hello(None);

        assert_eq!(sniff_stream_prefix(&hello), SniffStatus::Unrecognized);
    }

    #[test]
    fn sni_carrying_ip_literal_is_not_a_domain() {
        let hello = build_tls_client_hello(Some("203.0.113.7"));

        assert_eq!(sniff_stream_prefix(&hello), SniffStatus::Unrecognized);
    }

    #[test]
    fn extracts_http_host_header() {
        let request = b"GET /path HTTP/1.1\r\nUser-Agent: curl\r\nHost: API.Example.org:8080\r\n";

        assert_eq!(
            sniff_stream_prefix(request),
            SniffStatus::Domain("api.example.org".into())
        );
    }

    #[test]
    fn http_request_without_host_is_conclusive_at_header_end() {
        let request = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";

        assert_eq!(sniff_stream_prefix(request), SniffStatus::Unrecognized);
    }

    #[test]
    fn partial_http_request_needs_more_data() {
        assert_eq!(sniff_stream_prefix(b"GE"), SniffStatus::NeedMoreData);
        assert_eq!(
            sniff_stream_prefix(b"GET /path HTTP/1.1\r\nUser-Agent"),
            SniffStatus::NeedMoreData
        );
    }

    #[test]
    fn garbage_is_conclusively_unrecognized() {
        assert_eq!(
            sniff_stream_prefix(&[0x8f, 0x00, 0x13, 0x37]),
            SniffStatus::Unrecognized
        );
        assert_eq!(
            sniff_stream_prefix(b"SSH-2.0-X\r\n"),
            SniffStatus::Unrecognized
        );
    }

    #[test]
    fn http_host_with_ip_literal_is_not_a_domain() {
        let request = b"GET / HTTP/1.1\r\nHost: 203.0.113.7:8080\r\n";
        assert_eq!(sniff_stream_prefix(request), SniffStatus::Unrecognized);

        let bracketed = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n";
        assert_eq!(sniff_stream_prefix(bracketed), SniffStatus::Unrecognized);
    }

    #[test]
    fn sniffable_port_gate_matches_first_flight_ports() {
        assert!(is_sniffable_port(443));
        assert!(is_sniffable_port(80));
        assert!(!is_sniffable_port(22));
        assert!(!is_sniffable_port(25));
    }
}
