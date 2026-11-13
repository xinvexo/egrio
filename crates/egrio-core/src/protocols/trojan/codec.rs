//! The Trojan wire vocabulary: the auth hash, request framing,
//! and command set both halves speak, written once. Trojan runs inside a TLS
//! tunnel; this codec is the plaintext framing carried over it. The address is
//! the SOCKS vocabulary `target.rs` owns, shared with Shadowsocks.
//!
//! Wire reference: the trojan-gfw protocol spec
//! (<https://trojan-gfw.github.io/trojan/protocol>). After the TLS handshake the
//! client sends `hex(SHA224(password)) CRLF CMD ATYP DST.ADDR DST.PORT CRLF`
//! then the payload. Unlike stock Trojan the server does not proxy a camouflage
//! site on an unknown hash — it closes — so this
//! codec carries no fallback path.

use std::io;
use std::time::Duration;

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::target::parse_socks_address;
use crate::target::ConnectTarget;

/// Length of the hex-encoded SHA-224 password hash the client presents: 28
/// digest bytes render to 56 lowercase hex characters.
pub(crate) const TROJAN_HASH_LEN: usize = 56;

/// The CRLF that terminates each field of the Trojan preamble.
const CRLF: [u8; 2] = [0x0D, 0x0A];

/// How long the rest of a started UDP frame has to arrive, and how much of
/// its payload is read at a time. The budget is generous for the biggest
/// frame the framing allows (a 16-bit length) over any link a tunnel is
/// worth having; the chunk is what a peer's claim can hold before its bytes
/// are there.
const TROJAN_UDP_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const TROJAN_UDP_READ_CHUNK: usize = 8 * 1024;

/// Trojan request command: open a proxied TCP tunnel (mirrors SOCKS5 CONNECT).
pub(crate) const CMD_CONNECT: u8 = 0x01;

/// Trojan request command: UDP associate (mirrors SOCKS5). Both halves speak
/// it: the acceptor serves the framed datagram face and the connector opens it
/// for proxied UDP sessions.
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// `hex(SHA224(password))` — the 56-byte credential the client presents and the
/// server authenticates against. Lowercase hex, per the trojan spec.
pub(crate) fn password_hash_hex(password: &str) -> [u8; TROJAN_HASH_LEN] {
    let digest = Sha224::digest(password.as_bytes());
    let mut hex = [0_u8; TROJAN_HASH_LEN];
    for (index, byte) in digest.iter().enumerate() {
        hex[index * 2] = hex_nibble(byte >> 4);
        hex[index * 2 + 1] = hex_nibble(byte & 0x0f);
    }
    hex
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

/// Builds the client preamble that precedes the relayed payload: the auth hash,
/// the command, the SOCKS-encoded target, each field CRLF-terminated per the
/// spec. The connector appends the payload (and any folded early data) after it,
/// so the target's first flight rides the same TLS record.
pub(crate) fn encode_client_preamble(
    hash: &[u8; TROJAN_HASH_LEN],
    command: u8,
    target: &ConnectTarget,
) -> Result<Vec<u8>, String> {
    let address = target.socks_address()?;
    let mut preamble = Vec::with_capacity(TROJAN_HASH_LEN + 2 + 1 + address.len() + 2);
    preamble.extend_from_slice(hash);
    preamble.extend_from_slice(&CRLF);
    preamble.push(command);
    preamble.extend_from_slice(&address);
    preamble.extend_from_slice(&CRLF);
    Ok(preamble)
}

// ---- Server-handshake reads. The acceptor reads the
// hash first and authenticates it against the user table before reading the
// rest, so an unknown peer costs one bounded 56-byte read before the drop.

/// A domain SOCKS address is at most `ATYP + len + 255 + port`: the cap on one
/// address read, so a malformed request cannot make the acceptor read unbounded.
const MAX_ADDRESS_LEN: usize = 1 + 1 + u8::MAX as usize + 2;

/// Reads the 56-byte hex password hash the client presents. Exact and bounded:
/// this is all the acceptor reads before it authenticates, so an unauthenticated
/// peer never drives an unbounded read.
#[cfg(feature = "server")]
pub(crate) async fn read_auth_hash<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
) -> Result<[u8; TROJAN_HASH_LEN], String> {
    let mut hash = [0_u8; TROJAN_HASH_LEN];
    io.read_exact(&mut hash)
        .await
        .map_err(|error| error.to_string())?;
    Ok(hash)
}

/// Reads the request that follows the (already-authenticated) hash: the CRLF
/// after the hash, the command byte, the SOCKS target, and the trailing CRLF.
/// Every read is exact, so nothing of the client's payload is consumed — the
/// plaintext relay is the TLS stream itself, with no leftover to carry.
#[cfg(feature = "server")]
pub(crate) async fn read_request<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
) -> Result<(u8, ConnectTarget), String> {
    expect_crlf(io).await.map_err(|error| error.to_string())?;
    let mut command = [0_u8; 1];
    io.read_exact(&mut command)
        .await
        .map_err(|error| error.to_string())?;
    let target = read_socks_address(io).await?;
    expect_crlf(io).await.map_err(|error| error.to_string())?;
    Ok((command[0], target))
}

/// Reads one SOCKS address by its type byte, then decodes it through the shared
/// `target.rs` parser so the address vocabulary stays single-written.
#[cfg(feature = "server")]
async fn read_socks_address<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
) -> Result<ConnectTarget, String> {
    let mut address_type = [0_u8; 1];
    io.read_exact(&mut address_type)
        .await
        .map_err(|error| error.to_string())?;
    read_socks_address_body(io, address_type[0])
        .await
        .map_err(|error| error.to_string())
}

/// Decodes a SOCKS address whose type byte was already read: the UDP frame
/// reader peeks that byte to tell a clean end from a short read, so the body
/// decode is shared with [`read_socks_address`] rather than written twice.
async fn read_socks_address_body<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
    address_type: u8,
) -> io::Result<ConnectTarget> {
    let mut buffer = Vec::with_capacity(MAX_ADDRESS_LEN);
    buffer.push(address_type);
    match address_type {
        0x01 => read_more(io, &mut buffer, 4 + 2).await?,
        0x04 => read_more(io, &mut buffer, 16 + 2).await?,
        0x03 => {
            let mut length = [0_u8; 1];
            io.read_exact(&mut length).await?;
            buffer.push(length[0]);
            read_more(io, &mut buffer, length[0] as usize + 2).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Trojan address type {other}"),
            ))
        }
    }
    let (target, _consumed) = parse_socks_address(&buffer)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
    Ok(target)
}

/// Encodes one Trojan UDP-associate frame — `ATYP DST.ADDR DST.PORT | LENGTH(2) |
/// CRLF | PAYLOAD` (trojan spec). Request and response share this frame; on a
/// response the address is the origin the datagram came from, so the client
/// demuxes replies by it. The acceptor writes one per relayed response; the
/// connector writes one per outbound datagram.
pub(crate) fn encode_udp_frame(target: &ConnectTarget, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err(format!(
            "Trojan UDP payload of {} bytes exceeds the frame length field",
            payload.len()
        ));
    }
    let address = target.socks_address()?;
    let mut frame = Vec::with_capacity(address.len() + 2 + CRLF.len() + payload.len());
    frame.extend_from_slice(&address);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&CRLF);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Reads one Trojan UDP-associate frame off the TLS stream: the SOCKS address,
/// the 2-byte payload length, the CRLF separator, then exactly that many payload
/// bytes. `Ok(None)` is a clean end at a frame boundary (the client closed the
/// associate); a short read mid-frame is an error, because a length-framed
/// stream cannot resync.
pub(crate) async fn read_udp_frame<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
) -> io::Result<Option<(ConnectTarget, Vec<u8>)>> {
    let mut address_type = [0_u8; 1];
    let read = io.read(&mut address_type).await?;
    if read == 0 {
        return Ok(None);
    }
    // The frame has started, so the rest of it has a budget. The wait for a
    // frame to start is the one before this and has none: an associate may
    // stay open and quiet for as long as its client keeps it. What this
    // bounds is a peer that writes a byte and stops -- a length-framed
    // stream cannot be resynced, so the task would park for the connection's
    // life, holding what the declared length allocated.
    timeout(TROJAN_UDP_FRAME_TIMEOUT, async {
        let target = read_socks_address_body(io, address_type[0]).await?;
        let mut length = [0_u8; 2];
        io.read_exact(&mut length).await?;
        let payload_len = u16::from_be_bytes(length) as usize;
        expect_crlf(io).await?;
        // Grown as the payload arrives, not on the length the peer claims:
        // a frame that says 64 KiB and sends a hundred bytes holds a
        // chunk, not the claim.
        let mut payload = Vec::new();
        let mut left = payload_len;
        while left > 0 {
            let chunk = left.min(TROJAN_UDP_READ_CHUNK);
            read_more(io, &mut payload, chunk).await?;
            left -= chunk;
        }
        Ok(Some((target, payload)))
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Trojan UDP frame was started and left unfinished",
        )
    })?
}

/// Appends exactly `count` bytes read from `io` to `buffer`.
async fn read_more<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
    buffer: &mut Vec<u8>,
    count: usize,
) -> io::Result<()> {
    let start = buffer.len();
    buffer.resize(start + count, 0);
    io.read_exact(&mut buffer[start..]).await.map(|_| ())
}

/// Reads two bytes and requires them to be CRLF, the Trojan field separator.
async fn expect_crlf<R: AsyncRead + Unpin + ?Sized>(io: &mut R) -> io::Result<()> {
    let mut separator = [0_u8; 2];
    io.read_exact(&mut separator).await?;
    if separator != CRLF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trojan preamble field is not CRLF-terminated",
        ));
    }
    Ok(())
}

/// Bench-only handle over the Trojan client vocabulary (`--features
/// bench-internals`). The `outbound_hot_paths` criterion bench measures the
/// connector's dial-path costs without the TLS transport: the per-profile
/// SHA-224 credential hash and the per-dial request preamble encode;
/// outbound/Trojan hot-path changes cite this gate.
#[cfg(feature = "bench-internals")]
pub mod bench {
    use super::{encode_client_preamble, password_hash_hex, CMD_CONNECT, TROJAN_HASH_LEN};
    use crate::target::ConnectTarget;

    /// Length of the hex-encoded SHA-224 hash, re-exposed for the bench's
    /// return type.
    pub const TROJAN_HASH_HEX_LEN: usize = TROJAN_HASH_LEN;

    /// The connector's per-node preamble state: the password hash derived
    /// once at profile compile time, reused for every dialed connection.
    pub struct BenchTrojanPreamble {
        hash: [u8; TROJAN_HASH_HEX_LEN],
        target: ConnectTarget,
    }

    impl BenchTrojanPreamble {
        pub fn new(password: &str, host: &str, port: u16) -> Self {
            Self {
                hash: password_hash_hex(password),
                target: ConnectTarget {
                    host: host.into(),
                    port,
                },
            }
        }

        /// The per-profile credential derivation, `hex(SHA224(password))`
        /// ([`password_hash_hex`]): the connector runs it once per node at
        /// profile compile time.
        pub fn password_hash(password: &str) -> [u8; TROJAN_HASH_HEX_LEN] {
            password_hash_hex(password)
        }

        /// The per-dial CONNECT preamble build
        /// ([`encode_client_preamble`]): hash, CRLF, command, SOCKS-encoded
        /// target, CRLF — the bytes the connector writes ahead of the first
        /// payload on every new flow.
        pub fn encode_connect_preamble(&self) -> Vec<u8> {
            encode_client_preamble(&self.hash, CMD_CONNECT, &self.target)
                .expect("bench preamble encodes")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_lowercase_hex_sha224() {
        // The canonical SHA-224 of the empty string, hex-encoded (56 chars).
        assert_eq!(
            &password_hash_hex(""),
            b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        let hash = password_hash_hex("s3cr3t-preshared-key");
        assert_eq!(hash.len(), TROJAN_HASH_LEN);
        assert!(hash
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
    }

    #[test]
    fn preamble_lays_out_hash_command_address_each_crlf_terminated() {
        let hash = password_hash_hex("pw");
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let preamble = encode_client_preamble(&hash, CMD_CONNECT, &target).expect("preamble");

        assert_eq!(&preamble[..TROJAN_HASH_LEN], &hash);
        assert_eq!(&preamble[TROJAN_HASH_LEN..TROJAN_HASH_LEN + 2], &CRLF);
        let request = &preamble[TROJAN_HASH_LEN + 2..];
        assert_eq!(request[0], CMD_CONNECT);
        // ATYP domain, length, "example.com", port 443, then the trailing CRLF.
        assert_eq!(request[1], 0x03);
        assert_eq!(request[2] as usize, "example.com".len());
        assert_eq!(&request[3..3 + 11], b"example.com");
        assert_eq!(&request[3 + 11..3 + 11 + 2], &443_u16.to_be_bytes());
        assert_eq!(&request[3 + 11 + 2..], &CRLF);
    }

    /// One UDP-associate frame round-trips byte-exact, and reading past it hits a
    /// clean end — the receiver's `Ok(None)` at a frame boundary.
    #[tokio::test]
    async fn udp_frame_roundtrips_and_ends_cleanly() {
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let payload = b"trojan-udp-datagram-body";

        let frame = encode_udp_frame(&target, payload).expect("encode");
        let mut cursor = &frame[..];
        let (decoded_target, decoded_payload) = read_udp_frame(&mut cursor)
            .await
            .expect("read")
            .expect("one frame");

        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, payload);
        // The frame was consumed exactly: the next read is a clean end.
        assert!(read_udp_frame(&mut cursor)
            .await
            .expect("clean end")
            .is_none());
    }

    /// A peer that hands over `bytes` and then nothing at all: not EOF,
    /// which a slice gives, but a read that parks.
    struct Stalled {
        bytes: Vec<u8>,
        sent: usize,
    }

    impl AsyncRead for Stalled {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.sent == self.bytes.len() {
                return std::task::Poll::Pending;
            }
            let take = buf.remaining().min(self.bytes.len() - self.sent);
            let from = self.sent;
            buf.put_slice(&self.bytes[from..from + take]);
            self.sent += take;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A frame that starts and stops can be neither resynced nor waited out:
    /// its budget ends it, and with it the face task that was reading it.
    #[tokio::test(start_paused = true)]
    async fn a_started_udp_frame_that_stops_runs_out_of_its_budget() {
        let frame = encode_udp_frame(
            &ConnectTarget {
                host: "127.0.0.1".into(),
                port: 53,
            },
            b"payload",
        )
        .unwrap();
        let mut stalled = Stalled {
            bytes: frame[..3].to_vec(),
            sent: 0,
        };

        let error = read_udp_frame(&mut stalled)
            .await
            .expect_err("a frame left unfinished runs out of its budget");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// A payload longer than one read chunk arrives whole: the chunks are
    /// how much a peer's claim may hold before its bytes are there, not a
    /// bound on the frame.
    #[tokio::test]
    async fn a_udp_payload_longer_than_a_read_chunk_arrives_whole() {
        let target = ConnectTarget {
            host: "198.51.100.7".into(),
            port: 9,
        };
        let payload = vec![b'z'; TROJAN_UDP_READ_CHUNK * 2 + 7];

        let frame = encode_udp_frame(&target, &payload).expect("encode");
        let mut cursor = &frame[..];
        let (decoded_target, decoded_payload) = read_udp_frame(&mut cursor)
            .await
            .expect("read")
            .expect("one frame");

        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, payload);
    }

    /// A read at a closed associate (no bytes) is a clean end, not an error.
    #[tokio::test]
    async fn read_udp_frame_reports_clean_end_on_empty_input() {
        let mut empty: &[u8] = &[];
        assert!(read_udp_frame(&mut empty)
            .await
            .expect("clean end")
            .is_none());
    }

    #[tokio::test]
    async fn udp_frame_keeps_carrier_io_error_kinds_at_every_field_boundary() {
        let frame = encode_udp_frame(
            &ConnectTarget {
                host: "127.0.0.1".into(),
                port: 53,
            },
            b"payload",
        )
        .unwrap();
        for cut in [1, 4, 7, 9, frame.len() - 1] {
            let mut bytes = &frame[..cut];
            assert_eq!(
                read_udp_frame(&mut bytes).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let mut invalid = &[0xff][..];
        assert_eq!(
            read_udp_frame(&mut invalid).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// A zero-length domain in a Trojan request address is rejected at parse
    /// time (through the shared SOCKS parser), not passed through as an empty
    /// host that only fails later at route/dial.
    #[tokio::test]
    async fn read_socks_address_body_rejects_a_zero_length_domain() {
        // The caller already read ATYP=domain (0x03); the body is a length
        // byte of 0 then the port. The reader consumes that bounded remainder,
        // then the shared parser refuses the empty host.
        let mut body: &[u8] = &[0x00, 0x01, 0xbb];
        let error = read_socks_address_body(&mut body, 0x03)
            .await
            .expect_err("a zero-length domain must be rejected");
        assert!(error.to_string().contains("zero length"), "got: {error}");
    }
}
