//! The Shadowsocks AEAD wire codec: the frame format, address vocabulary,
//! and key derivation both halves of the protocol share, written once. The
//! connector
//! (client half) and acceptor (server half) differ only in which side runs
//! the request handshake; the steady-state duplex — [`ShadowsocksStream`] —
//! is identical for both, because a Shadowsocks session is symmetric once the
//! salts are exchanged.
//!
//! This module owns classic AEAD v1 framing. SS2022 has its own handshake
//! and session codec in `aead2022`; the two wire formats are never mixed.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use shadowsocks_crypto::{
    utils::random_iv_or_salt,
    v1::{openssl_bytes_to_key, Cipher},
    CipherKind,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::target::{parse_socks_address, ConnectTarget};

/// Plaintext cap on one AEAD TCP chunk (Shadowsocks spec: the 2-byte length
/// field is masked to 0x3fff so a chunk carries at most this many bytes).
pub(crate) const SHADOWSOCKS_MAX_TCP_CHUNK: usize = 0x3fff;

/// Parses a Clash cipher name (`aes-128-gcm`, `chacha20-ietf-poly1305`, …)
/// into the AEAD method both halves key against.
pub(crate) fn parse_cipher(name: &str) -> Result<CipherKind, String> {
    match name {
        "aes-128-gcm"
        | "aes-256-gcm"
        | "chacha20-ietf-poly1305"
        | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305" => name
            .parse::<CipherKind>()
            .map_err(|_| format!("unsupported Shadowsocks cipher '{name}'")),
        _ => Err(format!("unsupported Shadowsocks cipher '{name}'")),
    }
}

/// Derives the master key from the password with EVP_BytesToKey, as the
/// Shadowsocks AEAD v1 key schedule specifies.
pub(crate) fn shadowsocks_key(method: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0_u8; method.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

/// A fresh random per-direction salt of the method's salt length.
pub(crate) fn random_salt(method: CipherKind) -> Vec<u8> {
    let mut salt = vec![0_u8; method.salt_len()];
    random_iv_or_salt(&mut salt);
    salt
}

/// Seals one plaintext chunk into the AEAD TCP frame — a sealed 2-byte
/// length record followed by the sealed payload record — appending both to
/// `out` and advancing the cipher two nonces. This is the one place the
/// frame layout is written; both the handshake and the steady-state stream
/// call it.
fn seal_chunk(cipher: &mut Cipher, tag_len: usize, payload: &[u8], out: &mut Vec<u8>) {
    seal_chunk_from(
        cipher,
        tag_len,
        &[IoSlice::new(payload)],
        payload.len(),
        out,
    );
}

/// [`seal_chunk`] over the first `len` bytes of `bufs`. Each record is
/// sealed in place where it lands in `out`, so the plaintext is copied once
/// and a reused `out` allocates nothing.
fn seal_chunk_from(
    cipher: &mut Cipher,
    tag_len: usize,
    bufs: &[IoSlice<'_>],
    len: usize,
    out: &mut Vec<u8>,
) {
    debug_assert!(len <= SHADOWSOCKS_MAX_TCP_CHUNK);
    out.reserve(2 + tag_len + len + tag_len);
    let length_record = out.len();
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.resize(length_record + 2 + tag_len, 0);
    cipher.encrypt_packet(&mut out[length_record..]);

    let payload_record = out.len();
    let mut left = len;
    for buf in bufs {
        let take = buf.len().min(left);
        out.extend_from_slice(&buf[..take]);
        left -= take;
        if left == 0 {
            break;
        }
    }
    out.resize(payload_record + len + tag_len, 0);
    cipher.encrypt_packet(&mut out[payload_record..]);
}

/// Seals `plaintext` (any length, chunked to the frame cap) into `transport`.
/// The handshake path uses it to send the request header (and folded early
/// data); the steady-state relay uses [`ShadowsocksStream`]'s poll writer,
/// which shares [`seal_chunk`].
pub(crate) async fn write_sealed<W: AsyncWrite + Unpin + ?Sized>(
    transport: &mut W,
    cipher: &mut Cipher,
    tag_len: usize,
    plaintext: &[u8],
) -> Result<(), String> {
    let mut out = Vec::new();
    for chunk in plaintext.chunks(SHADOWSOCKS_MAX_TCP_CHUNK) {
        seal_chunk(cipher, tag_len, chunk, &mut out);
    }
    if out.is_empty() {
        return Ok(());
    }
    transport
        .write_all(&out)
        .await
        .map_err(|error| error.to_string())
}

/// Runs the client handshake on `transport` and returns the plaintext duplex:
/// send a fresh salt in the clear, then the sealed `request` (the SOCKS
/// target header with any folded early data), and hand back the stream whose
/// encryptor is advanced past it. Keeps `Cipher` construction inside the
/// codec so the connector speaks only in plaintext bytes.
pub(crate) async fn connect_client_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut transport: S,
    method: CipherKind,
    key: &[u8],
    request: &[u8],
) -> Result<ShadowsocksStream<S>, String> {
    let salt = random_salt(method);
    let mut encryptor = Cipher::new(method, key, &salt);
    transport
        .write_all(&salt)
        .await
        .map_err(|error| error.to_string())?;
    write_sealed(&mut transport, &mut encryptor, method.tag_len(), request).await?;
    // A carrier may buffer its writes, so the request reaches the node before
    // anything waits for its answer (see the Core document's outbound
    // handshakes); a bare socket flushes to nothing.
    transport.flush().await.map_err(|error| error.to_string())?;
    Ok(ShadowsocksStream::client(
        transport,
        method,
        key.to_vec(),
        encryptor,
    ))
}

// ---- Server-handshake primitives. The acceptor
// authenticates a peer by trial-decrypting the request's first length record
// against each user key: only the right key produces a valid AEAD tag, which
// both proves the user and yields the decryptor for the rest of the stream.
// These keep `Cipher` inside the codec so the acceptor speaks in keys and
// plaintext, never crypto state.

/// Tries to open a sealed length record with `key`: `Some((cipher, len))`
/// when the AEAD tag is valid (the peer holds this key), where `cipher` is
/// advanced past the record and `len` is the announced payload length; `None`
/// when the tag fails (wrong key). A valid tag with a nonsense length is still
/// `Some` — authentication succeeded, so the caller reports a protocol error,
/// not an auth failure.
pub(crate) fn try_open_length(
    method: CipherKind,
    key: &[u8],
    salt: &[u8],
    length_record: &[u8],
) -> Option<(Cipher, usize)> {
    let mut cipher = Cipher::new(method, key, salt);
    let mut probe = length_record.to_vec();
    if !cipher.decrypt_packet(&mut probe) {
        return None;
    }
    let payload_len = u16::from_be_bytes([probe[0], probe[1]]) as usize;
    Some((cipher, payload_len))
}

/// Opens a sealed payload record in place with the (already-advanced)
/// `cipher`, returning the plaintext with the tag stripped.
pub(crate) fn open_payload(
    cipher: &mut Cipher,
    tag_len: usize,
    mut record: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if !cipher.decrypt_packet(&mut record) {
        return Err("Shadowsocks request payload auth failed".into());
    }
    record.truncate(record.len() - tag_len);
    Ok(record)
}

/// Builds an encryptor keyed against `salt` — the acceptor's downlink cipher,
/// keyed to the server salt it just sent.
pub(crate) fn new_encryptor(method: CipherKind, key: &[u8], salt: &[u8]) -> Cipher {
    Cipher::new(method, key, salt)
}

// ---- UDP packet codec: each Shadowsocks UDP packet is
// independently keyed — `salt || sealed(socks_address || payload)` — so both
// halves seal and open whole datagrams rather than a stream of chunks.

/// A UDP packet under construction: the fresh random salt, with room for
/// `capacity` more bytes. The plaintext, a SOCKS address and the payload,
/// follows it, and [`seal_udp_in_place`] seals it.
pub(crate) fn begin_udp_packet(method: CipherKind, capacity: usize) -> Vec<u8> {
    let mut packet = Vec::with_capacity(method.salt_len() + capacity + method.tag_len());
    packet.resize(method.salt_len(), 0);
    random_iv_or_salt(&mut packet);
    packet
}

/// Seals the plaintext after the salt of a packet from [`begin_udp_packet`]
/// in place, appending the tag.
pub(crate) fn seal_udp_in_place(method: CipherKind, key: &[u8], packet: &mut Vec<u8>) {
    packet.resize(packet.len() + method.tag_len(), 0);
    let (salt, sealed) = packet.split_at_mut(method.salt_len());
    Cipher::new(method, key, salt).encrypt_packet(sealed);
}

/// Seals one UDP payload for `target` into a Shadowsocks UDP packet.
pub(crate) fn seal_udp_packet(
    method: CipherKind,
    key: &[u8],
    target: &ConnectTarget,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let address = target.socks_address()?;
    let mut packet = begin_udp_packet(method, address.len() + payload.len());
    packet.extend_from_slice(&address);
    packet.extend_from_slice(payload);
    seal_udp_in_place(method, key, &mut packet);
    Ok(packet)
}

/// Opens a Shadowsocks UDP packet in place: where in `packet` its plaintext,
/// the SOCKS address of the origin and then the payload, now lies.
pub(crate) fn open_udp_in_place(
    method: CipherKind,
    key: &[u8],
    packet: &mut [u8],
) -> Result<std::ops::Range<usize>, String> {
    let salt_len = method.salt_len();
    let tag_len = method.tag_len();
    if packet.len() < salt_len + tag_len {
        return Err("Shadowsocks UDP packet is too short".into());
    }
    let end = packet.len() - tag_len;
    let (salt, sealed) = packet.split_at_mut(salt_len);
    if !Cipher::new(method, key, salt).decrypt_packet(sealed) {
        return Err("failed to decrypt Shadowsocks UDP packet".into());
    }
    Ok(salt_len..end)
}

/// Opens a Shadowsocks UDP packet, returning the origin target it names and
/// the payload after it.
pub(crate) fn open_udp_packet(
    method: CipherKind,
    key: &[u8],
    packet: &[u8],
) -> Result<(ConnectTarget, Vec<u8>), String> {
    let mut packet = packet.to_vec();
    let plaintext = open_udp_in_place(method, key, &mut packet)?;
    let plaintext = &packet[plaintext];
    let (target, address_len) = parse_socks_address(plaintext)?;
    Ok((target, plaintext[address_len..].to_vec()))
}

// ---- The steady-state duplex both halves relay through.

/// The write (encrypt) half state: seals plaintext into AEAD chunks and
/// buffers the ciphertext across partial transport writes.
struct EncryptState {
    cipher: Cipher,
    tag_len: usize,
    /// Sealed bytes not yet flushed to the transport. Bounded to one chunk:
    /// [`Self::poll_write`] refuses new plaintext until this drains, which is
    /// also how backpressure reaches the peer. A drained one keeps its
    /// capacity: `seal_chunk_from` appends into it, so that is one allocation
    /// saved per chunk sent against a chunk's worth held per idle connection.
    pending: Vec<u8>,
    pending_pos: usize,
}

impl EncryptState {
    fn poll_flush_pending<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        transport: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut *transport).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => self.pending_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Seals up to one chunk of `bufs`, however many slices it spans, so the
    /// relay hands over what it gathered without merging it first.
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        transport: &mut W,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // Drain the previous chunk before sealing another: a full transport
        // stops us reading more from the relay's source (backpressure).
        match self.poll_flush_pending(transport, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let take = bufs
            .iter()
            .map(|buf| buf.len())
            .sum::<usize>()
            .min(SHADOWSOCKS_MAX_TCP_CHUNK);
        if take == 0 {
            return Poll::Ready(Ok(0));
        }
        seal_chunk_from(
            &mut self.cipher,
            self.tag_len,
            bufs,
            take,
            &mut self.pending,
        );
        // Best-effort flush; whatever the transport could not take stays
        // buffered and drains via a later poll_write/poll_flush.
        if let Poll::Ready(Err(error)) = self.poll_flush_pending(transport, cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        transport: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_flush_pending(transport, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(transport).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        transport: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Shadowsocks AEAD has no plaintext close frame: flush the last chunk
        // and let the transport FIN mark the end.
        match self.poll_flush_pending(transport, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(transport).poll_shutdown(cx)
    }
}

/// Which record the read half is currently assembling.
enum ReadStage {
    /// Reading the peer salt to build the decryptor (client half only; the
    /// acceptor starts past this with the decryptor already keyed).
    Salt,
    /// Reading a sealed 2-byte length record.
    Length,
    /// Reading a sealed payload record of `payload_len + tag_len` bytes.
    Payload,
}

/// The read (decrypt) half state: assembles one AEAD record at a time into
/// `scratch`, opens it in place, and delivers the plaintext.
struct DecryptState {
    method: CipherKind,
    /// Master key, used only to build the decryptor when the salt arrives
    /// (client half); unused once `decryptor` is set.
    key: Vec<u8>,
    tag_len: usize,
    decryptor: Option<Cipher>,
    stage: ReadStage,
    /// Bytes of the current record read so far.
    scratch: Vec<u8>,
    filled: usize,
    payload_len: usize,
    /// Decrypted plaintext waiting to be handed to the reader.
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    eof: bool,
}

impl DecryptState {
    fn begin_length(&mut self) {
        self.stage = ReadStage::Length;
        self.scratch = vec![0_u8; 2 + self.tag_len];
        self.filled = 0;
    }

    fn begin_payload(&mut self, payload_len: usize) {
        self.stage = ReadStage::Payload;
        self.payload_len = payload_len;
        self.scratch = vec![0_u8; payload_len + self.tag_len];
        self.filled = 0;
    }

    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        transport: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.plaintext_pos < self.plaintext.len() {
                let available = self.plaintext.len() - self.plaintext_pos;
                let take = available.min(buf.remaining());
                buf.put_slice(&self.plaintext[self.plaintext_pos..self.plaintext_pos + take]);
                self.plaintext_pos += take;
                if self.plaintext_pos == self.plaintext.len() {
                    // Delivered. This storage is the scratch `begin_payload`
                    // allocated for the record and nothing reuses it -- the
                    // next record brings its own -- so keeping it is a whole
                    // chunk held per idle connection for nothing.
                    self.plaintext = Vec::new();
                    self.plaintext_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                // Clean end: deliver zero bytes.
                return Poll::Ready(Ok(()));
            }

            // Fill the current record from the transport.
            while self.filled < self.scratch.len() {
                let read = {
                    let mut record = ReadBuf::new(&mut self.scratch[self.filled..]);
                    match Pin::new(&mut *transport).poll_read(cx, &mut record) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    record.filled().len()
                };
                if read == 0 {
                    if self.filled == 0 && matches!(self.stage, ReadStage::Salt | ReadStage::Length)
                    {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Shadowsocks stream closed mid-record",
                    )));
                }
                self.filled += read;
            }

            match self.stage {
                ReadStage::Salt => {
                    self.decryptor = Some(Cipher::new(self.method, &self.key, &self.scratch));
                    self.begin_length();
                }
                ReadStage::Length => {
                    let mut record = std::mem::take(&mut self.scratch);
                    let decryptor = self
                        .decryptor
                        .as_mut()
                        .expect("decryptor keyed before length record");
                    if !decryptor.decrypt_packet(&mut record) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks chunk length auth failed",
                        )));
                    }
                    let payload_len = u16::from_be_bytes([record[0], record[1]]) as usize;
                    if payload_len == 0 || payload_len > SHADOWSOCKS_MAX_TCP_CHUNK {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks chunk length out of range",
                        )));
                    }
                    self.begin_payload(payload_len);
                }
                ReadStage::Payload => {
                    let mut record = std::mem::take(&mut self.scratch);
                    let decryptor = self
                        .decryptor
                        .as_mut()
                        .expect("decryptor keyed before payload record");
                    if !decryptor.decrypt_packet(&mut record) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks chunk payload auth failed",
                        )));
                    }
                    record.truncate(self.payload_len);
                    self.plaintext = record;
                    self.plaintext_pos = 0;
                    self.begin_length();
                }
            }
        }
    }
}

/// A Shadowsocks AEAD session as a plaintext duplex stream: reads decrypt the
/// peer's chunks, writes seal into chunks, and the relay stage
/// (`copy_bidirectional`) drives it exactly like a bare socket. Both halves
/// build one after their handshake — the connector after writing its request,
/// the acceptor after authenticating it — so the frame logic lives here once.
pub(crate) struct ShadowsocksStream<S> {
    transport: S,
    encrypt: EncryptState,
    decrypt: DecryptState,
}

impl<S> ShadowsocksStream<S> {
    /// The client half's stream: its request (salt + sealed header) is already
    /// on the wire, so `encryptor` is advanced past it; the read half learns
    /// the server salt lazily on the first downlink read.
    pub(crate) fn client(
        transport: S,
        method: CipherKind,
        key: Vec<u8>,
        encryptor: Cipher,
    ) -> Self {
        let tag_len = method.tag_len();
        Self {
            transport,
            encrypt: EncryptState {
                cipher: encryptor,
                tag_len,
                pending: Vec::new(),
                pending_pos: 0,
            },
            decrypt: DecryptState {
                method,
                key,
                tag_len,
                decryptor: None,
                stage: ReadStage::Salt,
                scratch: vec![0_u8; method.salt_len()],
                filled: 0,
                payload_len: 0,
                plaintext: Vec::new(),
                plaintext_pos: 0,
                eof: false,
            },
        }
    }

    /// The server half's stream: the acceptor already read the client salt and
    /// the request's first chunk, so `decryptor` is keyed and advanced and
    /// `leftover` is the relay bytes that trailed the request address;
    /// `encryptor` is freshly keyed against the server salt the acceptor sent.
    pub(crate) fn server(
        transport: S,
        method: CipherKind,
        decryptor: Cipher,
        leftover: Vec<u8>,
        encryptor: Cipher,
    ) -> Self {
        let tag_len = method.tag_len();
        Self {
            transport,
            encrypt: EncryptState {
                cipher: encryptor,
                tag_len,
                pending: Vec::new(),
                pending_pos: 0,
            },
            decrypt: DecryptState {
                method,
                key: Vec::new(),
                tag_len,
                decryptor: Some(decryptor),
                stage: ReadStage::Length,
                scratch: vec![0_u8; 2 + tag_len],
                filled: 0,
                payload_len: 0,
                plaintext: leftover,
                plaintext_pos: 0,
                eof: false,
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.decrypt.poll_read(&mut this.transport, cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.encrypt
            .poll_write(&mut this.transport, cx, &[IoSlice::new(buf)])
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.encrypt.poll_write(&mut this.transport, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.encrypt.poll_flush(&mut this.transport, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.encrypt.poll_shutdown(&mut this.transport, cx)
    }
}

/// Bench-only handles over the Shadowsocks AEAD codec (`--features
/// bench-internals`). The `outbound_hot_paths` criterion bench measures the
/// production crypto sequences without sockets: the connector's per-datagram
/// UDP seal/open — whose per-salt subkey derivation + cipher setup is the
/// protocol-mandated floor — and the established stream's per-chunk seal/open.
#[cfg(feature = "bench-internals")]
pub mod bench {
    use shadowsocks_crypto::{v1::Cipher, CipherKind};

    use super::{
        open_udp_packet, parse_cipher, random_salt, seal_chunk, seal_udp_packet, shadowsocks_key,
    };
    use crate::target::ConnectTarget;

    /// Plaintext cap on one AEAD TCP chunk, re-exposed so the bench can seal
    /// full-size relay chunks.
    pub const SHADOWSOCKS_MAX_TCP_CHUNK: usize = super::SHADOWSOCKS_MAX_TCP_CHUNK;

    /// The connector's per-node UDP crypto state: the cipher method and the
    /// master key it derives once at profile compile time. Each datagram is
    /// independently keyed on the wire (`salt || AEAD(...)`), so seal and
    /// open iterate freely with no shared state between iterations.
    pub struct BenchShadowsocksUdpCodec {
        method: CipherKind,
        key: Vec<u8>,
        target: ConnectTarget,
    }

    impl BenchShadowsocksUdpCodec {
        pub fn new(cipher: &str, password: &str) -> Self {
            let method = parse_cipher(cipher).expect("bench cipher parses");
            let key = shadowsocks_key(method, password);
            Self {
                method,
                key,
                target: ConnectTarget {
                    host: "203.0.113.9".into(),
                    port: 4_500,
                },
            }
        }

        /// Master-key derivation alone (EVP_BytesToKey): once per profile in
        /// production, benched to bound what deriving it per datagram would
        /// cost (the decision-2 hypothesis this bench falsified).
        pub fn master_key(&self, password: &str) -> Vec<u8> {
            shadowsocks_key(self.method, password)
        }

        /// The uplink per-datagram seal ([`seal_udp_packet`]): fresh salt,
        /// per-salt subkey derivation + cipher setup, in-place AEAD seal.
        pub fn seal(&self, payload: &[u8]) -> Vec<u8> {
            seal_udp_packet(self.method, &self.key, &self.target, payload)
                .expect("bench seal succeeds")
        }

        /// The downlink per-datagram open ([`open_udp_packet`]): salt split,
        /// per-salt subkey derivation + cipher setup, in-place AEAD open,
        /// SOCKS address parse. Returns the payload the relay would forward.
        pub fn open(&self, packet: &[u8]) -> Vec<u8> {
            let (_origin, payload) =
                open_udp_packet(self.method, &self.key, packet).expect("bench open succeeds");
            payload
        }
    }

    /// One direction of an established Shadowsocks TCP session, both ends in
    /// one handle: the encryptor seals relay chunks exactly as
    /// `ShadowsocksStream`'s write half does, and the paired decryptor opens
    /// them as the peer's read half does, the two advancing in nonce
    /// lockstep. Seal-only advances just the encryptor, so a measurement
    /// mixes seal-only and roundtrip on separate instances.
    pub struct BenchShadowsocksStreamCodec {
        tag_len: usize,
        encryptor: Cipher,
        decryptor: Cipher,
        /// Reused like `EncryptState::pending`: cleared per chunk, not
        /// reallocated.
        sealed: Vec<u8>,
    }

    impl BenchShadowsocksStreamCodec {
        pub fn new(cipher: &str, password: &str) -> Self {
            let method = parse_cipher(cipher).expect("bench cipher parses");
            let key = shadowsocks_key(method, password);
            let salt = random_salt(method);
            Self {
                tag_len: method.tag_len(),
                encryptor: Cipher::new(method, &key, &salt),
                decryptor: Cipher::new(method, &key, &salt),
                sealed: Vec::new(),
            }
        }

        /// Seals one relay chunk (sealed length record + sealed payload
        /// record, [`seal_chunk`]) into the reused buffer, returning the
        /// ciphertext length. Advances the encryptor two nonces, like one
        /// `poll_write` of the stream.
        pub fn seal_chunk(&mut self, payload: &[u8]) -> usize {
            self.sealed.clear();
            seal_chunk(&mut self.encryptor, self.tag_len, payload, &mut self.sealed);
            self.sealed.len()
        }

        /// One steady-state chunk roundtrip: seal, then open both records
        /// the way the peer's `DecryptState` does (fresh per-record scratch,
        /// in-place decrypt). Returns the recovered plaintext length.
        pub fn roundtrip_chunk(&mut self, payload: &[u8]) -> usize {
            self.seal_chunk(payload);
            let record_split = 2 + self.tag_len;
            let mut length_record = self.sealed[..record_split].to_vec();
            assert!(
                self.decryptor.decrypt_packet(&mut length_record),
                "bench length record opens"
            );
            let payload_len = u16::from_be_bytes([length_record[0], length_record[1]]) as usize;
            let mut payload_record = self.sealed[record_split..].to_vec();
            assert!(
                self.decryptor.decrypt_packet(&mut payload_record),
                "bench payload record opens"
            );
            payload_record.truncate(payload_len);
            payload_record.len()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method() -> CipherKind {
        parse_cipher("aes-256-gcm").expect("known cipher")
    }

    #[test]
    fn udp_packet_seals_and_opens_byte_exact() {
        let method = method();
        let key = shadowsocks_key(method, "pre-shared");
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let payload = b"udp-body-that-round-trips";

        let packet = seal_udp_packet(method, &key, &target, payload).expect("seal");
        let (opened_target, opened_payload) = open_udp_packet(method, &key, &packet).expect("open");

        assert_eq!(opened_target, target);
        assert_eq!(opened_payload, payload);
    }

    #[test]
    fn udp_packet_open_rejects_a_wrong_key() {
        let method = method();
        let target = ConnectTarget {
            host: "10.0.0.1".into(),
            port: 53,
        };
        let sealed = seal_udp_packet(method, &shadowsocks_key(method, "right"), &target, b"q")
            .expect("seal");

        assert!(open_udp_packet(method, &shadowsocks_key(method, "wrong"), &sealed).is_err());
    }

    /// A vectored write seals one chunk across the slices it is given, and
    /// the frames on the wire open to exactly the bytes written.
    #[tokio::test]
    async fn vectored_writes_seal_whole_chunks_across_slices() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let method = method();
        let key = shadowsocks_key(method, "pre-shared");
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let mut stream = connect_client_stream(client, method, &key, b"header")
            .await
            .expect("client handshake");
        assert!(stream.is_write_vectored());
        let parts = [vec![1_u8; 10_000], vec![2_u8; 10_000], vec![3_u8; 5]];
        let slices = parts
            .iter()
            .map(|part| IoSlice::new(part))
            .collect::<Vec<_>>();
        let first = stream
            .write_vectored(&slices)
            .await
            .expect("vectored write");
        assert_eq!(
            first, SHADOWSOCKS_MAX_TCP_CHUNK,
            "one whole chunk across slices"
        );
        let written = parts.concat();
        stream.write_all(&written[first..]).await.expect("the rest");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.expect("read the wire");
        let (salt, mut frames) = wire.split_at(method.salt_len());
        let mut decryptor = Cipher::new(method, &key, salt);
        let tag = method.tag_len();
        let mut opened = Vec::new();
        while !frames.is_empty() {
            let mut length = frames[..2 + tag].to_vec();
            assert!(decryptor.decrypt_packet(&mut length), "length record opens");
            let len = usize::from(u16::from_be_bytes([length[0], length[1]]));
            let mut payload = frames[2 + tag..2 + tag + len + tag].to_vec();
            assert!(
                decryptor.decrypt_packet(&mut payload),
                "payload record opens"
            );
            opened.extend_from_slice(&payload[..len]);
            frames = &frames[2 + tag + len + tag..];
        }
        assert_eq!(&opened[..6], b"header");
        assert_eq!(&opened[6..], &written[..]);
    }

    /// A record the reader has taken is storage nothing reuses, so it goes
    /// with the record rather than waiting out the connection's idle hours.
    #[tokio::test]
    async fn a_delivered_record_leaves_no_storage_behind() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let method = method();
        let key = shadowsocks_key(method, "pre-shared");
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let mut stream = connect_client_stream(client, method, &key, b"header")
            .await
            .expect("client handshake");

        // The downlink's salt, then one whole chunk sealed under it.
        let salt = random_salt(method);
        let mut cipher = Cipher::new(method, &key, &salt);
        let payload = vec![7_u8; SHADOWSOCKS_MAX_TCP_CHUNK];
        let mut wire = salt;
        seal_chunk_from(
            &mut cipher,
            method.tag_len(),
            &[IoSlice::new(&payload)],
            payload.len(),
            &mut wire,
        );
        server.write_all(&wire).await.expect("write the downlink");

        let mut taken = vec![0_u8; payload.len()];
        stream.read_exact(&mut taken).await.expect("read the chunk");

        assert_eq!(taken, payload);
        assert_eq!(
            stream.decrypt.plaintext.capacity(),
            0,
            "the record's storage went with the record"
        );
    }

    #[test]
    fn try_open_length_authenticates_only_the_matching_key() {
        let method = method();
        let right = shadowsocks_key(method, "right");
        let wrong = shadowsocks_key(method, "wrong");
        let salt = random_salt(method);
        // Seal a length record for a 7-byte payload under the right key.
        let mut encryptor = Cipher::new(method, &right, &salt);
        let mut length_record = vec![0_u8; 2 + method.tag_len()];
        length_record[..2].copy_from_slice(&7_u16.to_be_bytes());
        encryptor.encrypt_packet(&mut length_record);

        assert!(try_open_length(method, &wrong, &salt, &length_record).is_none());
        let (_cipher, payload_len) =
            try_open_length(method, &right, &salt, &length_record).expect("right key opens");
        assert_eq!(payload_len, 7);
    }
    /// A carrier that buffers its writes until flushed, as a TLS or QUIC hop
    /// does; the bytes a `write_all` gave it are not on the wire yet.
    #[derive(Default)]
    struct Wire {
        wire: Vec<u8>,
        held: Vec<u8>,
    }

    struct Buffering(std::sync::Arc<std::sync::Mutex<Wire>>);

    impl tokio::io::AsyncWrite for Buffering {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().expect("wire").held.extend_from_slice(buffer);
            std::task::Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut state = self.0.lock().expect("wire");
            let held = std::mem::take(&mut state.held);
            state.wire.extend_from_slice(&held);
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncRead for Buffering {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// The request reaches the node before anything waits for its answer: a
    /// carrier that buffers would otherwise hold the tail of the handshake
    /// while the node, and then the first-byte budget, waited.
    #[tokio::test]
    async fn the_client_handshake_reaches_a_buffering_carrier_s_wire() {
        let method = method();
        let key = shadowsocks_key(method, "pre-shared");
        let wire = std::sync::Arc::new(std::sync::Mutex::new(Wire::default()));
        let _stream = connect_client_stream(
            Buffering(std::sync::Arc::clone(&wire)),
            method,
            &key,
            b"request header",
        )
        .await
        .expect("the handshake completes");
        let state = wire.lock().expect("wire");
        assert!(
            state.held.is_empty(),
            "nothing of the handshake is still held"
        );
        assert!(
            state.wire.len() > b"request header".len(),
            "the salt and the sealed request are on the wire"
        );
    }
}
