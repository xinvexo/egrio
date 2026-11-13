//! The control channel's pre-shared wrapping (tls-crypt) and the replay
//! windows both channels check packet ids against.
//!
//! tls-crypt (OpenVPN `tls_crypt.c`, the wire protocol draft's "Encrypting
//! control channel packets"): every control packet past its opcode and
//! session id is encrypted with AES-256-CTR and authenticated with
//! HMAC-SHA256 under a 2048-bit static key, the tag doubling as the IV:
//!
//! ```text
//! op|key_id  session_id(8)  packet_id(4) time(4)  tag(32)  AES-256-CTR(Ke, tag[..16], plaintext)
//! tag = HMAC-SHA256(Ka, op|key_id || session_id || packet_id || time || plaintext)
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, UnboundCipherKey, AES_256,
};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

/// The bytes ahead of a control packet's wrapped part: opcode and key id,
/// then the sender's session id.
pub(super) const HEADER_LEN: usize = 1 + 8;
const PACKET_ID_LEN: usize = 8;
const TAG_LEN: usize = 32;
/// What tls-crypt adds to a control packet's plaintext.
pub(super) const OVERHEAD: usize = PACKET_ID_LEN + TAG_LEN;

/// An OpenVPN static key (`-----BEGIN OpenVPN Static key V1-----`): two
/// directions of a 64-byte cipher key and a 64-byte HMAC key.
#[derive(Clone)]
pub(crate) struct StaticKey([u8; 256]);

impl StaticKey {
    /// Parses the hex between the header and footer lines; anything outside
    /// them is ignored, as the format asks.
    pub(super) fn parse(text: &str) -> Result<Self, String> {
        const HEAD: &str = "-----BEGIN OpenVPN Static key V1-----";
        const FOOT: &str = "-----END OpenVPN Static key V1-----";
        let start = text
            .find(HEAD)
            .ok_or("the static key has no OpenVPN Static key V1 header")?
            + HEAD.len();
        let end = start
            + text[start..]
                .find(FOOT)
                .ok_or("the static key has no footer")?;
        let digits: Vec<u8> = text[start..end]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if digits.len() != 512 {
            return Err(format!(
                "the static key holds {} bytes, not 256",
                digits.len() / 2
            ));
        }
        let mut key = [0_u8; 256];
        for (byte, pair) in key.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| "the static key is not hex")?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| "the static key is not hex")?;
        }
        Ok(Self(key))
    }

    /// Direction `index`'s cipher key, its first `len` bytes.
    fn cipher(&self, index: usize, len: usize) -> &[u8] {
        &self.0[index * 128..index * 128 + len]
    }

    /// Direction `index`'s HMAC key, its first `len` bytes.
    fn hmac(&self, index: usize, len: usize) -> &[u8] {
        &self.0[index * 128 + 64..index * 128 + 64 + len]
    }
}

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StaticKey(..)")
    }
}

/// One side's tls-crypt: the client sends with the key's second direction and
/// reads with its first (`tls_crypt_init_key`: the server's direction is
/// "normal", the client's "inverse").
pub(super) struct TlsCrypt {
    encrypt: EncryptingKey,
    sign: hmac::Key,
    decrypt: DecryptingKey,
    verify: hmac::Key,
    next_id: u32,
    time: u32,
    replay: ReplayWindow,
}

impl TlsCrypt {
    pub(super) fn client(key: &StaticKey) -> Self {
        Self::directed(key, 1, 0)
    }

    /// The server's side, for the tests' server.
    #[cfg(test)]
    pub(super) fn server(key: &StaticKey) -> Self {
        Self::directed(key, 0, 1)
    }

    fn directed(key: &StaticKey, out: usize, inbound: usize) -> Self {
        let cipher = |index| {
            UnboundCipherKey::new(&AES_256, key.cipher(index, 32)).expect("a 32-byte AES-256 key")
        };
        Self {
            encrypt: EncryptingKey::ctr(cipher(out)).expect("AES-256-CTR"),
            sign: hmac::Key::new(hmac::HMAC_SHA256, key.hmac(out, 32)),
            decrypt: DecryptingKey::ctr(cipher(inbound)).expect("AES-256-CTR"),
            verify: hmac::Key::new(hmac::HMAC_SHA256, key.hmac(inbound, 32)),
            next_id: 1,
            time: unix_seconds(),
            replay: ReplayWindow::default(),
        }
    }

    /// Wraps `plaintext` behind `header` (opcode and session id) into a wire
    /// packet. Each call takes a fresh packet id, retransmissions included.
    pub(super) fn wrap(&mut self, header: &[u8; HEADER_LEN], plaintext: &[u8]) -> Vec<u8> {
        if self.next_id == u32::MAX {
            // The id would wrap: a new time starts a new series.
            self.time = unix_seconds().max(self.time + 1);
            self.next_id = 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut packet = Vec::with_capacity(HEADER_LEN + OVERHEAD + plaintext.len());
        packet.extend_from_slice(header);
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&self.time.to_be_bytes());
        let mut mac = hmac::Context::with_key(&self.sign);
        mac.update(&packet);
        mac.update(plaintext);
        let tag = mac.sign();
        packet.extend_from_slice(tag.as_ref());
        let start = packet.len();
        packet.extend_from_slice(plaintext);
        let iv: [u8; 16] = tag.as_ref()[..16].try_into().expect("a 32-byte tag");
        self.encrypt
            .less_safe_encrypt(
                &mut packet[start..],
                EncryptionContext::Iv128(FixedLength::from(iv)),
            )
            .expect("CTR encrypts any length");
        packet
    }

    /// The plaintext of a wire packet, if it authenticates and is no replay.
    pub(super) fn unwrap(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let tag_at = HEADER_LEN + PACKET_ID_LEN;
        let body_at = tag_at + TAG_LEN;
        if packet.len() < body_at {
            return None;
        }
        let tag = &packet[tag_at..body_at];
        let mut plaintext = packet[body_at..].to_vec();
        let iv: [u8; 16] = tag[..16].try_into().expect("a 32-byte tag");
        self.decrypt
            .decrypt(
                &mut plaintext,
                DecryptionContext::Iv128(FixedLength::from(iv)),
            )
            .ok()?;
        let mut mac = hmac::Context::with_key(&self.verify);
        mac.update(&packet[..tag_at]);
        mac.update(&plaintext);
        verify_slices_are_equal(mac.sign().as_ref(), tag).ok()?;
        let id = u32::from_be_bytes(packet[HEADER_LEN..HEADER_LEN + 4].try_into().ok()?);
        let time = u32::from_be_bytes(packet[HEADER_LEN + 4..tag_at].try_into().ok()?);
        self.replay.accept(time, id).then_some(plaintext)
    }
}

fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |since| since.as_secs() as u32)
}

/// A packet-id replay window (OpenVPN `packet_id_test`): ids newer than any
/// seen are taken, older ones only within the window and once. The long form
/// pairs the id with a time, a later time starting a new series and an
/// earlier one refused; the data channel's short form keeps the time at 0.
#[derive(Debug, Default)]
pub(super) struct ReplayWindow {
    time: u32,
    highest: u32,
    /// Bit `n` set: id `highest - n` was seen.
    seen: u64,
}

impl ReplayWindow {
    /// Records the id and whether it was new. Id 0 is never valid.
    pub(super) fn accept(&mut self, time: u32, id: u32) -> bool {
        if id == 0 || time < self.time {
            return false;
        }
        if time > self.time {
            self.time = time;
            self.highest = id;
            self.seen = 1;
            return true;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = id;
            return true;
        }
        let back = self.highest - id;
        if back >= 64 || self.seen & (1 << back) != 0 {
            return false;
        }
        self.seen |= 1 << back;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StaticKey {
        let mut text =
            String::from("# 2048 bit OpenVPN static key\n-----BEGIN OpenVPN Static key V1-----\n");
        for line in 0..16 {
            for byte in 0..16 {
                text.push_str(&format!("{:02x}", line * 16 + byte));
            }
            text.push('\n');
        }
        text.push_str("-----END OpenVPN Static key V1-----\n");
        StaticKey::parse(&text).expect("a valid key")
    }

    #[test]
    fn a_static_key_reads_its_hex_between_the_markers() {
        let key = key();
        assert_eq!(key.cipher(0, 4), [0, 1, 2, 3]);
        assert_eq!(key.hmac(1, 2), [192, 193]);
        assert!(StaticKey::parse(
            "-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----"
        )
        .is_err());
    }

    #[test]
    fn wrapped_packets_open_on_the_other_side_once() {
        let key = key();
        let mut client = TlsCrypt::client(&key);
        let mut server = TlsCrypt::server(&key);
        let header = [0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let packet = client.wrap(&header, b"control plaintext");
        assert_eq!(&packet[..HEADER_LEN], header);
        assert_eq!(packet.len(), HEADER_LEN + OVERHEAD + 17);
        assert_ne!(&packet[HEADER_LEN + OVERHEAD..], b"control plaintext");
        assert_eq!(
            server.unwrap(&packet).as_deref(),
            Some(&b"control plaintext"[..])
        );
        // A replay, and a packet the client cannot open: its own direction.
        assert_eq!(server.unwrap(&packet), None);
        let mut tampered = client.wrap(&header, b"x");
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(server.unwrap(&tampered), None);
        let own = client.wrap(&header, b"y");
        assert_eq!(client.unwrap(&own), None);
    }

    #[test]
    fn the_replay_window_takes_reordered_ids_once_and_refuses_old_ones() {
        let mut window = ReplayWindow::default();
        assert!(!window.accept(0, 0));
        assert!(window.accept(0, 5));
        assert!(window.accept(0, 3));
        assert!(!window.accept(0, 3));
        assert!(window.accept(0, 70));
        assert!(!window.accept(0, 6));
        assert!(window.accept(0, 7));
        // A later time starts a new series; an earlier one is refused.
        assert!(window.accept(1, 1));
        assert!(!window.accept(0, 80));
    }
}
