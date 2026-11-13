//! The data channel (OpenVPN `crypto.c`'s AEAD mode, the wire protocol
//! draft's "AEAD encrypted data channel packet"):
//!
//! ```text
//! P_DATA_V2: op|key_id  peer_id(3)  packet_id(4)  tag(16)  ciphertext
//! P_DATA_V1: op|key_id              packet_id(4)  tag(16)  ciphertext
//! nonce = packet_id || implicit IV (8 bytes),  AD = op|key_id || peer_id || packet_id  (V1: packet_id)
//! ```
//!
//! A TLS session's 256 bytes of key material hold the client-to-server
//! cipher and HMAC keys, then the server-to-client ones; an AEAD cipher keys
//! from the first and takes its implicit IV from the second
//! (`init_key_contexts`, `key_ctx_update_implicit_iv`).

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

use super::config::DataCipher;
use super::crypt::ReplayWindow;
use super::wire::{first_byte, key_id, opcode, P_DATA_V1, P_DATA_V2};

const TAG_LEN: usize = 16;

/// The keepalive a peer sends when it has sent nothing else for `ping`
/// seconds (`ping.c`).
pub(super) const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
/// The prefix of an OCC message (`occ.c`), then its opcode.
const OCC_MAGIC: [u8; 16] = [
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
];
const OCC_EXIT: u8 = 6;

/// The explicit exit notification a client sends over the data channel when
/// the server takes none over the control channel.
pub(super) fn occ_exit() -> Vec<u8> {
    let mut message = OCC_MAGIC.to_vec();
    message.push(OCC_EXIT);
    message
}

/// What a data packet carried.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Payload {
    Ip(Vec<u8>),
    Ping,
    /// The peer is going away (an explicit exit notification).
    Exit,
    /// Another OCC message; nothing this client answers.
    Other,
}

impl Payload {
    fn classify(plaintext: Vec<u8>) -> Self {
        if plaintext == PING {
            Self::Ping
        } else if plaintext.starts_with(&OCC_MAGIC) {
            if plaintext.get(OCC_MAGIC.len()) == Some(&OCC_EXIT) {
                Self::Exit
            } else {
                Self::Other
            }
        } else {
            Self::Ip(plaintext)
        }
    }
}

/// One key id's data channel keys.
pub(super) struct DataKeys {
    key_id: u8,
    seal: LessSafeKey,
    seal_iv: [u8; 8],
    open: LessSafeKey,
    open_iv: [u8; 8],
    next_id: u32,
    replay: ReplayWindow,
}

impl DataKeys {
    /// The server's keys from the same material: the directions swapped.
    #[cfg(test)]
    pub(super) fn server(cipher: DataCipher, material: &[u8; 256], key_id: u8) -> Self {
        let mut swapped = [0_u8; 256];
        swapped[..128].copy_from_slice(&material[128..]);
        swapped[128..].copy_from_slice(&material[..128]);
        Self::client(cipher, &swapped, key_id)
    }

    /// The client's keys from a session's key material.
    pub(super) fn client(cipher: DataCipher, material: &[u8; 256], key_id: u8) -> Self {
        let (algorithm, len) = match cipher {
            DataCipher::Aes128Gcm => (&AES_128_GCM, 16),
            DataCipher::Aes256Gcm => (&AES_256_GCM, 32),
            DataCipher::ChaCha20Poly1305 => (&CHACHA20_POLY1305, 32),
        };
        let key = |at: usize| {
            LessSafeKey::new(
                UnboundKey::new(algorithm, &material[at..at + len]).expect("key length"),
            )
        };
        let iv = |at: usize| -> [u8; 8] { material[at..at + 8].try_into().expect("8 bytes") };
        Self {
            key_id,
            seal: key(0),
            seal_iv: iv(64),
            open: key(128),
            open_iv: iv(192),
            next_id: 1,
            replay: ReplayWindow::default(),
        }
    }

    pub(super) fn key_id(&self) -> u8 {
        self.key_id
    }

    /// A data packet carrying `payload`, as `P_DATA_V2` when the server gave
    /// a peer id; `None` once the packet ids ran out.
    pub(super) fn seal(&mut self, peer_id: Option<u32>, payload: &[u8]) -> Option<Vec<u8>> {
        if self.next_id == u32::MAX {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut packet = Vec::with_capacity(8 + TAG_LEN + payload.len());
        let ad_start = match peer_id {
            Some(peer_id) => {
                packet.push(first_byte(P_DATA_V2, self.key_id));
                packet.extend_from_slice(&peer_id.to_be_bytes()[1..]);
                0
            }
            None => {
                packet.push(first_byte(P_DATA_V1, self.key_id));
                1
            }
        };
        packet.extend_from_slice(&id.to_be_bytes());
        let ad_end = packet.len();
        packet.extend_from_slice(&[0; TAG_LEN]);
        packet.extend_from_slice(payload);
        let (head, body) = packet.split_at_mut(ad_end + TAG_LEN);
        let tag = self
            .seal
            .seal_in_place_separate_tag(
                nonce(id, &self.seal_iv),
                Aad::from(&head[ad_start..ad_end]),
                body,
            )
            .ok()?;
        head[ad_end..].copy_from_slice(tag.as_ref());
        Some(packet)
    }

    /// The payload of a data packet under this key id, if it authenticates
    /// and is no replay.
    pub(super) fn open(&mut self, packet: &[u8]) -> Option<Payload> {
        let first = *packet.first()?;
        if key_id(first) != self.key_id {
            return None;
        }
        let (ad_start, id_at) = match opcode(first) {
            P_DATA_V2 => (0, 4),
            P_DATA_V1 => (1, 1),
            _ => return None,
        };
        let tag_at = id_at + 4;
        let body_at = tag_at + TAG_LEN;
        if packet.len() < body_at {
            return None;
        }
        let id = u32::from_be_bytes(packet[id_at..tag_at].try_into().ok()?);
        let mut plaintext = packet[body_at..].to_vec();
        self.open
            .open_in_place_separate_tag(
                nonce(id, &self.open_iv),
                Aad::from(&packet[ad_start..tag_at]),
                &packet[tag_at..body_at],
                &mut plaintext,
            )
            .ok()?;
        self.replay
            .accept(0, id)
            .then(|| Payload::classify(plaintext))
    }
}

fn nonce(id: u32, implicit: &[u8; 8]) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&id.to_be_bytes());
    nonce[4..].copy_from_slice(implicit);
    Nonce::assume_unique_for_key(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_packets_open_on_the_other_side_once_in_both_formats() {
        let material: [u8; 256] = std::array::from_fn(|index| index as u8);
        for cipher in [
            DataCipher::Aes128Gcm,
            DataCipher::Aes256Gcm,
            DataCipher::ChaCha20Poly1305,
        ] {
            let mut client = DataKeys::client(cipher, &material, 2);
            let mut receiver = DataKeys::server(cipher, &material, 2);
            let packet = client.seal(Some(7), b"\x45 an IP packet").unwrap();
            assert_eq!(packet[..4], [first_byte(P_DATA_V2, 2), 0, 0, 7]);
            assert_eq!(packet.len(), 4 + 4 + TAG_LEN + 14);
            assert_eq!(
                receiver.open(&packet),
                Some(Payload::Ip(b"\x45 an IP packet".to_vec()))
            );
            assert_eq!(receiver.open(&packet), None, "a replay");
            let mut tampered = client.seal(Some(7), b"x").unwrap();
            tampered[3] ^= 1;
            assert_eq!(
                receiver.open(&tampered),
                None,
                "the peer id is authenticated"
            );
            let v1 = client.seal(None, &PING).unwrap();
            assert_eq!(v1[0], first_byte(P_DATA_V1, 2));
            assert_eq!(receiver.open(&v1), Some(Payload::Ping));
            // Another key id is not this key's to open.
            let mut other = DataKeys::server(cipher, &material, 3);
            assert_eq!(other.open(&client.seal(Some(7), b"y").unwrap()), None);
        }
    }

    #[test]
    fn an_exit_notification_is_told_apart_from_ip() {
        let mut exit = OCC_MAGIC.to_vec();
        exit.push(OCC_EXIT);
        assert_eq!(Payload::classify(exit), Payload::Exit);
        let mut request = OCC_MAGIC.to_vec();
        request.push(0);
        assert_eq!(Payload::classify(request), Payload::Other);
    }
}
