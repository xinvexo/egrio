//! OpenVPN packets on the wire (`ssl_pkt.h`, the wire protocol draft's
//! "Control channel wire packet structure"). Every packet starts with one
//! byte of opcode and key id; over TCP each one is prefixed with its 16-bit
//! length.

use super::crypt::{TlsCrypt, HEADER_LEN};

pub(super) const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub(super) const P_CONTROL_V1: u8 = 4;
pub(super) const P_ACK_V1: u8 = 5;
pub(super) const P_DATA_V1: u8 = 6;
pub(super) const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub(super) const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub(super) const P_DATA_V2: u8 = 9;

pub(super) fn opcode(first: u8) -> u8 {
    first >> 3
}

pub(super) fn key_id(first: u8) -> u8 {
    first & 0x07
}

pub(super) fn first_byte(opcode: u8, key_id: u8) -> u8 {
    opcode << 3 | key_id & 0x07
}

/// Acks one control packet carries besides its own message (OpenVPN's
/// `CONTROL_SEND_ACK_MAX`), and an ack-only packet (`RELIABLE_ACK_SIZE`).
pub(super) const ACKS_WITH_MESSAGE: usize = 4;
pub(super) const ACKS_ALONE: usize = 8;

/// A control packet's plaintext: what tls-crypt encrypts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlPlain {
    pub(super) acks: Vec<u32>,
    /// The session id the acks are for: the receiver's own.
    pub(super) acked_session: Option<[u8; 8]>,
    /// Absent on `P_ACK_V1`.
    pub(super) message_id: Option<u32>,
    pub(super) payload: Vec<u8>,
}

impl ControlPlain {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.acks.len() * 4 + 8 + 4 + self.payload.len());
        out.push(self.acks.len() as u8);
        for ack in &self.acks {
            out.extend_from_slice(&ack.to_be_bytes());
        }
        if !self.acks.is_empty() {
            out.extend_from_slice(&self.acked_session.unwrap_or_default());
        }
        if let Some(id) = self.message_id {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Reads a plaintext; an ack-only packet has no message id.
    pub(super) fn decode(plain: &[u8], ack_only: bool) -> Option<Self> {
        let (&count, mut rest) = plain.split_first()?;
        let mut acks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (id, tail) = rest.split_first_chunk::<4>()?;
            acks.push(u32::from_be_bytes(*id));
            rest = tail;
        }
        let acked_session = if count > 0 {
            let (session, tail) = rest.split_first_chunk::<8>()?;
            rest = tail;
            Some(*session)
        } else {
            None
        };
        let message_id = if ack_only {
            None
        } else {
            let (id, tail) = rest.split_first_chunk::<4>()?;
            rest = tail;
            Some(u32::from_be_bytes(*id))
        };
        Some(Self {
            acks,
            acked_session,
            message_id,
            payload: rest.to_vec(),
        })
    }
}

/// How control packets are protected: tls-crypt, or nothing beyond TLS.
pub(super) enum Wrap {
    None,
    Crypt(TlsCrypt),
}

impl Wrap {
    /// A whole control packet from our session id and its plaintext.
    pub(super) fn seal(
        &mut self,
        opcode: u8,
        key_id: u8,
        session: &[u8; 8],
        plain: &ControlPlain,
    ) -> Vec<u8> {
        let mut header = [0_u8; HEADER_LEN];
        header[0] = first_byte(opcode, key_id);
        header[1..].copy_from_slice(session);
        let plain = plain.encode();
        match self {
            Self::None => [&header[..], &plain].concat(),
            Self::Crypt(crypt) => crypt.wrap(&header, &plain),
        }
    }

    /// The sender's session id and the plaintext of a control packet, if it
    /// opens.
    pub(super) fn open(&mut self, packet: &[u8]) -> Option<([u8; 8], ControlPlain)> {
        let session: [u8; 8] = packet.get(1..HEADER_LEN)?.try_into().ok()?;
        let ack_only = opcode(packet[0]) == P_ACK_V1;
        let plain = match self {
            Self::None => ControlPlain::decode(&packet[HEADER_LEN..], ack_only)?,
            Self::Crypt(crypt) => ControlPlain::decode(&crypt.unwrap(packet)?, ack_only)?,
        };
        Some((session, plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plaintexts_round_trip_with_and_without_acks() {
        let message = ControlPlain {
            acks: vec![],
            acked_session: None,
            message_id: Some(0),
            payload: vec![],
        };
        assert_eq!(message.encode(), [0, 0, 0, 0, 0]);
        assert_eq!(
            ControlPlain::decode(&message.encode(), false),
            Some(message)
        );
        let ack = ControlPlain {
            acks: vec![3, 4],
            acked_session: Some([9; 8]),
            message_id: None,
            payload: vec![],
        };
        assert_eq!(ack.encode().len(), 1 + 8 + 8);
        assert_eq!(ControlPlain::decode(&ack.encode(), true), Some(ack));
        assert_eq!(ControlPlain::decode(&[1, 0, 0], false), None);
    }

    #[test]
    fn the_first_byte_holds_opcode_and_key_id() {
        let byte = first_byte(P_CONTROL_HARD_RESET_CLIENT_V2, 0);
        assert_eq!(byte, 0x38);
        assert_eq!(opcode(first_byte(P_DATA_V2, 5)), P_DATA_V2);
        assert_eq!(key_id(first_byte(P_DATA_V2, 5)), 5);
    }
}
