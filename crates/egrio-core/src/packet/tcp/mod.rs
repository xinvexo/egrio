//! The capture TCP stack: terminates the TCP flows the capture device
//! delivers, as the server each client addressed, and hands each flow's
//! bytes to the relay as a [`CapturedTcpStream`]. The packet pump drives
//! the [`TcpEngine`] inline; see `docs/architecture/core.md` (Captured TCP).

mod budget;
pub(crate) mod checksum;
mod connection;
mod cubic;
mod engine;
mod rack;
mod scoreboard;
mod segment;
mod seq;
mod stream;
#[cfg(test)]
mod tests;
mod time_wait;

use bytes::Bytes;

pub(crate) use engine::{FlowHolders, ForeignSegment, QueueShare, TcpEngine};
#[cfg(test)]
pub(crate) use stream::FlowShared;
pub(crate) use stream::{CapturedTcpStream, EngineWake};

/// Payload pieces one segment may reference; a segment spanning more relay
/// chunks ends early.
pub(crate) const MAX_PIECES: usize = 8;

/// One segment the stack sends: its finished IP and TCP header, then its
/// payload as slices of the relay's buffers.
#[derive(Clone, Debug)]
pub(crate) struct OutSegment {
    pub(crate) header: segment::Header,
    pub(crate) payload: Payload,
}

impl OutSegment {
    /// The segment's bytes in order: the header, then each payload piece.
    pub(crate) fn parts(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.header.as_slice()).chain(self.payload.slices())
    }

    pub(crate) fn len(&self) -> usize {
        self.header.as_slice().len() + self.payload.total_len()
    }

    /// Completes the TCP checksum, for a device that does not have its OS
    /// do it.
    pub(crate) fn finish_checksum(&mut self) {
        self.header.finish_checksum(self.payload.slices());
    }

    /// The segment as one contiguous packet with its checksum complete.
    #[cfg(test)]
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.finish_checksum(self.payload.slices());
        let mut packet = Vec::with_capacity(self.len());
        packet.extend_from_slice(header.as_slice());
        for piece in self.payload.slices() {
            packet.extend_from_slice(piece);
        }
        packet
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Payload {
    pieces: [Bytes; MAX_PIECES],
    count: usize,
}

impl Payload {
    pub(crate) fn push(&mut self, piece: Bytes) {
        self.pieces[self.count] = piece;
        self.count += 1;
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }

    pub(crate) fn total_len(&self) -> usize {
        self.pieces[..self.count].iter().map(Bytes::len).sum()
    }

    pub(crate) fn slices(&self) -> impl Iterator<Item = &[u8]> + Clone {
        self.pieces[..self.count].iter().map(|piece| piece.as_ref())
    }
}
