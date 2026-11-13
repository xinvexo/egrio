//! TIME-WAIT without its connection. Once a flow that closed first has
//! acknowledged the client's FIN, the engine frees the connection and keeps
//! this record until the wait ends (RFC 9293 section 3.10.7.4), so the wait
//! holds none of the live flows.

use std::time::Instant;

use super::connection::TIME_WAIT;
use super::segment::{self, Outgoing, Received, SackBlocks, ACK, FIN, RST, SYN};
use super::seq::Seq;
use super::{OutSegment, Payload};

/// What TIME-WAIT keeps of a connection.
#[derive(Clone, Copy, Debug)]
pub(super) struct TimeWait {
    pub(super) snd_nxt: Seq,
    pub(super) rcv_nxt: Seq,
    /// The right edge of the receive window last advertised.
    pub(super) rcv_edge: Seq,
    /// The window field of the last segment sent.
    pub(super) window: u16,
    pub(super) until: Instant,
}

/// What a segment for the tuple does to the record.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Ignore,
    /// Answer with [`TimeWait::ack`].
    Acknowledge,
    /// An RST at exactly `rcv_nxt` ends the wait.
    End,
    /// A SYN beyond the old sequence space opens a new incarnation.
    Reopen,
}

impl TimeWait {
    /// Takes a segment as the connection in TIME-WAIT would have.
    pub(super) fn on_segment(&mut self, seg: &Received, now: Instant) -> Verdict {
        if seg.has(SYN) && !seg.has(ACK) && seg.seq.is_after(self.rcv_nxt) {
            return Verdict::Reopen;
        }
        if !seg.acceptable(self.rcv_nxt, self.rcv_edge) {
            if seg.has(RST) {
                return Verdict::Ignore;
            }
            if seg.has(FIN) {
                // The client did not hear our ACK of its FIN.
                self.until = now + TIME_WAIT;
            }
            return Verdict::Acknowledge;
        }
        if seg.has(RST) {
            // RFC 5961 section 3.2: an RST elsewhere in the window draws a
            // challenge ACK.
            return if seg.seq == self.rcv_nxt {
                Verdict::End
            } else {
                Verdict::Acknowledge
            };
        }
        if seg.has(SYN) || (seg.has(ACK) && seg.ack.is_after(self.snd_nxt)) {
            // A SYN draws a challenge ACK (RFC 5961 section 4.2), and an ACK
            // of what was never sent an ACK (section 5.2).
            return Verdict::Acknowledge;
        }
        Verdict::Ignore
    }

    /// The ACK answering `seg`.
    pub(super) fn ack(&self, seg: &Received) -> OutSegment {
        let outgoing = Outgoing {
            local: seg.target,
            client: seg.client,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: ACK,
            window: self.window,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: SackBlocks::default(),
        };
        OutSegment {
            header: segment::write_header(&outgoing, 0),
            payload: Payload::default(),
        }
    }
}
