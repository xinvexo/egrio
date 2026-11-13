//! The control channel's reliability layer (OpenVPN `reliable.c`): numbered
//! messages, each acknowledged by id, retransmitted on a doubling timeout or
//! once later ones were acknowledged past it, and delivered to TLS in order.
//! It runs over TCP too, where nothing is lost and acks only free the window.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Messages in flight at once (`TLS_RELIABLE_N_SEND_BUFFERS`).
const SEND_WINDOW: usize = 6;
/// Messages buffered ahead of the next one due (`TLS_RELIABLE_N_REC_BUFFERS`).
const RECEIVE_WINDOW: u32 = 12;
/// A message is sent again once this many later ones were acknowledged
/// (`N_ACK_RETRANSMIT`).
const ACKS_TO_RETRANSMIT: u8 = 3;
/// Retransmission backs off to at most the initial timeout times 2^6
/// (`RELIABLE_MAX_TIMEOUT_SHIFT`).
const MAX_BACKOFF_SHIFT: u32 = 6;

struct Outgoing {
    id: u32,
    opcode: u8,
    payload: Vec<u8>,
    /// `None` until first sent.
    next_try: Option<Instant>,
    timeout: Duration,
    later_acks: u8,
}

pub(super) struct Reliable {
    send: VecDeque<Outgoing>,
    next_id: u32,
    initial_timeout: Duration,
    receive_next: u32,
    received: BTreeMap<u32, (u8, Vec<u8>)>,
    acks: Vec<u32>,
}

impl Reliable {
    /// `initial_timeout` is the config's `tls-timeout`.
    pub(super) fn new(initial_timeout: Duration) -> Self {
        Self {
            send: VecDeque::new(),
            next_id: 0,
            initial_timeout,
            receive_next: 0,
            received: BTreeMap::new(),
            acks: Vec::new(),
        }
    }

    /// Queues a message; it goes out once the window has room.
    pub(super) fn queue(&mut self, opcode: u8, payload: Vec<u8>) {
        self.send.push_back(Outgoing {
            id: self.next_id,
            opcode,
            payload,
            next_try: None,
            timeout: self.initial_timeout,
            later_acks: 0,
        });
        self.next_id = self.next_id.wrapping_add(1);
    }

    /// Takes the peer's acks: acknowledged messages leave, and earlier ones
    /// count the acks that passed them.
    pub(super) fn acknowledge(&mut self, acks: &[u32]) {
        for &ack in acks {
            let Some(index) = self.send.iter().position(|message| message.id == ack) else {
                continue;
            };
            self.send.remove(index);
            for earlier in self.send.iter_mut().take(index) {
                if earlier.next_try.is_some() {
                    earlier.later_acks = earlier.later_acks.saturating_add(1);
                }
            }
        }
    }

    /// Takes a message from the peer and returns those now deliverable, in
    /// order. Every message in or behind the window is acknowledged, a
    /// repeated one again: the peer resends when our ack was lost.
    pub(super) fn receive(&mut self, id: u32, opcode: u8, payload: Vec<u8>) -> Vec<(u8, Vec<u8>)> {
        let ahead = id.wrapping_sub(self.receive_next);
        if ahead >= RECEIVE_WINDOW && ahead < u32::MAX / 2 {
            return Vec::new();
        }
        if !self.acks.contains(&id) {
            self.acks.push(id);
        }
        if ahead < RECEIVE_WINDOW {
            self.received.entry(id).or_insert((opcode, payload));
        }
        let mut ready = Vec::new();
        while let Some(message) = self.received.remove(&self.receive_next) {
            ready.push(message);
            self.receive_next = self.receive_next.wrapping_add(1);
        }
        ready
    }

    pub(super) fn has_acks(&self) -> bool {
        !self.acks.is_empty()
    }

    /// Up to `max` pending acks, oldest first.
    pub(super) fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let count = self.acks.len().min(max);
        self.acks.drain(..count).collect()
    }

    /// The messages to send now: first transmissions within the window, and
    /// retransmissions whose timeout ran out or that later acks passed.
    pub(super) fn due(&mut self, now: Instant) -> Vec<(u32, u8, Vec<u8>)> {
        let max_timeout = self.initial_timeout * (1 << MAX_BACKOFF_SHIFT);
        let mut due = Vec::new();
        for message in self.send.iter_mut().take(SEND_WINDOW) {
            let send = match message.next_try {
                None => true,
                Some(at) => now >= at || message.later_acks >= ACKS_TO_RETRANSMIT,
            };
            if !send {
                continue;
            }
            if message.next_try.is_some() {
                message.timeout = (message.timeout * 2).min(max_timeout);
            }
            message.next_try = Some(now + message.timeout);
            message.later_acks = 0;
            due.push((message.id, message.opcode, message.payload.clone()));
        }
        due
    }

    /// When the next retransmission is due, if any message waits on an ack.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.send
            .iter()
            .take(SEND_WINDOW)
            .filter_map(|message| message.next_try)
            .min()
    }

    /// Whether every queued message was acknowledged.
    pub(super) fn settled(&self) -> bool {
        self.send.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_go_out_within_the_window_and_back_off_until_acked() {
        let start = Instant::now();
        let mut reliable = Reliable::new(Duration::from_secs(2));
        for index in 0..8 {
            reliable.queue(4, vec![index]);
        }
        let first: Vec<u32> = reliable.due(start).iter().map(|(id, ..)| *id).collect();
        assert_eq!(first, [0, 1, 2, 3, 4, 5]);
        assert!(reliable.due(start).is_empty());
        assert_eq!(
            reliable.next_deadline(),
            Some(start + Duration::from_secs(2))
        );
        // Acks free the window; the rest go out, and the late ones repeat.
        reliable.acknowledge(&[0, 1]);
        let next: Vec<u32> = reliable.due(start).iter().map(|(id, ..)| *id).collect();
        assert_eq!(next, [6, 7]);
        let again: Vec<u32> = reliable
            .due(start + Duration::from_secs(2))
            .iter()
            .map(|(id, ..)| *id)
            .collect();
        assert_eq!(again, [2, 3, 4, 5, 6, 7]);
        assert_eq!(
            reliable.next_deadline(),
            Some(start + Duration::from_secs(6))
        );
        // Three later acks send message 2 again before its timeout.
        reliable.acknowledge(&[3, 4, 5]);
        let fast: Vec<u32> = reliable
            .due(start + Duration::from_secs(3))
            .iter()
            .map(|(id, ..)| *id)
            .collect();
        assert_eq!(fast, [2]);
        reliable.acknowledge(&[2, 6, 7]);
        assert!(reliable.settled());
    }

    #[test]
    fn received_messages_deliver_in_order_and_are_acked_even_when_repeated() {
        let mut reliable = Reliable::new(Duration::from_secs(2));
        assert!(reliable.receive(1, 4, b"b".to_vec()).is_empty());
        let ready = reliable.receive(0, 4, b"a".to_vec());
        assert_eq!(ready, [(4, b"a".to_vec()), (4, b"b".to_vec())]);
        assert_eq!(reliable.take_acks(8), [1, 0]);
        assert!(reliable.receive(0, 4, b"a".to_vec()).is_empty());
        assert_eq!(reliable.take_acks(8), [0]);
        // Beyond the window: neither kept nor acked.
        assert!(reliable.receive(40, 4, vec![]).is_empty());
        assert!(!reliable.has_acks());
    }
}
