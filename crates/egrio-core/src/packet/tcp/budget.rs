//! What an engine's flows draw on together: the receive windows the
//! receiving flows have promised, which their clients may send into the
//! capture device at any moment, and the send buffers the flows holding the
//! relay's bytes have been granted out of the engine's memory.
//!
//! Each flow's window and buffer grow with what it uses; a flow that holds
//! nothing is
//! charged nothing; and pressure on what the flows share holds a flow back to
//! a floor, never to nothing. Linux guarantees each socket `tcp_rmem[0]` even
//! under moderate memory pressure, clamps windows to four segments under
//! pressure (`tcp_adjust_rcv_ssthresh` in `include/net/tcp.h`), and at its
//! hard limit drops a segment rather than announce a zero window
//! (`tcp_prune_queue` in `net/ipv4/tcp_input.c`); it charges a send buffer
//! only for the memory it holds. Capture devices impose another bound:
//! on Linux a local sender is held back by its own queueing
//! discipline, while utun and Wintun drop what their queue cannot hold, so
//! the windows the receiving flows promise are budgeted against that queue.

use std::time::{Duration, Instant};

use super::connection::Connection;

/// How an engine sizes its flows' receive windows: the flows that are
/// receiving share `budget`, each an equal part of it up to `max`. A flow
/// starts at `start` and doubles each time its client sends a whole window
/// in time, so it earns room by filling what it has: a flow handed its
/// whole share before it needed it holds that promise against the budget,
/// and the flows that open later have to wait for it to drain. What the
/// receiving flows have promised holds a flow's window back, but only down
/// to its floor: its starting window, within its share. The floors of every
/// flow count fit the budget as the shares do, because what the windows
/// offer arrives before the engine can read it: a floor that could exceed
/// the share promised more than the budget once enough flows reached it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Windows {
    pub(super) budget: usize,
    /// What the flows together may have written and unacknowledged toward
    /// their clients. The receive side's budget is the capture device's
    /// queue, a hard limit; this one is the engine's own memory, and without
    /// it each flow sized its send buffer alone: 1 MiB apiece is a gigabyte
    /// once a thousand clients stop reading, and every tunnel's engine adds
    /// another. Only flows holding the relay's bytes hold any of it, so at
    /// 32 MiB nothing changes until 32 of them are sending at once, each at
    /// the floor.
    pub(super) send_budget: usize,
    /// The most one flow's send buffer grows to: twice what may be in
    /// flight toward its peer ([`Connection::size_send_buffer`]) needs no
    /// more.
    pub(super) send_max: usize,
    max: usize,
    pub(super) start: usize,
    /// The window scale (RFC 7323 section 2.3) that puts `max` at 32 768
    /// units, leaving the 16-bit field room to round up.
    pub(super) shift: u8,
    /// Out-of-order segments a flow holds; the window bounds their bytes.
    pub(super) out_of_order: usize,
}

/// A capture's flows: the bytes of a client's upload in flight sit in the
/// capture device's queues before the engine reads them, and what does not
/// fit the device drops. The budget is what those queues hold: Wintun's ring
/// and the macOS utun socket's receive buffer are both 4 MiB. A burst of
/// flows with large segments can fill those queues before the engine drains
/// them, so the advertised windows share one budget.
/// A client's round trip is microseconds, so a send buffer of 4 MiB holds
/// many of them at any rate the device carries.
pub(super) const CAPTURE_WINDOWS: Windows = Windows {
    budget: 4 * 1024 * 1024,
    send_budget: 32 * 1024 * 1024,
    send_max: 4 * 1024 * 1024,
    max: 1024 * 1024,
    start: 16 * 1024,
    shift: 5,
    out_of_order: 256,
};
/// The flows a tunnel's engine opens: the bytes in flight sit in the
/// network, so a window and a send buffer cover the path's bandwidth-delay
/// product. One flow may take the whole of each 32 MiB budget; flows
/// sending together share it, bounding the engine's memory. A young flow
/// starts at 8 MiB and earns the rest by filling it within a round trip.
/// The out-of-order limit must also hold a window's worth of tunnel
/// segments, so loss early in the window does not discard its remainder.
pub(super) const TUNNEL_WINDOWS: Windows = Windows {
    budget: 32 * 1024 * 1024,
    send_budget: 32 * 1024 * 1024,
    send_max: 32 * 1024 * 1024,
    max: 32 * 1024 * 1024,
    start: 8 * 1024 * 1024,
    shift: 10,
    out_of_order: 32 * 1024 * 1024 / 1360 + 1,
};
/// A flow counts as receiving this long after it opened or delivered data,
/// and for as long as it holds bytes the relay has not taken: a flow the
/// relay has backed up has not stopped receiving, and the window it already
/// advertised still brings bytes to the capture device. Leaving such a flow
/// out left the counted flows a share each of the whole budget while it held
/// bytes besides, so the windows together offered more than the device holds.
/// Only a receiving flow's promise counts against the budget: one whose
/// client has gone quiet sends nothing into the device, and while every open
/// flow's promise counted, connections that had once uploaded kept the whole
/// budget for as long as they stayed open.
const RECEIVING_IDLE: Duration = Duration::from_secs(1);

/// What an engine's flows hold together of each budget, kept as sums so a
/// grant costs no walk over the flows. Each flow keeps its own part of each
/// sum ([`Connection::promised`], [`Connection::send_recorded`]) and whether
/// it is receiving.
#[derive(Debug)]
pub(super) struct Budget {
    pub(super) windows: Windows,
    receiving: usize,
    /// The windows the receiving flows have advertised and their clients
    /// have not used yet, summed. The budget is handed out against this, not
    /// per flow: an advertised right edge never moves left, so a flow that
    /// promised while few were receiving keeps its promise while the others
    /// arrive. A flow that stops receiving takes its promise out of the sum,
    /// and one that receives again puts it back.
    pub(super) promised: usize,
    /// What the flows together hold of [`Windows::send_budget`], summed the
    /// same way as `promised`.
    pub(super) granted: usize,
    next_sweep: Option<Instant>,
}

impl Budget {
    pub(super) fn new(windows: Windows) -> Self {
        Self {
            windows,
            receiving: 0,
            promised: 0,
            granted: 0,
            next_sweep: None,
        }
    }

    /// Flows counted as receiving.
    pub(super) fn receiving(&self) -> usize {
        self.receiving
    }

    /// A flow opened. It counts as receiving at once, so flows that open
    /// together split the budget before their data arrives.
    pub(super) fn open(&mut self, now: Instant) {
        self.receiving += 1;
        self.arm_sweep(now);
    }

    /// After a segment of `conn`: its window grows if its client filled one
    /// in time, and a flow whose client delivered data counts as receiving.
    pub(super) fn note_delivery(&mut self, conn: &mut Connection, now: Instant) {
        conn.grow_window(self.windows.share(self.receiving), now);
        if conn.take_delivered() {
            conn.last_data = now;
            if !conn.receiving {
                // Its client sends again, so what it may still send counts.
                conn.receiving = true;
                self.receiving += 1;
                self.promised += conn.promised;
                self.arm_sweep(now);
            }
        }
    }

    /// The receive-window limit for `conn`: its share of the budget and the
    /// window it has earned, and no more than the budget leaves after what
    /// the other receiving flows have promised, which reaches the capture
    /// device whenever their clients choose to send. Those promises hold the
    /// flow back to its floor and no further: a SYN|ACK offering no window
    /// leaves the client's first bytes, a TLS ClientHello, waiting for its
    /// zero-window probe, and macOS sends none sooner than five seconds
    /// (`TCPTV_PERSMIN`, XNU `bsd/netinet/tcp_timer.h`).
    pub(super) fn window_cap(&self, conn: &Connection) -> usize {
        let own = if conn.receiving { conn.promised } else { 0 };
        let others = self.promised.saturating_sub(own);
        let room = self.windows.budget.saturating_sub(others);
        let floor = self.windows.floor(self.receiving);
        self.windows
            .share(self.receiving)
            .min(conn.allowance)
            .min(room.max(floor))
    }

    /// After `conn` changed: records its promise, taking it into the sum
    /// while the flow is receiving, and grants it its send buffer, which may
    /// be no more than the send budget leaves after the others' grants.
    /// Those bytes are the engine's own memory, waiting for the client to
    /// acknowledge them.
    pub(super) fn resync(&mut self, conn: &mut Connection) {
        let (before, after) = (conn.promised, conn.outstanding_window());
        conn.promised = after;
        if conn.receiving {
            self.promised = self.promised + after - before;
        }
        let before = conn.send_recorded;
        let others = self.granted.saturating_sub(before);
        conn.grant_send(self.windows.send_budget.saturating_sub(others));
        let after = conn.send_granted();
        if before != after {
            self.granted = self.granted + after - before;
            conn.send_recorded = after;
        }
    }

    /// `conn` is gone: its parts leave the sums.
    pub(super) fn remove(&mut self, conn: &Connection) {
        if conn.receiving {
            self.receiving -= 1;
            self.promised -= conn.promised;
        }
        self.granted -= conn.send_recorded;
    }

    /// When [`Self::sweep`] next has something to do.
    pub(super) fn next_sweep(&self) -> Option<Instant> {
        self.next_sweep
    }

    /// Once due, stops counting the flows whose clients have gone quiet: no
    /// data for [`RECEIVING_IDLE`] and nothing the relay has not taken.
    pub(super) fn sweep<'a>(
        &mut self,
        conns: impl Iterator<Item = &'a mut Connection>,
        now: Instant,
    ) {
        if !self.next_sweep.is_some_and(|due| due <= now) {
            return;
        }
        self.next_sweep = None;
        for conn in conns {
            if conn.receiving
                && !conn.holds_client_bytes()
                && now.duration_since(conn.last_data.max(conn.opened)) >= RECEIVING_IDLE
            {
                conn.receiving = false;
                self.receiving -= 1;
                self.promised -= conn.promised;
            }
        }
        if self.receiving > 0 {
            self.next_sweep = Some(now + RECEIVING_IDLE / 2);
        }
    }

    /// Every flow ended: nothing is left to sweep, so the pump has no reason
    /// to wake for it.
    pub(super) fn end(&mut self) {
        self.next_sweep = None;
    }

    fn arm_sweep(&mut self, now: Instant) {
        if self.next_sweep.is_none() {
            self.next_sweep = Some(now + RECEIVING_IDLE / 2);
        }
    }
}

impl Windows {
    /// The budget's equal share for each of `receiving` flows, at most
    /// `max`. Their shares together never exceed the budget.
    fn share(&self, receiving: usize) -> usize {
        (self.budget / receiving.max(1)).min(self.max)
    }

    /// What the other flows' promises can hold a flow's window back to while
    /// `receiving` flows are receiving: its starting window, within its
    /// share. An engine holds at most [`MAX_FLOWS`](super::engine::MAX_FLOWS),
    /// so a floor is never nothing, and the floors together fit the budget as
    /// the shares do.
    fn floor(&self, receiving: usize) -> usize {
        self.share(receiving).min(self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::super::connection::MAX_OFFERED_MSS;
    use super::super::engine::MAX_FLOWS;
    use super::{CAPTURE_WINDOWS, TUNNEL_WINDOWS};

    /// What the windows offer arrives in the capture device's queues before
    /// the engine reads them, and the device drops what does not fit, so
    /// the budget bounds their sum. A floor under each flow's share broke
    /// this once enough flows reached it: with a 128 KiB floor under a
    /// 4 MiB budget, 33 flows and up offered more than the queues hold, and
    /// a client uploading through a 65 535-byte MTU lost whole 64 KiB
    /// segments to the drops.
    #[test]
    fn the_shares_of_every_flow_count_fit_the_budget() {
        for windows in [CAPTURE_WINDOWS, TUNNEL_WINDOWS] {
            for receiving in 1..=MAX_FLOWS {
                let share = windows.share(receiving);
                assert!(
                    receiving * share <= windows.budget,
                    "{receiving} flows of {share} bytes exceed {}",
                    windows.budget
                );
                assert!(share > 0, "{receiving} flows leave one with no window");
                let floor = windows.floor(receiving);
                assert!(
                    floor > 0 && floor <= share,
                    "{receiving} flows put the floor at {floor} beside a share of {share}"
                );
            }
        }
    }

    /// The window a busy flow gets has to hold several of the segments the
    /// engine offers, or SWS avoidance withholds its window update until half
    /// the window frees and the flow stalls.
    #[test]
    fn a_busy_flows_window_holds_several_offered_segments() {
        const BUSY: usize = 64;
        const SEGMENTS: usize = 4;
        for windows in [CAPTURE_WINDOWS, TUNNEL_WINDOWS] {
            let share = windows.share(BUSY);
            assert!(
                share >= SEGMENTS * MAX_OFFERED_MSS,
                "{BUSY} flows leave {share} bytes, under {SEGMENTS} segments of \
                 {MAX_OFFERED_MSS}"
            );
        }
    }
}
