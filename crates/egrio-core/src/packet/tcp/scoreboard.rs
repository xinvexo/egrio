//! The sender's record of what is in flight, segment by segment (RFC 6675's
//! scoreboard): each transmission's range, when it last went out, and
//! whether the peer selectively acknowledged it, loss detection found it
//! lost, or it went out again. A second queue holds the transmissions in the
//! order they went out, so loss detection walks only the oldest ones
//! instead of the whole window (RFC 8985 section 6.2, step 5).

use std::collections::VecDeque;
use std::time::Instant;

use super::seq::Seq;

#[derive(Clone, Debug)]
pub(super) struct Sent {
    id: u64,
    pub(super) start: Seq,
    /// The sequence number after the segment: its payload and its FIN.
    pub(super) end: Seq,
    pub(super) fin: bool,
    /// When it last went out.
    pub(super) xmit: Instant,
    pub(super) retransmitted: bool,
    pub(super) sacked: bool,
    /// Loss detection found it lost; it waits to go out again unless
    /// `resent`.
    pub(super) lost: bool,
    /// Sent again after it was found lost, and neither acknowledged nor
    /// found lost since: back in the network.
    pub(super) resent: bool,
}

impl Sent {
    pub(super) fn len(&self) -> usize {
        self.end.offset_from(self.start)
    }

    /// Whether loss detection may still find it lost: in the network and
    /// not delivered.
    fn in_network(&self) -> bool {
        !self.sacked && (!self.lost || self.resent)
    }
}

/// What loss detection makes of the oldest transmission in flight.
pub(super) enum Verdict {
    Lost,
    /// Lost unless delivered by this time.
    LostAt(Instant),
    /// Sent too recently to judge: neither it nor anything sent after it.
    Fine,
}

#[derive(Debug, Default)]
pub(super) struct Scoreboard {
    /// Unacknowledged segments in sequence order, their ids consecutive:
    /// segments only join at the back and leave at the front.
    segments: VecDeque<Sent>,
    /// (transmission time, id) in the order they went out. An entry is
    /// stale once its segment is acknowledged, SACKed or found lost, or went
    /// out again.
    order: VecDeque<(Instant, u64)>,
    next_id: u64,
    /// Bytes outstanding, SACKed, found lost (resent or not), and resent.
    outstanding: usize,
    sacked: usize,
    lost: usize,
    resent: usize,
    /// Segments found lost and not yet sent again.
    waiting: usize,
}

impl Scoreboard {
    pub(super) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Gives back the room the queues kept beyond `segments` entries, once
    /// nothing is in flight. A window's worth of records is a quarter of a
    /// megabyte at a 4 MiB send buffer and 1500-byte segments, and a flow
    /// that burst once kept that for as long as it lived. The caller passes
    /// what its current send buffer would need, so a flow between bursts
    /// keeps its room and one that has gone quiet gives it back.
    pub(super) fn trim(&mut self, segments: usize) {
        if !self.segments.is_empty() {
            return;
        }
        self.segments.shrink_to(segments);
        self.order.shrink_to(segments);
    }

    pub(super) fn sacked(&self) -> usize {
        self.sacked
    }

    pub(super) fn sacked_segments(&self, mss: usize) -> usize {
        self.sacked.div_ceil(mss.max(1))
    }

    /// RFC 6675's pipe: bytes in the network, i.e. sent and neither
    /// acknowledged, SACKed nor lost, plus retransmissions of lost bytes.
    pub(super) fn pipe(&self) -> usize {
        self.outstanding - self.sacked - self.lost + self.resent
    }

    pub(super) fn first(&self) -> Option<&Sent> {
        self.segments.front()
    }

    pub(super) fn last(&self) -> Option<&Sent> {
        self.segments.back()
    }

    /// A segment of new data went out.
    pub(super) fn sent(&mut self, start: Seq, end: Seq, fin: bool, now: Instant) {
        debug_assert!(self
            .segments
            .back()
            .is_none_or(|last| last.end == start && last.id + 1 == self.next_id));
        let id = self.next_id;
        self.next_id += 1;
        let segment = Sent {
            id,
            start,
            end,
            fin,
            xmit: now,
            retransmitted: false,
            sacked: false,
            lost: false,
            resent: false,
        };
        self.outstanding += segment.len();
        self.segments.push_back(segment);
        self.order.push_back((now, id));
    }

    /// The cumulative acknowledgement `ack`: the segments it covers leave,
    /// one it ends inside is cut; each that was not SACKed is `delivered`.
    pub(super) fn acknowledge(&mut self, ack: Seq, mut delivered: impl FnMut(&Sent)) {
        while let Some(front) = self.segments.front() {
            if front.end.is_after(ack) {
                break;
            }
            let segment = self.segments.pop_front().unwrap();
            self.forget(&segment);
            if !segment.sacked {
                delivered(&segment);
            }
        }
        // Entries of segments that left are stale.
        let first = self.segments.front().map_or(self.next_id, |front| front.id);
        while self.order.front().is_some_and(|&(_, id)| id < first) {
            self.order.pop_front();
        }
        if let Some(front) = self.segments.front_mut() {
            if ack.is_after(front.start) {
                let cut = ack.offset_from(front.start);
                front.start = ack;
                self.outstanding -= cut;
                if front.sacked {
                    self.sacked -= cut;
                } else if front.lost {
                    self.lost -= cut;
                    if front.resent {
                        self.resent -= cut;
                    }
                }
            }
        }
    }

    /// Removes a segment's bytes from the counters.
    fn forget(&mut self, segment: &Sent) {
        let length = segment.len();
        self.outstanding -= length;
        if segment.sacked {
            self.sacked -= length;
        } else if segment.lost {
            self.lost -= length;
            if segment.resent {
                self.resent -= length;
            } else {
                self.waiting -= 1;
            }
        }
    }

    /// SACK blocks: each segment a block covers whole is marked and
    /// `delivered`.
    pub(super) fn select(&mut self, blocks: &[(Seq, Seq)], mut delivered: impl FnMut(&Sent)) {
        for &(left, right) in blocks {
            let first = self
                .segments
                .partition_point(|segment| segment.start.is_before(left));
            for index in first..self.segments.len() {
                let segment = &mut self.segments[index];
                if segment.end.is_after(right) {
                    break;
                }
                if segment.sacked {
                    continue;
                }
                let length = segment.len();
                segment.sacked = true;
                self.sacked += length;
                if segment.lost {
                    segment.lost = false;
                    self.lost -= length;
                    if segment.resent {
                        segment.resent = false;
                        self.resent -= length;
                    } else {
                        self.waiting -= 1;
                    }
                }
                delivered(&self.segments[index]);
            }
        }
    }

    /// The segment with `id`, if it is still unacknowledged.
    fn position(&self, id: u64) -> Option<usize> {
        let first = self.segments.front()?.id;
        let index = usize::try_from(id.checked_sub(first)?).ok()?;
        (index < self.segments.len()).then_some(index)
    }

    fn mark_lost(&mut self, index: usize) {
        let segment = &mut self.segments[index];
        if !segment.in_network() {
            return;
        }
        let length = segment.len();
        if segment.resent {
            // The retransmission went missing too.
            segment.resent = false;
            self.resent -= length;
        } else {
            segment.lost = true;
            self.lost += length;
        }
        self.waiting += 1;
    }

    /// Walks the transmissions in the order they went out, oldest first,
    /// marking lost what `judge` finds lost; stops at the first it cannot
    /// judge yet. Returns whether it marked any, and when the oldest one it
    /// stopped at would be lost.
    pub(super) fn detect(
        &mut self,
        mut judge: impl FnMut(&Sent) -> Verdict,
    ) -> (bool, Option<Instant>) {
        let mut marked = false;
        while let Some(&(xmit, id)) = self.order.front() {
            let Some(index) = self.position(id) else {
                self.order.pop_front();
                continue;
            };
            let segment = &self.segments[index];
            if segment.xmit != xmit || !segment.in_network() {
                self.order.pop_front();
                continue;
            }
            match judge(segment) {
                Verdict::Lost => {
                    self.order.pop_front();
                    self.mark_lost(index);
                    marked = true;
                }
                Verdict::LostAt(at) => return (marked, Some(at)),
                Verdict::Fine => return (marked, None),
            }
        }
        (marked, None)
    }

    /// Marks the first segment lost: what a peer without SACK reveals
    /// through duplicate and partial acknowledgements.
    pub(super) fn mark_first_lost(&mut self) -> bool {
        if self.segments.front().is_some_and(Sent::in_network) {
            self.mark_lost(0);
            return true;
        }
        false
    }

    /// A retransmission timeout: SACK information is dropped, since the
    /// peer may have discarded what it SACKed (RFC 2018 section 8), and
    /// every segment `expired` finds lost is marked, the first one always
    /// (RFC 8985 section 6.3).
    pub(super) fn on_timeout(&mut self, mut expired: impl FnMut(&Sent) -> bool) {
        for index in 0..self.segments.len() {
            let segment = &mut self.segments[index];
            if segment.sacked {
                segment.sacked = false;
                self.sacked -= segment.len();
            }
            if index == 0 || expired(&self.segments[index]) {
                self.mark_lost(index);
            }
        }
    }

    /// Segments found lost wait to go out again.
    pub(super) fn has_waiting(&self) -> bool {
        self.waiting > 0
    }

    /// The lowest segment found lost and not yet sent again.
    pub(super) fn next_lost(&self) -> Option<&Sent> {
        if self.waiting == 0 {
            return None;
        }
        self.segments
            .iter()
            .find(|segment| segment.lost && !segment.resent && !segment.sacked)
    }

    /// The segment starting at `start` went out again at `now`; a lost one
    /// is in the network again.
    pub(super) fn resent(&mut self, start: Seq, now: Instant) {
        let index = self
            .segments
            .partition_point(|segment| segment.start.is_before(start));
        let Some(segment) = self.segments.get_mut(index) else {
            return;
        };
        debug_assert_eq!(segment.start, start);
        segment.retransmitted = true;
        segment.xmit = now;
        if segment.lost && !segment.resent && !segment.sacked {
            segment.resent = true;
            self.resent += segment.len();
            self.waiting -= 1;
        }
        let id = segment.id;
        self.order.push_back((now, id));
        // Retransmissions leave stale entries behind the front; keep the
        // queue in proportion to what is in flight.
        if self.order.len() > 4 * self.segments.len() + 64 {
            let mut order = std::mem::take(&mut self.order);
            order.retain(|&(xmit, id)| {
                self.position(id).is_some_and(|index| {
                    let segment = &self.segments[index];
                    segment.xmit == xmit && segment.in_network()
                })
            });
            self.order = order;
        }
    }

    #[cfg(test)]
    pub(super) fn segments(&self) -> impl Iterator<Item = &Sent> {
        self.segments.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn board(count: u32, now: Instant) -> Scoreboard {
        let mut board = Scoreboard::default();
        for k in 0..count {
            board.sent(
                Seq(k * 100),
                Seq(k * 100 + 100),
                false,
                now + Duration::from_millis(u64::from(k)),
            );
        }
        board
    }

    /// A burst's records are a quarter megabyte at a full send buffer. A
    /// flow that has gone quiet gives that room back instead of holding it
    /// for as long as it lives.
    #[test]
    fn a_board_with_nothing_in_flight_gives_its_room_back() {
        let now = Instant::now();
        let mut board = board(2048, now);
        let burst = board.segments.capacity();
        assert!(burst >= 2048, "the burst's records are all there");

        // Still in flight: the room stays, whatever the caller asks.
        board.trim(8);
        assert_eq!(board.segments.capacity(), burst);

        board.acknowledge(Seq(2048 * 100), |_| {});
        board.trim(8);

        assert!(board.is_empty());
        assert!(
            board.segments.capacity() < burst / 8,
            "capacity {} is still a burst's worth",
            board.segments.capacity()
        );
        assert!(board.order.capacity() < burst / 8);
    }

    #[test]
    fn sacks_and_losses_shape_what_is_in_the_network() {
        let now = Instant::now();
        let mut board = board(10, now);
        assert_eq!(board.pipe(), 1000);
        let mut delivered = Vec::new();
        board.select(&[(Seq(300), Seq(500)), (Seq(700), Seq(1000))], |s| {
            delivered.push(s.start.0)
        });
        assert_eq!(delivered, [300, 400, 700, 800, 900]);
        assert_eq!(board.pipe(), 500);
        // Everything sent before segment 900 and not delivered is lost.
        let (marked, timer) = board.detect(|s| {
            if s.xmit < now + Duration::from_millis(9) {
                Verdict::Lost
            } else {
                Verdict::Fine
            }
        });
        assert!(marked && timer.is_none());
        assert_eq!(board.pipe(), 0);
        assert_eq!(board.next_lost().unwrap().start, Seq(0));
        // Resent, the first is in the network again.
        board.resent(Seq(0), now + Duration::from_millis(20));
        assert_eq!(board.pipe(), 100);
        assert_eq!(board.next_lost().unwrap().start, Seq(100));
        // A cumulative ACK through 500 delivers what was not SACKed.
        delivered.clear();
        board.acknowledge(Seq(500), |s| delivered.push(s.start.0));
        assert_eq!(delivered, [0, 100, 200]);
        assert_eq!(board.first().unwrap().start, Seq(500));
        assert_eq!(board.pipe(), 0);
        assert_eq!(board.sacked(), 300);
    }

    #[test]
    fn a_retransmission_lost_again_waits_to_go_out_once_more() {
        let now = Instant::now();
        let mut board = board(3, now);
        board.detect(|s| {
            if s.start == Seq(0) {
                Verdict::Lost
            } else {
                Verdict::Fine
            }
        });
        board.resent(Seq(0), now + Duration::from_millis(50));
        assert!(!board.has_waiting());
        // The retransmission's entry is the newest; the older ones go first.
        let (_, timer) = board.detect(|s| {
            if s.start == Seq(0) {
                Verdict::Lost
            } else {
                Verdict::LostAt(s.xmit + Duration::from_millis(100))
            }
        });
        assert_eq!(timer, Some(now + Duration::from_millis(101)));
        assert!(
            !board.has_waiting(),
            "segment 0's retransmission is not judged before 100 and 200"
        );
        let (marked, _) = board.detect(|_| Verdict::Lost);
        assert!(marked);
        assert_eq!(board.segments().filter(|s| s.lost && !s.resent).count(), 3);
    }

    #[test]
    fn a_partial_acknowledgement_cuts_the_first_segment() {
        let now = Instant::now();
        let mut board = board(2, now);
        board.mark_first_lost();
        board.acknowledge(Seq(40), |_| panic!("not delivered whole"));
        assert_eq!(board.first().unwrap().start, Seq(40));
        assert_eq!(board.pipe(), 100);
        board.acknowledge(Seq(200), |_| {});
        assert!(board.is_empty());
        assert_eq!(board.pipe(), 0);
        assert!(!board.has_waiting());
    }

    #[test]
    fn a_timeout_forgets_sacks_and_marks_the_first_segment() {
        let now = Instant::now();
        let mut board = board(4, now);
        board.select(&[(Seq(200), Seq(300))], |_| {});
        board.on_timeout(|_| false);
        assert_eq!(board.sacked(), 0);
        assert_eq!(board.next_lost().unwrap().start, Seq(0));
        assert_eq!(board.pipe(), 300);
    }
}
