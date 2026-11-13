//! Turns at a QUIC connection's send space for the streams that share it.
//!
//! quinn admits a stream write only while the connection has send space left
//! (the peer's `MAX_DATA` and the local send window). A write it turns away
//! waits in a list that quinn-proto 0.11 drains whole, newest first, as soon
//! as any space frees (`StreamsState::poll`): every waiting writer wakes, the
//! first to run takes the space and the rest wait again, so which stream
//! loses is up to the scheduler. On the Core's one worker the task woken last
//! runs first (Tokio's LIFO slot), so one stream can repeatedly win while
//! other writers remain starved.
//!
//! [`SendTurns`] puts the writers of one connection in line instead. quinn
//! still decides when space frees and still holds the waker of each stream
//! it turned away, but that waker only marks the stream released here. The
//! two oldest released streams try and each outcome passes the turn on, so
//! released streams write in the order they were turned away; one that comes
//! away empty keeps its place for the next release, and one that wrote lines
//! up again behind the others. A stream quinn has not released, such as one
//! waiting for the peer's `MAX_STREAM_DATA`, holds nobody up. Only the writers
//! taking a turn are woken, rather than every writer per release.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use tokio::io::AsyncWrite;

/// How many released writers may take their turn at once: the next one
/// wakes while the one before it writes, so a release of more space than one
/// write takes is not drained one task wakeup at a time.
const TURNS_AT_ONCE: usize = 2;

/// The line of one connection's writers.
pub(super) struct SendTurns {
    line: Mutex<Line>,
}

impl Default for SendTurns {
    fn default() -> Self {
        Self::with_turns_at_once(TURNS_AT_ONCE)
    }
}

struct Line {
    at_once: usize,
    next_key: u64,
    writers: HashMap<u64, Writer>,
    /// Writers quinn turned away or that lined up behind a turn, oldest
    /// first.
    queue: VecDeque<u64>,
    /// Writers woken for their turn that have not polled yet, and writers
    /// whose attempt is out.
    active: usize,
    /// The released writer whose turn-away showed the connection's space
    /// gone: nobody else tries until quinn releases a writer again.
    spent: Option<u64>,
}

#[derive(Default)]
struct Writer {
    queued: bool,
    /// How often quinn released the writer.
    released: u64,
    /// The releases its attempts have used.
    used: u64,
    /// Lined up behind a turn in progress without quinn turning it away.
    lined_up: bool,
    woken: bool,
    trying: bool,
    task: Option<Waker>,
}

impl Writer {
    fn due(&self) -> bool {
        self.released > self.used || self.lined_up
    }
}

/// What an attempt is based on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ticket {
    released: u64,
    /// The attempt uses a release by quinn, which reports a stream writable
    /// only while it has room under its own limit: if it is turned away
    /// anyway, the connection's space is gone and quinn holds its waker for
    /// the next release, so the writers behind it need not try.
    spent_release: bool,
}

impl Line {
    fn any_due(&self) -> bool {
        self.queue.iter().any(|key| self.writers[key].due())
    }

    /// Whether `key` is among the first due writers allowed at once.
    fn has_turn(&self, key: u64) -> bool {
        let mut ahead = 0;
        for queued in &self.queue {
            if *queued == key {
                return ahead < self.at_once;
            }
            if self.writers[queued].due() {
                ahead += 1;
                if ahead >= self.at_once {
                    return false;
                }
            }
        }
        false
    }

    /// Wakes the first due writers that are neither woken nor trying, while
    /// fewer than `at_once` are, unless the connection's space is gone.
    fn pass_turn(&mut self) -> Vec<Waker> {
        let mut wake = Vec::new();
        if self.spent.is_some() {
            return wake;
        }
        for key in &self.queue {
            if self.active >= self.at_once {
                break;
            }
            let writer = self.writers.get_mut(key).expect("queued writers are known");
            if writer.due() && !writer.woken && !writer.trying {
                writer.woken = true;
                self.active += 1;
                wake.extend(writer.task.clone());
            }
        }
        wake
    }

    fn end_attempt(&mut self, key: u64) {
        let writer = self.writers.get_mut(&key).expect("the writer is known");
        if std::mem::take(&mut writer.trying) {
            self.active -= 1;
        }
    }
}

impl SendTurns {
    fn with_turns_at_once(at_once: usize) -> Self {
        Self {
            line: Mutex::new(Line {
                at_once,
                next_key: 0,
                writers: HashMap::new(),
                queue: VecDeque::new(),
                active: 0,
                spent: None,
            }),
        }
    }

    fn line(&self) -> MutexGuard<'_, Line> {
        self.line
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Wraps a send stream of this connection.
    pub(super) fn stream(self: &Arc<Self>, send: quinn::SendStream) -> TurnSend {
        let key = self.join();
        TurnSend {
            send,
            release: Waker::from(Arc::new(Release {
                turns: Arc::clone(self),
                key,
            })),
            turns: Arc::clone(self),
            key,
        }
    }

    fn join(&self) -> u64 {
        let mut line = self.line();
        let key = line.next_key;
        line.next_key += 1;
        line.writers.insert(key, Writer::default());
        key
    }

    fn leave(&self, key: u64) {
        let mut line = self.line();
        let Some(writer) = line.writers.remove(&key) else {
            return;
        };
        if writer.woken || writer.trying {
            line.active -= 1;
        }
        if writer.queued {
            line.queue.retain(|queued| *queued != key);
        }
        if line.spent == Some(key) {
            // quinn will not release it any more.
            line.spent = None;
        }
        let next = line.pass_turn();
        drop(line);
        wake(next);
    }

    /// Whether the writer may try quinn now; otherwise it waits for its turn
    /// and `task` is woken.
    fn try_turn(&self, key: u64, task: &Waker) -> Option<Ticket> {
        let mut guard = self.line();
        let line = &mut *guard;
        let writer = line.writers.get_mut(&key)?;
        if !writer
            .task
            .as_ref()
            .is_some_and(|known| known.will_wake(task))
        {
            writer.task = Some(task.clone());
        }
        let was_woken = std::mem::take(&mut writer.woken);
        let queued = writer.queued;
        let due = writer.due();
        if was_woken {
            line.active -= 1;
        }
        let allowed = if queued {
            line.spent.is_none() && due && line.has_turn(key)
        } else {
            !line.any_due()
        };
        let writer = line.writers.get_mut(&key).expect("the writer is known");
        if allowed {
            let ticket = Ticket {
                released: writer.released,
                spent_release: writer.released > writer.used,
            };
            writer.lined_up = false;
            writer.trying = true;
            line.active += 1;
            return Some(ticket);
        }
        if !queued {
            // Behind a turn in progress, or behind writers waiting for
            // quinn's next release.
            writer.queued = true;
            writer.lined_up = true;
            line.queue.push_back(key);
        }
        let next = line.pass_turn();
        drop(guard);
        wake(next);
        None
    }

    /// quinn turned the attempt away and will release the writer when it can
    /// write: it keeps its place in line.
    fn turned_away(&self, key: u64, ticket: Ticket) {
        let mut line = self.line();
        if !line.writers.contains_key(&key) {
            return;
        }
        line.end_attempt(key);
        let writer = line.writers.get_mut(&key).expect("the writer is known");
        writer.used = ticket.released;
        let released_meanwhile = writer.due();
        if !writer.queued {
            writer.queued = true;
            line.queue.push_back(key);
        }
        if ticket.spent_release && !released_meanwhile {
            line.spent = Some(key);
        }
        let next = line.pass_turn();
        drop(line);
        wake(next);
    }

    /// The attempt wrote or failed for good: the writer leaves the line and
    /// the next due writer tries.
    fn wrote(&self, key: u64) {
        let mut line = self.line();
        if !line.writers.contains_key(&key) {
            return;
        }
        line.end_attempt(key);
        let writer = line.writers.get_mut(&key).expect("the writer is known");
        writer.used = writer.released;
        writer.lined_up = false;
        if writer.queued {
            writer.queued = false;
            line.queue.retain(|queued| *queued != key);
        }
        let next = line.pass_turn();
        drop(line);
        wake(next);
    }

    /// quinn woke the writer: space freed, or the stream was stopped or the
    /// connection lost.
    fn release(&self, key: u64) {
        let mut line = self.line();
        let Some(writer) = line.writers.get_mut(&key) else {
            return;
        };
        writer.released += 1;
        let queued = writer.queued;
        line.spent = None;
        // A writer released while its attempt is still out is not queued
        // yet; `turned_away` sees the release.
        let next = if queued { line.pass_turn() } else { Vec::new() };
        drop(line);
        wake(next);
    }
}

fn wake(tasks: Vec<Waker>) {
    for task in tasks {
        task.wake();
    }
}

/// The waker quinn holds for a stream it turned away.
struct Release {
    turns: Arc<SendTurns>,
    key: u64,
}

impl Wake for Release {
    fn wake(self: Arc<Self>) {
        self.turns.release(self.key);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.turns.release(self.key);
    }
}

/// A QUIC send stream whose writes take turns with the other streams of its
/// connection.
pub(super) struct TurnSend {
    send: quinn::SendStream,
    turns: Arc<SendTurns>,
    key: u64,
    release: Waker,
}

impl Drop for TurnSend {
    fn drop(&mut self) {
        self.turns.leave(self.key);
    }
}

impl AsyncWrite for TurnSend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = &mut *self;
        let Some(ticket) = stream.turns.try_turn(stream.key, cx.waker()) else {
            return Poll::Pending;
        };
        let mut released = Context::from_waker(&stream.release);
        match Pin::new(&mut stream.send).poll_write(&mut released, buffer) {
            Poll::Pending => {
                stream.turns.turned_away(stream.key, ticket);
                Poll::Pending
            }
            Poll::Ready(result) => {
                stream.turns.wrote(stream.key);
                Poll::Ready(result.map_err(io::Error::other))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Task(AtomicUsize);

    impl Wake for Task {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Writers {
        turns: SendTurns,
        keys: Vec<u64>,
        tasks: Vec<(Arc<Task>, Waker)>,
    }

    impl Writers {
        fn new(count: usize) -> Self {
            Self::with_turns_at_once(count, 1)
        }

        fn with_turns_at_once(count: usize, at_once: usize) -> Self {
            let turns = SendTurns::with_turns_at_once(at_once);
            let keys = (0..count).map(|_| turns.join()).collect();
            let tasks = (0..count)
                .map(|_| {
                    let task = Arc::new(Task::default());
                    (task.clone(), Waker::from(task))
                })
                .collect();
            Self { turns, keys, tasks }
        }

        fn try_turn(&self, writer: usize) -> Option<Ticket> {
            self.turns
                .try_turn(self.keys[writer], &self.tasks[writer].1)
        }

        /// The writer tries and quinn turns it away.
        fn turned_away(&self, writer: usize) {
            let ticket = self.try_turn(writer).expect("the writer may try");
            self.turns.turned_away(self.keys[writer], ticket);
        }

        fn wrote(&self, writer: usize) {
            self.try_turn(writer).expect("the writer may try");
            self.turns.wrote(self.keys[writer]);
        }

        /// quinn releases the writers newest first.
        fn release(&self, writers: &[usize]) {
            for writer in writers.iter().rev() {
                self.turns.release(self.keys[*writer]);
            }
        }

        fn leave(&self, writer: usize) {
            self.turns.leave(self.keys[writer]);
        }

        /// The writers woken since the last call.
        fn woken(&self) -> Vec<usize> {
            (0..self.keys.len())
                .filter(|writer| self.tasks[*writer].0 .0.swap(0, Ordering::SeqCst) > 0)
                .collect()
        }
    }

    const NONE: [usize; 0] = [];

    #[test]
    fn released_writers_try_oldest_first_one_woken_at_a_time() {
        let writers = Writers::new(3);
        for writer in 0..3 {
            writers.turned_away(writer);
        }
        writers.release(&[0, 1, 2]);
        // The first release woke the newest writer; it passes the turn to
        // the oldest instead of trying.
        assert_eq!(writers.woken(), [2]);
        assert_eq!(writers.try_turn(2), None);
        assert_eq!(writers.woken(), [0]);
        assert_eq!(writers.try_turn(1), None, "not its turn");
        writers.wrote(0);
        assert_eq!(writers.woken(), [1]);
        // A released writer turned away means the space is gone: the one
        // behind it waits for quinn's next release instead of trying.
        writers.turned_away(1);
        assert_eq!(writers.woken(), NONE);
        writers.release(&[1]);
        assert_eq!(writers.woken(), [1], "it kept its place");
        writers.wrote(1);
        assert_eq!(writers.woken(), [2]);
        writers.wrote(2);
        assert_eq!(writers.woken(), NONE);
    }

    #[test]
    fn a_writer_that_wrote_lines_up_behind_the_waiting_ones() {
        let writers = Writers::new(2);
        writers.turned_away(0);
        writers.release(&[0]);
        assert_eq!(writers.woken(), [0]);
        writers.wrote(0);
        // Writer 1 waits for the turn in progress; writer 0 writes again
        // and has to line up behind it.
        writers.turned_away(1);
        writers.release(&[1]);
        assert_eq!(writers.woken(), [1]);
        assert_eq!(writers.try_turn(0), None);
        writers.wrote(1);
        assert_eq!(writers.woken(), [0]);
        assert!(writers.try_turn(0).is_some());
    }

    #[test]
    fn a_writer_quinn_has_not_released_holds_nobody_up() {
        let writers = Writers::new(2);
        // Writer 0 waits for its stream's own limit and is never released.
        writers.turned_away(0);
        writers.turned_away(1);
        writers.release(&[1]);
        assert_eq!(writers.woken(), [1]);
        assert!(writers.try_turn(1).is_some());
    }

    #[test]
    fn a_newcomer_lines_up_behind_a_turn_in_progress() {
        let writers = Writers::new(2);
        writers.turned_away(0);
        writers.release(&[0]);
        assert_eq!(writers.woken(), [0]);
        assert_eq!(writers.try_turn(1), None);
        assert_eq!(writers.woken(), NONE);
        writers.wrote(0);
        assert_eq!(writers.woken(), [1], "the turn passes to the newcomer");
        assert!(writers.try_turn(1).is_some());
    }

    #[test]
    fn a_newcomer_turned_away_passes_the_turn_on() {
        let writers = Writers::new(3);
        writers.turned_away(0);
        writers.release(&[0]);
        assert_eq!(writers.woken(), [0]);
        assert_eq!(writers.try_turn(1), None);
        assert_eq!(writers.try_turn(2), None);
        writers.wrote(0);
        assert_eq!(writers.woken(), [1]);
        // Its own stream limit may have turned it away, which says nothing
        // about the connection's space.
        writers.turned_away(1);
        assert_eq!(writers.woken(), [2]);
    }

    #[test]
    fn a_release_during_the_attempt_is_not_lost() {
        let writers = Writers::new(1);
        let ticket = writers.try_turn(0).expect("nobody is due");
        // quinn registers the waker and releases it before the outcome is
        // recorded.
        writers.turns.release(writers.keys[0]);
        writers.turns.turned_away(writers.keys[0], ticket);
        assert_eq!(writers.woken(), [0], "woken to try again");
        assert!(writers.try_turn(0).is_some());
    }

    #[test]
    fn a_leaving_writer_passes_its_turn_on() {
        let writers = Writers::new(2);
        writers.turned_away(0);
        writers.turned_away(1);
        writers.release(&[0, 1]);
        assert_eq!(writers.woken(), [1]);
        assert_eq!(writers.try_turn(1), None);
        assert_eq!(writers.woken(), [0]);
        writers.leave(0);
        assert_eq!(writers.woken(), [1]);
        assert!(writers.try_turn(1).is_some());
    }

    #[test]
    fn a_woken_writer_that_leaves_passes_the_turn_on() {
        let writers = Writers::new(2);
        writers.turned_away(0);
        writers.turned_away(1);
        writers.release(&[0, 1]);
        assert_eq!(writers.woken(), [1]);
        writers.leave(1);
        assert_eq!(writers.woken(), [0]);
        assert!(writers.try_turn(0).is_some());
    }

    #[test]
    fn the_writers_behind_a_departed_waiter_try_without_a_release() {
        let writers = Writers::new(2);
        writers.turned_away(0);
        writers.turned_away(1);
        writers.release(&[0, 1]);
        assert_eq!(writers.woken(), [1]);
        assert_eq!(writers.try_turn(1), None);
        assert_eq!(writers.woken(), [0]);
        writers.turned_away(0);
        assert_eq!(
            writers.woken(),
            NONE,
            "writer 1 waits for writer 0's release"
        );
        // quinn will not release writer 0 any more; writer 1 tries instead.
        writers.leave(0);
        assert_eq!(writers.woken(), [1]);
    }

    #[test]
    fn two_released_writers_take_their_turns_at_once() {
        let writers = Writers::with_turns_at_once(3, 2);
        for writer in 0..3 {
            writers.turned_away(writer);
        }
        writers.release(&[0, 1, 2]);
        assert_eq!(writers.woken(), [1, 2]);
        // The newest is not among the first two due writers: it hands its
        // place to the oldest.
        assert_eq!(writers.try_turn(2), None);
        assert_eq!(writers.woken(), [0]);
        assert!(writers.try_turn(1).is_some());
        assert!(writers.try_turn(0).is_some());
    }

    #[test]
    fn a_spent_release_stops_the_line_while_another_attempt_is_out() {
        let writers = Writers::with_turns_at_once(3, 2);
        for writer in 0..3 {
            writers.turned_away(writer);
        }
        writers.release(&[0, 1, 2]);
        assert_eq!(writers.try_turn(2), None);
        let first = writers.try_turn(0).expect("its turn");
        let second = writers.try_turn(1).expect("its turn");
        writers.woken();
        writers.turns.turned_away(writers.keys[1], second);
        writers.turns.wrote(writers.keys[0]);
        let _ = first;
        assert_eq!(writers.woken(), NONE, "writer 2 waits for the next release");
        writers.release(&[1]);
        assert_eq!(writers.woken(), [1, 2]);
    }
}
