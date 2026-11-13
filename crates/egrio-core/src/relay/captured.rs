//! The relay's copy for a captured TCP flow. The flow's bytes arrive as
//! slices of the captured packets and go straight to the upstream's writes;
//! the buffers read from the upstream go to the TCP engine whole, which sends
//! and retransmits from them. No copy buffer sits in between. Each direction
//! keeps the generic copy's behavior (`copy.rs`): flush the writer when the
//! reader has nothing more, shut it down after EOF, end both directions on
//! the first error, and draw on the task's cooperative budget.

use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::coop;
use tokio::time::{Instant, Sleep};

use crate::packet::tcp::CapturedTcpStream;
use crate::tcp_flow::TcpFlowIoAction;

/// Client bytes gathered per upstream write: the chunks queued now, up to
/// this many bytes and `UP_PIECES` pieces, go out in one vectored write.
/// A chunk is one captured segment's payload, so at a 1500-byte MTU writing
/// them one by one would cost a write per packet.
const UP_GATHER: usize = 64 * 1024;
const UP_PIECES: usize = 16;
/// Upstream reads go into buffers of this size; each read takes what the
/// upstream has, and the bytes leave as one chunk.
const DOWN_BUFFER: usize = 64 * 1024;
/// Below this much room a buffer is replaced before the next read, so reads
/// stay large.
const DOWN_MIN_ROOM: usize = 16 * 1024;
/// The stack read that looks for bytes once the download buffer went back
/// (see `DOWN_IDLE_RELEASE`).
const DOWN_PROBE: usize = 4 * 1024;
/// Once a burst (reads that follow each other within `DOWN_BURST_GAP`) has
/// handed the engine `DOWN_BULK` bytes, a read of less than
/// `DOWN_SMALL_READ` waits, with what it joins, up to `DOWN_HOLD` for
/// `DOWN_COALESCE` bytes before they go to the engine, when the burst's
/// rate brings the missing bytes within `DOWN_HOLD_MAX`. An upstream that yields
/// a packet's worth per read (QUIC) would otherwise make each of its
/// packets a segment of its own through the capture device: a write there,
/// then a receive and an acknowledgement in the client's stack. The client
/// acknowledges every segment at once, so waiting only while bytes are
/// unacknowledged (Nagle's algorithm) would never wait. A slower burst (under
/// about 16 MB/s) does not wait: the hold would run out every time and add
/// latency without filling a segment. Larger reads (TLS records, a socket's
/// backlog) never wait: their segments are large
/// already, and a wait per read would cost a fast flow its peak. A transfer
/// within `DOWN_BULK` never waits; a larger one's last bytes wait one
/// `DOWN_HOLD`, which a millisecond timer may round up to two. The gap is
/// wide enough that the pauses QUIC flow control causes do not restart the
/// count.
const DOWN_COALESCE: usize = 32 * 1024;
const DOWN_SMALL_READ: usize = 8 * 1024;
const DOWN_BULK: usize = 1024 * 1024;
const DOWN_BURST_GAP: Duration = Duration::from_millis(10);
const DOWN_HOLD: Duration = Duration::from_millis(1);
/// The longest a hold lasts: the millisecond timer rounds `DOWN_HOLD` up to
/// the next tick.
const DOWN_HOLD_MAX: Duration = Duration::from_millis(2);
/// An upstream quiet this long gets its read buffer back, so an idle
/// connection holds no download storage. Releasing at every pause instead
/// would give each small burst a fresh block that the engine then keeps
/// until the client acknowledges it.
const DOWN_IDLE_RELEASE: Duration = Duration::from_secs(1);

/// Copies `client` to `upstream` and back until both directions reached EOF
/// and shut their writers down; returns `(upload, download)` byte counts.
/// `client_error` records which client operation failed; the upstream's own
/// wrapper records its failures.
pub(super) async fn copy_captured<U>(
    client: &mut CapturedTcpStream,
    upstream: &mut U,
    client_error: &(dyn Fn(TcpFlowIoAction) + Sync),
) -> io::Result<(u64, u64)>
where
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut up = Up::Reading;
    let mut up_bytes = 0u64;
    let mut up_flush = false;
    let mut gathered = VecDeque::new();
    let mut down = Down::new();
    poll_fn(|cx| {
        let up_done = poll_up(
            cx,
            &mut up,
            &mut gathered,
            &mut up_bytes,
            &mut up_flush,
            client,
            upstream,
            client_error,
        )?;
        let down_done = down.poll(cx, client, upstream, client_error)?;
        // A finished direction keeps answering with its count, so waiting
        // for the other one here loses nothing.
        let up_done = ready!(up_done);
        let down_done = ready!(down_done);
        Poll::Ready(Ok((up_done, down_done)))
    })
    .await
}

enum Up {
    Reading,
    /// Writing the gathered chunks; then EOF if `eof`.
    Writing {
        eof: bool,
    },
    Flushing,
    ShuttingDown,
    Done,
}

#[allow(clippy::too_many_arguments)]
fn poll_up<U>(
    cx: &mut Context<'_>,
    state: &mut Up,
    gathered: &mut VecDeque<Bytes>,
    total: &mut u64,
    need_flush: &mut bool,
    client: &mut CapturedTcpStream,
    upstream: &mut U,
    client_error: &(dyn Fn(TcpFlowIoAction) + Sync),
) -> Poll<io::Result<u64>>
where
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let coop = ready!(coop::poll_proceed(cx));
    loop {
        match state {
            Up::Reading => match client.poll_read_chunk(cx, UP_GATHER) {
                Poll::Ready(Ok(Some(chunk))) => {
                    coop.made_progress();
                    // Take whatever else is queued already.
                    let mut bytes = chunk.len();
                    gathered.push_back(chunk);
                    let mut eof = false;
                    while bytes < UP_GATHER && gathered.len() < UP_PIECES {
                        match client.poll_read_chunk(cx, UP_GATHER - bytes) {
                            Poll::Ready(Ok(Some(chunk))) => {
                                bytes += chunk.len();
                                gathered.push_back(chunk);
                            }
                            Poll::Ready(Ok(None)) => {
                                eof = true;
                                break;
                            }
                            // Reported once the gathered bytes are written.
                            Poll::Ready(Err(_)) | Poll::Pending => break,
                        }
                    }
                    *state = Up::Writing { eof };
                }
                Poll::Ready(Ok(None)) => {
                    coop.made_progress();
                    *state = Up::Flushing;
                }
                Poll::Ready(Err(error)) => {
                    coop.made_progress();
                    client_error(TcpFlowIoAction::Read);
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    // The upstream may hold back what it was given until
                    // flushed, and its peer may answer only then.
                    if *need_flush {
                        ready!(Pin::new(&mut *upstream).poll_flush(cx))?;
                        coop.made_progress();
                        *need_flush = false;
                    }
                    return Poll::Pending;
                }
            },
            Up::Writing { eof } => {
                let eof = *eof;
                if gathered.len() > 1 && !upstream.is_write_vectored() {
                    // A writer that takes one slice per call (QUIC streams,
                    // AEAD framing) gets the chunks as one buffer: a copy
                    // instead of a write, a lock and a frame per chunk.
                    let mut merged = BytesMut::with_capacity(gathered.iter().map(Bytes::len).sum());
                    for chunk in gathered.drain(..) {
                        merged.extend_from_slice(&chunk);
                    }
                    gathered.push_back(merged.freeze());
                }
                let written = {
                    let mut slices = [IoSlice::new(&[]); UP_PIECES];
                    let count = gathered.len().min(UP_PIECES);
                    for (slice, chunk) in slices.iter_mut().zip(gathered.iter()) {
                        *slice = IoSlice::new(chunk);
                    }
                    Pin::new(&mut *upstream).poll_write_vectored(cx, &slices[..count])
                };
                match written {
                    Poll::Ready(Ok(0)) => {
                        coop.made_progress();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into writer",
                        )));
                    }
                    Poll::Ready(Ok(mut written)) => {
                        coop.made_progress();
                        *total += written as u64;
                        *need_flush = true;
                        while written > 0 {
                            let front = gathered.front_mut().expect("written bytes were gathered");
                            if front.len() <= written {
                                written -= front.len();
                                gathered.pop_front();
                            } else {
                                front.advance(written);
                                written = 0;
                            }
                        }
                        if gathered.is_empty() {
                            *state = if eof { Up::Flushing } else { Up::Reading };
                        }
                    }
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                    Poll::Ready(Err(error)) => {
                        coop.made_progress();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            Up::Flushing => {
                ready!(Pin::new(&mut *upstream).poll_flush(cx))?;
                coop.made_progress();
                *state = Up::ShuttingDown;
            }
            Up::ShuttingDown => {
                ready!(Pin::new(&mut *upstream).poll_shutdown(cx))?;
                coop.made_progress();
                *state = Up::Done;
            }
            Up::Done => return Poll::Ready(Ok(*total)),
        }
    }
}

/// The upstream-to-client direction.
struct Down {
    state: DownState,
    total: u64,
    buffer: BytesMut,
    /// The upstream's end or error, waiting behind the bytes read before it.
    then: Option<io::Result<()>>,
    /// When the upstream last had bytes.
    last_read: Instant,
    /// Wakes the copy to give the buffer back once the upstream stays quiet.
    release: Option<Pin<Box<Sleep>>>,
    /// Bytes the current burst handed the engine, and when it began.
    burst: usize,
    burst_started: Instant,
    /// Ends the wait of bytes held for more (`DOWN_HOLD`).
    hold: Option<Pin<Box<Sleep>>>,
}

enum DownState {
    Reading,
    Writing(Option<Bytes>),
    ShuttingDown,
    Done,
}

impl Down {
    fn new() -> Self {
        Self {
            state: DownState::Reading,
            total: 0,
            buffer: BytesMut::new(),
            then: None,
            last_read: Instant::now(),
            release: None,
            burst: 0,
            burst_started: Instant::now(),
            hold: None,
        }
    }

    fn poll<U>(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut CapturedTcpStream,
        upstream: &mut U,
        client_error: &(dyn Fn(TcpFlowIoAction) + Sync),
    ) -> Poll<io::Result<u64>>
    where
        U: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let coop = ready!(coop::poll_proceed(cx));
        loop {
            match &mut self.state {
                DownState::Reading => {
                    match self.then.take() {
                        Some(Ok(())) => {
                            coop.made_progress();
                            // Nothing more arrives from the upstream, and the
                            // copy lives on while the upload direction does,
                            // so the read storage goes back now rather than
                            // waiting for a quiet spell that never comes.
                            self.give_storage_back();
                            self.state = DownState::ShuttingDown;
                            continue;
                        }
                        Some(Err(error)) => {
                            coop.made_progress();
                            self.give_storage_back();
                            return Poll::Ready(Err(error));
                        }
                        None => {}
                    }
                    let before = self.buffer.len();
                    if self.buffer.capacity() == 0 {
                        // The buffer went back after a quiet spell. Every
                        // upload write wakes this copy too, so look for bytes
                        // on the stack first and allocate only for some.
                        let mut probe = [std::mem::MaybeUninit::<u8>::uninit(); DOWN_PROBE];
                        let mut read = ReadBuf::uninit(&mut probe);
                        match Pin::new(&mut *upstream).poll_read(cx, &mut read) {
                            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                                self.then = Some(Ok(()));
                            }
                            Poll::Ready(Ok(())) => {
                                self.buffer.reserve(DOWN_BUFFER);
                                self.buffer.extend_from_slice(read.filled());
                                self.total += read.filled().len() as u64;
                            }
                            Poll::Ready(Err(error))
                                if error.kind() == io::ErrorKind::Interrupted =>
                            {
                                continue;
                            }
                            Poll::Ready(Err(error)) => self.then = Some(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else if self.buffer.capacity() - self.buffer.len() < DOWN_MIN_ROOM {
                        // Reclaims the old storage once the engine dropped
                        // every chunk cut from it, and allocates otherwise.
                        self.buffer.reserve(DOWN_BUFFER);
                    }
                    // Takes everything the upstream has now, while the buffer
                    // has room: a stream that yields a few kilobytes per read
                    // (QUIC, TLS records) then hands over one chunk, not many.
                    while self.then.is_none() {
                        let mut read = ReadBuf::uninit(self.buffer.spare_capacity_mut());
                        match Pin::new(&mut *upstream).poll_read(cx, &mut read) {
                            Poll::Ready(Ok(())) => {
                                let filled = read.filled().len();
                                if filled == 0 {
                                    self.then = Some(Ok(()));
                                    break;
                                }
                                // SAFETY: the reader initialized `filled`
                                // bytes of the spare capacity it was given.
                                unsafe { self.buffer.set_len(self.buffer.len() + filled) };
                                self.total += filled as u64;
                                if self.buffer.capacity() - self.buffer.len() < DOWN_MIN_ROOM {
                                    break;
                                }
                            }
                            Poll::Ready(Err(error))
                                if error.kind() == io::ErrorKind::Interrupted => {}
                            Poll::Ready(Err(error)) => {
                                self.then = Some(Err(error));
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                    let fresh = self.buffer.len() - before;
                    if fresh > 0 {
                        let now = Instant::now();
                        if now.duration_since(self.last_read) > DOWN_BURST_GAP {
                            self.burst = 0;
                            self.burst_started = now;
                        }
                        self.last_read = now;
                    }
                    if !self.buffer.is_empty() {
                        if self.holds(cx, fresh) {
                            return Poll::Pending;
                        }
                        self.burst = self.burst.saturating_add(self.buffer.len());
                        coop.made_progress();
                        let chunk = if self.buffer.len() == self.buffer.capacity() {
                            // The reads filled the buffer: the whole storage
                            // goes with the chunk. Splitting it would leave a
                            // buffer that still holds the block it cut from
                            // while reporting no capacity, which every
                            // release below reads as storage already given
                            // back, so an idle flow kept a whole
                            // `DOWN_BUFFER`.
                            std::mem::take(&mut self.buffer).freeze()
                        } else {
                            self.buffer.split().freeze()
                        };
                        self.state = DownState::Writing(Some(chunk));
                    } else if self.then.is_none() {
                        self.release_when_quiet(cx);
                        return Poll::Pending;
                    }
                }
                DownState::Writing(chunk) => match client.poll_write_chunk(cx, chunk) {
                    Poll::Ready(Ok(())) => {
                        coop.made_progress();
                        self.state = DownState::Reading;
                    }
                    Poll::Ready(Err(error)) => {
                        coop.made_progress();
                        client_error(TcpFlowIoAction::Write);
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DownState::ShuttingDown => {
                    ready!(Pin::new(&mut *client).poll_shutdown(cx))?;
                    coop.made_progress();
                    self.state = DownState::Done;
                }
                DownState::Done => return Poll::Ready(Ok(self.total)),
            }
        }
    }

    /// Whether the bytes read so far wait for more (`DOWN_COALESCE`): only
    /// in a bulk burst whose upstream has not ended, after a small read
    /// (`fresh` bytes), when the burst's rate brings the missing bytes within
    /// `DOWN_HOLD_MAX`, and for `DOWN_HOLD` at most. A wait returns with the
    /// upstream's and the timer's wakeups registered.
    fn holds(&mut self, cx: &mut Context<'_>, fresh: usize) -> bool {
        if self.then.is_none()
            && self.burst >= DOWN_BULK
            && fresh < DOWN_SMALL_READ
            && self.buffer.len() < DOWN_COALESCE
            && fills_within_hold(
                self.burst,
                self.burst_started.elapsed(),
                DOWN_COALESCE - self.buffer.len(),
            )
        {
            let hold = self
                .hold
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(DOWN_HOLD)));
            if hold.as_mut().poll(cx).is_pending() {
                return true;
            }
        }
        self.hold = None;
        false
    }

    /// Gives the read storage and the timers back. The upstream's end reaches
    /// this copy while the upload direction keeps it alive, and
    /// [`Self::release_when_quiet`] only runs while reads are still expected,
    /// so without this a connection whose download finished held a whole
    /// `DOWN_BUFFER` until the client closed as well.
    fn give_storage_back(&mut self) {
        self.buffer = BytesMut::new();
        self.release = None;
        self.hold = None;
    }

    /// Called while the upstream has nothing: drops the read buffer once the
    /// upstream has been quiet for `DOWN_IDLE_RELEASE`, and otherwise keeps a
    /// timer that wakes the copy then. A timer armed before a later read
    /// wakes early and is pushed back, so it moves at most once per wakeup.
    fn release_when_quiet(&mut self, cx: &mut Context<'_>) {
        if self.buffer.capacity() == 0 {
            self.release = None;
            return;
        }
        let deadline = self.last_read + DOWN_IDLE_RELEASE;
        if Instant::now() >= deadline {
            self.buffer = BytesMut::new();
            self.release = None;
            return;
        }
        let timer = self
            .release
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if timer.as_mut().poll(cx).is_ready() {
            timer.as_mut().reset(deadline);
            let _ = timer.as_mut().poll(cx);
        }
    }
}

/// Whether `missing` bytes arrive within `DOWN_HOLD_MAX` at the rate of a
/// burst that brought `burst` bytes in `elapsed`.
fn fills_within_hold(burst: usize, elapsed: Duration, missing: usize) -> bool {
    // missing / (burst / elapsed) <= hold, without dividing.
    (missing as u128) * elapsed.as_micros() <= (burst as u128) * DOWN_HOLD_MAX.as_micros()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::packet::tcp::{EngineWake, FlowShared};

    /// An upstream that yields one queued piece per read, then its end, and
    /// takes every write.
    struct Pieces {
        reads: VecDeque<&'static [u8]>,
        writes: Vec<usize>,
        shut_down: bool,
    }

    impl AsyncRead for Pieces {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(piece) = self.reads.pop_front() {
                buf.put_slice(piece);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Pieces {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut_down = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn small_upstream_reads_reach_the_engine_as_one_chunk_before_the_end() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        // The client sends nothing and ends its side.
        shared.finish_recv();
        let mut upstream = Pieces {
            reads: VecDeque::from([&b"one "[..], &b"two "[..], &b"three"[..]]),
            writes: Vec::new(),
            shut_down: false,
        };
        let counts = copy_captured(&mut client, &mut upstream, &|_| {})
            .await
            .unwrap();
        assert_eq!(counts, (0, 13));
        assert!(upstream.shut_down, "the client's end reached the upstream");
        let mut written = VecDeque::new();
        assert!(
            shared.take_written(&mut written),
            "the upstream's end follows its bytes"
        );
        assert_eq!(written.len(), 1, "three reads, one chunk");
        assert_eq!(&written[0][..], b"one two three");
    }

    /// The upstream's end reaches this copy while the upload direction keeps
    /// it alive, and the quiet-spell release only runs while more reads are
    /// expected, so the read storage has to go back when the end arrives.
    #[tokio::test]
    async fn the_upstreams_end_gives_the_read_storage_back() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        // One piece, then the end: the read storage keeps the room the piece
        // left over, which no later read will use.
        let mut upstream = Pieces {
            reads: VecDeque::from([&b"hello"[..]]),
            writes: Vec::new(),
            shut_down: false,
        };
        let mut down = Down::new();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut total = None;
        for _ in 0..8 {
            if let Poll::Ready(count) = down.poll(&mut cx, &mut client, &mut upstream, &|_| {}) {
                total = Some(count.expect("the copy succeeds"));
                break;
            }
        }
        assert_eq!(total, Some(5), "the piece reached the client");
        assert_eq!(
            down.buffer.capacity(),
            0,
            "the read storage went back with the upstream's end"
        );
        assert!(
            down.release.is_none() && down.hold.is_none(),
            "no timer is left"
        );
    }

    #[tokio::test]
    async fn chunks_for_a_writer_without_vectored_writes_go_out_as_one_write() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        for byte in 1..=3u8 {
            shared.deliver(Bytes::from(vec![byte; 2000]));
        }
        shared.finish_recv();
        let mut upstream = Pieces {
            reads: VecDeque::new(),
            writes: Vec::new(),
            shut_down: false,
        };
        let counts = copy_captured(&mut client, &mut upstream, &|_| {})
            .await
            .unwrap();
        assert_eq!(counts, (6000, 0));
        assert_eq!(upstream.writes, [6000], "three chunks, one write");
        assert!(upstream.shut_down);
    }

    /// An upstream that yields its queued pieces, then has nothing more for
    /// now without ending.
    struct Quiet {
        reads: VecDeque<&'static [u8]>,
    }

    impl AsyncRead for Quiet {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.reads.pop_front() {
                Some(piece) => {
                    // A read never takes more than its room; the rest waits.
                    let take = piece.len().min(buf.remaining());
                    buf.put_slice(&piece[..take]);
                    if take < piece.len() {
                        self.reads.push_front(&piece[take..]);
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for Quiet {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Polls the download direction once; returns whether it is pending.
    async fn poll_once<U: AsyncRead + AsyncWrite + Unpin>(
        down: &mut Down,
        client: &mut CapturedTcpStream,
        upstream: &mut U,
    ) -> bool {
        std::future::poll_fn(|cx| {
            Poll::Ready(down.poll(cx, client, upstream, &|_| {}).is_pending())
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn small_reads_wait_for_more_once_a_burst_is_bulk() {
        static PIECE: [u8; 16 * 1024] = [7; 16 * 1024];
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        let mut upstream = Quiet {
            reads: VecDeque::new(),
        };
        let mut down = Down::new();
        let mut written = VecDeque::new();
        // A short response goes out read by read; the client acknowledges
        // it, so the send buffer never fills.
        for _ in 0..DOWN_BULK / PIECE.len() {
            upstream.reads.push_back(&PIECE[..]);
            assert!(poll_once(&mut down, &mut client, &mut upstream).await);
            shared.take_written(&mut written);
            assert_eq!(written.len(), 1, "nothing waits below the bulk mark");
            written.clear();
            shared.acknowledged(PIECE.len());
        }
        // The burst is bulk now: a small read waits, then goes out.
        upstream.reads.push_back(&b"tail"[..]);
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert!(written.is_empty(), "the read waits for more");
        upstream.reads.push_back(&b" end"[..]);
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert!(written.is_empty());
        tokio::time::advance(DOWN_HOLD).await;
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert_eq!(&written.pop_front().unwrap()[..], b"tail end");
        // A large read never waits.
        upstream.reads.push_back(&PIECE[..]);
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert_eq!(written.pop_front().unwrap().len(), PIECE.len());
        // A pause ends the burst: the next small read goes out at once.
        tokio::time::advance(DOWN_BURST_GAP * 2).await;
        upstream.reads.push_back(&b"next"[..]);
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert_eq!(&written.pop_front().unwrap()[..], b"next");
    }

    #[test]
    fn a_hold_waits_only_for_bytes_the_burst_rate_brings_in_time() {
        let mib = 1024 * 1024;
        // 1 MiB in 10 ms: 32 KiB come in a third of a millisecond.
        assert!(fills_within_hold(
            mib,
            Duration::from_millis(10),
            DOWN_COALESCE
        ));
        // 1 MiB in 40 ms, 26 MB/s: in 1.25 ms, within what a hold lasts.
        assert!(fills_within_hold(
            mib,
            Duration::from_millis(40),
            DOWN_COALESCE
        ));
        // 1 MiB in 100 ms: they would take three.
        assert!(!fills_within_hold(
            mib,
            Duration::from_millis(100),
            DOWN_COALESCE
        ));
        assert!(fills_within_hold(mib, Duration::ZERO, DOWN_COALESCE));
    }

    #[tokio::test(start_paused = true)]
    async fn small_reads_of_a_slow_burst_go_out_at_once() {
        static PIECE: [u8; 16 * 1024] = [7; 16 * 1024];
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        let mut upstream = Quiet {
            reads: VecDeque::new(),
        };
        let mut down = Down::new();
        let mut written = VecDeque::new();
        // About 10 MB/s: a bulk burst whose next 32 KiB would take longer
        // than a hold.
        for _ in 0..DOWN_BULK / PIECE.len() {
            tokio::time::advance(Duration::from_micros(1500)).await;
            upstream.reads.push_back(&PIECE[..]);
            assert!(poll_once(&mut down, &mut client, &mut upstream).await);
            shared.take_written(&mut written);
            written.clear();
            shared.acknowledged(PIECE.len());
        }
        tokio::time::advance(Duration::from_micros(1500)).await;
        upstream.reads.push_back(&b"tail"[..]);
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        shared.take_written(&mut written);
        assert_eq!(&written.pop_front().unwrap()[..], b"tail");
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_upstream_gives_its_read_buffer_back() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        let mut upstream = Quiet {
            reads: VecDeque::from([&b"response"[..]]),
        };
        let mut down = Down::new();
        assert!(
            poll_once(&mut down, &mut client, &mut upstream).await,
            "the upstream has nothing more yet"
        );
        let mut written = VecDeque::new();
        shared.take_written(&mut written);
        assert_eq!(&written[0][..], b"response");
        // A pause shorter than the release delay keeps the buffer.
        tokio::time::advance(DOWN_IDLE_RELEASE / 2).await;
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        assert!(down.buffer.capacity() > 0);
        tokio::time::advance(DOWN_IDLE_RELEASE).await;
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        assert_eq!(
            down.buffer.capacity(),
            0,
            "an idle flow holds no read buffer"
        );
        assert!(down.release.is_none());
    }

    /// An upstream that records how much room each read offers, yields its
    /// queued bytes as far as the room goes, and otherwise has nothing yet.
    struct Offered {
        reads: VecDeque<u8>,
        offered: Vec<usize>,
    }

    impl AsyncRead for Offered {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.offered.push(buf.remaining());
            if self.reads.is_empty() {
                return Poll::Pending;
            }
            let take = buf.remaining().min(self.reads.len());
            let piece: Vec<u8> = self.reads.drain(..take).collect();
            buf.put_slice(&piece);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Offered {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Once the buffer went back, a wakeup that finds no bytes (as every
    /// upload write's does) reads into the stack, not a fresh buffer; bytes
    /// that come later still arrive whole through a full-size buffer.
    #[tokio::test(start_paused = true)]
    async fn a_released_buffer_is_not_taken_back_for_wakeups_without_bytes() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        let mut upstream = Offered {
            reads: VecDeque::from(b"response".to_vec()),
            offered: Vec::new(),
        };
        let mut down = Down::new();
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        tokio::time::advance(DOWN_IDLE_RELEASE * 2).await;
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        assert_eq!(down.buffer.capacity(), 0);

        upstream.offered.clear();
        for _ in 0..1000 {
            assert!(poll_once(&mut down, &mut client, &mut upstream).await);
            assert_eq!(down.buffer.capacity(), 0);
        }
        assert!(
            upstream.offered.iter().all(|&room| room == DOWN_PROBE),
            "each empty wakeup reads into the stack probe"
        );

        let body: Vec<u8> = (0..20_000_u32).map(|i| i as u8).collect();
        upstream.reads.extend(body.iter().copied());
        assert!(poll_once(&mut down, &mut client, &mut upstream).await);
        assert!(down.buffer.capacity() > 0, "bytes take the buffer back");
        let mut written = VecDeque::new();
        shared.take_written(&mut written);
        let delivered: Vec<u8> = written
            .iter()
            .skip(1)
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert_eq!(delivered, body);
    }
    /// A read that filled the buffer hands its whole storage over: splitting
    /// there would leave a `BytesMut` that still holds the block it cut from
    /// while reporting no capacity, and every release path reads no capacity
    /// as storage already given back, so an idle flow kept a whole
    /// `DOWN_BUFFER`.
    #[tokio::test]
    async fn a_filled_read_buffer_hands_its_whole_storage_over() {
        let shared = Arc::new(FlowShared::new(0, Arc::new(EngineWake::default())));
        let address = "10.0.0.2:40000".parse().unwrap();
        let mut client = CapturedTcpStream::new(
            address,
            address,
            crate::attribution::ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        // Enough bytes to fill a whole DOWN_BUFFER and no more, so the reads
        // leave the buffer with its length at its capacity.
        static FILL: [u8; DOWN_BUFFER] = [9; DOWN_BUFFER];
        let mut upstream = Quiet {
            reads: VecDeque::from([&FILL[..]]),
        };
        let mut down = Down::new();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(down
            .poll(&mut cx, &mut client, &mut upstream, &|_| {})
            .is_pending());

        let mut written = VecDeque::new();
        shared.take_written(&mut written);
        assert_eq!(
            written.iter().map(Bytes::len).sum::<usize>(),
            DOWN_BUFFER,
            "the whole buffer reached the engine"
        );
        assert!(
            written.iter().all(Bytes::is_unique),
            "no handle on the read storage is left behind"
        );
        assert_eq!(
            down.buffer.capacity(),
            0,
            "and the buffer reports none, truthfully"
        );
    }
}
