//! The handoff between the TCP engine and one flow's relay, and the stream
//! the relay holds.
//!
//! Bytes cross as reference-counted chunks: the engine queues slices of the
//! captured packets for the relay to write upstream, and the relay hands the
//! engine the buffers it read from upstream, which the engine sends and keeps
//! for retransmission until the client acknowledges them. Each side wakes the
//! other only when that side waits: the relay when its queue turns non-empty
//! or the send buffer gains room, the engine when written bytes arrive at an
//! empty queue, enough bytes were consumed to reopen the receive window, or a
//! close flag flips.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::attribution::{ClientOwner, ProcessInfo};

/// The send buffer's floor: bytes the relay may have written that the
/// client has not acknowledged, which bound a flow's download bytes in the
/// engine. The engine raises the limit toward its windows' ceiling
/// (`Windows::send_max` in `budget.rs`) while the peer's window lets more be
/// in flight. A flow holding none of those bytes has no buffer at all; its
/// relay may write one chunk regardless.
pub(crate) const MIN_SEND_BUFFER: usize = 1024 * 1024;
/// Payloads up to this size are copied into a shared buffer instead of being
/// queued as their own chunks, so a flood of tiny segments costs memory in
/// proportion to its bytes, not its count.
const SMALL_PAYLOAD: usize = 1024;
/// The shared buffer small payloads are copied into.
const SMALL_BUFFER: usize = 16 * 1024;

/// One direction's waker slot.
#[derive(Debug, Default)]
struct WakerSlot {
    waker: Mutex<Option<Waker>>,
}

impl WakerSlot {
    fn register(&self, waker: &Waker) {
        let mut slot = self.waker.lock().expect("tcp stream waker slot");
        match slot.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    /// Wakes the waiting task; returns whether one was waiting.
    fn wake(&self) -> bool {
        let waker = self.waker.lock().expect("tcp stream waker slot").take();
        let waiting = waker.is_some();
        if let Some(waker) = waker {
            waker.wake();
        }
        waiting
    }
}

/// How a flow's receive side ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvEnd {
    Open,
    /// The client's FIN: reads return EOF once the queue is drained.
    Eof,
    /// The connection was reset or aborted: reads fail.
    Reset,
}

#[derive(Debug)]
struct RecvQueue {
    chunks: VecDeque<Bytes>,
    /// Small payloads accumulate here, after every chunk in `chunks`.
    small: BytesMut,
    len: usize,
    end: RecvEnd,
    /// The engine wants a call once the queue holds at most this many bytes:
    /// the relay has read enough for a window update. `None` while it wants
    /// none.
    wake_at: Option<usize>,
}

impl RecvQueue {
    fn push(&mut self, payload: Bytes) {
        self.len += payload.len();
        if payload.len() <= SMALL_PAYLOAD {
            if self.small.capacity() - self.small.len() < payload.len() {
                self.flush_small();
                self.small.reserve(SMALL_BUFFER);
            }
            self.small.extend_from_slice(&payload);
        } else {
            self.flush_small();
            self.chunks.push_back(payload);
        }
    }

    fn flush_small(&mut self) {
        if !self.small.is_empty() {
            let filled = self.small.split().freeze();
            self.chunks.push_back(filled);
        }
    }

    fn pop(&mut self, limit: usize) -> Option<Bytes> {
        if self.chunks.is_empty() {
            self.flush_small();
        }
        let front = self.chunks.front_mut()?;
        let chunk = if front.len() > limit {
            front.split_to(limit)
        } else {
            self.chunks.pop_front().expect("front chunk")
        };
        self.len -= chunk.len();
        if self.len == 0 {
            // A drained queue keeps no coalescing storage, so an idle flow
            // holds no buffer.
            self.small = BytesMut::new();
        }
        Some(chunk)
    }
}

/// Why the send side stopped taking bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendEnd {
    Open,
    /// The relay shut its write half down; the engine sends FIN after the
    /// queued bytes.
    Shutdown,
    /// The connection is gone; writes fail.
    Closed,
}

#[derive(Debug)]
struct SendQueue {
    chunks: VecDeque<Bytes>,
    end: SendEnd,
}

/// The wakeup path between flows and the engine: flows that need the
/// engine's attention, the notification its driver waits on, and a count of
/// the work the engine handed the relays.
#[derive(Debug, Default)]
pub(crate) struct EngineWake {
    pub(crate) notify: Notify,
    pending: Mutex<Vec<usize>>,
    handoffs: AtomicU64,
}

impl EngineWake {
    /// The flows that asked for attention since the last call.
    pub(crate) fn take_pending(&self, into: &mut Vec<usize>) {
        let mut pending = self.pending.lock().expect("tcp engine wake list");
        into.append(&mut pending);
    }

    /// How often the engine has handed the relays work: delivered client
    /// bytes, or woke a relay task that waited. The driver yields after a
    /// turn that did, so the relays run before it goes on.
    pub(crate) fn handoffs(&self) -> u64 {
        self.handoffs.load(Ordering::Relaxed)
    }
}

/// State one flow's relay and the engine share.
#[derive(Debug)]
pub(crate) struct FlowShared {
    /// The engine's slot for the flow.
    slot: usize,
    recv: Mutex<RecvQueue>,
    send: Mutex<SendQueue>,
    /// Bytes the relay wrote that the client has not acknowledged.
    send_held: AtomicUsize,
    /// How many bytes `send_held` may reach; the engine sets it.
    send_limit: AtomicUsize,
    /// The length of the chunk a waiting writer holds; 0 while none waits.
    send_wanted: AtomicUsize,
    recv_waker: WakerSlot,
    send_waker: WakerSlot,
    /// The handshake completed: set at once for an accepted flow, by the
    /// engine for one it opened.
    established: AtomicBool,
    /// The relay dropped its stream.
    dropped: AtomicBool,
    /// The flow is refused: the engine answers the client with RST.
    reset_requested: AtomicBool,
    /// The flow is in the engine's attention list.
    scheduled: AtomicBool,
    engine: Arc<EngineWake>,
}

impl FlowShared {
    pub(crate) fn new(slot: usize, engine: Arc<EngineWake>) -> Self {
        Self {
            slot,
            recv: Mutex::new(RecvQueue {
                chunks: VecDeque::new(),
                small: BytesMut::new(),
                len: 0,
                end: RecvEnd::Open,
                wake_at: None,
            }),
            send: Mutex::new(SendQueue {
                chunks: VecDeque::new(),
                end: SendEnd::Open,
            }),
            send_held: AtomicUsize::new(0),
            send_limit: AtomicUsize::new(MIN_SEND_BUFFER),
            send_wanted: AtomicUsize::new(0),
            recv_waker: WakerSlot::default(),
            send_waker: WakerSlot::default(),
            established: AtomicBool::new(true),
            dropped: AtomicBool::new(false),
            reset_requested: AtomicBool::new(false),
            scheduled: AtomicBool::new(false),
            engine,
        }
    }

    /// Puts the flow on the engine's attention list and wakes its driver.
    fn schedule(&self) {
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            self.engine
                .pending
                .lock()
                .expect("tcp engine wake list")
                .push(self.slot);
            self.engine.notify.notify_one();
        }
    }

    fn hand_off(&self) {
        self.engine.handoffs.fetch_add(1, Ordering::Relaxed);
    }

    /// Wakes the relay task waiting in `slot`, if one is.
    fn wake_relay(&self, slot: &WakerSlot) {
        if slot.wake() {
            self.hand_off();
        }
    }

    /// Called by the engine as it attends to the flow, before it looks at
    /// anything: later events schedule it again.
    pub(crate) fn unschedule(&self) {
        self.scheduled.store(false, Ordering::Release);
    }

    /// Shared state for a flow the engine opens: not established until the
    /// peer's SYN|ACK.
    pub(crate) fn opening(slot: usize, engine: Arc<EngineWake>) -> Self {
        let shared = Self::new(slot, engine);
        shared.established.store(false, Ordering::Release);
        shared
    }

    // Engine side.

    /// The handshake of a flow the engine opened completed.
    pub(crate) fn establish(&self) {
        self.established.store(true, Ordering::Release);
        self.wake_relay(&self.send_waker);
    }

    /// Queues in-order client bytes for the relay.
    pub(crate) fn deliver(&self, payload: Bytes) {
        let mut recv = self.recv.lock().expect("tcp recv queue");
        let was_empty = recv.len == 0;
        recv.push(payload);
        drop(recv);
        self.hand_off();
        if was_empty {
            self.recv_waker.wake();
        }
    }

    /// The client's FIN: no more bytes follow.
    pub(crate) fn finish_recv(&self) {
        let mut recv = self.recv.lock().expect("tcp recv queue");
        if recv.end == RecvEnd::Open {
            recv.end = RecvEnd::Eof;
        }
        drop(recv);
        self.wake_relay(&self.recv_waker);
    }

    /// Client bytes queued for the relay.
    pub(crate) fn recv_queued(&self) -> usize {
        self.recv.lock().expect("tcp recv queue").len
    }

    /// Asks for a call once the relay's reads leave at most `level` bytes
    /// queued, or stops asking. Checked under the queue lock, so reads racing
    /// with the request cannot slip past it.
    pub(crate) fn wake_when_queued_at_most(&self, level: Option<usize>) {
        let mut recv = self.recv.lock().expect("tcp recv queue");
        let reached = level.is_some_and(|level| recv.len <= level);
        recv.wake_at = if reached { None } else { level };
        drop(recv);
        if reached {
            self.schedule();
        }
    }

    /// Moves the relay's written chunks to `into`; returns whether the relay
    /// shut its write half down.
    pub(crate) fn take_written(&self, into: &mut VecDeque<Bytes>) -> bool {
        let mut send = self.send.lock().expect("tcp send queue");
        into.append(&mut send.chunks);
        send.end == SendEnd::Shutdown
    }

    /// The client acknowledged `bytes` of the relay's data. A waiting writer
    /// is woken once its chunk fits.
    pub(crate) fn acknowledged(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.send_held.fetch_sub(bytes, Ordering::SeqCst);
        self.wake_writer_if_it_fits();
    }

    /// Sets how many unacknowledged bytes the relay may have written; a
    /// waiting writer whose chunk fits under a raised limit is woken.
    pub(crate) fn set_send_limit(&self, limit: usize) {
        if self.send_limit.swap(limit, Ordering::SeqCst) < limit {
            self.wake_writer_if_it_fits();
        }
    }

    fn wake_writer_if_it_fits(&self) {
        let wanted = self.send_wanted.load(Ordering::SeqCst);
        if wanted == 0 {
            return;
        }
        let held = self.send_held.load(Ordering::SeqCst);
        if held == 0 || held + wanted <= self.send_limit.load(Ordering::SeqCst) {
            self.send_wanted.store(0, Ordering::SeqCst);
            self.wake_relay(&self.send_waker);
        }
    }

    pub(crate) fn is_dropped(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }

    pub(crate) fn is_reset_requested(&self) -> bool {
        self.reset_requested.load(Ordering::Acquire)
    }

    /// Ends both directions. A reset makes the relay's reads and writes
    /// fail; a graceful close leaves reads to finish with EOF.
    pub(crate) fn close(&self, reset: bool) {
        {
            let mut recv = self.recv.lock().expect("tcp recv queue");
            if reset {
                recv.end = RecvEnd::Reset;
            } else if recv.end == RecvEnd::Open {
                recv.end = RecvEnd::Eof;
            }
        }
        self.send.lock().expect("tcp send queue").end = SendEnd::Closed;
        self.wake_relay(&self.recv_waker);
        self.wake_relay(&self.send_waker);
    }

    // Relay side.

    /// Ready once the handshake completed; an error once the flow ended
    /// first: refused, unreachable, or never answered.
    fn poll_established(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.established.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        // Registered before the checks below, so an establishment or a
        // close racing with them finds the waker.
        self.send_waker.register(cx.waker());
        if self.established.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        if self.send.lock().expect("tcp send queue").end == SendEnd::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the peer refused the connection or did not answer",
            )));
        }
        Poll::Pending
    }

    fn poll_read_chunk(
        &self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let mut recv = self.recv.lock().expect("tcp recv queue");
        if let Some(chunk) = recv.pop(limit) {
            let wake = recv.wake_at.is_some_and(|level| recv.len <= level);
            if wake {
                recv.wake_at = None;
            }
            drop(recv);
            if wake {
                self.schedule();
            }
            return Poll::Ready(Ok(Some(chunk)));
        }
        match recv.end {
            RecvEnd::Eof => Poll::Ready(Ok(None)),
            RecvEnd::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            RecvEnd::Open => {
                // Registered under the queue lock, so a delivery after this
                // point finds the waker.
                self.recv_waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_write_chunk(
        &self,
        cx: &mut Context<'_>,
        chunk: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        let Some(bytes) = chunk.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        let length = bytes.len();
        if length == 0 {
            chunk.take();
            return Poll::Ready(Ok(()));
        }
        let mut send = self.send.lock().expect("tcp send queue");
        if send.end != SendEnd::Open {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let fits = |shared: &Self| {
            let held = shared.send_held.load(Ordering::SeqCst);
            held == 0 || held + length <= shared.send_limit.load(Ordering::SeqCst)
        };
        if !fits(self) {
            self.send_waker.register(cx.waker());
            self.send_wanted.store(length, Ordering::SeqCst);
            // Re-check after announcing the wait: an acknowledgement or a
            // raised limit before the announcement made room without seeing it.
            if !fits(self) {
                return Poll::Pending;
            }
            self.send_wanted.store(0, Ordering::SeqCst);
        }
        self.send_held.fetch_add(length, Ordering::SeqCst);
        let was_empty = send.chunks.is_empty();
        send.chunks.push_back(chunk.take().expect("chunk to write"));
        drop(send);
        if was_empty {
            self.schedule();
        }
        Poll::Ready(Ok(()))
    }

    fn shutdown_write(&self) {
        let mut send = self.send.lock().expect("tcp send queue");
        if send.end == SendEnd::Open {
            send.end = SendEnd::Shutdown;
        }
        drop(send);
        self.schedule();
    }
}

/// One captured TCP flow as the relay sees it.
#[derive(Debug)]
pub(crate) struct CapturedTcpStream {
    client: SocketAddr,
    target: SocketAddr,
    owner: ClientOwner,
    shared: Arc<FlowShared>,
}

impl CapturedTcpStream {
    pub(crate) fn new(
        client: SocketAddr,
        target: SocketAddr,
        owner: ClientOwner,
        shared: Arc<FlowShared>,
    ) -> Self {
        Self {
            client,
            target,
            owner,
            shared,
        }
    }

    pub(crate) fn client_addr(&self) -> SocketAddr {
        self.client
    }

    pub(crate) fn target_addr(&self) -> SocketAddr {
        self.target
    }

    /// The owner of the client socket, if the attribution gate already
    /// knows it.
    pub(crate) fn process(&self) -> Option<&Arc<ProcessInfo>> {
        self.owner.known()
    }

    /// The owner as the gate handed it on, known or still being looked up;
    /// the stream keeps an unknown one.
    pub(crate) fn take_owner(&mut self) -> ClientOwner {
        std::mem::replace(&mut self.owner, ClientOwner::Known(None))
    }

    /// A handle that refuses this flow with an RST, as a server refusing the
    /// connection would, instead of the FIN a dropped stream gets.
    /// Waits for the handshake of a flow the engine opened.
    pub(crate) async fn established(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.shared.poll_established(cx)).await
    }

    pub(crate) fn reset_handle(&self) -> CapturedTcpReset {
        CapturedTcpReset(Arc::clone(&self.shared))
    }

    /// The next chunk of client bytes, at most `limit` long; `None` at EOF.
    pub(crate) fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<io::Result<Option<Bytes>>> {
        self.shared.poll_read_chunk(cx, limit)
    }

    /// Hands `chunk` to the engine once the send buffer has room for it;
    /// takes it out of the option when it does.
    pub(crate) fn poll_write_chunk(
        &mut self,
        cx: &mut Context<'_>,
        chunk: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        self.shared.poll_write_chunk(cx, chunk)
    }
}

/// Refuses one captured flow; see [`CapturedTcpStream::reset_handle`].
#[derive(Debug)]
pub(crate) struct CapturedTcpReset(Arc<FlowShared>);

impl CapturedTcpReset {
    pub(crate) fn reset(self) {
        self.0.reset_requested.store(true, Ordering::Release);
        self.0.schedule();
    }
}

impl Drop for CapturedTcpStream {
    fn drop(&mut self) {
        // The engine sends what was written, then FIN; client bytes arriving
        // after this get an RST (RFC 1122 section 4.2.2.13).
        self.shared.dropped.store(true, Ordering::Release);
        self.shared.schedule();
    }
}

impl AsyncRead for CapturedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let limit = buf.remaining();
        if limit == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(chunk) = std::task::ready!(self.poll_read_chunk(cx, limit))? {
            buf.put_slice(&chunk);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CapturedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = buf.len().min(MIN_SEND_BUFFER);
        let mut chunk = Some(Bytes::copy_from_slice(&buf[..length]));
        match self.shared.poll_write_chunk(cx, &mut chunk) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(length)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.shutdown_write();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn flow() -> (CapturedTcpStream, Arc<FlowShared>, Arc<EngineWake>) {
        let engine = Arc::new(EngineWake::default());
        let shared = Arc::new(FlowShared::new(7, Arc::clone(&engine)));
        let stream = CapturedTcpStream::new(
            "10.0.0.2:53123".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            ClientOwner::Known(None),
            Arc::clone(&shared),
        );
        (stream, shared, engine)
    }

    fn pending(engine: &EngineWake) -> Vec<usize> {
        let mut slots = Vec::new();
        engine.take_pending(&mut slots);
        slots
    }

    #[tokio::test]
    async fn delivered_bytes_read_in_order_then_eof() {
        let (mut stream, shared, _engine) = flow();
        shared.deliver(Bytes::from_static(b"tiny "));
        shared.deliver(Bytes::from(vec![b'x'; 2000]));
        shared.deliver(Bytes::from_static(b" tail"));
        shared.finish_recv();
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(&read[..5], b"tiny ");
        assert!(read[5..2005].iter().all(|byte| *byte == b'x'));
        assert_eq!(&read[2005..], b" tail");
        assert_eq!(shared.recv_queued(), 0);
    }

    #[tokio::test]
    async fn a_reset_fails_reads_and_writes() {
        let (mut stream, shared, _engine) = flow();
        shared.close(true);
        let mut buf = [0u8; 4];
        let error = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let error = stream.write(b"late").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn writes_wait_for_send_buffer_room() {
        let (mut stream, shared, engine) = flow();
        stream.write_all(&vec![1u8; MIN_SEND_BUFFER]).await.unwrap();
        assert_eq!(
            pending(&engine),
            vec![7],
            "the first write schedules the flow"
        );
        shared.unschedule();

        let mut chunk = Some(Bytes::from_static(b"more"));
        let blocked = poll_fn(|cx| Poll::Ready(stream.poll_write_chunk(cx, &mut chunk))).await;
        assert!(blocked.is_pending(), "a full send buffer holds the writer");

        let mut taken = VecDeque::new();
        assert!(!shared.take_written(&mut taken));
        assert_eq!(taken.iter().map(Bytes::len).sum::<usize>(), MIN_SEND_BUFFER);
        shared.acknowledged(4);
        let ready = poll_fn(|cx| Poll::Ready(stream.poll_write_chunk(cx, &mut chunk))).await;
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert!(chunk.is_none());
    }

    #[tokio::test]
    async fn the_engine_counts_the_work_it_hands_the_relay() {
        let (mut stream, shared, engine) = flow();
        shared.deliver(Bytes::from_static(b"unread"));
        assert_eq!(engine.handoffs(), 1, "delivered bytes count");
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 6);

        stream.write_all(&vec![1u8; MIN_SEND_BUFFER]).await.unwrap();
        shared.acknowledged(4);
        assert_eq!(engine.handoffs(), 1, "no write waited for the room");
        let mut chunk = Some(Bytes::from(vec![2u8; 8]));
        let blocked = poll_fn(|cx| Poll::Ready(stream.poll_write_chunk(cx, &mut chunk))).await;
        assert!(blocked.is_pending());
        shared.acknowledged(4);
        assert_eq!(engine.handoffs(), 2, "the waiting write was woken");
    }

    #[tokio::test]
    async fn a_drained_queue_keeps_no_coalescing_buffer() {
        let (mut stream, shared, _engine) = flow();
        shared.deliver(Bytes::from_static(b"small request"));
        assert!(shared.recv.lock().unwrap().small.capacity() > 0);
        let mut buf = [0u8; 64];
        let read = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], b"small request");
        assert_eq!(shared.recv.lock().unwrap().small.capacity(), 0);
    }

    #[tokio::test]
    async fn a_raised_send_limit_admits_a_waiting_writer() {
        let (mut stream, shared, _engine) = flow();
        stream.write_all(&vec![1u8; MIN_SEND_BUFFER]).await.unwrap();
        let mut chunk = Some(Bytes::from(vec![2u8; 4096]));
        let blocked = poll_fn(|cx| Poll::Ready(stream.poll_write_chunk(cx, &mut chunk))).await;
        assert!(blocked.is_pending());
        shared.set_send_limit(MIN_SEND_BUFFER + 4096);
        let ready = poll_fn(|cx| Poll::Ready(stream.poll_write_chunk(cx, &mut chunk))).await;
        assert!(matches!(ready, Poll::Ready(Ok(()))));
    }

    #[tokio::test]
    async fn reading_down_to_the_requested_level_schedules_the_engine_once() {
        let (mut stream, shared, engine) = flow();
        shared.deliver(Bytes::from(vec![0u8; 4096]));
        shared.wake_when_queued_at_most(Some(1000));
        let mut buf = [0u8; 2048];
        stream.read_exact(&mut buf).await.unwrap();
        assert!(pending(&engine).is_empty());
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(pending(&engine), vec![7]);
        shared.unschedule();
        shared.deliver(Bytes::from(vec![0u8; 4096]));
        stream.read_exact(&mut buf).await.unwrap();
        assert!(pending(&engine).is_empty(), "the request was used up");
    }

    #[tokio::test]
    async fn a_level_already_reached_schedules_the_engine_at_once() {
        let (_stream, shared, engine) = flow();
        shared.deliver(Bytes::from(vec![0u8; 500]));
        shared.wake_when_queued_at_most(Some(1000));
        assert_eq!(
            pending(&engine),
            vec![7],
            "reads finished before the request"
        );
    }

    #[tokio::test]
    async fn shutdown_and_drop_reach_the_engine() {
        let (mut stream, shared, engine) = flow();
        stream.write_all(b"last").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut taken = VecDeque::new();
        assert!(
            shared.take_written(&mut taken),
            "shutdown follows the bytes"
        );
        assert_eq!(taken.len(), 1);
        assert_eq!(pending(&engine), vec![7]);
        shared.unschedule();
        drop(stream);
        assert!(shared.is_dropped());
        assert_eq!(pending(&engine), vec![7]);
    }
}
