//! Bidirectional copy whose buffers exist only while bytes are in flight.
//!
//! Each direction runs the same state machine as Tokio's
//! `copy_bidirectional` (tokio 1.54 `io/util/copy.rs` and
//! `copy_bidirectional.rs`): read into the buffer, write it out, flush when
//! the reader has nothing more, shut the writer down after EOF, and end both
//! directions on the first error; reads and writes draw on the task's
//! cooperative budget. The difference is the buffer: a direction borrows it
//! from a pool when it reads and returns it as soon as the reader is pending
//! with nothing left to write, so an idle connection holds none.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::coop;

use crate::buffer_pool::{BufferPool, PooledBuffer};

/// Copy buffer per direction while bytes move: a busy connection holds two.
const RELAY_BUFFER_SIZE: usize = 64 * 1024;

/// Returned relay buffers kept for the next busy direction.
static RELAY_BUFFERS: BufferPool = BufferPool::new(RELAY_BUFFER_SIZE, 16);

/// Borrows of the relay pool served from its free list, and borrows that had
/// to allocate: the instrument that presses many sessions at once reads this
/// to say whether what the pool keeps covers the directions asking together.
#[cfg(feature = "bench-internals")]
pub fn relay_buffer_borrows() -> (usize, usize) {
    RELAY_BUFFERS.borrows()
}

/// Copies `a` to `b` and `b` to `a` until both directions reached EOF and
/// shut their writers down; returns the byte counts `(a→b, b→a)`.
pub(super) async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_with(&RELAY_BUFFERS, a, b).await
}

async fn copy_bidirectional_with<A, B>(
    pool: &'static BufferPool,
    a: &mut A,
    b: &mut B,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = Transfer::Running(Direction::new(pool));
    let mut b_to_a = Transfer::Running(Direction::new(pool));
    poll_fn(|cx| {
        let a_to_b = a_to_b.poll(cx, a, b)?;
        let b_to_a = b_to_a.poll(cx, b, a)?;
        // A finished direction keeps answering with its count, so returning
        // early here loses nothing.
        let a_to_b = ready!(a_to_b);
        let b_to_a = ready!(b_to_a);
        Poll::Ready(Ok((a_to_b, b_to_a)))
    })
    .await
}

enum Transfer {
    Running(Direction),
    ShuttingDown(u64),
    Done(u64),
}

impl Transfer {
    fn poll<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut reader = Pin::new(reader);
        let mut writer = Pin::new(writer);
        loop {
            match self {
                Self::Running(direction) => {
                    let count = ready!(direction.poll_copy(cx, reader.as_mut(), writer.as_mut()))?;
                    *self = Self::ShuttingDown(count);
                }
                Self::ShuttingDown(count) => {
                    ready!(writer.as_mut().poll_shutdown(cx))?;
                    *self = Self::Done(*count);
                }
                Self::Done(count) => return Poll::Ready(Ok(*count)),
            }
        }
    }
}

struct Direction {
    pool: &'static BufferPool,
    /// Present while bytes are being read or written.
    buffer: Option<PooledBuffer>,
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
}

impl Direction {
    fn new(pool: &'static BufferPool) -> Self {
        Self {
            pool,
            buffer: None,
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
        }
    }

    fn poll_fill_buf<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let pool = self.pool;
        let buffer = self.buffer.get_or_insert_with(|| pool.take());
        let mut buf = ReadBuf::new(buffer);
        buf.set_filled(self.cap);
        let result = loop {
            match reader.as_mut().poll_read(cx, &mut buf) {
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        };
        if let Poll::Ready(Ok(())) = result {
            let filled = buf.filled().len();
            self.read_done = self.cap == filled;
            self.cap = filled;
        }
        result
    }

    fn poll_write_buf<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            let buffer = self.buffer.as_ref().expect("buffered bytes have a buffer");
            match writer.as_mut().poll_write(cx, &buffer[self.pos..self.cap]) {
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Pending => {
                    // Top the buffer up while the writer is busy, for a
                    // larger write next time.
                    if !self.read_done && self.cap < self.pool.size() {
                        ready!(self.poll_fill_buf(cx, reader.as_mut()))?;
                    }
                    return Poll::Pending;
                }
                result => return result,
            }
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let coop = ready!(coop::poll_proceed(cx));
        loop {
            if self.cap < self.pool.size() && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut()) {
                    Poll::Ready(Ok(())) => coop.made_progress(),
                    Poll::Ready(Err(error)) => {
                        coop.made_progress();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => {
                        // With bytes still buffered, go on to write them.
                        if self.pos == self.cap {
                            // The reader may be waiting on what the writer
                            // still buffers.
                            if self.need_flush {
                                ready!(writer.as_mut().poll_flush(cx))?;
                                coop.made_progress();
                                self.need_flush = false;
                            }
                            // Nothing to read and nothing to write: the
                            // buffer goes back until bytes arrive.
                            self.buffer = None;
                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                let written = ready!(self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()))?;
                coop.made_progress();
                if written == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                }
                self.pos += written;
                self.amt += written as u64;
                self.need_flush = true;
            }
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );
            self.pos = 0;
            self.cap = 0;

            if self.read_done {
                self.buffer = None;
                ready!(writer.as_mut().poll_flush(cx))?;
                coop.made_progress();
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, BufWriter};

    use super::*;

    #[tokio::test]
    async fn both_directions_reach_the_other_side_and_end_with_shutdown() {
        static POOL: BufferPool = BufferPool::new(1024, 4);
        let (mut client, mut a) = duplex(4096);
        let (mut b, mut upstream) = duplex(4096);
        let relay =
            tokio::spawn(async move { copy_bidirectional_with(&POOL, &mut a, &mut b).await });

        client.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        upstream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        upstream.write_all(&[7_u8; 3000]).await.unwrap();
        let mut response = vec![0_u8; 3000];
        client.read_exact(&mut response).await.unwrap();
        assert!(response.iter().all(|byte| *byte == 7));

        client.shutdown().await.unwrap();
        assert_eq!(
            upstream.read(&mut request).await.unwrap(),
            0,
            "EOF reaches the upstream"
        );
        upstream.shutdown().await.unwrap();
        assert_eq!(
            client.read(&mut request).await.unwrap(),
            0,
            "EOF reaches the client"
        );
        assert_eq!(relay.await.unwrap().unwrap(), (7, 3000));
    }

    /// One direction ending is not the end of the other. An HTTP client that
    /// half-closes after its request -- or whose request framing ends while it
    /// pipelines the next one -- still has a response on the way back, and
    /// that response is the whole point of the connection.
    #[tokio::test]
    async fn a_direction_that_ends_leaves_the_other_running() {
        static POOL: BufferPool = BufferPool::new(1024, 4);
        let (mut client, mut a) = duplex(4096);
        let (mut b, mut upstream) = duplex(4096);
        let relay =
            tokio::spawn(async move { copy_bidirectional_with(&POOL, &mut a, &mut b).await });

        client.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        upstream.read_exact(&mut request).await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            upstream.read(&mut [0_u8; 8]).await.unwrap(),
            0,
            "the end of the request reaches the upstream"
        );

        // Only now does the upstream answer.
        upstream.write_all(b"the whole response").await.unwrap();
        let mut response = vec![0_u8; 18];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"the whole response");
        upstream.shutdown().await.unwrap();
        assert_eq!(relay.await.unwrap().unwrap(), (7, 18));
    }

    #[tokio::test]
    async fn an_idle_connection_holds_no_buffer() {
        static POOL: BufferPool = BufferPool::new(1024, 4);
        let (mut client, mut a) = duplex(4096);
        let (mut b, mut upstream) = duplex(4096);
        let relay =
            tokio::spawn(async move { copy_bidirectional_with(&POOL, &mut a, &mut b).await });

        client.write_all(b"ping").await.unwrap();
        let mut ping = [0_u8; 4];
        upstream.read_exact(&mut ping).await.unwrap();
        upstream.write_all(b"pong").await.unwrap();
        client.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"pong");

        // Both directions now wait on readers with nothing buffered.
        tokio::time::timeout(Duration::from_secs(5), async {
            while POOL.lent() > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("both copy buffers return to the pool");

        drop(client);
        drop(upstream);
        relay.await.unwrap().ok();
    }

    #[tokio::test]
    async fn a_quiet_reader_flushes_what_the_writer_buffered() {
        static POOL: BufferPool = BufferPool::new(1024, 4);
        let (mut client, mut a) = duplex(4096);
        let (b, mut upstream) = duplex(4096);
        // The upstream side only shows bytes once flushed.
        let mut b = BufWriter::new(b);
        let relay =
            tokio::spawn(async move { copy_bidirectional_with(&POOL, &mut a, &mut b).await });

        client.write_all(b"hello").await.unwrap();
        let mut hello = [0_u8; 5];
        tokio::time::timeout(Duration::from_secs(5), upstream.read_exact(&mut hello))
            .await
            .expect("the relay flushes when its reader goes quiet")
            .unwrap();
        assert_eq!(&hello, b"hello");

        drop(client);
        drop(upstream);
        relay.await.unwrap().ok();
    }

    #[tokio::test]
    async fn a_writer_that_takes_nothing_fails_the_copy() {
        struct Zero;
        impl AsyncRead for Zero {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for Zero {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(0))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        static POOL: BufferPool = BufferPool::new(1024, 4);
        let (mut client, mut a) = duplex(4096);
        client.write_all(b"data").await.unwrap();
        let error = copy_bidirectional_with(&POOL, &mut a, &mut Zero)
            .await
            .expect_err("a zero-length write is an error");
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
}
