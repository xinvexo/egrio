//! A stream whose first reads replay bytes a handshake already took from it.
//! A handshake that reads its message in chunks, rather than a byte per read,
//! overshoots into whatever follows (a request body, a tunnel's first bytes);
//! it hands those back through this, so the next reader sees the stream
//! intact.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.position < this.prefix.len() {
            let count = buf.remaining().min(this.prefix.len() - this.position);
            buf.put_slice(&this.prefix[this.position..this.position + count]);
            this.position += count;
            if this.position == this.prefix.len() {
                // Replayed: free the buffer for the rest of the stream's life.
                this.prefix = Vec::new();
                this.position = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn replays_the_prefix_before_the_stream_and_writes_through() {
        let (near, mut far) = duplex(64);
        let mut stream = PrefixedStream::new(b"head".to_vec(), near);
        far.write_all(b"-tail").await.unwrap();
        drop(far);

        let mut first = [0_u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"he");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"ad-tail");
        assert!(stream.prefix.is_empty(), "a replayed prefix is freed");
    }
}
