//! Holds a Hysteria 2 client connection's UDP sends to its agreed rate (see
//! `congestion.rs`). quinn's own pacer releases about 2 ms of the congestion
//! window per wakeup, which cannot keep a fixed rate when the connection
//! wakes less often, so the rate is enforced here with a token bucket over the
//! bytes each transmit puts on the wire. Every client connection owns its
//! endpoint and so its socket: the bucket paces exactly one connection.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::congestion::SendRate;

/// The bucket holds this much of the rate. It must outlast the gap between
/// the connection's wakeups, which follow acknowledgements arriving in
/// batches every few milliseconds, or the rate falls short; more would let a
/// longer burst out after an idle spell.
const BURST: Duration = Duration::from_millis(4);

pub(super) struct PacedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    rate: Arc<SendRate>,
    bucket: Mutex<Bucket>,
}

impl PacedSocket {
    pub(super) fn new(inner: Arc<dyn AsyncUdpSocket>, rate: Arc<SendRate>) -> Self {
        Self {
            inner,
            rate,
            bucket: Mutex::new(Bucket::new(Instant::now())),
        }
    }

    /// How long until the bucket is out of debt, if it is in debt.
    fn debt(&self) -> Option<Duration> {
        let pacing = self.rate.pacing();
        if pacing == 0 {
            return None;
        }
        let mut bucket = self.bucket.lock().expect("Hysteria2 pacer bucket");
        bucket.refill(Instant::now(), pacing);
        bucket.debt(pacing)
    }
}

impl fmt::Debug for PacedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacedSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for PacedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PacedPoller {
            inner: Arc::clone(&self.inner).create_io_poller(),
            socket: self,
            sleep: None,
        })
    }

    /// Admits a transmit while the bucket is out of debt and charges all of
    /// it, so a transmit larger than the tokens left borrows from the next
    /// ones and the long-run rate stays exact.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let pacing = self.rate.pacing();
        if pacing == 0 {
            return self.inner.try_send(transmit);
        }
        let mut bucket = self.bucket.lock().expect("Hysteria2 pacer bucket");
        bucket.refill(Instant::now(), pacing);
        if bucket.debt(pacing).is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)?;
        bucket.charge(transmit.contents.len());
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Reports the socket writable once the bucket is out of debt and the
/// underlying socket is writable.
struct PacedPoller {
    socket: Arc<PacedSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl fmt::Debug for PacedPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacedPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for PacedPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(debt) = this.socket.debt() {
            let deadline = tokio::time::Instant::now() + debt;
            let sleep = match &mut this.sleep {
                Some(sleep) => {
                    sleep.as_mut().reset(deadline);
                    sleep
                }
                None => this
                    .sleep
                    .insert(Box::pin(tokio::time::sleep_until(deadline))),
            };
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

/// Bytes the connection may still send. Negative while the excess of the
/// last transmit is being repaid.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    refilled: Instant,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            tokens: 0.0,
            refilled: now,
        }
    }

    fn refill(&mut self, now: Instant, pacing: u64) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        let burst = pacing as f64 * BURST.as_secs_f64();
        self.tokens = (self.tokens + elapsed * pacing as f64).min(burst);
        self.refilled = now;
    }

    fn debt(&self, pacing: u64) -> Option<Duration> {
        (self.tokens < 0.0).then(|| Duration::from_secs_f64(-self.tokens / pacing as f64))
    }

    fn charge(&mut self, bytes: usize) {
        self.tokens -= bytes as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transmit_borrows_from_the_next_and_the_debt_is_repaid_at_the_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        let pacing = 1_000_000;
        assert_eq!(
            bucket.debt(pacing),
            None,
            "an empty bucket admits a transmit"
        );
        bucket.charge(12_000);
        assert_eq!(bucket.debt(pacing), Some(Duration::from_millis(12)));
        bucket.refill(start + Duration::from_millis(5), pacing);
        assert_eq!(bucket.debt(pacing), Some(Duration::from_millis(7)));
        bucket.refill(start + Duration::from_millis(12), pacing);
        assert_eq!(bucket.debt(pacing), None);
    }

    #[test]
    fn an_idle_spell_banks_at_most_the_burst() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        let pacing = 10_000_000;
        bucket.refill(start + Duration::from_secs(1), pacing);
        assert_eq!(bucket.tokens, 40_000.0, "4 ms of 10 MB/s");
    }

    #[test]
    fn the_long_run_rate_is_the_pacing_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        let pacing = 2_000_000;
        let (mut now, mut sent) = (start, 0_usize);
        // Admit 12 KB transmits whenever out of debt, waking every 3 ms.
        while now < start + Duration::from_secs(1) {
            bucket.refill(now, pacing);
            while bucket.debt(pacing).is_none() {
                bucket.charge(12_000);
                sent += 12_000;
            }
            now += Duration::from_millis(3);
        }
        assert!((1_990_000..=2_020_000).contains(&sent), "sent {sent}");
    }
}
