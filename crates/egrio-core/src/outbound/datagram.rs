//! Datagram I/O errors retain their origin. An ICMP-derived error on a native
//! UDP socket is not evidence that a TLS/QUIC carrier has failed, and vice versa.

use std::{fmt, future::Future, io, pin::Pin};

use tokio::net::UdpSocket;

use crate::buffer_pool::{BufferPool, PooledBuffer};

// One complete ordinary UDP datagram, including protocol framing. Bounds on
// associations and queued payloads control memory; receive buffers never
// trade data integrity for a smaller allocation.
pub(crate) const UDP_DATAGRAM_CAPACITY: usize = 65536;

/// Receive buffers, borrowed for one datagram at a time: an association
/// waiting for a reply holds none.
pub(crate) static UDP_DATAGRAM_BUFFERS: BufferPool = BufferPool::new(UDP_DATAGRAM_CAPACITY, 8);

/// Borrows of the UDP read pool, as [`crate::relay::copy::relay_buffer_borrows`].
#[cfg(feature = "bench-internals")]
pub fn udp_buffer_borrows() -> (usize, usize) {
    UDP_DATAGRAM_BUFFERS.borrows()
}

/// Waits for a datagram on a connected `socket` and reads it into a buffer
/// borrowed for that read (Tokio's `readable` + `try_recv` pairing), returning
/// the buffer and the datagram's length. Cancel-safe: a buffer is borrowed
/// only between readiness and the read, with no await in between.
pub(crate) async fn recv_datagram(socket: &UdpSocket) -> io::Result<(PooledBuffer, usize)> {
    loop {
        socket.readable().await?;
        let mut buffer = UDP_DATAGRAM_BUFFERS.take();
        match socket.try_recv(&mut buffer) {
            Ok(read) => return Ok((buffer, read)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Whether an error a UDP socket reported concerns one datagram or the path
/// it took rather than the socket, which goes on sending and receiving. The
/// ICMP answer to an earlier datagram comes back like this on a later call:
/// on a connected socket everywhere, and on Windows on an unconnected one
/// too, where `recvfrom` fails with `WSAECONNRESET` after a datagram the
/// socket sent met a closed port
/// (<https://learn.microsoft.com/windows/win32/api/winsock/nf-winsock-recvfrom>).
pub(crate) fn is_datagram_event(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    )
}

/// What a loop that serves many peers on one UDP socket waits out after a
/// failed receive before it receives again: nothing after an event about one
/// datagram ([`is_datagram_event`]), and a pause after anything else -- the
/// host out of buffers, or an error the platform does not explain -- so a
/// failure that persists costs a retry now and then instead of a spinning
/// thread. Such a loop never ends on a receive error: the socket is its own
/// and stays valid, and ending would let one peer that closes its port early
/// end the service for every other peer.
pub(crate) async fn after_receive_error(error: &io::Error) {
    const RETRY: std::time::Duration = std::time::Duration::from_millis(50);
    if !is_datagram_event(error) {
        tokio::time::sleep(RETRY).await;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramOperation {
    Send,
    Receive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramSendCancellation {
    /// Cancelling a pending send leaves the transport reusable and does not
    /// submit the datagram (Tokio UDP send/send_to cancellation contract).
    AtomicDatagram,
    /// The future can have written a prefix of a framed carrier message.
    MayLeavePartialFrame,
}

pub(crate) type DatagramFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DatagramError>> + Send + 'a>>;

#[derive(Debug)]
pub(crate) enum DatagramError {
    NativeSocket(io::Error),
    Carrier(io::Error),
    Protocol(String),
    /// This packet was rejected before any application bytes were sent.
    Rejected(String),
}

impl DatagramError {
    /// These native socket events concern a datagram or network path. Keep
    /// the socket mapping (RFC 4787 REQ-12); never replay the affected payload.
    /// A carrier with the same ErrorKind is still a terminal transport error.
    pub(crate) fn is_packet_error(&self, operation: DatagramOperation) -> bool {
        matches!(self, Self::Rejected(_))
            || matches!(self, Self::NativeSocket(_) if operation == DatagramOperation::Send)
            || matches!(self, Self::NativeSocket(error) if is_datagram_event(error))
    }
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeSocket(error) => write!(f, "UDP socket: {error}"),
            Self::Carrier(error) => write!(f, "UDP carrier: {error}"),
            Self::Protocol(message) | Self::Rejected(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for DatagramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NativeSocket(error) | Self::Carrier(error) => Some(error),
            Self::Protocol(_) | Self::Rejected(_) => None,
        }
    }
}
impl From<String> for DatagramError {
    fn from(message: String) -> Self {
        Self::Protocol(message)
    }
}
impl From<DatagramError> for String {
    fn from(error: DatagramError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Windows reports on an unconnected socket once a datagram it sent
    /// met a closed port is an event about that datagram: the loop serving
    /// the socket receives again at once. Anything it cannot place waits out
    /// a pause first, so a failure that stays costs retries, not a core.
    #[tokio::test(start_paused = true)]
    async fn only_an_unexplained_receive_error_is_waited_out() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
        ] {
            let error = io::Error::from(kind);
            assert!(is_datagram_event(&error), "{kind:?}");
            let before = tokio::time::Instant::now();
            after_receive_error(&error).await;
            assert_eq!(before.elapsed(), std::time::Duration::ZERO, "{kind:?}");
        }
        for kind in [io::ErrorKind::OutOfMemory, io::ErrorKind::Other] {
            let error = io::Error::from(kind);
            assert!(!is_datagram_event(&error), "{kind:?}");
            let before = tokio::time::Instant::now();
            after_receive_error(&error).await;
            assert!(
                before.elapsed() >= std::time::Duration::from_millis(50),
                "{kind:?}"
            );
        }
    }
}
