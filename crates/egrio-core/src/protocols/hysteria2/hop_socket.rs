//! The socket under a chained Hysteria 2 carrier: the datagrams of the hop
//! its `dialer-proxy` names stand in for a UDP socket of this host. quinn
//! sends without waiting, so its packets queue for a task that hands each to
//! the hop in turn, and the hop's packets queue for quinn's reads. Every
//! packet reads as coming from the one remote the carrier was dialed to, so
//! quinn never takes the hop's packets for a path that migrated. The hop
//! wraps each packet again, so the carrier keeps QUIC's initial packet size:
//! the socket reports that its packets may fragment, which keeps quinn from
//! probing for a larger one (path MTU discovery).

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinHandle;
use tokio_util::sync::PollSender;

use crate::outbound::{DatagramOperation, OutboundDatagramTransport};
use crate::target::ConnectTarget;

/// Packets queued each way between quinn and the hop.
const QUEUE: usize = 1024;

pub(super) struct HopSocket {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    remote: SocketAddr,
    /// No address of this host: the hop's own socket has that.
    local: SocketAddr,
    tasks: [JoinHandle<()>; 2],
}

impl HopSocket {
    /// A socket over `hop`, the hop's datagrams to `server`, that quinn sees
    /// connected to `remote`.
    pub(super) fn new(
        hop: OutboundDatagramTransport,
        server: ConnectTarget,
        remote: SocketAddr,
    ) -> Self {
        let (outgoing, mut queued) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (deliver, incoming) = mpsc::channel(QUEUE);
        let mut receiver = hop.receiver;
        // Ends when the hop's datagrams do; quinn's next read then fails,
        // which ends the carrier at once instead of at its idle timeout. A
        // packet's own error (an ICMP error a hop's socket reports) loses
        // just that packet.
        let receive = tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(Some((_, packet))) => {
                        if deliver.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Err(error) if error.is_packet_error(DatagramOperation::Receive) => {}
                    Ok(None) | Err(_) => return,
                }
            }
        });
        let reads = receive.abort_handle();
        let sender = hop.sender;
        let send = tokio::spawn(async move {
            while let Some(packet) = queued.recv().await {
                match sender.send(&server, &packet).await {
                    Ok(()) => {}
                    // Lost alone, as a socket loses a packet its full queue
                    // drops.
                    Err(error) if error.is_packet_error(DatagramOperation::Send) => {}
                    Err(_) => {
                        reads.abort();
                        return;
                    }
                }
            }
        });
        let local = match remote {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        Self {
            outgoing,
            incoming: Mutex::new(incoming),
            remote,
            local,
            tasks: [send, receive],
        }
    }
}

impl Drop for HopSocket {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl fmt::Debug for HopSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HopSocket")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for HopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QueuePoller(PollSender::new(self.outgoing.clone())))
    }

    /// A full queue waits like a socket's send buffer; once the hop's
    /// datagrams failed, packets are lost while the carrier ends.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match self.outgoing.try_send(transmit.contents.to_vec()) {
            Ok(()) | Err(TrySendError::Closed(_)) => Ok(()),
            Err(TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut incoming = self.incoming.lock().expect("hop socket reads");
        let Some(mut packet) = ready!(incoming.poll_recv(cx)) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the dialer-proxy's datagrams ended",
            )));
        };
        let mut count = 0;
        loop {
            let len = packet.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&packet[..len]);
            meta[count] = RecvMeta {
                addr: self.remote,
                len,
                stride: len,
                ..RecvMeta::default()
            };
            count += 1;
            if count == bufs.len().min(meta.len()) {
                break;
            }
            match incoming.try_recv() {
                Ok(next) => packet = next,
                Err(_) => break,
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Ready when the queue to the hop has room.
struct QueuePoller(PollSender<Vec<u8>>);

impl fmt::Debug for QueuePoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueuePoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for QueuePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Room is reserved only to learn there is some; `try_send` takes it.
        let ready = ready!(self.0.poll_reserve(cx));
        if ready.is_ok() {
            self.0.abort_send();
        }
        Poll::Ready(Ok(()))
    }
}

/// The address quinn knows the server by: the one `server` names, or one
/// that stands in for its name, which only the hop resolves.
pub(super) fn remote_address(server: &ConnectTarget) -> SocketAddr {
    match server.ip() {
        Some(ip) => SocketAddr::new(ip, server.port),
        // TEST-NET-1 (RFC 5737): no host of this network has it.
        None => SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), server.port)),
    }
}
