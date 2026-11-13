//! The connection to the server one `remote` names: UDP or TCP from this
//! host, or through the node's dialer-proxy — the hop's datagrams for UDP,
//! its stream for TCP. Over TCP every packet carries its 16-bit length
//! (the wire protocol draft's "TCP and UDP transport modes").
//!
//! A reader task hands each packet to the tunnel task until the link fails
//! or the tunnel ends.

use std::io;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use super::config::{Remote, Transport};
use crate::egress::EgressRuntime;
use crate::outbound::{dial_server, Dialer, OutboundDatagramSender, OutboundError, ServerStream};
use crate::target::ConnectTarget;

/// Packets read ahead of the tunnel task, which takes them in batches of 48.
const READ_AHEAD: usize = 1024;
/// Bytes the read-ahead holds at once. The places alone do not bound it: a
/// packet's length is framed in 16 bits, so a thousand places are 64 MiB if
/// a server frames every packet at the maximum, where the 1400-byte tunnel
/// this link carries needs under two. The bytes are the budget, and a reader
/// that has spent them waits for the tunnel task to take what it already
/// has, which is backpressure on the server rather than loss.
const READ_AHEAD_BYTES: usize = 2 * 1024 * 1024;
/// The largest packet a TCP link frames.
const MAX_FRAME: usize = u16::MAX as usize;

/// A packet waiting for the tunnel task. It holds the share of
/// [`READ_AHEAD_BYTES`] its own bytes take for as long as it is the queue's
/// or the tunnel task's.
pub(super) struct LinkPacket {
    pub(super) bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

/// Takes `bytes` bytes of the read-ahead budget, waiting for the tunnel task
/// to free the room. A packet can never ask for more than the whole budget:
/// the framing cannot express it.
async fn held(budget: &Arc<Semaphore>, bytes: usize) -> Option<OwnedSemaphorePermit> {
    let want = u32::try_from(bytes.min(READ_AHEAD_BYTES)).expect("a frame fits u32");
    Arc::clone(budget).acquire_many_owned(want).await.ok()
}

/// Queues `bytes` for the tunnel task once the budget has room for it.
/// `false` once nothing is reading.
async fn queue(
    packets: &mpsc::Sender<LinkPacket>,
    budget: &Arc<Semaphore>,
    bytes: Vec<u8>,
) -> bool {
    let Some(budget) = held(budget, bytes.len()).await else {
        return false;
    };
    packets
        .send(LinkPacket {
            bytes,
            _budget: budget,
        })
        .await
        .is_ok()
}

pub(super) enum LinkSender {
    Udp(Arc<UdpSocket>),
    Stream(WriteHalf<ServerStream>),
    Datagrams {
        sender: Box<dyn OutboundDatagramSender>,
        server: ConnectTarget,
    },
}

impl LinkSender {
    pub(super) async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.send(packet).await.map(drop),
            Self::Stream(stream) => {
                let length = u16::try_from(packet.len())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                let mut framed = Vec::with_capacity(2 + packet.len());
                framed.extend_from_slice(&length.to_be_bytes());
                framed.extend_from_slice(packet);
                stream.write_all(&framed).await
            }
            Self::Datagrams { sender, server } => sender
                .send(server, packet)
                .await
                .map_err(|error| io::Error::other(error.to_string())),
        }
    }

    pub(super) fn is_stream(&self) -> bool {
        matches!(self, Self::Stream(_))
    }
}

/// Connects to `remote` and starts reading it; packets arrive on the
/// receiver until the link fails or `cancel` fires.
pub(super) async fn connect(
    egress: &EgressRuntime,
    dialer: &Dialer,
    remote: &Remote,
    cancel: CancellationToken,
) -> Result<(LinkSender, mpsc::Receiver<LinkPacket>), OutboundError> {
    let (packets, receiver) = mpsc::channel(READ_AHEAD);
    let budget = Arc::new(Semaphore::new(READ_AHEAD_BYTES));
    let server = ConnectTarget {
        host: remote.host.clone(),
        port: remote.port,
    };
    let sender = match remote.transport {
        Transport::Tcp => {
            let stream = dial_server(
                egress,
                dialer,
                &remote.host,
                remote.port,
                "OpenVPN server",
                true,
            )
            .await?;
            let (read, write) = tokio::io::split(stream);
            spawn(egress, read_stream(read, packets, budget), cancel)?;
            LinkSender::Stream(write)
        }
        Transport::Udp => match dialer.hop(egress, &server)? {
            Some(hop) => {
                let transport = hop.datagrams(&server).await?;
                let mut receiver = transport.receiver;
                spawn(
                    egress,
                    async move {
                        while let Ok(Some((_, packet))) = receiver.recv().await {
                            if !queue(&packets, &budget, packet).await {
                                break;
                            }
                        }
                    },
                    cancel,
                )?;
                LinkSender::Datagrams {
                    sender: transport.sender,
                    server,
                }
            }
            None => {
                let socket = Arc::new(
                    egress
                        .connect_udp_host(&remote.host, remote.port, "OpenVPN UDP socket")
                        .await
                        .map_err(OutboundError::hop_dial)?,
                );
                let reader = Arc::clone(&socket);
                spawn(
                    egress,
                    async move {
                        let mut buffer = vec![0_u8; MAX_FRAME];
                        while let Ok(read) = reader.recv(&mut buffer).await {
                            if !queue(&packets, &budget, buffer[..read].to_vec()).await {
                                break;
                            }
                        }
                    },
                    cancel,
                )?;
                LinkSender::Udp(socket)
            }
        },
    };
    Ok((sender, receiver))
}

fn spawn(
    egress: &EgressRuntime,
    reader: impl std::future::Future<Output = ()> + Send + 'static,
    cancel: CancellationToken,
) -> Result<(), OutboundError> {
    egress
        .spawn_policy_task(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = reader => {}
            }
        })
        .map(drop)
        .map_err(|error| OutboundError::new(crate::outbound::OutboundStage::Local, error))
}

async fn read_stream(
    mut read: ReadHalf<ServerStream>,
    packets: mpsc::Sender<LinkPacket>,
    budget: Arc<Semaphore>,
) {
    let mut buffer = BytesMut::with_capacity(64 * 1024);
    loop {
        while buffer.len() >= 2 {
            let length = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
            if buffer.len() < 2 + length {
                break;
            }
            buffer.advance(2);
            let packet = buffer.split_to(length).to_vec();
            if !queue(&packets, &budget, packet).await {
                return;
            }
        }
        match read.read_buf(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    /// A thousand places are not a bound on a queue whose entries the wire
    /// sizes: what stops the reader is the bytes.
    #[tokio::test]
    async fn the_read_ahead_runs_out_of_bytes_before_it_runs_out_of_places() {
        let (packets, mut receiver) = mpsc::channel(READ_AHEAD);
        let budget = Arc::new(Semaphore::new(READ_AHEAD_BYTES));
        let frame = vec![0_u8; MAX_FRAME];

        let mut queued = 0;
        while timeout(
            Duration::from_millis(50),
            queue(&packets, &budget, frame.clone()),
        )
        .await
        .is_ok_and(|sent| sent)
        {
            queued += 1;
        }

        assert!(
            queued * MAX_FRAME <= READ_AHEAD_BYTES && (queued + 1) * MAX_FRAME > READ_AHEAD_BYTES,
            "the budget stopped the reader at {queued} frames of {MAX_FRAME} bytes"
        );
        assert!(
            queued < READ_AHEAD,
            "{queued} frames filled the budget, so the places were not what stopped it"
        );

        // The tunnel task taking one frame makes room for one more, and no
        // packet was lost to make it: the reader was waiting, not dropping.
        drop(receiver.recv().await.expect("a frame the reader queued"));
        assert!(
            timeout(
                Duration::from_millis(50),
                queue(&packets, &budget, frame.clone())
            )
            .await
            .is_ok_and(|sent| sent),
            "the room one frame freed takes one frame"
        );
    }
}
