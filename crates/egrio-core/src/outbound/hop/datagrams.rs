//! A chained node's datagrams. The node seals each datagram as it would for
//! a socket of this host, and the hop's datagrams carry the packet to the
//! node's server and the server's packets back, where the node opens them.

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::outbound::{
    BoxedOutboundStream, DatagramError, DatagramFuture, DatagramSendCancellation,
    OutboundDatagramReceiver, OutboundDatagramSender, OutboundDatagramTransport,
};
use crate::target::ConnectTarget;

/// How a node frames its datagrams to its server.
pub(crate) trait DatagramCodec: Send + Sync {
    /// The packet that carries `payload` to `target` through the node's
    /// server.
    fn seal(&self, target: &ConnectTarget, payload: &[u8]) -> Result<Vec<u8>, DatagramError>;

    /// The remote a packet from the node's server comes from, and its
    /// payload. `None` skips a packet that does not open, as a lost one.
    fn open(&self, packet: &mut [u8]) -> Option<(ConnectTarget, Vec<u8>)>;
}

/// The node's datagrams over `hop`, the hop's datagrams to `server`.
/// `association` lives as long as the transport and ends it when it closes:
/// a SOCKS5 association's control connection.
pub(crate) fn chained_datagrams(
    hop: OutboundDatagramTransport,
    server: ConnectTarget,
    codec: Arc<dyn DatagramCodec>,
    association: Option<BoxedOutboundStream>,
) -> OutboundDatagramTransport {
    OutboundDatagramTransport {
        sender: Box::new(ChainedSender {
            hop: hop.sender,
            server,
            codec: Arc::clone(&codec),
        }),
        receiver: Box::new(ChainedReceiver {
            hop: hop.receiver,
            codec,
            association,
        }),
    }
}

struct ChainedSender {
    hop: Box<dyn OutboundDatagramSender>,
    server: ConnectTarget,
    codec: Arc<dyn DatagramCodec>,
}

impl OutboundDatagramSender for ChainedSender {
    fn send_cancellation(&self) -> DatagramSendCancellation {
        self.hop.send_cancellation()
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let packet = self.codec.seal(target, payload)?;
            self.hop.send(&self.server, &packet).await
        })
    }
}

struct ChainedReceiver {
    hop: Box<dyn OutboundDatagramReceiver>,
    codec: Arc<dyn DatagramCodec>,
    association: Option<BoxedOutboundStream>,
}

impl OutboundDatagramReceiver for ChainedReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            let Self {
                hop,
                codec,
                association,
            } = self;
            let ended = held_until_closed(association.as_mut());
            tokio::pin!(ended);
            loop {
                // Biased: packets the hop already delivered come before an
                // association ending at the same time.
                tokio::select! {
                    biased;
                    received = hop.recv() => match received? {
                        Some((_, mut packet)) => {
                            if let Some(datagram) = codec.open(&mut packet) {
                                return Ok(Some(datagram));
                            }
                        }
                        None => return Ok(None),
                    },
                    ended = &mut ended => return ended.map(|()| None),
                }
            }
        })
    }
}

/// Resolves when `association` closes: on EOF, or with the error that ended
/// it. Bytes it carries meanwhile do not end it; without one it never
/// resolves.
pub(crate) async fn held_until_closed(
    association: Option<&mut BoxedOutboundStream>,
) -> Result<(), DatagramError> {
    let Some(stream) = association else {
        return std::future::pending().await;
    };
    let mut probe = [0_u8; 1];
    loop {
        match stream.read(&mut probe).await {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(error) => return Err(DatagramError::Carrier(error)),
        }
    }
}
