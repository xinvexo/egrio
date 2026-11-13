//! Shadowsocks in the dual-half layout: `codec` writes the
//! AEAD frame, address vocabulary, and key schedule once; `connector` is the
//! client half (`OutboundConnector`) and `acceptor` the server half
//! (`InboundAcceptor`). Both wrap the same `codec::ShadowsocksStream` once
//! their handshakes diverge, so the wire format is written a single time.

pub(crate) mod acceptor;
mod aead2022;
pub(crate) mod codec;
pub(crate) mod connector;
pub(crate) mod udp;

#[cfg(test)]
mod gate;

pub(crate) use connector::{unsupported_option, ShadowsocksConnector};

use tokio::io::{AsyncRead, AsyncReadExt};

/// What a refused handshake does with its connection. SIP022 section 3.1.4
/// requires a server not to show how many bytes it consumed before it gave
/// up, and closing with bytes still unread sends an RST that shows just that
/// to a peer probing one byte at a time. The connection is read and
/// discarded until the peer closes it, so the server closes after the peer,
/// with nothing unread, whatever the handshake had read; the listener's
/// handshake budget bounds the wait.
pub(crate) async fn discard_until_closed<S: AsyncRead + Unpin + ?Sized>(io: &mut S) {
    let mut sink = [0_u8; 4096];
    while let Ok(read) = io.read(&mut sink).await {
        if read == 0 {
            break;
        }
    }
}
