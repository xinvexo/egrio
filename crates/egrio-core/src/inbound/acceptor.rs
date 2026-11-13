//! The inbound layer's object contract, the dual of the outbound layer's
//! `OutboundConnector`.
//!
//! An acceptor is one wire protocol's server half: on an accepted duplex
//! transport it runs the protocol handshake, authenticates the peer, and
//! deframes what the connection carries, yielding either one proxied byte
//! stream or one authenticated multi-flow datagram face. Everything the
//! acceptor yields feeds the same protocol-blind dispatch pipeline
//! (`inbound/dispatch.rs`) — a deployment's role is decided by which
//! acceptors and connectors its host composes, never by a mode flag.
//!
//! Protocol replies are data, not callbacks: plaintext proxy protocols
//! answer their client between pipeline stages (an HTTP status line, a
//! SOCKS5 reply byte), so an accepted stream carries those byte strings in
//! an [`InboundReplyPlan`] for the dispatcher to write at the fixed reply
//! points. Encrypted protocols leave every field empty — their only
//! "reply" is relayed bytes, and failure is closing the stream.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::attribution::ClientOwner;
use crate::packet::tcp::CapturedTcpStream;
use crate::target::ConnectTarget;

/// Boxed future all acceptor methods return: keeps the trait object-safe
/// without an async-trait dependency (same shape as `OutboundFuture`).
pub(crate) type InboundFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Any duplex byte stream an acceptor can hand the dispatcher: the
/// plaintext side of whatever wire protocol the acceptor terminates.
pub(crate) trait InboundStream: AsyncRead + AsyncWrite + Send + Unpin {
    /// The captured TCP flow this stream is, if it is one: the relay moves
    /// its bytes without copy buffers.
    fn as_captured_tcp(&mut self) -> Option<&mut CapturedTcpStream>;
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> InboundStream for T {
    fn as_captured_tcp(&mut self) -> Option<&mut CapturedTcpStream> {
        (self as &mut dyn std::any::Any).downcast_mut::<CapturedTcpStream>()
    }
}

pub(crate) type BoxedInboundStream = Box<dyn InboundStream>;

/// How an inbound whose protocol has no refusal reply refuses a session: a
/// captured TCP flow is reset, as the server it stands in for would refuse
/// the connection. Called before the stream is dropped.
pub(crate) type StreamReset = Box<dyn FnOnce() + Send>;

/// One inbound wire protocol's server half.
pub(crate) trait InboundAcceptor: Send + Sync + fmt::Debug {
    /// Runs handshake, authentication, and deframing on one accepted
    /// transport. Handshake-phase replies (a SOCKS5 method refusal, an
    /// auth failure) are the acceptor's own business; from the returned
    /// session onward the dispatcher owns the reply points.
    fn accept(&self, io: BoxedInboundStream) -> InboundFuture<'_, InboundSession>;
}

/// What one accepted-and-authenticated connection carries.
pub(crate) enum InboundSession {
    /// One proxied TCP connection.
    Stream(AcceptedStream),
    /// One authenticated connection multiplexing UDP flows. Constructed by the
    /// Trojan UDP-associate acceptor and, as its QUIC-server analogue, the
    /// Hysteria2 acceptor — both behind the `server` feature — so a non-server
    /// lib build sees this arm unconstructed, hence the gate.
    #[cfg_attr(not(test), allow(dead_code))]
    Datagrams(AcceptedDatagramFace),
}

/// One proxied TCP connection as the acceptor's handshake left it: routing
/// metadata, the duplex IO the relay will drive,
/// and the protocol's reply vocabulary.
pub(crate) struct AcceptedStream {
    /// Ledger label for the session registry (`http-connect`, ...).
    pub(crate) inbound: &'static str,
    /// Authenticated peer identity; `None` on unauthenticated local
    /// capture inbounds. Multi-user credential tables are a `server`
    /// feature concern — the contract only carries what a handshake
    /// already proved.
    pub(crate) user: Option<Arc<str>>,
    /// The local process owning the client socket, from the Core's flow
    /// scanner: a captured flow's SYN, or a loopback listener client looked
    /// up during its handshake; still pending when no rule routes by
    /// process. A client can never assert it; unknown when remote.
    pub(crate) process: ClientOwner,
    pub(crate) target: ConnectTarget,
    pub(crate) io: BoxedInboundStream,
    pub(crate) replies: InboundReplyPlan,
    /// Run instead of a refusal reply when the session is refused (admission,
    /// REJECT, an unavailable outbound); `None` for protocols that answer
    /// with their reply bytes and close.
    pub(crate) reset: Option<StreamReset>,
}

/// Protocol reply bytes the dispatcher writes at its fixed pipeline reply
/// points. Empty fields write nothing.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct InboundReplyPlan {
    /// Tunnel established (written early when a sniff needs the client's
    /// first flight, otherwise after the dial succeeds).
    pub(crate) success: &'static [u8],
    /// Session refused by admission control.
    pub(crate) admission_refused: &'static [u8],
    /// Routing decided REJECT/BLOCK.
    pub(crate) route_rejected: &'static [u8],
    /// The routed outbound does not exist or is not implemented.
    pub(crate) outbound_unavailable: &'static [u8],
    /// The outbound dial failed.
    pub(crate) dial_failed: &'static [u8],
}

/// The datagram face of one authenticated connection:
/// deliberately not a mirror of `connect_datagram`, because one connection
/// carries many client flows. The receiver yields deframed datagrams, the
/// responder frames replies back to their flow; the dispatcher pairs the
/// face's `user` with each frame's claimed source, so two users behind
/// identical private addresses stay separate flows in the UDP session
/// table (its key includes the user).
// Constructed by the Trojan and Hysteria2 server acceptors; see
// `InboundSession::Datagrams`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct AcceptedDatagramFace {
    pub(crate) user: Option<Arc<str>>,
    pub(crate) receiver: Box<dyn InboundDatagramReceiver>,
    pub(crate) responder: Box<dyn InboundDatagramResponder>,
}

/// One deframed inbound datagram: the client flow it belongs to (the
/// protocol's flow discriminator, expressed as the client socket address
/// the wire encodes), the proxied target, and the payload.
#[derive(Debug)]
pub(crate) struct InboundDatagram {
    pub(crate) source: SocketAddr,
    pub(crate) target: ConnectTarget,
    pub(crate) payload: Vec<u8>,
}

/// Receive half of a datagram face: yields deframed datagrams.
/// `Ok(None)` is the connection's clean end. Decode policy mirrors the
/// outbound rule: a framed stream that cannot resync ends instead of
/// skipping.
pub(crate) trait InboundDatagramReceiver: Send {
    fn next(&mut self) -> InboundFuture<'_, Option<InboundDatagram>>;
}

/// Send half of a datagram face: frames one response back to the client
/// flow that `source` names, tagged with the remote it came from. `&self`
/// so late responses can be framed while the receive half is parked in
/// `next` (implementations lock internally when their wire needs it).
pub(crate) trait InboundDatagramResponder: Send + Sync {
    fn respond<'a>(
        &'a self,
        source: SocketAddr,
        from: &'a ConnectTarget,
        payload: &'a [u8],
    ) -> InboundFuture<'a, ()>;
}
