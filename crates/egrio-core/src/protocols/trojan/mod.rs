//! Trojan in the dual-half layout: `codec` writes the auth hash,
//! request framing, and command set once; `connector` is the client half
//! (`OutboundConnector`) and `acceptor` the server half (`InboundAcceptor`).
//! Trojan runs over TLS — the acceptor terminates it behind the `server`
//! feature, the connector originates it in every build — and the shared
//! client-side TLS config lives in `crate::tls`, so the wire format is the only
//! thing this module writes twice-adjacent.

pub(crate) mod codec;
pub(crate) mod connector;

#[cfg(feature = "server")]
pub(crate) mod acceptor;

#[cfg(all(test, feature = "server"))]
pub(crate) mod gate;

#[cfg(feature = "server")]
pub(crate) use acceptor::{TrojanAcceptor, TrojanUserTable};
pub(crate) use connector::{unsupported_option, TrojanConnector};
