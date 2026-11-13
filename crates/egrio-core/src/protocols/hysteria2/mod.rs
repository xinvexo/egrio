mod congestion;
mod connector;
mod hop_socket;
mod pacer;
mod paths;
mod policer;
mod socket;
mod turns;

// The QUIC/HTTP-3 wire vocabulary both halves speak:
// the varint codec, the auth/frame constants, the padding, and the UDP
// datagram frame. Always compiled — the connector links it in every build and
// the acceptor reuses the same items, so the frame format has one home.
mod codec;
// The acceptor terminates TLS, so it is server-only; a live QUIC listener in a
// server assembly composes it.
#[cfg(feature = "server")]
mod acceptor;
#[cfg(all(test, feature = "server"))]
mod gate;
#[cfg(all(test, feature = "server"))]
pub(crate) mod test_server;

#[cfg(feature = "server")]
pub(crate) use acceptor::{Hysteria2Acceptor, Hysteria2UserTable};
// Bench-only surface (`--features bench-internals`): re-exports the codec's
// UDP-frame wrapper for `crate::bench_internals` while `codec` itself stays
// module-private.
#[cfg(feature = "bench-internals")]
pub use codec::bench;
pub(crate) use connector::{unsupported_option, Hysteria2Connector};
