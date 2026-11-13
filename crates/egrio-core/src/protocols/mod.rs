//! Wire protocols in the dual-half layout: each protocol
//! keeps its client half (`connector`, the `OutboundConnector` impl) and
//! its server half (`acceptor`, the `InboundAcceptor` impl) side by side,
//! with frame/address vocabulary both halves speak in `codec` — the wire
//! format is written once. A protocol missing a half simply has no module
//! for it yet (hysteria2's acceptor arrives with the certificate-loading
//! slice; Shadowsocks lands its connector first, then its acceptor with the
//! server slice; Trojan reconstructs both halves in-tree, its acceptor
//! terminating TLS behind the `server` feature; OpenVPN is a client only).
//!
//! The contracts live one layer up — `outbound/mod.rs` and
//! `inbound/acceptor.rs` — and DIRECT stays with the outbound contract:
//! it is the dial primitive every assembly needs, not a wire protocol
//! with halves.

pub(crate) mod http;
pub(crate) mod hysteria2;
pub(crate) mod openvpn;
pub(crate) mod shadowsocks;
pub(crate) mod socks5;
pub(crate) mod trojan;
