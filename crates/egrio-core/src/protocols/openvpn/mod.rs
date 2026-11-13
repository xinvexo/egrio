//! The OpenVPN client outbound, in the modern protocol's subset: a tls-crypt
//! control channel carrying TLS with the client's certificate and optional
//! username and password, the server's pushed configuration, and an AEAD
//! data channel with peer ids and keys from TLS's keying material exporter
//! (OpenVPN 2.6 or later on the server). Implemented from the OpenVPN source
//! (`release/2.6`, `src/openvpn`) and the wire protocol draft
//! (github.com/OpenVPN/openvpn-rfc, `openvpn-wire-protocol.xml`).
//!
//! The tunnel carries this host's own connections only: the Core opens TCP
//! connections (with its own TCP engine, `packet::tcp`) and UDP associations
//! from the address the server assigns, and takes their replies. Nothing
//! listens there, so the VPN's other hosts cannot reach this one through it.

mod config;
mod connector;
mod control;
mod crypt;
mod data;
mod exchange;
mod link;
mod reliable;
mod stack;
mod tunnel;
mod verify;
mod wire;

pub(crate) use connector::{unsupported_option, OpenVpnConnector};

#[cfg(test)]
mod live;
#[cfg(test)]
pub(crate) mod test_server;
#[cfg(test)]
mod tests;
