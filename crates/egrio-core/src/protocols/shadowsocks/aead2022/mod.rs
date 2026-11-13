//! SIP022/SIP023 adapters over the official shadowsocks-rust wire codec.
//! Sockets and resolution stay in EgressRuntime; UDP session identity and
//! replay windows stay here, rather than in a second networking runtime.

use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::relay::socks5::Address;
use shadowsocks_crypto::CipherKind;

use crate::target::ConnectTarget;

mod replay;
mod tcp;
mod udp;
mod udp_server;

pub(super) use tcp::{accept, connect};
pub(super) use udp::{client_transport, ClientCodec};
pub(super) use udp_server::serve;

#[cfg(test)]
mod interop;
#[cfg(test)]
mod tests;

pub(super) struct Config {
    pub(super) server: ServerConfig,
    pub(super) context: SharedContext,
}

impl Config {
    pub(super) fn new(method: CipherKind, password: &str) -> Result<Arc<Self>, String> {
        // This address is only a key-parsing input. Never call the library's
        // dial/bind helpers: transport creation belongs exclusively to Egrio.
        let server = ServerConfig::new(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            password,
            method,
        )
        .map_err(|error| format!("invalid Shadowsocks 2022 key: {error}"))?;
        Ok(Arc::new(Self {
            server,
            context: Context::new_shared(ServerType::Local),
        }))
    }
}

pub(super) fn to_address(target: &ConnectTarget) -> Result<Address, String> {
    // Preserve Egrio's domain-length and scoped-IPv6 validation.
    let bytes = target.socks_address()?;
    Address::read_cursor(&mut Cursor::new(bytes)).map_err(|error| error.to_string())
}

pub(super) fn from_address(address: Address) -> ConnectTarget {
    match address {
        Address::SocketAddress(address) => ConnectTarget {
            host: address.ip().to_string(),
            port: address.port(),
        },
        Address::DomainNameAddress(host, port) => ConnectTarget { host, port },
    }
}
