//! The Shadowsocks client half, an `OutboundConnector`: dial the
//! proxy, run the AEAD handshake, and relay the plaintext duplex. TCP folds
//! the SOCKS target header (and any sniffed early data) into the request's
//! first sealed chunk; UDP seals one independently-keyed packet per datagram
//! and hands the pair to the shared session actor. A chained node's packets
//! go through its dialer-proxy's datagrams.

use crate::outbound::options::{option_string, udp_switch};
use crate::outbound::{
    recv_datagram, DatagramError, DatagramFuture, PumpDatagrams, PumpFrom, PumpTo,
};
use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Waker};

use serde_json::Value as JsonValue;
use shadowsocks_crypto::CipherKind;
use tokio::net::UdpSocket;

use super::aead2022;
use crate::egress::EgressRuntime;
use crate::outbound::{
    chained_datagrams, dial_server, BoxedOutboundStream, DatagramCodec, Dialer, OutboundConnector,
    OutboundDatagramReceiver, OutboundDatagramSender, OutboundDatagramTransport, OutboundError,
    OutboundFuture, OutboundResultExt, OutboundStage,
};
use crate::protocols::shadowsocks::codec::{
    begin_udp_packet, connect_client_stream, open_udp_in_place, open_udp_packet, parse_cipher,
    seal_udp_in_place, seal_udp_packet, shadowsocks_key,
};
use crate::target::ConnectTarget;

/// One Shadowsocks proxy hop. The cipher config is parsed once at compile
/// time; a bad cipher/password surfaces as a dial error (mirroring the other
/// connectors), never a silently dropped proxy.
pub(crate) struct ShadowsocksConnector {
    host: String,
    port: u16,
    dialer: Dialer,
    config: Result<ShadowsocksCipherConfig, String>,
    udp: bool,
}

/// The AEAD method plus its derived master key — everything both TCP and UDP
/// need to seal and open. Held apart from the connector so a bad profile is
/// an error value rather than an unrepresentable state.
enum ShadowsocksCipherConfig {
    Aead { method: CipherKind, key: Vec<u8> },
    Aead2022(Arc<aead2022::Config>),
}

/// A plugin (obfs, v2ray-plugin, shadow-tls) wraps the stream in another
/// protocol, so the server cannot read a connection made without it.
pub(crate) fn unsupported_option(options: &JsonValue) -> Option<String> {
    option_string(options, &["plugin"])
        .map(|plugin| format!("Shadowsocks plugin '{plugin}' is not supported yet"))
}

impl ShadowsocksCipherConfig {
    fn from_options(options: &JsonValue) -> Result<Self, String> {
        let cipher = option_string(options, &["cipher", "method"])
            .ok_or_else(|| "Shadowsocks cipher is required".to_string())?;
        let method = parse_cipher(&cipher)?;
        let password = option_string(options, &["password", "pass"])
            .ok_or_else(|| "Shadowsocks password is required".to_string())?;
        if let Some(issue) = unsupported_option(options) {
            return Err(issue);
        }
        if method.is_aead_2022() {
            Ok(Self::Aead2022(aead2022::Config::new(method, &password)?))
        } else {
            Ok(Self::Aead {
                method,
                key: shadowsocks_key(method, &password),
            })
        }
    }
}

impl ShadowsocksConnector {
    pub(crate) fn new(host: String, port: u16, options: &JsonValue) -> Self {
        Self {
            host,
            port,
            dialer: Dialer::from_options(options),
            config: ShadowsocksCipherConfig::from_options(options),
            udp: udp_switch(options),
        }
    }

    fn config(&self) -> Result<&ShadowsocksCipherConfig, String> {
        self.config.as_ref().map_err(String::clone)
    }
}

impl fmt::Debug for ShadowsocksConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the derived key. `configured` distinguishes a valid
        // cipher/password from a profile that will fail at dial.
        formatter
            .debug_struct("ShadowsocksConnector")
            .field("server", &format_args!("{}:{}", self.host, self.port))
            .field("configured", &self.config.is_ok())
            .finish_non_exhaustive()
    }
}

impl OutboundConnector for ShadowsocksConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let config = self.config().at(OutboundStage::Config)?;
            let transport = dial_server(
                egress,
                &self.dialer,
                &self.host,
                self.port,
                "Shadowsocks proxy",
                false,
            )
            .await?;
            // The request is only written: Shadowsocks never acknowledges the
            // target, so every failure here is the node's stream.
            match config {
                ShadowsocksCipherConfig::Aead2022(config) => {
                    aead2022::connect(transport, config, target, early_data)
                        .await
                        .at(OutboundStage::HopConnect)
                }
                ShadowsocksCipherConfig::Aead { method, key } => {
                    // Fold the target and sniffed first flight into one record.
                    let mut request = target.socks_address().at(OutboundStage::Local)?;
                    request.extend_from_slice(early_data);
                    let stream = connect_client_stream(transport, *method, key, &request)
                        .await
                        .at(OutboundStage::HopConnect)?;
                    Ok(Box::new(stream) as BoxedOutboundStream)
                }
            }
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async move {
            let config = self.config().at(OutboundStage::Config)?;
            let server = ConnectTarget {
                host: self.host.clone(),
                port: self.port,
            };
            if let Some(hop) = self.dialer.hop(egress, &server)? {
                let datagrams = hop.datagrams(&server).await?;
                let codec: Arc<dyn DatagramCodec> = match config {
                    ShadowsocksCipherConfig::Aead2022(config) => {
                        Arc::new(aead2022::ClientCodec::new(Arc::clone(config)))
                    }
                    ShadowsocksCipherConfig::Aead { method, key } => Arc::new(AeadCodec {
                        method: *method,
                        key: key.clone(),
                    }),
                };
                return Ok(chained_datagrams(datagrams, server, codec, None));
            }
            let socket = Arc::new(
                egress
                    .connect_udp_host(&self.host, self.port, "Shadowsocks UDP proxy")
                    .await
                    .map_err(OutboundError::hop_dial)?,
            );
            match config {
                ShadowsocksCipherConfig::Aead2022(config) => {
                    Ok(aead2022::client_transport(socket, Arc::clone(config)))
                }
                ShadowsocksCipherConfig::Aead { method, key } => {
                    let io = Arc::new(ShadowsocksUdpIo {
                        socket,
                        method: *method,
                        key: key.clone(),
                        pump: OnceLock::new(),
                    });
                    Ok(OutboundDatagramTransport {
                        sender: Box::new(ShadowsocksDatagramSender(Arc::clone(&io))),
                        receiver: Box::new(ShadowsocksDatagramReceiver(io)),
                    })
                }
            }
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn udp_enabled(&self) -> bool {
        self.udp
    }
}

/// A chained node's AEAD packets (SIP004): one sealed packet per datagram,
/// naming its target, the same as on a socket of this host.
struct AeadCodec {
    method: CipherKind,
    key: Vec<u8>,
}

impl DatagramCodec for AeadCodec {
    fn seal(&self, target: &ConnectTarget, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
        Ok(seal_udp_packet(self.method, &self.key, target, payload)?)
    }

    fn open(&self, packet: &mut [u8]) -> Option<(ConnectTarget, Vec<u8>)> {
        open_udp_packet(self.method, &self.key, packet).ok()
    }
}

/// The proxy socket of one Shadowsocks association. Every datagram is sealed
/// with its own target address (Shadowsocks UDP carries the SOCKS address in
/// every packet), so one association relays to every remote the client
/// addresses (EIM). The session actor sends and reads through it, and once a
/// captured flow's association is learned, the packet pump does so itself.
struct ShadowsocksUdpIo {
    socket: Arc<UdpSocket>,
    method: CipherKind,
    key: Vec<u8>,
    /// Set once the packet pump reads the socket (see
    /// [`PumpDatagrams::hand_reads_to`]).
    pump: OnceLock<Waker>,
}

impl ShadowsocksUdpIo {
    /// Asks for the next packet to wake the pump; whether one is waiting
    /// already, in which case no wakeup is registered.
    fn arm(&self) -> bool {
        self.pump.get().is_some_and(|waker| {
            self.socket
                .poll_recv_ready(&mut Context::from_waker(waker))
                .is_ready()
        })
    }
}

impl PumpDatagrams for ShadowsocksUdpIo {
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> io::Result<()> {
        let mut packet = begin_udp_packet(self.method, 19 + payload.len());
        to.push_socks_address(&mut packet)?;
        packet.extend_from_slice(payload);
        seal_udp_in_place(self.method, &self.key, &mut packet);
        // Sent at once: a new socket's readiness starts empty, so a
        // non-blocking send through the reactor would refuse it.
        socket2::SockRef::from(&*self.socket)
            .send(&packet)
            .map(drop)
    }

    fn hand_reads_to(&self, waker: Waker) {
        if self.pump.set(waker.clone()).is_ok() && self.arm() {
            waker.wake();
        }
    }

    fn try_recv(&self, buffer: &mut [u8]) -> io::Result<(usize, PumpFrom, usize)> {
        loop {
            let read = match self.socket.try_recv(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.arm() {
                        continue;
                    }
                    return Err(error);
                }
                read => read?,
            };
            // A packet that does not open is skipped like a lost one; the
            // sealed address is the reply's origin (EIF).
            let Ok(plaintext) = open_udp_in_place(self.method, &self.key, &mut buffer[..read])
            else {
                continue;
            };
            let Some((from, address)) = PumpFrom::from_socks_address(&buffer[plaintext.clone()])
            else {
                continue;
            };
            let start = plaintext.start + address;
            buffer.copy_within(start..plaintext.end, 0);
            let length = plaintext.end - start;
            return Ok((length, from, length));
        }
    }
}

struct ShadowsocksDatagramSender(Arc<ShadowsocksUdpIo>);

impl OutboundDatagramSender for ShadowsocksDatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let io = &self.0;
            let packet = seal_udp_packet(io.method, &io.key, target, payload)?;
            io.socket
                .send(&packet)
                .await
                .map(|_| ())
                .map_err(DatagramError::NativeSocket)
        })
    }
}

struct ShadowsocksDatagramReceiver(Arc<ShadowsocksUdpIo>);

impl OutboundDatagramReceiver for ShadowsocksDatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            let io = &self.0;
            loop {
                let (buffer, read) = match recv_datagram(&io.socket).await {
                    Ok(received) => received,
                    Err(error) => return Err(DatagramError::NativeSocket(error)),
                };
                // Skip a single undecodable datagram rather than tear down the
                // session, as the datagram contract requires: UDP has no
                // resync to lose. The sealed address is
                // the reply's origin (EIF), the framing source for the client.
                match open_udp_packet(io.method, &io.key, &buffer[..read]) {
                    Ok((from, payload)) => return Ok(Some((from, payload))),
                    Err(_) => continue,
                }
            }
        })
    }

    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        Some(Arc::clone(&self.0) as Arc<dyn PumpDatagrams>)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_plugin_it_does_not_speak_fails_loudly() {
        let config =
            |options| ShadowsocksConnector::new("proxy.example.com".into(), 443, &options).config;
        let Err(error) = config(json!({
            "cipher": "aes-256-gcm",
            "password": "x",
            "plugin": "obfs",
            "plugin-opts": {"mode": "tls"},
        })) else {
            panic!("an obfs plugin must not be ignored");
        };
        assert!(error.contains("obfs"), "{error}");
        assert!(
            config(json!({"cipher": "aes-256-gcm", "password": "x", "udp-over-tcp": false}))
                .is_ok()
        );
    }
}
