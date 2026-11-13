//! The Trojan client half, an `OutboundConnector`: dial the proxy,
//! run the TLS handshake, and relay the plaintext duplex. The Trojan preamble
//! folds the SOCKS target header and any sniffed early data into the first
//! write, so the target's first flight rides the same TLS record; Trojan adds no
//! per-frame layer over TLS, so the plaintext stream is the TLS stream itself.
//! UDP associate rides the same TLS tunnel as a framed datagram stream: one
//! associate per UDP session, every frame carrying its own target (EIM), so a
//! single transport reaches every remote the client addresses.

use crate::outbound::options::{option_string, udp_switch};
use crate::outbound::{DatagramError, DatagramFuture};
use std::fmt;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::egress::EgressRuntime;
use crate::outbound::{
    BoxedOutboundStream, CarrierDial, Dialer, OutboundConnector, OutboundDatagramReceiver,
    OutboundDatagramSender, OutboundDatagramTransport, OutboundError, OutboundFuture,
    OutboundResultExt, OutboundStage, WarmCarriers,
};
use crate::protocols::trojan::codec::{
    encode_client_preamble, encode_udp_frame, password_hash_hex, read_udp_frame, CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
};
use crate::target::ConnectTarget;
use crate::tls::{unsupported_trust_options, TlsClient, TlsClientOptions};

/// One Trojan proxy hop. The TLS/auth config is parsed once at compile time; a
/// missing password surfaces as a dial error (mirroring the other connectors),
/// never a silently dropped proxy.
pub(crate) struct TrojanConnector {
    host: String,
    port: u16,
    config: Result<TrojanClientConfig, String>,
    udp: bool,
}

/// Everything a Trojan dial needs beyond the server address: the precomputed
/// auth hash and the node's TLS carriers. Held apart from the connector so a
/// bad profile is an error value rather than an unrepresentable state.
struct TrojanClientConfig {
    hash: [u8; 56],
    /// Dialed with a TLS client built once at profile compile time and shared
    /// by every dial: rebuilding per dial paid a webpki root-store
    /// construction per flow and, worse, gave each flow an empty session
    /// cache — sharing the config is what lets TLS session resumption skip
    /// the certificate re-verification on every flow after the node's first.
    carriers: Arc<WarmCarriers>,
}

/// A transport, handshake or trust option this connector does not speak,
/// which must fail loudly: plain TLS to a WebSocket, gRPC or REALITY server can
/// never connect, and a dropped certificate pin would weaken the hop.
pub(crate) fn unsupported_option(options: &JsonValue) -> Option<String> {
    if let Some(network) =
        option_string(options, &["network"]).filter(|network| !network.eq_ignore_ascii_case("tcp"))
    {
        return Some(format!("Trojan transport '{network}' is not supported yet"));
    }
    if options
        .get("reality-opts")
        .is_some_and(|value| !value.is_null())
    {
        return Some("Trojan REALITY is not supported yet".into());
    }
    let trust = unsupported_trust_options(options);
    (!trust.is_empty())
        .then(|| format!("Trojan options are not supported yet: {}", trust.join(", ")))
}

/// The ALPN a Trojan hop offers when its profile names none. Trojan is
/// meant to pass as HTTPS, and browsers offer these two (RFC 7301); a
/// ClientHello without ALPN would stand out.
const DEFAULT_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

impl TrojanClientConfig {
    fn from_options(host: &str, port: u16, options: &JsonValue) -> Result<Self, String> {
        let password = option_string(options, &["password", "pass"])
            .ok_or_else(|| "Trojan password is required".to_string())?;
        if let Some(issue) = unsupported_option(options) {
            return Err(issue);
        }
        let mut tls = TlsClientOptions::from_node(options);
        // An `alpn` the profile gives, even an empty one, is used as given.
        if options.get("alpn").is_none() {
            tls.alpn = DEFAULT_ALPN
                .iter()
                .map(|protocol| protocol.to_vec())
                .collect();
        }
        let tls = TlsClient::new(host, &tls)
            .map_err(|error| format!("invalid Trojan TLS settings: {error}"))?;
        Ok(Self {
            hash: password_hash_hex(&password),
            carriers: Arc::new(WarmCarriers::new(CarrierDial {
                host: host.to_string(),
                port,
                dialer: Dialer::from_options(options),
                label: "Trojan proxy",
                tls: Some(tls),
            })),
        })
    }
}

impl TrojanConnector {
    pub(crate) fn new(host: String, port: u16, options: &JsonValue) -> Self {
        Self {
            config: TrojanClientConfig::from_options(&host, port, options),
            host,
            port,
            udp: udp_switch(options),
        }
    }

    fn config(&self) -> Result<&TrojanClientConfig, String> {
        self.config.as_ref().map_err(String::clone)
    }

    /// Dials the proxy and completes the TLS handshake — the shared front of
    /// both the stream and the datagram face — or takes a carrier dialed
    /// ahead. The datagram face's carrier is `lasting`: a UDP association
    /// rides it for as long as its session lives, so a fresh dial sees to its
    /// path first.
    async fn dial_tls(
        &self,
        egress: &EgressRuntime,
        lasting: bool,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        let config = self.config().at(OutboundStage::Config)?;
        if lasting {
            config.carriers.dial_lasting(egress).await
        } else {
            config.carriers.dial(egress).await
        }
    }
}

impl fmt::Debug for TrojanConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the auth hash. `configured` distinguishes a valid profile
        // from one that will fail at dial.
        formatter
            .debug_struct("TrojanConnector")
            .field("server", &format_args!("{}:{}", self.host, self.port))
            .field(
                "sni",
                &self
                    .config
                    .as_ref()
                    .ok()
                    .and_then(|config| config.carriers.tls())
                    .map(TlsClient::server_name)
                    .unwrap_or("<unset>"),
            )
            .field("configured", &self.config.is_ok())
            .finish_non_exhaustive()
    }
}

impl OutboundConnector for TrojanConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let config = self.config().at(OutboundStage::Config)?;
            let mut stream = self.dial_tls(egress, false).await?;

            // The preamble carries the SOCKS target; sniffed early data folds
            // straight in. Flush it so the server can read the
            // request and dial before either side relays — otherwise both park.
            // Trojan never acknowledges the target, so a failure here is the
            // node's stream.
            let mut preamble = encode_client_preamble(&config.hash, CMD_CONNECT, target)
                .at(OutboundStage::Local)?;
            preamble.extend_from_slice(early_data);
            stream
                .write_all(&preamble)
                .await
                .at(OutboundStage::HopConnect)?;
            stream.flush().await.at(OutboundStage::HopConnect)?;

            // Trojan has no post-preamble framing over TLS: the plaintext duplex
            // the relay drives is the TLS stream itself.
            Ok(stream)
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async move {
            let config = self.config().at(OutboundStage::Config)?;
            let mut stream = self.dial_tls(egress, true).await?;

            // The request names the desired destination (trojan spec), the
            // association's first target: a server that opens its UDP session
            // for it resolves a name there. Every datagram frame below still
            // carries its own target, which keeps one associate
            // endpoint-independent (EIM). Flush so the server authenticates
            // and enters its frame loop before the first datagram.
            let preamble = encode_client_preamble(&config.hash, CMD_UDP_ASSOCIATE, target)
                .at(OutboundStage::Local)?;
            stream
                .write_all(&preamble)
                .await
                .at(OutboundStage::HopConnect)?;
            stream.flush().await.at(OutboundStage::HopConnect)?;

            let (read, write) = tokio::io::split(stream);
            Ok(OutboundDatagramTransport {
                sender: Box::new(TrojanDatagramSender {
                    write: Mutex::new(write),
                }),
                receiver: Box::new(TrojanDatagramReceiver { read }),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn udp_enabled(&self) -> bool {
        self.udp
    }

    /// Carriers dialed ahead on the old network may be stranded.
    fn network_changed(&self, _change: &crate::egress::NetworkChange, _egress: &EgressRuntime) {
        if let Ok(config) = &self.config {
            config.carriers.clear();
        }
    }
}

/// Frames one datagram per send onto the associate's TLS write half. The lock
/// keeps concurrent sends whole-frame atomic — a length-framed stream cannot
/// survive interleaved partial writes — and each frame is flushed immediately:
/// datagrams are latency-bound, so none may sit in a TLS buffer waiting for a
/// sibling.
struct TrojanDatagramSender {
    write: Mutex<WriteHalf<BoxedOutboundStream>>,
}

impl OutboundDatagramSender for TrojanDatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::MayLeavePartialFrame
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let frame = encode_udp_frame(target, payload)?;
            let mut write = self.write.lock().await;
            write
                .write_all(&frame)
                .await
                .map_err(DatagramError::Carrier)?;
            write.flush().await.map_err(DatagramError::Carrier)
        })
    }
}

/// Decodes response frames off the associate's TLS read half. Each frame's
/// address is the origin the datagram came from, which the UDP session uses
/// for endpoint-independent filtering (EIF). A decode error ends the transport
/// — a length-framed stream cannot resync mid-frame — and a clean close at a
/// frame boundary is the `Ok(None)` end.
struct TrojanDatagramReceiver {
    read: ReadHalf<BoxedOutboundStream>,
}

impl OutboundDatagramReceiver for TrojanDatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            read_udp_frame(&mut self.read)
                .await
                .map_err(DatagramError::Carrier)
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn tls(connector: &TrojanConnector) -> &TlsClient {
        connector
            .config()
            .expect("valid config")
            .carriers
            .tls()
            .expect("a Trojan carrier is TLS")
    }

    #[test]
    fn requires_a_password() {
        let connector = TrojanConnector::new("proxy.example.com".into(), 443, &json!({}));
        assert!(connector.config().is_err());
    }

    #[test]
    fn transports_and_reality_it_does_not_speak_fail_loudly() {
        let config = |options| TrojanConnector::new("proxy.example.com".into(), 443, &options);
        for network in ["ws", "grpc", "h2"] {
            let Err(error) = config(json!({"password": "x", "network": network})).config else {
                panic!("transport {network} must not be ignored");
            };
            assert!(error.contains(network), "{error}");
        }
        assert!(
            config(json!({"password": "x", "reality-opts": {"public-key": "k"}}))
                .config
                .is_err()
        );
        assert!(
            config(json!({"password": "x", "network": "tcp", "client-fingerprint": "chrome"}))
                .config
                .is_ok()
        );
    }

    #[test]
    fn sni_defaults_to_the_server_host() {
        let connector = TrojanConnector::new(
            "proxy.example.com".into(),
            443,
            &json!({ "password": "pw" }),
        );
        assert_eq!(tls(&connector).server_name(), "proxy.example.com");
        assert_eq!(
            tls(&connector).alpn(),
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn an_alpn_the_profile_gives_is_used_as_given_even_when_empty() {
        for (alpn, expected) in [
            (json!([]), Vec::<Vec<u8>>::new()),
            (json!(["http/1.1"]), vec![b"http/1.1".to_vec()]),
        ] {
            let connector = TrojanConnector::new(
                "proxy.example.com".into(),
                443,
                &json!({ "password": "pw", "alpn": alpn }),
            );
            assert_eq!(tls(&connector).alpn(), expected);
        }
    }

    #[test]
    fn reads_sni_insecure_and_alpn_options() {
        let connector = TrojanConnector::new(
            "1.2.3.4".into(),
            443,
            &json!({
                "password": "pw",
                "sni": "front.example.com",
                "skip-cert-verify": true,
                "alpn": ["h2", "http/1.1"]
            }),
        );
        assert_eq!(tls(&connector).server_name(), "front.example.com");
        assert_eq!(
            tls(&connector).alpn(),
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
