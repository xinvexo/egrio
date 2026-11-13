//! ICMP echo through the tunnel. One the rules send DIRECT leaves over the
//! physical uplink through the egress guard (`egress/echo.rs`) and its reply
//! comes back as from the address that was pinged; any other echo to a
//! fake-range address is answered on the spot, as there is no host behind
//! it. Echo cannot travel through a proxy, so everything else is dropped.

use std::net::IpAddr;

use super::frame::{build_icmp_packet, icmp_message, ipv4_icmp_checksum};

/// Echo request and reply types: ICMPv4 (RFC 792) and ICMPv6 (RFC 4443).
const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;

/// An echo request that arrived through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EchoRequest {
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) identifier: u16,
    pub(crate) sequence: u16,
    pub(crate) payload: Vec<u8>,
}

impl EchoRequest {
    /// The echo request `packet` carries, if it is one.
    pub(crate) fn parse(packet: &[u8]) -> Option<Self> {
        let icmp = icmp_message(packet)?;
        let request = if icmp.source.is_ipv4() {
            ECHO_REQUEST_V4
        } else {
            ECHO_REQUEST_V6
        };
        let message = icmp.message;
        (message.len() >= 8 && message[0] == request && message[1] == 0).then(|| Self {
            source: icmp.source,
            destination: icmp.destination,
            identifier: u16::from_be_bytes([message[4], message[5]]),
            sequence: u16::from_be_bytes([message[6], message[7]]),
            payload: message[8..].to_vec(),
        })
    }

    /// The reply the sender waits for: from the address it pinged, with its
    /// identifier, sequence and payload.
    pub(crate) fn reply(&self) -> Option<Vec<u8>> {
        let message = echo_message(
            self.destination.is_ipv6(),
            true,
            self.identifier,
            self.sequence,
            &self.payload,
        );
        build_icmp_packet(self.destination, self.source, &message)
    }
}

/// An echo request or reply message. ICMPv4 carries its checksum in the
/// message; the ICMPv6 checksum covers a pseudo-header, so the packet builder
/// fills it in.
pub(crate) fn echo_message(
    ipv6: bool,
    reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let kind = match (ipv6, reply) {
        (false, false) => ECHO_REQUEST_V4,
        (false, true) => ECHO_REPLY_V4,
        (true, false) => ECHO_REQUEST_V6,
        (true, true) => ECHO_REPLY_V6,
    };
    let mut message = Vec::with_capacity(8 + payload.len());
    message.extend_from_slice(&[kind, 0, 0, 0]);
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(payload);
    if !ipv6 {
        let checksum = ipv4_icmp_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(source: &str, destination: &str) -> Vec<u8> {
        let (source, destination): (IpAddr, IpAddr) =
            (source.parse().unwrap(), destination.parse().unwrap());
        let message = echo_message(destination.is_ipv6(), false, 0xabcd, 3, b"ping");
        build_icmp_packet(source, destination, &message).unwrap()
    }

    #[test]
    fn an_echo_request_turns_into_the_reply_its_sender_waits_for() {
        for (client, target) in [("10.0.0.2", "198.18.0.5"), ("fd00::2", "2001:db8::1")] {
            let echo = EchoRequest::parse(&request(client, target)).expect("echo request");
            assert_eq!((echo.identifier, echo.sequence), (0xabcd, 3));
            assert_eq!(echo.payload, b"ping");

            let reply = echo.reply().unwrap();
            let icmp = icmp_message(&reply).unwrap();
            assert_eq!(icmp.source.to_string(), target);
            assert_eq!(icmp.destination.to_string(), client);
            assert_eq!(icmp.message[0], if echo.source.is_ipv4() { 0 } else { 129 });
            assert_eq!(&icmp.message[4..], b"\xab\xcd\x00\x03ping");
            assert!(
                EchoRequest::parse(&reply).is_none(),
                "a reply is no request"
            );
        }
    }
}
