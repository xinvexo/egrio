use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{
    AcceptedStream, BoxedInboundStream, InboundAcceptor, InboundFuture, InboundReplyPlan,
    InboundSession,
};
use crate::target::ConnectTarget;

/// SOCKS5 CONNECT server half: the mixed listener's plaintext acceptor.
/// No-auth only; a credential
/// method would land behind the `server` feature with the multi-user
/// table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Socks5Acceptor;

impl InboundAcceptor for Socks5Acceptor {
    fn accept(&self, mut io: BoxedInboundStream) -> InboundFuture<'_, InboundSession> {
        Box::pin(async move {
            let target = read_socks5_target(&mut io).await?;
            Ok(InboundSession::Stream(AcceptedStream {
                inbound: "socks5-connect",
                user: None,
                process: ClientOwner::Known(None),
                target,
                io,
                replies: SOCKS5_REPLY_PLAN,
                reset: None,
            }))
        })
    }
}

const SOCKS5_REPLY_PLAN: InboundReplyPlan = InboundReplyPlan {
    success: &SOCKS5_SUCCESS_REPLY,
    admission_refused: &socks5_reply(0x05),
    route_rejected: &socks5_reply(0x02),
    outbound_unavailable: &socks5_reply(0x07),
    dial_failed: &socks5_reply(0x04),
};

const SOCKS5_SUCCESS_REPLY: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

const fn socks5_reply(status: u8) -> [u8; 10] {
    [0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

pub(crate) async fn write_socks5_reply<S: AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    status: u8,
) -> Result<(), String> {
    stream
        .write_all(&socks5_reply(status))
        .await
        .map_err(|error| error.to_string())
}

async fn read_socks5_target(stream: &mut BoxedInboundStream) -> Result<ConnectTarget, String> {
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|error| error.to_string())?;
    if greeting[0] != 0x05 {
        return Err(format!("invalid SOCKS version {}", greeting[0]));
    }

    let mut methods = vec![0_u8; greeting[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|error| error.to_string())?;
    if !methods.contains(&0x00) {
        stream
            .write_all(&[0x05, 0xff])
            .await
            .map_err(|error| error.to_string())?;
        return Err("SOCKS5 client does not offer no-auth method".into());
    }
    stream
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|error| error.to_string())?;

    let mut head = [0_u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|error| error.to_string())?;
    if head[0] != 0x05 {
        return Err(format!("invalid SOCKS request version {}", head[0]));
    }
    if head[1] != 0x01 {
        write_socks5_reply(stream.as_mut(), 0x07).await?;
        return Err(format!("unsupported SOCKS command {}", head[1]));
    }
    if head[2] != 0x00 {
        return Err("SOCKS request reserved byte must be zero".into());
    }

    let host = match head[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|error| error.to_string())?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| error.to_string())?;
            if length[0] == 0 {
                return Err("SOCKS5 domain target has zero length".into());
            }
            let mut domain = vec![0_u8; length[0] as usize];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|error| error.to_string())?;
            String::from_utf8(domain).map_err(|error| error.to_string())?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|error| error.to_string())?;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        unsupported => {
            write_socks5_reply(stream.as_mut(), 0x08).await?;
            return Err(format!("unsupported SOCKS address type {unsupported}"));
        }
    };

    let mut port = [0_u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|error| error.to_string())?;

    Ok(ConnectTarget {
        host,
        port: u16::from_be_bytes(port),
    })
}

#[cfg(test)]
mod tests {
    //! Handshake-parser tests over an in-memory duplex: the acceptor reads
    //! untrusted client bytes, so every malformed shape must end in an error
    //! (never a panic or a parked read), and every accepted shape must carry
    //! the right target. The dispatcher-facing reply plan is data; the only
    //! bytes accept itself writes are the method selection and the
    //! handshake-phase refusals asserted here.

    use tokio::io::{duplex, DuplexStream};
    use tokio::time::{timeout, Duration};

    use super::*;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Runs the acceptor against a fully scripted client. The script is
    /// written up front (the duplex buffers it), so no second task is
    /// needed; the accept future is bounded so a parser that stalls fails
    /// the test instead of hanging it. Returns the outcome and the client
    /// half, still open, for reply-byte assertions.
    async fn accept_scripted(script: &[u8]) -> (Result<InboundSession, String>, DuplexStream) {
        let (mut client, server) = duplex(4096);
        client
            .write_all(script)
            .await
            .expect("script fits the duplex buffer");
        let outcome = timeout(HANDSHAKE_TIMEOUT, Socks5Acceptor.accept(Box::new(server)))
            .await
            .expect("SOCKS5 handshake must not hang");
        (outcome, client)
    }

    fn accepted_stream(outcome: Result<InboundSession, String>) -> AcceptedStream {
        match outcome.expect("handshake accepted") {
            InboundSession::Stream(stream) => stream,
            InboundSession::Datagrams(_) => panic!("SOCKS5 CONNECT yields a stream session"),
        }
    }

    /// The handshake error, or a panic if the malformed input was accepted.
    /// (`expect_err` needs `Debug` on the session, which it deliberately
    /// does not carry.)
    fn rejected(outcome: Result<InboundSession, String>, why: &str) -> String {
        match outcome {
            Err(error) => error,
            Ok(_) => panic!("{why}: the handshake was accepted"),
        }
    }

    /// Everything the acceptor wrote back to the client: the server half is
    /// gone by now (dropped or consumed by the failed accept), so the
    /// buffered bytes end with EOF.
    async fn written_to_client(mut client: DuplexStream) -> Vec<u8> {
        let mut written = Vec::new();
        timeout(HANDSHAKE_TIMEOUT, client.read_to_end(&mut written))
            .await
            .expect("client drain must not hang")
            .expect("client drain");
        written
    }

    /// Greeting (no-auth) plus a CONNECT request head, followed by the given
    /// SOCKS address bytes and port.
    fn connect_script(address: &[u8], port: u16) -> Vec<u8> {
        let mut script = vec![0x05, 0x01, 0x00];
        script.extend_from_slice(&[0x05, 0x01, 0x00]);
        script.extend_from_slice(address);
        script.extend_from_slice(&port.to_be_bytes());
        script
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_an_ipv4_target() {
        let (outcome, client) = accept_scripted(&connect_script(&[0x01, 192, 0, 2, 7], 443)).await;

        let stream = accepted_stream(outcome);
        assert_eq!(stream.inbound, "socks5-connect");
        assert_eq!(stream.user, None);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "192.0.2.7".into(),
                port: 443,
            }
        );
        assert_eq!(stream.replies.success, SOCKS5_SUCCESS_REPLY);

        // Accept answers only the method selection; the request reply
        // belongs to the dispatcher's reply plan.
        drop(stream);
        assert_eq!(written_to_client(client).await, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_a_domain_target() {
        let mut address = vec![0x03, "example.com".len() as u8];
        address.extend_from_slice(b"example.com");
        let (outcome, _client) = accept_scripted(&connect_script(&address, 8080)).await;

        let stream = accepted_stream(outcome);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "example.com".into(),
                port: 8080,
            }
        );
    }

    #[tokio::test]
    async fn accepts_a_connect_request_to_an_ipv6_target() {
        let ip: Ipv6Addr = "2001:db8::1".parse().expect("ipv6 literal");
        let mut address = vec![0x04];
        address.extend_from_slice(&ip.octets());
        let (outcome, _client) = accept_scripted(&connect_script(&address, 53)).await;

        let stream = accepted_stream(outcome);
        assert_eq!(
            stream.target,
            ConnectTarget {
                host: "2001:db8::1".into(),
                port: 53,
            }
        );
    }

    #[tokio::test]
    async fn rejects_a_greeting_with_the_wrong_socks_version() {
        let (outcome, _client) = accept_scripted(&[0x04, 0x01, 0x00]).await;
        let error = rejected(outcome, "SOCKS4 greeting");
        assert!(error.contains("invalid SOCKS version 4"), "{error}");
    }

    #[tokio::test]
    async fn refuses_a_client_that_offers_no_no_auth_method() {
        // The one offered method is username/password (0x02); this acceptor
        // speaks no-auth only, so it answers "no acceptable methods".
        let (outcome, client) = accept_scripted(&[0x05, 0x01, 0x02]).await;
        let error = rejected(outcome, "auth-only client");
        assert!(error.contains("no-auth"), "{error}");
        assert_eq!(written_to_client(client).await, [0x05, 0xff]);
    }

    #[tokio::test]
    async fn rejects_a_udp_associate_command_with_the_unsupported_command_reply() {
        // Command 0x03 is UDP ASSOCIATE: this CONNECT-only acceptor refuses
        // it on the wire (reply 0x07) before reading any address bytes.
        let (outcome, client) = accept_scripted(&[0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01]).await;
        let error = rejected(outcome, "UDP associate");
        assert!(error.contains("unsupported SOCKS command 3"), "{error}");

        let written = written_to_client(client).await;
        assert_eq!(written[..2], [0x05, 0x00], "method selection first");
        assert_eq!(
            &written[2..],
            socks5_reply(0x07).as_slice(),
            "then the command-not-supported reply"
        );
    }

    #[tokio::test]
    async fn rejects_an_unknown_address_type_with_the_address_type_reply() {
        let (outcome, client) = accept_scripted(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x7f]).await;
        let error = rejected(outcome, "unknown address type");
        assert!(
            error.contains("unsupported SOCKS address type 127"),
            "{error}"
        );

        let written = written_to_client(client).await;
        assert_eq!(&written[2..], socks5_reply(0x08).as_slice());
    }

    #[tokio::test]
    async fn rejects_a_request_whose_reserved_byte_is_not_zero() {
        let (outcome, _client) = accept_scripted(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01]).await;
        let error = rejected(outcome, "nonzero reserved byte");
        assert!(error.contains("reserved byte"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_request_with_the_wrong_version_byte() {
        let (outcome, _client) = accept_scripted(&[0x05, 0x01, 0x00, 0x04, 0x01, 0x00, 0x01]).await;
        let error = rejected(outcome, "wrong request version");
        assert!(error.contains("invalid SOCKS request version 4"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_domain_target_that_is_not_utf8() {
        let script = [
            0x05, 0x01, 0x00, // greeting
            0x05, 0x01, 0x00, // request head
            0x03, 0x02, 0xff, 0xfe, // domain of two non-UTF-8 bytes
            0x01, 0xbb, // port 443
        ];
        let (outcome, _client) = accept_scripted(&script).await;
        let error = rejected(outcome, "non-UTF-8 domain");
        assert!(error.contains("utf-8"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_domain_target_of_zero_length() {
        // ATYP=domain (0x03) with a length byte of 0: an empty host must be
        // refused at parse time, not accepted as "" that only fails later at
        // route/dial.
        let (outcome, _client) = accept_scripted(&connect_script(&[0x03, 0x00], 443)).await;
        let error = rejected(outcome, "zero-length domain");
        assert!(error.contains("zero length"), "{error}");
    }

    #[tokio::test]
    async fn errors_instead_of_hanging_when_the_client_truncates_the_handshake() {
        // The greeting promises two methods but the client dies after one
        // byte: the read must surface EOF as an error, not park forever.
        let (mut client, server) = duplex(4096);
        client
            .write_all(&[0x05, 0x02, 0x00])
            .await
            .expect("partial greeting");
        drop(client);

        let outcome = timeout(HANDSHAKE_TIMEOUT, Socks5Acceptor.accept(Box::new(server)))
            .await
            .expect("truncated handshake must not hang");
        assert!(outcome.is_err(), "EOF mid-handshake is an error");
    }
}
