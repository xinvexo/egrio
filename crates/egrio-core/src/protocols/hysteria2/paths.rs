//! Which of a few fresh sockets sees the fastest path to a QUIC server. A
//! network that spreads flows over paths by their ports gives each socket a
//! path of its own. A packet of a QUIC version no server speaks draws a
//! Version Negotiation packet from the server (RFC 9000 section 6), which
//! times the round trip on that socket's path without a handshake.

use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::egress::pending::Pending;

/// The version a probe claims: one of those reserved to exercise version
/// negotiation (RFC 9000 section 15).
const PROBE_VERSION: u32 = 0x1a2a_3a4a;
/// A server answers only datagrams of at least this size (RFC 9000 section
/// 14.1).
const PROBE_SIZE: usize = 1200;

/// A long-header packet of [`PROBE_VERSION`] whose source connection ID is
/// `id`, padded to [`PROBE_SIZE`].
fn probe_packet(id: &[u8; 8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(PROBE_SIZE);
    packet.push(0xc0);
    packet.extend_from_slice(&PROBE_VERSION.to_be_bytes());
    packet.push(8);
    packet.extend_from_slice(&rand::rng().random::<[u8; 8]>());
    packet.push(8);
    packet.extend_from_slice(id);
    packet.resize(PROBE_SIZE, 0);
    packet
}

/// Whether `datagram` is a Version Negotiation packet answering the probe
/// with source connection ID `id`: a long header of version 0 whose
/// destination connection ID is that ID (RFC 9000 section 17.2.1).
fn answers(datagram: &[u8], id: &[u8; 8]) -> bool {
    datagram.len() >= 14
        && datagram[0] & 0x80 != 0
        && datagram[1..5] == [0; 4]
        && datagram[5] == 8
        && datagram[6..14] == id[..]
}

/// Sends a probe to `server` from each socket and returns the index of the
/// first to hear the answer, with its round trip; none within `wait`.
pub(super) async fn fastest(
    sockets: &[&UdpSocket],
    server: SocketAddr,
    wait: Duration,
) -> Option<(usize, Duration)> {
    let probes = sockets
        .iter()
        .enumerate()
        .map(|(index, socket)| async move {
            let id = rand::rng().random::<[u8; 8]>();
            let sent = Instant::now();
            socket.send_to(&probe_packet(&id), server).await.ok()?;
            let mut buffer = [0_u8; 1500];
            loop {
                let (length, from) = socket.recv_from(&mut buffer).await.ok()?;
                if from == server && answers(&buffer[..length], &id) {
                    return Some((index, sent.elapsed()));
                }
            }
        });
    let mut pending = Pending::new();
    for probe in probes {
        pending.push(probe);
    }
    let first = async {
        while let Some(answer) = pending.next().await {
            if answer.is_some() {
                return answer;
            }
        }
        None
    };
    tokio::time::timeout(wait, first).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers every probe it receives after `delay`, as a server's Version
    /// Negotiation would.
    async fn negotiating_server(delay: Duration) -> SocketAddr {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1500];
            while let Ok((length, from)) = server.recv_from(&mut buffer).await {
                let probe = &buffer[..length];
                if length < PROBE_SIZE || probe[1..5] != PROBE_VERSION.to_be_bytes() {
                    continue;
                }
                // Destination ID = the probe's source ID, source ID = its
                // destination ID, then the versions the server speaks.
                let mut answer = vec![0x80, 0, 0, 0, 0, 8];
                answer.extend_from_slice(&probe[15..23]);
                answer.push(8);
                answer.extend_from_slice(&probe[6..14]);
                answer.extend_from_slice(&1_u32.to_be_bytes());
                tokio::time::sleep(delay).await;
                let _ = server.send_to(&answer, from).await;
            }
        });
        address
    }

    #[test]
    fn a_probe_is_a_padded_long_header_of_a_reserved_version() {
        let packet = probe_packet(&[7; 8]);
        assert_eq!(packet.len(), PROBE_SIZE);
        assert_eq!(packet[0] & 0xc0, 0xc0);
        assert_eq!(packet[1..5], PROBE_VERSION.to_be_bytes());
        assert_eq!(PROBE_VERSION & 0x0f0f_0f0f, 0x0a0a_0a0a);
        assert_eq!((packet[5], packet[14]), (8, 8));
        assert_eq!(packet[15..23], [7; 8]);
    }

    #[test]
    fn only_the_negotiation_for_this_probe_answers_it() {
        let id = [7; 8];
        let mut negotiation = vec![0x80, 0, 0, 0, 0, 8];
        negotiation.extend_from_slice(&id);
        negotiation.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1]);
        assert!(answers(&negotiation, &id));
        assert!(!answers(&negotiation, &[9; 8]), "another probe's answer");
        let mut versioned = negotiation.clone();
        versioned[4] = 1;
        assert!(!answers(&versioned, &id), "not version negotiation");
        assert!(!answers(&negotiation[..10], &id));
    }

    #[tokio::test]
    async fn the_socket_whose_answer_comes_first_wins() {
        let server = negotiating_server(Duration::ZERO).await;
        let sockets = [
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        ];
        let (index, rtt) = fastest(
            &sockets.iter().collect::<Vec<_>>(),
            server,
            Duration::from_secs(2),
        )
        .await
        .expect("an answer");
        assert!(index < 2);
        assert!(rtt < Duration::from_secs(1));

        // A server that answers no probe gives no path.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        assert_eq!(
            fastest(&[&sockets[0]], silent_addr, Duration::from_millis(100)).await,
            None
        );
    }
}
