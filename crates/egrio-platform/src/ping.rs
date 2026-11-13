//! ICMP echo from a "ping socket": an ICMP datagram socket, which macOS opens
//! for any user and Linux for the groups in `net.ipv4.ping_group_range`
//! (icmp(7)). The egress guards of those platforms send the Core's echo with
//! it, protecting it like every other egress socket first.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Sends one echo request carrying `payload` to `target` from a ping socket
/// that `protect` prepares first (binding it to the uplink, marking it), and
/// waits up to `wait` for the reply. Blocks.
pub fn ping_socket_echo(
    target: IpAddr,
    payload: &[u8],
    wait: Duration,
    protect: impl FnOnce(RawFd) -> Result<(), String>,
) -> Result<(), String> {
    static SEQUENCE: AtomicU16 = AtomicU16::new(1);
    let ipv6 = target.is_ipv6();
    let socket = open(ipv6)?;
    protect(socket.as_raw_fd())?;
    // A datagram socket either way: whole messages in and out.
    let socket = UdpSocket::from(socket);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let request = request(ipv6, std::process::id() as u16, sequence, payload);
    socket
        .send_to(&request, SocketAddr::new(target, 0))
        .map_err(|error| format!("send the ICMP echo: {error}"))?;
    let deadline = Instant::now() + wait;
    let mut buffer = vec![0_u8; 60 + 8 + payload.len()];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("no ICMP echo reply in time".into());
        }
        socket
            .set_read_timeout(Some(left))
            .map_err(|error| format!("time the ICMP echo: {error}"))?;
        match socket.recv(&mut buffer) {
            Ok(read) if is_reply(&buffer[..read], ipv6, sequence, payload) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err("no ICMP echo reply in time".into());
            }
            Err(error) => return Err(format!("receive the ICMP echo reply: {error}")),
        }
    }
}

fn open(ipv6: bool) -> Result<OwnedFd, String> {
    let (domain, protocol) = if ipv6 {
        (libc::AF_INET6, libc::IPPROTO_ICMPV6)
    } else {
        (libc::AF_INET, libc::IPPROTO_ICMP)
    };
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_DGRAM;
    let raw = unsafe { libc::socket(domain, kind, protocol) };
    if raw < 0 {
        return Err(format!(
            "open an ICMP socket: {}",
            io::Error::last_os_error()
        ));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    #[cfg(not(target_os = "linux"))]
    unsafe {
        libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(socket)
}

/// An echo request: ICMPv4 (type 8, RFC 792) with its checksum, or ICMPv6
/// (type 128, RFC 4443), whose pseudo-header checksum the kernel fills in.
fn request(ipv6: bool, identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + payload.len());
    message.extend_from_slice(&[if ipv6 { 128 } else { 8 }, 0, 0, 0]);
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(payload);
    if !ipv6 {
        let checksum = internet_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    message
}

/// Whether `datagram` is the echo reply (type 0 or 129) to the request with
/// `sequence` and `payload`. An IPv4 socket may deliver the IP header first
/// (macOS does), an IPv6 one never does; Linux replaces the identifier with
/// the socket's own, so the sequence and payload identify the reply.
fn is_reply(datagram: &[u8], ipv6: bool, sequence: u16, payload: &[u8]) -> bool {
    let message = if !ipv6 && datagram.first().is_some_and(|byte| byte >> 4 == 4) {
        match datagram.get(usize::from(datagram[0] & 0x0f) * 4..) {
            Some(message) => message,
            None => return false,
        }
    } else {
        datagram
    };
    message.len() >= 8
        && message[0] == if ipv6 { 129 } else { 0 }
        && message[1] == 0
        && message[6..8] == sequence.to_be_bytes()
        && message[8..] == *payload
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_carry_their_checksum_and_replies_are_recognized() {
        let request = request(false, 0x1234, 7, b"payload");
        assert_eq!(internet_checksum(&request), 0);
        let mut reply = request.clone();
        reply[0] = 0;
        assert!(is_reply(&reply, false, 7, b"payload"));
        let mut with_header = vec![0x45];
        with_header.extend_from_slice(&[0; 19]);
        with_header.extend_from_slice(&reply);
        assert!(is_reply(&with_header, false, 7, b"payload"));
        assert!(!is_reply(&request, false, 7, b"payload"));
        assert!(!is_reply(&reply, false, 8, b"payload"));
        assert!(!is_reply(&reply, false, 7, b"other"));

        let mut reply = super::request(true, 0x4321, 9, b"payload");
        reply[0] = 129;
        assert!(is_reply(&reply, true, 9, b"payload"));
    }

    /// Needs ping sockets: always on macOS, on Linux when the test's group is
    /// in `net.ipv4.ping_group_range`; elsewhere there is nothing to test.
    #[test]
    fn loopback_answers() {
        if open(false).is_err() {
            return;
        }
        ping_socket_echo(
            std::net::Ipv4Addr::LOCALHOST.into(),
            b"egrio echo",
            Duration::from_secs(2),
            |_| Ok(()),
        )
        .expect("loopback answers the echo");
    }
}
