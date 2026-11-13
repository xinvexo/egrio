//! Egress socket marking for the desktop's Core.
//!
//! Core's upstream sockets carry Egrio's fwmark so the TUN's policy routing
//! and kill switch let them past, but `SO_MARK` needs `CAP_NET_ADMIN`
//! (socket(7)), which the desktop does not have. The desktop passes each new
//! socket to the service over its marking socket as `SCM_RIGHTS` ancillary
//! data (unix(7)): the service receives a reference to the same socket,
//! checks that it is a TCP or UDP socket of an IPv4 or IPv6 family, sets the
//! mark on it and closes its reference. The mark stays on the desktop's own
//! socket.
//!
//! Each request is the byte `MARK_REQUEST` carrying exactly one descriptor;
//! each answer is a little-endian `i32` errno, 0 on success.

use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::unix::{bind_world_connectable, peer_credentials};

const MARK_REQUEST: u8 = 1;
/// How long the desktop waits for one answer before failing the dial.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
/// Ancillary space for one descriptor (cmsg(3)).
const ONE_DESCRIPTOR_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;

/// `cmsghdr`-aligned ancillary data for one descriptor.
#[repr(C)]
union AncillaryBuffer {
    bytes: [u8; ONE_DESCRIPTOR_SPACE],
    _align: libc::cmsghdr,
}

impl AncillaryBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; ONE_DESCRIPTOR_SPACE],
        }
    }
}

/// The service's side.
#[derive(Debug)]
pub struct MarkListener {
    listener: UnixListener,
    allows: fn(u32) -> bool,
    mark: u32,
}

impl MarkListener {
    /// Binds `path` for every local user; connections from uids `allows`
    /// refuses are closed unanswered.
    pub fn bind(path: &Path, allows: fn(u32) -> bool, mark: u32) -> io::Result<Self> {
        Ok(Self {
            listener: bind_world_connectable(path)?,
            allows,
            mark,
        })
    }

    /// Serves marking connections, each on its own thread, for the life of
    /// the process.
    pub fn serve(self) {
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) => {
                    eprintln!("egrio-service: marking connection accept failed: {error}");
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            let allowed = peer_credentials(&stream).is_ok_and(|peer| (self.allows)(peer.uid));
            if allowed {
                let mark = self.mark;
                // A thread the system will not start ends this
                // connection, not the listener.
                if let Err(error) = std::thread::Builder::new()
                    .name("egrio-marking".into())
                    .spawn(move || serve_marking(&stream, mark))
                {
                    eprintln!("egrio-service: marking thread did not start: {error}");
                }
            }
        }
    }
}

fn serve_marking(stream: &UnixStream, mark: u32) {
    loop {
        let errno = match receive_descriptor(stream) {
            Ok(Some(Ok(socket))) => match mark_socket(socket.as_fd(), mark) {
                Ok(()) => 0,
                Err(error) => error.raw_os_error().unwrap_or(libc::EIO),
            },
            Ok(Some(Err(errno))) => errno,
            Ok(None) | Err(_) => return,
        };
        if io::Write::write_all(&mut &*stream, &errno.to_le_bytes()).is_err() {
            return;
        }
    }
}

/// Receives one request. `Ok(None)` ends the connection; a request that does
/// not carry exactly one descriptor is answered with `EINVAL`, and every
/// descriptor it did carry is closed.
fn receive_descriptor(stream: &UnixStream) -> io::Result<Option<Result<OwnedFd, i32>>> {
    let mut request = [0u8; 1];
    let mut data = libc::iovec {
        iov_base: request.as_mut_ptr().cast(),
        iov_len: request.len(),
    };
    let mut ancillary = AncillaryBuffer::new();
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = std::ptr::from_mut(&mut ancillary).cast();
    message.msg_controllen = ONE_DESCRIPTOR_SPACE as _;
    let received = loop {
        // Close-on-exec: the service runs ip, nft and resolvectl children.
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            break received;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    // SAFETY: recvmsg filled `message` and its ancillary buffer.
    let mut descriptors = unsafe { received_descriptors(&message) };
    if received == 0 {
        return Ok(None);
    }
    if request[0] != MARK_REQUEST
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || descriptors.len() != 1
    {
        return Ok(Some(Err(libc::EINVAL)));
    }
    Ok(descriptors.pop().map(Ok))
}

/// Takes ownership of every descriptor in `message`'s `SCM_RIGHTS` data.
///
/// # Safety
///
/// `message` must have been filled by `recvmsg`.
unsafe fn received_descriptors(message: &libc::msghdr) -> Vec<OwnedFd> {
    let mut descriptors = Vec::new();
    let mut header = libc::CMSG_FIRSTHDR(message);
    while !header.is_null() {
        if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
            let data = libc::CMSG_DATA(header).cast::<RawFd>();
            let length = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
            for index in 0..length / size_of::<RawFd>() {
                descriptors.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
            }
        }
        header = libc::CMSG_NXTHDR(message, header);
    }
    descriptors
}

/// Sets `mark` on a TCP, UDP or ICMP datagram ("ping") socket of an IPv4 or
/// IPv6 family; the Core relays echo routed DIRECT from a ping socket.
fn mark_socket(socket: BorrowedFd<'_>, mark: u32) -> io::Result<()> {
    let domain = socket_option(socket, libc::SO_DOMAIN)?;
    let kind = socket_option(socket, libc::SO_TYPE)?;
    let protocol = socket_option(socket, libc::SO_PROTOCOL)?;
    if !matches!(domain, libc::AF_INET | libc::AF_INET6)
        || !matches!(
            (kind, protocol),
            (libc::SOCK_STREAM, libc::IPPROTO_TCP)
                | (libc::SOCK_DGRAM, libc::IPPROTO_UDP)
                | (libc::SOCK_DGRAM, libc::IPPROTO_ICMP)
                | (libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6)
        )
    {
        return Err(io::Error::from_raw_os_error(libc::EPROTONOSUPPORT));
    }
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&mark).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn socket_option(socket: BorrowedFd<'_>, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// The desktop's side: one connection to the service, one request at a time.
#[derive(Debug)]
pub struct MarkClient {
    path: PathBuf,
    connection: Mutex<Option<UnixStream>>,
}

impl MarkClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            connection: Mutex::new(None),
        }
    }

    /// Has the service mark `socket`. A connection that ended (the service
    /// restarted) is replaced once; marking is idempotent, so a request whose
    /// answer was lost may be repeated.
    pub fn mark(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut failure = None;
        for _ in 0..2 {
            let stream = match connection.take() {
                Some(stream) => stream,
                None => self.connect()?,
            };
            match request(&stream, socket) {
                Ok(errno) => {
                    *connection = Some(stream);
                    return match errno {
                        0 => Ok(()),
                        errno => Err(io::Error::from_raw_os_error(errno)),
                    };
                }
                Err(error) => failure = Some(error),
            }
        }
        Err(failure.expect("a failed attempt records its error"))
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        stream.set_write_timeout(Some(ANSWER_TIMEOUT))?;
        Ok(stream)
    }
}

fn request(stream: &UnixStream, socket: BorrowedFd<'_>) -> io::Result<i32> {
    send_descriptor(stream, socket)?;
    let mut answer = [0u8; 4];
    (&*stream).read_exact(&mut answer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the Egrio service closed the marking connection",
            )
        } else {
            error
        }
    })?;
    Ok(i32::from_le_bytes(answer))
}

fn send_descriptor(stream: &UnixStream, socket: BorrowedFd<'_>) -> io::Result<()> {
    let request = [MARK_REQUEST];
    let mut data = libc::iovec {
        iov_base: request.as_ptr().cast_mut().cast(),
        iov_len: request.len(),
    };
    let mut ancillary = AncillaryBuffer::new();
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = std::ptr::from_mut(&mut ancillary).cast();
    message.msg_controllen = ONE_DESCRIPTOR_SPACE as _;
    // SAFETY: the ancillary buffer holds one cmsghdr plus one descriptor.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write_unaligned(socket.as_raw_fd());
    }
    loop {
        // MSG_NOSIGNAL: a service that went away is an error, not SIGPIPE.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        match sent {
            1 => return Ok(()),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the marking request was not sent",
                ))
            }
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MARK: u32 = 0xe672;

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("egrio-mark-{name}-{}.sock", std::process::id()))
    }

    fn own_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn serve(name: &str, allows: fn(u32) -> bool) -> MarkClient {
        let path = socket_path(name);
        let listener = MarkListener::bind(&path, allows, TEST_MARK).unwrap();
        std::thread::spawn(move || listener.serve());
        MarkClient::new(path)
    }

    fn socket(domain: libc::c_int, kind: libc::c_int) -> OwnedFd {
        let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn mark_of(socket: BorrowedFd<'_>) -> u32 {
        let mut mark = 0u32;
        let mut length = size_of::<u32>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                std::ptr::from_mut(&mut mark).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        mark
    }

    #[test]
    fn tcp_and_udp_sockets_of_both_families_come_back_marked() {
        let client = serve("marked", |uid| uid == own_uid());
        for (domain, kind) in [
            (libc::AF_INET, libc::SOCK_STREAM),
            (libc::AF_INET6, libc::SOCK_STREAM),
            (libc::AF_INET, libc::SOCK_DGRAM),
            (libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK),
        ] {
            let socket = socket(domain, kind);
            let result = client.mark(socket.as_fd());
            if own_uid() == 0 {
                result.unwrap();
                assert_eq!(mark_of(socket.as_fd()), TEST_MARK);
            } else {
                // Only a service with CAP_NET_ADMIN can set the mark.
                assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
            }
        }
    }

    #[test]
    fn descriptors_other_than_inet_tcp_or_udp_sockets_are_refused() {
        let client = serve("refused-kinds", |uid| uid == own_uid());
        let (unix, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            client.mark(unix.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::EPROTONOSUPPORT)
        );
        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert_eq!(
            client.mark(file.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::ENOTSOCK)
        );
        // Raw sockets need privileges the Core does not have; a ping socket
        // is the ICMP kind it uses, and only datagram ICMP is accepted.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if raw >= 0 {
            let raw = unsafe { OwnedFd::from_raw_fd(raw) };
            assert_eq!(
                client.mark(raw.as_fd()).unwrap_err().raw_os_error(),
                Some(libc::EPROTONOSUPPORT)
            );
        }
        let mut descriptors = [0; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let (read, _write) = unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        };
        assert_eq!(
            client.mark(read.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::ENOTSOCK)
        );
    }

    #[test]
    fn a_peer_the_helper_does_not_serve_gets_no_marks() {
        let client = serve("stranger", |uid| uid != own_uid());
        let socket = socket(libc::AF_INET, libc::SOCK_STREAM);
        let error = client.mark(socket.as_fd()).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
            ),
            "{error}"
        );
        assert_eq!(mark_of(socket.as_fd()), 0);
    }

    #[test]
    fn a_restarted_service_is_reconnected_transparently() {
        let path = socket_path("restart");
        let first = MarkListener::bind(&path, |uid| uid == own_uid(), TEST_MARK).unwrap();
        let client = MarkClient::new(&path);
        // One served connection, then the "service" goes away.
        let served = std::thread::spawn(move || {
            let (stream, _) = first.listener.accept().unwrap();
            let socket = receive_descriptor(&stream).unwrap().unwrap().unwrap();
            drop(socket);
            io::Write::write_all(&mut &stream, &0i32.to_le_bytes()).unwrap();
        });
        let socket = socket(libc::AF_INET, libc::SOCK_STREAM);
        client.mark(socket.as_fd()).unwrap();
        served.join().unwrap();
        let second = MarkListener::bind(&path, |uid| uid == own_uid(), TEST_MARK).unwrap();
        std::thread::spawn(move || second.serve());
        let result = client.mark(socket.as_fd());
        if own_uid() == 0 {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        }
    }
}
