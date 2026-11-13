//! Control transport over a Unix domain stream socket.
//!
//! The service socket is connectable by every local user; each connection
//! is authorized by the service's [`PeerPolicy`] from what the kernel
//! recorded of the peer at `connect(2)`: the uids allowed at installation on
//! Linux (`SO_PEERCRED`, unix(7)), the peer's code signature on macOS. An
//! unauthorized peer's hello is answered with an authentication error and
//! the connection ends; it has two seconds to send that hello, and at most
//! sixteen such peers are waiting at once, so a process that may not use the
//! service cannot hold its threads.
//!
//! A response may carry one descriptor (`SCM_RIGHTS`, unix(7) and unix(4)):
//! it rides the first bytes of that response's frame, and the desktop's
//! reader keeps it until the caller of the request takes it.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::framing::{encode_frame, read_frame, write_frame, FrameError};
use crate::protocol::{
    protocol_version, ControlEnvelope, ControlErrorCode, ControlRequest, ControlResponse,
};
use crate::session::{ControlRequestHandler, ControlServerSession};
use crate::transport::{
    ControlConnection, ControlFuture, ControlTransport, TransportError, TransportErrorKind,
};

/// The peer process as the kernel recorded it at `connect(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Reads `SO_PEERCRED` from a connected Unix stream socket (socket(7),
/// unix(7)).
#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// The peer's effective ids (getpeereid(3)) and its process id
/// (sys/un.h `LOCAL_PEERPID`).
#[cfg(target_os = "macos")]
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: getpeereid writes the two ids.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
    // SAFETY: getsockopt writes one pid_t.
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut pid).cast(),
            &mut length,
        )
    };
    if got != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials { pid, uid, gid })
}

/// Who may control the service, decided per connection.
pub trait PeerPolicy: Send + Sync + std::fmt::Debug {
    /// Why `peer` may not control the service, if it may not.
    fn authorize(&self, stream: &UnixStream, peer: &PeerCredentials) -> Result<(), String>;
}

/// The desktop's side: connects to the service socket.
#[derive(Clone, Debug)]
pub struct UnixSocketTransport {
    path: PathBuf,
}

impl UnixSocketTransport {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ControlTransport for UnixSocketTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::task::spawn_blocking(move || {
                UnixStream::connect(&path).map_err(|error| {
                    TransportError::new(
                        TransportErrorKind::ConnectFailed,
                        format!(
                            "failed to connect to the Egrio service at {}: {error}",
                            path.display()
                        ),
                    )
                })
            })
            .await
            .map_err(|error| {
                TransportError::new(
                    TransportErrorKind::ConnectFailed,
                    format!("Unix socket connect task failed: {error}"),
                )
            })??;
            let connection: Arc<dyn ControlConnection> =
                Arc::new(UnixSocketConnection::new(stream)?);
            Ok(connection)
        })
    }
}

#[derive(Debug)]
struct UnixSocketConnection {
    reader: Arc<Mutex<DescriptorReader>>,
    /// Descriptors that arrived with responses, oldest first.
    received: Arc<Mutex<Vec<OwnedFd>>>,
    writer: Arc<Mutex<UnixStream>>,
    /// Shuts the socket down without waiting for a reader blocked in a
    /// frame read, which holds the reader lock.
    control: UnixStream,
    closed: Arc<AtomicBool>,
}

impl UnixSocketConnection {
    fn new(stream: UnixStream) -> Result<Self, TransportError> {
        let clone = |stream: &UnixStream| {
            stream.try_clone().map_err(|error| {
                TransportError::new(TransportErrorKind::ConnectFailed, error.to_string())
            })
        };
        let received = Arc::new(Mutex::new(Vec::new()));
        Ok(Self {
            reader: Arc::new(Mutex::new(DescriptorReader {
                stream: clone(&stream)?,
                received: Arc::clone(&received),
            })),
            received,
            control: clone(&stream)?,
            writer: Arc::new(Mutex::new(stream)),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Drop for UnixSocketConnection {
    fn drop(&mut self) {
        self.close_now();
    }
}

impl ControlConnection for UnixSocketConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        let reader = Arc::clone(&self.reader);
        let closed = Arc::clone(&self.closed);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut reader = reader.lock().expect("Unix socket reader mutex");
                match read_frame(&mut *reader) {
                    Ok(Some(envelope)) => Ok(envelope),
                    Ok(None) => Err(TransportError::disconnected(
                        "Egrio service closed the connection",
                    )),
                    Err(_) if closed.load(Ordering::Acquire) => Err(TransportError::disconnected(
                        "Unix socket control connection closed",
                    )),
                    Err(error) => Err(frame_read_error(error)),
                }
            })
            .await
            .map_err(|error| {
                TransportError::disconnected(format!("Unix socket read task failed: {error}"))
            })?
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        let writer = Arc::clone(&self.writer);
        let closed = Arc::clone(&self.closed);
        let envelope = envelope.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                if closed.load(Ordering::Acquire) {
                    return Err(TransportError::disconnected(
                        "Unix socket control connection closed",
                    ));
                }
                let mut writer = writer.lock().expect("Unix socket writer mutex");
                write_frame(&mut *writer, &envelope).map_err(frame_write_error)
            })
            .await
            .map_err(|error| {
                TransportError::possibly_delivered(format!(
                    "Unix socket write task failed: {error}"
                ))
            })?
        })
    }

    fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.control.shutdown(std::net::Shutdown::Both);
        }
    }

    fn take_descriptor(&self) -> Option<OwnedFd> {
        let mut received = self
            .received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!received.is_empty()).then(|| received.remove(0))
    }
}

/// Reads the response stream, keeping the descriptors that ride it.
#[derive(Debug)]
struct DescriptorReader {
    stream: UnixStream,
    received: Arc<Mutex<Vec<OwnedFd>>>,
}

impl Read for DescriptorReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut descriptors = Vec::new();
        let read = receive(&self.stream, buffer, &mut descriptors)?;
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(descriptors);
        Ok(read)
    }
}

/// Room for the descriptors one response may carry, with headroom so a
/// misbehaving peer's extras are received and closed instead of truncated.
const ANCILLARY_DESCRIPTORS: usize = 4;
const ANCILLARY_SPACE: usize =
    unsafe { libc::CMSG_SPACE((ANCILLARY_DESCRIPTORS * std::mem::size_of::<RawFd>()) as u32) }
        as usize;

/// `cmsghdr`-aligned ancillary data (cmsg(3)).
#[repr(C)]
union Ancillary {
    bytes: [u8; ANCILLARY_SPACE],
    _align: libc::cmsghdr,
}

/// One `recvmsg` into `buffer`; descriptors that came with it are pushed to
/// `descriptors`, close-on-exec.
fn receive(
    stream: &UnixStream,
    buffer: &mut [u8],
    descriptors: &mut Vec<OwnedFd>,
) -> io::Result<usize> {
    let mut data = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut ancillary = Ancillary {
        bytes: [0; ANCILLARY_SPACE],
    };
    // SAFETY: an all-zero msghdr is valid before its fields are set.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = std::ptr::from_mut(&mut ancillary).cast();
    message.msg_controllen = ANCILLARY_SPACE as _;
    let received = loop {
        // SAFETY: `message` points at live buffers.
        let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
        if received >= 0 {
            break received as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    // SAFETY: recvmsg filled `message` and its ancillary buffer.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                let length = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for index in 0..length / std::mem::size_of::<RawFd>() {
                    let descriptor = OwnedFd::from_raw_fd(data.add(index).read_unaligned());
                    libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                    descriptors.push(descriptor);
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    Ok(received)
}

/// Writes `bytes`, the first of them carrying `descriptor`.
fn send_with_descriptor(
    stream: &UnixStream,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
) -> io::Result<()> {
    let one = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut ancillary = Ancillary {
        bytes: [0; ANCILLARY_SPACE],
    };
    let mut data = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: an all-zero msghdr is valid before its fields are set.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = std::ptr::from_mut(&mut ancillary).cast();
    message.msg_controllen = one as _;
    // SAFETY: the ancillary buffer holds one cmsghdr plus one descriptor.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write_unaligned(descriptor.as_raw_fd());
    }
    let sent = loop {
        // SAFETY: `message` points at live buffers. A peer that went away is
        // an error: Rust programs ignore SIGPIPE.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) };
        if sent > 0 {
            break sent as usize;
        }
        let error = io::Error::last_os_error();
        if sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "the response was not sent",
            ));
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    (&*stream).write_all(&bytes[sent..])
}

/// How long a peer the policy refused has to send the request its refusal
/// answers, and to take the answer. The socket is connectable by every local
/// user and the service gives each connection a thread, so a refused peer
/// that sent nothing held that thread for as long as it liked.
const REFUSED_PEER_TIMEOUT: Duration = Duration::from_secs(2);

/// Refused peers that may be waiting for their answer at once; past it a
/// refused peer is dropped unanswered. With the time above, this bounds the
/// threads a process that may not use the service can hold in it. Peers the
/// policy accepts are not counted: they are the user the service runs for.
const REFUSED_PEERS: usize = 16;

/// One of the [`REFUSED_PEERS`] places, held until the connection ends.
#[derive(Debug)]
struct RefusedPlace(Arc<AtomicUsize>);

impl RefusedPlace {
    fn take(taken: &Arc<AtomicUsize>) -> Option<Self> {
        taken
            .try_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < REFUSED_PEERS).then_some(taken + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(taken)))
    }
}

impl Drop for RefusedPlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The service's side: accepts control connections and authorizes them.
#[derive(Debug)]
pub struct UnixSocketListener {
    listener: UnixListener,
    policy: Arc<dyn PeerPolicy>,
    refused: Arc<AtomicUsize>,
    refused_timeout: Duration,
}

impl UnixSocketListener {
    /// Binds `path`, connectable by every local user: `policy` authorizes
    /// each connection.
    pub fn bind(path: &Path, policy: Arc<dyn PeerPolicy>) -> io::Result<Self> {
        Ok(Self {
            listener: bind_world_connectable(path)?,
            policy,
            refused: Arc::default(),
            refused_timeout: REFUSED_PEER_TIMEOUT,
        })
    }

    pub fn accept(&self) -> Result<UnixServerConnection, TransportError> {
        let (stream, _) = self.listener.accept().map_err(|error| {
            TransportError::new(TransportErrorKind::ConnectFailed, error.to_string())
        })?;
        let peer = peer_credentials(&stream).map_err(|error| {
            TransportError::new(
                TransportErrorKind::Authentication,
                format!("failed to read the peer credentials: {error}"),
            )
        })?;
        let authorized = self.policy.authorize(&stream, &peer);
        let refused = match &authorized {
            Ok(()) => None,
            Err(_) => {
                let place = RefusedPlace::take(&self.refused).ok_or_else(|| {
                    TransportError::new(
                        TransportErrorKind::Authentication,
                        "too many refused peers are waiting for their answer",
                    )
                })?;
                // Both directions: a peer that never reads would park the
                // write of its refusal instead.
                stream
                    .set_read_timeout(Some(self.refused_timeout))
                    .and_then(|()| stream.set_write_timeout(Some(self.refused_timeout)))
                    .map_err(|error| {
                        TransportError::new(TransportErrorKind::ConnectFailed, error.to_string())
                    })?;
                Some(place)
            }
        };
        let reader = stream.try_clone().map_err(|error| {
            TransportError::new(TransportErrorKind::ConnectFailed, error.to_string())
        })?;
        Ok(UnixServerConnection {
            authorized,
            peer,
            reader: Mutex::new(reader),
            writer: Mutex::new(stream),
            _refused: refused,
        })
    }
}

/// One accepted control connection.
#[derive(Debug)]
pub struct UnixServerConnection {
    peer: PeerCredentials,
    authorized: Result<(), String>,
    reader: Mutex<UnixStream>,
    writer: Mutex<UnixStream>,
    /// A refused peer's place among those being answered.
    _refused: Option<RefusedPlace>,
}

impl UnixServerConnection {
    pub fn peer(&self) -> PeerCredentials {
        self.peer
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized.is_ok()
    }

    fn read_request(&self) -> Result<Option<ControlEnvelope<ControlRequest>>, TransportError> {
        let mut reader = self.reader.lock().expect("Unix socket server reader mutex");
        read_frame(&mut *reader).map_err(frame_read_error)
    }

    fn write_response(
        &self,
        response: &ControlEnvelope<ControlResponse>,
        descriptor: Option<OwnedFd>,
    ) -> Result<(), TransportError> {
        let mut writer = self.writer.lock().expect("Unix socket server writer mutex");
        let Some(descriptor) = descriptor else {
            return write_frame(&mut *writer, response).map_err(frame_write_error);
        };
        let frame = encode_frame(response).map_err(frame_write_error)?;
        send_with_descriptor(&writer, &frame, std::os::fd::AsFd::as_fd(&descriptor))
            .map_err(|error| frame_write_error(FrameError::Io(error)))
    }

    /// Serves one request; `Ok(false)` ends the connection. An unauthorized
    /// peer gets an authentication error for its first request and nothing
    /// else.
    pub fn serve_once(
        &self,
        session: &ControlServerSession,
        handler: &dyn ControlRequestHandler,
    ) -> Result<bool, TransportError> {
        let Some(request) = self.read_request()? else {
            return Ok(false);
        };
        if let Err(reason) = &self.authorized {
            let refusal = ControlEnvelope {
                protocol: protocol_version(),
                request_id: request.request_id,
                runtime_id: request.runtime_id,
                session_id: None,
                body: ControlResponse::Error {
                    code: ControlErrorCode::AuthenticationFailed,
                    message: reason.clone(),
                },
            };
            let _ = self.write_response(&refusal, None);
            return Ok(false);
        }
        let response = session.handle(request, handler);
        if let Err(error) = self.write_response(&response, handler.take_descriptor()) {
            handler.response_failed(&response.body);
            return Err(error);
        }
        Ok(true)
    }
}

/// Binds a service socket at `path`, replacing a stale socket file, and
/// lets every local user connect; each service authorizes its peers.
pub fn bind_world_connectable(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn frame_read_error(error: FrameError) -> TransportError {
    let kind = match error {
        FrameError::Io(_) => TransportErrorKind::Disconnected,
        FrameError::Json(_) | FrameError::InvalidLength(_) => TransportErrorKind::Protocol,
    };
    TransportError::new(kind, error.to_string())
}

fn frame_write_error(error: FrameError) -> TransportError {
    let kind = match error {
        FrameError::Io(_) => TransportErrorKind::PossiblyDelivered,
        FrameError::Json(_) | FrameError::InvalidLength(_) => TransportErrorKind::Protocol,
    };
    TransportError::new(kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use egrio_runtime::{CapabilityKind, CapabilityObservation, RuntimeId};

    use super::*;
    use crate::client::ControlClient;

    /// Serves the listed uids.
    #[derive(Debug)]
    struct AllowedUids(Vec<u32>);

    impl PeerPolicy for AllowedUids {
        fn authorize(&self, _stream: &UnixStream, peer: &PeerCredentials) -> Result<(), String> {
            if self.0.contains(&peer.uid) {
                Ok(())
            } else {
                Err(format!("uid {} is not allowed", peer.uid))
            }
        }
    }

    #[derive(Debug)]
    struct ObservingHandler;

    impl ControlRequestHandler for ObservingHandler {
        fn handle(
            &self,
            request: ControlRequest,
        ) -> Result<ControlResponse, (ControlErrorCode, String)> {
            match request {
                ControlRequest::Observe { capability } => {
                    Ok(ControlResponse::Observation(CapabilityObservation {
                        capability,
                        active: true,
                        verified: true,
                    }))
                }
                _ => Err((ControlErrorCode::UnsupportedMethod, "test handler".into())),
            }
        }
    }

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("egrio-{name}-{}.sock", std::process::id()))
    }

    /// Serves every connection on its own thread until the listener drops.
    fn serve(listener: UnixSocketListener) {
        std::thread::spawn(move || {
            while let Ok(connection) = listener.accept() {
                std::thread::spawn(move || {
                    let session = ControlServerSession::new("test", vec![CapabilityKind::Dns]);
                    while let Ok(true) = connection.serve_once(&session, &ObservingHandler) {}
                });
            }
        });
    }

    fn own_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    /// The socket takes connections from every local user and each gets a
    /// thread, so a peer the policy refuses must not be able to keep one: it
    /// has a bounded time to send the request its refusal answers.
    #[test]
    fn a_refused_peer_that_sends_nothing_is_dropped_when_its_time_is_up() {
        let path = socket_path("refused-silent");
        let mut listener = UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![]))).unwrap();
        listener.refused_timeout = Duration::from_millis(50);
        let silent = UnixStream::connect(&path).unwrap();
        let connection = listener.accept().expect("a refused peer is still answered");
        assert!(!connection.is_authorized());

        let session = ControlServerSession::new("test", vec![CapabilityKind::Dns]);
        let started = std::time::Instant::now();
        let served = connection.serve_once(&session, &ObservingHandler);
        assert!(
            served.is_err(),
            "the read gave up on the silent peer: {served:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(silent);
        let _ = std::fs::remove_file(path);
    }

    /// Past the bound a refused peer is dropped unanswered, and a place comes
    /// back when a refused connection ends; peers the policy accepts are not
    /// counted.
    #[test]
    fn refused_peers_wait_for_their_answer_in_bounded_number() {
        let path = socket_path("refused-bound");
        let listener = UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![]))).unwrap();
        let mut peers = Vec::new();
        let mut held = Vec::new();
        for _ in 0..REFUSED_PEERS {
            peers.push(UnixStream::connect(&path).unwrap());
            held.push(listener.accept().expect("a place is free"));
        }
        peers.push(UnixStream::connect(&path).unwrap());
        let over = listener.accept().expect_err("no place is left");
        assert_eq!(over.kind(), TransportErrorKind::Authentication);

        held.pop();
        peers.push(UnixStream::connect(&path).unwrap());
        assert!(listener.accept().is_ok(), "the place came back");
        let _ = std::fs::remove_file(path);

        let path = socket_path("accepted-unbounded");
        let listener =
            UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![own_uid()]))).unwrap();
        let mut accepted = Vec::new();
        for _ in 0..REFUSED_PEERS + 4 {
            peers.push(UnixStream::connect(&path).unwrap());
            accepted.push(listener.accept().expect("an accepted peer takes no place"));
        }
        assert!(accepted.iter().all(UnixServerConnection::is_authorized));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_allowed_peer_runs_a_control_session_over_the_socket() {
        let path = socket_path("allowed");
        serve(UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![own_uid()]))).unwrap());
        let client = ControlClient::connect(
            Arc::new(UnixSocketTransport::new(&path)),
            RuntimeId::new(),
            "test",
        )
        .await
        .expect("an allowed uid completes the hello");
        let answer = client
            .request(ControlRequest::Observe {
                capability: CapabilityKind::Dns,
            })
            .await
            .unwrap();
        assert!(matches!(
            answer,
            ControlResponse::Observation(CapabilityObservation { active: true, .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_outside_the_allowed_uids_is_refused_at_hello() {
        let path = socket_path("refused");
        let stranger = own_uid().wrapping_add(1);
        serve(UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![stranger]))).unwrap());
        let error = ControlClient::connect(
            Arc::new(UnixSocketTransport::new(&path)),
            RuntimeId::new(),
            "test",
        )
        .await
        .expect_err("the peer uid is not allowed");
        assert_eq!(error.kind(), TransportErrorKind::Authentication, "{error}");
        assert!(error.to_string().contains("not allowed"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// Answers an observation with a descriptor riding the response.
    #[derive(Debug)]
    struct DescriptorHandler(Mutex<Option<OwnedFd>>);

    impl ControlRequestHandler for DescriptorHandler {
        fn handle(
            &self,
            request: ControlRequest,
        ) -> Result<ControlResponse, (ControlErrorCode, String)> {
            ObservingHandler.handle(request)
        }

        fn take_descriptor(&self) -> Option<OwnedFd> {
            self.0.lock().unwrap().take()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_descriptor_rides_its_response_to_the_caller() {
        let path = socket_path("descriptor");
        let listener =
            UnixSocketListener::bind(&path, Arc::new(AllowedUids(vec![own_uid()]))).unwrap();
        let (sent, mut kept) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let connection = listener.accept().unwrap();
            let session = ControlServerSession::new("test", vec![CapabilityKind::Dns]);
            let handler = DescriptorHandler(Mutex::new(None));
            // The hello carries none; the observation carries `sent`.
            connection.serve_once(&session, &handler).unwrap();
            *handler.0.lock().unwrap() = Some(OwnedFd::from(sent));
            connection.serve_once(&session, &handler).unwrap();
        });
        let client = ControlClient::connect(
            Arc::new(UnixSocketTransport::new(&path)),
            RuntimeId::new(),
            "test",
        )
        .await
        .unwrap();
        assert!(client.take_descriptor().is_none());
        client
            .request(ControlRequest::Observe {
                capability: CapabilityKind::Dns,
            })
            .await
            .unwrap();
        let mut received = UnixStream::from(client.take_descriptor().expect("the descriptor"));
        received.write_all(b"through").unwrap();
        let mut echoed = [0u8; 7];
        kept.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"through");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn peer_credentials_name_this_process() {
        let (left, _right) = UnixStream::pair().unwrap();
        let peer = peer_credentials(&left).unwrap();
        assert_eq!(peer.uid, own_uid());
        assert_eq!(peer.pid, std::process::id() as i32);
    }
}
