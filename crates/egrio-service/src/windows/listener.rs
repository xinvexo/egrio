//! The service's side of the control pipe: the instances clients connect to,
//! who a client is, and the requests it sends.
//!
//! The listener holds an instance of the pipe from the moment it is bound
//! and makes the next one before it hands a connected one on, so the pipe's
//! name is never free. The first is created with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE`, which fails if the name is taken, and
//! creating a further instance of an existing pipe takes
//! `FILE_CREATE_PIPE_INSTANCE`, which the pipe's ACL gives the system and
//! administrators only: no other process can ever serve this name.
//!
//! Every local user may connect, so what a connection costs before its
//! client is known to be Egrio is bounded: a program the service does not
//! admit is turned away by the accepting thread at once, and an admitted one
//! has [`FIRST_FRAME_TIMEOUT`] to send its first frame, at most
//! [`UNIDENTIFIED_CLIENTS`] of them at a time.

use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_NO_DATA};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::protocol::{ControlEnvelope, ControlRequest};
use crate::session::{ControlRequestHandler, ControlServerSession};
use crate::transport::{TransportError, TransportErrorKind};

use super::identity::{
    admit_named_pipe_client, authenticate_named_pipe_client, AdmittedProcess, AuthenticatedClient,
    OwnedHandle,
};
use super::pipe::{self, Event, Interrupt, PipeEnd, Watch};
use super::transport::{
    frame_read_error, frame_write_error, wide_null, windows_named_pipe_endpoint,
};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
/// FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_APPEND_DATA, which is
/// FILE_CREATE_PIPE_INSTANCE for named pipes.
#[cfg(test)]
const PIPE_AUTHENTICATED_USER_ACCESS: u32 = 0x0012_019B;
const PIPE_SECURITY_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019B;;;AU)";

/// How long an admitted client has to send its first frame. A client sends
/// its Hello as soon as it has connected; the time is for one that never
/// does, which holds a thread of the service until it is up.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Admitted clients that may be connected without having sent their first
/// frame. With the time above, this bounds the threads that clients nobody
/// has identified yet can hold; past it a new one is dropped unanswered.
const UNIDENTIFIED_CLIENTS: usize = 16;

/// One of the [`UNIDENTIFIED_CLIENTS`] places, held until the client is
/// identified or dropped.
#[derive(Debug)]
struct UnidentifiedPlace(Arc<AtomicUsize>);

impl UnidentifiedPlace {
    fn take(taken: &Arc<AtomicUsize>) -> Option<Self> {
        taken
            .try_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < UNIDENTIFIED_CLIENTS).then_some(taken + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(taken)))
    }
}

impl Drop for UnidentifiedPlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A pipe instance's server end. Dropping it disconnects whoever is
/// connected to it.
#[derive(Debug)]
struct ServerEnd(PipeEnd);

impl ServerEnd {
    /// Makes an instance a client came to ready to wait for the next one.
    fn disconnect(&self) {
        // SAFETY: the handle is a pipe's server end. Without a client the
        // call fails and changes nothing.
        unsafe { DisconnectNamedPipe(self.0.raw()) };
    }
}

impl Drop for ServerEnd {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// The service's side: accepts control connections and admits their
/// programs.
#[derive(Debug)]
pub struct WindowsNamedPipeListener {
    endpoint: String,
    /// The instance the next client connects to.
    waiting: Mutex<ServerEnd>,
    unidentified: Arc<AtomicUsize>,
    first_frame_timeout: Duration,
}

impl WindowsNamedPipeListener {
    /// Takes the pipe's name: fails if any process already serves it.
    pub fn bind(endpoint: impl Into<String>) -> Result<Self, TransportError> {
        let endpoint = endpoint.into();
        let waiting = Mutex::new(create_instance(&endpoint, true)?);
        Ok(Self {
            endpoint,
            waiting,
            unidentified: Arc::default(),
            first_frame_timeout: FIRST_FRAME_TIMEOUT,
        })
    }

    pub fn for_service(service_name: &str) -> Result<Self, TransportError> {
        Self::bind(windows_named_pipe_endpoint(service_name))
    }

    /// The time an admitted client has to send its first frame, for a test
    /// that waits it out.
    #[doc(hidden)]
    pub fn with_first_frame_timeout(mut self, timeout: Duration) -> Self {
        self.first_frame_timeout = timeout;
        self
    }

    /// Waits for a client; `None` once `stop` is set. A client whose program
    /// the service does not admit, or that finds every place for the
    /// unidentified taken, is an authentication error and already gone.
    pub fn accept(&self, stop: &Event) -> Result<Option<AdmittedClient>, TransportError> {
        let mut waiting = lock(&self.waiting);
        let watch = Watch {
            events: &[stop],
            deadline: None,
        };
        loop {
            match waiting.0.connect(watch) {
                Ok(Ok(())) => break,
                Ok(Err(_)) => return Ok(None),
                // A client that came and went before the instance waited
                // for one: disconnected, the instance waits again.
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    waiting.disconnect();
                }
                Err(error) => {
                    // An instance that cannot wait is replaced, its
                    // successor made first so the name stays taken.
                    if let Ok(fresh) = create_instance(&self.endpoint, false) {
                        *waiting = fresh;
                    }
                    return Err(TransportError::new(
                        TransportErrorKind::ConnectFailed,
                        format!(
                            "failed to accept on Windows named pipe '{}': {error}",
                            self.endpoint
                        ),
                    ));
                }
            }
        }
        let refuse = |waiting: &ServerEnd, reason: String| {
            waiting.disconnect();
            Err(TransportError::new(
                TransportErrorKind::Authentication,
                reason,
            ))
        };
        let process = match admit_named_pipe_client(waiting.0.raw()) {
            Ok(process) => process,
            Err(reason) => return refuse(&waiting, reason),
        };
        let Some(place) = UnidentifiedPlace::take(&self.unidentified) else {
            return refuse(
                &waiting,
                "too many clients have yet to send their first control frame".into(),
            );
        };
        let successor = match create_instance(&self.endpoint, false) {
            Ok(successor) => successor,
            Err(error) => {
                waiting.disconnect();
                return Err(error);
            }
        };
        let pipe = std::mem::replace(&mut *waiting, successor);
        Ok(Some(AdmittedClient {
            pipe,
            process,
            first_frame: self.first_frame_timeout,
            _place: place,
        }))
    }
}

/// A connected client whose program the service admits and whose first
/// frame has yet to come.
#[derive(Debug)]
pub struct AdmittedClient {
    pipe: ServerEnd,
    process: AdmittedProcess,
    first_frame: Duration,
    _place: UnidentifiedPlace,
}

impl AdmittedClient {
    /// Reads the client's first frame, the session-less Hello, and then
    /// checks who sent it: the pipe lets the service act as its client only
    /// once it has read from it. The frame is served ahead of the pipe.
    /// Nothing is dispatched before the client is identified. Meant for a
    /// thread of the connection's own: it waits for the client.
    pub fn identify(self, stop: &Event) -> Result<WindowsServerConnection, TransportError> {
        let watch = Watch {
            events: &[stop],
            deadline: Some(Instant::now() + self.first_frame),
        };
        let first = match pipe::read_frame(&self.pipe.0, watch).map_err(frame_read_error)? {
            Ok(Some(first)) => first,
            Ok(None) => {
                return Err(TransportError::disconnected(
                    "client closed the pipe before the first control frame",
                ))
            }
            Err(Interrupt::Deadline) => {
                return Err(TransportError::disconnected(
                    "client did not send a control frame within the first-frame timeout",
                ))
            }
            Err(Interrupt::Event(_)) => {
                return Err(TransportError::disconnected("the service is stopping"))
            }
        };
        let client = authenticate_named_pipe_client(self.pipe.0.raw(), self.process)
            .map_err(|error| TransportError::new(TransportErrorKind::Authentication, error))?;
        Ok(WindowsServerConnection {
            client,
            pipe: self.pipe,
            first: Mutex::new(Some(first)),
        })
    }
}

/// One identified control connection.
#[derive(Debug)]
pub struct WindowsServerConnection {
    client: AuthenticatedClient,
    pipe: ServerEnd,
    /// The frame read before the client could be identified.
    first: Mutex<Option<ControlEnvelope<ControlRequest>>>,
}

/// What a wait for a connection's next request came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Served {
    /// A request, answered.
    Request,
    /// The client closed the connection.
    Closed,
    /// The event at this index of those watched was set first.
    Interrupted(usize),
}

impl WindowsServerConnection {
    pub fn client(&self) -> &AuthenticatedClient {
        &self.client
    }

    /// Serves the connection's next request, waiting for it until the client
    /// closes the connection or one of `events` is set.
    pub fn serve_once(
        &self,
        session: &ControlServerSession,
        handler: &dyn ControlRequestHandler,
        events: &[&Event],
    ) -> Result<Served, TransportError> {
        let watch = Watch {
            events,
            deadline: None,
        };
        let first = lock(&self.first).take();
        let request = match first {
            Some(first) => first,
            None => match pipe::read_frame(&self.pipe.0, watch).map_err(frame_read_error)? {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(Served::Closed),
                Err(interrupt) => return interrupted(interrupt),
            },
        };
        let response = session.handle(request, handler);
        match pipe::write_frame(&self.pipe.0, &response, watch) {
            Ok(Ok(())) => Ok(Served::Request),
            Ok(Err(interrupt)) => {
                handler.response_failed(&response.body);
                interrupted(interrupt)
            }
            Err(error) => {
                handler.response_failed(&response.body);
                Err(frame_write_error(error))
            }
        }
    }
}

fn interrupted(interrupt: Interrupt) -> Result<Served, TransportError> {
    match interrupt {
        Interrupt::Event(index) => Ok(Served::Interrupted(index)),
        Interrupt::Deadline => Err(TransportError::disconnected(
            "a wait without a deadline ended on one",
        )),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// One instance of the pipe at `endpoint`; `first` takes the name.
fn create_instance(endpoint: &str, first: bool) -> Result<ServerEnd, TransportError> {
    let failed = |error: std::io::Error| {
        TransportError::new(
            TransportErrorKind::ConnectFailed,
            format!("failed to create Windows named pipe '{endpoint}': {error}"),
        )
    };
    let endpoint_wide = wide_null(endpoint);
    let descriptor = PipeSecurityDescriptor::local_client_read_write()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let taking_the_name = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    // SAFETY: the name is NUL-terminated and the attributes outlive the call.
    let handle = unsafe {
        CreateNamedPipeW(
            endpoint_wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | taking_the_name,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &attributes,
        )
    };
    let handle =
        OwnedHandle::from_raw(handle).map_err(|_| failed(std::io::Error::last_os_error()))?;
    PipeEnd::new(handle).map(ServerEnd).map_err(failed)
}

struct PipeSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PipeSecurityDescriptor {
    fn local_client_read_write() -> Result<Self, TransportError> {
        let sddl = wide_null(PIPE_SECURITY_SDDL);
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(TransportError::new(
                TransportErrorKind::Authentication,
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(Self(descriptor))
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as _) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_acl_grants_authenticated_clients_data_access_only() {
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
        const PIPE_CLIENT_DATA_ACCESS: u32 = 0x0000_0003;

        assert_eq!(
            PIPE_AUTHENTICATED_USER_ACCESS & FILE_CREATE_PIPE_INSTANCE,
            0
        );
        assert_eq!(
            PIPE_AUTHENTICATED_USER_ACCESS & PIPE_CLIENT_DATA_ACCESS,
            PIPE_CLIENT_DATA_ACCESS
        );
        assert!(PIPE_SECURITY_SDDL.contains("0x0012019B;;;AU"));
        assert!(!PIPE_SECURITY_SDDL.contains("GRGW;;;AU"));
    }

    fn endpoint(tag: &str) -> String {
        format!(
            r"\\.\pipe\egrio-listener-test-{}-{tag}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        )
    }

    #[test]
    fn a_bound_name_cannot_be_bound_again() {
        let endpoint = endpoint("bound");
        let first = WindowsNamedPipeListener::bind(endpoint.clone()).expect("the name is free");
        let second =
            WindowsNamedPipeListener::bind(endpoint.clone()).expect_err("the name is taken");
        assert_eq!(second.kind(), TransportErrorKind::ConnectFailed);
        drop(first);
        WindowsNamedPipeListener::bind(endpoint).expect("the name is free again");
    }

    #[test]
    fn a_stop_ends_an_accept_that_no_client_came_to() {
        let listener = WindowsNamedPipeListener::bind(endpoint("stop")).unwrap();
        let stop = Arc::new(Event::new().unwrap());
        let setter = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                stop.set();
            })
        };
        let started = Instant::now();
        assert!(listener.accept(&stop).unwrap().is_none());
        assert!(started.elapsed() >= Duration::from_millis(50));
        // Set, it ends every accept after it too.
        assert!(listener.accept(&stop).unwrap().is_none());
        setter.join().unwrap();
    }
}
