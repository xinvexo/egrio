//! One end of the control pipe, and what a wait on it watches.
//!
//! Both ends are opened for overlapped I/O. A read, a write or a connect
//! then waits on its own event together with whatever else should end the
//! wait -- the service stopping, a packet session's fault, a deadline, the
//! connection closing -- so nothing parks in a call only the peer can end
//! and nothing polls. An overlapped handle is also what lets a read and a
//! write be in flight at once: a synchronous one serializes its requests at
//! the file object, and a reader parked in `ReadFile` would hold back the
//! write of the very request it is waiting to see answered.
//!
//! Official basis (Microsoft Learn): `CreateNamedPipe` and `ConnectNamedPipe`
//! for the overlapped mode and its manual-reset event; `GetOverlappedResult`
//! for a pending operation's result; `CancelIoEx` for taking one back, whose
//! `OVERLAPPED` "must not be freed or reused until it has completed".

use std::io;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{de::DeserializeOwned, Serialize};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::framing::FrameError;

use super::identity::OwnedHandle;

/// A manual-reset event. Once set it stays set, so it ends every wait that
/// watches it, whenever that wait starts.
#[derive(Debug)]
pub struct Event(OwnedHandle);

impl Event {
    pub fn new() -> io::Result<Self> {
        // SAFETY: creates an unnamed manual-reset event, not yet signalled.
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw(handle)
            .map(Self)
            .map_err(io::Error::other)
    }

    pub fn set(&self) {
        // SAFETY: the handle is this event's, open while `self` lives.
        unsafe { SetEvent(self.raw()) };
    }

    pub fn is_set(&self) -> bool {
        self.wait(Duration::ZERO)
    }

    /// Waits for it to be set, at most `timeout`; whether it is set.
    pub fn wait(&self, timeout: Duration) -> bool {
        // SAFETY: as in `set`.
        unsafe { WaitForSingleObject(self.raw(), milliseconds(timeout)) == WAIT_OBJECT_0 }
    }

    fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

/// Events a wait may watch at once: the service stopping and a session's
/// fault are all there is.
const WATCHED_EVENTS: usize = 2;

/// What a wait on pipe I/O watches besides the I/O itself.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Watch<'a> {
    /// Events whose setting ends the wait; at most [`WATCHED_EVENTS`].
    pub(super) events: &'a [&'a Event],
    /// When the wait ends whatever has happened.
    pub(super) deadline: Option<Instant>,
}

/// What ended a wait on pipe I/O before the I/O did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Interrupt {
    /// The watched event at this index was set.
    Event(usize),
    Deadline,
}

/// One end of a pipe opened with `FILE_FLAG_OVERLAPPED`.
#[derive(Debug)]
pub(super) struct PipeEnd {
    handle: OwnedHandle,
    /// The event of the read, or the connect, in flight. One at a time: the
    /// lock is what keeps two operations from sharing the event.
    reads: Mutex<Event>,
    /// The same for the write in flight.
    writes: Mutex<Event>,
}

impl PipeEnd {
    pub(super) fn new(handle: OwnedHandle) -> io::Result<Self> {
        Ok(Self {
            handle,
            reads: Mutex::new(Event::new()?),
            writes: Mutex::new(Event::new()?),
        })
    }

    pub(super) fn raw(&self) -> HANDLE {
        self.handle.raw()
    }

    /// Reads into `buffer`. `Ok(Ok(0))` once the peer has closed its end.
    pub(super) fn read(
        &self,
        buffer: &mut [u8],
        watch: Watch<'_>,
    ) -> io::Result<Result<usize, Interrupt>> {
        if buffer.is_empty() {
            return Ok(Ok(0));
        }
        let done = lock(&self.reads);
        let handle = self.raw();
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let pointer = buffer.as_mut_ptr();
        let read = overlapped(handle, &done, watch, |operation| {
            // SAFETY: `pointer` addresses `length` writable bytes that
            // outlive the operation: `overlapped` returns only once the
            // system has let go of them.
            unsafe { ReadFile(handle, pointer, length, null_mut(), operation) }
        });
        match read {
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(Ok(0)),
            read => read.map(|read| read.map(|read| read as usize)),
        }
    }

    pub(super) fn write(
        &self,
        bytes: &[u8],
        watch: Watch<'_>,
    ) -> io::Result<Result<usize, Interrupt>> {
        if bytes.is_empty() {
            return Ok(Ok(0));
        }
        let done = lock(&self.writes);
        let handle = self.raw();
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let pointer = bytes.as_ptr();
        overlapped(handle, &done, watch, |operation| {
            // SAFETY: as in `read`, for `length` readable bytes.
            unsafe { WriteFile(handle, pointer, length, null_mut(), operation) }
        })
        .map(|written| written.map(|written| written as usize))
    }

    /// Waits, at a pipe's server end, for a client to connect to it.
    pub(super) fn connect(&self, watch: Watch<'_>) -> io::Result<Result<(), Interrupt>> {
        let done = lock(&self.reads);
        let handle = self.raw();
        overlapped(handle, &done, watch, |operation| {
            // SAFETY: `handle` is a pipe's server end; see `overlapped` for
            // `operation`.
            unsafe { ConnectNamedPipe(handle, operation) }
        })
        .map(|connected| connected.map(|_| ()))
    }
}

/// Starts one overlapped operation on `handle` and waits for it to end, or
/// for what `watch` watches. An operation the watch outran is taken back
/// before this returns: until the system has finished with it, the
/// `OVERLAPPED` here and the caller's buffer are the system's to write.
fn overlapped(
    handle: HANDLE,
    done: &Event,
    watch: Watch<'_>,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> io::Result<Result<u32, Interrupt>> {
    // SAFETY: all zeroes is an `OVERLAPPED`'s documented initial state.
    let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
    operation.hEvent = done.raw();
    let mut transferred = 0_u32;
    if start(&mut operation) == 0 {
        // SAFETY: reads this thread's last error.
        match unsafe { GetLastError() } {
            ERROR_IO_PENDING => {}
            // A client that connected before the server asked for one: a
            // good connection, reported as a failure of the asking.
            ERROR_PIPE_CONNECTED => return Ok(Ok(0)),
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
        let outran = match wait(done, watch) {
            Ok(None) => None,
            Ok(Some(interrupt)) => Some(Ok(Err(interrupt))),
            Err(error) => Some(Err(error)),
        };
        if let Some(outcome) = outran {
            // SAFETY: `operation` is the one just started on `handle`. The
            // second call returns once it has completed, cancelled or not.
            unsafe {
                CancelIoEx(handle, &operation);
                GetOverlappedResult(handle, &operation, &mut transferred, 1);
            }
            return outcome;
        }
    }
    // SAFETY: `operation` has completed on `handle`.
    if unsafe { GetOverlappedResult(handle, &operation, &mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Ok(transferred))
}

/// Waits for `done`; `Some` when what `watch` watches came first.
fn wait(done: &Event, watch: Watch<'_>) -> io::Result<Option<Interrupt>> {
    debug_assert!(watch.events.len() <= WATCHED_EVENTS);
    let mut handles = [done.raw(); 1 + WATCHED_EVENTS];
    let mut count = 1_u32;
    for (slot, event) in handles[1..].iter_mut().zip(watch.events) {
        *slot = event.raw();
        count += 1;
    }
    let timeout = watch.deadline.map_or(INFINITE, |deadline| {
        milliseconds(deadline.saturating_duration_since(Instant::now()))
    });
    // SAFETY: the first `count` handles are live events. The lowest index
    // signalled is returned, so an operation that has completed is never
    // reported as outrun.
    match unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, timeout) } {
        WAIT_OBJECT_0 => Ok(None),
        WAIT_TIMEOUT => Ok(Some(Interrupt::Deadline)),
        index if index > WAIT_OBJECT_0 && index < WAIT_OBJECT_0 + count => {
            Ok(Some(Interrupt::Event((index - WAIT_OBJECT_0 - 1) as usize)))
        }
        _ => Err(io::Error::last_os_error()),
    }
}

/// `duration` in the milliseconds a wait takes, rounded up so that a wait
/// for what is left of a deadline does not return before it.
fn milliseconds(duration: Duration) -> u32 {
    let milliseconds = duration.as_nanos().div_ceil(1_000_000);
    u32::try_from(milliseconds).map_or(INFINITE - 1, |value| value.min(INFINITE - 1))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// A pipe end as the frame codec's reader and writer, remembering what cut
/// a wait short: the codec reports only an I/O error.
struct Watched<'a> {
    pipe: &'a PipeEnd,
    watch: Watch<'a>,
    interrupt: Option<Interrupt>,
}

impl Watched<'_> {
    /// Not `Interrupted`, which `read_exact` and `write_all` retry.
    fn interrupted(&mut self, interrupt: Interrupt) -> io::Error {
        self.interrupt = Some(interrupt);
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "the wait on the control pipe ended before its I/O",
        )
    }
}

impl io::Read for Watched<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe
            .read(buffer, self.watch)?
            .map_err(|interrupt| self.interrupted(interrupt))
    }
}

impl io::Write for Watched<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pipe
            .write(bytes, self.watch)?
            .map_err(|interrupt| self.interrupted(interrupt))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads one frame; `Ok(Ok(None))` when the peer closed its end between
/// frames, `Ok(Err(_))` when what `watch` watches ended the wait.
pub(super) fn read_frame<T: DeserializeOwned>(
    pipe: &PipeEnd,
    watch: Watch<'_>,
) -> Result<Result<Option<T>, Interrupt>, FrameError> {
    let mut reader = Watched {
        pipe,
        watch,
        interrupt: None,
    };
    match (crate::framing::read_frame(&mut reader), reader.interrupt) {
        (Err(FrameError::Io(_)), Some(interrupt)) => Ok(Err(interrupt)),
        (frame, _) => frame.map(Ok),
    }
}

/// Writes one frame; `Ok(Err(_))` when what `watch` watches ended the wait,
/// with the frame written in part or not at all.
pub(super) fn write_frame<T: Serialize>(
    pipe: &PipeEnd,
    value: &T,
    watch: Watch<'_>,
) -> Result<Result<(), Interrupt>, FrameError> {
    let mut writer = Watched {
        pipe,
        watch,
        interrupt: None,
    };
    match (
        crate::framing::write_frame(&mut writer, value),
        writer.interrupt,
    ) {
        (Err(FrameError::Io(_)), Some(interrupt)) => Ok(Err(interrupt)),
        (written, _) => written.map(Ok),
    }
}
