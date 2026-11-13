//! The desktop's side of the control pipe.

use std::ptr::{null, null_mut};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

use crate::framing::FrameError;
use crate::protocol::{ControlEnvelope, ControlRequest, ControlResponse};
use crate::transport::{
    ControlConnection, ControlFuture, ControlTransport, TransportError, TransportErrorKind,
};

use super::identity::OwnedHandle;
use super::pipe::{self, Event, PipeEnd, Watch};

/// How long a connect waits for a pipe instance: the service always has one
/// waiting, except between a client's connecting and its successor's making.
const CONNECT_TIMEOUT_MS: u32 = 1_500;
const PIPE_CLIENT_DATA_ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA;

#[derive(Clone, Debug)]
pub struct WindowsNamedPipeTransport {
    endpoint: String,
}

impl WindowsNamedPipeTransport {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn for_service(service_name: &str) -> Self {
        Self::new(windows_named_pipe_endpoint(service_name))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl ControlTransport for WindowsNamedPipeTransport {
    fn connect(&self) -> ControlFuture<'_, Arc<dyn ControlConnection>> {
        Box::pin(async move {
            let endpoint = self.endpoint.clone();
            let connection =
                tokio::task::spawn_blocking(move || WindowsNamedPipeConnection::connect(&endpoint))
                    .await
                    .map_err(|error| {
                        TransportError::new(
                            TransportErrorKind::ConnectFailed,
                            format!("named pipe connect task failed: {error}"),
                        )
                    })??;
            Ok(Arc::new(connection) as Arc<dyn ControlConnection>)
        })
    }
}

/// The client end of the control pipe. A frame's I/O runs on the tokio
/// blocking pool, where it waits for the pipe or for the connection to
/// close: no core worker is parked, and closing ends whatever is in flight.
#[derive(Debug)]
struct WindowsNamedPipeConnection {
    pipe: Arc<ClientEnd>,
}

#[derive(Debug)]
struct ClientEnd {
    pipe: PipeEnd,
    /// Set when the connection closes. Every read and write watches it, so
    /// one that starts after the close ends as one in flight does.
    closed: Event,
}

impl ClientEnd {
    fn closed() -> TransportError {
        TransportError::disconnected("Windows named pipe control connection closed")
    }
}

impl WindowsNamedPipeConnection {
    fn connect(endpoint: &str) -> Result<Self, TransportError> {
        let failed = |what: &str, error: std::io::Error| {
            TransportError::new(
                TransportErrorKind::ConnectFailed,
                format!("{what} Windows named pipe '{endpoint}': {error}"),
            )
        };
        let endpoint_wide = wide_null(endpoint);
        let handle = loop {
            // The service may learn who its client is and no more.
            let handle = unsafe {
                CreateFileW(
                    endpoint_wide.as_ptr(),
                    PIPE_CLIENT_DATA_ACCESS,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                break handle;
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_BUSY {
                return Err(failed(
                    "failed to open",
                    std::io::Error::from_raw_os_error(error as i32),
                ));
            }
            if unsafe { WaitNamedPipeW(endpoint_wide.as_ptr(), CONNECT_TIMEOUT_MS) } == 0 {
                return Err(failed(
                    "timed out waiting for",
                    std::io::Error::last_os_error(),
                ));
            }
        };
        let handle = OwnedHandle::from_raw(handle)
            .map_err(|error| failed("failed to open", std::io::Error::other(error)))?;
        let end = PipeEnd::new(handle)
            .and_then(|pipe| {
                Ok(ClientEnd {
                    pipe,
                    closed: Event::new()?,
                })
            })
            .map_err(|error| failed("failed to open", error))?;
        Ok(Self {
            pipe: Arc::new(end),
        })
    }
}

impl Drop for WindowsNamedPipeConnection {
    fn drop(&mut self) {
        self.pipe.closed.set();
    }
}

impl ControlConnection for WindowsNamedPipeConnection {
    fn read_envelope(&self) -> ControlFuture<'_, ControlEnvelope<ControlResponse>> {
        let end = Arc::clone(&self.pipe);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let watch = Watch {
                    events: &[&end.closed],
                    deadline: None,
                };
                match pipe::read_frame(&end.pipe, watch) {
                    Ok(Ok(Some(envelope))) => Ok(envelope),
                    Ok(Ok(None)) => Err(TransportError::disconnected("Windows named pipe closed")),
                    Ok(Err(_)) => Err(ClientEnd::closed()),
                    Err(error) => Err(frame_read_error(error)),
                }
            })
            .await
            .map_err(|error| {
                TransportError::disconnected(format!("named pipe read task failed: {error}"))
            })?
        })
    }

    fn write_envelope<'a>(
        &'a self,
        envelope: &'a ControlEnvelope<ControlRequest>,
    ) -> ControlFuture<'a, ()> {
        let end = Arc::clone(&self.pipe);
        let envelope = envelope.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let watch = Watch {
                    events: &[&end.closed],
                    deadline: None,
                };
                match pipe::write_frame(&end.pipe, &envelope, watch) {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(ClientEnd::closed()),
                    Err(error) => Err(frame_write_error(error)),
                }
            })
            .await
            .map_err(|error| {
                TransportError::new(
                    TransportErrorKind::PossiblyDelivered,
                    format!("named pipe write task failed: {error}"),
                )
            })?
        })
    }

    fn close_now(&self) {
        self.pipe.closed.set();
    }
}

pub fn windows_named_pipe_endpoint(service_name: &str) -> String {
    let component: String = service_name
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || matches!(value, '-' | '_') {
                value
            } else {
                '-'
            }
        })
        .collect();
    format!(r"\\.\pipe\egrio-{component}-privileged-control")
}

pub(super) fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(super) fn frame_read_error(error: FrameError) -> TransportError {
    let kind = match error {
        FrameError::Io(_) => TransportErrorKind::Disconnected,
        FrameError::Json(_) | FrameError::InvalidLength(_) => TransportErrorKind::Protocol,
    };
    TransportError::new(kind, error.to_string())
}

pub(super) fn frame_write_error(error: FrameError) -> TransportError {
    let kind = match error {
        FrameError::Io(_) => TransportErrorKind::PossiblyDelivered,
        FrameError::Json(_) | FrameError::InvalidLength(_) => TransportErrorKind::Protocol,
    };
    TransportError::new(kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_asks_for_data_access_and_nothing_else() {
        assert_eq!(PIPE_CLIENT_DATA_ACCESS, 0x0000_0003);
    }
}
