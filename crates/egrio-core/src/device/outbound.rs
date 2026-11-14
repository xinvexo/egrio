//! Host-originated streams use this device's nodes and egress without entering
//! a listener or depending on its routing rules.
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::NativeCoreDevice;
use crate::outbound::{BoxedOutboundStream, OUTBOUND_DIAL_BUDGET};
use crate::runtime::{open_resolved_outbound_connection_with_budget, NativeCoreRuntime};
use crate::target::ConnectTarget;

/// A stream pinned to its Core and route epoch. Device stop and node changes
/// cancel both pending dials and established I/O, as for ordinary sessions.
pub struct CoreOutboundStream {
    stream: BoxedOutboundStream,
    _runtime: NativeCoreRuntime,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl NativeCoreDevice {
    /// Connects through an explicit outbound, or the current global choice
    /// when omitted. Business routing rules do not participate.
    pub async fn connect_outbound(
        &self,
        outbound: Option<&str>,
        host: &str,
        port: u16,
    ) -> Result<CoreOutboundStream, String> {
        self.ensure_running()?;
        self.tracked_session(|runtime| async move {
            let target = ConnectTarget {
                host: host.into(),
                port,
            };
            let name = outbound.unwrap_or_else(|| runtime.global_outbound());
            let resolved = runtime
                .resolve_outbound(name, &target)
                .ok_or_else(|| format!("outbound '{name}' is not implemented"))?;
            let cancel = runtime.connection_cancellation();
            let (stream, _) = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err("outbound connection cancelled".into()),
                result = open_resolved_outbound_connection_with_budget(
                    &runtime, &target, &resolved, &[], OUTBOUND_DIAL_BUDGET
                ) => result.map_err(|error| error.to_string())?,
            };
            Ok(CoreOutboundStream {
                stream,
                cancelled: Box::pin(cancel.cancelled_owned()),
                _runtime: runtime,
            })
        })
        .await
    }
}

impl CoreOutboundStream {
    fn poll_open(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.cancelled.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Core connection cancelled",
            )),
            Poll::Pending => Ok(()),
        }
    }
}

impl AsyncRead for CoreOutboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CoreOutboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
