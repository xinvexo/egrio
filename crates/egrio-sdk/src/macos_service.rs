//! Whether the macOS service answers this app. launchd runs the copy in the
//! app bundle, so after an update the process still running may be the old
//! copy: it answers a newer protocol by exiting, and launchd starts the new
//! one.

use std::sync::Arc;

use egrio_runtime::RuntimeId;
use egrio_service::client::ControlClient;
use egrio_service::transport::TransportErrorKind;
use egrio_service::unix::UnixSocketTransport;

/// Why the service did not open a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacosServiceHello {
    /// Nothing answers on the control socket.
    Unreachable(String),
    /// It speaks another protocol: an older copy that is giving way.
    OtherProtocol(String),
    /// It refused this process (not the Egrio app of its team).
    Refused(String),
}

/// Opens and closes one control session.
pub async fn macos_service_hello(app_version: &str) -> Result<(), MacosServiceHello> {
    let transport = Arc::new(UnixSocketTransport::new(
        egrio_platform_macos::MACOS_SERVICE_SOCKET,
    ));
    match ControlClient::connect(transport, RuntimeId::new(), app_version).await {
        Ok(client) => {
            let _ = client.close().await;
            Ok(())
        }
        Err(error) => Err(match error.kind() {
            TransportErrorKind::Protocol => MacosServiceHello::OtherProtocol(error.to_string()),
            TransportErrorKind::Authentication => MacosServiceHello::Refused(error.to_string()),
            _ => MacosServiceHello::Unreachable(error.to_string()),
        }),
    }
}
