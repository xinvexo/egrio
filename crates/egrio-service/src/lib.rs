//! Privileged capability adapter service and client protocol.
//!
//! This crate owns the versioned service boundary: the Windows service, the
//! Linux root helper and the macOS launchd service share its protocol, client
//! and session routing. It does not own an Egrio Runtime or Core data plane.

pub mod client;
pub mod framing;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod packet_pump;
pub mod protocol;
pub mod remote;
pub mod session;
pub mod shared_memory;
pub mod transport;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub use protocol::{
    protocol_version, ControlEnvelope, ControlErrorCode, ControlRequest, ControlResponse,
    OwnedTunChannel, PacketChannel, ProtocolVersion, SharedRingChannel, UtunChannel,
    MAX_CONTROL_FRAME_BYTES, SERVICE_PROTOCOL_MAJOR, SERVICE_PROTOCOL_MINOR,
};
pub use remote::ServicePlatform;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub use remote::ServiceTunEgress;
