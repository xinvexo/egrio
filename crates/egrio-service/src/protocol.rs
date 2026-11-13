use std::net::SocketAddr;

use egrio_runtime::{
    CapabilityCheckpoint, CapabilityKind, CapabilityObservation, CapabilityOperationReport,
    IpPrefix, PacketCaptureSettings, RuntimeId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SERVICE_PROTOCOL_MAJOR: u16 = 9;
pub const SERVICE_PROTOCOL_MINOR: u16 = 0;
pub const MAX_CONTROL_FRAME_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[must_use]
pub const fn protocol_version() -> ProtocolVersion {
    ProtocolVersion {
        major: SERVICE_PROTOCOL_MAJOR,
        minor: SERVICE_PROTOCOL_MINOR,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControlEnvelope<T> {
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub runtime_id: RuntimeId,
    pub session_id: Option<Uuid>,
    pub body: T,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "kebab-case")]
pub enum ControlRequest {
    Hello {
        app_version: String,
    },
    Prepare {
        capability: CapabilityKind,
        settings: serde_json::Value,
    },
    Apply {
        capability: CapabilityKind,
        settings: serde_json::Value,
    },
    Observe {
        capability: CapabilityKind,
    },
    Restore {
        checkpoint: CapabilityCheckpoint,
    },
    OpenPacketCapture {
        settings: PacketCaptureSettings,
    },
    /// Replaces what the open capture keeps outside the tunnel (macOS).
    UpdateExcludedPrefixes {
        prefixes: Vec<IpPrefix>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlErrorCode {
    InvalidFrame,
    IncompatibleVersion,
    AuthenticationFailed,
    InvalidSession,
    UnsupportedMethod,
    CapabilityFailed,
    Internal,
}

/// How the desktop reaches the packet device the service holds for its
/// session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PacketChannel {
    /// Windows: the service pumps its Wintun session through a shared-memory
    /// ring whose handles it duplicated into the desktop process.
    SharedRing(SharedRingChannel),
    /// Linux: a persistent TUN the service created owned by the peer's uid;
    /// the desktop attaches to it by name without `CAP_NET_ADMIN`.
    OwnedTun(OwnedTunChannel),
    /// macOS: the utun the service created for the session; a descriptor of
    /// its socket rides this response.
    Utun(UtunChannel),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UtunChannel {
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnedTunChannel {
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
    /// The physical resolvers read before the TUN's DNS capture took over
    /// the system resolver, for Core egress DNS while TUN is active.
    pub physical_dns_servers: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SharedRingChannel {
    pub channel_id: Uuid,
    pub mapping: u64,
    pub rx_data_available: u64,
    pub rx_space_available: u64,
    pub tx_data_available: u64,
    pub tx_space_available: u64,
    pub mapping_len: u64,
    pub abi_major: u16,
    pub abi_minor: u16,
    /// Interface index of the TUN adapter the service holds for this session;
    /// the desktop binds Core egress away from it without opening the adapter.
    pub interface_index: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "kebab-case")]
pub enum ControlResponse {
    Hello {
        service_version: String,
        session_id: Uuid,
        capabilities: Vec<CapabilityKind>,
    },
    Checkpoint(CapabilityCheckpoint),
    Operation(CapabilityOperationReport),
    Observation(CapabilityObservation),
    PacketChannel(PacketChannel),
    Error {
        code: ControlErrorCode,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_stable() {
        assert_eq!(protocol_version(), ProtocolVersion { major: 9, minor: 0 });
        assert_eq!(MAX_CONTROL_FRAME_BYTES, 1_048_576);
    }

    #[test]
    fn request_vocabulary_has_no_product_desired_state() {
        let request = ControlRequest::Observe {
            capability: CapabilityKind::Dns,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"method":"observe","params":{"capability":"dns"}}"#
        );
        assert!(!json.contains("desired_state"));
        assert!(!json.contains("profile"));
        assert!(!json.contains("command"));
    }
}
