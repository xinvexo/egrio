pub mod attribution;
mod buffer_pool;
pub mod capture;
mod connection_termination;
pub use connection_termination::{ConnectionFailureCause, ConnectionTermination};
/// The server-role certificate-loading subsystem;
/// linked only into server builds.
#[cfg(feature = "server")]
pub mod certificate;
pub mod device;
pub mod dns;
pub mod egress;
pub mod geodata;
pub mod inbound;
mod outbound;
pub use outbound::OutboundStage;
pub mod packet;
mod policy_group;
mod prefixed;
pub mod profile;
mod protocols;
mod relay;
pub mod rule_engine;
pub mod runtime;
pub mod self_test;
pub mod session_registry;
mod sniff;
pub mod status;
mod suspension;
mod target;
mod tcp_flow;
pub use tcp_flow::{
    NativeTcpFlowError, TcpFlowBudget, TcpFlowContext, TcpFlowFailure, TcpFlowIoAction,
    TcpFlowIoSide, TcpFlowStage,
};
pub mod telemetry;
/// Shared client-side TLS (the rustls `ClientConfig` builder the encrypted
/// outbound hops reuse). Server-side TLS lives in `certificate.rs`.
mod tls;
mod udp;
pub use udp::{
    UdpTransportDiagnostics, UdpTransportErrorSource, UdpTransportFailure,
    UdpTransportFailureCause, UdpTransportStage,
};
#[cfg(feature = "validation-tools")]
pub mod validation;
pub mod watchdog;

/// Bench-only wrappers over crate-internal hot paths — the session tables
/// (`session_tables` bench) and the outbound protocol codec paths
/// (`outbound_hot_paths` bench). Never part of the shipping API.
#[cfg(feature = "bench-internals")]
pub mod bench_internals {
    pub use crate::outbound::udp_buffer_borrows;
    pub use crate::packet::bench::BenchPacketClassifier;
    pub use crate::protocols::hysteria2::bench::BenchHysteria2UdpFrame;
    pub use crate::protocols::shadowsocks::codec::bench::{
        BenchShadowsocksStreamCodec, BenchShadowsocksUdpCodec, SHADOWSOCKS_MAX_TCP_CHUNK,
    };
    pub use crate::protocols::trojan::codec::bench::BenchTrojanPreamble;
    pub use crate::relay::relay_buffer_borrows;
    pub use crate::session_registry::bench::BenchSessionRegistry;
    pub use crate::udp::bench::{BenchUdpDatagram, BenchUdpSessionTable};
}

pub use attribution::{FlowKey, FlowProtocol, FlowScanner, ProcessInfo, FLOW_SCAN_BATCH};
pub use capture::{
    validate_fake_ip_capture_addresses, NativeCoreCaptureConfig, NativeCoreDnsHijackConfig,
    NativeCoreDnsHijackMode, NativeCoreInterfaceNetwork,
};
pub use device::{
    ConnectionCutoverReport, CorePolicyApplyReport, CorePolicyState, CorePolicyUpdate,
    CoreStartInputs, CoreStateAudit, KillSessionsReport, NativeCoreDevice,
    NativeCoreDeviceRunReport, NativeCoreDeviceState, NativeCoreDeviceStatus,
    PreparedCorePolicyUpdate, RetirementTicket,
};
pub use dns::{DnsDecision, DnsDecisionAction, DnsEngine, DnsQueryInput, DnsRecordType};
pub use egress::{
    is_forbidden_direct_destination, CaptureEgressOverlay, EgressAddressFamily, EgressBinding,
    EgressNetwork, EgressPolicyRejection, EgressSocketContext, EgressSocketDescriptor,
    EgressSocketGuard, NativeCoreEgressConfig,
};
pub use inbound::{
    CoreInbound, CoreSessionManager, CoreSessionStartConfig, Hysteria2Inbound,
    ListenerScopeUpdateReport,
};
pub use packet::{
    PacketDevice, PacketInterest, PacketQueue, PacketReady, PacketSend, ReceivedPacket,
};
pub use policy_group::DEFAULT_PROBE_TEST_URL;
pub use profile::{
    rule_text, PolicyGroup, PolicyGroupKind, ProxyNode, ProxyProtocol, RouteRule, RouteRules,
    RuleKind, RuntimeProfile, TrafficPolicyMode,
};
pub use rule_engine::{
    rule_support_issues, RouteDecision, RouteEvaluation, RouteMatchInput, RouteMatchKind,
    RuleEngine, RuleEngineCompileWarning,
};
pub use runtime::{probe_profile_node, proxy_support_issue, CoreRuntime, CoreRuntimeConfig};
pub use session_registry::{
    SessionPhase, SessionPhaseCounts, SessionRegistryCounters, SessionSnapshot,
};
pub use sniff::SniffCounters;
pub use status::{ListenerFallback, NativeCoreState, NativeCoreStatus, PortUnavailable};
pub use telemetry::{
    traffic_telemetry_snapshot, PerUserTraffic, TrafficConnectionProtocol,
    TrafficConnectionSnapshot, TrafficConnectionState, TrafficTelemetrySnapshot, TrafficVolume,
};
pub use watchdog::WatchdogStats;
