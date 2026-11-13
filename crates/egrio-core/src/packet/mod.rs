mod device;
mod executor;
mod frame;
pub(crate) mod icmp;
mod pipeline;
#[cfg(test)]
mod probe;
pub(crate) mod reassembly;
#[cfg(test)]
mod robustness_tests;
pub(crate) mod source_fragment;
pub(crate) mod tcp;

pub(crate) use device::PumpRuntimes;
pub use device::{
    PacketDevice, PacketInterest, PacketQueue, PacketReady, PacketSend, ReceivedPacket,
};
#[cfg(test)]
pub(crate) use executor::PACKET_UDP_DRAIN_MAX_DATAGRAMS;
pub(crate) use executor::{
    drain_pending_udp_packets, execute_captured_packet, Answer, AnswerSink, PacketExecutionOutcome,
    UdpOutput,
};
pub(crate) use frame::{
    attribution_flow, build_udp_packet, datagram_frames, split_udp_train, udp_endpoints,
    udp_train_header, CapturedPacket,
};
#[cfg(test)]
pub(crate) use frame::{ipv4_header_checksum, ipv4_tcp_checksum};
pub(crate) use pipeline::PacketCoreAction;

#[cfg(feature = "bench-internals")]
pub(crate) mod bench {
    use super::{pipeline::process_captured_packet, CapturedPacket};
    use crate::runtime::NativeCoreRuntime;
    use crate::RuntimeProfile;

    /// The per-packet classification the pump runs before UDP/ICMP
    /// execution: parse, Fake-IP lookup, DNS capture and rule decision.
    pub struct BenchPacketClassifier {
        runtime: NativeCoreRuntime,
    }

    impl BenchPacketClassifier {
        pub fn compile(profile: &RuntimeProfile) -> Self {
            Self {
                runtime: NativeCoreRuntime::compile_with_egress(profile, Default::default()),
            }
        }

        /// Returns the decided action's name, e.g. `DnsCapture`.
        pub fn classify(&self, packet: &[u8]) -> Result<String, String> {
            process_captured_packet(&self.runtime, &CapturedPacket::from_bytes(packet))
                .map(|outcome| format!("{:?}", outcome.action))
        }
    }
}
