# egrio-core

Reusable native proxy core for Egrio.

This crate is intentionally independent from any GUI. GUI apps, CLI tools, system
extensions, and external developers should depend on this crate directly.

## Public Runtime Boundary

`CoreRuntime` is the preferred public SDK boundary for daemon, CLI, GUI, and
platform adapters. It owns core data-plane lifecycle, route decisions, outbound
selection, DNS/fake-IP handling, TCP and UDP relay, and session telemetry.

`CoreSessionManager` is the reusable local HTTP/SOCKS and UDP DNS listener
manager. It is still core-owned because it manages proxy listeners and their
accepted data-plane sessions, not Wintun/WFP/utun system takeover state.

## Packet Capture Boundary

Captured traffic has one entry: a platform adapter implements `PacketDevice`
over each queue of its TUN (macOS utun socket, Windows Wintun ring, Linux
`/dev/net/tun`) and hands the queues, each paired with the
executor its pump runs on, to `NativeCoreDevice::run_packet_queues`. The
device contract is non-blocking `try_recv`/`try_send` plus a cancel-safe
`ready` wait; Core's event-driven pump parses each IPv4/IPv6 packet,
terminates TCP in its own TCP engine, relays UDP through per-source session actors,
answers captured DNS, and writes reply packets back. An optional
`FlowScanner` lets the shared attribution gate tag new flows with their
owning process before routing.

```rust
use egrio_core::{
    CoreRuntime, PacketDevice, PacketInterest, PacketReady, PacketSend, ReceivedPacket,
    RuntimeProfile,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct MyTun;

impl PacketDevice for MyTun {
    fn name(&self) -> &str {
        "my-tun"
    }
    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
        Ok(None) // one raw IP packet when available
    }
    fn try_send(&mut self, _packet: &[u8]) -> Result<PacketSend, String> {
        Ok(PacketSend::Sent) // or PacketSend::Full to wait for writability
    }
    fn ready(&mut self, _interest: PacketInterest) -> PacketReady<'_> {
        Box::pin(async { Ok(()) }) // resolve when the TUN is readable/writable
    }
}

async fn capture(profile: RuntimeProfile, stop: CancellationToken) {
    let core = CoreRuntime::from_profile(profile);
    let queues: Vec<(Box<dyn PacketDevice>, _)> =
        vec![(Box::new(MyTun), tokio::runtime::Handle::current())];
    let report = core.device().run_packet_queues(queues, stop).await;
    println!("{} packets in, {} out", report.packets_received, report.packets_written);
}
```

The packet path captures DNS according to the adapter's
`NativeCoreDnsHijackConfig`: `capture_udp_port(53)` handles queries sent to
any UDP/53 destination; `capture_virtual_dns_targets` handles UDP/53 and
length-prefixed TCP/53 only for the advertised virtual DNS targets. Both execute the same runtime DNS
policy as explicit proxy connections. See the authoritative
[Core data plane document](../../docs/architecture/core.md#模块布局)
for resolver purposes, configured fake-IP allocation, and lifecycle behavior.

OS ownership is deliberately outside this crate. Platform adapters own TUN
capture and restoration mechanics; this crate owns runtime profile
execution, rules, DNS policy, protocol handling, session lifecycle, and
outbound decisions. Product concerns such as subscription fetching, Clash YAML
import, saved profile repositories, and GUI settings belong to the host
backend.

See the [capture model](../../docs/architecture/overview.md#捕获模型) for the
platform data path and the [platform documents](../../docs/README.md) for what
each platform implements and has validated.
