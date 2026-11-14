use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::Serialize;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::sync::Notify;

use crate::attribution::{AttributionWorker, FlowKey, FlowScanner, OwnerLookup, ProcessInfo};
use crate::capture::NativeCoreCaptureConfig;
use crate::dns::resolver::{
    resolve_dns_query_payload, resolve_dns_query_payload_for_transport, DnsQueryTransport,
};
use crate::egress::{EgressNetwork, EgressSocketGuard, NativeCoreEgressConfig, NetworkChange};
use crate::inbound::acceptor::{AcceptedStream, InboundReplyPlan};
use crate::inbound::dispatch::dispatch_accepted_stream;
use crate::outbound::probe::parse_probe_url;
use crate::packet::tcp::{
    CapturedTcpStream, EngineWake, FlowHolders, ForeignSegment, QueueShare, TcpEngine,
};
use crate::packet::{drain_pending_udp_packets, CapturedPacket, PacketQueue};
use crate::policy_group::{now_unix, OutboundProbePlan, DEFAULT_PROBE_INTERVAL_SECS};
use crate::profile::RuntimeProfile;
use crate::rule_engine::RouteMatchKind;
use crate::runtime::probe_outbound_once;
use crate::runtime::{NativeCoreRuntime, NativeCoreSessionState, RuntimeSnapshot};
use crate::session_registry::FinishedSession;
use crate::session_registry::{SessionRegistryCounters, SessionSnapshot};
use crate::target::ConnectTarget;
#[cfg(test)]
use crate::tcp_flow::{NativeTcpFlowError, TcpFlowContext, TcpFlowFailure, TcpFlowStage};
use crate::telemetry::{
    TrafficConnectionProtocol, TrafficConnectionSnapshot, TrafficConnectionState,
    TrafficTelemetrySnapshot,
};
use crate::udp;
use crate::watchdog::{WatchdogState, WatchdogStats, WATCHDOG_STALL_THRESHOLD, WATCHDOG_TICK};

// `NativeCoreDevice` is one handle over the whole Core; its methods live by
// what they do. This file keeps the device's state, its reports, its
// lifecycle (`start`, `close`, `status`) and the policy snapshot a session
// pins.
/// The engine of each capture queue, the captured streams it accepts and the
/// DNS served over TCP on the tunnel's resolver address.
mod captured_tcp;
/// Compiling a profile, its egress and its capture into a device.
mod compile;
/// Replacing the profile or egress of a running device, and the cutover of
/// the connections the old one made.
mod config;
mod fake_ip_keeper;
/// The entries one packet, one TCP flow and one UDP datagram come in by.
mod flows;
/// The active health-probe subsystem; the `kick_probe_loop` waker stays in
/// this file because the lifecycle methods fire it.
mod health;
mod outbound;
pub use outbound::CoreOutboundStream;
mod policy;
/// The packet-device pump (the TCP engine's driver); shared packet helpers
/// and the run types stay in this file.
mod pump;
/// Read-only session/traffic projections (they borrow only the session
/// tables, not lifecycle/TCP engine state).
mod telemetry;
pub use policy::{
    CorePolicyApplyReport, CorePolicyState, CorePolicyUpdate, PreparedCorePolicyUpdate,
    RetirementTicket,
};

#[derive(Debug, Clone)]
pub struct NativeCoreDevice {
    inner: Arc<NativeCoreDeviceInner>,
}

#[derive(Debug)]
struct NativeCoreDeviceInner {
    snapshot: ArcSwap<RuntimeSnapshot>,
    sessions: NativeCoreSessionState,
    state: Mutex<NativeCoreDeviceState>,
    /// Wakes the health-probe loop out of its sleep: snapshot swaps refresh
    /// the schedule, network changes (with `probe_reset`) trigger an
    /// immediate full re-probe, and close lets the loop observe shutdown.
    probe_kick: Notify,
    /// When set, the next probe-loop wakeup discards its schedule and probes
    /// everything now (network-change semantics).
    probe_reset: AtomicBool,
    /// Whether a health-probe scheduler is currently running for this device.
    /// Serve entrypoints spawn unconditionally, and a single device may host
    /// both a listener session and the capture pump (the Runtime-owned single
    /// Core), so the spawn must be idempotent per device rather than per
    /// entrypoint.
    probe_loop_running: AtomicBool,
    /// Scheduling-delay counters fed by the (optional) watchdog heartbeat.
    watchdog: WatchdogState,
    /// Device-durable egress socket guard: every snapshot recompile
    /// re-attaches it, so profile hot-applies can never publish an unguarded
    /// egress runtime.
    socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    /// Device-durable process attribution: the one scanner worker of this
    /// Core, shared by every packet pump run and the listener, so process
    /// rules see the same owners whichever layer carried the connection.
    /// Joined when the device's last handle drops.
    attribution: Option<Arc<AttributionWorker>>,
    /// The captured-TCP engines, one per capture queue, each created on its
    /// queue's first captured TCP packet and dropped together on close or
    /// cutover, which resets their flows. Accepted flows relay through the
    /// ordinary session pipeline.
    packet_tcp: Mutex<PacketTcpEngines>,
    /// Live captured-flow count for the bounded-state audit. Outlives engine
    /// instances so the audit reads one place.
    packet_tcp_active: Arc<AtomicUsize>,
    /// Where the fake-IP mappings are kept for the next Core, if the host
    /// named a file.
    fake_ip_keeper: std::sync::OnceLock<Arc<fake_ip_keeper::FakeIpKeeper>>,
}

/// One capture queue's captured-TCP engine. The queue's pump drives it; only
/// the test drain, which drives it without a pump, shares the lock.
#[derive(Debug)]
struct PacketTcp {
    engine: Mutex<TcpEngine>,
    /// Raised by flows that need the engine, and for segments other queues
    /// forward; the pump waits on it.
    wake: Arc<EngineWake>,
    /// Segments of this engine's flows that arrived on other queues.
    forwarded: Mutex<Forwarded>,
}

/// Segments another queue's pump handed over, bounded in count and in bytes.
/// A write-blocked holder parks on writability and does not wake for the
/// notify these come with, so without a bound a foreign queue that keeps
/// reading one flow's upload grew this at the link's rate, each entry pinning
/// a whole captured packet. Dropping past the bound is the device's own drop,
/// which the client's retransmission covers; the counts say how often.
#[derive(Debug, Default)]
struct Forwarded {
    segments: Vec<(bytes::Bytes, crate::attribution::ClientOwner)>,
    bytes: usize,
    dropped: u64,
}

impl Forwarded {
    /// Packets held for another queue's engine, and their bytes: the same
    /// shape of bound the attribution gate puts on the packets it holds.
    const MAX_PACKETS: usize = 256;
    const MAX_BYTES: usize = 512 * 1024;

    fn push(&mut self, packet: bytes::Bytes, process: crate::attribution::ClientOwner) {
        if self.segments.len() >= Self::MAX_PACKETS || self.bytes + packet.len() > Self::MAX_BYTES {
            self.dropped += 1;
            return;
        }
        self.bytes += packet.len();
        self.segments.push((packet, process));
    }

    /// The segments held, and how many were dropped since the last take.
    fn take(&mut self) -> (Vec<(bytes::Bytes, crate::attribution::ClientOwner)>, u64) {
        self.bytes = 0;
        (
            std::mem::take(&mut self.segments),
            std::mem::take(&mut self.dropped),
        )
    }
}

impl PacketTcp {
    fn engine(&self) -> std::sync::MutexGuard<'_, TcpEngine> {
        self.engine.lock().expect("captured TCP engine")
    }
}

/// The device's captured-TCP engines, one per queue of the capture they were
/// made for.
#[derive(Debug, Default)]
struct PacketTcpEngines {
    /// The capture's queue count.
    count: usize,
    queues: Vec<Option<Arc<PacketTcp>>>,
    /// Which queue holds each flow, when there are several.
    holders: Option<Arc<FlowHolders>>,
}

impl PacketTcpEngines {
    fn get(&self, queue: PacketQueue) -> Option<Arc<PacketTcp>> {
        if self.count != queue.count {
            return None;
        }
        self.queues.get(queue.index)?.clone()
    }

    /// Takes every engine out, for the caller to shut down outside the lock.
    fn take_all(&mut self) -> Vec<Arc<PacketTcp>> {
        self.count = 0;
        self.holders = None;
        self.queues.drain(..).flatten().collect()
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCoreDeviceState {
    Created,
    Running,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeCoreDeviceStatus {
    pub state: NativeCoreDeviceState,
    pub tcp_sessions: usize,
    pub udp_sessions: usize,
}

/// What the kill switch cancelled, per ledger: task-owned TCP
/// relays are signalled through their cancellation tokens; UDP and
/// packet-bridge sessions are table-owned and torn down directly.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KillSessionsReport {
    pub outbound: String,
    pub tcp_relay_sessions: usize,
    pub udp_sessions: usize,
}

/// Sessions invalidated by a routing update or an explicit connection cutover.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ConnectionCutoverReport {
    pub tcp_relay_sessions: usize,
    pub udp_sessions: usize,
}

/// Bounded-state audit: every table that may hold per-session or cached
/// state, in one snapshot. The churn/soak gates assert this returns to zero
/// (or to the cache floor) after load; a growing count here is a leak.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoreStateAudit {
    pub tcp_relay_sessions: SessionRegistryCounters,
    pub udp_sessions: usize,
    pub udp_session_sockets: usize,
    /// Datagrams dropped on a full session send mailbox since compile; a
    /// steadily climbing count under normal load means sessions stopped
    /// draining, not ordinary UDP loss.
    pub udp_send_drops: u64,
    /// DNS answers rejected by bounded admission or failed resolution since compile.
    pub udp_dns_answer_failures: u64,
    pub udp_transport: crate::UdpTransportDiagnostics,
    pub packet_tcp_sessions: usize,
    pub fake_dns_entries: usize,
    pub watchdog: WatchdogStats,
    /// Sniff-stage counters. Not a bounded table, but the
    /// gate surface for the short-circuit: a profile without reachable
    /// domain rules must keep `attempted` at zero.
    pub sniff: crate::sniff::SniffCounters,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NativeCoreDeviceRunReport {
    pub packets_received: u64,
    pub packets_written: u64,
    pub packets_failed: u64,
    /// Captured TCP packets handed to the TCP engine. Per-flow routing
    /// outcomes live in the session registry, not in per-packet action
    /// counters.
    pub packets_captured_tcp: u64,
    pub packets_action_dns_capture: u64,
    pub packets_action_direct_udp: u64,
    pub packets_action_proxy_udp: u64,
    pub packets_action_icmp_echo_reply: u64,
    pub packets_action_icmp_echo_relay: u64,
    pub packets_action_icmp_drop: u64,
    pub packets_action_multicast_drop: u64,
    pub pending_drain_attempts: u64,
    /// Segments another capture queue read for this queue's engine that did
    /// not fit the bound on what it holds for it.
    pub packets_forwarded_dropped: u64,
    pub shutdown_requested: bool,
    pub last_error: Option<String>,
    /// The error that terminated the serve loop, when it did not exit through
    /// shutdown or its run limits. The pump records it here and returns the
    /// report instead of propagating, so the counters accumulated up to the
    /// failure always survive for the session's stop report.
    pub fatal_error: Option<String>,
}

impl NativeCoreDeviceRunReport {
    pub(crate) fn record_fatal(&mut self, error: String) {
        self.last_error = Some(error.clone());
        self.fatal_error = Some(error);
    }

    /// A per-packet failure: counted and kept for diagnostics, never fatal.
    pub(crate) fn record_failure(&mut self, error: String) {
        self.packets_failed += 1;
        self.last_error = Some(error);
    }

    /// The report of a capture whose queues reported `reports`: the counters
    /// add up, the first fatal error stands, and the run stopped on request
    /// only if every queue's did.
    pub(crate) fn sum(reports: impl IntoIterator<Item = Self>) -> Self {
        let mut total = Self {
            shutdown_requested: true,
            ..Self::default()
        };
        for report in reports {
            let Self {
                packets_received,
                packets_written,
                packets_failed,
                packets_captured_tcp,
                packets_action_dns_capture,
                packets_action_direct_udp,
                packets_action_proxy_udp,
                packets_action_icmp_echo_reply,
                packets_action_icmp_echo_relay,
                packets_action_icmp_drop,
                packets_action_multicast_drop,
                pending_drain_attempts,
                packets_forwarded_dropped,
                shutdown_requested,
                last_error,
                fatal_error,
            } = report;
            total.packets_received += packets_received;
            total.packets_written += packets_written;
            total.packets_failed += packets_failed;
            total.packets_captured_tcp += packets_captured_tcp;
            total.packets_action_dns_capture += packets_action_dns_capture;
            total.packets_action_direct_udp += packets_action_direct_udp;
            total.packets_action_proxy_udp += packets_action_proxy_udp;
            total.packets_action_icmp_echo_reply += packets_action_icmp_echo_reply;
            total.packets_action_icmp_echo_relay += packets_action_icmp_echo_relay;
            total.packets_action_icmp_drop += packets_action_icmp_drop;
            total.packets_action_multicast_drop += packets_action_multicast_drop;
            total.pending_drain_attempts += pending_drain_attempts;
            total.packets_forwarded_dropped += packets_forwarded_dropped;
            total.shutdown_requested &= shutdown_requested;
            total.last_error = last_error.or(total.last_error);
            total.fatal_error = total.fatal_error.or(fatal_error);
        }
        total.shutdown_requested &= total.fatal_error.is_none();
        total
    }
}

/// A test driver's view of one captured stream or datagram flow. Production
/// ingress reaches the dispatcher through the TCP engine, listeners and the
/// packet executor; these only let unit tests feed the same pipeline.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeTcpFlowTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) process_name: Option<String>,
    pub(crate) process_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct NativeTcpFlowOutcome {
    pub(crate) outbound: String,
    pub(crate) matched_rule: Option<String>,
    pub(crate) matched_kind: Option<RouteMatchKind>,
    pub(crate) matched_payload: Option<String>,
    pub(crate) target: String,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeUdpFlowTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) process_name: Option<String>,
    pub(crate) process_path: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeUdpFlowDatagram {
    pub(crate) flow_id: Option<String>,
    pub(crate) source: SocketAddr,
    pub(crate) target: NativeUdpFlowTarget,
    pub(crate) payload: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeUdpFlowPendingDatagram {
    pub(crate) flow_id: String,
    pub(crate) source_endpoint: String,
    pub(crate) payload: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeUdpFlowSendReport {
    pub(crate) target: String,
    pub(crate) bytes_sent: usize,
    pub(crate) enqueued: bool,
}

/// Everything a caller supplies to start (or ensure) a Core: the compiled
/// profile, the resolved egress configuration, the packet capture/DNS
/// policy, an optional physical egress socket guard, and an optional
/// platform flow scanner. The guard belongs to the start inputs because it
/// is a property of the network topology the Core will dial under (a
/// capture session's routes would otherwise steer the Core's own upstream
/// dials back into the tunnel), not of any single dial. The scanner belongs
/// here because attribution serves every connection the Core accepts, from
/// the TUN or the listener, not one capture session.
pub struct CoreStartInputs {
    pub profile: RuntimeProfile,
    pub egress: NativeCoreEgressConfig,
    pub egress_socket_guard: Option<Arc<dyn EgressSocketGuard>>,
    pub capture: NativeCoreCaptureConfig,
    pub flow_scanner: Option<Arc<dyn FlowScanner>>,
    /// The file the Core keeps its fake-IP mappings in for the next Core
    /// (a new generation or after a restart); `None` keeps them for this
    /// Core only.
    pub fake_ip_mappings: Option<std::path::PathBuf>,
}

/// Whether `runtime`'s policy still sends a live UDP identity to the
/// `outbound` it uses.
///
/// An identity's rule decision is pinned while it lives (EIM) and every
/// datagram of it re-resolves that decision, so resolving it here asks
/// exactly what the data path asks: a selection that moved the group moves
/// the identity. Only a selection ever reaches this -- changing the mode or
/// the global outbound rebuilds the DNS generation, and no UDP session
/// outlives that -- so the decision itself cannot have gone stale.
fn udp_identity_keeps_route(
    runtime: &NativeCoreRuntime,
    decision: &crate::rule_engine::RouteDecision,
    target: &crate::target::ConnectTarget,
    outbound: &str,
) -> bool {
    debug_assert_eq!(
        decision.traffic_policy_mode,
        runtime.traffic_policy().0,
        "a mode change ends every UDP session with its DNS generation"
    );
    runtime
        .resolve_outbound(&decision.outbound, target)
        .is_some_and(|resolved| resolved.name == outbound)
}

/// Whether `runtime`'s policy routes the session that asked `question` to
/// the `outbound` it already relays through.
///
/// The question is asked exactly as the session's own decision was given
/// it, address included, so nothing is resolved a second time and nothing
/// can answer differently except what a policy change moved: the mode, the
/// global outbound, or what a group selects.
fn keeps_its_route(
    runtime: &NativeCoreRuntime,
    question: &crate::session_registry::RouteQuestion,
    outbound: &str,
) -> bool {
    let decision = runtime.route_with_address(&question.input, question.address);
    runtime
        .resolve_outbound(&decision.outbound, &question.dial_target)
        .is_some_and(|resolved| resolved.name == outbound)
}

impl NativeCoreDevice {
    /// Immutable packet-link MTU for this Core generation.
    pub fn capture_mtu(&self) -> u32 {
        self.inner.snapshot.load().capture.mtu
    }

    /// Rejects a TUN whose interface or virtual DNS addresses this Core's
    /// current fake-IP pool could hand out as remote destinations.
    pub fn validate_capture_addresses(&self, addresses: &[IpAddr]) -> Result<(), String> {
        crate::capture::validate_fake_ip_capture_addresses(
            &self.inner.snapshot.load().dns.config,
            addresses.iter().copied(),
        )
    }

    /// Checks destinations a capture routes outside its tunnel against this
    /// Core's fake-IP pool.
    pub fn validate_excluded_destinations(
        &self,
        prefixes: impl IntoIterator<Item = (IpAddr, u8)>,
    ) -> Result<(), String> {
        crate::capture::validate_fake_ip_excluded_destinations(
            &self.inner.snapshot.load().dns.config,
            prefixes,
        )
    }

    /// Evaluates a saved profile without starting a device, listener or probes.
    pub fn preview_route(
        profile: &RuntimeProfile,
        input: &crate::RouteMatchInput,
    ) -> Result<crate::RouteEvaluation, String> {
        let device = Self::from_snapshot(
            RuntimeSnapshot::compile(
                profile,
                Default::default(),
                Default::default(),
                None,
                crate::policy_group::GroupStateTable::default(),
            ),
            None,
            None,
        );
        // A stopped profile resolves nothing: an IP rule that would ask for a
        // name's address does not match here.
        let result = device.evaluate(input, None);
        device.close();
        result
    }

    /// The Core's attribution worker, which packet pump runs share.
    pub(crate) fn attribution(&self) -> Option<Arc<AttributionWorker>> {
        self.inner.attribution.clone()
    }

    /// Whether the current policy can route by process, so a new flow waits
    /// for its owner.
    pub(crate) fn routes_by_process(&self) -> bool {
        let snapshot = self.inner.snapshot.load();
        snapshot
            .rule_engine
            .routes_by_process_for(snapshot.traffic_policy_mode)
    }

    /// Starts looking up the process owning a newly accepted client socket;
    /// `None` when this Core has no scanner. `urgent` scans at once for a
    /// caller that will wait on the answer.
    pub(crate) fn request_owner(&self, flow: FlowKey, urgent: bool) -> Option<OwnerLookup> {
        self.inner
            .attribution
            .as_ref()
            .map(|worker| worker.request(flow, urgent))
    }

    #[cfg(test)]
    pub(crate) fn policy_epoch(&self) -> u64 {
        self.inner
            .sessions
            .route_admission
            .read()
            .expect("route admission lock")
            .epoch
    }

    pub(crate) fn pinned_runtime(&self) -> NativeCoreRuntime {
        let admission = self
            .inner
            .sessions
            .route_admission
            .read()
            .expect("route admission lock");
        if self.inner.sessions.registry.is_closed() {
            admission.cancellation.cancel();
        }
        NativeCoreRuntime::pinned_at(
            self.inner.snapshot.load_full(),
            self.inner.sessions.clone(),
            &admission,
        )
    }

    /// Evaluates routing and resolves policy groups using the same snapshot
    /// and live selection/health state as a new connection, without dialing;
    /// a name an IP rule asks about resolves as a connection's would.
    pub async fn evaluate_route(
        &self,
        input: &crate::RouteMatchInput,
    ) -> Result<crate::RouteEvaluation, String> {
        let address = self.pinned_runtime().rule_address(input).await;
        self.evaluate(input, address)
    }

    fn evaluate(
        &self,
        input: &crate::RouteMatchInput,
        address: Option<crate::rule_engine::RuleAddress>,
    ) -> Result<crate::RouteEvaluation, String> {
        let runtime = self.pinned_runtime();
        let decision = runtime.route_with_address(input, address);
        let resolved_outbound = if crate::rule_engine::is_reject_outbound(&decision.outbound) {
            decision.outbound.clone()
        } else {
            runtime
                .resolve_outbound(&decision.outbound, &crate::runtime::route_target(input))
                .map(|resolved| resolved.name)
                .ok_or_else(|| format!("outbound '{}' cannot be resolved", decision.outbound))?
        };
        Ok(crate::RouteEvaluation {
            decision,
            resolved_outbound,
            resolved_ip: address.and_then(|address| address.ip),
        })
    }

    /// One inbound session's future over a runtime pinned to the snapshot
    /// and route epoch current now. Holding that runtime is what keeps the
    /// session in the epoch's completion ticket.
    pub(crate) fn tracked_session<F: std::future::Future>(
        &self,
        make: impl FnOnce(NativeCoreRuntime) -> F,
    ) -> F {
        let admission = self
            .inner
            .sessions
            .route_admission
            .read()
            .expect("route admission lock");
        if self.inner.sessions.registry.is_closed() {
            admission.cancellation.cancel();
        }
        let runtime = NativeCoreRuntime::pinned_at(
            self.inner.snapshot.load_full(),
            self.inner.sessions.clone(),
            &admission,
        )
        .joining_epoch();
        make(runtime)
    }

    /// Wakes the probe loop: `notify_waiters` reaches a loop parked in its
    /// sleep, and `notify_one` stores a permit for a loop that is currently
    /// mid-probe and not yet re-registered, so kicks are never lost.
    fn kick_probe_loop(&self) {
        self.inner.probe_kick.notify_waiters();
        self.inner.probe_kick.notify_one();
    }

    /// Spawns the event-loop watchdog heartbeat. Optional,
    /// host-driven, like the health-probe loop: it is a periodic waker.
    /// Exits when the device closes; aborting the handle is also safe.
    pub fn spawn_event_loop_watchdog(&self) -> tokio::task::JoinHandle<()> {
        self.spawn_event_loop_watchdog_with(WATCHDOG_TICK, WATCHDOG_STALL_THRESHOLD)
    }

    pub(crate) fn spawn_event_loop_watchdog_with(
        &self,
        tick: Duration,
        threshold: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let device = self.clone();
        tokio::spawn(async move {
            loop {
                {
                    let state = *device.inner.state.lock().expect("native core device state");
                    if matches!(
                        state,
                        NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed
                    ) {
                        return;
                    }
                }
                let due = tokio::time::Instant::now() + tick;
                tokio::time::sleep_until(due).await;
                // How late the runtime woke us is the scheduling delay: the
                // only thing that grows it is something blocking the
                // executor.
                device.inner.watchdog.record_tick(due.elapsed(), threshold);
            }
        })
    }

    pub fn watchdog_stats(&self) -> WatchdogStats {
        self.inner.watchdog.stats()
    }

    /// Starts a freshly compiled device. `Closed` is terminal and stays
    /// closed: `SessionRegistry::close` cancels a one-shot root token and
    /// latches `closed`, with no reopen, so restarting would produce a
    /// half-alive device that admits UDP and dials upstream while refusing
    /// every TCP session and handing out born-cancelled tokens. Callers that
    /// need a live device after close compile a new one — which is what the
    /// Runtime's per-generation Core already does.
    pub fn start(&self) -> NativeCoreDeviceStatus {
        let mut state = self.inner.state.lock().expect("native core device state");
        if matches!(*state, NativeCoreDeviceState::Created) {
            udp::reopen_udp_sessions(&self.pinned_runtime());
            *state = NativeCoreDeviceState::Running;
        }
        drop(state);
        self.status()
    }

    pub fn close(&self) -> NativeCoreDeviceStatus {
        let was_closed = {
            let mut state = self.inner.state.lock().expect("native core device state");
            if matches!(*state, NativeCoreDeviceState::Closed) {
                true
            } else {
                *state = NativeCoreDeviceState::Closing;
                false
            }
        };

        self.inner.sessions.lifetime.cancel();
        self.inner.snapshot.load().egress.retire_policy();
        self.inner.snapshot.load().dns.retire();
        let retired = {
            let mut admission = self
                .inner
                .sessions
                .route_admission
                .write()
                .expect("route admission lock");
            admission.advance()
        };
        drop(retired);
        let runtime = self.pinned_runtime();
        // Retiring the engine resets every captured flow; each relay unwinds
        // through the registry close below.
        if !was_closed {
            self.retire_packet_tcp();
        }
        // Repeat the UDP cleanup even for an already-closed device. An inbound
        // receive that raced with the first close may have admitted a late UDP
        // actor before its own shutdown barrier completed.
        udp::close_udp_sessions(&runtime);
        // Cancel the session tree root: every live TCP relay unwinds and
        // deregisters; new registrations are refused.
        self.inner.sessions.registry.close();

        let mut state = self.inner.state.lock().expect("native core device state");
        *state = NativeCoreDeviceState::Closed;
        drop(state);
        // Wake the health-probe loop so it observes the closed state and
        // exits instead of sleeping toward its next probe slot.
        self.kick_probe_loop();
        if let Some(keeper) = self.inner.fake_ip_keeper.get() {
            keeper.save(&self.inner.sessions.fake_dns);
        }
        self.status()
    }

    /// Whether the currently published Core configuration resolves IPv6 DNS
    /// addresses. Numeric IPv6 destinations remain usable when false.
    pub fn ipv6_enabled(&self) -> bool {
        self.inner.snapshot.load().egress.ipv6_enabled()
    }

    pub fn status(&self) -> NativeCoreDeviceStatus {
        let runtime = self.pinned_runtime();
        udp::sweep_idle_udp_sessions(&runtime);

        NativeCoreDeviceStatus {
            state: *self.inner.state.lock().expect("native core device state"),
            tcp_sessions: self.inner.packet_tcp_active.load(Ordering::Relaxed),
            udp_sessions: self.inner.sessions.udp_sessions.len(),
        }
    }

    pub(crate) fn ensure_running(&self) -> Result<(), String> {
        let state = *self.inner.state.lock().expect("native core device state");
        match state {
            NativeCoreDeviceState::Running => Ok(()),
            NativeCoreDeviceState::Created => {
                self.start();
                Ok(())
            }
            NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed => {
                Err("native core device is closed".into())
            }
        }
    }
}

/// Whether a captured packet is TCP: IPv4 protocol field, or the IPv6 next
/// header of the base header (extension chains are left to the TCP engine's
/// full parser, matching the frame parser's fast-path assumption).
fn is_tcp_packet(payload: &[u8]) -> bool {
    match payload.first().map(|byte| byte >> 4) {
        Some(4) => payload.get(9) == Some(&6),
        Some(6) => payload.get(6) == Some(&6),
        _ => false,
    }
}

/// Folds the authenticated `user` across the live TCP and UDP ledgers into
/// per-user byte totals. Sessions with no user (local capture) are skipped, and
/// a `BTreeMap` keys the output for a stable, user-sorted order.
fn fold_per_user_traffic(
    tcp: &[SessionSnapshot],
    udp: &[crate::udp::NativeUdpSession],
) -> Vec<crate::PerUserTraffic> {
    use std::collections::BTreeMap;

    let mut by_user: BTreeMap<String, crate::PerUserTraffic> = BTreeMap::new();
    for session in tcp {
        let Some(user) = session.user.as_deref() else {
            continue;
        };
        let entry = by_user
            .entry(user.to_string())
            .or_insert_with(|| crate::PerUserTraffic {
                user: user.to_string(),
                ..Default::default()
            });
        entry.tcp_connections += 1;
        entry.upload_bytes += session.upload_bytes;
        entry.download_bytes += session.download_bytes;
    }
    for session in udp {
        let Some(user) = session.key.user.as_deref() else {
            continue;
        };
        let entry = by_user
            .entry(user.to_string())
            .or_insert_with(|| crate::PerUserTraffic {
                user: user.to_string(),
                ..Default::default()
            });
        entry.udp_flows += 1;
        entry.upload_bytes += session.bytes_sent;
        entry.download_bytes += session.bytes_received;
    }
    by_user.into_values().collect()
}

#[cfg(test)]
mod per_user_traffic_tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use crate::session_registry::SessionRegistry;

    /// TCP sessions fold into per-user byte totals; anonymous (local-capture)
    /// sessions are excluded, and one user's connections sum together. The UDP
    /// arm is proven end to end by the server gate.
    #[test]
    fn folds_tcp_by_user_and_skips_anonymous_sessions() {
        let registry = SessionRegistry::with_capacity(8);

        let alice_one = registry
            .register("shadowsocks", None, "a.example:443".into())
            .expect("registered");
        alice_one.set_user(&Arc::from("alice"));
        let counters = alice_one.byte_counters();
        counters.up.store(100, Ordering::Relaxed);
        counters.down.store(200, Ordering::Relaxed);

        let alice_two = registry
            .register("shadowsocks", None, "b.example:443".into())
            .expect("registered");
        alice_two.set_user(&Arc::from("alice"));
        alice_two.byte_counters().up.store(10, Ordering::Relaxed);

        let bob = registry
            .register("shadowsocks", None, "c.example:443".into())
            .expect("registered");
        bob.set_user(&Arc::from("bob"));
        bob.byte_counters().down.store(500, Ordering::Relaxed);

        // No user: the local-capture shape, which must not appear.
        let anonymous = registry
            .register("mixed", None, "d.example:443".into())
            .expect("registered");
        anonymous.byte_counters().up.store(999, Ordering::Relaxed);

        let folded = super::fold_per_user_traffic(&registry.snapshot(), &[]);

        assert_eq!(
            folded.len(),
            2,
            "two authenticated users; anonymous excluded"
        );
        let alice = folded
            .iter()
            .find(|row| row.user == "alice")
            .expect("alice row");
        assert_eq!(alice.tcp_connections, 2);
        assert_eq!(alice.upload_bytes, 110);
        assert_eq!(alice.download_bytes, 200);
        assert_eq!(alice.udp_flows, 0);
        let bob = folded
            .iter()
            .find(|row| row.user == "bob")
            .expect("bob row");
        assert_eq!(bob.tcp_connections, 1);
        assert_eq!(bob.upload_bytes, 0);
        assert_eq!(bob.download_bytes, 500);
    }
}

/// The ledger's row as the connection table's: its strings go with it.
fn tcp_connection_snapshot(session: SessionSnapshot) -> TrafficConnectionSnapshot {
    TrafficConnectionSnapshot {
        id: format!("tcp-{}", session.id).into(),
        protocol: TrafficConnectionProtocol::Tcp,
        process_name: session.process_name,
        process_path: session.process_path,
        source: session.source,
        destination: session.target,
        host: session.host,
        rule: session.matched_rule,
        inbound: session.inbound,
        outbound: session.outbound.unwrap_or_else(|| "-".into()),
        egress_interface: session.egress_interface,
        upload_bytes: session.upload_bytes,
        download_bytes: session.download_bytes,
        opened_at_unix: session.created_at_unix,
        updated_at_unix: session.phase_since_unix,
        state: TrafficConnectionState::Active,
        termination: None,
        closed_at_unix: None,
    }
}

fn udp_connection_snapshot(session: crate::udp::NativeUdpSession) -> TrafficConnectionSnapshot {
    let destination: Arc<str> = session.target.authority().into();
    TrafficConnectionSnapshot {
        id: format!("udp-{}-{destination}", session.key.source).into(),
        protocol: TrafficConnectionProtocol::Udp,
        process_name: session.process_name.map(Arc::from),
        process_path: session.process_path.map(Arc::from),
        source: Some(session.key.source.to_string().into()),
        destination,
        host: None,
        rule: session.matched_rule.map(Arc::from),
        inbound: session.inbound,
        outbound: session.outbound.into(),
        egress_interface: session.egress_interface,
        upload_bytes: session.bytes_sent,
        download_bytes: session.bytes_received,
        opened_at_unix: session.created_at_unix,
        updated_at_unix: session.updated_at_unix,
        state: TrafficConnectionState::Active,
        termination: None,
        closed_at_unix: None,
    }
}

/// Terminal-record projection: the same row shape as a live session, tagged
/// with how and when it ended.
fn finished_connection_snapshot(finished: FinishedSession) -> TrafficConnectionSnapshot {
    let mut connection = tcp_connection_snapshot(finished.snapshot);
    connection.state = TrafficConnectionState::from(&finished.termination);
    connection.termination = Some(finished.termination);
    connection.closed_at_unix = Some(finished.closed_at_unix);
    connection.updated_at_unix = finished.closed_at_unix;
    connection
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod dns_contract_tests;
