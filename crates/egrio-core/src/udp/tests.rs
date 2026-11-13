use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use tokio::net::UdpSocket;

use super::*;
use crate::capture::NativeCoreCaptureConfig;
use crate::egress::{
    EgressBinding, EgressRuntime, EgressSocketContext, EgressSocketDescriptor, EgressSocketGuard,
    NativeCoreEgressConfig,
};
use crate::outbound::{
    OutboundConnector, OutboundDatagramReceiver, OutboundDatagramSender, OutboundFuture,
};
use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
use crate::runtime::{NativeCoreRuntime, NativeCoreSessionState, RuntimeSnapshot};
use crate::self_test::{self_test_profile, serve_one_udp_echo};

struct SilentDatagramSender;

impl OutboundDatagramSender for SilentDatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(
        &'a self,
        _target: &'a ConnectTarget,
        _payload: &'a [u8],
    ) -> DatagramFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

struct BlockingDatagramSender;

impl OutboundDatagramSender for BlockingDatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::MayLeavePartialFrame
    }

    fn send<'a>(
        &'a self,
        _target: &'a ConnectTarget,
        _payload: &'a [u8],
    ) -> DatagramFuture<'a, ()> {
        Box::pin(std::future::pending::<Result<(), DatagramError>>())
    }
}

struct PendingDatagramReceiver;

impl OutboundDatagramReceiver for PendingDatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(std::future::pending::<
            Result<Option<(ConnectTarget, Vec<u8>)>, DatagramError>,
        >())
    }
}

#[derive(Debug)]
struct CountingDatagramConnector {
    connects: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct BlockingDatagramConnector;

#[derive(Debug)]
struct BoundEgressGuard;

impl EgressSocketGuard for BoundEgressGuard {
    fn protect_socket(
        &self,
        _descriptor: EgressSocketDescriptor,
        _context: EgressSocketContext,
    ) -> Result<EgressBinding, String> {
        Ok(EgressBinding::bound(42))
    }
}

impl OutboundConnector for BlockingDatagramConnector {
    fn connect_stream<'a>(
        &'a self,
        _egress: &'a crate::egress::EgressRuntime,
        _target: &'a ConnectTarget,
        _early_data: &'a [u8],
    ) -> OutboundFuture<'a, crate::outbound::BoxedOutboundStream> {
        Box::pin(async {
            Err(crate::outbound::OutboundError::new(
                crate::outbound::OutboundStage::Config,
                "blocking connector is UDP-only",
            ))
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        _egress: &'a crate::egress::EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async {
            Ok(OutboundDatagramTransport {
                sender: Box::new(BlockingDatagramSender),
                receiver: Box::new(PendingDatagramReceiver),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }
}

impl OutboundConnector for CountingDatagramConnector {
    fn connect_stream<'a>(
        &'a self,
        _egress: &'a crate::egress::EgressRuntime,
        _target: &'a ConnectTarget,
        _early_data: &'a [u8],
    ) -> OutboundFuture<'a, crate::outbound::BoxedOutboundStream> {
        Box::pin(async {
            Err(crate::outbound::OutboundError::new(
                crate::outbound::OutboundStage::Config,
                "counting connector is UDP-only",
            ))
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        _egress: &'a crate::egress::EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        let connects = Arc::clone(&self.connects);
        Box::pin(async move {
            connects.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(OutboundDatagramTransport {
                sender: Box::new(SilentDatagramSender),
                receiver: Box::new(PendingDatagramReceiver),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }
}

/// Receiver fed by a test-held channel: yields exactly the responses the
/// test pushes, and stays pending otherwise (a peer that never answers).
/// Every reply is framed as coming from one scripted remote.
struct ScriptedDatagramReceiver {
    responses: mpsc::Receiver<Vec<u8>>,
}

impl OutboundDatagramReceiver for ScriptedDatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            Ok(self.responses.recv().await.map(|payload| {
                (
                    ConnectTarget {
                        host: "192.0.2.1".into(),
                        port: 9,
                    },
                    payload,
                )
            }))
        })
    }
}

fn direct_route() -> crate::rule_engine::RouteDecision {
    crate::rule_engine::RouteDecision {
        traffic_policy_mode: crate::profile::TrafficPolicyMode::Rule,
        outbound: "DIRECT".into(),
        matched_rule: None,
        matched_kind: None,
        matched_payload: None,
        no_resolve: false,
    }
}

/// A socket owned by `datagram`'s session in `table`, whose responses
/// the test scripts through the returned sender.
fn scripted_session_socket(
    table: &UdpSessionTable,
    datagram: &UdpDatagram,
) -> (SessionUdpSocket, mpsc::Sender<Vec<u8>>) {
    scripted_session_socket_with_slot(
        table,
        datagram,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
    )
}

fn scripted_session_socket_with_slot(
    table: &UdpSessionTable,
    datagram: &UdpDatagram,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> (SessionUdpSocket, mpsc::Sender<Vec<u8>>) {
    let (response_tx, responses) = mpsc::channel(16);
    let socket = UdpSessionSocket::spawn(
        "DIRECT",
        true,
        table.socket_owner(
            &super::udp_session_key(datagram),
            datagram.flow_id.clone(),
            datagram.pump_queue,
        ),
        EgressRuntime::default(),
        &tokio_util::task::TaskTracker::new(),
        Arc::default(),
        crate::policy_group::GroupStateTable::default(),
        Arc::default(),
        None,
        slot,
        std::future::ready(Ok(OutboundDatagramTransport {
            sender: Box::new(SilentDatagramSender),
            receiver: Box::new(ScriptedDatagramReceiver { responses }),
        })),
    );
    (socket, response_tx)
}

#[tokio::test]
async fn ended_transport_retains_quota_until_valid_replies_are_drained() {
    let mut sessions = NativeCoreSessionState::default();
    sessions.udp_sessions.association_slots = Arc::new(tokio::sync::Semaphore::new(1));
    let snapshot = RuntimeSnapshot::compile(
        &self_test_profile(),
        Default::default(),
        Default::default(),
        None,
        sessions.group_state.clone(),
    );
    let runtime = NativeCoreRuntime::pinned(Arc::new(snapshot), sessions);
    let table = runtime.udp_sessions();
    let first = udp_datagram("127.0.0.1:55600".parse().unwrap(), "retained-replies");
    let (socket, responses) = scripted_session_socket_with_slot(
        table,
        &first,
        table.association_slots.clone().try_acquire_owned().unwrap(),
    );
    table.store_session_socket(&first, &direct_route(), socket.clone(), now_unix());
    responses.send(b"queued-a".to_vec()).await.unwrap();
    responses.send(b"queued-b".to_vec()).await.unwrap();
    drop(responses);
    timeout(Duration::from_secs(1), async {
        while socket.accepts_sends() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(socket);
    assert_eq!(
        table.association_slots.available_permits(),
        0,
        "finished actor does not release the retained reply object's lease"
    );
    let second = udp_datagram("127.0.0.1:55601".parse().unwrap(), "next-association");
    let error = send_udp_flow_datagram(&runtime, second.clone())
        .await
        .unwrap_err();
    assert!(error.contains("Core association limit"));
    assert_eq!(table.session_socket_count(), 1);
    let replies = drain_pending_udp_flow_responses(&runtime, 16, Duration::from_secs(1)).await;
    assert_eq!(
        replies.len(),
        2,
        "quota pressure must not discard deliverable replies"
    );
    assert_eq!(replies[0].payload, b"queued-a");
    assert_eq!(replies[1].payload, b"queued-b");
    assert_eq!(table.association_slots.available_permits(), 1);
    assert!(
        send_udp_flow_datagram(&runtime, second)
            .await
            .unwrap()
            .enqueued
    );
    table.close();
    runtime.task_tracker().close();
    runtime.task_tracker().wait().await;
    assert_eq!(table.association_slots.available_permits(), 1);
}

#[tokio::test]
async fn udp_session_snapshot_records_bound_egress_interface() {
    let egress = EgressRuntime::with_socket_guard(
        NativeCoreEgressConfig::default(),
        Some(Arc::new(BoundEgressGuard)),
    )
    .with_binding_recorder();
    let connector_egress = egress.clone();
    let (response_tx, responses) = mpsc::channel(1);
    let table = UdpSessionTable::default();
    let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 54_100)), "bound");
    let socket = UdpSessionSocket::spawn(
        "DIRECT",
        true,
        table.socket_owner(
            &super::udp_session_key(&datagram),
            datagram.flow_id.clone(),
            datagram.pump_queue,
        ),
        egress,
        &tokio_util::task::TaskTracker::new(),
        Arc::default(),
        crate::policy_group::GroupStateTable::default(),
        Arc::default(),
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        async move {
            let _socket = connector_egress
                .connect_udp_host("127.0.0.1", 9, "UDP egress binding test")
                .await
                .map_err(crate::outbound::OutboundError::hop_dial)?;
            Ok(OutboundDatagramTransport {
                sender: Box::new(SilentDatagramSender),
                receiver: Box::new(ScriptedDatagramReceiver { responses }),
            })
        },
    );
    for _ in 0..100 {
        if socket.egress_interface() == Some(42) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(socket.egress_interface(), Some(42));

    table.store_session_socket(&datagram, &direct_route(), Arc::clone(&socket), now_unix());
    assert_eq!(table.sessions_snapshot()[0].egress_interface, Some(42));
    drop(response_tx);
}

async fn drain_flow_responses(
    runtime: &NativeCoreRuntime,
    expected: usize,
) -> Vec<UdpPendingFlowDatagram> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut responses = Vec::new();
    while responses.len() < expected {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let mut batch =
            drain_pending_udp_flow_responses(runtime, expected - responses.len(), deadline - now)
                .await;
        if batch.is_empty() {
            break;
        }
        responses.append(&mut batch);
    }
    responses
}

fn counting_runtime(connects: Arc<AtomicUsize>) -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("udp-counting");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Counting",
        no_resolve: false,
    }]
    .into();
    let mut snapshot = RuntimeSnapshot::compile(
        &profile,
        NativeCoreEgressConfig::default(),
        NativeCoreCaptureConfig::default(),
        None,
        crate::policy_group::GroupStateTable::default(),
    );
    snapshot.insert_outbound_for_test("Counting", Arc::new(CountingDatagramConnector { connects }));
    NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default())
}

fn blocking_runtime() -> NativeCoreRuntime {
    let mut profile = RuntimeProfile::new("udp-blocking");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "Blocking",
        no_resolve: false,
    }]
    .into();
    let mut snapshot = RuntimeSnapshot::compile(
        &profile,
        NativeCoreEgressConfig::default(),
        NativeCoreCaptureConfig::default(),
        None,
        crate::policy_group::GroupStateTable::default(),
    );
    snapshot.insert_outbound_for_test("Blocking", Arc::new(BlockingDatagramConnector));
    NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default())
}

#[tokio::test]
async fn remote_scoped_udp_target_is_rejected_before_transport_creation() {
    let connects = Arc::new(AtomicUsize::new(0));
    let runtime = counting_runtime(Arc::clone(&connects));
    for host in ["fe80::1%7", "fe80::1%test-interface"] {
        let mut datagram = udp_datagram("127.0.0.1:54120".parse().unwrap(), "scoped-remote");
        datagram.target.host = host.into();
        let error = send_udp_flow_datagram(&runtime, datagram)
            .await
            .unwrap_err();
        assert!(error.contains("requires a DIRECT outbound"), "{error}");
    }
    assert_eq!(connects.load(AtomicOrdering::Relaxed), 0);
    assert_eq!(runtime.udp_sessions().len(), 0);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 0);
}

#[tokio::test]
async fn remote_udp_eim_revalidates_each_target_without_replacing_valid_transport() {
    let connects = Arc::new(AtomicUsize::new(0));
    let runtime = counting_runtime(Arc::clone(&connects));
    let datagram = udp_datagram("127.0.0.1:54121".parse().unwrap(), "remote-eim");
    assert!(
        send_udp_flow_datagram(&runtime, datagram.clone())
            .await
            .unwrap()
            .enqueued
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while connects.load(AtomicOrdering::Relaxed) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut scoped = datagram.clone();
    scoped.target.host = "fe80::1%7".into();
    let error = send_udp_flow_datagram(&runtime, scoped).await.unwrap_err();
    assert!(error.contains("requires a DIRECT outbound"), "{error}");
    assert_eq!(
        runtime.udp_sessions().snapshot_for_test()[0].packets_sent,
        1
    );
    assert!(
        send_udp_flow_datagram(&runtime, datagram)
            .await
            .unwrap()
            .enqueued
    );
    assert_eq!(connects.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(
        runtime.udp_sessions().snapshot_for_test()[0].packets_sent,
        2
    );
    close_udp_sessions(&runtime);
}

#[tokio::test]
async fn concurrent_admission_for_one_key_spawns_one_actor() {
    let connects = Arc::new(AtomicUsize::new(0));
    let runtime = counting_runtime(Arc::clone(&connects));
    let mut sends = tokio::task::JoinSet::new();
    for index in 0..32_u8 {
        let runtime = runtime.clone();
        sends.spawn(async move {
            send_udp_flow_datagram(
                &runtime,
                UdpDatagram {
                    flow_id: Some("shared-flow".into()),
                    pump_queue: None,
                    inbound: "tun",
                    user: None,
                    source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54_000)),
                    target: ConnectTarget {
                        host: "203.0.113.9".into(),
                        port: 4_500,
                    },
                    payload: vec![index],
                    process_name: None,
                    process_path: None,
                },
            )
            .await
        });
    }
    while let Some(result) = sends.join_next().await {
        assert!(
            result
                .expect("send task joins")
                .expect("send succeeds")
                .enqueued
        );
    }
    for _ in 0..100 {
        if connects.load(AtomicOrdering::Relaxed) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(connects.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 1);
    assert_eq!(runtime.udp_sessions().len(), 1);
}

#[tokio::test]
async fn mailbox_full_counts_a_drop_without_counting_a_send() {
    let runtime = blocking_runtime();
    let mut enqueued = 0_u64;
    let mut dropped = 0_u64;
    for index in 0..(UDP_SEND_MAILBOX as u64 + 16) {
        let outcome = send_udp_flow_datagram(
            &runtime,
            UdpDatagram {
                flow_id: Some("blocked-mailbox".into()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54_005)),
                target: ConnectTarget {
                    host: "203.0.113.9".into(),
                    port: 4_500,
                },
                payload: index.to_be_bytes().to_vec(),
                process_name: None,
                process_path: None,
            },
        )
        .await
        .expect("mailbox pressure send returns a report");
        if outcome.enqueued {
            enqueued += 1;
        } else {
            dropped += 1;
        }
        tokio::task::yield_now().await;
    }
    assert!(dropped > 0, "blocking sender must fill the mailbox");
    assert_eq!(runtime.udp_sessions().send_drops(), dropped);
    let session = runtime
        .udp_sessions()
        .sessions_snapshot()
        .into_iter()
        .next()
        .expect("session stats exist");
    assert_eq!(session.packets_sent, enqueued);
    assert_eq!(session.bytes_sent, enqueued * 8);
}

#[tokio::test]
async fn finished_actor_keeps_buffered_response_through_idle_sweep() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 54_001)),
        "finished-flow",
    );
    let route = runtime.route(&udp_route_input(&datagram));
    let (socket, response_tx) = scripted_session_socket(runtime.udp_sessions(), &datagram);
    runtime
        .udp_sessions()
        .store_session_socket(&datagram, &route, Arc::clone(&socket), now_unix());
    runtime.udp_sessions().record_sent(
        &datagram,
        &route,
        &socket,
        datagram.payload.len(),
        now_unix(),
    );
    response_tx
        .send(b"buffered-after-finish".to_vec())
        .await
        .expect("queue response");
    drop(response_tx);
    for _ in 0..100 {
        if !socket.accepts_sends() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!socket.accepts_sends());

    assert_eq!(runtime.udp_sessions().sweep_idle(now_unix()), 0);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 1);
    let responses = drain_flow_responses(&runtime, 1).await;
    assert_eq!(responses[0].payload, b"buffered-after-finish");
}

#[tokio::test]
async fn replacement_drains_the_finished_actor_before_retiring_it() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let datagram = UdpDatagram {
        flow_id: Some("replacement-flow".into()),
        pump_queue: None,
        inbound: "tun",
        user: None,
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 54_004)),
        target: ConnectTarget {
            host: "203.0.113.9".into(),
            port: 4_500,
        },
        payload: b"replacement-send".to_vec(),
        process_name: None,
        process_path: None,
    };
    let route = runtime.route(&udp_route_input(&datagram));
    let (old_socket, response_tx) = scripted_session_socket(runtime.udp_sessions(), &datagram);
    runtime.udp_sessions().store_session_socket(
        &datagram,
        &route,
        Arc::clone(&old_socket),
        now_unix(),
    );
    runtime.udp_sessions().record_sent(
        &datagram,
        &route,
        &old_socket,
        datagram.payload.len(),
        now_unix(),
    );
    response_tx
        .send(b"retired-response".to_vec())
        .await
        .expect("queue retired response");
    drop(response_tx);
    for _ in 0..100 {
        if !old_socket.accepts_sends() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!old_socket.accepts_sends());

    let send = send_udp_flow_datagram(&runtime, datagram)
        .await
        .expect("fresh generation sends");
    assert!(send.enqueued);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 2);
    let responses = drain_flow_responses(&runtime, 1).await;
    assert_eq!(responses[0].payload, b"retired-response");
    assert_eq!(runtime.udp_sessions().session_socket_count(), 1);
}

#[tokio::test]
async fn authenticated_faces_with_the_same_user_drain_only_their_own_flows() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let user = Some(Arc::<str>::from("alice"));
    let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000));
    let route = direct_route();
    let mut response_txs = Vec::new();
    for (face_id, payload) in [(1_u64, b"face-one".as_slice()), (2, b"face-two")] {
        let datagram = UdpDatagram {
            flow_id: Some(format!("udp-face/{face_id}/{source}")),
            pump_queue: None,
            inbound: "udp-associate",
            user: user.clone(),
            source,
            target: ConnectTarget {
                host: "192.0.2.1".into(),
                port: 9,
            },
            payload: b"request".to_vec(),
            process_name: None,
            process_path: None,
        };
        let (socket, response_tx) = scripted_session_socket(runtime.udp_sessions(), &datagram);
        runtime.udp_sessions().store_session_socket(
            &datagram,
            &route,
            Arc::clone(&socket),
            now_unix(),
        );
        runtime.udp_sessions().record_sent(
            &datagram,
            &route,
            &socket,
            datagram.payload.len(),
            now_unix(),
        );
        response_tx
            .send(payload.to_vec())
            .await
            .expect("queue face response");
        response_txs.push(response_tx);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(runtime.udp_sessions().len(), 2);

    let first = drain_udp_face_responses(
        &runtime,
        &user,
        Some("udp-face/1/"),
        16,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].payload, b"face-one");
    let second = drain_udp_face_responses(
        &runtime,
        &user,
        Some("udp-face/2/"),
        16,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].payload, b"face-two");
    drop(response_txs);
}

/// A reply lists on its own user's hub. That is what keeps one reply
/// from waking every other connection's drain and walking each of them
/// over the whole list: what a reply costs follows the user's own flows
/// rather than every flow the node holds.
#[tokio::test]
async fn a_reply_lists_where_its_own_users_drain_looks() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let route = direct_route();
    let mut response_txs = Vec::new();
    for (name, port) in [("alice", 55_000_u16), ("bob", 55_001)] {
        let user = Some(Arc::<str>::from(name));
        let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port));
        let datagram = UdpDatagram {
            flow_id: Some(format!("udp-face/1/{source}")),
            pump_queue: None,
            inbound: "udp-associate",
            user,
            source,
            target: ConnectTarget {
                host: "192.0.2.1".into(),
                port: 9,
            },
            payload: b"request".to_vec(),
            process_name: None,
            process_path: None,
        };
        let (socket, response_tx) = scripted_session_socket(table, &datagram);
        table.store_session_socket(&datagram, &route, Arc::clone(&socket), now_unix());
        table.record_sent(
            &datagram,
            &route,
            &socket,
            datagram.payload.len(),
            now_unix(),
        );
        response_tx
            .send(b"reply".to_vec())
            .await
            .expect("queue a reply");
        response_txs.push(response_tx);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let listed = |hub: &ReadyHub| hub.sockets.lock().expect("UDP ready list mutex").len();
    for name in ["alice", "bob"] {
        assert_eq!(
            listed(&table.face_hub(&Some(Arc::<str>::from(name)))),
            1,
            "{name}'s reply waits on {name}'s hub"
        );
    }
    assert_eq!(
        listed(&table.ready),
        0,
        "a user's reply never lists where the flows with no user of their own do"
    );
    drop(response_txs);
}

/// A socket whose peer is gone: every datagram sent to it comes back as
/// an ICMP error, which the platform hands over on the next read. It
/// reports `errors` of them before falling quiet.
struct FailingPumpIo {
    left: std::sync::atomic::AtomicUsize,
}

impl crate::outbound::PumpDatagrams for FailingPumpIo {
    fn try_send(&self, _to: &crate::outbound::PumpTo, _payload: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn hand_reads_to(&self, _waker: std::task::Waker) {}

    fn try_recv(
        &self,
        _buffer: &mut [u8],
    ) -> std::io::Result<(usize, crate::outbound::PumpFrom, usize)> {
        if self
            .left
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .is_err()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }
}

/// What waited for a name that never resolved is counted: those
/// datagrams were taken from a client that will never see them sent, and
/// a preparation that fails drops them.
#[tokio::test]
async fn datagrams_that_waited_for_a_name_count_when_it_fails_to_resolve() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let key = UdpSessionKey {
        user: None,
        face_flow: None,
        source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000)),
    };
    let identity = AssociationKey::for_target(
        &ConnectTarget {
            host: "198.18.0.7".into(),
            port: 443,
        },
        &ConnectTarget {
            host: "name.example".into(),
            port: 443,
        },
    );
    let target = ConnectTarget {
        host: "name.example".into(),
        port: 443,
    };
    let waiting = 3;
    {
        let mut state = table.state.lock().expect("UDP sessions mutex");
        let entry = state.entry_for(&key, || {
            UdpSessionEntry::new(udp_session(key.clone(), now_unix()))
        });
        entry.identities.insert(
            identity.clone(),
            Identity {
                route: direct_route(),
                outbound: "DIRECT".into(),
                state: IdentityState::Preparing(Preparation {
                    id: 1,
                    pending: (0..waiting)
                        .map(|_| (target.clone(), b"waiting".to_vec()))
                        .collect(),
                    pending_bytes: waiting * b"waiting".len(),
                    slot: None,
                    task: None,
                }),
            },
        );
    }

    let before = table.send_drops();
    PreparationTask {
        key: key.clone(),
        identity,
        id: 1,
        target,
        resolver: Arc::new(target::TargetResolver::new(runtime.clone(), true, "DIRECT")),
        flow_id: None,
        pump_queue: None,
    }
    .attach(
        &runtime,
        Err(PreparationFailure::Failed(
            crate::outbound::OutboundError::new(
                crate::outbound::OutboundStage::TargetResolve,
                "no answer for the name",
            ),
        )),
    );

    assert_eq!(
        table.send_drops() - before,
        waiting as u64,
        "each datagram that waited for the name is a loss"
    );
}

/// A transport that takes `takes` datagrams of a train and then has no
/// room, which is what a full socket buffer does mid-train.
struct PartialTrainPumpIo {
    takes: std::sync::atomic::AtomicUsize,
}

impl crate::outbound::PumpDatagrams for PartialTrainPumpIo {
    fn try_send(&self, _to: &crate::outbound::PumpTo, _payload: &[u8]) -> std::io::Result<()> {
        if self
            .takes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .is_err()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        Ok(())
    }

    fn hand_reads_to(&self, _waker: std::task::Waker) {}

    fn try_recv(
        &self,
        _buffer: &mut [u8],
    ) -> std::io::Result<(usize, crate::outbound::PumpFrom, usize)> {
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
}

/// A train the transport takes only part of loses the rest, and the
/// count says so: the send reports what it sent, and the difference is
/// as much a loss as the datagram a full socket buffer refuses.
#[tokio::test]
async fn a_train_the_transport_half_takes_counts_what_it_left() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000)),
        "pump-flow-with-a-half-taken-train",
    );
    let (socket, _response_tx) = scripted_session_socket(table, &datagram);
    assert!(
        socket
            .pump_io
            .set(Arc::new(PartialTrainPumpIo {
                takes: std::sync::atomic::AtomicUsize::new(2),
            }) as Arc<dyn crate::outbound::PumpDatagrams>)
            .is_ok(),
        "the socket hands its sends to the pump"
    );
    let send = PumpUdpSend {
        socket: Arc::downgrade(&socket),
        to: PumpTo::Addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 443))),
        direct: true,
        group: None,
    };

    let segment = 1200;
    let before = table.send_drops();
    let outcome = send.send_train(table, &vec![b'u'; segment * 5], segment);

    assert!(matches!(outcome, PumpSend::Sent), "two of five went");
    assert_eq!(
        table.send_drops() - before,
        3,
        "the three the transport had no room for are losses"
    );
}

/// A socket whose platform hands over the datagrams that arrived
/// together as one read ([`PumpFrom`] of `length` bytes in `segment`
/// sized datagrams), once.
struct CoalescedPumpIo {
    length: usize,
    segment: usize,
    read: AtomicBool,
}

impl crate::outbound::PumpDatagrams for CoalescedPumpIo {
    fn try_send(&self, _to: &crate::outbound::PumpTo, _payload: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn hand_reads_to(&self, _waker: std::task::Waker) {}

    fn try_recv(
        &self,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, crate::outbound::PumpFrom, usize)> {
        if self.read.swap(true, Ordering::AcqRel) {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        assert!(
            self.length <= buffer.len(),
            "the read fits the pump's buffer"
        );
        buffer[..self.length].fill(b'u');
        Ok((
            self.length,
            crate::outbound::PumpFrom::Addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 443))),
            self.segment,
        ))
    }
}

/// A platform that coalesces small datagrams hands over more link frames
/// in one read than the output queue keeps for a datagram. The reply is
/// cut into trains of that many: a train the queue cannot take is the
/// whole read lost, and how many datagrams a read carries is the
/// platform's to choose.
#[tokio::test]
async fn a_coalesced_read_becomes_trains_the_output_queue_can_take() {
    const MTU: usize = 1500;
    let frames = crate::packet::datagram_frames(MTU);
    let segment = 100;
    let datagrams = frames * 2 + 3;
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000)),
        "pump-flow-with-a-coalesced-read",
    );
    let (socket, _response_tx) = scripted_session_socket(table, &datagram);
    assert!(
        socket
            .pump_io
            .set(Arc::new(CoalescedPumpIo {
                length: segment * datagrams,
                segment,
                read: AtomicBool::new(false),
            }) as Arc<dyn crate::outbound::PumpDatagrams>)
            .is_ok(),
        "the socket hands its reads to the pump"
    );

    let mut out = Vec::new();
    socket.read_pump_io(PUMP_READ_QUANTUM, Some(MTU), &mut out);

    let mut carried = 0;
    for (reply, _) in &out {
        let UdpReply::Train(train) = reply else {
            panic!("a coalesced read is a train");
        };
        let in_train = train.payload.len().div_ceil(train.segment);
        assert!(
            in_train <= frames,
            "a train of {in_train} datagrams is more than the queue keeps for one"
        );
        carried += in_train;
    }
    assert_eq!(
        carried,
        datagrams,
        "every datagram of the read is carried, in {} trains",
        out.len()
    );
}

/// The read quantum bounds a turn's work, and an error a socket reports
/// is work: a peer that is gone answers every datagram with an ICMP
/// error, and a socket handing those over as fast as the pump takes them
/// would otherwise hold the pump for as long as they kept coming.
#[tokio::test]
async fn a_socket_reporting_errors_gives_the_pump_its_turn_back() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000)),
        "pump-flow-with-a-dead-peer",
    );
    let (socket, _response_tx) = scripted_session_socket(table, &datagram);
    let errors = Arc::new(FailingPumpIo {
        left: std::sync::atomic::AtomicUsize::new(4 * PUMP_READ_QUANTUM),
    });
    assert!(
        socket
            .pump_io
            .set(Arc::clone(&errors) as Arc<dyn crate::outbound::PumpDatagrams>)
            .is_ok(),
        "the socket hands its reads to the pump"
    );

    let mut out = Vec::new();
    assert!(
        !socket.read_pump_io(PUMP_READ_QUANTUM, None, &mut out),
        "the socket is not empty, so the pump comes back to it"
    );
    assert!(out.is_empty(), "an error is not a reply");
    assert!(
        errors.left.load(Ordering::Acquire) > 0,
        "the turn ended with errors still waiting, instead of draining them all"
    );
}

/// A capture that reopens with fewer queues than the one before it
/// leaves sockets listed on hubs no pump looks at any more. The first
/// queue's pump takes what is there, so a client still sending hears
/// back instead of waiting out its session.
#[tokio::test]
async fn the_first_pump_takes_the_replies_of_a_queue_the_capture_dropped() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let route = direct_route();
    // A captured flow the old capture gave to its fourth queue.
    let mut datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 55_000)),
        "pump-flow-on-a-dropped-queue",
    );
    datagram.pump_queue = Some(3);
    let (socket, response_tx) = scripted_session_socket(table, &datagram);
    table.store_session_socket(&datagram, &route, Arc::clone(&socket), now_unix());
    table.record_sent(
        &datagram,
        &route,
        &socket,
        datagram.payload.len(),
        now_unix(),
    );
    response_tx
        .send(b"reply".to_vec())
        .await
        .expect("queue a reply");
    // This capture has one queue, so nothing serves the fourth's hub.
    table.note_capture_queues(1);
    tokio::time::sleep(Duration::from_millis(20)).await;

    let replies = drain_pump_replies(&runtime, 0, 16, None).await;
    assert_eq!(
        replies.responses.len(),
        1,
        "the first queue's pump took the reply left on the dropped queue's hub"
    );
    drop(response_tx);
}

#[tokio::test]
async fn response_drain_round_robins_busy_flows() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let route = direct_route();
    let mut response_txs = Vec::new();
    for (port, flow_id, byte) in [(55_001, "fair-flow-a", b'a'), (55_002, "fair-flow-b", b'b')] {
        let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), flow_id);
        let (socket, response_tx) = scripted_session_socket(runtime.udp_sessions(), &datagram);
        runtime.udp_sessions().store_session_socket(
            &datagram,
            &route,
            Arc::clone(&socket),
            now_unix(),
        );
        runtime.udp_sessions().record_sent(
            &datagram,
            &route,
            &socket,
            datagram.payload.len(),
            now_unix(),
        );
        for _ in 0..4 {
            response_tx
                .send(vec![byte])
                .await
                .expect("queue fair response");
        }
        response_txs.push(response_tx);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut flow_ids = drain_pending_udp_flow_responses(&runtime, 2, Duration::from_secs(1))
        .await
        .into_iter()
        .map(|response| response.flow_id)
        .collect::<Vec<_>>();
    flow_ids.sort();
    assert_eq!(flow_ids, vec!["fair-flow-a", "fair-flow-b"]);
    drop(response_txs);
}

#[tokio::test]
async fn flow_ids_are_trimmed_consistently_for_send_snapshot_and_close() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let mut datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 55_003)),
        "trimmed-flow",
    );
    datagram.flow_id = Some("  trimmed-flow  ".into());
    let report = send_udp_flow_datagram(&runtime, datagram)
        .await
        .expect("trimmed flow sends");
    assert!(report.enqueued);
    assert_eq!(
        runtime.udp_sessions().sessions_snapshot()[0]
            .flow_id
            .as_deref(),
        Some("trimmed-flow")
    );
    assert_eq!(
        close_udp_flow_sessions(&runtime, "  trimmed-flow  ").expect("trimmed close succeeds"),
        1
    );
}

#[tokio::test]
async fn live_source_cannot_change_flow_identity() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 54_002));
    let first = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("first-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source,
            target: ConnectTarget {
                host: "203.0.113.9".into(),
                port: 4_500,
            },
            payload: b"first".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect("first flow sends");
    assert!(first.enqueued);

    let error = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("second-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source,
            target: ConnectTarget {
                host: "203.0.113.9".into(),
                port: 4_500,
            },
            payload: b"second".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect_err("live source keeps its original flow id");
    assert!(error.contains("already owned by flow"), "{error}");
}

#[tokio::test]
async fn closed_table_rejects_admission() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    runtime.udp_sessions().close();
    let error = send_udp_flow_datagram(
        &runtime,
        udp_datagram(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 54_003)),
            "closed-flow",
        ),
    )
    .await
    .expect_err("closed table rejects new actors");
    assert!(error.contains("closed"), "{error}");
    assert_eq!(runtime.udp_sessions().len(), 0);
}

#[tokio::test]
async fn connect_failure_recycles_the_session_actor() {
    let table = UdpSessionTable::default();
    let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 54_101)), "failing");
    let socket = UdpSessionSocket::spawn(
        "DIRECT",
        true,
        table.socket_owner(
            &super::udp_session_key(&datagram),
            datagram.flow_id.clone(),
            datagram.pump_queue,
        ),
        EgressRuntime::default(),
        &tokio_util::task::TaskTracker::new(),
        Arc::default(),
        crate::policy_group::GroupStateTable::default(),
        Arc::default(),
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        std::future::ready(Err::<OutboundDatagramTransport, _>(
            crate::outbound::OutboundError::new(
                crate::outbound::OutboundStage::HopConnect,
                "scripted connect failure",
            ),
        )),
    );

    let _ = socket.send_nowait(
        ConnectTarget {
            host: "192.0.2.1".into(),
            port: 9,
        },
        b"never-sent".to_vec(),
    );

    // The failed actor refuses new sends, so lookups rebuild instead of
    // queueing datagrams into a dead session.
    for _ in 0..100 {
        if !socket.accepts_sends() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!socket.accepts_sends());
}

#[tokio::test]
async fn stalled_socks_handshake_ends_only_transport() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        waiting_tx.send(()).unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    });
    let mut profile = RuntimeProfile::new("udp-stalled-handshake");
    profile.proxies.push(crate::profile::ProxyNode {
        id: "stalled".into(),
        name: "stalled".into(),
        protocol: crate::profile::ProxyProtocol::Socks5,
        server: Some("127.0.0.1".into()),
        port: Some(port),
        options: serde_json::json!({"udp": true}),
    });
    profile.rules = profile
        .rules
        .iter()
        .chain([RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "stalled",
            no_resolve: false,
        }])
        .collect();
    let core = crate::NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let mut datagram = udp_datagram("127.0.0.1:54123".parse().unwrap(), "stalled-flow");
    datagram.target = ConnectTarget {
        host: "192.0.2.1".into(),
        port: 443,
    };
    datagram.payload = vec![42; 1024];
    for _ in 0..8 {
        assert!(
            send_udp_flow_datagram(&runtime, datagram.clone())
                .await
                .unwrap()
                .enqueued
        );
    }
    timeout(Duration::from_secs(3), waiting_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(actor::Budgets::default().dial + Duration::from_millis(1)).await;
    tokio::time::resume();
    timeout(Duration::from_secs(1), async {
        while core.state_audit().udp_transport.failures == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        runtime.udp_sessions().flow_session_count("stalled-flow") > 0,
        "a child transport failure cannot close its UDP flow"
    );
    let audit = core.state_audit();
    assert_eq!(audit.udp_transport.failures, 1);
    assert_eq!(
        audit.udp_transport.recent_failures[0].stage,
        UdpTransportStage::Dial
    );
    assert!(
        core.pinned_runtime()
            .group_state()
            .health_snapshot("stalled")
            .is_none(),
        "unclassified transport failure must not poison node health"
    );
    assert_eq!(audit.udp_sessions, 1);
    close_udp_flow_sessions(&runtime, "stalled-flow").unwrap();
    assert_eq!(core.state_audit().udp_sessions, 0);
    timeout(Duration::from_secs(3), proxy)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn native_core_relays_udp_direct_datagram() {
    let payload = b"udp-direct-poc";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move { serve_one_udp_echo(target_socket).await });
    let source_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind source");
    let source_addr = source_socket.local_addr().expect("source addr");
    drop(source_socket);
    let profile = self_test_profile();
    let runtime = NativeCoreRuntime::compile(&profile);

    let outcome = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("direct-flow-1".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: source_addr,
            target: ConnectTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
            },
            payload: payload.to_vec(),
            process_name: Some("Google Chrome".into()),
            process_path: Some("/Applications/Google Chrome.app".into()),
        },
    )
    .await
    .expect("UDP direct send succeeds");
    assert!(outcome.enqueued);
    let responses = drain_flow_responses(&runtime, 1).await;
    let response = responses.first().expect("UDP direct response");

    let session = runtime
        .udp_sessions()
        .session_for_flow("direct-flow-1")
        .unwrap();
    assert_eq!(session.outbound, "DIRECT");
    assert_eq!(
        session.matched_rule.as_deref(),
        Some("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
    );
    assert_eq!(response.payload, payload);
    echo_task.await.expect("echo join").expect("echo completes");

    let sessions = runtime.udp_sessions().snapshot_for_test();
    assert_eq!(sessions.len(), 1);
    let session = sessions.first().expect("session recorded");
    assert_eq!(session.key.source, source_addr);
    assert_eq!(session.flow_id.as_deref(), Some("direct-flow-1"));
    assert_eq!(session.process_name.as_deref(), Some("Google Chrome"));
    assert_eq!(
        session.process_path.as_deref(),
        Some("/Applications/Google Chrome.app")
    );
    assert_eq!(session.outbound, "DIRECT");
    assert_eq!(
        session.matched_rule.as_deref(),
        Some("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
    );
    assert!(session.created_at_unix <= session.updated_at_unix);
    assert_eq!(session.packets_sent, 1);
    assert_eq!(session.packets_received, 1);
    assert_eq!(session.bytes_sent, payload.len() as u64);
    assert_eq!(session.bytes_received, payload.len() as u64);
    // The device's volume counts the same datagrams.
    assert_eq!(
        runtime.udp_sessions().volume.volume(),
        crate::TrafficVolume {
            upload_bytes: payload.len() as u64,
            download_bytes: payload.len() as u64,
        }
    );
}

#[tokio::test]
async fn late_udp_response_keeps_session_and_reaches_flow_drain() {
    let payload = b"late-response-request";
    let late_response = b"late-response-answer";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 128];
        let (_read, peer) = target_socket
            .recv_from(&mut buffer)
            .await
            .expect("late target receives datagram");
        // Answer well past the first-response budget so the relay outcome
        // must come back empty and the answer must travel via drain.
        tokio::time::sleep(Duration::from_millis(300)).await;
        target_socket
            .send_to(late_response, peer)
            .await
            .expect("late target answers");
    });
    let source_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53211));
    let profile = self_test_profile();
    let runtime = NativeCoreRuntime::compile(&profile);

    let outcome = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("late-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: source_addr,
            target: ConnectTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
            },
            payload: payload.to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect("no-wait send succeeds");

    assert!(outcome.enqueued);
    assert_eq!(
        runtime.udp_sessions().session_socket_count(),
        1,
        "session socket must stay cached for late responses"
    );

    // The long-poll parks on the actors' notify and wakes when the late
    // answer lands, well before its own deadline.
    let drain_started = std::time::Instant::now();
    let drained = drain_pending_udp_flow_responses(&runtime, 32, Duration::from_secs(5)).await;
    responder.await.expect("late responder");

    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].payload, late_response);
    assert_eq!(drained[0].flow_id, "late-flow");
    assert!(
        drain_started.elapsed() < Duration::from_secs(2),
        "drain must wake on arrival, not on its deadline (elapsed {:?})",
        drain_started.elapsed()
    );
}

#[tokio::test]
async fn flow_send_never_waits_and_responses_arrive_via_drain() {
    let payload = b"nowait-request";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 128];
        let (read, peer) = target_socket
            .recv_from(&mut buffer)
            .await
            .expect("target receives datagram");
        // Answer slower than any inline budget: a blocking send path
        // would stall here, the no-wait path must not.
        tokio::time::sleep(Duration::from_millis(250)).await;
        target_socket
            .send_to(&buffer[..read], peer)
            .await
            .expect("target answers");
    });
    let profile = self_test_profile();
    let runtime = NativeCoreRuntime::compile(&profile);

    let send_started = std::time::Instant::now();
    let outcome = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("nowait-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53321)),
            target: ConnectTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
            },
            payload: payload.to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect("no-wait send succeeds");

    assert!(outcome.enqueued);
    assert!(
        send_started.elapsed() < Duration::from_millis(100),
        "no-wait send must return before the upstream answers (elapsed {:?})",
        send_started.elapsed()
    );

    let drained = drain_pending_udp_flow_responses(&runtime, 32, Duration::from_secs(5)).await;
    responder.await.expect("responder");
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].flow_id, "nowait-flow");
    assert_eq!(drained[0].payload, payload);

    let sessions = runtime.udp_sessions().snapshot_for_test();
    assert_eq!(sessions.len(), 1);
    let session = sessions.first().expect("session recorded");
    assert_eq!(session.packets_sent, 1);
    assert_eq!(session.packets_received, 1);
}

#[tokio::test]
async fn flow_send_requires_a_flow_id() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());

    let error = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: None,
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53322)),
            target: ConnectTarget {
                host: Ipv4Addr::LOCALHOST.to_string(),
                port: 9,
            },
            payload: b"unowned".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect_err("flow id is required");

    assert!(error.contains("flow id"), "{error}");
}

#[tokio::test]
async fn flow_sends_before_connect_completes_stay_ordered() {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let collector = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut buffer = [0_u8; 128];
        for _ in 0..3 {
            let (read, _peer) = target_socket
                .recv_from(&mut buffer)
                .await
                .expect("target receives datagram");
            received.push(buffer[..read].to_vec());
        }
        received
    });
    let profile = self_test_profile();
    let runtime = NativeCoreRuntime::compile(&profile);

    // All three sends land in the mailbox before the actor's connect can
    // plausibly have finished; the actor flushes them in order.
    for payload in [b"first".as_slice(), b"second", b"third"] {
        let outcome = send_udp_flow_datagram(
            &runtime,
            UdpDatagram {
                flow_id: Some("ordered-flow".into()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53323)),
                target: ConnectTarget {
                    host: target_addr.ip().to_string(),
                    port: target_addr.port(),
                },
                payload: payload.to_vec(),
                process_name: None,
                process_path: None,
            },
        )
        .await
        .expect("no-wait send succeeds");
        assert!(outcome.enqueued);
    }

    let received = tokio::time::timeout(Duration::from_secs(5), collector)
        .await
        .expect("collector finishes")
        .expect("collector joins");
    assert_eq!(
        received,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert_eq!(
        runtime.udp_sessions().session_socket_count(),
        1,
        "one actor owns the whole ordered burst"
    );
}

#[tokio::test]
async fn native_core_reuses_direct_udp_socket_for_same_flow() {
    let first_payload = b"udp-direct-first";
    let second_payload = b"udp-direct-second";
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP target");
    let target_addr = target_socket.local_addr().expect("target addr");
    let echo_task = tokio::spawn(async move {
        let mut peers = Vec::new();
        let mut payloads = Vec::new();
        for _ in 0..2 {
            let mut buffer = vec![0_u8; 65535];
            let (read, peer) = target_socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            buffer.truncate(read);
            target_socket
                .send_to(&buffer, peer)
                .await
                .map_err(|error| error.to_string())?;
            peers.push(peer);
            payloads.push(buffer);
        }
        Ok::<_, String>((peers, payloads))
    });
    let source_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53123));
    let profile = self_test_profile();
    let runtime = NativeCoreRuntime::compile(&profile);

    for payload in [first_payload.as_slice(), second_payload.as_slice()] {
        let outcome = send_udp_flow_datagram(
            &runtime,
            UdpDatagram {
                flow_id: Some("reused-flow".into()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: source_addr,
                target: ConnectTarget {
                    host: target_addr.ip().to_string(),
                    port: target_addr.port(),
                },
                payload: payload.to_vec(),
                process_name: None,
                process_path: None,
            },
        )
        .await
        .expect("UDP direct send succeeds");
        assert!(outcome.enqueued);
    }

    let responses = drain_flow_responses(&runtime, 2).await;
    assert_eq!(responses.len(), 2);

    let (peers, payloads) = echo_task.await.expect("echo join").expect("echo completes");
    assert_eq!(
        payloads,
        vec![first_payload.to_vec(), second_payload.to_vec()]
    );
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0], peers[1]);
    assert_eq!(runtime.udp_sessions().session_socket_count_for_test(), 1);
    let sessions = runtime.udp_sessions().snapshot_for_test();
    let session = sessions.first().expect("session recorded");
    assert_eq!(session.packets_sent, 2);
    assert_eq!(session.packets_received, 2);
}

#[tokio::test]
async fn native_core_rejects_udp_by_rule() {
    let mut profile = RuntimeProfile::new("udp-reject");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "REJECT",
        no_resolve: false,
    }]
    .into();
    let runtime = NativeCoreRuntime::compile(&profile);

    let result = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("rejected-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53123)),
            target: ConnectTarget {
                host: Ipv4Addr::LOCALHOST.to_string(),
                port: 9,
            },
            payload: b"blocked".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await;

    assert!(result
        .expect_err("UDP datagram should be rejected")
        .contains("rejected"));
    assert_eq!(runtime.udp_sessions().len(), 0);
}

/// The NE flow path hands the raw fake IP over (QUIC dials the fake-IP
/// answer directly); the reverse lookup must feed the domain into the
/// rule match, the session key, and the dial target.
#[tokio::test]
async fn flow_datagram_to_fake_ip_routes_and_dials_by_domain() {
    let mut profile = RuntimeProfile::new("udp-fake-ip");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    profile.rules = vec![
        RouteRule {
            kind: RuleKind::Domain,
            payload: Some("fake-quic.test"),
            outbound: "DIRECT",
            no_resolve: false,
        },
        RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        },
    ]
    .into();
    let runtime = NativeCoreRuntime::compile(&profile);
    let fake_ip = runtime
        .fake_dns()
        .allocate_ipv4("fake-quic.test")
        .expect("allocate fake IP");

    let outcome = send_udp_flow_datagram(
        &runtime,
        UdpDatagram {
            flow_id: Some("fake-ip-flow".into()),
            pump_queue: None,
            inbound: "tun",
            user: None,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53400)),
            target: ConnectTarget {
                host: fake_ip.to_string(),
                port: 443,
            },
            payload: b"quic-initial".to_vec(),
            process_name: None,
            process_path: None,
        },
    )
    .await
    .expect("fake-IP flow datagram routes by domain");

    // Without the reverse lookup the datagram falls through to the
    // MATCH reject; the domain rule firing proves routing saw the domain.
    let session = runtime
        .udp_sessions()
        .session_for_flow("fake-ip-flow")
        .unwrap();
    assert_eq!(session.outbound, "DIRECT");
    assert_eq!(
        session.matched_rule.as_deref(),
        Some("DOMAIN,fake-quic.test,DIRECT")
    );
    assert!(outcome.enqueued);

    // The recorded session (and with it the dial target the actor was
    // spawned around) carries the domain, not the unroutable fake IP.
    let sessions = runtime.udp_sessions().snapshot_for_test();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].target.host, "fake-quic.test");
}

/// A fake-range IP with no live mapping (for example, minted by an
/// earlier capture session) must be refused: the match-all DIRECT rule
/// would otherwise dial the configured virtual address into the void.
#[tokio::test]
async fn stale_fake_ip_datagram_is_rejected_instead_of_dialed() {
    let mut profile = RuntimeProfile::new("udp-stale-fake");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    let runtime = NativeCoreRuntime::compile(&profile);

    // An unmapped pool address and the reserved tunnel-gateway slot are
    // both stale fake targets.
    for host in ["198.18.5.5", "198.18.0.1"] {
        let error = send_udp_flow_datagram(
            &runtime,
            UdpDatagram {
                flow_id: Some("stale-fake-flow".into()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53401)),
                target: ConnectTarget {
                    host: host.into(),
                    port: 443,
                },
                payload: b"doomed".to_vec(),
                process_name: None,
                process_path: None,
            },
        )
        .await
        .expect_err("stale fake target must be rejected");
        assert!(error.contains("stale fake IP"), "{error}");
    }

    assert_eq!(runtime.udp_sessions().len(), 0);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 0);
}

/// A face drain is what sweeps while no capture is open: a host serving
/// only authenticated faces must not hold an idle session's place and
/// association slot until one of its clients happens to send.
#[tokio::test]
async fn a_face_drain_sweeps_the_idle_sessions_no_capture_would() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let now = now_unix();
    table.insert_for_test(udp_session(
        udp_session_key(53_124),
        now - UDP_SESSION_IDLE_SECONDS - 1,
    ));
    assert_eq!(table.len(), 1);

    // A drain of a connection with no flows of its own, which is what a
    // quiet one's is.
    let drained = drain_udp_face_responses(
        &runtime,
        &Some(Arc::from("alice")),
        Some("udp-face/1/"),
        16,
        Duration::from_millis(10),
    )
    .await;

    assert!(drained.is_empty(), "it has no replies of its own");
    assert_eq!(table.len(), 0, "the idle session's place came back");
}

#[tokio::test]
async fn udp_session_sweep_removes_idle_session_and_socket_together() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let active_key = udp_session_key(53123);
    let idle_key = udp_session_key(53124);
    let now = now_unix();

    runtime.udp_sessions().insert_for_test(udp_session(
        active_key.clone(),
        now - UDP_SESSION_IDLE_SECONDS,
    ));
    runtime.udp_sessions().insert_for_test(udp_session(
        idle_key.clone(),
        now - UDP_SESSION_IDLE_SECONDS - 1,
    ));
    let idle_datagram = udp_datagram(idle_key.source, "idle-flow");
    let (idle_socket, _responses) = scripted_session_socket(runtime.udp_sessions(), &idle_datagram);
    runtime
        .udp_sessions()
        .store_session_socket(&idle_datagram, &direct_route(), idle_socket, now);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 1);

    assert_eq!(sweep_idle_udp_sessions(&runtime), 1);
    let sessions = runtime.udp_sessions().snapshot_for_test();
    assert!(sessions.iter().any(|session| session.key == active_key));
    assert!(!sessions.iter().any(|session| session.key == idle_key));
    assert_eq!(runtime.udp_sessions().session_socket_count(), 0);
}

/// Fills the table with sessions on live sockets: streams whose traffic
/// ran from a minute ago until 30 seconds ago, except those `activity`
/// gives as `(created, updated, received)`.
fn fill_with_live_sessions(
    table: &UdpSessionTable,
    now: i64,
    activity: impl Fn(usize) -> Option<(i64, i64, u64)>,
) -> Vec<(SessionUdpSocket, mpsc::Sender<Vec<u8>>)> {
    (0..UDP_SESSION_MAX_ENTRIES)
        .map(|index| {
            let key = udp_session_key(10_000 + index as u16);
            let datagram = udp_datagram(key.source, "live-flow");
            let (socket, responses) = scripted_session_socket(table, &datagram);
            table.store_session_socket(&datagram, &direct_route(), socket.clone(), now);
            let (created, updated, received) = activity(index).unwrap_or((now - 60, now - 30, 10));
            table.set_activity_for_test(&key, created, updated, received);
            (socket, responses)
        })
        .collect()
}

#[tokio::test]
async fn a_full_table_of_streams_and_waiting_exchanges_refuses_a_new_owner() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let now = now_unix();
    // One exchange still waits for its reply.
    let _live = fill_with_live_sessions(table, now, |index| (index == 0).then_some((now, now, 0)));
    let new_datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 20_000)), "new-flow");
    let error = send_udp_flow_datagram(&runtime, new_datagram.clone())
        .await
        .unwrap_err();
    assert!(error.contains("Core flow limit"));
    let sessions = table.snapshot_for_test();
    assert_eq!(sessions.len(), UDP_SESSION_MAX_ENTRIES);
    assert!(!sessions
        .iter()
        .any(|session| session.key.source == new_datagram.source));
    assert_eq!(table.session_socket_count(), UDP_SESSION_MAX_ENTRIES);
}

#[tokio::test]
async fn a_full_table_reclaims_a_batch_of_the_least_recently_active_exchanges() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let now = now_unix();
    // A batch of finished exchanges and six more recent ones, every third
    // one unanswered; every other session is a stream idle for longer
    // than any of them, short of the idle sweep.
    let exchanges = UDP_RECLAIM_BATCH + 6;
    let live = fill_with_live_sessions(table, now, |index| {
        Some(if index < UDP_RECLAIM_BATCH {
            let at = now - 110 + (index * 100 / UDP_RECLAIM_BATCH) as i64;
            (at, at, u64::from(index % 3 != 0))
        } else if index < exchanges {
            (now - 5, now - 5, u64::from(index % 3 != 0))
        } else {
            (now - 118, now - 115, 10)
        })
    });
    let new_datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 20_000)), "new-flow");
    assert!(
        send_udp_flow_datagram(&runtime, new_datagram.clone())
            .await
            .unwrap()
            .enqueued
    );
    let sessions = table.snapshot_for_test();
    assert_eq!(
        sessions.len(),
        UDP_SESSION_MAX_ENTRIES - UDP_RECLAIM_BATCH + 1
    );
    let held = |index: usize| {
        sessions
            .iter()
            .any(|session| session.key == udp_session_key(10_000 + index as u16))
    };
    for index in 0..exchanges {
        assert_eq!(
            held(index),
            index >= UDP_RECLAIM_BATCH,
            "exchange {index} is reclaimed with the stalest"
        );
        assert_eq!(live[index].0.accepts_sends(), index >= UDP_RECLAIM_BATCH);
    }
    assert!(
        (exchanges..UDP_SESSION_MAX_ENTRIES).all(held),
        "streams stay"
    );
    assert!(sessions
        .iter()
        .any(|session| session.key.source == new_datagram.source));
}

#[tokio::test]
async fn a_full_table_keeps_an_answered_exchange_whose_port_asks_again() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let now = now_unix();
    // A batch of exchanges answered this second; every fourth client port
    // has since sent again, as a new socket on a reused port does.
    let _live = fill_with_live_sessions(table, now, |index| {
        (index < UDP_RECLAIM_BATCH).then_some((now, now, 1))
    });
    for index in (0..UDP_RECLAIM_BATCH).step_by(4) {
        let source = udp_session_key(10_000 + index as u16).source;
        assert!(
            send_udp_flow_datagram(&runtime, udp_datagram(source, "live-flow"))
                .await
                .unwrap()
                .enqueued
        );
    }
    let new_datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 20_000)), "new-flow");
    assert!(
        send_udp_flow_datagram(&runtime, new_datagram)
            .await
            .unwrap()
            .enqueued
    );
    let sessions = table.snapshot_for_test();
    let held = |index: usize| {
        sessions
            .iter()
            .any(|session| session.key == udp_session_key(10_000 + index as u16))
    };
    for index in 0..UDP_RECLAIM_BATCH {
        assert_eq!(
            held(index),
            index % 4 == 0,
            "exchange {index} waits for its new answer or goes"
        );
    }
}

#[tokio::test]
async fn a_reclaimed_exchange_hands_its_association_slot_back_at_once() {
    let mut sessions = NativeCoreSessionState::default();
    sessions.udp_sessions.association_slots = Arc::new(tokio::sync::Semaphore::new(1));
    let snapshot = RuntimeSnapshot::compile(
        &self_test_profile(),
        Default::default(),
        Default::default(),
        None,
        sessions.group_state.clone(),
    );
    let runtime = NativeCoreRuntime::pinned(Arc::new(snapshot), sessions);
    let table = runtime.udp_sessions();
    let now = now_unix();
    let first = udp_datagram("127.0.0.1:55610".parse().unwrap(), "answered");
    let (socket, _responses) = scripted_session_socket_with_slot(
        table,
        &first,
        table.association_slots.clone().try_acquire_owned().unwrap(),
    );
    table.store_session_socket(&first, &direct_route(), socket.clone(), now);
    table.set_activity_for_test(&udp_session_key(55_610), now - 10, now - 10, 1);
    let second = udp_datagram("127.0.0.1:55611".parse().unwrap(), "next");
    assert!(
        send_udp_flow_datagram(&runtime, second)
            .await
            .unwrap()
            .enqueued
    );
    assert!(!socket.accepts_sends());
    assert!(!table
        .snapshot_for_test()
        .iter()
        .any(|session| session.key == udp_session_key(55_610)));
    table.close();
    runtime.task_tracker().close();
    runtime.task_tracker().wait().await;
    assert_eq!(table.association_slots.available_permits(), 1);
}

#[tokio::test]
async fn closed_session_is_not_recreated_by_late_send_accounting() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 20_001)),
        "closed-flow",
    );
    let route = runtime.route(&udp_route_input(&datagram));
    let (socket, _responses) = scripted_session_socket(runtime.udp_sessions(), &datagram);
    runtime
        .udp_sessions()
        .store_session_socket(&datagram, &route, Arc::clone(&socket), now_unix());

    assert_eq!(runtime.udp_sessions().close(), 1);
    runtime.udp_sessions().record_sent(
        &datagram,
        &route,
        &socket,
        datagram.payload.len(),
        now_unix(),
    );

    assert_eq!(runtime.udp_sessions().len(), 0);
    assert_eq!(runtime.udp_sessions().session_socket_count(), 0);
}

#[tokio::test]
async fn send_rejects_a_different_flow_in_the_source_entry() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let source: SocketAddr = "127.0.0.1:49003".parse().unwrap();
    assert!(
        send_udp_flow_datagram(&runtime, udp_datagram(source, "first-lifetime"))
            .await
            .unwrap()
            .enqueued
    );
    let error = send_udp_flow_datagram(&runtime, udp_datagram(source, "another-lifetime"))
        .await
        .unwrap_err();
    assert!(error.contains("already owned by flow"), "{error}");
    assert_eq!(
        runtime.udp_sessions().snapshot_for_test()[0].packets_sent,
        1,
        "the rejected send must not enter the old mailbox"
    );
    close_udp_sessions(&runtime);
}

#[tokio::test]
async fn packet_drain_preserves_other_flow_response_namespaces() {
    let runtime = NativeCoreRuntime::compile(&self_test_profile());
    let table = runtime.udp_sessions();
    let mut response_txs = Vec::new();
    for (index, id) in ["consumer-a:a", "ptun-udp|b", "consumer-a:c"]
        .into_iter()
        .enumerate()
    {
        let datagram = udp_datagram(SocketAddr::from(([127, 0, 0, 1], 49010 + index as u16)), id);
        let (socket, tx) = scripted_session_socket(table, &datagram);
        table.store_session_socket(&datagram, &direct_route(), socket.clone(), now_unix());
        tx.send(vec![1]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !socket.response_rx.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        response_txs.push(tx);
    }
    let packet = drain_pending_udp_flow_responses_for_prefix(
        &runtime,
        Some("ptun-udp|"),
        16,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(packet.len(), 1);
    assert_eq!(packet[0].flow_id, "ptun-udp|b");
    let mut consumer = Vec::new();
    for _ in 0..2 {
        consumer.extend(
            drain_pending_udp_flow_responses_for_prefix(
                &runtime,
                Some("consumer-a:"),
                16,
                Duration::from_secs(1),
            )
            .await,
        );
        if consumer.len() == 2 {
            break;
        }
    }
    let mut ids = consumer
        .into_iter()
        .map(|item| item.flow_id)
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, ["consumer-a:a", "consumer-a:c"]);
    table.close();
    drop(response_txs);
}

pub(super) fn udp_session_key(source_port: u16) -> UdpSessionKey {
    UdpSessionKey {
        user: None,
        face_flow: None,
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, source_port)),
    }
}

fn udp_datagram(source: SocketAddr, flow_id: &str) -> UdpDatagram {
    UdpDatagram {
        flow_id: Some(flow_id.into()),
        pump_queue: None,
        inbound: "tun",
        user: None,
        source,
        target: ConnectTarget {
            host: Ipv4Addr::LOCALHOST.to_string(),
            port: 9,
        },
        payload: b"session-datagram".to_vec(),
        process_name: None,
        process_path: None,
    }
}

fn udp_session(key: UdpSessionKey, updated_at_unix: i64) -> NativeUdpSession {
    NativeUdpSession {
        key,
        inbound: "tun",
        target: ConnectTarget {
            host: Ipv4Addr::LOCALHOST.to_string(),
            port: 9,
        },
        flow_id: None,
        process_name: None,
        process_path: None,
        outbound: "DIRECT".into(),
        matched_rule: None,
        egress_interface: None,
        created_at_unix: updated_at_unix,
        updated_at_unix,
        packets_sent: 0,
        packets_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
    }
}
/// A session with only a name on its way to a transport holds its place
/// while the preparation could still work, and yields it once the
/// preparation has outlasted one: a node that went unreachable after a
/// network change otherwise held every slot for the whole 30-second dial
/// budget, refusing every new UDP flow including the tunnel's own DNS.
/// Refusing the newcomer is what keeps a burst of new flows stable, so
/// the yield waits.
#[test]
fn a_preparation_that_outlasted_a_working_one_yields_its_place() {
    let created = 1_700_000_000;
    // The client keeps sending, so the session is a stream rather than a
    // finished exchange: the exchange rule below never reclaims it.
    let mut stats = udp_session(udp_session_key(40000), created);
    stats.created_at_unix = created;
    stats.updated_at_unix = created + 20;
    stats.packets_sent = 100;
    let mut entry = UdpSessionEntry::new(stats);
    entry.identities.insert(
        AssociationKey::Real,
        Identity {
            route: direct_route(),
            outbound: "DIRECT".into(),
            state: IdentityState::Preparing(Preparation {
                id: 1,
                pending_bytes: 0,
                pending: VecDeque::new(),
                slot: None,
                task: None,
            }),
        },
    );
    assert!(
        !entry.reclaimable(created + UDP_PREPARING_YIELD_SECONDS - 1),
        "a preparation that could still work keeps its place"
    );
    assert!(
        entry.reclaimable(created + UDP_PREPARING_YIELD_SECONDS),
        "one that has outlasted a working preparation yields it"
    );
    assert!(
        entry.reclaimable(created + 29),
        "and keeps yielding for the rest of the dial budget"
    );

    // An answer, however late it came, is evidence of a working flow.
    entry.stats.packets_received = 1;
    assert!(
        !entry.reclaimable(created + 600),
        "a session that got an answer keeps its place"
    );
}
/// The send mailbox is bounded in bytes as well as in datagrams: a
/// captured datagram carries up to 65 535 bytes once the pump has
/// reassembled its fragments, so the datagram count alone let the
/// mailboxes of a thousand associations against a stalled transport
/// reach gigabytes.
#[tokio::test]
async fn the_send_mailbox_is_bounded_in_bytes_as_well_as_datagrams() {
    let table = UdpSessionTable::default();
    let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 54_201)), "stalled");
    // A connect that never finishes, so the actor never takes a datagram
    // out of the mailbox.
    let socket = UdpSessionSocket::spawn(
        "DIRECT",
        true,
        table.socket_owner(
            &super::udp_session_key(&datagram),
            datagram.flow_id.clone(),
            datagram.pump_queue,
        ),
        EgressRuntime::default(),
        &tokio_util::task::TaskTracker::new(),
        Arc::default(),
        crate::policy_group::GroupStateTable::default(),
        Arc::default(),
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        std::future::pending::<Result<OutboundDatagramTransport, crate::outbound::OutboundError>>(),
    );

    let target = ConnectTarget {
        host: "192.0.2.1".into(),
        port: 9,
    };
    let big = vec![0_u8; 64 * 1024];
    let mut enqueued = 0;
    for _ in 0..UDP_SEND_MAILBOX {
        match socket.send_nowait(target.clone(), big.clone()) {
            UdpSendNowait::Enqueued => enqueued += 1,
            _ => break,
        }
    }
    assert!(
        enqueued < UDP_SEND_MAILBOX,
        "the datagram count alone did not stop it: {enqueued} queued"
    );
    assert_eq!(
        enqueued,
        UDP_QUEUE_BYTES / big.len(),
        "the byte bound stopped it"
    );
}
/// The datagrams waiting for a name to resolve are bounded: the send path
/// never waits on DNS, so each one holds its payload in a task of its own
/// for up to the DNS query budget, and a client streaming to a fake IP
/// otherwise had tens of thousands of them alive at once.
#[tokio::test]
async fn the_datagrams_waiting_on_a_name_are_bounded() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let table = runtime.udp_sessions();
    assert_eq!(
        table.resolving.available_permits(),
        UDP_RESOLVING_DATAGRAMS,
        "the bound starts whole"
    );

    // Every place is taken, as a flood of first datagrams to one fake IP
    // takes them while the name resolves.
    let held = Arc::clone(&table.resolving)
        .acquire_many_owned(UDP_RESOLVING_DATAGRAMS as u32)
        .await
        .expect("the bound's places");
    let dropped = table.send_drops.load(Ordering::Relaxed);
    let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 54_301)), "resolving");
    let input = super::udp_route_input(&datagram);
    send_once_resolved(&runtime, datagram, input);
    assert_eq!(
        table.send_drops.load(Ordering::Relaxed),
        dropped + 1,
        "past the bound the datagram is dropped and counted"
    );

    // A place given back admits the next one.
    drop(held);
    let datagram = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 54_302)), "resolving");
    let input = super::udp_route_input(&datagram);
    send_once_resolved(&runtime, datagram, input);
    assert!(
        table.resolving.available_permits() < UDP_RESOLVING_DATAGRAMS,
        "the admitted datagram holds a place while it waits"
    );
}
/// A client of an authenticated datagram face chooses the source it
/// claims and the face gives each one its own flow id, so one user's
/// frames mint a session entry each: the table keeps places for local
/// capture so that cannot refuse every application's UDP.
#[tokio::test]
async fn an_inbound_user_cannot_take_the_places_kept_for_capture() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    {
        let mut state = runtime
            .udp_sessions()
            .state
            .lock()
            .expect("udp session state");
        // Live, so the idle sweep on the send path leaves them.
        let now = now_unix();
        for port in 0..(UDP_SESSION_MAX_ENTRIES - UDP_SESSION_CAPTURE_RESERVE) as u16 {
            let key = udp_session_key(port);
            state
                .entries
                .insert(key.clone(), UdpSessionEntry::new(udp_session(key, now)));
        }
    }

    let mut face = udp_datagram(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 60_001)),
        "udp-face/1/claimed",
    );
    face.inbound = "udp-associate";
    let error = send_udp_flow_datagram(&runtime, face)
        .await
        .expect_err("the reserve refuses an inbound user");
    assert!(error.contains("capture reserve"), "{error}");

    let captured = udp_datagram(SocketAddr::from((Ipv4Addr::LOCALHOST, 60_002)), "captured");
    send_udp_flow_datagram(&runtime, captured)
        .await
        .expect("capture keeps the places kept for it");
}

fn user_session_key(user: &Arc<str>, source_port: u16) -> UdpSessionKey {
    UdpSessionKey {
        user: Some(Arc::clone(user)),
        face_flow: None,
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, source_port)),
    }
}

fn user_face_datagram(user: &Arc<str>, source_port: u16, flow_id: &str) -> UdpDatagram {
    let mut datagram = udp_datagram(
        SocketAddr::from((Ipv4Addr::LOCALHOST, source_port)),
        flow_id,
    );
    datagram.inbound = "udp-associate";
    datagram.user = Some(Arc::clone(user));
    datagram
}

/// Fills one authenticated user's places and asks for one more, then asks
/// for the first of another user's.
#[tokio::test]
async fn one_user_cannot_take_the_places_left_to_the_other_users() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let flood: Arc<str> = Arc::from("flood");
    {
        let mut state = runtime
            .udp_sessions()
            .state
            .lock()
            .expect("udp session state");
        // Live, so the idle sweep on the send path leaves them.
        let now = now_unix();
        for port in 0..UDP_SESSION_PER_USER_ENTRIES as u16 {
            let key = user_session_key(&flood, 50_000 + port);
            state.entry_for(&key, || UdpSessionEntry::new(udp_session(key.clone(), now)));
        }
        assert_eq!(state.held_by(&flood), UDP_SESSION_PER_USER_ENTRIES);
    }

    let error = send_udp_flow_datagram(
        &runtime,
        user_face_datagram(&flood, 60_001, "udp-face/1/claimed"),
    )
    .await
    .expect_err("the user has its places");
    assert!(error.contains("per-user"), "{error}");

    let other: Arc<str> = Arc::from("other");
    send_udp_flow_datagram(
        &runtime,
        user_face_datagram(&other, 60_002, "udp-face/2/claimed"),
    )
    .await
    .expect("another user still has places of its own");
}

/// The cap counts what a user holds now, so its places come back as its
/// sessions end -- every path that drops an entry walks them all, and the
/// count follows from there.
#[tokio::test]
async fn a_users_places_come_back_as_its_sessions_end() {
    let runtime = counting_runtime(Arc::new(AtomicUsize::new(0)));
    let flood: Arc<str> = Arc::from("flood");
    let now = now_unix();
    {
        let mut state = runtime
            .udp_sessions()
            .state
            .lock()
            .expect("udp session state");
        for port in 0..UDP_SESSION_PER_USER_ENTRIES as u16 {
            let key = user_session_key(&flood, 50_000 + port);
            state.entry_for(&key, || UdpSessionEntry::new(udp_session(key.clone(), now)));
        }
    }

    let swept = runtime
        .udp_sessions()
        .sweep_idle(now + UDP_SESSION_IDLE_SECONDS + 1);
    assert_eq!(swept, UDP_SESSION_PER_USER_ENTRIES);
    assert_eq!(
        runtime
            .udp_sessions()
            .state
            .lock()
            .expect("udp session state")
            .held_by(&flood),
        0
    );

    send_udp_flow_datagram(
        &runtime,
        user_face_datagram(&flood, 60_001, "udp-face/1/claimed"),
    )
    .await
    .expect("the user's places came back with its sessions");
}
