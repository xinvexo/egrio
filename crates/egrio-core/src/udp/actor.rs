//! One owner for a UDP transport's dial, relay, cancellation and terminal fact.
//! A datagram may be lost; an actor must never park forever while dialing or
//! writing it. Receive silence is not evidence of failure for UDP.

use std::sync::OnceLock;
use std::task::Waker;

use crate::outbound::{
    DatagramError, DatagramOperation, DatagramSendCancellation, OutboundError, OutboundStage,
    PumpDatagrams,
};
use crate::policy_group::GroupStateTable;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::*;

const RECENT_FAILURES: usize = 16;
const MAX_ERROR_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpTransportStage {
    Dial,
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpTransportErrorSource {
    NativeSocket,
    Carrier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UdpTransportFailureCause {
    Timeout {
        duration_ms: u64,
    },
    Message {
        message: String,
    },
    /// The outbound failed to establish, at the stage its connector observed.
    Outbound {
        stage: OutboundStage,
        message: String,
    },
    Io {
        source: UdpTransportErrorSource,
        error_kind: String,
        os_code: Option<i32>,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UdpTransportFailure {
    pub outbound: String,
    pub stage: UdpTransportStage,
    pub cause: UdpTransportFailureCause,
    pub at_unix: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UdpTransportDiagnostics {
    pub completed: u64,
    pub cancelled: u64,
    pub failures: u64,
    pub packet_errors: u64,
    /// Oldest first, bounded independently of session churn. No payloads are
    /// stored; connector diagnostics retain their stage.
    pub recent_failures: Vec<UdpTransportFailure>,
    pub recent_packet_errors: Vec<UdpTransportFailure>,
}

#[derive(Debug, Default)]
pub(super) struct Diagnostics(Mutex<UdpTransportDiagnostics>);

impl Diagnostics {
    pub(super) fn snapshot(&self) -> UdpTransportDiagnostics {
        self.0.lock().expect("UDP transport diagnostics").clone()
    }

    pub(super) fn record_packet_error(
        &self,
        outbound: &str,
        stage: UdpTransportStage,
        error: DatagramError,
    ) {
        self.record_packet_end(outbound, ActorEnd::datagram(stage, error));
    }

    /// A transport the packet pump drove ended on `error`.
    pub(super) fn record_failure(
        &self,
        outbound: &str,
        stage: UdpTransportStage,
        error: DatagramError,
    ) {
        self.record(outbound, ActorEnd::datagram(stage, error));
    }

    /// A fake IP's name failed to resolve for its transport: a dial failure,
    /// as it is when the transport resolves its first target itself.
    pub(super) fn record_dial_failure(&self, outbound: &str, error: OutboundError) {
        self.record(outbound, ActorEnd::outbound(UdpTransportStage::Dial, error));
    }

    pub(super) fn record_dial_timeout(&self, outbound: &str, budget: Duration) {
        self.record(
            outbound,
            ActorEnd::timed_out(UdpTransportStage::Dial, budget),
        );
    }

    fn record_packet_end(&self, outbound: &str, end: ActorEnd) {
        let ActorEnd::Failed { stage, cause } = end else {
            unreachable!()
        };
        let mut diagnostics = self.0.lock().expect("UDP transport diagnostics");
        diagnostics.packet_errors += 1;
        if diagnostics.recent_packet_errors.len() == RECENT_FAILURES {
            diagnostics.recent_packet_errors.remove(0);
        }
        diagnostics.recent_packet_errors.push(UdpTransportFailure {
            outbound: outbound.into(),
            stage,
            cause,
            at_unix: now_unix(),
        });
    }

    fn record(&self, outbound: &str, end: ActorEnd) {
        let mut diagnostics = self.0.lock().expect("UDP transport diagnostics");
        match end {
            ActorEnd::Completed => diagnostics.completed += 1,
            ActorEnd::Cancelled => diagnostics.cancelled += 1,
            ActorEnd::Failed { stage, cause } => {
                diagnostics.failures += 1;
                if diagnostics.recent_failures.len() == RECENT_FAILURES {
                    diagnostics.recent_failures.remove(0);
                }
                diagnostics.recent_failures.push(UdpTransportFailure {
                    outbound: outbound.into(),
                    stage,
                    cause,
                    at_unix: now_unix(),
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Budgets {
    pub dial: Duration,
    pub send: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            // The same end-to-end ceiling as TCP, including carrier lock
            // wait, DNS and proxy authentication rather than only TCP dial.
            dial: crate::outbound::OUTBOUND_DIAL_BUDGET,
            // One queued datagram is no longer timely after ten seconds of
            // blocked transport progress. Terminate the transport: dropping
            // a partial TLS-framed send and reusing it corrupts framing.
            send: Duration::from_secs(10),
        }
    }
}

fn bounded_message(mut message: String) -> String {
    if message.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    message
}

enum ActorEnd {
    Completed,
    Cancelled,
    Failed {
        stage: UdpTransportStage,
        cause: UdpTransportFailureCause,
    },
}

impl ActorEnd {
    fn datagram(stage: UdpTransportStage, error: DatagramError) -> Self {
        let (source, error) = match error {
            DatagramError::NativeSocket(error) => (UdpTransportErrorSource::NativeSocket, error),
            DatagramError::Carrier(error) => (UdpTransportErrorSource::Carrier, error),
            DatagramError::Protocol(message) | DatagramError::Rejected(message) => {
                return Self::message(stage, message)
            }
        };
        Self::Failed {
            stage,
            cause: UdpTransportFailureCause::Io {
                source,
                error_kind: format!("{:?}", error.kind()),
                os_code: error.raw_os_error(),
                message: bounded_message(error.to_string()),
            },
        }
    }
    fn message(stage: UdpTransportStage, message: String) -> Self {
        let message = bounded_message(message);
        Self::Failed {
            stage,
            cause: UdpTransportFailureCause::Message { message },
        }
    }

    fn outbound(stage: UdpTransportStage, error: OutboundError) -> Self {
        Self::Failed {
            stage,
            cause: UdpTransportFailureCause::Outbound {
                stage: error.stage,
                message: bounded_message(error.message),
            },
        }
    }

    fn timed_out(stage: UdpTransportStage, duration: Duration) -> Self {
        Self::Failed {
            stage,
            cause: UdpTransportFailureCause::Timeout {
                duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            },
        }
    }
}

/// Constructed before spawning so an abort before the task's first poll also
/// records its cancellation. The client owner outlives individual transports.
struct Completion {
    outbound: String,
    diagnostics: Arc<Diagnostics>,
    end: Option<ActorEnd>,
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.diagnostics.record(
            &self.outbound,
            self.end.take().unwrap_or(ActorEnd::Cancelled),
        );
    }
}

pub(super) struct Actor {
    pub outbound: String,
    pub diagnostics: Arc<Diagnostics>,
    /// Charged when the dial fails at a stage that is the node's fault; a
    /// datagram path gives no other unambiguous health evidence.
    pub node_health: GroupStateTable,
    pub policy_cancel: CancellationToken,
    pub send_rx: mpsc::Receiver<UdpQueuedSend>,
    pub response_tx: mpsc::Sender<(ConnectTarget, Vec<u8>)>,
    /// Bytes waiting in the send mailbox, given back as each datagram is
    /// taken out of it.
    pub queued: Arc<super::QueuedBytes>,
    /// Lists the socket for the drains after a response is queued and once
    /// the actor ends.
    pub ready: Arc<super::ReadySignal>,
    pub replies: Arc<ReplyTable>,
    pub target_resolver: Option<Arc<super::target::TargetResolver>>,
    pub _association_slot: Arc<super::AssociationSlot>,
    pub budgets: Budgets,
    /// For a captured flow: where a transport the packet pump can drive is
    /// published once connected, so the pump sends and reads on it itself.
    pub pump_io: Option<Arc<OnceLock<Arc<dyn PumpDatagrams>>>>,
}

impl Actor {
    pub(super) fn spawn<F>(
        self,
        epoch: std::sync::Arc<crate::runtime::EpochMembership>,
        connect: F,
    ) -> JoinHandle<()>
    where
        F: std::future::Future<Output = Result<OutboundDatagramTransport, OutboundError>>
            + Send
            + 'static,
    {
        let mut completion = Completion {
            outbound: self.outbound.clone(),
            diagnostics: self.diagnostics.clone(),
            end: None,
        };
        let policy_cancel = self.policy_cancel.clone();
        let ready = self.ready.clone();
        tokio::spawn(async move {
            // The session's place in its epoch, held for exactly as long as
            // the actor runs.
            let _epoch = epoch;
            let end = tokio::select! { biased;
                _ = policy_cancel.cancelled() => ActorEnd::Cancelled,
                end = self.run(connect) => end,
            };
            completion.end = Some(end);
            drop(completion);
            ready.end();
        })
    }

    async fn run<F>(mut self, connect: F) -> ActorEnd
    where
        F: std::future::Future<Output = Result<OutboundDatagramTransport, OutboundError>>,
    {
        let transport = match timeout(self.budgets.dial, connect).await {
            Ok(Ok(transport)) => transport,
            Ok(Err(error)) => {
                if error.stage.charges_node() {
                    self.node_health.record_failure(&self.outbound, now_unix());
                }
                return ActorEnd::outbound(UdpTransportStage::Dial, error);
            }
            // A dial that never answered names no stage: not node evidence.
            Err(_) => return ActorEnd::timed_out(UdpTransportStage::Dial, self.budgets.dial),
        };
        let OutboundDatagramTransport {
            sender,
            mut receiver,
        } = transport;
        // A captured flow's transport goes to the packet pump where it can
        // drive it: the pump sends and reads on it, waking on its readiness,
        // so the receive half stays idle and this actor only sends what the
        // pump hands it.
        let pump_reads = match (&self.pump_io, receiver.pump_datagrams()) {
            (Some(slot), Some(datagrams)) => {
                datagrams.hand_reads_to(Waker::from(Arc::new(super::PumpWake(self.ready.clone()))));
                let _ = slot.set(datagrams);
                true
            }
            _ => false,
        };
        // One message at a time, each under its own send budget. Nothing
        // queues behind a destination that is slow to resolve: the transport
        // every real destination of one client shares carries literal
        // addresses only, which resolve without asking DNS, and a name gets a
        // transport of its own (see `AssociationKey`). What can wait here is
        // the socket, and a socket whose buffer is full is backpressure for
        // every destination of it alike.
        let send_half = async {
            while let Some(message) = self.send_rx.recv().await {
                self.queued
                    .sends
                    .fetch_sub(message.payload.len(), Ordering::Relaxed);
                let deadline = Instant::now() + self.budgets.send;
                let target = if let Some(resolver) = &self.target_resolver {
                    match tokio::time::timeout_at(deadline, resolver.resolve(&message.target)).await
                    {
                        Ok(Ok(target)) => target,
                        Ok(Err(error)) => {
                            self.diagnostics.record_packet_end(
                                &self.outbound,
                                ActorEnd::message(UdpTransportStage::Send, error),
                            );
                            continue;
                        }
                        Err(_) => {
                            self.diagnostics.record_packet_end(
                                &self.outbound,
                                ActorEnd::timed_out(UdpTransportStage::Send, self.budgets.send),
                            );
                            continue;
                        }
                    }
                } else {
                    message.target
                };
                match tokio::time::timeout_at(deadline, sender.send(&target, &message.payload))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) if error.is_packet_error(DatagramOperation::Send) => {
                        self.diagnostics.record_packet_error(
                            &self.outbound,
                            UdpTransportStage::Send,
                            error,
                        );
                        // Drop this packet. Yield for cancellation/fairness;
                        // the next iteration consumes a different datagram.
                        tokio::task::yield_now().await;
                    }
                    Ok(Err(error)) => return ActorEnd::datagram(UdpTransportStage::Send, error),
                    Err(_)
                        if sender.send_cancellation()
                            == DatagramSendCancellation::AtomicDatagram =>
                    {
                        self.diagnostics.record_packet_end(
                            &self.outbound,
                            ActorEnd::timed_out(UdpTransportStage::Send, self.budgets.send),
                        );
                    }
                    Err(_) => {
                        return ActorEnd::timed_out(UdpTransportStage::Send, self.budgets.send)
                    }
                }
                // The permit stays with a payload until upstream send completes.
            }
            ActorEnd::Completed
        };
        let receive_half = async {
            if pump_reads {
                // The pump reads the datagrams; what is left here is the
                // transport ending with the carrier that holds it.
                return match receiver.ended().await {
                    Ok(()) => ActorEnd::Completed,
                    Err(error) => ActorEnd::datagram(UdpTransportStage::Receive, error),
                };
            }
            loop {
                let (remote, payload) = match receiver.recv().await {
                    Ok(Some(datagram)) => datagram,
                    Ok(None) => return ActorEnd::Completed,
                    Err(error) if error.is_packet_error(DatagramOperation::Receive) => {
                        self.diagnostics.record_packet_error(
                            &self.outbound,
                            UdpTransportStage::Receive,
                            error,
                        );
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(error) => return ActorEnd::datagram(UdpTransportStage::Receive, error),
                };
                let remote = self.replies.source(remote);
                // Parking here is the reply side's backpressure: the receive
                // half stops reading, the upstream socket's buffer fills and
                // the kernel drops at the source, which is what a UDP peer
                // should see. Its bound is the queue's datagram count.
                if self.response_tx.send((remote, payload)).await.is_err() {
                    return ActorEnd::Cancelled;
                }
                self.ready.raise();
            }
        };
        tokio::select! { end = send_half => end, end = receive_half => end }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::outbound::{DatagramFuture, OutboundDatagramReceiver, OutboundDatagramSender};

    use super::*;

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct BlockedSender(DropCount);
    impl OutboundDatagramSender for BlockedSender {
        fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
            crate::outbound::DatagramSendCancellation::MayLeavePartialFrame
        }

        fn send<'a>(&'a self, _: &'a ConnectTarget, _: &'a [u8]) -> DatagramFuture<'a, ()> {
            let _ = &self.0;
            Box::pin(std::future::pending())
        }
    }

    struct Receiver {
        _drop: DropCount,
        error: Option<String>,
    }

    struct EventReceiver(VecDeque<Result<Option<(ConnectTarget, Vec<u8>)>, DatagramError>>);
    impl OutboundDatagramReceiver for EventReceiver {
        fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
            Box::pin(async move {
                match self.0.pop_front() {
                    Some(event) => event,
                    None => std::future::pending().await,
                }
            })
        }
    }

    struct PacketErrorSender(Arc<Mutex<Vec<Vec<u8>>>>);
    impl OutboundDatagramSender for PacketErrorSender {
        fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
            crate::outbound::DatagramSendCancellation::AtomicDatagram
        }

        fn send<'a>(&'a self, _: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
            Box::pin(async move {
                let mut sent = self.0.lock().unwrap();
                sent.push(payload.to_vec());
                if sent.len() == 1 {
                    Err(DatagramError::NativeSocket(
                        io::ErrorKind::ConnectionRefused.into(),
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }
    impl OutboundDatagramReceiver for Receiver {
        fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
            Box::pin(async move {
                match self.error.take() {
                    Some(message) => Err(DatagramError::Protocol(message)),
                    None => std::future::pending().await,
                }
            })
        }
    }

    fn actor() -> (
        Actor,
        mpsc::Sender<UdpQueuedSend>,
        mpsc::Receiver<(ConnectTarget, Vec<u8>)>,
    ) {
        let (send_tx, send_rx) = mpsc::channel(4);
        let (response_tx, responses) = mpsc::channel(4);
        (
            Actor {
                outbound: "proxy".into(),
                diagnostics: Arc::default(),
                node_health: GroupStateTable::default(),
                policy_cancel: CancellationToken::new(),
                send_rx,
                response_tx,
                queued: Arc::default(),
                ready: super::super::ReadySignal::detached(),
                replies: Arc::default(),
                target_resolver: None,
                _association_slot: super::super::AssociationSlot::new(
                    Arc::new(tokio::sync::Semaphore::new(1))
                        .try_acquire_owned()
                        .unwrap(),
                ),
                budgets: Budgets::default(),
                pump_io: None,
            },
            send_tx,
            responses,
        )
    }

    fn message() -> UdpQueuedSend {
        UdpQueuedSend {
            target: ConnectTarget {
                host: "192.0.2.1".into(),
                port: 443,
            },
            payload: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn atomic_send_timeout_drops_only_that_packet_and_keeps_real_socket_mapping() {
        struct AtomicSender {
            socket: Arc<tokio::net::UdpSocket>,
            calls: Arc<AtomicUsize>,
        }
        impl OutboundDatagramSender for AtomicSender {
            fn send_cancellation(&self) -> DatagramSendCancellation {
                DatagramSendCancellation::AtomicDatagram
            }
            fn send<'a>(
                &'a self,
                target: &'a ConnectTarget,
                payload: &'a [u8],
            ) -> DatagramFuture<'a, ()> {
                Box::pin(async move {
                    if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return std::future::pending().await;
                    }
                    self.socket
                        .send_to(payload, target.authority().parse::<SocketAddr>().unwrap())
                        .await
                        .map(|_| ())
                        .map_err(DatagramError::NativeSocket)
                })
            }
        }
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        sender
            .send_to(b"prime", receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut buffer = [0; 32];
        let (_, original_peer) = receiver.recv_from(&mut buffer).await.unwrap();
        let (actor, send_tx, _responses) = actor();
        let cancel = actor.policy_cancel.clone();
        let diagnostics = actor.diagnostics.clone();
        let duration = actor.budgets.send;
        let calls = Arc::new(AtomicUsize::new(0));
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(AtomicSender {
                    socket: sender,
                    calls: calls.clone(),
                }),
                receiver: Box::new(Receiver {
                    _drop: DropCount(Arc::default()),
                    error: None,
                }),
            })),
        );
        for payload in [b"cancelled-packet".as_slice(), b"next-packet".as_slice()] {
            let mut packet = message();
            packet.target = ConnectTarget {
                host: "127.0.0.1".into(),
                port: receiver.local_addr().unwrap().port(),
            };
            packet.payload = payload.to_vec();
            assert!(send_tx.try_send(packet).is_ok());
        }
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::pause();
        tokio::time::advance(duration + Duration::from_millis(1)).await;
        tokio::time::resume();
        let (len, peer) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], b"next-packet");
        assert_eq!(peer, original_peer);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the timed-out payload is never replayed"
        );
        assert!(!task.is_finished());
        let stats = diagnostics.snapshot();
        assert_eq!(stats.packet_errors, 1);
        assert_eq!(stats.failures, 0);
        assert!(matches!(
            stats.recent_packet_errors[0].cause,
            UdpTransportFailureCause::Timeout { .. }
        ));
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn native_packet_errors_preserve_transport_and_never_replay_failed_payload() {
        let (actor, send_tx, mut received) = actor();
        let diagnostics = actor.diagnostics.clone();
        let cancel = actor.policy_cancel.clone();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(PacketErrorSender(sent.clone())),
                receiver: Box::new(EventReceiver(VecDeque::from([
                    Err(DatagramError::NativeSocket(
                        io::ErrorKind::ConnectionRefused.into(),
                    )),
                    Ok(Some((message().target, b"valid-after-icmp".to_vec()))),
                ]))),
            })),
        );
        assert!(send_tx.try_send(message()).is_ok());
        let mut second = message();
        second.payload = b"next-packet".to_vec();
        assert!(send_tx.try_send(second).is_ok());
        let (_, payload) = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"valid-after-icmp");
        timeout(Duration::from_secs(1), async {
            while sent.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!task.is_finished());
        assert_eq!(
            *sent.lock().unwrap(),
            vec![vec![1, 2, 3], b"next-packet".to_vec()]
        );
        let stats = diagnostics.snapshot();
        assert_eq!(stats.packet_errors, 2);
        assert_eq!(stats.failures, 0);
        assert!(stats.recent_packet_errors.iter().all(|event| matches!(
            &event.cause, UdpTransportFailureCause::Io { source: UdpTransportErrorSource::NativeSocket, error_kind, .. } if error_kind == "ConnectionRefused"
        )));
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn carrier_connection_reset_is_terminal_even_when_native_reset_is_not() {
        let (actor, _send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(PacketErrorSender(Arc::default())),
                receiver: Box::new(EventReceiver(VecDeque::from([Err(
                    DatagramError::Carrier(io::ErrorKind::ConnectionReset.into()),
                )]))),
            })),
        );
        task.await.unwrap();
        let stats = diagnostics.snapshot();
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.packet_errors, 0);
        assert!(matches!(&stats.recent_failures[0].cause,
            UdpTransportFailureCause::Io { source: UdpTransportErrorSource::Carrier, error_kind, .. }
            if error_kind == "ConnectionReset"));
    }

    #[tokio::test]
    async fn repeated_ready_native_errors_yield_to_cancellation_and_bound_diagnostics() {
        struct FailingReceiver;
        impl OutboundDatagramReceiver for FailingReceiver {
            fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
                Box::pin(std::future::ready(Err(DatagramError::NativeSocket(
                    io::ErrorKind::NetworkUnreachable.into(),
                ))))
            }
        }
        let (actor, _send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let cancel = actor.policy_cancel.clone();
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(PacketErrorSender(Arc::default())),
                receiver: Box::new(FailingReceiver),
            })),
        );
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let stats = diagnostics.snapshot();
        assert!(stats.packet_errors >= 16);
        assert_eq!(stats.recent_packet_errors.len(), RECENT_FAILURES);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.cancelled, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_dial_expires_drops_future_and_closes_mailbox() {
        let (actor, send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let guard = DropCount(drops.clone());
        let dial_budget = actor.budgets.dial;
        assert!(send_tx.try_send(message()).is_ok());
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            async move {
                let _guard = guard;
                std::future::pending().await
            },
        );
        tokio::task::yield_now().await;
        tokio::time::advance(dial_budget).await;
        task.await.unwrap();
        assert!(send_tx.is_closed());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let stats = diagnostics.snapshot();
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.recent_failures[0].stage, UdpTransportStage::Dial);
        assert_eq!(
            stats.recent_failures[0].cause,
            UdpTransportFailureCause::Timeout {
                duration_ms: 30_000
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_send_expires_and_drops_both_transport_halves() {
        let (actor, send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let send_budget = actor.budgets.send;
        let drops = Arc::new(AtomicUsize::new(0));
        let transport = OutboundDatagramTransport {
            sender: Box::new(BlockedSender(DropCount(drops.clone()))),
            receiver: Box::new(Receiver {
                _drop: DropCount(drops.clone()),
                error: None,
            }),
        };
        for _ in 0..4 {
            assert!(send_tx.try_send(message()).is_ok());
        }
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(transport)),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(send_budget).await;
        task.await.unwrap();
        assert!(send_tx.is_closed());
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        let stats = diagnostics.snapshot();
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.recent_failures[0].stage, UdpTransportStage::Send);
        assert_eq!(
            stats.recent_failures[0].cause,
            UdpTransportFailureCause::Timeout {
                duration_ms: 10_000
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn receive_failure_keeps_stage_and_bounded_diagnostic() {
        let (actor, _send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(BlockedSender(DropCount(drops.clone()))),
                receiver: Box::new(Receiver {
                    _drop: DropCount(drops.clone()),
                    error: Some("接收失败".repeat(400)),
                }),
            })),
        );
        task.await.unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        let stats = diagnostics.snapshot();
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.recent_failures[0].stage, UdpTransportStage::Receive);
        let UdpTransportFailureCause::Message { message } = &stats.recent_failures[0].cause else {
            panic!("message cause")
        };
        assert!(message.starts_with("接收失败"));
        assert!(message.len() <= MAX_ERROR_BYTES);
    }

    #[tokio::test(start_paused = true)]
    async fn receive_silence_is_not_failure_and_policy_cancellation_is_neutral() {
        let (actor, send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let cancel = actor.policy_cancel.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::ready(Ok(OutboundDatagramTransport {
                sender: Box::new(BlockedSender(DropCount(drops.clone()))),
                receiver: Box::new(Receiver {
                    _drop: DropCount(drops.clone()),
                    error: None,
                }),
            })),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(!task.is_finished());
        cancel.cancel();
        task.await.unwrap();
        assert!(send_tx.is_closed());
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        let stats = diagnostics.snapshot();
        assert_eq!(stats.cancelled, 1);
        assert_eq!(stats.failures, 0);
    }

    #[tokio::test]
    async fn abort_before_first_poll_records_cancellation_once() {
        let (actor, send_tx, _responses) = actor();
        let diagnostics = actor.diagnostics.clone();
        let task = actor.spawn(
            crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
            std::future::pending(),
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(send_tx.is_closed());
        let stats = diagnostics.snapshot();
        assert_eq!(stats.cancelled, 1);
        assert_eq!(stats.failures, 0);
    }

    #[tokio::test]
    async fn only_a_node_failure_at_dial_charges_the_node() {
        for (stage, charged) in [
            (OutboundStage::HopAuth, true),
            (OutboundStage::HopConnect, true),
            (OutboundStage::Target, false),
            (OutboundStage::TargetResolve, false),
            (OutboundStage::Local, false),
        ] {
            let (mut actor, _send_tx, _responses) = actor();
            let node_health = GroupStateTable::default();
            actor.node_health = node_health.clone();
            let diagnostics = actor.diagnostics.clone();
            actor
                .spawn(
                    crate::runtime::EpochMembership::of(&tokio_util::task::TaskTracker::new()),
                    std::future::ready(Err(OutboundError::new(stage, "scripted"))),
                )
                .await
                .unwrap();
            assert_eq!(
                node_health
                    .health_snapshot("proxy")
                    .map(|health| health.consecutive_failures),
                charged.then_some(1),
                "{stage:?}"
            );
            assert_eq!(
                diagnostics.snapshot().recent_failures[0].cause,
                UdpTransportFailureCause::Outbound {
                    stage,
                    message: "scripted".into()
                }
            );
        }
    }

    #[test]
    fn failure_history_is_bounded_while_counts_remain_cumulative() {
        let diagnostics = Diagnostics::default();
        for index in 0..100 {
            diagnostics.record(
                "proxy",
                ActorEnd::message(UdpTransportStage::Dial, index.to_string()),
            );
        }
        let stats = diagnostics.snapshot();
        assert_eq!(stats.failures, 100);
        assert_eq!(stats.recent_failures.len(), RECENT_FAILURES);
        assert_eq!(
            stats.recent_failures[0].cause,
            UdpTransportFailureCause::Message {
                message: "84".into()
            }
        );
    }
}
