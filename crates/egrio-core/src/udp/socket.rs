//! One transport of a session: the actor task around a connector's datagram
//! transport, the bounded mailbox datagrams reach it through, and the bounded
//! queue its responses wait in.

use super::*;

pub(super) enum UdpSendNowait {
    Enqueued,
    MailboxFull,
    /// The actor's transport already ended; the payload comes back so the
    /// caller can retry it against a rebuilt session.
    Closed(Vec<u8>),
}

/// The UDP session actor around a connector-provided datagram transport.
/// One task owns the whole transport lifecycle:
/// it awaits the connect, then moves datagrams from the bounded send mailbox
/// to the protocol sender and decoded responses into the bounded response
/// queue for immediate replies and flow drain. Handing a datagram to the
/// actor never waits on connect, hostname resolution, or upstream I/O, which
/// is what keeps one slow session from head-of-line-blocking the serial
/// callers above it (provider IPC loop, packet loop). The actor is
/// protocol-blind; a datagram carries its own target (EIM) and a response its
/// own remote (EIF).
pub(super) struct UdpQueuedSend {
    pub(super) target: ConnectTarget,
    pub(super) payload: Vec<u8>,
}

/// One of the Core's association slots. A session socket and its actor
/// share it; it returns once both are gone, or at once when the table
/// reclaims the socket.
#[derive(Debug)]
pub(super) struct AssociationSlot(std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>);

impl AssociationSlot {
    pub(super) fn new(permit: tokio::sync::OwnedSemaphorePermit) -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(Some(permit))))
    }

    fn release(&self) {
        self.0.lock().expect("association slot mutex").take();
    }
}

/// Bytes waiting in a socket's send mailbox, bounded alongside its datagram
/// count by [`UDP_QUEUE_BYTES`]. Shared with the actor, which gives them back
/// as it takes each datagram out.
#[derive(Debug, Default)]
pub(crate) struct QueuedBytes {
    pub(crate) sends: std::sync::atomic::AtomicUsize,
}

pub(super) struct UdpSessionSocket {
    /// The session this socket belongs to, and its flow id: what a drain
    /// filters on and credits a reply to.
    pub(super) key: UdpSessionKey,
    pub(super) flow_id: Option<String>,
    /// This session's place in the route epoch that admitted it, the same one
    /// its actor holds, so a policy change reaches it through the table.
    pub(super) epoch: Arc<crate::runtime::EpochMembership>,
    pub(super) ready: Arc<ReadySignal>,
    send_tx: mpsc::Sender<UdpQueuedSend>,
    pub(super) response_rx: AsyncMutex<mpsc::Receiver<(ConnectTarget, Vec<u8>)>>,
    queued: Arc<QueuedBytes>,
    pub(super) actor_task: JoinHandle<()>,
    // Retained reply queues and the running task share this admission lease.
    association_slot: Arc<AssociationSlot>,
    /// The outbound this socket dials: every identity of the session routed
    /// there shares it (EIM) until its actor ends, then it is rebuilt.
    pub(super) outbound: String,
    pub(super) binding: EgressBindingRecorder,
    /// Which replies come from the fake IPs of the identities on it (EIF).
    pub(super) replies: Arc<ReplyTable>,
    /// For a captured flow: its transport, once connected, where the packet
    /// pump can drive it; the pump then sends and reads on it itself.
    pub(super) pump_io: Arc<OnceLock<Arc<dyn PumpDatagrams>>>,
    /// Whether the transport is DIRECT, whose destinations the egress floor
    /// may refuse.
    pub(super) direct: bool,
    pub(super) pump_sent: PumpSent,
    /// Set by abort and retirement, before the actor has finished unwinding.
    closed: AtomicBool,
    /// Ends the pump's sends and reads as soon as a policy change cancels the
    /// actor.
    policy_cancel: tokio_util::sync::CancellationToken,
    diagnostics: Arc<actor::Diagnostics>,
}

impl std::fmt::Debug for UdpSessionSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpSessionSocket")
            .field("actor_task_finished", &self.actor_task.is_finished())
            .finish_non_exhaustive()
    }
}

impl Drop for UdpSessionSocket {
    fn drop(&mut self) {
        self.actor_task.abort();
    }
}

/// Who a session socket belongs to and where it reports waiting replies.
pub(super) struct SocketOwner {
    pub(super) hub: ReadyHub,
    pub(super) key: UdpSessionKey,
    pub(super) flow_id: Option<String>,
    /// A captured flow's pump, which drives the transport once it can.
    pub(super) pump_owned: bool,
}

impl UdpSessionSocket {
    pub(super) fn spawn<F>(
        outbound: &str,
        direct: bool,
        owner: SocketOwner,
        egress: EgressRuntime,
        tasks: &tokio_util::task::TaskTracker,
        diagnostics: Arc<actor::Diagnostics>,
        node_health: crate::policy_group::GroupStateTable,
        replies: Arc<ReplyTable>,
        target_resolver: Option<Arc<target::TargetResolver>>,
        association_slot: tokio::sync::OwnedSemaphorePermit,
        connect: F,
    ) -> SessionUdpSocket
    where
        F: std::future::Future<
                Output = Result<OutboundDatagramTransport, crate::outbound::OutboundError>,
            > + Send
            + 'static,
    {
        // The session's place in the route epoch that admitted it, held by
        // its actor and by the socket the table keeps.
        let epoch = crate::runtime::EpochMembership::of(tasks);
        let queued = Arc::new(QueuedBytes::default());
        let (send_tx, send_rx) = mpsc::channel::<UdpQueuedSend>(UDP_SEND_MAILBOX);
        let (response_tx, response_rx) =
            mpsc::channel::<(ConnectTarget, Vec<u8>)>(UDP_RESPONSE_QUEUE);
        let association_slot = AssociationSlot::new(association_slot);
        let pump_io = Arc::new(OnceLock::new());
        let pump_owned = owner.pump_owned;
        let policy_cancel = egress.policy_cancel();
        Arc::new_cyclic(|socket| {
            let ready = Arc::new(ReadySignal {
                queued: AtomicBool::new(false),
                ended: AtomicBool::new(false),
                hub: owner.hub,
                socket: socket.clone(),
            });
            let actor_task = actor::Actor {
                outbound: outbound.to_string(),
                diagnostics: diagnostics.clone(),
                node_health,
                policy_cancel: policy_cancel.clone(),
                send_rx,
                response_tx,
                queued: Arc::clone(&queued),
                ready: ready.clone(),
                replies: replies.clone(),
                target_resolver,
                _association_slot: association_slot.clone(),
                budgets: actor::Budgets::default(),
                pump_io: pump_owned.then(|| Arc::clone(&pump_io)),
            }
            .spawn(Arc::clone(&epoch), connect);
            Self {
                key: owner.key,
                epoch,
                flow_id: owner.flow_id,
                ready,
                send_tx,
                response_rx: AsyncMutex::new(response_rx),
                queued,
                actor_task,
                association_slot,
                outbound: outbound.to_string(),
                binding: egress.binding_recorder(),
                replies,
                pump_io,
                direct,
                pump_sent: PumpSent::default(),
                closed: AtomicBool::new(false),
                policy_cancel,
                diagnostics,
            }
        })
    }

    pub(super) fn matches_outbound(&self, outbound: &str) -> bool {
        self.outbound == outbound
    }

    pub(super) fn egress_interface(&self) -> Option<u32> {
        self.binding.current().interface_index
    }

    /// A finished actor can still be drained, but must not take new
    /// datagrams: lookups treat it as a miss so the next send rebuilds the
    /// session around a fresh transport.
    pub(super) fn accepts_sends(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && !self.policy_cancel.is_cancelled()
            && !self.actor_task.is_finished()
    }

    pub(super) fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.actor_task.abort();
    }

    /// Ends the actor of a socket that stays in its session until its queued
    /// responses are drained, and lists it so a drain visits and releases it.
    pub(super) fn retire(&self) {
        self.abort();
        self.ready.end();
    }

    /// Closes a socket the table reclaimed to new datagrams and hands its
    /// association slot back at once; [`Reclaimed`] ends its actor.
    pub(super) fn reclaim(&self) {
        self.closed.store(true, Ordering::Release);
        self.association_slot.release();
    }

    /// Whether replies wait in its queue for a drain. The pump reads its
    /// sockets on demand: none wait there.
    pub(super) fn holds_replies(&self) -> bool {
        self.pump_io.get().is_none()
            && !self
                .response_rx
                .try_lock()
                .is_ok_and(|responses| responses.is_empty())
    }

    pub(super) fn is_drained(&self) -> bool {
        if self.accepts_sends() {
            return false;
        }
        // The pump reads its sockets on demand: nothing waits once they close.
        self.pump_io.get().is_some()
            || self
                .response_rx
                .try_lock()
                .is_ok_and(|responses| responses.is_empty())
    }

    /// Reads up to `max` datagrams from the DIRECT sockets this socket handed
    /// to the packet pump, framing them to the client from their
    /// client-facing source, each reply with its payload length: datagrams
    /// read together as one train when `train_mtu` (the device's MTU, if it
    /// takes trains) fits them, otherwise each as a packet. Returns whether
    /// the sockets are empty and armed to wake the pump again.
    pub(super) fn read_pump_io(
        &self,
        max: usize,
        train_mtu: Option<usize>,
        out: &mut Vec<(UdpReply, usize)>,
    ) -> bool {
        let Some(sockets) = self.pump_io.get() else {
            return true;
        };
        if !self.accepts_sends() {
            return true;
        }
        let client = self.key.source;
        let mut buffer = UDP_DATAGRAM_BUFFERS.take();
        let mut read = 0;
        {
            loop {
                if read >= max {
                    return false;
                }
                match sockets.try_recv(&mut buffer) {
                    Ok((length, from, segment)) => {
                        let Some(source) = self.replies.pump_source(from) else {
                            // A name the client cannot be answered from.
                            read += 1;
                            continue;
                        };
                        let data = &buffer[..length];
                        let segment = segment.clamp(1, length.max(1));
                        let header = if client.is_ipv6() { 48 } else { 28 };
                        let train = length > segment
                            && train_mtu.is_some_and(|mtu| segment + header <= mtu);
                        if train {
                            read += length.div_ceil(segment);
                            // One train carries at most the frames the output
                            // queue keeps for a datagram, because that is the
                            // room it guarantees a drain; a read the platform
                            // coalesced beyond it becomes several trains
                            // rather than one the queue would have to refuse
                            // whole. (A refused train is the whole read lost,
                            // and the count is the platform's to choose: a
                            // Linux GRO read of small datagrams is many of
                            // them.)
                            let per_train = segment
                                * train_mtu
                                    .map(crate::packet::datagram_frames)
                                    .unwrap_or(1)
                                    .max(1);
                            for part in data.chunks(per_train.max(segment)) {
                                if let Ok(header) =
                                    crate::packet::udp_train_header(source, client, part.len())
                                {
                                    out.push((
                                        UdpReply::Train(UdpTrain {
                                            header,
                                            payload: part.to_vec(),
                                            segment,
                                        }),
                                        part.len(),
                                    ));
                                }
                            }
                            continue;
                        }
                        // An empty datagram is one datagram too.
                        let datagrams = data.chunks(segment).chain(data.is_empty().then_some(data));
                        for datagram in datagrams {
                            read += 1;
                            if let Ok(packet) = crate::packet::build_udp_packet(
                                source.ip(),
                                client.ip(),
                                source.port(),
                                client.port(),
                                datagram,
                            ) {
                                out.push((UdpReply::Packet(packet), datagram.len()));
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        let error = DatagramError::NativeSocket(error);
                        if error.is_packet_error(DatagramOperation::Receive) {
                            self.diagnostics.record_packet_error(
                                &self.outbound,
                                UdpTransportStage::Receive,
                                error,
                            );
                            // It counts against the read quantum like a
                            // datagram: a dead peer answers every datagram
                            // sent to it with an ICMP error, and a socket
                            // handing those over as fast as the pump can
                            // take them would otherwise hold the pump for as
                            // long as they kept coming -- the quantum bounds
                            // the work of a turn, and this is work.
                            read += 1;
                            continue;
                        }
                        // A socket that fails otherwise cannot be read again:
                        // end the transport, and the next datagram builds anew.
                        self.diagnostics.record_failure(
                            &self.outbound,
                            UdpTransportStage::Receive,
                            error,
                        );
                        self.abort();
                        return true;
                    }
                }
            }
        }
        true
    }

    pub(super) fn note_client_target(&self, facing: &ConnectTarget) {
        self.replies.note_real_target(facing);
    }

    /// Hands one datagram to the actor without waiting for connect or
    /// upstream I/O. A full mailbox drops the datagram (normal UDP loss
    /// semantics under overload); a closed mailbox returns it so the caller
    /// can retry against a rebuilt session.
    pub(super) fn send_nowait(&self, target: ConnectTarget, payload: Vec<u8>) -> UdpSendNowait {
        let bytes = payload.len();
        if self.queued.sends.load(Ordering::Relaxed) + bytes > UDP_QUEUE_BYTES {
            return UdpSendNowait::MailboxFull;
        }
        match self.send_tx.try_send(UdpQueuedSend { target, payload }) {
            Ok(()) => {
                self.queued.sends.fetch_add(bytes, Ordering::Relaxed);
                UdpSendNowait::Enqueued
            }
            Err(mpsc::error::TrySendError::Full(_)) => UdpSendNowait::MailboxFull,
            Err(mpsc::error::TrySendError::Closed(message)) => {
                UdpSendNowait::Closed(message.payload)
            }
        }
    }

    /// Drains queued responses, each already framed to its client-facing
    /// source (EIF), for the flow/face drains.
    pub(super) async fn drain_available(
        &self,
        limit: usize,
    ) -> (Vec<(ConnectTarget, Vec<u8>)>, bool) {
        let mut drained = Vec::new();
        let mut response_rx = self.response_rx.lock().await;
        while drained.len() < limit {
            match response_rx.try_recv() {
                Ok((remote, payload)) => drained.push((remote, payload)),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        let queue_empty = response_rx.is_empty();
        (drained, queue_empty)
    }
}
