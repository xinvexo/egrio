//! Draining responses: what the packet pumps and the datagram faces take
//! from the sockets listed as ready, each from its own flows.

use super::*;

/// Drains responses from every flow session, polling for up to `max_wait`
/// when nothing is queued. Production consumers use the packet pumps' drains
/// and the face drains; this lets tests observe any flow, or the flows under
/// one prefix.
#[cfg(test)]
pub(crate) async fn drain_pending_udp_flow_responses(
    runtime: &NativeCoreRuntime,
    max_datagrams: usize,
    max_wait: Duration,
) -> Vec<UdpPendingFlowDatagram> {
    drain_pending_udp_flow_responses_for_prefix(runtime, None, max_datagrams, max_wait).await
}

#[cfg(test)]
pub(crate) async fn drain_pending_udp_flow_responses_for_prefix(
    runtime: &NativeCoreRuntime,
    prefix: Option<&str>,
    max_datagrams: usize,
    max_wait: Duration,
) -> Vec<UdpPendingFlowDatagram> {
    let limit = max_datagrams.clamp(1, UDP_FLOW_DRAIN_MAX_DATAGRAMS);
    let table = runtime.udp_sessions();
    let deadline = Instant::now() + max_wait;
    // The sockets that moved their transport to the packet pump are its own.
    let mine = |socket: &UdpSessionSocket| {
        socket.pump_io.get().is_none()
            && socket.key.user.is_none()
            && socket.key.face_flow.is_none()
            && socket
                .flow_id
                .as_deref()
                .is_some_and(|flow_id| prefix.is_none_or(|prefix| flow_id.starts_with(prefix)))
    };

    loop {
        table.sweep_idle_if_due(now_unix());
        // Every hub: captured flows list on their pump's, the others on the
        // table's own. A test drain polls rather than parking on each.
        let hubs = std::iter::once(table.ready.clone())
            .chain(
                table
                    .pump_ready
                    .lock()
                    .expect("UDP pump ready hubs mutex")
                    .iter()
                    .cloned(),
            )
            .collect::<Vec<_>>();
        let mut drained = Vec::new();
        for hub in &hubs {
            table
                .drain_ready(hub, &mine, limit - drained.len(), None, |socket, reply| {
                    if let (Some(flow_id), UdpReply::Response(source_endpoint, payload)) =
                        (&socket.flow_id, reply)
                    {
                        drained.push(UdpPendingFlowDatagram {
                            flow_id: flow_id.clone(),
                            source: socket.key.source,
                            source_endpoint,
                            payload,
                        });
                    }
                })
                .await;
            if drained.len() >= limit {
                break;
            }
        }
        if !drained.is_empty() {
            return drained;
        }
        if Instant::now() >= deadline {
            return Vec::new();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Capture queue `queue`'s pump drain, without waiting: up to
/// `max_datagrams` replies of the captured flows its packets opened, read
/// from the sockets they handed to the pump or queued by their session
/// actors.
pub(crate) async fn drain_pump_replies(
    runtime: &NativeCoreRuntime,
    queue: usize,
    max_datagrams: usize,
    train_mtu: Option<usize>,
) -> PumpReplies {
    let table = runtime.udp_sessions();
    table.sweep_idle_if_due(now_unix());
    let mut replies = PumpReplies::default();
    // Only the queue's captured flows list on its hub. The first queue also
    // takes what is left on the hubs of queues this capture does not have
    // (see `pump_hubs_above`); they are empty unless a capture reopened with
    // fewer queues than the one before it.
    let hub = table.pump_hub(queue);
    let dropped = match queue == 0 && table.dropped_hubs.load(Ordering::Acquire) {
        true => table.pump_hubs_above(table.pump_queues.load(Ordering::Relaxed).max(1)),
        false => Vec::new(),
    };
    let mut budget = max_datagrams.clamp(1, UDP_FLOW_DRAIN_MAX_DATAGRAMS);
    for hub in std::iter::once(&hub).chain(dropped.iter()) {
        let drained = table
            .drain_ready(
                hub,
                |_| true,
                budget,
                train_mtu,
                |socket, reply| match reply {
                    UdpReply::Packet(packet) => replies.packets.push(packet),
                    UdpReply::Train(train) => replies.trains.push(train),
                    UdpReply::Response(source_endpoint, payload) => {
                        if let Some(flow_id) = &socket.flow_id {
                            replies.responses.push(UdpPendingFlowDatagram {
                                flow_id: flow_id.clone(),
                                source: socket.key.source,
                                source_endpoint,
                                payload,
                            });
                        }
                    }
                },
            )
            .await;
        budget = budget.saturating_sub(drained);
        if budget == 0 {
            break;
        }
    }
    replies
}

/// One drained datagram-face response: the client flow it belongs to
/// (`source`, the session key's client 2-tuple), the client-facing address to
/// frame the reply from (`source_endpoint`, EIF — the reply's real remote
/// unless it maps back to a fake IP the client addressed), and the payload.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct UdpFaceResponse {
    /// Stable authenticated face identity, including protocols whose wire
    /// session survives changes to the client's source address (SS2022).
    pub(crate) flow_id: Option<String>,
    pub(crate) source: SocketAddr,
    pub(crate) source_endpoint: ConnectTarget,
    pub(crate) payload: Vec<u8>,
}

/// The datagram-face drain: collects the queued responses of one
/// authenticated connection's flows — scoped to the face's `user`, so one
/// connection never drains, or is starved by, another's — parking on the
/// session actors' notify for up to `max_wait` when nothing is queued. The
/// no-wait send path ([`send_udp_flow_datagram`]) enqueues; this delivers, so a
/// stalled target never head-of-line-blocks the connection's other flows.
/// Carries the flow source because a face frames replies by source rather
/// than by flow id.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn drain_udp_face_responses(
    runtime: &NativeCoreRuntime,
    user: &Option<Arc<str>>,
    flow_prefix: Option<&str>,
    max_datagrams: usize,
    max_wait: Duration,
) -> Vec<UdpFaceResponse> {
    let limit = max_datagrams.clamp(1, UDP_FLOW_DRAIN_MAX_DATAGRAMS);
    let table = runtime.udp_sessions();
    // A face drain runs for as long as its connection does, so it is what
    // sweeps while no capture is open: the sweep is otherwise the send
    // path's and the pumps', and a host serving only authenticated faces
    // would hold every idle session's place and association slot until one
    // of its clients happened to send.
    table.sweep_idle_if_due(now_unix());
    // This user's hub alone: a reply of another connection's flow neither
    // wakes this drain nor is walked over by it.
    let hub = table.face_hub(user);
    let notify = Arc::clone(&hub.notify);
    let deadline = Instant::now() + max_wait;
    let mine = |socket: &UdpSessionSocket| {
        socket.pump_io.get().is_none()
            && &socket.key.user == user
            && flow_prefix.is_none_or(|prefix| {
                socket
                    .flow_id
                    .as_deref()
                    .is_some_and(|flow_id| flow_id.starts_with(prefix))
            })
    };

    loop {
        // Register interest before draining: a response that lands between the
        // drain and the park leaves a permit, so the wakeup is never lost.
        let notified = notify.notified();
        tokio::pin!(notified);

        let mut drained = Vec::new();
        table
            .drain_ready(&hub, mine, limit, None, |socket, reply| {
                if let UdpReply::Response(source_endpoint, payload) = reply {
                    drained.push(UdpFaceResponse {
                        flow_id: socket.key.face_flow.clone(),
                        source: socket.key.source,
                        source_endpoint,
                        payload,
                    });
                }
            })
            .await;
        if !drained.is_empty() {
            return drained;
        }

        let now = Instant::now();
        if now >= deadline {
            return Vec::new();
        }
        if timeout(deadline - now, &mut notified).await.is_err() {
            return Vec::new();
        }
    }
}
