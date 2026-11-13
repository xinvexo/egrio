//! The task that resolves a fake IP's name before the identity joins a
//! transport, so the transport knows which replies are its.

use super::*;

/// Why a fake IP's name did not resolve for its outbound.
pub(super) enum PreparationFailure {
    Failed(crate::outbound::OutboundError),
    TimedOut(Duration),
}

/// A fake IP's name resolving for its identity's outbound before the
/// identity joins a transport ([`Preparation`]).
pub(super) struct PreparationTask {
    pub(super) key: UdpSessionKey,
    pub(super) identity: AssociationKey,
    pub(super) id: u64,
    /// The first datagram's target: the name, and the port it went to.
    pub(super) target: ConnectTarget,
    pub(super) resolver: Arc<target::TargetResolver>,
    pub(super) flow_id: Option<String>,
    pub(super) pump_queue: Option<usize>,
}

impl PreparationTask {
    pub(super) fn spawn(self, runtime: &NativeCoreRuntime) -> JoinHandle<()> {
        let runtime = runtime.clone();
        runtime.task_tracker().clone().spawn(async move {
            let budget = crate::outbound::OUTBOUND_DIAL_BUDGET;
            let prepared = match timeout(budget, self.resolver.prepare(&self.target, false)).await {
                Ok(prepared) => prepared.map_err(PreparationFailure::Failed),
                Err(_) => Err(PreparationFailure::TimedOut(budget)),
            };
            let _ = runtime.with_route_admission(|| self.attach(&runtime, prepared));
        })
    }

    /// Joins the identity to the transport its outbound's identities share,
    /// or opens one of its own when another identity there claims its
    /// address, then sends what waited, in order. A failure ends the
    /// preparation: what waited is dropped, and the next datagram starts
    /// anew.
    pub(super) fn attach(
        self,
        runtime: &NativeCoreRuntime,
        prepared: Result<ConnectTarget, PreparationFailure>,
    ) {
        let table = runtime.udp_sessions();
        let mut state = table.state.lock().expect("native core UDP sessions mutex");
        if !state.accepting {
            return;
        }
        let Some(entry) = state.entries.get_mut(&self.key) else {
            return;
        };
        let Some(Identity {
            route,
            outbound,
            state: identity_state,
        }) = entry.identities.remove(&self.identity)
        else {
            return;
        };
        let mut preparation = match identity_state {
            IdentityState::Preparing(preparation) if preparation.id == self.id => preparation,
            identity_state => {
                entry.identities.insert(
                    self.identity,
                    Identity {
                        route,
                        outbound,
                        state: identity_state,
                    },
                );
                return;
            }
        };
        // This task's own handle: finished with, not to be aborted.
        drop(preparation.task.take());
        let wire = match prepared {
            Ok(wire) => wire,
            // What waited for the name goes with the preparation, and is
            // counted: those datagrams were taken from a client that will
            // never see them sent, which is what the drop count is for.
            Err(PreparationFailure::Failed(error)) => {
                table.record_send_drops(preparation.pending.len());
                table
                    .transport_diagnostics
                    .record_dial_failure(&outbound, error);
                return;
            }
            Err(PreparationFailure::TimedOut(budget)) => {
                table.record_send_drops(preparation.pending.len());
                table
                    .transport_diagnostics
                    .record_dial_timeout(&outbound, budget);
                return;
            }
        };
        let Some(claim) = Claim::new(&self.identity, wire).map(Arc::new) else {
            return;
        };
        let shared_key = SocketKey::Shared(outbound.clone());
        let shared = entry
            .sockets
            .get(&shared_key)
            .filter(|socket| socket.accepts_sends())
            .cloned();
        let socket = match shared {
            Some(socket)
                if !claim
                    .wire_ip()
                    .is_some_and(|ip| socket.replies.is_claimed(ip)) =>
            {
                socket.replies.add(Arc::clone(&claim));
                socket
            }
            shared => {
                let installs = match shared {
                    Some(_) => SocketKey::Own(self.identity.clone()),
                    None => shared_key,
                };
                let (Some(connector), Some(slot)) = (
                    runtime.outbound_table().get(&outbound).cloned(),
                    preparation.slot.take(),
                ) else {
                    return;
                };
                entry.prune_drained();
                if entry.sockets.contains_key(&installs)
                    && entry.retired_sockets.len() >= UDP_RETIRED_SOCKET_MAX
                {
                    return;
                }
                let port = preparation
                    .pending
                    .front()
                    .map_or(self.target.port, |(target, _)| target.port);
                let socket = open_session_socket(
                    runtime,
                    &self.key,
                    self.flow_id,
                    self.pump_queue,
                    &outbound,
                    connector,
                    Arc::new(ReplyTable::with_claim(Arc::clone(&claim))),
                    self.resolver,
                    slot,
                    claim.send_target(port),
                );
                entry.install(installs, Arc::clone(&socket));
                socket
            }
        };
        for (target, payload) in preparation.pending.drain(..) {
            if !matches!(
                socket.send_nowait(claim.send_target(target.port), payload),
                UdpSendNowait::Enqueued
            ) {
                table.record_send_drop();
            }
        }
        entry.identities.insert(
            self.identity,
            Identity {
                route,
                outbound,
                state: IdentityState::Ready {
                    socket,
                    claim: Some(claim),
                },
            },
        );
    }
}
