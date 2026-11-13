//! The send path of one datagram: admission, the route of its target
//! identity, and the transport it joins or opens.

use super::*;

/// The no-wait flow send: route, hand the payload to the session actor, and
/// return. Responses are delivered exclusively through
/// [`drain_pending_udp_flow_responses`]; nothing on this path waits on
/// connect, hostname resolution, or upstream RTT.
pub(crate) async fn send_udp_flow_datagram(
    runtime: &NativeCoreRuntime,
    datagram: UdpDatagram,
) -> Result<UdpSendOutcome, String> {
    match runtime.with_route_admission(|| {
        send_udp_flow_datagram_admitted(runtime, datagram, AddressLookup::Pending)
    })?? {
        UdpSend::Sent(outcome) => Ok(outcome),
        UdpSend::NeedsAddress(deferred) => {
            let (datagram, input) = *deferred;
            send_once_resolved(runtime, datagram, input);
            Ok(UdpSendOutcome { enqueued: true })
        }
    }
}

/// A new association whose IP rules ask for its name's address. The send
/// path never waits on DNS, so this datagram waits in its own task while the
/// name resolves and is then admitted with the address; datagrams that come
/// meanwhile do the same, and the first admitted opens the association.
pub(super) fn send_once_resolved(
    runtime: &NativeCoreRuntime,
    datagram: UdpDatagram,
    input: RouteMatchInput,
) {
    // Bounded, so the first datagrams of a new association cannot pile up
    // while its name resolves; see `UDP_RESOLVING_DATAGRAMS`.
    let Ok(waiting) = Arc::clone(&runtime.udp_sessions().resolving).try_acquire_owned() else {
        runtime.udp_sessions().record_send_drop();
        return;
    };
    let tasks = runtime.task_tracker().clone();
    let cancel = runtime.connection_cancellation();
    let runtime = runtime.clone();
    tasks.spawn(async move {
        let _waiting = waiting;
        let address = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            address = runtime.rule_address(&input) => address,
        };
        let sent = runtime.with_route_admission(|| {
            send_udp_flow_datagram_admitted(&runtime, datagram, AddressLookup::Done(address))
        });
        if !matches!(sent, Ok(Ok(UdpSend::Sent(_)))) {
            runtime.udp_sessions().record_send_drop();
        }
    });
}

/// Whether a new association has had its name resolved for the IP rules.
#[derive(Clone, Copy)]
enum AddressLookup {
    /// Not yet: admission hands the datagram back to resolve it first.
    Pending,
    /// Done, or no rule asked: route with this.
    Done(Option<RuleAddress>),
}

enum UdpSend {
    Sent(UdpSendOutcome),
    /// The datagram, handed back, and the input whose name to resolve.
    NeedsAddress(Box<(UdpDatagram, RouteMatchInput)>),
}

enum Admission {
    /// Goes to this transport, sent to the target given.
    Routed(
        crate::rule_engine::RouteDecision,
        SessionUdpSocket,
        ConnectTarget,
    ),
    /// Waits, counted, while its identity's name resolves.
    Queued,
    /// Lost like any UDP datagram: its identity's waiting room is full.
    Dropped,
    NeedsAddress(RouteMatchInput),
}

fn send_udp_flow_datagram_admitted(
    runtime: &NativeCoreRuntime,
    mut datagram: UdpDatagram,
    lookup: AddressLookup,
) -> Result<UdpSend, String> {
    let Some(flow_id) = datagram
        .flow_id
        .take()
        .map(|flow_id| flow_id.trim().to_string())
        .filter(|flow_id| !flow_id.is_empty())
    else {
        return Err("UDP flow datagram requires a flow id".into());
    };
    datagram.flow_id = Some(flow_id);

    runtime.udp_sessions().sweep_idle_if_due(now_unix());
    let client_target = datagram.target.clone();
    let waited = |enqueued: bool| {
        if !enqueued {
            runtime.udp_sessions().record_send_drop();
        }
        Ok(UdpSend::Sent(UdpSendOutcome { enqueued }))
    };
    let (mut route, mut socket, target) =
        match route_and_session_socket(runtime, &mut datagram, lookup)? {
            Admission::Routed(route, socket, target) => (route, socket, target),
            Admission::Queued => return waited(true),
            Admission::Dropped => return waited(false),
            Admission::NeedsAddress(input) => {
                datagram.target = client_target;
                return Ok(UdpSend::NeedsAddress(Box::new((datagram, input))));
            }
        };
    let payload = std::mem::take(&mut datagram.payload);
    let bytes_sent = payload.len();

    let handed_to_actor = match socket.send_nowait(target, payload) {
        UdpSendNowait::Enqueued => true,
        UdpSendNowait::MailboxFull => false,
        UdpSendNowait::Closed(payload) => {
            // The actor died between lookup and send (transport ended).
            // Re-route and rebuild once — which re-notes the client target on
            // the fresh session — then retry; a second failure means the
            // connect itself is failing and the datagram is dropped like any
            // UDP loss.
            runtime
                .udp_sessions()
                .invalidate_socket(&udp_session_key(&datagram), &socket);
            datagram.target = client_target.clone();
            datagram.payload = payload;
            let target = match route_and_session_socket(runtime, &mut datagram, lookup)? {
                Admission::Routed(retry_route, retry_socket, target) => {
                    route = retry_route;
                    socket = retry_socket;
                    target
                }
                Admission::Queued => return waited(true),
                Admission::Dropped => return waited(false),
                Admission::NeedsAddress(input) => {
                    datagram.target = client_target;
                    return Ok(UdpSend::NeedsAddress(Box::new((datagram, input))));
                }
            };
            match socket.send_nowait(target, std::mem::take(&mut datagram.payload)) {
                UdpSendNowait::Enqueued => true,
                UdpSendNowait::MailboxFull => false,
                UdpSendNowait::Closed(_) => {
                    runtime
                        .udp_sessions()
                        .invalidate_socket(&udp_session_key(&datagram), &socket);
                    false
                }
            }
        }
    };
    let enqueued = handed_to_actor
        && runtime
            .udp_sessions()
            .record_sent(&datagram, &route, &socket, bytes_sent, now_unix());
    waited(enqueued)
}

/// The rule-match input of a datagram whose fake-IP target has already
/// given way to its domain.
pub(super) fn udp_route_input(datagram: &UdpDatagram) -> RouteMatchInput {
    RouteMatchInput {
        host: datagram.target.host_for_route(),
        destination_ip: datagram.target.ip(),
        destination_port: Some(datagram.target.port),
        source_ip: Some(datagram.source.ip()),
        source_port: Some(datagram.source.port()),
        network: Some(crate::rule_engine::TransportNetwork::Udp),
        process_name: datagram.process_name.clone(),
        process_path: datagram.process_path.clone(),
    }
}

/// The UDP arm of the fake-IP enrich stage: flow targets arrive as raw IPs
/// (QUIC to a fake-IP answer, most visibly), so a fake-range hit rewrites
/// the target to its domain before anything else reads it — the domain then
/// feeds the rule match, the session key, and the dial, exactly like the
/// TCP paths and the packet executor. A fake-range IP the store cannot name
/// is rejected instead of dialed: a configured virtual address has no
/// known target until a mapping or original hostname is available.
pub(super) fn rewrite_fake_ip_target(
    runtime: &NativeCoreRuntime,
    target: &mut ConnectTarget,
) -> Result<(), String> {
    let Some(ip) = target.ip() else {
        return Ok(());
    };
    if let Some(domain) = runtime.fake_dns_domain_for_ip(ip) {
        target.host = domain;
    } else if runtime.is_stale_fake_target(ip) {
        return Err(format!(
            "UDP datagram targets stale fake IP {}:{} with no live domain mapping",
            target.host, target.port
        ));
    }
    Ok(())
}

/// Routes a datagram to the transport of its identity within its unique
/// client owner. The real targets are one identity; each fake IP and the name
/// it stands for is another, every destination port of it included. An
/// identity's route is pinned while it lives, and the identities routed to
/// one outbound share its transport, so one mapping serves every remote
/// (EIM). A fake IP's name resolves before its identity joins the transport,
/// in a task of its own while its datagrams wait in order ([`Preparation`]);
/// a name the proxy resolves gets a transport of its own. Only a new
/// datagram can replace an ended transport, and previously queued or lost
/// payloads are never replayed. Admission never waits on DNS or upstream IO:
/// a new identity whose IP rules ask for its name's address is handed back
/// until `lookup` carries it.
fn route_and_session_socket(
    runtime: &NativeCoreRuntime,
    datagram: &mut UdpDatagram,
    lookup: AddressLookup,
) -> Result<Admission, String> {
    let client_facing = datagram.target.clone();
    rewrite_fake_ip_target(runtime, &mut datagram.target)?;
    let identity_key = AssociationKey::for_target(&client_facing, &datagram.target);
    let key = udp_session_key(datagram);
    let table = runtime.udp_sessions();
    let admission_epoch = {
        let state = table.state.lock().expect("native core UDP sessions mutex");
        if !state.accepting {
            return Err("UDP session table is closed".into());
        }
        state.admission_epoch
    };

    loop {
        let (observed, pinned) = {
            let state = table.state.lock().expect("native core UDP sessions mutex");
            check_admission(&state, admission_epoch, &key, datagram)?;
            let (observed, identity) = Observed::of(state.entries.get(&key), &identity_key);
            (observed, identity.map(|identity| identity.route.clone()))
        };

        // The rule decision is pinned while a live identity holds it (EIM).
        // One whose transport ended is drainable but no longer owns
        // admission, so the next send re-routes it.
        let route = match (pinned, lookup) {
            (Some(route), _) => route,
            (None, AddressLookup::Done(address)) => {
                runtime.route_with_address(&udp_route_input(datagram), address)
            }
            (None, AddressLookup::Pending) => {
                let input = udp_route_input(datagram);
                match runtime.route_step(&input, None) {
                    RouteStep::Decided(route) => route,
                    RouteStep::NeedsAddress(_) => return Ok(Admission::NeedsAddress(input)),
                }
            }
        };
        if crate::rule_engine::is_reject_outbound(&route.outbound) {
            return Err(format!("UDP datagram rejected by outbound {}", route.outbound).into());
        }
        let outbound_name = {
            let resolved = runtime
                .resolve_outbound(&route.outbound, &datagram.target)
                .ok_or_else(|| format!("UDP outbound '{}' is not implemented", route.outbound))?;
            if !resolved.connector.supports_udp() {
                return Err(
                    format!("outbound '{}' does not support UDP yet", route.outbound).into(),
                );
            }
            runtime
                .egress()
                .validate_outbound_target(&datagram.target, resolved.connector.is_direct())
                .map_err(|reason| reason.to_string())?;
            resolved.name
        };
        let connector = runtime
            .outbound_table()
            .get(&outbound_name)
            .cloned()
            .ok_or_else(|| format!("UDP outbound '{outbound_name}' is not implemented"))?;

        let mut reclaimed = Reclaimed {
            runtime,
            entries: Vec::new(),
        };
        let mut state = table.state.lock().expect("native core UDP sessions mutex");
        check_admission(&state, admission_epoch, &key, datagram)?;
        if !observed.is(&Observed::of(state.entries.get(&key), &identity_key).0) {
            drop(state);
            continue;
        }
        if let Some(entry) = state.entries.get_mut(&key) {
            let identity = entry
                .identities
                .get_mut(&identity_key)
                .filter(|identity| identity.outbound == outbound_name);
            match identity.map(|identity| &mut identity.state) {
                Some(IdentityState::Ready { socket, claim }) if socket.accepts_sends() => {
                    let target = match claim {
                        Some(claim) => claim.send_target(datagram.target.port),
                        None => {
                            socket.note_client_target(&client_facing);
                            datagram.target.clone()
                        }
                    };
                    return Ok(Admission::Routed(route, Arc::clone(socket), target));
                }
                Some(IdentityState::Preparing(preparation)) => {
                    if preparation.pending.len() >= UDP_SEND_MAILBOX
                        || preparation.pending_bytes + datagram.payload.len() > UDP_QUEUE_BYTES
                    {
                        return Ok(Admission::Dropped);
                    }
                    let payload = std::mem::take(&mut datagram.payload);
                    let bytes = payload.len();
                    preparation.pending_bytes += bytes;
                    preparation
                        .pending
                        .push_back((datagram.target.clone(), payload));
                    record_session_send(
                        &mut entry.stats,
                        datagram,
                        &route,
                        &outbound_name,
                        bytes,
                        now_unix(),
                    );
                    table.volume.add_upload(bytes as u64);
                    return Ok(Admission::Queued);
                }
                _ => {}
            }
        }

        // A new identity, or one whose transport ended or whose route now
        // leads to another outbound.
        let resolver = Arc::new(target::TargetResolver::new(
            runtime.clone(),
            connector.is_direct(),
            &outbound_name,
        ));
        let prepares = matches!(identity_key, AssociationKey::Virtual { .. })
            && !resolver.passes_name(&datagram.target.host);
        let shared_key = SocketKey::Shared(outbound_name.clone());
        let new_owner = !state.entries.contains_key(&key);
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.prune_drained();
        }
        let shared = state
            .entries
            .get(&key)
            .and_then(|entry| entry.sockets.get(&shared_key))
            .filter(|socket| socket.accepts_sends())
            .cloned();
        // Where it puts a transport it opens; a preparation holds a slot
        // until it joins one.
        let installs = match &identity_key {
            AssociationKey::Real => shared.is_none().then(|| shared_key.clone()),
            AssociationKey::Virtual { .. } => {
                (!prepares).then(|| SocketKey::Own(identity_key.clone()))
            }
        };
        let needs_slot = installs.is_some() || prepares;
        let full = |entries: &HashMap<UdpSessionKey, UdpSessionEntry>| {
            (new_owner && entries.len() >= UDP_SESSION_MAX_ENTRIES)
                || (needs_slot && table.association_slots.available_permits() == 0)
        };
        if full(&state.entries) {
            let seen = (
                state.entries.len(),
                table.association_slots.available_permits(),
            );
            let stood = state.swept_full.is_some_and(|(at, entries, permits)| {
                (entries, permits) == seen && at.elapsed() < UDP_FULL_SWEEP_STANDS
            });
            if !stood {
                // Finished sockets hold their association slots until pruned.
                for entry in state.entries.values_mut() {
                    entry.prune_drained();
                }
                reclaimed.entries = reclaim_sessions(&mut state.entries, &key, now_unix(), full);
                state.recount_users();
                state.swept_full = reclaimed.entries.is_empty().then(|| {
                    (
                        Instant::now(),
                        state.entries.len(),
                        table.association_slots.available_permits(),
                    )
                });
            }
        }
        if new_owner && state.entries.len() >= UDP_SESSION_MAX_ENTRIES {
            return Err("UDP Core flow limit reached".into());
        }
        if new_owner
            && datagram.inbound != "tun"
            && state.entries.len() >= UDP_SESSION_MAX_ENTRIES - UDP_SESSION_CAPTURE_RESERVE
        {
            return Err("UDP inbound flow limit reached, capture reserve".into());
        }
        if new_owner
            && key
                .user
                .as_ref()
                .is_some_and(|user| state.held_by(user) >= UDP_SESSION_PER_USER_ENTRIES)
        {
            return Err("UDP per-user flow limit reached".into());
        }
        if state.entries.get(&key).is_some_and(|entry| {
            !entry.identities.contains_key(&identity_key)
                && entry.identities.len() >= UDP_ASSOCIATIONS_PER_OWNER
        }) {
            return Err("UDP per-owner association limit reached".into());
        }
        if state.entries.get(&key).is_some_and(|entry| {
            installs
                .as_ref()
                .is_some_and(|installs| entry.sockets.contains_key(installs))
                && entry.retired_sockets.len() >= UDP_RETIRED_SOCKET_MAX
        }) {
            return Err("UDP pending reply association limit reached".into());
        }
        let slot = needs_slot
            .then(|| table.association_slots.clone().try_acquire_owned())
            .transpose()
            .map_err(|_| "UDP Core association limit reached")?;

        let now = now_unix();
        let entry = state.entry_for(&key, || {
            UdpSessionEntry::new(new_udp_session(datagram, &route, &key, &outbound_name, now))
        });
        entry.stats.outbound.clone_from(&outbound_name);
        entry.stats.matched_rule = route.matched_rule.clone();
        if let Some(previous) = entry.identities.remove(&identity_key) {
            entry.release_identity(&identity_key, previous);
        }
        let open = |replies: Arc<ReplyTable>, slot| {
            open_session_socket(
                runtime,
                &key,
                datagram.flow_id.clone(),
                datagram.pump_queue,
                &outbound_name,
                Arc::clone(&connector),
                replies,
                Arc::clone(&resolver),
                slot,
                datagram.target.clone(),
            )
        };
        let (socket, claim) = match (installs, slot) {
            // The real targets join the shared transport.
            (None, None) => (shared.expect("a live shared transport"), None),
            // A name that resolves first waits for its transport.
            (None, Some(slot)) => {
                let id = NEXT_PREPARATION.fetch_add(1, Ordering::Relaxed);
                let payload = std::mem::take(&mut datagram.payload);
                let bytes = payload.len();
                let task = PreparationTask {
                    key: key.clone(),
                    identity: identity_key.clone(),
                    id,
                    target: datagram.target.clone(),
                    resolver,
                    flow_id: datagram.flow_id.clone(),
                    pump_queue: datagram.pump_queue,
                }
                .spawn(runtime);
                entry.identities.insert(
                    identity_key,
                    Identity {
                        route: route.clone(),
                        outbound: outbound_name.clone(),
                        state: IdentityState::Preparing(Preparation {
                            id,
                            pending_bytes: payload.len(),
                            pending: VecDeque::from([(datagram.target.clone(), payload)]),
                            slot: Some(slot),
                            task: Some(task),
                        }),
                    },
                );
                record_session_send(
                    &mut entry.stats,
                    datagram,
                    &route,
                    &outbound_name,
                    bytes,
                    now,
                );
                table.volume.add_upload(bytes as u64);
                return Ok(Admission::Queued);
            }
            (Some(installs), Some(slot)) => {
                // The proxy resolves the name: the identity's own transport
                // knows its replies by the first one.
                let claim = Claim::new(&identity_key, datagram.target.clone()).map(Arc::new);
                let replies = claim.as_ref().map_or_else(ReplyTable::default, |claim| {
                    ReplyTable::with_claim(Arc::clone(claim))
                });
                let socket = open(Arc::new(replies), slot);
                entry.install(installs, Arc::clone(&socket));
                (socket, claim)
            }
            (Some(_), None) => unreachable!("a transport opens with a slot"),
        };
        let target = match &claim {
            Some(claim) => claim.send_target(datagram.target.port),
            None => {
                socket.note_client_target(&client_facing);
                datagram.target.clone()
            }
        };
        entry.identities.insert(
            identity_key,
            Identity {
                route: route.clone(),
                outbound: outbound_name,
                state: IdentityState::Ready {
                    socket: Arc::clone(&socket),
                    claim,
                },
            },
        );
        drop(state);
        drop(reclaimed);
        return Ok(Admission::Routed(route, socket, target));
    }
}

/// Whether `datagram` may still be admitted to the session `key` under the
/// admission generation it started in.
fn check_admission(
    state: &UdpSessionState,
    admission_epoch: u64,
    key: &UdpSessionKey,
    datagram: &UdpDatagram,
) -> Result<(), String> {
    if !state.accepting || state.admission_epoch != admission_epoch {
        return Err("UDP session admission generation changed".into());
    }
    if let Some(entry) = state.entries.get(key) {
        if entry.stats.flow_id != datagram.flow_id {
            return Err(format!(
                "UDP source {} is already owned by flow {:?}",
                key.source, entry.stats.flow_id
            ));
        }
    }
    Ok(())
}

/// Opens a transport through `outbound` for the session `key`, its first
/// datagram going to `first`: an address, a name the proxy resolves, or a
/// name the Core resolves once for the connector and that datagram alike (a
/// datagram face's real target).
#[allow(clippy::too_many_arguments)]
pub(super) fn open_session_socket(
    runtime: &NativeCoreRuntime,
    key: &UdpSessionKey,
    flow_id: Option<String>,
    pump_queue: Option<usize>,
    outbound: &str,
    connector: Arc<dyn OutboundConnector>,
    replies: Arc<ReplyTable>,
    resolver: Arc<target::TargetResolver>,
    slot: tokio::sync::OwnedSemaphorePermit,
    first: ConnectTarget,
) -> SessionUdpSocket {
    let table = runtime.udp_sessions();
    let egress = runtime.egress().with_binding_recorder();
    let connector_egress = egress.clone();
    let prepare_target = Arc::clone(&resolver);
    // A captured flow through a connection every flow of its outbound shares
    // goes to the queue whose pump runs where that connection's tasks do.
    let pump_queue = pump_queue.map(|queue| {
        connector
            .carrier_runtime()
            .and_then(|carrier| runtime.pump_runtimes().queue_of(carrier))
            .unwrap_or(queue)
    });
    UdpSessionSocket::spawn(
        outbound,
        connector.is_direct(),
        table.socket_owner(key, flow_id, pump_queue),
        egress,
        runtime.task_tracker(),
        table.transport_diagnostics.clone(),
        runtime.group_state().clone(),
        replies,
        Some(resolver),
        slot,
        async move {
            let target = prepare_target.prepare(&first, true).await?;
            connector.connect_datagram(&connector_egress, &target).await
        },
    )
}

pub(super) fn new_udp_session(
    datagram: &UdpDatagram,
    route: &crate::rule_engine::RouteDecision,
    key: &UdpSessionKey,
    outbound: &str,
    now: i64,
) -> NativeUdpSession {
    NativeUdpSession {
        key: key.clone(),
        inbound: datagram.inbound,
        target: datagram.target.clone(),
        flow_id: datagram.flow_id.clone(),
        process_name: datagram.process_name.clone(),
        process_path: datagram.process_path.clone(),
        outbound: outbound.to_string(),
        matched_rule: route.matched_rule.clone(),
        egress_interface: None,
        created_at_unix: now,
        updated_at_unix: now,
        packets_sent: 0,
        packets_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
    }
}

pub(super) fn record_session_send(
    session: &mut NativeUdpSession,
    datagram: &UdpDatagram,
    route: &crate::rule_engine::RouteDecision,
    outbound: &str,
    bytes_sent: usize,
    now: i64,
) {
    debug_assert_eq!(session.key.source, datagram.source);
    debug_assert!(session.created_at_unix <= now);
    if session.outbound != outbound {
        session.outbound = outbound.to_string();
    }
    debug_assert_eq!(session.flow_id, datagram.flow_id);
    // A datagram that passed before its owner was found carries none; it
    // never clears an owner an earlier datagram brought.
    if datagram.process_name.is_some() || datagram.process_path.is_some() {
        if session.process_name != datagram.process_name {
            session.process_name = datagram.process_name.clone();
        }
        if session.process_path != datagram.process_path {
            session.process_path = datagram.process_path.clone();
        }
    }
    if session.matched_rule != route.matched_rule {
        session.matched_rule = route.matched_rule.clone();
    }
    session.updated_at_unix = now;
    session.packets_sent += 1;
    session.bytes_sent += bytes_sent as u64;
}

pub(super) fn udp_session_key(datagram: &UdpDatagram) -> UdpSessionKey {
    UdpSessionKey {
        user: datagram.user.clone(),
        face_flow: (datagram.inbound == "udp-associate")
            .then(|| datagram.flow_id.clone())
            .flatten(),
        source: datagram.source,
    }
}
