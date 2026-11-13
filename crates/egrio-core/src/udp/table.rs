//! The UDP session table: its entries, the limits on them, and what closes,
//! sweeps and counts them.

use super::*;

pub(super) struct UdpSessionState {
    pub(super) accepting: bool,
    pub(super) admission_epoch: u64,
    pub(super) entries: HashMap<UdpSessionKey, UdpSessionEntry>,
    /// When a sweep of a full table last found nothing to reclaim, with the
    /// table size and the free association slots it saw. While both are
    /// unchanged a sweep would find the same nothing, so an admission that
    /// needs room is refused without one; the time bounds that, because a
    /// socket finishing frees a slot only once the sweep prunes it, which
    /// neither count shows. The sweep prunes every entry's finished sockets
    /// and walks every entry for a reclaimable one, under the one lock every
    /// capture queue's pump and every inbound face share, and a client
    /// sending into a table that stays full paid it on every datagram --
    /// which stalls that queue's captured TCP as well.
    pub(super) swept_full: Option<(Instant, usize, usize)>,
    /// Entries each authenticated user holds, for
    /// [`UDP_SESSION_PER_USER_ENTRIES`]. Kept by [`Self::entry_for`] as
    /// entries arrive and recounted after a sweep, which already walks every
    /// entry; a user drops out of the map with its last entry.
    per_user: HashMap<Arc<str>, usize>,
}

impl UdpSessionState {
    /// The entry for `key`, made by `new` if the key is new, with the user it
    /// belongs to counted. Every entry the table gains comes through here.
    pub(super) fn entry_for(
        &mut self,
        key: &UdpSessionKey,
        new: impl FnOnce() -> UdpSessionEntry,
    ) -> &mut UdpSessionEntry {
        if !self.entries.contains_key(key) {
            if let Some(user) = key.user.clone() {
                *self.per_user.entry(user).or_insert(0) += 1;
            }
        }
        self.entries.entry(key.clone()).or_insert_with(new)
    }

    /// Entries `user` holds.
    pub(super) fn held_by(&self, user: &Arc<str>) -> usize {
        self.per_user.get(user).copied().unwrap_or(0)
    }

    /// Counts the users again from the entries. Every path that removes an
    /// entry walks them all anyway, so the count follows removals without
    /// each of those paths knowing about it.
    pub(super) fn recount_users(&mut self) {
        self.per_user.clear();
        for key in self.entries.keys() {
            if let Some(user) = key.user.clone() {
                *self.per_user.entry(user).or_insert(0) += 1;
            }
        }
    }
}

impl Default for UdpSessionState {
    fn default() -> Self {
        Self {
            accepting: true,
            admission_epoch: 0,
            entries: HashMap::new(),
            swept_full: None,
            per_user: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct UdpSessionTable {
    pub(super) association_slots: Arc<tokio::sync::Semaphore>,
    /// Admission for the datagrams waiting on a name, see
    /// [`UDP_RESOLVING_DATAGRAMS`].
    pub(super) resolving: Arc<tokio::sync::Semaphore>,
    pub(super) state: Arc<Mutex<UdpSessionState>>,
    /// The sockets with responses waiting, which the drains visit, and the
    /// notify they park on instead of polling on a timer. The flows with no
    /// user list here: local capture inbounds, and a loopback SOCKS5
    /// association.
    pub(super) ready: ReadyHub,
    /// The same for each authenticated user. A face drain is scoped to one
    /// user, so listing a user's sockets apart is what keeps one reply from
    /// waking every other connection's drain and walking each of them over
    /// the whole list: the cost of a reply follows the user's own flows
    /// rather than the node's. The names come from the inbound's user table,
    /// so the map is bounded by the configured users; an entry is kept once
    /// made, because a socket holds its hub and taking the hub out of the
    /// map while a socket still lists on it would leave those replies for
    /// nobody to drain.
    face_ready: Arc<Mutex<HashMap<Arc<str>, ReadyHub>>>,
    /// The same for each capture queue's pump, which drains only the flows
    /// its own packets opened: a reply wakes that pump alone.
    pub(super) pump_ready: Arc<Mutex<Vec<ReadyHub>>>,
    /// How many queues the capture now running has, and whether hubs above
    /// that exist -- a capture that reopened with fewer queues than the one
    /// before it. Both are set once when a capture starts, so the drain of
    /// the ordinary case reads one atomic instead of taking the hub lock to
    /// find nothing.
    pub(super) pump_queues: Arc<AtomicUsize>,
    pub(super) dropped_hubs: Arc<AtomicBool>,
    /// When idle sessions were last swept, in Unix seconds: sends and drains
    /// sweep at most once a second instead of walking every session each time.
    last_sweep_unix: Arc<AtomicI64>,
    /// Datagrams dropped because a session send mailbox was full.
    pub(super) send_drops: Arc<AtomicU64>,
    /// DNS requests rejected by bounded admission or failed resolution.
    dns_answer_failures: Arc<AtomicU64>,
    pub(super) transport_diagnostics: Arc<actor::Diagnostics>,
    /// The device's traffic volume, counted with the per-session stats.
    pub(super) volume: Arc<crate::telemetry::TrafficVolumeCounter>,
}

impl Default for UdpSessionTable {
    fn default() -> Self {
        Self::counting_into(Arc::default())
    }
}

impl UdpSessionTable {
    /// A session table whose datagrams also count into `volume`.
    pub(crate) fn counting_into(volume: Arc<crate::telemetry::TrafficVolumeCounter>) -> Self {
        Self {
            association_slots: Arc::new(tokio::sync::Semaphore::new(UDP_ASSOCIATIONS_GLOBAL)),
            resolving: Arc::new(tokio::sync::Semaphore::new(UDP_RESOLVING_DATAGRAMS)),
            state: Arc::new(Mutex::new(UdpSessionState::default())),
            ready: ReadyHub::default(),
            face_ready: Arc::default(),
            pump_ready: Arc::default(),
            pump_queues: Arc::default(),
            dropped_hubs: Arc::default(),
            last_sweep_unix: Arc::new(AtomicI64::new(i64::MIN)),
            send_drops: Arc::new(AtomicU64::new(0)),
            dns_answer_failures: Arc::new(AtomicU64::new(0)),
            transport_diagnostics: Arc::default(),
            volume,
        }
    }
}

impl std::fmt::Debug for UdpSessionTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpSessionTable")
            .field("sessions", &self.len())
            .field("session_sockets", &self.session_socket_count())
            .finish()
    }
}

impl UdpSessionTable {
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .len()
    }

    pub(crate) fn reopen(&self) {
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        if !state.accepting {
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            state.accepting = true;
        }
    }

    pub(crate) fn close(&self) -> usize {
        self.clear_sessions(true)
    }

    pub(crate) fn cutover(&self) -> usize {
        self.clear_sessions(false)
    }

    fn clear_sessions(&self, close_admission: bool) -> usize {
        let (closed, sockets) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            if close_admission {
                state.accepting = false;
            }
            let closed = state.entries.len();
            let sockets =
                state
                    .entries
                    .drain()
                    .fold(Vec::new(), |mut sockets, (_key, mut entry)| {
                        entry.take_sockets(&mut sockets);
                        sockets
                    });
            (closed, sockets)
        };
        close_session_sockets(sockets);
        closed
    }

    #[cfg(test)]
    pub(crate) fn close_flow(&self, flow_id: &str) -> usize {
        let (closed, sockets) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            let before = state.entries.len();
            let mut sockets = Vec::new();
            state.entries.retain(|_, entry| {
                if entry.stats.flow_id.as_deref() == Some(flow_id) {
                    entry.take_sockets(&mut sockets);
                    false
                } else {
                    true
                }
            });
            state.recount_users();
            (before - state.entries.len(), sockets)
        };
        close_session_sockets(sockets);
        closed
    }

    /// Closes every session whose flow id starts with `prefix`, under the same
    /// admission fence as explicit flow close. Inbound faces namespace their flow ids
    /// (`udp-face/{id}/…`, `ss-udp/{user}/…`) precisely so a teardown can
    /// reclaim exactly its own flows without enumerating them — the ids embed
    /// the client source, which the face does not track.
    pub(crate) fn close_flows_with_prefix(&self, prefix: &str) -> usize {
        if prefix.is_empty() {
            return 0;
        }
        let (closed, sockets) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            let before = state.entries.len();
            let mut sockets = Vec::new();
            state.entries.retain(|_, entry| {
                if entry
                    .stats
                    .flow_id
                    .as_deref()
                    .is_some_and(|flow_id| flow_id.starts_with(prefix))
                {
                    entry.take_sockets(&mut sockets);
                    false
                } else {
                    true
                }
            });
            state.recount_users();
            (before - state.entries.len(), sockets)
        };
        close_session_sockets(sockets);
        closed
    }

    /// Kill switch: closes every UDP session relaying through `outbound`
    /// (the concrete node recorded at relay time). Dropping the session
    /// socket aborts its actor; the next datagram on the flow re-resolves
    /// and rebuilds.
    pub(crate) fn close_by_outbound(&self, outbound: &str) -> usize {
        self.close_sessions_where(|socket| socket.matches_outbound(outbound))
    }

    /// Network change: closes every UDP session with a socket whose egress
    /// the change took away (see [`NetworkChange::strands`]); the next
    /// datagram on the flow rebuilds it over the network that is there now.
    pub(crate) fn close_stranded(&self, change: &NetworkChange) -> usize {
        self.close_sessions_where(|socket| change.strands(&socket.binding.current()))
    }

    /// A policy change: closes every session whose identities the new policy
    /// does not all route where they go, and gives the rest their place in
    /// `epoch`, the route epoch that policy opened. One session can hold
    /// transports to several outbounds (EIM), and the identities on them
    /// would have to be taken apart one by one; closing the session instead
    /// costs its flows an egress port, and the next datagram rebuilds what
    /// the policy now asks for.
    pub(crate) fn reroute(
        &self,
        keeps_route: &dyn Fn(&crate::rule_engine::RouteDecision, &ConnectTarget, &str) -> bool,
        epoch: &tokio_util::task::TaskTracker,
    ) -> usize {
        let (closed, sockets) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            let before = state.entries.len();
            let mut sockets = Vec::new();
            state.entries.retain(|_key, entry| {
                let port = entry.stats.target.port;
                let keeps = entry.identities.iter().all(|(key, identity)| {
                    let target = match key {
                        AssociationKey::Real => entry.stats.target.clone(),
                        AssociationKey::Virtual { logical_host, .. } => ConnectTarget {
                            host: logical_host.clone(),
                            port,
                        },
                    };
                    keeps_route(&identity.route, &target, &identity.outbound)
                });
                if keeps {
                    for socket in entry.sockets.values().chain(entry.retired_sockets.iter()) {
                        socket.epoch.move_to(epoch);
                    }
                } else {
                    entry.take_sockets(&mut sockets);
                }
                keeps
            });
            state.recount_users();
            (before - state.entries.len(), sockets)
        };
        close_session_sockets(sockets);
        closed
    }

    fn close_sessions_where(&self, matches: impl Fn(&UdpSessionSocket) -> bool) -> usize {
        let (closed, sockets, retired) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.admission_epoch = state.admission_epoch.wrapping_add(1);
            let before = state.entries.len();
            let mut sockets = Vec::new();
            let mut retired = Vec::new();
            state.entries.retain(|_key, entry| {
                if entry.sockets.values().any(|socket| matches(socket)) {
                    entry.take_sockets(&mut sockets);
                    false
                } else {
                    entry.retired_sockets.retain(|socket| {
                        if matches(socket) {
                            retired.push(Arc::clone(socket));
                            false
                        } else {
                            true
                        }
                    });
                    true
                }
            });
            state.recount_users();
            (before - state.entries.len(), sockets, retired)
        };
        close_session_sockets(sockets);
        close_session_sockets(retired);
        closed
    }

    /// Sweeps idle sessions unless that already happened this second.
    pub(super) fn sweep_idle_if_due(&self, now: i64) {
        let last = self.last_sweep_unix.load(Ordering::Relaxed);
        if last != now
            && self
                .last_sweep_unix
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.sweep_idle(now);
        }
    }

    pub(crate) fn sweep_idle(&self, now: i64) -> usize {
        let (swept, sockets) = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            let before = state.entries.len();
            let mut sockets = Vec::new();
            state.entries.retain(|_key, entry| {
                if is_idle_since(entry.last_active_unix(), now) {
                    entry.take_sockets(&mut sockets);
                    false
                } else {
                    entry.prune_drained();
                    true
                }
            });
            state.recount_users();
            (before - state.entries.len(), sockets)
        };
        close_session_sockets(sockets);
        swept
    }

    pub(super) fn record_sent(
        &self,
        datagram: &UdpDatagram,
        route: &crate::rule_engine::RouteDecision,
        socket: &SessionUdpSocket,
        bytes_sent: usize,
        now: i64,
    ) -> bool {
        let key = udp_session_key(datagram);
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        let Some(entry) = state.entries.get_mut(&key) else {
            return false;
        };
        if !entry
            .sockets
            .values()
            .any(|current| Arc::ptr_eq(current, socket))
        {
            return false;
        }
        record_session_send(
            &mut entry.stats,
            datagram,
            route,
            &socket.outbound,
            bytes_sent,
            now,
        );
        self.volume.add_upload(bytes_sent as u64);
        true
    }

    #[cfg(feature = "bench-internals")]
    pub(super) fn socket_lookup_for_bench(
        &self,
        key: &UdpSessionKey,
        outbound: &str,
    ) -> Option<SessionUdpSocket> {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .get(key)
            .and_then(|entry| entry.sockets.get(&SocketKey::Shared(outbound.to_string())))
            .filter(|socket| socket.accepts_sends())
            .cloned()
    }

    #[cfg(feature = "bench-internals")]
    pub(super) fn record_for_bench(
        &self,
        datagram: &UdpDatagram,
        route: &crate::rule_engine::RouteDecision,
        outbound: &str,
        bytes_sent: usize,
        bytes_received: usize,
        now: i64,
    ) {
        let key = udp_session_key(datagram);
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        if !state.entries.contains_key(&key) && state.entries.len() >= UDP_SESSION_MAX_ENTRIES {
            evict_oldest_session(&mut state.entries);
            state.recount_users();
        }
        let entry = state.entry_for(&key, || {
            UdpSessionEntry::new(new_udp_session(datagram, route, &key, outbound, now))
        });
        record_session_send(&mut entry.stats, datagram, route, outbound, bytes_sent, now);
        entry.stats.packets_received += 1;
        entry.sent_when_answered = entry.packets_sent();
        entry.stats.bytes_received += bytes_received as u64;
        self.volume.add_upload(bytes_sent as u64);
        self.volume.add_download(bytes_received as u64);
    }

    #[cfg(test)]
    pub(super) fn store_session_socket(
        &self,
        datagram: &UdpDatagram,
        route: &crate::rule_engine::RouteDecision,
        socket: SessionUdpSocket,
        now: i64,
    ) {
        let key = udp_session_key(datagram);
        let replaced = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            assert!(state.accepting, "test table accepts session sockets");
            if !state.entries.contains_key(&key) {
                assert!(state.entries.len() < UDP_SESSION_MAX_ENTRIES);
            }
            let entry = state.entry_for(&key, || {
                UdpSessionEntry::new(new_udp_session(
                    datagram,
                    route,
                    &key,
                    &socket.outbound,
                    now,
                ))
            });
            entry.stats.outbound.clone_from(&socket.outbound);
            entry.identities.insert(
                AssociationKey::Real,
                Identity {
                    route: route.clone(),
                    outbound: socket.outbound.clone(),
                    state: IdentityState::Ready {
                        socket: socket.clone(),
                        claim: None,
                    },
                },
            );
            entry
                .sockets
                .insert(SocketKey::Shared(socket.outbound.clone()), socket)
        };
        close_session_sockets(replaced.into_iter().collect());
    }

    /// The ready hub of capture queue `queue`'s pump.
    pub(super) fn pump_hub(&self, queue: usize) -> ReadyHub {
        let mut hubs = self.pump_ready.lock().expect("UDP pump ready hubs mutex");
        if hubs.len() <= queue {
            hubs.resize_with(queue + 1, ReadyHub::default);
        }
        hubs[queue].clone()
    }

    /// Records the queue count of a capture that is starting, and whether
    /// the table holds hubs above it: those are the hubs of queues this
    /// capture does not have, and the first queue's pump takes what is left
    /// on them (see [`Self::pump_hubs_above`]). It stays recorded for the
    /// capture's life -- a socket keeps its own hub and lists there again
    /// after every reply, so one sweep of them would not do.
    pub(crate) fn note_capture_queues(&self, queues: usize) {
        let hubs = self
            .pump_ready
            .lock()
            .expect("UDP pump ready hubs mutex")
            .len();
        self.pump_queues.store(queues, Ordering::Relaxed);
        self.dropped_hubs.store(hubs > queues, Ordering::Release);
    }

    /// The hubs of queues a capture no longer has. A capture that reopened
    /// with fewer queues leaves the sockets a flow was given to the old
    /// queues listed where no pump looks, and their replies would wait there
    /// for good -- the client would send and never hear back until the
    /// session went idle. They are not dropped: a socket holds its hub, so
    /// taking one out of this list would lose the raises still to come.
    pub(super) fn pump_hubs_above(&self, queues: usize) -> Vec<ReadyHub> {
        self.pump_ready
            .lock()
            .expect("UDP pump ready hubs mutex")
            .iter()
            .skip(queues)
            .cloned()
            .collect()
    }

    /// Takes the sockets listed on `hub` that `mine` accepts, in the order
    /// they were listed, and leaves the rest listed for their own consumers.
    /// Sockets whose session is gone fall off the list.
    fn take_ready(
        &self,
        hub: &ReadyHub,
        mine: impl Fn(&UdpSessionSocket) -> bool,
    ) -> Vec<SessionUdpSocket> {
        let mut listed = hub.sockets.lock().expect("UDP ready list mutex");
        let mut taken = Vec::new();
        listed.retain(|socket| match socket.upgrade() {
            Some(socket) if mine(&socket) => {
                taken.push(socket);
                false
            }
            Some(_) => true,
            None => false,
        });
        taken
    }

    /// Drains up to `limit` replies from the listed sockets `mine` accepts,
    /// so busy flows take turns: one queued response per socket per pass, or
    /// up to [`PUMP_READ_QUANTUM`] datagrams from the sockets a socket handed
    /// to the packet pump. Each goes to `deliver`, a socket's in the order
    /// they came. A socket left with replies is listed again. Replies of a
    /// socket its session no longer owns are dropped.
    pub(super) async fn drain_ready(
        &self,
        hub: &ReadyHub,
        mine: impl Fn(&UdpSessionSocket) -> bool,
        limit: usize,
        train_mtu: Option<usize>,
        mut deliver: impl FnMut(&UdpSessionSocket, UdpReply),
    ) -> usize {
        let sockets = self.take_ready(hub, mine);
        // Unlisted before draining, so a reply arriving from here on lists
        // the socket again.
        for socket in &sockets {
            socket.ready.queued.store(false, Ordering::Release);
        }
        // Each reply with its payload length.
        let mut batches: Vec<Vec<(UdpReply, usize)>> = sockets.iter().map(|_| Vec::new()).collect();
        let mut emptied = vec![false; sockets.len()];
        let mut drained = 0;
        'passes: loop {
            let mut progressed = false;
            for (index, socket) in sockets.iter().enumerate() {
                if drained >= limit {
                    break 'passes;
                }
                if emptied[index] {
                    continue;
                }
                let before = batches[index].len();
                if socket.pump_io.get().is_some() {
                    emptied[index] = socket.read_pump_io(
                        PUMP_READ_QUANTUM.min(limit - drained),
                        train_mtu,
                        &mut batches[index],
                    );
                } else {
                    let (responses, queue_empty) = socket.drain_available(1).await;
                    emptied[index] = queue_empty;
                    batches[index].extend(responses.into_iter().map(|(source, payload)| {
                        let length = payload.len();
                        (UdpReply::Response(source, payload), length)
                    }));
                }
                let taken: usize = batches[index][before..]
                    .iter()
                    .map(|(reply, length)| match reply {
                        UdpReply::Train(train) => length.div_ceil(train.segment),
                        _ => 1,
                    })
                    .sum();
                if taken > 0 {
                    progressed = true;
                    drained += taken;
                }
            }
            if !progressed {
                break;
            }
        }
        let now = now_unix();
        let mut delivered = 0;
        for ((socket, batch), emptied) in sockets.iter().zip(batches).zip(emptied) {
            if !emptied {
                socket.ready.raise();
            } else if socket.ready.ended.load(Ordering::Acquire) && !socket.is_drained() {
                // Its actor is still unwinding: look again on a later drain.
                socket.ready.list();
            }
            if !batch.is_empty() {
                let bytes = batch.iter().map(|(_, length)| length).sum();
                if self.record_received(socket, batch.len(), bytes, now) {
                    delivered += batch.len();
                    for (reply, _) in batch {
                        deliver(socket, reply);
                    }
                }
            }
            if emptied {
                self.prune_drained_retired_socket(socket);
            }
        }
        delivered
    }

    fn record_received(
        &self,
        socket: &SessionUdpSocket,
        packets: usize,
        bytes: usize,
        now: i64,
    ) -> bool {
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        let Some(entry) = state.entries.get_mut(&socket.key) else {
            return false;
        };
        if !entry.owns_socket(socket) {
            return false;
        }
        entry.stats.updated_at_unix = now;
        entry.stats.packets_received += packets as u64;
        entry.stats.bytes_received += bytes as u64;
        entry.sent_when_answered = entry.packets_sent();
        self.volume.add_download(bytes as u64);
        true
    }

    fn prune_drained_retired_socket(&self, socket: &SessionUdpSocket) {
        if !socket.is_drained() {
            return;
        }
        let removed = {
            let mut state = self.state.lock().expect("native core UDP sessions mutex");
            state.entries.get_mut(&socket.key).and_then(|entry| {
                let removed =
                    if let Some(key) = entry.sockets.iter().find_map(|(key, current)| {
                        Arc::ptr_eq(current, socket).then(|| key.clone())
                    }) {
                        entry.sockets.remove(&key)
                    } else {
                        let position = entry
                            .retired_sockets
                            .iter()
                            .position(|retired| Arc::ptr_eq(retired, socket))?;
                        entry.retired_sockets.remove(position)
                    };
                if let Some(removed) = &removed {
                    removed.pump_sent.fold_into(&mut entry.stats);
                    entry
                        .identities
                        .retain(|_, identity| !identity.uses(removed));
                }
                removed
            })
        };
        close_session_sockets(removed.into_iter().collect());
    }

    #[cfg(test)]
    pub(super) fn flow_session_count(&self, prefix: &str) -> usize {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .values()
            .filter(|entry| {
                !(entry.sockets.is_empty()
                    && entry.retired_sockets.is_empty()
                    && entry.identities.is_empty())
                    && entry
                        .stats
                        .flow_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with(prefix))
            })
            .count()
    }

    pub(super) fn invalidate_socket(&self, key: &UdpSessionKey, socket: &SessionUdpSocket) -> bool {
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        let Some(entry) = state.entries.get_mut(key) else {
            return false;
        };
        entry.prune_drained();
        let Some(association) = entry
            .sockets
            .iter()
            .find_map(|(key, current)| Arc::ptr_eq(current, socket).then(|| key.clone()))
        else {
            return false;
        };
        if entry.retired_sockets.len() >= UDP_RETIRED_SOCKET_MAX {
            return false;
        }
        let invalidated = entry
            .sockets
            .remove(&association)
            .expect("current socket exists");
        invalidated.retire();
        entry.retired_sockets.push_back(invalidated);
        true
    }

    /// Where the flows of `user` list their replies, and what their drain
    /// parks on.
    pub(super) fn face_hub(&self, user: &Option<Arc<str>>) -> ReadyHub {
        let Some(user) = user else {
            return self.ready.clone();
        };
        self.face_ready
            .lock()
            .expect("UDP face ready hubs mutex")
            .entry(Arc::clone(user))
            .or_default()
            .clone()
    }

    /// What capture queue `queue`'s pump parks on for its flows' replies.
    pub(crate) fn pump_notify_handle(&self, queue: usize) -> Arc<Notify> {
        self.pump_hub(queue).notify
    }

    /// The pump's own send for a captured flow from `source` to the address
    /// `destination` it named, once that identity's transport is one the
    /// pump drives. A route through a policy group holds only while the
    /// group still resolves to the transport's outbound; the full send path
    /// follows the group when it chooses another.
    pub(crate) fn pump_send(
        &self,
        runtime: &NativeCoreRuntime,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<PumpUdpSend> {
        let client = ConnectTarget {
            host: destination.ip().to_string(),
            port: destination.port(),
        };
        let mut logical = client.clone();
        rewrite_fake_ip_target(runtime, &mut logical).ok()?;
        let association = AssociationKey::for_target(&client, &logical);
        let key = UdpSessionKey {
            user: None,
            face_flow: None,
            source,
        };
        let (socket, claim, routed) = {
            let state = self.state.lock().expect("native core UDP sessions mutex");
            let identity = state.entries.get(&key)?.identities.get(&association)?;
            let IdentityState::Ready { socket, claim } = &identity.state else {
                return None;
            };
            (
                socket.clone(),
                claim.clone(),
                identity.route.outbound.clone(),
            )
        };
        if !socket.accepts_sends() || socket.pump_io.get().is_none() {
            return None;
        }
        let wire = match &claim {
            None => Some(destination),
            Some(claim) => claim
                .wire_ip()
                .map(|ip| SocketAddr::new(ip, destination.port())),
        };
        let to = match wire {
            Some(remote) => {
                if matches!(remote.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
                    || socket.direct && runtime.egress().refuses_destination(remote.ip())
                {
                    return None;
                }
                PumpTo::Addr(remote)
            }
            // A name the proxy resolves goes to it as the full path sends it.
            None if !socket.direct => PumpTo::Name(claim?.wire_name(destination.port())?),
            None => return None,
        };
        // A route through a policy group holds while the group resolves to
        // this socket's outbound; it is checked again when the group's state
        // changes or an ejection the answer stepped around runs out.
        let groups = runtime.group_state();
        let version = groups.version();
        let (resolved, until) = runtime.resolve_outbound_until(&routed, &logical)?;
        if resolved.name != socket.outbound {
            return None;
        }
        let group = (resolved.name != routed).then(|| (groups.clone(), version, until));
        Some(PumpUdpSend {
            socket: Arc::downgrade(&socket),
            to,
            direct: socket.direct,
            group,
        })
    }

    /// Who a session socket of the flow `flow_id` belongs to, reporting to
    /// this table: the pump of capture queue `pump_queue` for a captured flow,
    /// or the table's own consumers.
    pub(super) fn socket_owner(
        &self,
        key: &UdpSessionKey,
        flow_id: Option<String>,
        pump_queue: Option<usize>,
    ) -> SocketOwner {
        let hub = match pump_queue {
            Some(queue) => self.pump_hub(queue),
            None => self.face_hub(&key.user),
        };
        SocketOwner {
            hub,
            key: key.clone(),
            flow_id,
            pump_owned: pump_queue.is_some(),
        }
    }

    pub(crate) fn record_send_drop(&self) {
        self.record_send_drops(1);
    }

    /// Datagrams lost at the send: a socket buffer with no room, a mailbox
    /// with no room, a train the transport took only part of, or what waited
    /// for a name that never resolved.
    pub(crate) fn record_send_drops(&self, count: usize) {
        if count > 0 {
            self.send_drops.fetch_add(count as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn send_drops(&self) -> u64 {
        self.send_drops.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn admission_epoch(&self) -> Option<u64> {
        let state = self.state.lock().expect("native core UDP sessions mutex");
        state.accepting.then_some(state.admission_epoch)
    }

    pub(crate) fn record_dns_answer_failure(&self) {
        self.dns_answer_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn transport_diagnostics(&self) -> UdpTransportDiagnostics {
        self.transport_diagnostics.snapshot()
    }

    pub(crate) fn dns_answer_failures(&self) -> u64 {
        self.dns_answer_failures.load(Ordering::Relaxed)
    }

    pub(crate) fn session_socket_count(&self) -> usize {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .values()
            .map(|entry| entry.sockets.len() + entry.retired_sockets.len())
            .sum()
    }

    #[cfg(test)]
    pub(super) fn set_activity_for_test(
        &self,
        key: &UdpSessionKey,
        created_at_unix: i64,
        updated_at_unix: i64,
        packets_received: u64,
    ) {
        let mut state = self.state.lock().expect("native core UDP sessions mutex");
        let stats = &mut state.entries.get_mut(key).expect("a UDP session").stats;
        stats.created_at_unix = created_at_unix;
        stats.updated_at_unix = updated_at_unix;
        stats.packets_received = packets_received;
    }

    #[cfg(test)]
    pub(super) fn insert_for_test(&self, session: NativeUdpSession) {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .insert(session.key.clone(), UdpSessionEntry::new(session));
    }

    /// Connection-table view of live UDP sessions (stats entries).
    pub(crate) fn sessions_snapshot(&self) -> Vec<NativeUdpSession> {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .values()
            .map(|entry| {
                let mut stats = entry.current_stats();
                stats.egress_interface = entry
                    .sockets
                    .values()
                    .find_map(|socket| socket.egress_interface());
                stats
            })
            .collect()
    }

    /// Datagrams the packet pump sent itself on the live sockets.
    #[cfg(test)]
    pub(crate) fn pump_sent_for_test(&self) -> u64 {
        self.state
            .lock()
            .expect("native core UDP sessions mutex")
            .entries
            .values()
            .flat_map(|entry| entry.sockets.values().chain(entry.retired_sockets.iter()))
            .map(|socket| socket.pump_sent.packets.load(Ordering::Relaxed))
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> Vec<NativeUdpSession> {
        self.sessions_snapshot()
    }

    #[cfg(test)]
    pub(crate) fn session_for_flow(&self, flow_id: &str) -> Option<NativeUdpSession> {
        self.sessions_snapshot()
            .into_iter()
            .find(|session| session.flow_id.as_deref() == Some(flow_id))
    }

    #[cfg(test)]
    pub(crate) fn session_socket_count_for_test(&self) -> usize {
        self.session_socket_count()
    }
}

/// Called after the session-table lock is released.
fn close_session_sockets(sockets: Vec<SessionUdpSocket>) {
    for socket in sockets {
        socket.abort();
    }
}

pub(crate) fn reopen_udp_sessions(runtime: &NativeCoreRuntime) {
    runtime.udp_sessions().reopen();
}

pub(crate) fn close_udp_sessions(runtime: &NativeCoreRuntime) -> usize {
    runtime.udp_sessions().close()
}

#[cfg(test)]
pub(crate) fn close_udp_flow_sessions(
    runtime: &NativeCoreRuntime,
    flow_id: &str,
) -> Result<usize, String> {
    let flow_id = flow_id.trim();
    if flow_id.is_empty() {
        return Err("UDP flow id is required to close flow sessions".into());
    }
    Ok(runtime.udp_sessions().close_flow(flow_id))
}

pub(crate) fn sweep_idle_udp_sessions(runtime: &NativeCoreRuntime) -> usize {
    runtime.udp_sessions().sweep_idle(now_unix())
}
