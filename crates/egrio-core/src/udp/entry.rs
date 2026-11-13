//! One session of the table: the target identities its client addressed,
//! the transports they share or own, and when the session may give way.

use super::*;

/// Where a session keeps a transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SocketKey {
    /// The transport every identity of the session routed to this outbound
    /// shares.
    Shared(String),
    /// One identity's own: a name the proxy resolves, or a name that
    /// resolved to an address another identity on the shared transport
    /// claims (see [`ReplyTable`]).
    Own(AssociationKey),
}

/// One target identity of a session ([`AssociationKey`]): its route, pinned
/// while it lives, and where its datagrams go.
pub(super) struct Identity {
    pub(super) route: crate::rule_engine::RouteDecision,
    /// The concrete outbound the route resolved to.
    pub(super) outbound: String,
    pub(super) state: IdentityState,
}

pub(super) enum IdentityState {
    /// A fake IP whose name resolves before it joins a transport, so that
    /// the transport knows which replies are its; its datagrams wait here.
    Preparing(Preparation),
    Ready {
        socket: SessionUdpSocket,
        /// A fake IP's binding; `None` for the real identity.
        claim: Option<Arc<Claim>>,
    },
}

pub(super) struct Preparation {
    /// Tells this preparation from a later one of the same identity.
    pub(super) id: u64,
    /// The datagrams sent meanwhile, in order: each one's target and payload.
    pub(super) pending: VecDeque<(ConnectTarget, Vec<u8>)>,
    /// Their bytes, so the queue is bounded in both.
    pub(super) pending_bytes: usize,
    /// The association slot it holds until it joins a transport, which it
    /// hands to a transport it opens.
    pub(super) slot: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) task: Option<JoinHandle<()>>,
}

impl Drop for Preparation {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Identity {
    /// Whether its datagrams still have somewhere to go.
    fn is_live(&self) -> bool {
        match &self.state {
            IdentityState::Preparing(_) => true,
            IdentityState::Ready { socket, .. } => socket.accepts_sends(),
        }
    }

    pub(super) fn uses(&self, socket: &SessionUdpSocket) -> bool {
        matches!(&self.state, IdentityState::Ready { socket: current, .. } if Arc::ptr_eq(current, socket))
    }
}

/// What admission saw of an identity before it routed outside the table's
/// lock.
pub(super) enum Observed {
    Absent,
    Ready(SessionUdpSocket),
    Preparing(u64),
}

impl Observed {
    pub(super) fn of<'a>(
        entry: Option<&'a UdpSessionEntry>,
        key: &AssociationKey,
    ) -> (Self, Option<&'a Identity>) {
        match entry.and_then(|entry| entry.identities.get(key)) {
            Some(identity) => match &identity.state {
                IdentityState::Ready { socket, .. } if socket.accepts_sends() => {
                    (Self::Ready(Arc::clone(socket)), Some(identity))
                }
                IdentityState::Ready { .. } => (Self::Absent, None),
                IdentityState::Preparing(preparation) => {
                    (Self::Preparing(preparation.id), Some(identity))
                }
            },
            None => (Self::Absent, None),
        }
    }

    pub(super) fn is(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) => true,
            (Self::Ready(observed), Self::Ready(current)) => Arc::ptr_eq(observed, current),
            (Self::Preparing(observed), Self::Preparing(current)) => observed == current,
            _ => false,
        }
    }
}

pub(super) static NEXT_PREPARATION: AtomicU64 = AtomicU64::new(0);

pub(super) struct UdpSessionEntry {
    /// The target identities the client addressed.
    pub(super) identities: HashMap<AssociationKey, Identity>,
    /// Its live transports.
    pub(super) sockets: HashMap<SocketKey, SessionUdpSocket>,
    pub(super) retired_sockets: std::collections::VecDeque<SessionUdpSocket>,
    pub(super) stats: NativeUdpSession,
    /// The datagrams the session had sent when its latest reply was
    /// recorded: one sent since waits for an answer of its own.
    pub(super) sent_when_answered: u64,
}

impl UdpSessionEntry {
    pub(super) fn new(stats: NativeUdpSession) -> Self {
        Self {
            identities: HashMap::new(),
            sockets: HashMap::new(),
            retired_sockets: std::collections::VecDeque::new(),
            stats,
            sent_when_answered: 0,
        }
    }

    pub(super) fn prune_drained(&mut self) {
        let Self {
            identities,
            sockets,
            retired_sockets,
            stats,
            ..
        } = self;
        let mut keep = |socket: &SessionUdpSocket| {
            let drained = socket.is_drained();
            if drained {
                socket.pump_sent.fold_into(stats);
            }
            !drained
        };
        sockets.retain(|_, socket| keep(socket));
        retired_sockets.retain(|socket| keep(socket));
        identities.retain(|_, identity| identity.is_live());
    }

    /// Puts `socket` at `key`, retiring the one it replaces so that the
    /// replies queued there still drain.
    pub(super) fn install(&mut self, key: SocketKey, socket: SessionUdpSocket) {
        if let Some(previous) = self.sockets.insert(key, socket) {
            previous.retire();
            self.retired_sockets.push_back(previous);
        }
    }

    /// Takes away an identity that no longer sends where it did, and its
    /// transport with it when no other identity uses that.
    pub(super) fn release_identity(&mut self, key: &AssociationKey, identity: Identity) {
        let IdentityState::Ready { socket, .. } = identity.state else {
            return;
        };
        // Its claim on the transport's replies goes with it, whether or not
        // the transport itself stays.
        socket.replies.remove(key);
        if self.identities.values().any(|other| other.uses(&socket)) {
            return;
        }
        let Some(key) = self
            .sockets
            .iter()
            .find_map(|(key, current)| Arc::ptr_eq(current, &socket).then(|| key.clone()))
        else {
            return;
        };
        let released = self.sockets.remove(&key).expect("current socket exists");
        if self.retired_sockets.len() < UDP_RETIRED_SOCKET_MAX {
            released.retire();
            self.retired_sockets.push_back(released);
        } else {
            released.abort();
        }
    }

    /// Hands back at once the association slots its preparing identities
    /// hold, for a table that reclaims the session.
    pub(super) fn reclaim_preparations(&mut self) {
        for identity in self.identities.values_mut() {
            if let IdentityState::Preparing(preparation) = &mut identity.state {
                preparation.slot.take();
                if let Some(task) = preparation.task.take() {
                    task.abort();
                }
            }
        }
    }

    /// Whether a transport, or a name on its way to one, still takes its
    /// datagrams.
    fn has_live_transport(&self) -> bool {
        self.sockets.values().any(|socket| socket.accepts_sends())
            || self
                .identities
                .values()
                .any(|identity| matches!(identity.state, IdentityState::Preparing(_)))
    }

    /// The session's statistics with what the pump sent on its sockets.
    pub(super) fn current_stats(&self) -> NativeUdpSession {
        let mut stats = self.stats.clone();
        for socket in self.sockets.values().chain(self.retired_sockets.iter()) {
            socket.pump_sent.add_to(&mut stats);
        }
        stats
    }

    pub(super) fn last_active_unix(&self) -> i64 {
        self.sockets
            .values()
            .chain(self.retired_sockets.iter())
            .map(|socket| socket.pump_sent.at_unix.load(Ordering::Relaxed))
            .fold(self.stats.updated_at_unix, i64::max)
    }

    /// Every datagram the session sent, the pump's included.
    pub(super) fn packets_sent(&self) -> u64 {
        self.sockets
            .values()
            .chain(self.retired_sockets.iter())
            .map(|socket| socket.pump_sent.packets.load(Ordering::Relaxed))
            .fold(self.stats.packets_sent, u64::saturating_add)
    }

    /// Whether a full table may take this session's place: none of its
    /// sockets takes datagrams any more, or it has only a name on its way to
    /// a transport and nothing has come back, or its traffic ended within
    /// `UDP_EXCHANGE_SECONDS` of its start and its latest datagram was
    /// answered or has waited that long since. A client that sends again
    /// from the same port (a new exchange on a reused source port) keeps the
    /// session until that datagram is answered. Streams keep their place
    /// until they idle out, and so does a session with replies waiting for a
    /// drain.
    pub(super) fn reclaimable(&self, now: i64) -> bool {
        if self
            .sockets
            .values()
            .chain(self.retired_sockets.iter())
            .any(|socket| socket.holds_replies())
        {
            return false;
        }
        if !self.has_live_transport() {
            return true;
        }
        // Only a name on its way to a transport is live here, nothing has
        // come back, and the preparation has outlasted a working one: the
        // session has established nothing, so under a full table it yields
        // to the admission asking for its place.
        if self.stats.packets_received == 0
            && !self.sockets.values().any(|socket| socket.accepts_sends())
            && now - self.stats.created_at_unix >= UDP_PREPARING_YIELD_SECONDS
        {
            return true;
        }
        let last = self.last_active_unix();
        let answered =
            self.stats.packets_received > 0 && self.packets_sent() <= self.sent_when_answered;
        last - self.stats.created_at_unix < UDP_EXCHANGE_SECONDS
            && (answered || now - last >= UDP_EXCHANGE_SECONDS)
    }

    pub(super) fn take_sockets(&mut self, sockets: &mut Vec<SessionUdpSocket>) {
        sockets.extend(self.sockets.drain().map(|(_, socket)| socket));
        sockets.extend(self.retired_sockets.drain(..));
    }

    pub(super) fn owns_socket(&self, socket: &SessionUdpSocket) -> bool {
        self.sockets
            .values()
            .any(|current| Arc::ptr_eq(current, socket))
            || self
                .retired_sockets
                .iter()
                .any(|retired| Arc::ptr_eq(retired, socket))
    }
}
