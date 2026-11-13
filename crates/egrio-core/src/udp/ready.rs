//! The ready hub: the session sockets that have responses waiting, which is
//! what a drain visits, and the notify the drains park on.

use super::*;

/// The session sockets that have responses waiting, and the notify the drains
/// park on. A drain visits these sockets instead of every session, so its
/// cost follows the replies waiting rather than the sessions open.
#[derive(Clone, Default)]
pub(super) struct ReadyHub {
    pub(super) sockets: Arc<Mutex<VecDeque<Weak<UdpSessionSocket>>>>,
    pub(super) notify: Arc<Notify>,
}

/// One session socket's place on the [`ReadyHub`].
pub(crate) struct ReadySignal {
    /// Set while the socket is on the ready list, so it is listed once.
    pub(super) queued: AtomicBool,
    /// Set once the socket's actor ended or was aborted: the socket then
    /// stays listed until a drain finds it drained and releases it.
    pub(super) ended: AtomicBool,
    pub(super) hub: ReadyHub,
    pub(super) socket: Weak<UdpSessionSocket>,
}

impl ReadySignal {
    /// A signal tied to no socket or table, for actors under test.
    #[cfg(test)]
    pub(crate) fn detached() -> Arc<Self> {
        Arc::new(Self {
            queued: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            hub: ReadyHub::default(),
            socket: Weak::new(),
        })
    }

    /// Lists the socket for the drains unless it is listed already. Its
    /// actor raises after every response it queues and once more when it
    /// ends, so a finished socket is visited and released.
    pub(crate) fn raise(&self) {
        if self.list() {
            // Several consumers (the packet pump, datagram faces) share this
            // notify and each drains only its own flows: wake every
            // registered waiter, and leave one permit for a consumer that
            // registers after.
            self.hub.notify.notify_waiters();
            self.hub.notify.notify_one();
        }
    }

    /// Marks the actor ended and lists the socket for release.
    pub(crate) fn end(&self) {
        self.ended.store(true, Ordering::Release);
        self.raise();
    }

    /// Lists the socket without waking anyone; whether it was not listed yet.
    pub(super) fn list(&self) -> bool {
        if self.queued.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.hub
            .sockets
            .lock()
            .expect("UDP ready list mutex")
            .push_back(self.socket.clone());
        true
    }
}
