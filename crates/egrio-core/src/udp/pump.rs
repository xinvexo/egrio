//! What a packet pump sends for itself: an established captured flow's
//! datagrams go out on its association's transport without routing, the
//! session table's lock or the session actor.

use super::*;

/// Wakes the drains when a socket the packet pump reads has datagrams: the
/// socket's readiness lists it on the ready hub like a queued response.
pub(crate) struct PumpWake(pub(crate) Arc<ReadySignal>);

impl Wake for PumpWake {
    fn wake(self: Arc<Self>) {
        self.0.raise();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.raise();
    }
}

/// Datagrams the packet pump sent itself, outside the session table's lock;
/// folded into the session's statistics when they are read.
#[derive(Default)]
pub(super) struct PumpSent {
    pub(super) packets: AtomicU64,
    bytes: AtomicU64,
    /// Unix seconds of the latest one.
    pub(super) at_unix: AtomicI64,
}

impl PumpSent {
    fn record(&self, packets: u64, bytes: usize, now: i64) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.at_unix.fetch_max(now, Ordering::Relaxed);
    }

    /// Adds what was counted here to `stats` and starts over.
    pub(super) fn fold_into(&self, stats: &mut NativeUdpSession) {
        stats.packets_sent += self.packets.swap(0, Ordering::Relaxed);
        stats.bytes_sent += self.bytes.swap(0, Ordering::Relaxed);
        stats.updated_at_unix = stats
            .updated_at_unix
            .max(self.at_unix.load(Ordering::Relaxed));
    }

    pub(super) fn add_to(&self, stats: &mut NativeUdpSession) {
        stats.packets_sent += self.packets.load(Ordering::Relaxed);
        stats.bytes_sent += self.bytes.load(Ordering::Relaxed);
        stats.updated_at_unix = stats
            .updated_at_unix
            .max(self.at_unix.load(Ordering::Relaxed));
    }
}

/// A captured flow's datagrams to one destination, which the packet pump
/// sends on its association's transport without the session actor.
pub(crate) struct PumpUdpSend {
    pub(super) socket: Weak<UdpSessionSocket>,
    pub(super) to: PumpTo,
    /// Whether the association is DIRECT rather than through a proxy.
    pub(super) direct: bool,
    /// For a route through a policy group: the group state version it was
    /// resolved at and the unix second until which that answer stands (the
    /// earliest ejection it stepped around runs out then). The group may
    /// choose another member once the version moves or that second comes,
    /// which the full send path follows.
    pub(super) group: Option<(crate::policy_group::GroupStateTable, u64, i64)>,
}

pub(crate) enum PumpSend {
    Sent,
    /// Lost like any UDP datagram: the socket's buffer was full or the send
    /// failed.
    Dropped,
    /// The association is gone or no longer takes datagrams: route anew.
    Stale,
}

impl PumpUdpSend {
    /// Whether the flow's association is DIRECT rather than through a proxy.
    pub(crate) fn is_direct(&self) -> bool {
        self.direct
    }

    pub(crate) fn send(&self, table: &UdpSessionTable, payload: &[u8]) -> PumpSend {
        self.send_with(table, 1, |datagrams, to| {
            datagrams.try_send(to, payload).map(|()| (1, payload.len()))
        })
    }

    /// Sends a train of datagrams: `segment` payload bytes each, the last one
    /// fewer.
    pub(crate) fn send_train(
        &self,
        table: &UdpSessionTable,
        payload: &[u8],
        segment: usize,
    ) -> PumpSend {
        self.send_with(
            table,
            payload.len().div_ceil(segment.max(1)),
            |datagrams, to| {
                datagrams
                    .try_send_train(to, payload, segment)
                    .map(|sent| (sent, payload.len().min(sent * segment)))
            },
        )
    }

    /// Sends through the association's transport while the flow may still
    /// use it; `send` reports the datagrams and bytes it sent, of the
    /// `offered` it was given.
    fn send_with(
        &self,
        table: &UdpSessionTable,
        offered: usize,
        send: impl FnOnce(&dyn PumpDatagrams, &PumpTo) -> std::io::Result<(usize, usize)>,
    ) -> PumpSend {
        let Some(socket) = self.socket.upgrade() else {
            return PumpSend::Stale;
        };
        if !socket.accepts_sends() {
            return PumpSend::Stale;
        }
        let now = now_unix();
        if self
            .group
            .as_ref()
            .is_some_and(|(groups, version, until)| groups.version() != *version || now >= *until)
        {
            return PumpSend::Stale;
        }
        let Some(datagrams) = socket.pump_io.get() else {
            return PumpSend::Stale;
        };
        match send(datagrams.as_ref(), &self.to) {
            Ok((packets, bytes)) => {
                socket.pump_sent.record(packets as u64, bytes, now);
                table.volume.add_upload(bytes as u64);
                // A train the transport took only part of: what it left is
                // lost like the datagram a full socket buffer refuses, and
                // counted the same way.
                table.record_send_drops(offered.saturating_sub(packets));
                PumpSend::Sent
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                table.record_send_drop();
                PumpSend::Dropped
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => PumpSend::Stale,
            Err(error) => {
                table.transport_diagnostics.record_packet_error(
                    &socket.outbound,
                    UdpTransportStage::Send,
                    DatagramError::NativeSocket(error),
                );
                PumpSend::Dropped
            }
        }
    }
}
