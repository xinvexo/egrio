//! Session registry: the shadow ledger of live TCP relay
//! sessions.
//!
//! Ownership stays with the session tasks — the registry never owns sockets
//! or buffers. Each task-owned relay registers on entry and holds a
//! [`SessionGuard`]; the guard's `Drop` is the only deregistration path, so
//! "connection leak" and "registry entry leak" are the same observable and
//! the churn gate can assert both at once. Cancellation is a tree:
//! the registry root token (cancelled on device close) parents every
//! session token, and `kill_by_outbound` cancels the per-session tokens the
//! kill-switch selects.
//!
//! UDP flow sessions and packet-bridge TCP sessions keep their existing
//! specialized tables (they are table-owned, not task-owned); the device
//! merges all ledgers at the read surface.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::telemetry::TrafficVolumeCounter;

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::egress::{EgressBinding, NetworkChange};
use crate::policy_group::now_unix;
use crate::runtime::EpochMembership;
use crate::ConnectionTermination;

/// Global admission cap on concurrently registered relay sessions. Above it
/// new sessions are refused fail-fast (with a counter and an error the
/// inbound answers with), so a pathological local app cannot grow core state
/// without bound. The local listener additionally holds its own
/// transport-level semaphore in front of the handshake.
pub(crate) const MAX_ACTIVE_SESSIONS: usize = 4096;

/// A session is stalled, for diagnostics, once it has sat in a
/// pre-Established phase — or in Established without a single downstream
/// byte, the black-hole signature the relay budgets reap — for this long.
/// Deliberately far under every budget so the attribution window opens
/// well before a reap or timeout clears the evidence.
pub(crate) const STALLED_SESSION_THRESHOLD_SECONDS: i64 = 10;

/// Lifecycle phase. `Enriching` covers the sniff wait
/// so a session stalled on its first-data budget is attributable at a
/// glance; `HalfClosed` is not observable through `copy_bidirectional` and
/// is deferred until the relay loop owns direction shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionPhase {
    Accepted,
    Enriching,
    Routing,
    Dialing,
    Established,
}

/// One live session as seen by the ledger; field names line up with
/// `TrafficConnectionSnapshot` so the UI connection table is a projection.
///
/// The strings are the ledger's own, shared rather than copied: a host's
/// poll of the whole table is then a walk of pointers under the ledger lock
/// -- which every admission and teardown also takes -- and the connection
/// table's rows carry the same strings on (`TrafficConnectionSnapshot`).
/// The snapshot walks the table under one lock so each row belongs to the
/// same ledger view; sharing strings avoids allocating copies in that lock.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub id: u64,
    pub inbound: &'static str,
    /// Authenticated peer identity on multi-user inbounds;
    /// `None` on local capture inbounds.
    pub user: Option<Arc<str>>,
    pub process_name: Option<Arc<str>>,
    pub process_path: Option<Arc<str>>,
    pub source: Option<Arc<str>>,
    pub target: Arc<str>,
    /// Domain the routing decision actually used when the raw target was an
    /// IP: a fake-IP reverse hit or a sniffed SNI/Host.
    pub host: Option<Arc<str>>,
    pub outbound: Option<Arc<str>>,
    pub matched_rule: Option<Arc<str>>,
    /// Physical egress interface index the dial bound to (Windows
    /// `IP_UNICAST_IF`); `None` until the dial funnel stamps it, or when no
    /// guard bound one.
    pub egress_interface: Option<u32>,
    pub phase: SessionPhase,
    pub phase_since_unix: i64,
    pub created_at_unix: i64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SessionRegistryCounters {
    pub active: u64,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub killed_total: u64,
    /// Sessions the established-phase budgets reaped (first-upstream-byte
    /// or idle, see `relay.rs`) — kept apart from `killed_total`, which
    /// counts control-plane kills (kill switch, connection cutover).
    pub reaped_total: u64,
    /// Live sessions bucketed by lifecycle phase, from the same locked pass
    /// as `active`: a Dialing pile-up or an Established black-hole cohort
    /// is readable from any host that prints the audit, without cloning
    /// the ledger.
    pub phases: SessionPhaseCounts,
}

/// Per-phase population of the live ledger, in lifecycle order.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct SessionPhaseCounts {
    pub accepted: u64,
    pub enriching: u64,
    pub routing: u64,
    pub dialing: u64,
    pub established: u64,
}

impl SessionPhaseCounts {
    fn record(&mut self, phase: SessionPhase) {
        match phase {
            SessionPhase::Accepted => self.accepted += 1,
            SessionPhase::Enriching => self.enriching += 1,
            SessionPhase::Routing => self.routing += 1,
            SessionPhase::Dialing => self.dialing += 1,
            SessionPhase::Established => self.established += 1,
        }
    }
}

#[derive(Debug)]
struct SessionEntry {
    inbound: &'static str,
    /// Authenticated peer identity the acceptor's handshake proved; one
    /// `Arc<str>` per session, shared with UDP flow keys rather than copied.
    user: Option<Arc<str>>,
    process_name: Option<Arc<str>>,
    process_path: Option<Arc<str>>,
    source: Option<Arc<str>>,
    target: Arc<str>,
    host: Option<Arc<str>>,
    outbound: Option<Arc<str>>,
    matched_rule: Option<Arc<str>>,
    /// What the routing decision saw, once it has been made.
    question: Option<Box<RouteQuestion>>,
    /// Where the dial's physical socket left the host, stamped by the dial
    /// funnel after the connector returns (empty until then).
    egress: EgressBinding,
    phase: SessionPhase,
    phase_since_unix: i64,
    created_at_unix: i64,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    cancel: CancellationToken,
    termination: Option<ConnectionTermination>,
    /// The session's place in the route epoch that admitted it, the same one
    /// its task holds, and the ledger is where a policy change reaches it.
    /// Only a session admitted outside a Core -- the ledger's own tests --
    /// has none.
    epoch: Option<Arc<EpochMembership>>,
}

/// The question a live session was routed by. A policy change asks it again
/// and resolves the answer through the groups: a session the new policy
/// sends to the same outbound keeps running, and the rest end as the kill
/// switch ends them.
///
/// Asking it again needs no resolver and no second decision of any kind: a
/// policy update leaves the rules themselves alone -- changing them is a
/// profile reload, which ends every session -- so the same input and the
/// same address reach the same rule, and only what that rule's outbound
/// resolves to can have moved.
#[derive(Debug, Clone)]
pub(crate) struct RouteQuestion {
    pub(crate) input: crate::RouteMatchInput,
    /// What the name resolved to for the IP rules that asked, exactly as the
    /// decision was given it.
    pub(crate) address: Option<crate::rule_engine::RuleAddress>,
    /// Where the dial went, which resolving a group reads.
    pub(crate) dial_target: crate::target::ConnectTarget,
}

/// Cap of the finished-session history ring. Fixed-size by construction, so
/// it is deliberately not part of the bounded-state audit (whose tables must
/// drain to zero); it exists so sub-poll-interval sessions still reach the
/// UI connection history instead of vanishing between two snapshots.
const FINISHED_SESSION_HISTORY: usize = 512;

/// Terminal record of one deregistered session: the last ledger projection
/// plus when and how it ended.
#[derive(Debug, Clone)]
pub struct FinishedSession {
    /// Increases by one per terminal record, so a poller can ask for only
    /// the records it has not seen.
    pub seq: u64,
    pub snapshot: SessionSnapshot,
    pub termination: ConnectionTermination,
    pub closed_at_unix: i64,
}

#[derive(Debug)]
struct RegistryInner {
    /// Parent of every session token; cancelled once on close so the whole
    /// session population unwinds without per-session bookkeeping.
    root: CancellationToken,
    capacity: usize,
    closed: AtomicBool,
    next_id: AtomicU64,
    /// Bounded by `capacity` via admission control; entries leave only
    /// through guard drop, which is what makes the registry a leak detector.
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    /// Ring of the most recent terminal records (see
    /// [`FINISHED_SESSION_HISTORY`]); pushed on deregistration, read by the
    /// connection-history projection.
    finished: Mutex<VecDeque<FinishedSession>>,
    /// The sequence number of the newest terminal record; changes only
    /// under the `finished` mutex.
    finished_seq: AtomicU64,
    accepted_total: AtomicU64,
    completed_total: AtomicU64,
    failed_total: AtomicU64,
    rejected_total: AtomicU64,
    killed_total: AtomicU64,
    reaped_total: AtomicU64,
    /// The device's traffic volume every session's relay also counts into.
    volume: Arc<TrafficVolumeCounter>,
}

/// Cloning shares the ledger (like the other durable session tables).
#[derive(Debug, Clone)]
pub(crate) struct SessionRegistry {
    inner: Arc<RegistryInner>,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::counting_into(Arc::default())
    }
}

impl SessionRegistry {
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    /// A registry whose sessions' relays also count into `volume`.
    pub(crate) fn counting_into(volume: Arc<TrafficVolumeCounter>) -> Self {
        Self::with_capacity_counting_into(MAX_ACTIVE_SESSIONS, volume)
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_counting_into(capacity, Arc::default())
    }

    fn with_capacity_counting_into(capacity: usize, volume: Arc<TrafficVolumeCounter>) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                root: CancellationToken::new(),
                capacity,
                closed: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                sessions: Mutex::new(HashMap::new()),
                finished: Mutex::new(VecDeque::new()),
                finished_seq: AtomicU64::new(0),
                accepted_total: AtomicU64::new(0),
                completed_total: AtomicU64::new(0),
                failed_total: AtomicU64::new(0),
                rejected_total: AtomicU64::new(0),
                killed_total: AtomicU64::new(0),
                reaped_total: AtomicU64::new(0),
                volume,
            }),
        }
    }

    /// Admits and records a new session, or refuses it fail-fast when the
    /// registry is at capacity or the core is closing. The returned guard is
    /// the session's registration: dropping it deregisters.
    pub(crate) fn admit(
        &self,
        inbound: &'static str,
        source: Option<String>,
        target: String,
        epoch: Option<Arc<EpochMembership>>,
    ) -> Result<SessionGuard, String> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err("native core is closed — refusing new session".into());
        }
        let now = now_unix();
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let cancel = self.inner.root.child_token();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut sessions = self.inner.sessions.lock().expect("session registry mutex");
            if sessions.len() >= self.inner.capacity {
                drop(sessions);
                self.inner.rejected_total.fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "native core session limit {} reached — refusing new session",
                    self.inner.capacity
                ));
            }
            sessions.insert(
                id,
                SessionEntry {
                    inbound,
                    user: None,
                    process_name: None,
                    process_path: None,
                    source: source.map(Arc::from),
                    target: Arc::from(target),
                    host: None,
                    outbound: None,
                    matched_rule: None,
                    question: None,
                    egress: EgressBinding::default(),
                    phase: SessionPhase::Accepted,
                    phase_since_unix: now,
                    created_at_unix: now,
                    bytes_up: Arc::clone(&bytes_up),
                    bytes_down: Arc::clone(&bytes_down),
                    cancel: cancel.clone(),
                    termination: None,
                    epoch,
                },
            );
        }
        self.inner.accepted_total.fetch_add(1, Ordering::Relaxed);

        Ok(SessionGuard {
            registry: self.clone(),
            id,
            cancel,
            bytes_up,
            bytes_down,
        })
    }

    /// Kill switch: cancels every live session relaying through `outbound`
    /// (the concrete node name recorded at dial time). The owning tasks
    /// unwind and their guards deregister; the count is how many were
    /// signalled.
    /// [`Self::admit`] for the ledger tests and benches, which have no route
    /// epoch to put the session in.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn register(
        &self,
        inbound: &'static str,
        source: Option<String>,
        target: String,
    ) -> Result<SessionGuard, String> {
        self.admit(inbound, source, target, None)
    }

    pub(crate) fn kill_by_outbound(&self, outbound: &str) -> usize {
        let sessions = self.inner.sessions.lock().expect("session registry mutex");
        let mut killed = 0;
        for entry in sessions.values() {
            if entry.outbound.as_deref() == Some(outbound) {
                entry.cancel.cancel();
                killed += 1;
            }
        }
        drop(sessions);
        self.inner
            .killed_total
            .fetch_add(killed as u64, Ordering::Relaxed);
        killed
    }

    /// Network change: cancels every live session whose physical egress the
    /// change took away (see [`NetworkChange::strands`]).
    pub(crate) fn kill_stranded(&self, change: &NetworkChange) -> usize {
        let sessions = self.inner.sessions.lock().expect("session registry mutex");
        let mut killed = 0;
        for entry in sessions.values() {
            if !entry.cancel.is_cancelled() && change.strands(&entry.egress) {
                entry.cancel.cancel();
                killed += 1;
            }
        }
        drop(sessions);
        self.inner
            .killed_total
            .fetch_add(killed as u64, Ordering::Relaxed);
        killed
    }

    /// A policy change: ends every live session the new policy would route
    /// somewhere else and gives the rest their place in `epoch`, the route
    /// epoch that policy opened. A session that has not routed yet belongs
    /// to the epoch being left, which cancels it.
    pub(crate) fn reroute(
        &self,
        keeps_route: &dyn Fn(&RouteQuestion, &str) -> bool,
        epoch: &tokio_util::task::TaskTracker,
    ) -> usize {
        let sessions = self.inner.sessions.lock().expect("session registry mutex");
        let mut ended = 0;
        for entry in sessions.values() {
            let kept = match (&entry.question, &entry.outbound) {
                (Some(question), Some(outbound)) => keeps_route(question, outbound),
                _ => false,
            };
            if kept {
                if let Some(epoch_membership) = &entry.epoch {
                    epoch_membership.move_to(epoch);
                }
            } else if !entry.cancel.is_cancelled() {
                entry.cancel.cancel();
                ended += 1;
            }
        }
        drop(sessions);
        self.inner
            .killed_total
            .fetch_add(ended as u64, Ordering::Relaxed);
        ended
    }

    pub(crate) fn kill_all(&self) -> usize {
        let sessions = self.inner.sessions.lock().expect("session registry mutex");
        let mut killed = 0;
        for entry in sessions.values() {
            if !entry.cancel.is_cancelled() {
                entry.cancel.cancel();
                killed += 1;
            }
        }
        self.inner
            .killed_total
            .fetch_add(killed as u64, Ordering::Relaxed);
        killed
    }

    /// Device shutdown: refuse new registrations and cancel the root token,
    /// which cancels every session token in the tree. Returns how many live
    /// sessions were signalled.
    pub(crate) fn close(&self) -> usize {
        self.inner.closed.store(true, Ordering::Relaxed);
        let live = self
            .inner
            .sessions
            .lock()
            .expect("session registry mutex")
            .len();
        self.inner.root.cancel();
        live
    }

    pub(crate) fn counters(&self) -> SessionRegistryCounters {
        let (active, phases) = {
            let sessions = self.inner.sessions.lock().expect("session registry mutex");
            let mut phases = SessionPhaseCounts::default();
            for entry in sessions.values() {
                phases.record(entry.phase);
            }
            (sessions.len() as u64, phases)
        };
        SessionRegistryCounters {
            active,
            accepted_total: self.inner.accepted_total.load(Ordering::Relaxed),
            rejected_total: self.inner.rejected_total.load(Ordering::Relaxed),
            killed_total: self.inner.killed_total.load(Ordering::Relaxed),
            reaped_total: self.inner.reaped_total.load(Ordering::Relaxed),
            phases,
        }
    }

    /// Connection-table view; the age distribution (`created_at_unix`,
    /// `phase_since_unix`) doubles as the leak detector for soak audits.
    pub(crate) fn snapshot(&self) -> Vec<SessionSnapshot> {
        let mut snapshots: Vec<SessionSnapshot> = {
            let sessions = self.inner.sessions.lock().expect("session registry mutex");
            sessions
                .iter()
                .map(|(id, entry)| snapshot_entry(*id, entry))
                .collect()
        };
        snapshots.sort_by_key(|snapshot| snapshot.id);
        snapshots
    }

    /// Diagnostic selection over the ledger: up to `limit` stalled sessions
    /// (see [`STALLED_SESSION_THRESHOLD_SECONDS`]), longest-stuck first.
    /// This is the attribution surface for a Dialing pile-up or an
    /// Established black-hole cohort — it names targets and outbounds,
    /// where the phase counters only size the cohort. Healthy traffic
    /// returns an empty Vec, so a periodic logger prints no destinations
    /// in normal operation.
    pub(crate) fn stalled_snapshot(&self, limit: usize, now_unix: i64) -> Vec<SessionSnapshot> {
        let mut stalled: Vec<SessionSnapshot> = {
            let sessions = self.inner.sessions.lock().expect("session registry mutex");
            sessions
                .iter()
                .filter(|(_, entry)| {
                    now_unix.saturating_sub(entry.phase_since_unix)
                        >= STALLED_SESSION_THRESHOLD_SECONDS
                        && (entry.phase != SessionPhase::Established
                            || entry.bytes_down.load(Ordering::Relaxed) == 0)
                })
                .map(|(id, entry)| snapshot_entry(*id, entry))
                .collect()
        };
        stalled.sort_by_key(|snapshot| snapshot.phase_since_unix);
        stalled.truncate(limit);
        stalled
    }

    /// Cumulative observed outcomes, independent of the bounded history ring.
    /// Admission refusal, cancellation, rejection and unknown drops are not
    /// counted as completed work or network failures.
    pub(crate) fn terminal_counts(&self) -> (u64, u64) {
        (
            self.inner.completed_total.load(Ordering::Relaxed),
            self.inner.failed_total.load(Ordering::Relaxed),
        )
    }

    /// Most recent terminal records, oldest first.
    pub(crate) fn finished_snapshot(&self) -> Vec<FinishedSession> {
        self.finished_since(0).0
    }

    /// The terminal records newer than `after`, oldest first, and the
    /// sequence number to ask after next time. Records the ring already
    /// dropped are gone.
    pub(crate) fn finished_since(&self, after: u64) -> (Vec<FinishedSession>, u64) {
        let finished = self
            .inner
            .finished
            .lock()
            .expect("session registry finished mutex");
        let newest = self.inner.finished_seq.load(Ordering::Relaxed);
        let records = finished
            .iter()
            .filter(|record| record.seq > after)
            .cloned()
            .collect();
        (records, newest)
    }

    fn deregister(&self, id: u64) {
        let entry = self
            .inner
            .sessions
            .lock()
            .expect("session registry mutex")
            .remove(&id);
        let Some(mut entry) = entry else {
            return;
        };
        let termination = entry.termination.take().unwrap_or_else(|| {
            if entry.cancel.is_cancelled() {
                ConnectionTermination::Cancelled
            } else {
                ConnectionTermination::Unknown
            }
        });
        match &termination {
            ConnectionTermination::Completed => {
                self.inner.completed_total.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionTermination::Failed { .. } => {
                self.inner.failed_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        let mut finished = self
            .inner
            .finished
            .lock()
            .expect("session registry finished mutex");
        if finished.len() >= FINISHED_SESSION_HISTORY {
            finished.pop_front();
        }
        let seq = self.inner.finished_seq.fetch_add(1, Ordering::Relaxed) + 1;
        finished.push_back(FinishedSession {
            seq,
            snapshot: snapshot_entry(id, &entry),
            termination,
            closed_at_unix: now_unix(),
        });
    }

    fn update_entry(&self, id: u64, update: impl FnOnce(&mut SessionEntry)) {
        let mut sessions = self.inner.sessions.lock().expect("session registry mutex");
        if let Some(entry) = sessions.get_mut(&id) {
            update(entry);
        }
    }
}

/// Fills in one session's process after its routing; see
/// [`SessionGuard::process_slot`].
#[derive(Debug)]
pub(crate) struct SessionProcessSlot {
    registry: SessionRegistry,
    id: u64,
}

impl SessionProcessSlot {
    pub(crate) fn fill(&self, process: &crate::attribution::ProcessInfo) {
        let (name, path) = (
            process.name.as_deref().map(Arc::from),
            process.path.as_deref().map(Arc::from),
        );
        self.registry.update_entry(self.id, |entry| {
            entry.process_name = name;
            entry.process_path = path;
        });
    }
}

/// A session's registration. Owned by the session task; drop = deregister,
/// which keeps "task ended" and "ledger entry gone" the same event.
#[derive(Debug)]
pub(crate) struct SessionGuard {
    registry: SessionRegistry,
    id: u64,
    cancel: CancellationToken,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
}

impl SessionGuard {
    /// The owner records the primary result before any secondary error reply
    /// or cleanup. Later cancellation must not overwrite an observed failure.
    pub(crate) fn record_termination(&self, termination: ConnectionTermination) {
        self.registry.update_entry(self.id, |entry| {
            entry.termination.get_or_insert(termination);
        });
    }

    /// The ledger id, stable for the session's lifetime; diagnostics
    /// (`EGRIO_RELAY_TRACE`) correlate stage lines with connection-table
    /// rows (`tcp-<id>`) through it.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The session's leaf in the cancellation tree; relay loops select on it.
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub(crate) fn set_phase(&self, phase: SessionPhase) {
        self.registry.update_entry(self.id, |entry| {
            entry.phase = phase;
            entry.phase_since_unix = now_unix();
        });
    }

    /// Records the authenticated peer identity the acceptor's handshake
    /// proved.
    pub(crate) fn set_user(&self, user: &Arc<str>) {
        let user = Arc::clone(user);
        self.registry
            .update_entry(self.id, |entry| entry.user = Some(user));
    }

    /// Records the domain the routing decision used for an IP target
    /// (fake-IP reverse hit or sniffed SNI/Host).
    pub(crate) fn set_host(&self, host: &str) {
        let host = Arc::from(host);
        self.registry
            .update_entry(self.id, |entry| entry.host = Some(host));
    }

    /// Where the session's process goes once a lookup the routing did not
    /// wait for answers; a session that ended by then is left alone.
    pub(crate) fn process_slot(&self) -> SessionProcessSlot {
        SessionProcessSlot {
            registry: self.registry.clone(),
            id: self.id,
        }
    }

    /// Records the routing decision: the concrete outbound that will be
    /// dialed (kill-switch filter key) or the reject outbound, matched rule,
    /// and process metadata.
    pub(crate) fn set_route(
        &self,
        outbound: &str,
        matched_rule: Option<&str>,
        question: RouteQuestion,
    ) {
        let outbound = Arc::from(outbound);
        let matched_rule = matched_rule.map(Arc::from);
        let process_name = question.input.process_name.as_deref().map(Arc::from);
        let process_path = question.input.process_path.as_deref().map(Arc::from);
        self.registry.update_entry(self.id, |entry| {
            entry.outbound = Some(outbound);
            entry.matched_rule = matched_rule;
            entry.process_name = process_name;
            entry.process_path = process_path;
            entry.question = Some(Box::new(question));
        });
    }

    /// Records where the dial's physical socket left the host: the interface
    /// a guard bound it to, if any, and its local address.
    pub(crate) fn set_egress(&self, egress: EgressBinding) {
        self.registry
            .update_entry(self.id, |entry| entry.egress = egress);
    }

    /// The session's live relay byte counters, shared with the ledger: the
    /// relay's counting wrapper streams into them as IO completes, so
    /// snapshots show real totals mid-flight and the established-phase
    /// budget watcher reads the same values.
    pub(crate) fn byte_counters(&self) -> SessionByteCounters {
        SessionByteCounters {
            up: Arc::clone(&self.bytes_up),
            down: Arc::clone(&self.bytes_down),
            volume: Arc::clone(&self.registry.inner.volume),
        }
    }

    /// Counts one established-phase budget reap (`relay.rs`); the reaping
    /// relay task returns right after, and its guard drop deregisters.
    pub(crate) fn record_budget_reap(&self) {
        self.registry
            .inner
            .reaped_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Upload/download counters shared between one session's ledger entry and
/// its relay task (upload = client→upstream); every add also counts into
/// the device's traffic volume.
#[derive(Debug, Clone)]
pub(crate) struct SessionByteCounters {
    pub(crate) up: Arc<AtomicU64>,
    pub(crate) down: Arc<AtomicU64>,
    volume: Arc<TrafficVolumeCounter>,
}

impl SessionByteCounters {
    pub(crate) fn add_up(&self, bytes: u64) {
        self.up.fetch_add(bytes, Ordering::Relaxed);
        self.volume.add_upload(bytes);
    }

    pub(crate) fn add_down(&self, bytes: u64) {
        self.down.fetch_add(bytes, Ordering::Relaxed);
        self.volume.add_download(bytes);
    }
}

/// The ledger entry → snapshot projection shared by every read surface.
fn snapshot_entry(id: u64, entry: &SessionEntry) -> SessionSnapshot {
    SessionSnapshot {
        id,
        inbound: entry.inbound,
        user: entry.user.clone(),
        process_name: entry.process_name.clone(),
        process_path: entry.process_path.clone(),
        source: entry.source.clone(),
        target: entry.target.clone(),
        host: entry.host.clone(),
        outbound: entry.outbound.clone(),
        matched_rule: entry.matched_rule.clone(),
        egress_interface: entry.egress.interface_index,
        phase: entry.phase,
        phase_since_unix: entry.phase_since_unix,
        created_at_unix: entry.created_at_unix,
        upload_bytes: entry.bytes_up.load(Ordering::Relaxed),
        download_bytes: entry.bytes_down.load(Ordering::Relaxed),
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// Bench-only handle over the crate-internal session registry
/// (`--features bench-internals`): measures one relay session's full ledger
/// lifecycle — admission + register, phase/route stamps, deregistration via
/// guard drop — which is the per-session coarse-mutex cost the sharding
/// follow-up is gated on.
#[cfg(feature = "bench-internals")]
pub mod bench {
    use std::sync::{Arc, Mutex};

    use super::{RouteQuestion, SessionGuard, SessionPhase, SessionRegistry};

    /// Cloning shares the underlying ledger, like the production handle.
    #[derive(Clone, Default)]
    pub struct BenchSessionRegistry {
        registry: SessionRegistry,
        /// Guards held resident so admission churn is measured against a
        /// populated ledger: a public server's cap check runs against many
        /// live sessions, not an empty table.
        resident: Arc<Mutex<Vec<SessionGuard>>>,
    }

    impl BenchSessionRegistry {
        pub fn new() -> Self {
            Self::default()
        }

        /// Admits and holds `count` sessions resident, so a later
        /// [`Self::session_roundtrip`] measures admission and teardown against
        /// that standing load. The guards drop with the bench registry.
        pub fn populate(&self, count: usize) {
            let mut resident = self.resident.lock().expect("bench resident guards");
            for index in 0..count {
                let guard = self
                    .registry
                    .register(
                        "bench",
                        Some("127.0.0.1:52000".into()),
                        format!("203.0.113.{}:443", index % 256),
                    )
                    .expect("bench registry admission");
                resident.push(guard);
            }
        }

        /// The connection table as a host polls it: one row per live
        /// session, built under the same ledger lock every admission and
        /// teardown takes.
        pub fn snapshot(&self) -> usize {
            self.registry.snapshot().len()
        }

        /// One TCP relay session's ledger lifecycle as the dispatcher drives
        /// it (register → Routing → route stamp → Established → drop). The
        /// per-session strings are allocated inside, as production does.
        pub fn session_roundtrip(&self) {
            let guard = self
                .registry
                .register(
                    "bench",
                    Some("127.0.0.1:52000".into()),
                    "203.0.113.9:443".into(),
                )
                .expect("bench registry admission");
            guard.set_phase(SessionPhase::Routing);
            guard.set_route(
                "DIRECT",
                Some("bench-rule"),
                RouteQuestion {
                    input: crate::RouteMatchInput {
                        host: Some("bench.example".into()),
                        destination_port: Some(443),
                        network: Some(crate::rule_engine::TransportNetwork::Tcp),
                        ..Default::default()
                    },
                    address: None,
                    dial_target: crate::target::ConnectTarget {
                        host: "bench.example".into(),
                        port: 443,
                    },
                },
            );
            guard.set_phase(SessionPhase::Established);
            guard.record_termination(crate::ConnectionTermination::Completed);
        }

        pub fn active(&self) -> u64 {
            self.registry.counters().active
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_route(guard: &SessionGuard, outbound: &str, matched_rule: Option<&str>) {
        guard.set_route(
            outbound,
            matched_rule,
            RouteQuestion {
                address: None,
                input: crate::RouteMatchInput {
                    process_name: Some("Google Chrome".into()),
                    process_path: Some("/Applications/Google Chrome.app".into()),
                    ..Default::default()
                },
                dial_target: crate::target::ConnectTarget {
                    host: "a.example".into(),
                    port: 443,
                },
            },
        );
    }

    #[test]
    fn admission_rejects_at_capacity_and_readmits_after_drop() {
        let registry = SessionRegistry::with_capacity(2);
        let first = registry
            .register("test", None, "a.example:443".into())
            .expect("first admitted");
        let _second = registry
            .register("test", None, "b.example:443".into())
            .expect("second admitted");

        let refused = registry
            .register("test", None, "c.example:443".into())
            .expect_err("third refused fail-fast");
        assert!(refused.contains("session limit 2 reached"), "{refused}");
        let counters = registry.counters();
        assert_eq!(counters.active, 2);
        assert_eq!(counters.accepted_total, 2);
        assert_eq!(counters.rejected_total, 1);

        drop(first);
        let _readmitted = registry
            .register("test", None, "c.example:443".into())
            .expect("slot freed by guard drop readmits");
        assert_eq!(registry.counters().active, 2);
    }

    #[test]
    fn guard_drop_is_the_only_deregistration_path() {
        let registry = SessionRegistry::with_capacity(8);
        let guard = registry
            .register(
                "test",
                Some("127.0.0.1:5000".into()),
                "a.example:443".into(),
            )
            .expect("registered");
        assert_eq!(registry.counters().active, 1);

        set_route(&guard, "NodeA", Some("rule-1"));
        guard.set_egress(EgressBinding::bound(7));
        guard.set_phase(SessionPhase::Established);
        let counters = guard.byte_counters();
        counters.up.store(100, Ordering::Relaxed);
        counters.down.store(200, Ordering::Relaxed);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        let session = &snapshot[0];
        assert_eq!(session.inbound, "test");
        assert_eq!(session.egress_interface, Some(7));
        assert_eq!(session.process_name.as_deref(), Some("Google Chrome"));
        assert_eq!(
            session.process_path.as_deref(),
            Some("/Applications/Google Chrome.app")
        );
        assert_eq!(session.source.as_deref(), Some("127.0.0.1:5000"));
        assert_eq!(&*session.target, "a.example:443");
        assert_eq!(session.outbound.as_deref(), Some("NodeA"));
        assert_eq!(session.matched_rule.as_deref(), Some("rule-1"));
        assert_eq!(session.phase, SessionPhase::Established);
        assert_eq!(session.upload_bytes, 100);
        assert_eq!(session.download_bytes, 200);

        drop(guard);
        assert_eq!(registry.counters().active, 0);
        assert!(registry.snapshot().is_empty(), "drop deregisters");
    }

    #[test]
    fn kill_by_outbound_cancels_matching_sessions_only() {
        let registry = SessionRegistry::with_capacity(8);
        let on_a = registry
            .register("test", None, "a.example:443".into())
            .expect("registered");
        set_route(&on_a, "NodeA", None);
        let on_b = registry
            .register("test", None, "b.example:443".into())
            .expect("registered");
        set_route(&on_b, "NodeB", None);
        let unrouted = registry
            .register("test", None, "c.example:443".into())
            .expect("registered");

        let killed = registry.kill_by_outbound("NodeA");

        assert_eq!(killed, 1);
        assert!(on_a.cancellation().is_cancelled());
        assert!(!on_b.cancellation().is_cancelled());
        assert!(!unrouted.cancellation().is_cancelled());
        assert_eq!(registry.counters().killed_total, 1);
        // Kill signals; the owning task still deregisters via its guard.
        assert_eq!(registry.counters().active, 3);
    }

    #[test]
    fn a_network_change_kills_only_the_sessions_it_stranded() {
        let registry = SessionRegistry::with_capacity(8);
        let egress = |interface: u32, local: &str| EgressBinding {
            interface_index: Some(interface),
            local_address: Some(local.parse().unwrap()),
        };
        let wired = registry
            .register("test", None, "a.example:443".into())
            .expect("registered");
        wired.set_egress(egress(2, "192.0.2.10"));
        let wifi = registry
            .register("test", None, "b.example:443".into())
            .expect("registered");
        wifi.set_egress(egress(3, "198.51.100.20"));
        let dialing = registry
            .register("test", None, "c.example:443".into())
            .expect("registered");
        let before = crate::egress::EgressNetwork {
            addresses: vec![
                (2, "192.0.2.10".parse().unwrap()),
                (3, "198.51.100.20".parse().unwrap()),
            ],
            ..Default::default()
        };
        let after = crate::egress::EgressNetwork {
            addresses: vec![(3, "198.51.100.20".parse().unwrap())],
            ..Default::default()
        };

        let killed = registry.kill_stranded(&NetworkChange::between(&before, &after));

        assert_eq!(killed, 1);
        assert!(wired.cancellation().is_cancelled());
        assert!(!wifi.cancellation().is_cancelled());
        assert!(!dialing.cancellation().is_cancelled());
        assert_eq!(registry.counters().killed_total, 1);
    }

    #[test]
    fn budget_reaps_count_separately_from_kills() {
        let registry = SessionRegistry::with_capacity(8);
        let guard = registry
            .register("test", None, "a.example:443".into())
            .expect("registered");

        guard.record_budget_reap();

        let counters = registry.counters();
        assert_eq!(counters.reaped_total, 1);
        assert_eq!(counters.killed_total, 0);
    }

    #[test]
    fn counters_bucket_live_sessions_by_phase() {
        let registry = SessionRegistry::with_capacity(8);
        let accepted = registry
            .register("test", None, "a.example:443".into())
            .expect("registered");
        let dialing = registry
            .register("test", None, "b.example:443".into())
            .expect("registered");
        dialing.set_phase(SessionPhase::Dialing);
        let established = registry
            .register("test", None, "c.example:443".into())
            .expect("registered");
        established.set_phase(SessionPhase::Established);

        let phases = registry.counters().phases;

        assert_eq!(phases.accepted, 1);
        assert_eq!(phases.dialing, 1);
        assert_eq!(phases.established, 1);
        assert_eq!(phases.enriching + phases.routing, 0);
        drop(accepted);
        assert_eq!(registry.counters().phases.accepted, 0);
    }

    #[test]
    fn stalled_snapshot_names_stuck_dials_and_silent_established_sessions() {
        let registry = SessionRegistry::with_capacity(8);
        let dialing = registry
            .register("test", None, "stuck-dial.example:443".into())
            .expect("registered");
        dialing.set_phase(SessionPhase::Dialing);
        let healthy = registry
            .register("test", None, "healthy.example:443".into())
            .expect("registered");
        healthy.set_phase(SessionPhase::Established);
        healthy.byte_counters().down.store(1, Ordering::Relaxed);
        let black_hole = registry
            .register("test", None, "black-hole.example:443".into())
            .expect("registered");
        black_hole.set_phase(SessionPhase::Established);
        let future = now_unix() + STALLED_SESSION_THRESHOLD_SECONDS;

        let stalled = registry.stalled_snapshot(8, future);

        let targets: Vec<&str> = stalled.iter().map(|snapshot| &*snapshot.target).collect();
        assert!(targets.contains(&"stuck-dial.example:443"), "{targets:?}");
        assert!(targets.contains(&"black-hole.example:443"), "{targets:?}");
        assert!(
            !targets.contains(&"healthy.example:443"),
            "an Established session with downstream bytes is not stalled: {targets:?}"
        );
        assert_eq!(stalled.len(), 2);
    }

    #[test]
    fn stalled_snapshot_is_empty_for_fresh_sessions_and_respects_the_limit() {
        let registry = SessionRegistry::with_capacity(8);
        let mut guards = Vec::new();
        for index in 0..3 {
            let guard = registry
                .register("test", None, format!("stuck-{index}.example:443"))
                .expect("registered");
            guard.set_phase(SessionPhase::Dialing);
            guards.push(guard);
        }

        assert!(
            registry.stalled_snapshot(8, now_unix()).is_empty(),
            "sessions under the threshold are not stalled"
        );
        let future = now_unix() + STALLED_SESSION_THRESHOLD_SECONDS;
        assert_eq!(registry.stalled_snapshot(2, future).len(), 2);
    }

    #[test]
    fn close_cancels_the_whole_tree_and_refuses_new_sessions() {
        let registry = SessionRegistry::with_capacity(8);
        let first = registry
            .register("test", None, "a.example:443".into())
            .expect("registered");
        let second = registry
            .register("test", None, "b.example:443".into())
            .expect("registered");

        let signalled = registry.close();

        assert_eq!(signalled, 2);
        assert!(
            first.cancellation().is_cancelled(),
            "root cancel reaches leaves"
        );
        assert!(second.cancellation().is_cancelled());
        let refused = registry
            .register("test", None, "c.example:443".into())
            .expect_err("closed registry refuses");
        assert!(refused.contains("closed"), "{refused}");
        // Sessions registered before close would also see cancellation
        // through tokens created later from the same root.
        assert!(registry.inner.root.child_token().is_cancelled());
    }

    #[test]
    fn explicit_termination_wins_over_phase_bytes_and_later_cancellation() {
        use crate::{ConnectionFailureCause, TcpFlowStage};
        let registry = SessionRegistry::with_capacity(8);
        let failure = ConnectionTermination::Failed {
            stage: TcpFlowStage::Relay,
            cause: ConnectionFailureCause::Message {
                message: "upstream failed".into(),
            },
        };
        let served = registry
            .register("test", None, "served.example:443".into())
            .unwrap();
        served.set_phase(SessionPhase::Established);
        served.byte_counters().down.store(2000, Ordering::Relaxed);
        served.record_termination(failure.clone());
        served.record_termination(ConnectionTermination::Completed);
        registry.kill_all();
        drop(served);

        let empty = registry
            .register("test", None, "empty.example:443".into())
            .unwrap();
        empty.record_termination(ConnectionTermination::Completed);
        drop(empty);

        let denied = registry
            .register("test", None, "denied.example:443".into())
            .unwrap();
        denied.set_phase(SessionPhase::Dialing);
        denied.record_termination(ConnectionTermination::PolicyRejected {
            reason: crate::egress::EgressPolicyRejection::UnresolvedIpv6Scope,
        });
        drop(denied);
        let finished = registry.finished_snapshot();
        assert_eq!(finished[0].termination, failure);
        assert_eq!(finished[0].snapshot.download_bytes, 2000);
        assert_eq!(finished[1].termination, ConnectionTermination::Completed);
        assert!(matches!(
            finished[2].termination,
            ConnectionTermination::PolicyRejected { .. }
        ));
        assert_eq!(registry.terminal_counts(), (1, 1));
        assert!(finished
            .iter()
            .all(|record| record.closed_at_unix >= record.snapshot.created_at_unix));
    }

    #[test]
    fn session_bytes_count_into_a_volume_that_outlives_the_sessions() {
        let volume = Arc::new(TrafficVolumeCounter::default());
        let registry = SessionRegistry::counting_into(Arc::clone(&volume));
        let first = registry
            .register("test", None, "first.example:443".into())
            .unwrap();
        first.byte_counters().add_up(100);
        first.byte_counters().add_down(2000);
        drop(first);
        let second = registry
            .register("test", None, "second.example:443".into())
            .unwrap();
        second.byte_counters().add_down(500);

        assert_eq!(registry.snapshot()[0].download_bytes, 500);
        assert_eq!(
            volume.volume(),
            crate::TrafficVolume {
                upload_bytes: 100,
                download_bytes: 2500,
            }
        );
    }

    #[test]
    fn unreported_drop_is_unknown_unless_the_owner_was_cancelled() {
        let registry = SessionRegistry::with_capacity(8);
        let unknown = registry
            .register("test", None, "unknown.example:443".into())
            .unwrap();
        unknown.set_phase(SessionPhase::Established);
        unknown.byte_counters().down.store(2000, Ordering::Relaxed);
        drop(unknown);
        let cancelled = registry
            .register("test", None, "cancelled.example:443".into())
            .unwrap();
        cancelled.set_phase(SessionPhase::Dialing);
        registry.kill_all();
        drop(cancelled);
        let finished = registry.finished_snapshot();
        assert_eq!(finished[0].termination, ConnectionTermination::Unknown);
        assert_eq!(finished[1].termination, ConnectionTermination::Cancelled);
        assert_eq!(registry.terminal_counts(), (0, 0));
    }

    #[test]
    fn a_poller_receives_each_terminal_record_once() {
        let registry = SessionRegistry::with_capacity(8);
        let finish = |target: &str| {
            drop(
                registry
                    .register("test", None, target.into())
                    .expect("registered"),
            );
        };
        finish("a.example:443");
        finish("b.example:443");
        let (first, cursor) = registry.finished_since(0);
        assert_eq!(first.len(), 2);
        assert_eq!(cursor, 2);
        let (none, unchanged) = registry.finished_since(cursor);
        assert!(none.is_empty());
        assert_eq!(unchanged, cursor);
        finish("c.example:443");
        let (next, cursor) = registry.finished_since(cursor);
        assert_eq!(next.len(), 1);
        assert_eq!(&*next[0].snapshot.target, "c.example:443");
        assert_eq!(cursor, 3);
    }

    #[test]
    fn finished_ring_is_bounded_and_keeps_the_newest_records() {
        let registry = SessionRegistry::with_capacity(8);
        for index in 0..(FINISHED_SESSION_HISTORY + 10) {
            let session = registry
                .register("test", None, format!("target-{index}.example:443"))
                .expect("registered");
            drop(session);
        }

        let finished = registry.finished_snapshot();
        assert_eq!(finished.len(), FINISHED_SESSION_HISTORY);
        assert_eq!(
            &*finished.last().expect("newest record").snapshot.target,
            format!("target-{}.example:443", FINISHED_SESSION_HISTORY + 9)
        );
    }
}
