//! App-process connection history: the accumulating ledger behind the UI
//! connection table. Core processes keep only bounded state (live tables
//! plus a small finished-session ring), so retention lives here, where the
//! lifetime matches the product rule: history survives everything except an
//! app restart or an explicit user clear (which removes finished rows only).
//!
//! The history takes in the Core's rows on its own timer, whether a window
//! shows or not (`operations::telemetry::absorb_connection_history`). Each
//! change advances its revision, so the connection table asks only for what
//! changed since the revision it holds; the rules page reads the per-rule hit
//! counts kept here.
//!
//! # What a row costs
//!
//! The history is what an idle app keeps most of, so its rows are shared
//! rather than copied, at every step:
//!
//! - a row is one allocation the history and every table showing it hold
//!   together, so a table's copy of the history is its pointers;
//! - the rows are found through an index of pointers, so the room a hash
//!   table leaves empty is that of a pointer and not of a row;
//! - a text many rows carry -- a program's name and path, a rule, an
//!   outbound, a host visited again -- is kept once for all of them
//!   ([`SharedTexts`]). A live row's texts are the Core's own
//!   (`TrafficConnectionSnapshot`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use egrio_core::{ConnectionTermination, TrafficConnectionSnapshot, TrafficConnectionState};
use serde::Serialize;

/// Retention guard: history is unbounded by product rule until restart or
/// manual clear, but runaway session churn should degrade to dropping the
/// oldest finished rows, never to unbounded app memory.
const HISTORY_CAP: usize = 5_000;

/// Removals kept for tables to catch up on; a table further behind receives
/// every row again, which costs it a pointer a row.
const REMOVALS_KEPT: usize = 1_024;

/// A row as the history and the tables showing it hold it.
pub type ConnectionRow = Arc<TrafficConnectionSnapshot>;

/// The history's figures without its rows.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficTotals {
    /// Cumulative over every row, live and finished: they move only when
    /// bytes move, and step down when a user clear or the cap drops rows.
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u64,
    /// Distinct named processes across the history; one name at two
    /// executable paths counts twice.
    pub processes: u64,
}

/// What changed in the history since the revision a table holds: the rows
/// added or changed and the ids removed or, for a table that holds none or
/// fell behind the removals kept, every row (`full`).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionsUpdate {
    pub revision: u64,
    pub full: bool,
    /// Newest connection first.
    pub rows: Vec<ConnectionRow>,
    pub removed: Vec<Arc<str>>,
    pub totals: TrafficTotals,
}

#[derive(Debug)]
struct Entry {
    row: ConnectionRow,
    /// The revision that last changed it.
    changed: u64,
}

/// The texts many rows have in common, each kept once for all the rows that
/// carry it. A row's own texts -- its id, its source port -- are not here.
///
/// A text is kept while something else holds it: a row, a table's copy of
/// one, the Core's session it came from. The others go whenever the set has
/// doubled since they last went, so it stays within twice what is in use.
#[derive(Debug, Default)]
struct SharedTexts {
    kept: HashSet<Arc<str>>,
    /// The size at which the texts nothing else holds are dropped.
    sweep_at: usize,
}

impl SharedTexts {
    /// Below this the set is not worth sweeping.
    const SMALL: usize = 64;

    /// Makes `text` the one kept for its content.
    fn share(&mut self, text: &mut Arc<str>) {
        if let Some(kept) = self.kept.get(&**text) {
            if !Arc::ptr_eq(kept, text) {
                *text = Arc::clone(kept);
            }
            return;
        }
        if self.kept.len() >= self.sweep_at.max(Self::SMALL) {
            self.kept.retain(|kept| Arc::strong_count(kept) > 1);
            self.sweep_at = self.kept.len() * 2;
        }
        self.kept.insert(Arc::clone(text));
    }

    fn share_row(&mut self, row: &mut TrafficConnectionSnapshot) {
        self.share(&mut row.destination);
        self.share(&mut row.outbound);
        for text in [
            &mut row.process_name,
            &mut row.process_path,
            &mut row.host,
            &mut row.rule,
        ]
        .into_iter()
        .flatten()
        {
            self.share(text);
        }
    }
}

#[derive(Debug, Default)]
pub struct ConnectionHistory {
    /// Keyed by connection id, which is the row's own; an id reused by a
    /// restarted core rekeys the older record (see [`Self::absorb`]) so
    /// history survives the reuse.
    entries: HashMap<Arc<str>, Entry>,
    texts: SharedTexts,
    /// Finished records closed at or before this instant stay suppressed:
    /// the core rings re-send recent terminal records on every poll, and
    /// this watermark is what makes a user clear stick.
    cleared_watermark_unix: i64,
    /// Where the last poll left off, so the next one receives only the
    /// terminal records it has not seen.
    cursor: egrio_runtime::TelemetryCursor,
    revision: u64,
    /// Ids removed and the revision that removed them, oldest first.
    removed: VecDeque<(u64, Arc<str>)>,
    /// A table at an older revision may have missed a removal no longer kept.
    removals_from: u64,
    /// The profile the running Core serves: the rows taken in count their
    /// rule hits for it.
    profile: Option<String>,
    /// Connections per rule, by the rule as its profile writes it, per
    /// profile.
    rule_hits: HashMap<String, HashMap<String, u64>>,
}

impl ConnectionHistory {
    pub fn set_profile(&mut self, profile: Option<String>) {
        self.profile = profile;
    }

    /// Folds one polled snapshot (live rows plus the core finished rings,
    /// every core merged and id-prefixed by the caller) into the ledger.
    ///
    /// Identity is `(id, opened_at_unix)`: an incoming row with a held id
    /// but a different opening instant is a new connection from a restarted
    /// core, so the held record is rekeyed out of its way instead of being
    /// overwritten. A matching identity always takes the incoming row —
    /// including a real terminal record or Active over an unknown result
    /// caused by a brief gap in observation. A connection the history takes
    /// in for the first time counts a hit for its rule.
    pub fn absorb(&mut self, connections: Vec<TrafficConnectionSnapshot>, now_unix: i64) {
        let revision = self.revision + 1;
        let mut changed = false;
        let live_ids: HashSet<Arc<str>> = connections
            .iter()
            .filter(|connection| connection.state == TrafficConnectionState::Active)
            .map(|connection| Arc::clone(&connection.id))
            .collect();

        for mut connection in connections {
            let terminal = connection.state != TrafficConnectionState::Active;
            if terminal
                && connection
                    .closed_at_unix
                    .is_some_and(|closed| closed <= self.cleared_watermark_unix)
            {
                continue;
            }
            match self.entries.get_mut(&*connection.id) {
                Some(held) if *held.row == connection => continue,
                Some(held) if held.row.opened_at_unix == connection.opened_at_unix => {
                    // The same connection, moved on: the row takes the new
                    // figures where it is, under the id it is found by.
                    connection.id = Arc::clone(&held.row.id);
                    self.texts.share_row(&mut connection);
                    match Arc::get_mut(&mut held.row) {
                        Some(row) => *row = connection,
                        // A table holds the row as it was.
                        None => held.row = Arc::new(connection),
                    }
                    held.changed = revision;
                    changed = true;
                    continue;
                }
                Some(_) => {
                    let mut held = self.entries.remove(&*connection.id).expect("held entry");
                    let row = Arc::make_mut(&mut held.row);
                    // The displaced row has no observed terminal result.
                    // A restarted Core must not turn it into a success.
                    if row.state == TrafficConnectionState::Active {
                        mark_unknown_result(row, now_unix);
                    }
                    row.id = format!("{}@{}", row.id, row.opened_at_unix).into();
                    held.changed = revision;
                    self.entries.insert(Arc::clone(&held.row.id), held);
                }
                None => {}
            }
            self.count_rule_hit(&connection);
            self.texts.share_row(&mut connection);
            changed = true;
            self.entries.insert(
                Arc::clone(&connection.id),
                Entry {
                    row: Arc::new(connection),
                    changed: revision,
                },
            );
        }

        // A row held as active that no longer appears live and got no
        // terminal record (UDP idle-out, ring overflow, host restart)
        // has an unknown result. This timestamp marks the observation gap,
        // not a successful completion; a later real record replaces it.
        for entry in self.entries.values_mut() {
            if entry.row.state == TrafficConnectionState::Active
                && !live_ids.contains(&entry.row.id)
            {
                mark_unknown_result(Arc::make_mut(&mut entry.row), now_unix);
                entry.changed = revision;
                changed = true;
            }
        }

        self.evict_past_the_cap(revision);
        if changed {
            self.revision = revision;
        }
    }

    /// Drops the finished rows that closed first until the history is
    /// within its cap, or has no finished row left.
    fn evict_past_the_cap(&mut self, revision: u64) {
        let excess = self.entries.len().saturating_sub(HISTORY_CAP);
        if excess == 0 {
            return;
        }
        let mut finished: Vec<(i64, &Arc<str>)> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.row.state != TrafficConnectionState::Active)
            .map(|(id, entry)| (entry.row.closed_at_unix.unwrap_or(0), id))
            .collect();
        if finished.len() > excess {
            finished.select_nth_unstable(excess - 1);
            finished.truncate(excess);
        }
        let evicted: Vec<Arc<str>> = finished.into_iter().map(|(_, id)| id.clone()).collect();
        for id in evicted {
            self.entries.remove(&id);
            self.note_removed(revision, id);
        }
    }

    fn count_rule_hit(&mut self, connection: &TrafficConnectionSnapshot) {
        let (Some(profile), Some(rule)) = (&self.profile, &connection.rule) else {
            return;
        };
        if !self.rule_hits.contains_key(profile) {
            self.rule_hits.insert(profile.clone(), HashMap::new());
        }
        let hits = self.rule_hits.get_mut(profile).expect("the profile's hits");
        match hits.get_mut(&**rule) {
            Some(count) => *count += 1,
            None => {
                hits.insert(rule.to_string(), 1);
            }
        }
    }

    fn note_removed(&mut self, revision: u64, id: Arc<str>) {
        self.removed.push_back((revision, id));
        if self.removed.len() > REMOVALS_KEPT {
            if let Some((dropped, _)) = self.removed.pop_front() {
                self.removals_from = dropped;
            }
        }
    }

    pub fn cursor(&self) -> egrio_runtime::TelemetryCursor {
        self.cursor
    }

    pub fn set_cursor(&mut self, cursor: egrio_runtime::TelemetryCursor) {
        self.cursor = cursor;
    }

    /// What changed since revision `since`; every row when `since` is
    /// `None` or older than the removals kept.
    pub fn changes_since(&self, since: Option<u64>) -> ConnectionsUpdate {
        let since = since.filter(|since| *since <= self.revision && *since >= self.removals_from);
        let (rows, removed) = match since {
            None => (self.rows_where(|_| true), Vec::new()),
            Some(since) => (
                self.rows_where(|entry| entry.changed > since),
                self.removed
                    .iter()
                    .rev()
                    .take_while(|(revision, _)| *revision > since)
                    .map(|(_, id)| id.clone())
                    .collect(),
            ),
        };
        ConnectionsUpdate {
            revision: self.revision,
            full: since.is_none(),
            rows,
            removed,
            totals: self.totals(),
        }
    }

    /// Newest connection first, a deterministic order so the unsorted UI
    /// table does not reshuffle between updates.
    fn rows_where(&self, filter: impl Fn(&Entry) -> bool) -> Vec<ConnectionRow> {
        let mut rows: Vec<ConnectionRow> = self
            .entries
            .values()
            .filter(|entry| filter(entry))
            .map(|entry| Arc::clone(&entry.row))
            .collect();
        rows.sort_unstable_by(|a, b| {
            b.opened_at_unix
                .cmp(&a.opened_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows
    }

    pub fn totals(&self) -> TrafficTotals {
        let mut totals = TrafficTotals {
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            processes: 0,
        };
        // A program's name and path are shared texts, so the rows of one
        // program are told by where its texts are, and only the few
        // programs there are have theirs read.
        let mut programs: HashMap<(*const u8, Option<*const u8>), (&str, Option<&str>)> =
            HashMap::new();
        for entry in self.entries.values() {
            let connection = &entry.row;
            totals.upload_bytes += connection.upload_bytes;
            totals.download_bytes += connection.download_bytes;
            if connection.state == TrafficConnectionState::Active {
                totals.active_connections += 1;
            }
            if let Some(name) = &connection.process_name {
                let path = connection.process_path.as_ref();
                programs
                    .entry((
                        Arc::as_ptr(name).cast(),
                        path.map(|path| Arc::as_ptr(path).cast()),
                    ))
                    .or_insert((name, path.map(|path| &**path)));
            }
        }
        let named: HashSet<(&str, Option<&str>)> = programs
            .into_values()
            .filter_map(|(name, path)| {
                let name = name.trim();
                (!name.is_empty()).then_some((name, path))
            })
            .collect();
        totals.processes = named.len() as u64;
        totals
    }

    /// The user's clear action: drops every non-active row, keeps active
    /// ones, and moves the watermark so the core
    /// rings' re-sent records stay gone. Returns how many rows were removed.
    pub fn clear_finished(&mut self, now_unix: i64) -> usize {
        let finished: Vec<Arc<str>> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.row.state != TrafficConnectionState::Active)
            .map(|(id, _)| id.clone())
            .collect();
        self.cleared_watermark_unix = now_unix;
        if finished.is_empty() {
            return 0;
        }
        self.revision += 1;
        let removed = finished.len();
        for id in finished {
            self.entries.remove(&id);
            self.note_removed(self.revision, id);
        }
        // The room of the rows that went, not kept for the ones to come.
        self.entries.shrink_to_fit();
        removed
    }

    /// Connections per rule of `profile`, since the app started or the user
    /// reset them. A rule is named as its profile writes it, which is how a
    /// connection's row names the rule that routed it, so a count stays with
    /// its rule when the list of rules changes.
    pub fn rule_hits(&self, profile: &str) -> HashMap<String, u64> {
        self.rule_hits.get(profile).cloned().unwrap_or_default()
    }

    pub fn reset_rule_hits(&mut self, profile: &str) {
        self.rule_hits.remove(profile);
    }
}

fn mark_unknown_result(connection: &mut TrafficConnectionSnapshot, observed_at_unix: i64) {
    let termination = ConnectionTermination::Unknown;
    connection.state = TrafficConnectionState::from(&termination);
    connection.termination = Some(termination);
    connection.closed_at_unix = Some(observed_at_unix);
    connection.updated_at_unix = observed_at_unix;
}

#[cfg(test)]
mod tests {
    use super::*;
    use egrio_core::{ConnectionFailureCause, TcpFlowStage, TrafficConnectionProtocol};

    fn row(
        id: &str,
        state: TrafficConnectionState,
        opened_at: i64,
        closed_at: Option<i64>,
    ) -> TrafficConnectionSnapshot {
        let termination = match state {
            TrafficConnectionState::Active => None,
            TrafficConnectionState::Completed => Some(ConnectionTermination::Completed),
            TrafficConnectionState::Failed => Some(ConnectionTermination::Failed {
                stage: TcpFlowStage::Dial,
                cause: ConnectionFailureCause::Message {
                    message: "test failure".into(),
                },
            }),
            TrafficConnectionState::Cancelled => Some(ConnectionTermination::Cancelled),
            TrafficConnectionState::Rejected => Some(ConnectionTermination::RouteRejected),
            TrafficConnectionState::Unknown => Some(ConnectionTermination::Unknown),
        };
        TrafficConnectionSnapshot {
            id: id.into(),
            protocol: TrafficConnectionProtocol::Tcp,
            process_name: None,
            process_path: None,
            source: None,
            destination: "example.com:443".into(),
            host: None,
            rule: None,
            inbound: "tun".into(),
            outbound: "DIRECT".into(),
            egress_interface: None,
            upload_bytes: 0,
            download_bytes: 0,
            opened_at_unix: opened_at,
            updated_at_unix: closed_at.unwrap_or(opened_at),
            state,
            termination,
            closed_at_unix: closed_at,
        }
    }

    fn view(history: &ConnectionHistory) -> Vec<ConnectionRow> {
        history.changes_since(None).rows
    }

    fn ids(connections: &[ConnectionRow]) -> Vec<&str> {
        connections
            .iter()
            .map(|connection| &*connection.id)
            .collect()
    }

    #[test]
    fn totals_sum_every_row_and_count_each_named_process_once() {
        let mut history = ConnectionHistory::default();
        let with = |id, state, closed, process: Option<&str>, bytes: u64| {
            let mut connection = row(id, state, 1, closed);
            connection.process_name = process.map(Into::into);
            connection.upload_bytes = bytes;
            connection.download_bytes = bytes * 10;
            connection
        };
        let mut elsewhere = with(
            "f",
            TrafficConnectionState::Completed,
            Some(2),
            Some("ssh"),
            6,
        );
        elsewhere.process_path = Some("/opt/bin/ssh".into());
        history.absorb(
            vec![
                with("a", TrafficConnectionState::Active, None, Some("curl"), 1),
                with(
                    "b",
                    TrafficConnectionState::Completed,
                    Some(2),
                    Some(" curl "),
                    2,
                ),
                with("c", TrafficConnectionState::Failed, Some(2), Some("ssh"), 3),
                with(
                    "d",
                    TrafficConnectionState::Completed,
                    Some(2),
                    Some(" "),
                    4,
                ),
                with("e", TrafficConnectionState::Completed, Some(2), None, 5),
                elsewhere,
            ],
            3,
        );
        let totals = history.totals();
        assert_eq!((totals.upload_bytes, totals.download_bytes), (21, 210));
        assert_eq!(totals.processes, 3);
        assert_eq!(totals.active_connections, 1);
    }

    #[test]
    fn vanished_active_rows_have_an_unknown_result() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![row("udp-1", TrafficConnectionState::Active, 100, None)],
            100,
        );
        history.absorb(Vec::new(), 130);

        let view = view(&history);
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].state, TrafficConnectionState::Unknown);
        assert!(matches!(
            view[0].termination,
            Some(ConnectionTermination::Unknown)
        ));
        assert_eq!(view[0].closed_at_unix, Some(130));
    }

    #[test]
    fn terminal_ring_records_overwrite_the_live_row() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![row("tcp-1", TrafficConnectionState::Active, 100, None)],
            100,
        );
        history.absorb(
            vec![row("tcp-1", TrafficConnectionState::Failed, 100, Some(101))],
            105,
        );

        let view = view(&history);
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].state, TrafficConnectionState::Failed);
        assert_eq!(view[0].closed_at_unix, Some(101));
    }

    #[test]
    fn a_later_terminal_record_replaces_an_unknown_result() {
        for state in [
            TrafficConnectionState::Completed,
            TrafficConnectionState::Failed,
            TrafficConnectionState::Cancelled,
            TrafficConnectionState::Rejected,
        ] {
            let mut history = ConnectionHistory::default();
            history.absorb(
                vec![row("tcp-1", TrafficConnectionState::Active, 100, None)],
                100,
            );
            history.absorb(Vec::new(), 110);
            assert_eq!(view(&history)[0].state, TrafficConnectionState::Unknown);

            let terminal = row("tcp-1", state, 100, Some(108));
            let reason = terminal.termination.clone();
            history.absorb(vec![terminal], 115);

            let view = view(&history);
            assert_eq!(view.len(), 1);
            assert_eq!(view[0].state, state);
            assert_eq!(view[0].termination, reason);
            assert_eq!(view[0].closed_at_unix, Some(108));
        }
    }

    #[test]
    fn clear_drops_finished_rows_and_suppresses_ring_resends() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![
                row("tcp-1", TrafficConnectionState::Failed, 100, Some(110)),
                row("tcp-2", TrafficConnectionState::Completed, 100, Some(115)),
                row("tcp-3", TrafficConnectionState::Active, 100, None),
                row("tcp-5", TrafficConnectionState::Cancelled, 100, Some(116)),
                row("tcp-6", TrafficConnectionState::Rejected, 100, Some(117)),
                row("tcp-7", TrafficConnectionState::Unknown, 100, Some(118)),
            ],
            120,
        );

        assert_eq!(history.clear_finished(120), 5);
        // The next poll re-sends the same ring records; they must stay gone,
        // while records finishing after the clear appear.
        history.absorb(
            vec![
                row("tcp-1", TrafficConnectionState::Failed, 100, Some(110)),
                row("tcp-3", TrafficConnectionState::Active, 100, None),
                row("tcp-4", TrafficConnectionState::Completed, 118, Some(125)),
                row("tcp-5", TrafficConnectionState::Cancelled, 100, Some(116)),
                row("tcp-6", TrafficConnectionState::Rejected, 100, Some(117)),
                row("tcp-7", TrafficConnectionState::Unknown, 100, Some(118)),
            ],
            126,
        );

        let view = view(&history);
        assert_eq!(ids(&view), vec!["tcp-4", "tcp-3"]);
        assert_eq!(view[1].state, TrafficConnectionState::Active);
    }

    #[test]
    fn reused_ids_from_a_restarted_core_rekey_the_older_record() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![row(
                "tcp-1",
                TrafficConnectionState::Completed,
                100,
                Some(110),
            )],
            110,
        );
        history.absorb(
            vec![row("tcp-1", TrafficConnectionState::Active, 200, None)],
            200,
        );

        let view = view(&history);
        assert_eq!(view.len(), 2);
        assert_eq!(&*view[0].id, "tcp-1");
        assert_eq!(view[0].state, TrafficConnectionState::Active);
        assert_eq!(&*view[1].id, "tcp-1@100");
        assert_eq!(view[1].state, TrafficConnectionState::Completed);
    }

    #[test]
    fn a_reused_id_retains_the_displaced_active_row_as_unknown() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![row("tcp-1", TrafficConnectionState::Active, 100, None)],
            100,
        );
        history.absorb(
            vec![row("tcp-1", TrafficConnectionState::Active, 200, None)],
            200,
        );

        let view = view(&history);
        assert_eq!(view.len(), 2);
        assert_eq!(&*view[0].id, "tcp-1");
        assert_eq!(view[0].state, TrafficConnectionState::Active);
        assert_eq!(view[0].termination, None);
        assert_eq!(&*view[1].id, "tcp-1@100");
        assert_eq!(view[1].state, TrafficConnectionState::Unknown);
        assert!(matches!(
            view[1].termination,
            Some(ConnectionTermination::Unknown)
        ));
        assert_eq!(view[1].closed_at_unix, Some(200));
    }

    #[test]
    fn a_row_closed_during_a_host_outage_resurrects_when_seen_live_again() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![row("ne-tcp-1", TrafficConnectionState::Active, 100, None)],
            100,
        );
        // Host query fails for one poll: no terminal result was observed.
        history.absorb(Vec::new(), 105);
        assert_eq!(view(&history)[0].state, TrafficConnectionState::Unknown);

        // Host answers again with the same connection still live.
        history.absorb(
            vec![row("ne-tcp-1", TrafficConnectionState::Active, 100, None)],
            110,
        );

        let view = view(&history);
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].state, TrafficConnectionState::Active);
        assert_eq!(view[0].termination, None);
        assert_eq!(view[0].closed_at_unix, None);
    }

    #[test]
    fn history_caps_by_evicting_the_oldest_finished_rows() {
        let mut history = ConnectionHistory::default();
        let rows: Vec<TrafficConnectionSnapshot> = (0..HISTORY_CAP + 10)
            .map(|index| {
                row(
                    &format!("tcp-{index}"),
                    TrafficConnectionState::Completed,
                    index as i64,
                    Some(index as i64 + 1),
                )
            })
            .chain(std::iter::once(row(
                "tcp-live",
                TrafficConnectionState::Active,
                0,
                None,
            )))
            .collect();
        history.absorb(rows, 99_999);

        let update = history.changes_since(Some(0));
        assert_eq!(update.removed.len(), 11);
        assert!(update.removed.contains(&"tcp-0".into()));
        let view = view(&history);
        assert_eq!(view.len(), HISTORY_CAP);
        assert!(view.iter().any(|entry| &*entry.id == "tcp-live"));
        assert!(!view.iter().any(|entry| &*entry.id == "tcp-0"));
    }

    #[test]
    fn a_table_receives_only_what_changed_since_its_revision() {
        let mut history = ConnectionHistory::default();
        let mut live = row("tcp-1", TrafficConnectionState::Active, 100, None);
        let done = row("tcp-2", TrafficConnectionState::Completed, 90, Some(95));
        history.absorb(vec![live.clone(), done.clone()], 100);
        let first = history.changes_since(None);
        assert!(first.full);
        assert_eq!(ids(&first.rows), vec!["tcp-1", "tcp-2"]);

        // The same rows again change nothing.
        history.absorb(vec![live.clone(), done.clone()], 102);
        let idle = history.changes_since(Some(first.revision));
        assert_eq!(idle.revision, first.revision);
        assert!(!idle.full && idle.rows.is_empty() && idle.removed.is_empty());

        live.download_bytes = 4096;
        live.updated_at_unix = 104;
        history.absorb(vec![live, done], 104);
        let moved = history.changes_since(Some(first.revision));
        assert!(!moved.full);
        assert_eq!(ids(&moved.rows), vec!["tcp-1"]);
        assert_eq!(moved.rows[0].download_bytes, 4096);
        assert_eq!(moved.totals.download_bytes, 4096);

        assert_eq!(history.clear_finished(110), 1);
        let cleared = history.changes_since(Some(moved.revision));
        assert!(cleared.rows.is_empty());
        assert_eq!(cleared.removed, vec![Arc::<str>::from("tcp-2")]);
        assert!(
            history.changes_since(Some(cleared.revision + 1)).full,
            "a revision the history never had"
        );
    }

    #[test]
    fn a_table_behind_the_removals_kept_receives_every_row() {
        let mut history = ConnectionHistory::default();
        let behind = history.changes_since(None).revision;
        let batch = HISTORY_CAP - 1;
        for round in 0..=REMOVALS_KEPT / batch {
            let opened = round as i64 * 10;
            history.absorb(
                (0..batch)
                    .map(|index| {
                        row(
                            &format!("tcp-{round}-{index}"),
                            TrafficConnectionState::Completed,
                            opened,
                            Some(opened + 1),
                        )
                    })
                    .collect(),
                opened + 2,
            );
            history.clear_finished(opened + 2);
        }
        history.absorb(
            vec![row("tcp-live", TrafficConnectionState::Active, 1_000, None)],
            1_000,
        );

        let update = history.changes_since(Some(behind));
        assert!(update.full);
        assert_eq!(ids(&update.rows), vec!["tcp-live"]);
        assert!(update.removed.is_empty());
    }

    /// A connection as the Core hands it over: with strings of its own.
    fn of_a_program(
        id: &str,
        state: TrafficConnectionState,
        opened: i64,
    ) -> TrafficConnectionSnapshot {
        let closed = (state != TrafficConnectionState::Active).then_some(opened + 1);
        let mut connection = row(id, state, opened, closed);
        connection.process_name = Some("curl".into());
        connection.process_path = Some("/usr/bin/curl".into());
        connection.host = Some("example.com".into());
        connection.rule = Some("rule-1".into());
        connection.outbound = "Proxy".into();
        connection
    }

    #[test]
    fn rows_and_the_texts_they_have_in_common_are_shared() {
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![
                of_a_program("a", TrafficConnectionState::Completed, 1),
                of_a_program("b", TrafficConnectionState::Completed, 2),
            ],
            3,
        );
        // A table's rows are the history's own.
        let table = view(&history);
        assert!(Arc::ptr_eq(&table[0], &view(&history)[0]));
        // What both rows say is said once.
        let (a, b) = (&table[1], &table[0]);
        assert_eq!((&*a.id, &*b.id), ("a", "b"));
        assert!(Arc::ptr_eq(&a.outbound, &b.outbound));
        assert!(Arc::ptr_eq(&a.destination, &b.destination));
        for (one, other) in [
            (&a.process_name, &b.process_name),
            (&a.process_path, &b.process_path),
            (&a.host, &b.host),
            (&a.rule, &b.rule),
        ] {
            assert!(Arc::ptr_eq(one.as_ref().unwrap(), other.as_ref().unwrap()));
        }
        // The id a row is found by is the row's own.
        let (key, entry) = history.entries.get_key_value("a").unwrap();
        assert!(Arc::ptr_eq(key, &entry.row.id));
    }

    #[test]
    fn a_row_that_moves_on_keeps_its_place_unless_a_table_holds_it() {
        let mut history = ConnectionHistory::default();
        let live = |bytes: u64| {
            let mut connection = of_a_program("a", TrafficConnectionState::Active, 1);
            connection.download_bytes = bytes;
            connection
        };
        history.absorb(vec![live(0)], 1);
        let place = Arc::as_ptr(&history.entries["a"].row);
        let shared = Arc::as_ptr(&history.entries["a"].row.outbound);

        // Nothing else holds the row: it takes the new figures where it is.
        history.absorb(vec![live(10)], 2);
        let entry = &history.entries["a"];
        assert_eq!(entry.row.download_bytes, 10);
        assert_eq!(Arc::as_ptr(&entry.row), place);
        assert_eq!(Arc::as_ptr(&entry.row.outbound), shared);
        assert!(Arc::ptr_eq(
            history.entries.get_key_value("a").unwrap().0,
            &entry.row.id
        ));

        // A table holds it: the table keeps what it showed until it asks.
        let table = view(&history);
        history.absorb(vec![live(20)], 3);
        assert_eq!(table[0].download_bytes, 10);
        assert_eq!(history.entries["a"].row.download_bytes, 20);
        assert_eq!(view(&history)[0].download_bytes, 20);
        // The same holds for a row whose result was never seen.
        let table = view(&history);
        history.absorb(Vec::new(), 4);
        assert_eq!(table[0].state, TrafficConnectionState::Active);
        assert_eq!(view(&history)[0].state, TrafficConnectionState::Unknown);
    }

    #[test]
    fn the_texts_nothing_carries_any_more_are_dropped() {
        let mut texts = SharedTexts::default();
        let mut carried: Vec<Arc<str>> = Vec::new();
        for index in 0..10_000 {
            let mut text: Arc<str> = format!("text-{index}").into();
            texts.share(&mut text);
            // One text in a hundred stays with a row.
            if index % 100 == 0 {
                carried.push(text);
            }
        }
        assert!(
            texts.kept.len() <= 2 * carried.len() + SharedTexts::SMALL,
            "{} kept for {} carried",
            texts.kept.len(),
            carried.len()
        );
        for text in &carried {
            let mut again: Arc<str> = text.to_string().into();
            texts.share(&mut again);
            assert!(Arc::ptr_eq(&again, text));
        }
    }

    #[test]
    fn rows_that_closed_first_go_first_past_the_cap() {
        let mut history = ConnectionHistory::default();
        // Closed in the reverse of the order they are handed over in.
        let rows = (0..HISTORY_CAP + 3)
            .map(|index| {
                let closed = (HISTORY_CAP + 3 - index) as i64;
                row(
                    &format!("tcp-{index}"),
                    TrafficConnectionState::Completed,
                    0,
                    Some(closed),
                )
            })
            .collect();
        history.absorb(rows, 99_999);
        let mut removed = history.changes_since(Some(0)).removed;
        removed.sort();
        let last = HISTORY_CAP + 2;
        assert_eq!(
            removed,
            [last - 2, last - 1, last]
                .map(|index| Arc::<str>::from(format!("tcp-{index}")))
                .to_vec()
        );
        assert_eq!(history.entries.len(), HISTORY_CAP);
    }

    #[test]
    fn each_connection_counts_one_hit_for_the_running_profile() {
        let ruled = |id: &str, state, opened_at, closed_at, rule: Option<&str>| {
            let mut connection = row(id, state, opened_at, closed_at);
            connection.rule = rule.map(Into::into);
            connection
        };
        let mut history = ConnectionHistory::default();
        history.absorb(
            vec![ruled(
                "tcp-0",
                TrafficConnectionState::Active,
                90,
                None,
                Some("MATCH,DIRECT"),
            )],
            90,
        );
        assert!(history.rule_hits("a").is_empty(), "no profile, no hits");

        history.set_profile(Some("a".into()));
        let first = vec![
            ruled(
                "tcp-1",
                TrafficConnectionState::Active,
                100,
                None,
                Some("MATCH,DIRECT"),
            ),
            ruled(
                "tcp-2",
                TrafficConnectionState::Active,
                100,
                None,
                Some("MATCH,DIRECT"),
            ),
            ruled(
                "tcp-3",
                TrafficConnectionState::Active,
                100,
                None,
                Some("rule-1"),
            ),
            ruled("tcp-4", TrafficConnectionState::Active, 100, None, None),
        ];
        history.absorb(first, 100);
        // Updates and terminal records of the same connections count nothing,
        // and a reused id is a new connection.
        let mut busier = ruled(
            "tcp-1",
            TrafficConnectionState::Active,
            100,
            None,
            Some("MATCH,DIRECT"),
        );
        busier.download_bytes = 10;
        history.absorb(
            vec![
                busier,
                ruled(
                    "tcp-2",
                    TrafficConnectionState::Completed,
                    100,
                    Some(101),
                    Some("MATCH,DIRECT"),
                ),
                ruled(
                    "tcp-3",
                    TrafficConnectionState::Active,
                    102,
                    None,
                    Some("rule-1"),
                ),
            ],
            102,
        );
        let hits = history.rule_hits("a");
        assert_eq!(hits.get("MATCH,DIRECT"), Some(&2));
        assert_eq!(hits.get("rule-1"), Some(&2));
        assert_eq!(hits.len(), 2);

        history.set_profile(Some("b".into()));
        history.absorb(
            vec![ruled(
                "tcp-5",
                TrafficConnectionState::Active,
                103,
                None,
                Some("MATCH,DIRECT"),
            )],
            103,
        );
        assert_eq!(history.rule_hits("b").get("MATCH,DIRECT"), Some(&1));
        assert_eq!(history.rule_hits("a").get("MATCH,DIRECT"), Some(&2));

        history.reset_rule_hits("a");
        assert!(history.rule_hits("a").is_empty());
        assert_eq!(history.rule_hits("b").len(), 1);
    }
}
