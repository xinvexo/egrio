//! What a full table gives up: exchanges that ended, and preparations that
//! outlasted any that could still work.

use super::*;

pub(super) fn is_idle_since(last_active_unix: i64, now: i64) -> bool {
    now.saturating_sub(last_active_unix) > UDP_SESSION_IDLE_SECONDS
}

/// The least recently active reclaimable sessions other than `keep`'s give
/// way: a batch of them, then more while `full` still holds. Without it,
/// one-shot exchanges would hold their slots and sockets for the whole idle
/// timeout and refuse every new flow meanwhile.
/// They leave the table at once and end as [`Reclaimed`].
pub(super) fn reclaim_sessions(
    entries: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    keep: &UdpSessionKey,
    now: i64,
    full: impl Fn(&HashMap<UdpSessionKey, UdpSessionEntry>) -> bool,
) -> Vec<UdpSessionEntry> {
    let mut stale: Vec<(i64, UdpSessionKey)> = entries
        .iter()
        .filter(|(key, entry)| *key != keep && entry.reclaimable(now))
        .map(|(key, entry)| (entry.last_active_unix(), key.clone()))
        .collect();
    let batch = UDP_RECLAIM_BATCH.min(stale.len());
    if batch < stale.len() {
        stale.select_nth_unstable_by_key(batch, |(at, _)| *at);
    }
    let (first, rest) = stale.split_at_mut(batch);
    let mut reclaimed = Vec::with_capacity(batch);
    for (_, key) in first.iter() {
        reclaimed.extend(reclaim_session(entries, key));
    }
    if full(entries) {
        rest.sort_unstable_by_key(|(at, _)| *at);
        for (_, key) in rest.iter() {
            if !full(entries) {
                break;
            }
            reclaimed.extend(reclaim_session(entries, key));
        }
    }
    reclaimed
}

fn reclaim_session(
    entries: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
    key: &UdpSessionKey,
) -> Option<UdpSessionEntry> {
    let mut entry = entries.remove(key)?;
    for socket in entry.sockets.values().chain(entry.retired_sockets.iter()) {
        socket.reclaim();
    }
    entry.reclaim_preparations();
    Some(entry)
}

/// Sessions the table reclaimed during one admission. Dropped after the
/// table's lock on every way out of admission, it ends their actors and frees
/// them in a task of their own: aborting a task schedules it and may wake a
/// worker, and freeing a session drops its mailbox, waking its actor. Done
/// by the packet pump a batch at a time, under the lock, this was four tenths
/// of its admission work in a storm of new flows.
pub(super) struct Reclaimed<'a> {
    pub(super) runtime: &'a NativeCoreRuntime,
    pub(super) entries: Vec<UdpSessionEntry>,
}

impl Drop for Reclaimed<'_> {
    fn drop(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let entries = std::mem::take(&mut self.entries);
        self.runtime.task_tracker().spawn(async move {
            for entry in &entries {
                for socket in entry.sockets.values().chain(entry.retired_sockets.iter()) {
                    socket.actor_task.abort();
                }
            }
        });
    }
}

#[cfg(feature = "bench-internals")]
pub(super) fn evict_oldest_session(
    sessions: &mut HashMap<UdpSessionKey, UdpSessionEntry>,
) -> Option<UdpSessionEntry> {
    let oldest_key = sessions
        .iter()
        .min_by_key(|(_, entry)| entry.stats.updated_at_unix)
        .map(|(key, _)| key.clone())?;
    sessions.remove(&oldest_key)
}
