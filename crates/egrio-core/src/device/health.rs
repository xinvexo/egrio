//! The active health-probe subsystem split off `NativeCoreDevice`: the
//! single-shot probe and the scheduler loop, which also takes the egress
//! guard's network changes. The loop waits on `inner.probe_kick`/reads
//! `inner.probe_reset` directly; the `kick_probe_loop` waker stays in
//! `mod.rs` because the lifecycle methods there (apply_config,
//! select_group_member, apply_network_change, close) fire it. Everything
//! else reaches here through `use super::*`.

use tokio::task::{AbortHandle, Id as TaskId, JoinSet};

use super::*;

/// Probes in flight at once. A blackholed node holds its slot for the whole
/// probe budget, so a healthy node due behind many of them waits one budget
/// per this many, not one per node.
pub(super) const MAX_CONCURRENT_PROBES: usize = 8;

impl NativeCoreDevice {
    /// Runs one active health probe of `outbound` (a concrete node, or a
    /// group resolved to one) against `test_url` and records the outcome in
    /// the durable health table. Returns the measured latency.
    pub async fn probe_outbound(&self, outbound: &str, test_url: &str) -> Result<Duration, String> {
        self.ensure_running()?;
        let probe = parse_probe_url(test_url)
            .ok_or_else(|| format!("probe URL '{test_url}' is not supported"))?;
        self.tracked_session(move |runtime| async move {
            let cancel = runtime.connection_cancellation();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err("probe cancelled by connection cutover".into()),
                result = probe_outbound_once(&runtime, outbound, &probe) => result,
            }
        })
        .await
    }

    /// Spawns the health-probe scheduler. One task owns the schedule and
    /// starts due probes earliest first, at most [`MAX_CONCURRENT_PROBES`] at
    /// a time and one per node; a node is due again one interval after its
    /// probe ends. Per-node first-fire jitter keeps N nodes desynchronized.
    /// The schedule is derived again whenever the published snapshot changes,
    /// so profile hot swaps enroll and retire nodes without restarting the
    /// loop, and a retired node's probe is aborted; between swaps a wakeup
    /// costs one pass over the nodes, since every node's due time and every
    /// probe's end wakes the loop. The loop also applies
    /// each network the egress guard publishes (see
    /// [`apply_network_change`](Self::apply_network_change)); a network
    /// change aborts the probes in flight, whose outcome would describe the
    /// old network, and makes every node due at once. The task exits when
    /// the device closes, aborting its probes; aborting the returned handle
    /// is also safe.
    ///
    /// Idempotent per device: exactly one scheduler runs at a time, so the
    /// listener session and the capture pump can share one device (the
    /// Runtime-owned single Core) with both entrypoints spawning
    /// unconditionally. Returns `None` while a previously spawned loop is
    /// still alive.
    pub fn spawn_health_probe_loop(&self) -> Option<tokio::task::JoinHandle<()>> {
        if self
            .inner
            .probe_loop_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        // Drop guard rather than a trailing store: an aborted task never runs
        // code after its await point, but it does drop its future, so the flag
        // clears on normal exit and on abort alike.
        struct ProbeLoopSlot(NativeCoreDevice);
        impl Drop for ProbeLoopSlot {
            fn drop(&mut self) {
                self.0
                    .inner
                    .probe_loop_running
                    .store(false, Ordering::Release);
            }
        }
        let slot = ProbeLoopSlot(self.clone());
        Some(tokio::spawn(async move {
            slot.0.run_health_probe_loop().await;
            drop(slot);
        }))
    }

    async fn run_health_probe_loop(&self) {
        // Idle nodes by due time. A node in flight is only in `in_flight`,
        // so it never runs twice at once.
        let mut next_due: HashMap<String, tokio::time::Instant> = HashMap::new();
        let mut in_flight: HashMap<String, AbortHandle> = HashMap::new();
        // Dropping the set when the loop returns aborts the probes in flight.
        let mut probes = JoinSet::new();
        let mut probe_nodes: HashMap<TaskId, String> = HashMap::new();
        // The schedule's plans by node, and the snapshot they came from. A
        // weak handle: the loop must not keep an old generation alive, and
        // while it exists no new snapshot can take the old one's address.
        let mut plans: HashMap<String, OutboundProbePlan> = HashMap::new();
        let mut planned_from = std::sync::Weak::new();
        let mut network = self
            .inner
            .socket_guard
            .as_ref()
            .and_then(|guard| guard.network());
        let mut known = network
            .as_mut()
            .map(|feed| feed.borrow_and_update().clone())
            .unwrap_or_default();
        let mut awake = crate::suspension::mark();
        loop {
            {
                let state = *self.inner.state.lock().expect("native core device state");
                if matches!(
                    state,
                    NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed
                ) {
                    return;
                }
            }
            // Health measured before the host slept describes a network it
            // may have left; its probe deadlines did not count the sleep.
            if crate::suspension::slept_since(awake) {
                awake = crate::suspension::mark();
                self.apply_network_change(&NetworkChange::default());
            }
            let reset = self.inner.probe_reset.swap(false, Ordering::Relaxed);
            if reset {
                probes.abort_all();
                in_flight.clear();
                probe_nodes.clear();
            }

            let swapped = {
                let snapshot = self.inner.snapshot.load_full();
                let swapped = !std::ptr::eq(planned_from.as_ptr(), Arc::as_ptr(&snapshot));
                if swapped {
                    plans = snapshot
                        .probe_plans()
                        .into_iter()
                        .map(|plan| (plan.outbound.clone(), plan))
                        .collect();
                    planned_from = Arc::downgrade(&snapshot);
                }
                swapped
            };
            let now = tokio::time::Instant::now();
            // Every planned node is either due or in flight; a probe's end
            // moves its node back to due.
            if swapped || reset {
                next_due.retain(|name, _| plans.contains_key(name));
                in_flight.retain(|name, probe| {
                    let keep = plans.contains_key(name);
                    if !keep {
                        probe.abort();
                    }
                    keep
                });
                for plan in plans.values() {
                    if reset {
                        next_due.insert(plan.outbound.clone(), now);
                    } else if !in_flight.contains_key(&plan.outbound) {
                        next_due
                            .entry(plan.outbound.clone())
                            .or_insert(now + plan.initial_jitter);
                    }
                }
            }

            let mut due: Vec<_> = next_due
                .iter()
                .filter(|(_, due)| **due <= now)
                .map(|(name, due)| (*due, name.clone()))
                .collect();
            due.sort();
            let free = MAX_CONCURRENT_PROBES.saturating_sub(in_flight.len());
            for (_, name) in due.into_iter().take(free) {
                next_due.remove(&name);
                let test_url = plans
                    .get(&name)
                    .map(|plan| plan.test_url.clone())
                    .expect("due nodes are planned");
                let (device, outbound) = (self.clone(), name.clone());
                let probe = probes.spawn(async move {
                    // Outcome lands in the health table; failures are the
                    // point of probing, not loop errors.
                    let _ = device.probe_outbound(&outbound, &test_url).await;
                });
                probe_nodes.insert(probe.id(), name.clone());
                in_flight.insert(name, probe);
            }

            // With every slot busy, the next start waits for a probe to end.
            let wake = (in_flight.len() < MAX_CONCURRENT_PROBES)
                .then(|| next_due.values().min().copied())
                .flatten()
                .unwrap_or_else(|| now + Duration::from_secs(DEFAULT_PROBE_INTERVAL_SECS));
            tokio::select! {
                _ = tokio::time::sleep_until(wake) => {}
                Some(ended) = probes.join_next_with_id(), if !probes.is_empty() => {
                    let id = match ended {
                        Ok((id, ())) => id,
                        Err(error) => error.id(),
                    };
                    // A probe aborted by a reset or retirement is no longer
                    // its node's current one and leaves the schedule alone.
                    if let Some(node) = probe_nodes.remove(&id) {
                        if in_flight.get(&node).is_some_and(|probe| probe.id() == id) {
                            in_flight.remove(&node);
                            if let Some(plan) = plans.get(&node) {
                                next_due.insert(node, tokio::time::Instant::now() + plan.interval);
                            }
                        }
                    }
                }
                _ = self.inner.probe_kick.notified() => {}
                current = next_network(&mut network) => match current {
                    Some(current) => {
                        let previous = std::mem::replace(&mut known, current);
                        if previous != known {
                            self.apply_network_change(&NetworkChange::between(&previous, &known));
                        }
                    }
                    None => network = None,
                },
            }
        }
    }
}

/// The next network the egress guard publishes; `None` once its feed ends,
/// and never without one.
async fn next_network(
    feed: &mut Option<tokio::sync::watch::Receiver<EgressNetwork>>,
) -> Option<EgressNetwork> {
    let Some(feed) = feed else {
        return std::future::pending().await;
    };
    match feed.changed().await {
        Ok(()) => Some(feed.borrow_and_update().clone()),
        Err(_) => None,
    }
}
