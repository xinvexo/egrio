//! Policy-group runtime: compiled group topology, durable
//! selector/health state, dial-time group resolution, and health-probe
//! planning.
//!
//! Groups are virtual outbounds. The snapshot keeps them as a name graph and
//! every dial resolves the routed name to a concrete outbound at that moment,
//! so a group's answer reflects live health and the user's selection instead
//! of a value frozen at compile time. Health state lives outside the snapshot
//! (in [`GroupStateTable`]) because it must survive profile hot swaps.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::outbound::OutboundTable;
use crate::profile::{PolicyGroupKind, RuntimeProfile};
use crate::target::ConnectTarget;

/// Consecutive dial failures before a proxy outbound is ejected
/// (HAProxy-style "fall" threshold).
pub(crate) const OUTBOUND_FALL_THRESHOLD: u32 = 3;
/// Consecutive dial successes before an ejected outbound is marked healthy
/// again (HAProxy-style "rise" threshold).
pub(crate) const OUTBOUND_RISE_THRESHOLD: u32 = 2;
/// How long an ejection keeps the outbound out of group resolution. After
/// expiry the outbound is half-open: selectable again, re-ejected by the
/// next failure, fully healthy after the rise threshold.
pub(crate) const OUTBOUND_EJECTION_SECONDS: i64 = 30;
/// Hard cap on group-resolution recursion, over and above path cycle
/// detection, so a pathological profile cannot exhaust the stack.
pub(crate) const MAX_GROUP_RESOLVE_DEPTH: usize = 64;
/// UrlTest debounce: the current pick is kept unless a competitor's EWMA
/// beats it by more than this margin, so two nodes trading a few
/// milliseconds do not flap the group choice.
pub(crate) const URL_TEST_TOLERANCE_MICROS: u64 = 30_000;
/// Probe period for groups that do not declare `interval_seconds`.
pub(crate) const DEFAULT_PROBE_INTERVAL_SECS: u64 = 300;
/// Probe URL for groups that do not declare `test_url`.
pub const DEFAULT_PROBE_TEST_URL: &str = "http://www.gstatic.com/generate_204";
/// Whole-probe budget (dial + handshake + first response byte).
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Compiled policy-group topology: declared member order is preserved and
/// drives Fallback priority and tie-breaks. Immutable once compiled into a
/// snapshot.
#[derive(Debug, Clone)]
pub(crate) struct CompiledPolicyGroup {
    pub(crate) kind: PolicyGroupKind,
    pub(crate) members: Vec<String>,
    pub(crate) interval_seconds: Option<u64>,
    pub(crate) test_url: Option<String>,
    /// The profile-carried initial selection for Select groups; the durable
    /// selection in [`GroupStateTable`] takes precedence once set.
    pub(crate) selected: Option<String>,
    /// The compilation the group is of: the groups of one snapshot share
    /// it, and no other compilation in the process has it. It is how the
    /// state every snapshot shares tells whose groups an answer it keeps is
    /// for.
    topology: u64,
}

/// A number for one compilation of groups.
fn next_topology() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn compile_policy_groups(
    profile: &RuntimeProfile,
) -> HashMap<String, CompiledPolicyGroup> {
    let topology = next_topology();
    profile
        .groups
        .iter()
        .map(|group| {
            (
                group.name.clone(),
                CompiledPolicyGroup {
                    kind: group.kind.clone(),
                    members: group.members.clone(),
                    interval_seconds: group.interval_seconds,
                    test_url: group.test_url.clone(),
                    selected: group.selected.clone(),
                    topology,
                },
            )
        })
        .collect()
}

/// Durable group runtime state: the user's persistent selector choices,
/// UrlTest sticky picks, and per-outbound health. Survives snapshot swaps so
/// a profile re-apply neither forgets the user's selection nor amnesties a
/// dead node. Cloning shares the underlying table.
///
/// Bounds: every key is a group or outbound name from a compiled profile;
/// [`GroupStateTable::prune_unknown`] runs on each snapshot swap, so the
/// table stays bounded by the live profile instead of accumulating names
/// across profile churn.
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupStateTable {
    inner: Arc<Mutex<GroupState>>,
    /// Advances whenever a change can make a group resolve to another
    /// member: a selection, a UrlTest pick, an ejection set or lifted, or a
    /// reset. An ejection that simply runs out advances nothing; a
    /// resolution reports when the earliest one it depended on does (see
    /// [`resolve_outbound_until`]).
    version: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct GroupState {
    selections: HashMap<String, String>,
    url_test_picks: HashMap<String, String>,
    health: HashMap<String, OutboundHealth>,
    /// What each group last resolved to, kept while it stands.
    resolved: HashMap<String, Resolved>,
}

/// The node a group resolved to, kept for the flows routed to the group
/// after the one that walked it. A walk of a UrlTest group looks at every
/// member, in the state's lock, and a UDP flow walks it again to learn
/// whether the node takes UDP. The cached answer stands until
/// something a walk reads changes, and each such change is told apart:
///
/// - a selection, a pick, an ejection set or lifted, a reset: the state's
///   version moves;
/// - an ejection the walk stepped around running out: `until` passes;
/// - a probe's latency, which moves no version: the kept answers are dropped
///   (see [`GroupStateTable::record_probe_success`]);
/// - another snapshot's groups: `topology` differs.
///
/// A walk through a LoadBalance group gives each target its own node and is
/// not kept.
#[derive(Debug)]
struct Resolved {
    /// The compilation of the groups the walk went through.
    topology: u64,
    version: u64,
    /// When the walk was made: an earlier moment may have stepped around an
    /// ejection this one no longer saw.
    from: i64,
    until: i64,
    concrete: String,
}

impl GroupState {
    fn effective_selection(&self, name: &str, group: &CompiledPolicyGroup) -> Option<String> {
        self.selections
            .get(name)
            .filter(|member| group.members.contains(member))
            .or_else(|| {
                group
                    .selected
                    .as_ref()
                    .filter(|member| group.members.contains(member))
            })
            .or_else(|| group.members.first())
            .cloned()
    }

    fn probe_ewma_micros(&self, outbound: &str) -> Option<u64> {
        self.health
            .get(outbound)
            .and_then(|health| health.ewma_probe_micros)
    }

    /// When the outbound's ejection runs out, while it lasts at `now_unix`.
    /// An expired ejection is half-open and therefore selectable.
    fn ejected_until(&self, outbound: &str, now_unix: i64) -> Option<i64> {
        self.health
            .get(outbound)
            .map(|health| health.ejected_until_unix)
            .filter(|until| *until > now_unix)
    }

    /// Whether the pick changed.
    fn set_url_test_pick(&mut self, group: &str, member: &str) -> bool {
        if self.url_test_picks.get(group).map(String::as_str) == Some(member) {
            return false;
        }
        self.url_test_picks.insert(group.into(), member.into());
        true
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct OutboundHealth {
    pub(crate) consecutive_failures: u32,
    pub(crate) consecutive_successes: u32,
    pub(crate) ejected_until_unix: i64,
    /// EWMA of active-probe latency. Passive dial outcomes feed the streaks
    /// but not the EWMA: dial latency and full-probe latency are not
    /// comparable samples.
    pub(crate) ewma_probe_micros: Option<u64>,
}

impl OutboundHealth {
    /// Whether an ejection was lifted.
    fn mark_success(&mut self) -> bool {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        let lifted =
            self.consecutive_successes >= OUTBOUND_RISE_THRESHOLD && self.ejected_until_unix != 0;
        if lifted {
            self.ejected_until_unix = 0;
        }
        lifted
    }

    /// Whether the outbound was ejected.
    fn mark_failure(&mut self, now_unix: i64) -> bool {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let ejected = self.consecutive_failures >= OUTBOUND_FALL_THRESHOLD;
        if ejected {
            self.ejected_until_unix = now_unix + OUTBOUND_EJECTION_SECONDS;
        }
        ejected
    }
}

impl GroupStateTable {
    /// See the `version` field: a resolution made at one version holds until
    /// it changes, unless an ejection runs out meanwhile.
    pub(crate) fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    fn advance(&self) {
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn select(&self, group: &str, member: &str) {
        let mut state = self.inner.lock().expect("group state mutex");
        state.selections.insert(group.into(), member.into());
        self.advance();
    }

    #[cfg(test)]
    pub(crate) fn selection(&self, group: &str) -> Option<String> {
        let state = self.inner.lock().expect("group state mutex");
        state.selections.get(group).cloned()
    }

    pub(crate) fn effective_selection(
        &self,
        name: &str,
        group: &CompiledPolicyGroup,
    ) -> Option<String> {
        let state = self.inner.lock().expect("group state mutex");
        state.effective_selection(name, group)
    }

    pub(crate) fn record_success(&self, outbound: &str) {
        let mut state = self.inner.lock().expect("group state mutex");
        if state
            .health
            .entry(outbound.into())
            .or_default()
            .mark_success()
        {
            self.advance();
        }
    }

    pub(crate) fn record_failure(&self, outbound: &str, now_unix: i64) {
        let mut state = self.inner.lock().expect("group state mutex");
        if state
            .health
            .entry(outbound.into())
            .or_default()
            .mark_failure(now_unix)
        {
            self.advance();
        }
    }

    pub(crate) fn record_probe_success(&self, outbound: &str, latency: Duration) {
        let sample = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let mut state = self.inner.lock().expect("group state mutex");
        // A latency moves no version, but the next walk of a UrlTest group
        // may pick another node by it.
        state.resolved.clear();
        let health = state.health.entry(outbound.into()).or_default();
        health.ewma_probe_micros = Some(match health.ewma_probe_micros {
            // EWMA with alpha 0.3 in integer math: reacts within a few probes
            // without letting one outlier swing the ranking.
            Some(old) => {
                old.saturating_mul(7)
                    .saturating_add(sample.saturating_mul(3))
                    / 10
            }
            None => sample,
        });
        if health.mark_success() {
            self.advance();
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_ewma_micros(&self, outbound: &str) -> Option<u64> {
        let state = self.inner.lock().expect("group state mutex");
        state.probe_ewma_micros(outbound)
    }

    /// Whether group resolution should skip this outbound. Expired ejections
    /// are half-open and therefore selectable.
    #[cfg(test)]
    pub(crate) fn is_ejected(&self, outbound: &str, now_unix: i64) -> bool {
        let state = self.inner.lock().expect("group state mutex");
        state.ejected_until(outbound, now_unix).is_some()
    }

    /// Read by tests only.
    #[cfg(test)]
    pub(crate) fn health_snapshot(&self, outbound: &str) -> Option<OutboundHealth> {
        let state = self.inner.lock().expect("group state mutex");
        state.health.get(outbound).cloned()
    }

    /// Network-change handling: latency history measured on
    /// the old network is noise on the new one, and ejections earned there
    /// are stale evidence. Drop health and UrlTest picks; keep the user's
    /// explicit selections.
    pub(crate) fn reset_for_network_change(&self) {
        let mut state = self.inner.lock().expect("group state mutex");
        state.health.clear();
        state.url_test_picks.clear();
        state.resolved.clear();
        self.advance();
    }

    /// Drops entries whose group/outbound no longer exists in the published
    /// snapshot. Called on every snapshot swap; this is what keeps the
    /// durable table bounded across profile churn.
    pub(crate) fn prune_unknown(
        &self,
        known_outbound: impl Fn(&str) -> bool,
        known_group: impl Fn(&str) -> bool,
    ) {
        let mut state = self.inner.lock().expect("group state mutex");
        state.selections.retain(|group, _| known_group(group));
        state.url_test_picks.retain(|group, _| known_group(group));
        state.health.retain(|outbound, _| known_outbound(outbound));
        state.resolved.clear();
        self.advance();
    }

    #[cfg(test)]
    pub(crate) fn set_ejected_until_for_test(&self, outbound: &str, until_unix: i64) {
        let mut state = self.inner.lock().expect("group state mutex");
        state
            .health
            .entry(outbound.into())
            .or_default()
            .ejected_until_unix = until_unix;
        self.advance();
    }

    #[cfg(test)]
    fn set_url_test_pick(&self, group: &str, member: &str) {
        let mut state = self.inner.lock().expect("group state mutex");
        if state.set_url_test_pick(group, member) {
            self.advance();
        }
    }

    #[cfg(test)]
    pub(crate) fn set_probe_ewma_for_test(&self, outbound: &str, micros: u64) {
        let mut state = self.inner.lock().expect("group state mutex");
        state.resolved.clear();
        state
            .health
            .entry(outbound.into())
            .or_default()
            .ewma_probe_micros = Some(micros);
    }
}

struct ResolveContext<'a> {
    groups: &'a HashMap<String, CompiledPolicyGroup>,
    outbounds: &'a OutboundTable,
    /// The target being dialled; `None` when a report asks which member a
    /// group uses, where a LoadBalance group has no one answer.
    target: Option<&'a ConnectTarget>,
    now_unix: i64,
    /// Whether a UrlTest pick this walk makes is kept. A report must leave
    /// the sticky pick where the dials put it.
    record_picks: bool,
    /// The earliest moment an ejection this answer stepped around runs out:
    /// the member may be chosen again then.
    until: Cell<i64>,
    /// The walk went through a group that answers by the target.
    by_target: Cell<bool>,
}

impl ResolveContext<'_> {
    fn stepped_around(&self, ejected_until: i64) {
        self.until.set(self.until.get().min(ejected_until));
    }
}

struct MemberCandidate<'m> {
    member: &'m str,
    concrete: String,
    ejected: bool,
}

/// Resolves an outbound name (concrete node or policy group) to the concrete
/// outbound to dial right now. Returns `None` when the name is unknown, the
/// group kind is unsupported (Relay), no member resolves, or the walk hits a
/// cycle or the depth cap.
///
/// Ejection protection (Envoy max-ejection-percent adapted to client-sized
/// groups): health filtering may narrow a group's candidate pool but never
/// empty it — when every member is ejected the full member list is used, so
/// the last available node is effectively never ejected and a dead local
/// network surfaces as connect errors instead of an unresolvable group.
pub(crate) fn resolve_outbound_name(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    state: &GroupStateTable,
    name: &str,
    target: &ConnectTarget,
    now_unix: i64,
) -> Option<String> {
    resolve_outbound_until(groups, outbounds, state, name, target, now_unix).map(|(name, _)| name)
}

/// [`resolve_outbound_name`], with how long the answer stands while the
/// state's version does not move: until the earliest ejection it stepped
/// around runs out (`i64::MAX` when it stepped around none). The whole walk
/// reads the state under one lock.
pub(crate) fn resolve_outbound_until(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    state: &GroupStateTable,
    name: &str,
    target: &ConnectTarget,
    now_unix: i64,
) -> Option<(String, i64)> {
    // A node, or an outbound that rejects, is its own answer for good: the
    // state has nothing to say about it.
    if outbounds.contains_key(name) || crate::rule_engine::is_reject_outbound(name) {
        return Some((name.to_string(), i64::MAX));
    }
    let topology = groups.get(name)?.topology;
    let ctx = ResolveContext {
        groups,
        outbounds,
        target: Some(target),
        now_unix,
        record_picks: true,
        until: Cell::new(i64::MAX),
        by_target: Cell::new(false),
    };
    let mut guard = state.inner.lock().expect("group state mutex");
    // The version moves only inside this lock.
    if let Some(kept) = guard.resolved.get(name) {
        if kept.topology == topology
            && kept.version == state.version()
            && kept.from <= now_unix
            && now_unix < kept.until
        {
            return Some((kept.concrete.clone(), kept.until));
        }
    }
    let mut path = Vec::new();
    let mut picked = false;
    let resolved = resolve_name(&ctx, &mut guard, &mut picked, name, &mut path);
    if picked {
        state.advance();
    }
    let until = ctx.until.get();
    match &resolved {
        Some(concrete) if !ctx.by_target.get() => {
            guard.resolved.insert(
                name.to_string(),
                Resolved {
                    topology,
                    version: state.version(),
                    from: now_unix,
                    until,
                    concrete: concrete.clone(),
                },
            );
        }
        // Whatever was kept for the name no longer stands.
        _ => {
            guard.resolved.remove(name);
        }
    }
    resolved.map(|name| (name, until))
}

/// Whether rule matching may send a UDP flow to `name`: what it resolves to
/// right now has Clash's `udp` on. A name that resolves to no connector
/// (REJECT, an unimplemented node) is taken, so the flow is refused or fails
/// as a TCP flow would.
pub(crate) fn outbound_takes_udp(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    state: &GroupStateTable,
    name: &str,
    target: &ConnectTarget,
) -> bool {
    resolve_outbound_name(groups, outbounds, state, name, target, now_unix())
        .and_then(|resolved| outbounds.get(&resolved))
        .is_none_or(|connector| connector.udp_enabled())
}

fn resolve_name(
    ctx: &ResolveContext<'_>,
    state: &mut GroupState,
    picked: &mut bool,
    name: &str,
    path: &mut Vec<String>,
) -> Option<String> {
    // A rejecting outbound is where a walk ends, as a node is: a group
    // whose choice is `REJECT` refuses its flows.
    if ctx.outbounds.contains_key(name) || crate::rule_engine::is_reject_outbound(name) {
        return Some(name.to_string());
    }
    let group = ctx.groups.get(name)?;
    if path.len() >= MAX_GROUP_RESOLVE_DEPTH || path.iter().any(|seen| seen == name) {
        return None;
    }
    path.push(name.to_string());
    let resolved = resolve_group(ctx, state, picked, name, group, path);
    path.pop();
    resolved
}

fn resolve_group(
    ctx: &ResolveContext<'_>,
    state: &mut GroupState,
    picked: &mut bool,
    name: &str,
    group: &CompiledPolicyGroup,
    path: &mut Vec<String>,
) -> Option<String> {
    let member = chosen_member(ctx, state, picked, name, group, path)?;
    resolve_name(ctx, state, picked, &member, path)
}

/// The member a group dials through right now, as declared in it: a nested
/// group answers with the nested group's name, not the node at the end of
/// it. `None` when no member resolves, the kind dials all of them (Relay)
/// or is unimplemented, or a report asks a LoadBalance group, which maps
/// each target to its own member.
fn chosen_member(
    ctx: &ResolveContext<'_>,
    state: &mut GroupState,
    picked: &mut bool,
    name: &str,
    group: &CompiledPolicyGroup,
    path: &mut Vec<String>,
) -> Option<String> {
    match group.kind {
        // The user's explicit choice is authoritative: Select ignores
        // health. The durable in-core selection wins over the
        // profile-carried initial selection; either that is no longer a
        // member (profile changed) falls through to the first member.
        PolicyGroupKind::Select => state.effective_selection(name, group),
        // Only the members ahead of the chosen one are stepped around: one
        // of them coming back would take over.
        PolicyGroupKind::Fallback => {
            let mut first_resolvable = None;
            for member in &group.members {
                let Some(concrete) = resolve_name(ctx, state, picked, member, path) else {
                    continue;
                };
                let Some(until) = state.ejected_until(&concrete, ctx.now_unix) else {
                    return Some(member.clone());
                };
                ctx.stepped_around(until);
                if first_resolvable.is_none() {
                    first_resolvable = Some(member.clone());
                }
            }
            first_resolvable
        }
        PolicyGroupKind::UrlTest => {
            let pool = candidate_pool(ctx, state, picked, group, path);
            let ewmas: Vec<u64> = pool
                .iter()
                .map(|candidate| {
                    state
                        .probe_ewma_micros(&candidate.concrete)
                        .unwrap_or(u64::MAX)
                })
                .collect();
            // Declared order breaks EWMA ties (index in the key), which also
            // makes an entirely unprobed group deterministic.
            let best = (0..pool.len()).min_by_key(|&index| (ewmas[index], index))?;
            let chosen = state
                .url_test_picks
                .get(name)
                .and_then(|pick| pool.iter().position(|candidate| candidate.member == pick))
                .filter(|&pick| {
                    ewmas[pick] <= ewmas[best].saturating_add(URL_TEST_TOLERANCE_MICROS)
                })
                .unwrap_or(best);
            if ctx.record_picks {
                *picked |= state.set_url_test_pick(name, pool[chosen].member);
            }
            Some(pool[chosen].member.to_string())
        }
        // Rendezvous hashing over member names: the same target maps to the
        // same member for session affinity, and ejecting one member remaps
        // only the targets that were on it.
        PolicyGroupKind::LoadBalance => {
            let target = ctx.target?;
            ctx.by_target.set(true);
            let pool = candidate_pool(ctx, state, picked, group, path);
            let key = format!("{}:{}", target.host, target.port);
            pool.iter()
                .max_by_key(|candidate| rendezvous_score(candidate.member, &key))
                .map(|candidate| candidate.member.to_string())
        }
        PolicyGroupKind::Relay | PolicyGroupKind::Unknown => None,
    }
}

/// Which member a group uses right now, for a host that reports it. Reads
/// the state under one lock and changes none of it, so a report neither
/// moves a UrlTest pick nor advances the version a resolution's lifetime
/// hangs on.
pub(crate) fn group_member_in_use(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    state: &GroupStateTable,
    name: &str,
    now_unix: i64,
) -> Option<String> {
    let group = groups.get(name)?;
    let ctx = ResolveContext {
        groups,
        outbounds,
        target: None,
        now_unix,
        record_picks: false,
        until: Cell::new(i64::MAX),
        by_target: Cell::new(false),
    };
    let mut state = state.inner.lock().expect("group state mutex");
    let mut picked = false;
    let mut path = vec![name.to_string()];
    let member = chosen_member(&ctx, &mut state, &mut picked, name, group, &mut path);
    debug_assert!(!picked, "a report kept no pick");
    member
}

/// Resolvable members with ejected ones filtered out — unless that would
/// empty the pool (see [`resolve_outbound_name`] on ejection protection).
/// Member health is judged on the member's own resolved concrete node, so a
/// nested group counts as unhealthy exactly when what it would dial is.
fn candidate_pool<'g>(
    ctx: &ResolveContext<'_>,
    state: &mut GroupState,
    picked: &mut bool,
    group: &'g CompiledPolicyGroup,
    path: &mut Vec<String>,
) -> Vec<MemberCandidate<'g>> {
    let mut candidates = Vec::with_capacity(group.members.len());
    for member in &group.members {
        let Some(concrete) = resolve_name(ctx, state, picked, member, path) else {
            continue;
        };
        // Any member left out may come back and change the answer.
        let until = state.ejected_until(&concrete, ctx.now_unix);
        if let Some(until) = until {
            ctx.stepped_around(until);
        }
        candidates.push(MemberCandidate {
            member,
            ejected: until.is_some(),
            concrete,
        });
    }
    if candidates.iter().all(|candidate| candidate.ejected) {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|candidate| !candidate.ejected)
        .collect()
}

fn fnv1a_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_extend(0xcbf2_9ce4_8422_2325, bytes)
}

/// Highest-random-weight score; FNV-1a keeps the mapping reproducible across
/// runs (unlike `DefaultHasher`), which is what "same target, same node"
/// needs for login/session affinity. The separator byte keeps
/// ("ab", "c") and ("a", "bc") from colliding.
fn rendezvous_score(member: &str, key: &str) -> u64 {
    let hash = fnv1a(member.as_bytes());
    let hash = fnv1a_extend(hash, &[0xff]);
    fnv1a_extend(hash, key.as_bytes())
}

/// One node's probe schedule, derived from the groups that reference it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundProbePlan {
    /// Concrete node name (groups are flattened to leaves).
    pub(crate) outbound: String,
    pub(crate) test_url: String,
    pub(crate) interval: Duration,
    /// Deterministic per-node offset of the first probe; see [`probe_jitter`].
    pub(crate) initial_jitter: Duration,
}

/// Derives the probe schedule from the compiled groups: health-driven kinds
/// (UrlTest/Fallback/LoadBalance) enroll their concrete member nodes,
/// nested groups are flattened, Select-only members are not probed (the
/// user's manual choice does not consult health). A node referenced by
/// several groups is probed once at the shortest interval.
pub(crate) fn derive_probe_plans(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    node_test_urls: &HashMap<String, String>,
) -> Vec<OutboundProbePlan> {
    let mut plans: HashMap<String, (String, Duration)> = HashMap::new();
    for group in groups.values() {
        if !matches!(
            group.kind,
            PolicyGroupKind::UrlTest | PolicyGroupKind::Fallback | PolicyGroupKind::LoadBalance
        ) {
            continue;
        }
        let interval = Duration::from_secs(
            group
                .interval_seconds
                .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
                .max(1),
        );
        for node in concrete_member_nodes(groups, outbounds, group) {
            // The group's URL, else the node's own, else the default: a node
            // that reaches only some networks names a URL it can reach.
            let test_url = group
                .test_url
                .clone()
                .or_else(|| node_test_urls.get(&node).cloned())
                .unwrap_or_else(|| DEFAULT_PROBE_TEST_URL.to_string());
            plans
                .entry(node)
                .and_modify(|(url, existing)| {
                    if interval < *existing {
                        *existing = interval;
                        url.clone_from(&test_url);
                    }
                })
                .or_insert_with(|| (test_url.clone(), interval));
        }
    }

    let mut plans: Vec<OutboundProbePlan> = plans
        .into_iter()
        .map(|(outbound, (test_url, interval))| OutboundProbePlan {
            initial_jitter: probe_jitter(&outbound, interval),
            outbound,
            test_url,
            interval,
        })
        .collect();
    plans.sort_by(|a, b| a.outbound.cmp(&b.outbound));
    plans
}

fn concrete_member_nodes(
    groups: &HashMap<String, CompiledPolicyGroup>,
    outbounds: &OutboundTable,
    group: &CompiledPolicyGroup,
) -> Vec<String> {
    let mut visited_groups = HashSet::new();
    let mut queue: Vec<&str> = group.members.iter().map(String::as_str).collect();
    let mut nodes = Vec::new();
    while let Some(name) = queue.pop() {
        if outbounds.contains_key(name) {
            nodes.push(name.to_string());
            continue;
        }
        if let Some(nested) = groups.get(name) {
            if visited_groups.insert(name.to_string()) {
                queue.extend(nested.members.iter().map(String::as_str));
            }
        }
    }
    nodes
}

/// Deterministic per-node jitter over half the interval, derived from the
/// node name. N nodes sharing an interval fire spread out instead of in
/// lockstep (the probe-storm valve); hash-based rather than RNG-based so the
/// spread is assertable in tests and identical across restarts.
pub(crate) fn probe_jitter(outbound: &str, interval: Duration) -> Duration {
    let half_millis = (u64::try_from(interval.as_millis()).unwrap_or(u64::MAX) / 2).max(1);
    Duration::from_millis(fnv1a(outbound.as_bytes()) % half_millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_moves_only_on_changes_that_can_change_a_choice() {
        let groups = GroupStateTable::default();
        let start = groups.version();
        groups.record_success("node");
        groups.record_success("node");
        assert_eq!(
            groups.version(),
            start,
            "a healthy node's successes change no choice"
        );
        groups.select("Proxy", "node");
        let selected = groups.version();
        assert_ne!(selected, start);
        for _ in 0..OUTBOUND_FALL_THRESHOLD - 1 {
            groups.record_failure("node", 100);
        }
        assert_eq!(groups.version(), selected, "failures short of an ejection");
        groups.record_failure("node", 100);
        let ejected = groups.version();
        assert_ne!(ejected, selected, "the ejection");
        groups.record_success("node");
        assert_eq!(groups.version(), ejected);
        groups.record_success("node");
        assert_ne!(groups.version(), ejected, "the ejection is lifted");
    }

    const NOW: i64 = 1_000;

    fn direct_outbounds(names: &[&str]) -> OutboundTable {
        let direct: std::sync::Arc<dyn crate::outbound::OutboundConnector> =
            std::sync::Arc::new(crate::outbound::DirectConnector);
        names
            .iter()
            .map(|name| ((*name).to_string(), std::sync::Arc::clone(&direct)))
            .collect()
    }

    fn group(kind: PolicyGroupKind, members: &[&str]) -> CompiledPolicyGroup {
        CompiledPolicyGroup {
            kind,
            members: members.iter().map(|member| (*member).to_string()).collect(),
            interval_seconds: None,
            test_url: None,
            selected: None,
            topology: next_topology(),
        }
    }

    /// How long an answer stands: until the earliest ejection it stepped
    /// around runs out, and for ever when it stepped around none.
    #[test]
    fn an_answer_stands_until_an_ejection_it_stepped_around_runs_out() {
        let outbounds = direct_outbounds(&["a", "b", "c"]);
        let groups = HashMap::from([
            (
                "Pick".to_string(),
                group(PolicyGroupKind::Select, &["a", "b"]),
            ),
            (
                "Fall".to_string(),
                group(PolicyGroupKind::Fallback, &["a", "b", "c"]),
            ),
            (
                "Fast".to_string(),
                group(PolicyGroupKind::UrlTest, &["a", "b", "c"]),
            ),
            (
                "Spread".to_string(),
                group(PolicyGroupKind::LoadBalance, &["a", "b", "c"]),
            ),
            (
                "Outer".to_string(),
                group(PolicyGroupKind::Select, &["Fall"]),
            ),
        ]);
        let state = GroupStateTable::default();
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let until = |name: &str| {
            resolve_outbound_until(&groups, &outbounds, &state, name, &target, NOW)
                .map(|(_, until)| until)
        };
        for name in ["Pick", "Fall", "Fast", "Spread", "Outer"] {
            assert_eq!(until(name), Some(i64::MAX), "{name}: nothing ejected");
        }

        // Ejections behind Fallback's choice cannot change it; one ahead can.
        state.set_ejected_until_for_test("c", NOW + 50);
        assert_eq!(until("Fall"), Some(i64::MAX));
        state.set_ejected_until_for_test("a", NOW + 20);
        assert_eq!(
            resolve_outbound_until(&groups, &outbounds, &state, "Fall", &target, NOW),
            Some(("b".to_string(), NOW + 20))
        );
        assert_eq!(until("Outer"), Some(NOW + 20), "through a nested group");
        // Any member left out of a pool may come back and change it.
        assert_eq!(until("Fast"), Some(NOW + 20));
        assert_eq!(until("Spread"), Some(NOW + 20));
        // Select ignores health.
        assert_eq!(until("Pick"), Some(i64::MAX));
        // Once the earlier ejection ran out, the later one bounds the answer.
        assert_eq!(
            resolve_outbound_until(&groups, &outbounds, &state, "Fall", &target, NOW + 20),
            Some(("a".to_string(), i64::MAX))
        );
        assert_eq!(
            resolve_outbound_until(&groups, &outbounds, &state, "Fast", &target, NOW + 20)
                .map(|(_, until)| until),
            Some(NOW + 50)
        );
    }

    /// The flows after the one that walked a group take the answer it left,
    /// for as long as nothing a walk reads has changed.
    #[test]
    fn a_resolution_is_kept_until_something_a_walk_reads_changes() {
        let outbounds = direct_outbounds(&["a", "b", "c"]);
        let groups = HashMap::from([
            (
                "Fast".to_string(),
                group(PolicyGroupKind::UrlTest, &["a", "b", "c"]),
            ),
            (
                "Outer".to_string(),
                group(PolicyGroupKind::Select, &["Fast", "a"]),
            ),
            (
                "Spread".to_string(),
                group(PolicyGroupKind::LoadBalance, &["a", "b", "c"]),
            ),
            (
                "Empty".to_string(),
                group(PolicyGroupKind::Select, &["missing"]),
            ),
        ]);
        let state = GroupStateTable::default();
        let kept = |name: &str| {
            state
                .inner
                .lock()
                .unwrap()
                .resolved
                .get(name)
                .map(|kept| kept.concrete.clone())
        };
        let target = ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        let at = |name: &str, now: i64| {
            resolve_outbound_until(&groups, &outbounds, &state, name, &target, now)
        };
        let node = |name: &str, now: i64| at(name, now).map(|(node, _)| node);

        state.set_probe_ewma_for_test("b", 100_000);
        assert_eq!(at("Outer", NOW), Some(("b".into(), i64::MAX)));
        assert_eq!(kept("Outer").as_deref(), Some("b"));
        assert_eq!(kept("Fast"), None, "only the name asked for is kept");
        assert_eq!(at("Outer", NOW + 5), Some(("b".into(), i64::MAX)));

        // A node and a name nothing has need no walk and keep nothing; a
        // group that maps each target to its own node, or resolves to
        // nothing, keeps nothing either.
        assert_eq!(at("a", NOW), Some(("a".into(), i64::MAX)));
        assert_eq!(at("REJECT", NOW), Some(("REJECT".into(), i64::MAX)));
        assert_eq!(at("Nothing", NOW), None);
        assert!(at("Spread", NOW).is_some());
        assert_eq!(at("Empty", NOW), None);
        for name in ["a", "REJECT", "Nothing", "Spread", "Empty"] {
            assert_eq!(kept(name), None, "{name}");
        }

        // A probe's latency moves no version, and the next walk picks by it.
        let version = state.version();
        state.record_probe_success("c", Duration::from_micros(1));
        assert_eq!(state.version(), version);
        assert_eq!(kept("Outer"), None);
        assert_eq!(node("Outer", NOW).as_deref(), Some("c"));

        // A selection moves the version.
        state.select("Outer", "a");
        assert_eq!(node("Outer", NOW).as_deref(), Some("a"));
        state.select("Outer", "Fast");
        assert_eq!(node("Outer", NOW).as_deref(), Some("c"));

        // An ejection the walk stepped around bounds the answer in time,
        // and an answer made later says nothing of an earlier moment.
        state.set_ejected_until_for_test("c", NOW + 20);
        assert_eq!(at("Outer", NOW), Some(("b".into(), NOW + 20)));
        assert_eq!(at("Outer", NOW + 19), Some(("b".into(), NOW + 20)));
        assert_eq!(at("Outer", NOW + 20), Some(("c".into(), i64::MAX)));
        assert_eq!(at("Outer", NOW), Some(("b".into(), NOW + 20)));

        // Other groups under the same state are another topology.
        let other = HashMap::from([("Outer".to_string(), group(PolicyGroupKind::Select, &["c"]))]);
        assert_eq!(
            resolve_outbound_until(&other, &outbounds, &state, "Outer", &target, NOW),
            Some(("c".into(), i64::MAX))
        );
        assert_eq!(at("Outer", NOW), Some(("b".into(), NOW + 20)));
    }

    #[test]
    fn select_group_initial_selection_applies_until_a_durable_choice_lands() {
        let outbounds = direct_outbounds(&["node-a", "node-b"]);
        let mut select = group(PolicyGroupKind::Select, &["node-a", "node-b"]);
        select.selected = Some("node-b".into());
        let groups = HashMap::from([("Exit".to_string(), select)]);
        let state = GroupStateTable::default();

        // The profile-carried initial selection wins over declared order.
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Exit", "example.com"),
            Some("node-b".into())
        );

        // A durable in-core selection takes precedence once set.
        state.select("Exit", "node-a");
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Exit", "example.com"),
            Some("node-a".into())
        );
    }

    #[test]
    fn select_group_ignores_an_initial_selection_that_is_not_a_member() {
        let outbounds = direct_outbounds(&["node-a", "node-b"]);
        let mut select = group(PolicyGroupKind::Select, &["node-a", "node-b"]);
        select.selected = Some("node-gone".into());
        let groups = HashMap::from([("Exit".to_string(), select)]);
        let state = GroupStateTable::default();

        assert_eq!(
            resolve(&groups, &outbounds, &state, "Exit", "example.com"),
            Some("node-a".into())
        );
    }

    fn resolve(
        groups: &HashMap<String, CompiledPolicyGroup>,
        outbounds: &OutboundTable,
        state: &GroupStateTable,
        name: &str,
        host: &str,
    ) -> Option<String> {
        resolve_outbound_name(
            groups,
            outbounds,
            state,
            name,
            &ConnectTarget {
                host: host.into(),
                port: 443,
            },
            NOW,
        )
    }

    #[test]
    fn ejects_after_fall_threshold_and_half_opens_after_ttl() {
        let table = GroupStateTable::default();

        table.record_failure("proxy-a", NOW);
        table.record_failure("proxy-a", NOW);
        assert!(!table.is_ejected("proxy-a", NOW), "below fall threshold");

        table.record_failure("proxy-a", NOW);
        assert!(table.is_ejected("proxy-a", NOW), "fall threshold ejects");

        let after_ttl = NOW + OUTBOUND_EJECTION_SECONDS + 1;
        assert!(
            !table.is_ejected("proxy-a", after_ttl),
            "expired ejection is half-open"
        );

        // A failure in half-open re-ejects immediately: the consecutive
        // failure count is already at the threshold.
        table.record_failure("proxy-a", after_ttl);
        assert!(table.is_ejected("proxy-a", after_ttl));
    }

    #[test]
    fn rises_after_consecutive_successes() {
        let table = GroupStateTable::default();
        for _ in 0..OUTBOUND_FALL_THRESHOLD {
            table.record_failure("proxy-a", NOW);
        }
        assert!(table.is_ejected("proxy-a", NOW));

        table.record_success("proxy-a");
        assert!(
            table.is_ejected("proxy-a", NOW),
            "one success is below the rise threshold"
        );
        table.record_success("proxy-a");
        assert!(
            !table.is_ejected("proxy-a", NOW),
            "rise threshold clears the ejection"
        );

        // Recovery also reset the failure streak: one new failure must not
        // re-eject.
        table.record_failure("proxy-a", NOW);
        assert!(!table.is_ejected("proxy-a", NOW));
    }

    #[test]
    fn selection_is_per_group_and_overwritable() {
        let table = GroupStateTable::default();
        assert_eq!(table.selection("Group"), None);

        table.select("Group", "proxy-a");
        assert_eq!(table.selection("Group").as_deref(), Some("proxy-a"));

        table.select("Group", "proxy-b");
        assert_eq!(table.selection("Group").as_deref(), Some("proxy-b"));
        assert_eq!(table.selection("Other"), None);
    }

    #[test]
    fn select_group_honors_selection_and_falls_back_when_stale() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups =
            HashMap::from([("G".to_string(), group(PolicyGroupKind::Select, &["a", "b"]))]);
        let state = GroupStateTable::default();

        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a"),
            "no selection resolves to the first member"
        );

        state.select("G", "b");
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b")
        );

        // Selection ignores health: an ejected node the user picked stays.
        state.set_ejected_until_for_test("b", NOW + 100);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b")
        );

        state.select("G", "removed-node");
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a"),
            "stale selection falls back to the first member"
        );
    }

    /// What a host reports is the member as the group declares it — a
    /// nested group by its own name — and it follows the same health the
    /// dials follow.
    #[test]
    fn a_report_names_the_member_the_group_dials_through() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([
            (
                "Fast".to_string(),
                group(PolicyGroupKind::UrlTest, &["Inner", "b"]),
            ),
            (
                "Fall".to_string(),
                group(PolicyGroupKind::Fallback, &["Inner", "b"]),
            ),
            ("Inner".to_string(), group(PolicyGroupKind::Select, &["a"])),
            (
                "Spread".to_string(),
                group(PolicyGroupKind::LoadBalance, &["a", "b"]),
            ),
            ("Chain".to_string(), group(PolicyGroupKind::Relay, &["a"])),
        ]);
        let state = GroupStateTable::default();
        let report = |name| group_member_in_use(&groups, &outbounds, &state, name, NOW);

        state.set_probe_ewma_for_test("a", 10_000);
        state.set_probe_ewma_for_test("b", 50_000);
        assert_eq!(
            report("Fast").as_deref(),
            Some("Inner"),
            "the fastest member, as the nested group it is, not the node behind it"
        );
        assert_eq!(
            report("Fall").as_deref(),
            Some("Inner"),
            "the first member whose node is not ejected"
        );
        state.set_probe_ewma_for_test("a", 100_000);
        assert_eq!(
            report("Fast").as_deref(),
            Some("b"),
            "the member that is fastest now"
        );
        assert_eq!(
            report("Spread"),
            None,
            "a LoadBalance group maps each target to its own member"
        );
        assert_eq!(report("Chain"), None, "a Relay group dials all of them");
        assert_eq!(report("Nothing"), None, "a name no group has");

        state.set_ejected_until_for_test("a", NOW + 100);
        assert_eq!(
            report("Fast").as_deref(),
            Some("b"),
            "an ejected member is not reported"
        );
        assert_eq!(
            report("Fall").as_deref(),
            Some("b"),
            "the Fallback report steps around the ejected member's group"
        );
    }

    /// A report is an observation: the pick a UrlTest group dials through
    /// and the version a resolution's lifetime hangs on are the dials' to
    /// move.
    #[test]
    fn a_report_leaves_the_sticky_pick_and_the_version_alone() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([(
            "Fast".to_string(),
            group(PolicyGroupKind::UrlTest, &["a", "b"]),
        )]);
        let state = GroupStateTable::default();
        state.set_probe_ewma_for_test("a", 100_000);
        state.set_probe_ewma_for_test("b", 50_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Fast", "x").as_deref(),
            Some("b"),
            "the dial picks the fastest"
        );

        // "a" comes back inside the tolerance band of the pick: both the
        // dial and the report keep the member in use.
        state.set_probe_ewma_for_test("a", 45_000);
        assert_eq!(
            group_member_in_use(&groups, &outbounds, &state, "Fast", NOW).as_deref(),
            Some("b"),
            "the report reads the pick the dials made"
        );
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Fast", "x").as_deref(),
            Some("b"),
            "improvement inside the band does not move the pick"
        );

        // "a" improves decisively. The report says what the next dial
        // would use, and moves nothing: the version is what sends the
        // flows already routed through the group to another member.
        state.set_probe_ewma_for_test("a", 10_000);
        let version = state.version();
        assert_eq!(
            group_member_in_use(&groups, &outbounds, &state, "Fast", NOW).as_deref(),
            Some("a")
        );
        assert_eq!(state.version(), version, "a report advances nothing");
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Fast", "x").as_deref(),
            Some("a"),
            "the dial is what moves the pick"
        );
        assert_ne!(state.version(), version, "and what sends the flows over");
    }

    #[test]
    fn fallback_prefers_declared_order_and_skips_ejected() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([(
            "G".to_string(),
            group(PolicyGroupKind::Fallback, &["a", "b"]),
        )]);
        let state = GroupStateTable::default();

        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a")
        );

        state.set_ejected_until_for_test("a", NOW + 100);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b"),
            "ejected primary fails over to the backup"
        );

        // Ejection protection: with every member ejected the group still
        // resolves (declared order) instead of going dark.
        state.set_ejected_until_for_test("b", NOW + 100);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a"),
            "ejection never empties a group"
        );
    }

    #[test]
    fn url_test_prefers_lowest_ewma_and_tolerance_prevents_flapping() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([(
            "G".to_string(),
            group(PolicyGroupKind::UrlTest, &["a", "b"]),
        )]);
        let state = GroupStateTable::default();

        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a"),
            "unprobed group resolves in declared order"
        );

        state.set_probe_ewma_for_test("a", 100_000);
        state.set_probe_ewma_for_test("b", 50_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b"),
            "lowest EWMA wins"
        );

        // "a" improves to within the tolerance band of the current pick:
        // the pick must not flap.
        state.set_probe_ewma_for_test("a", 45_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b"),
            "improvement inside the tolerance band does not switch"
        );

        // "a" improves decisively: switch.
        state.set_probe_ewma_for_test("a", 15_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a")
        );

        // And the reverse jitter within tolerance keeps the new pick.
        state.set_probe_ewma_for_test("b", 40_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a")
        );
    }

    #[test]
    fn url_test_skips_ejected_pick() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([(
            "G".to_string(),
            group(PolicyGroupKind::UrlTest, &["a", "b"]),
        )]);
        let state = GroupStateTable::default();
        state.set_probe_ewma_for_test("a", 10_000);
        state.set_probe_ewma_for_test("b", 50_000);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("a")
        );

        state.set_ejected_until_for_test("a", NOW + 100);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "G", "x").as_deref(),
            Some("b"),
            "ejected pick is abandoned even though its EWMA is best"
        );
    }

    #[test]
    fn load_balance_is_sticky_per_target_and_remaps_only_ejected_targets() {
        let outbounds = direct_outbounds(&["a", "b", "c"]);
        let groups = HashMap::from([(
            "G".to_string(),
            group(PolicyGroupKind::LoadBalance, &["a", "b", "c"]),
        )]);
        let state = GroupStateTable::default();

        let hosts: Vec<String> = (0..24)
            .map(|index| format!("host-{index}.example"))
            .collect();
        let first_pass: Vec<String> = hosts
            .iter()
            .map(|host| resolve(&groups, &outbounds, &state, "G", host).expect("resolves"))
            .collect();
        let second_pass: Vec<String> = hosts
            .iter()
            .map(|host| resolve(&groups, &outbounds, &state, "G", host).expect("resolves"))
            .collect();
        assert_eq!(first_pass, second_pass, "same target maps to same node");
        let distinct: HashSet<&String> = first_pass.iter().collect();
        assert!(
            distinct.len() > 1,
            "targets spread across members, got {distinct:?}"
        );

        state.set_ejected_until_for_test("b", NOW + 100);
        for (host, before) in hosts.iter().zip(&first_pass) {
            let after = resolve(&groups, &outbounds, &state, "G", host).expect("resolves");
            if before == "b" {
                assert_ne!(after, "b", "targets on the ejected node remap");
            } else {
                assert_eq!(
                    &after, before,
                    "targets on healthy nodes must not move when another node is ejected"
                );
            }
        }
    }

    #[test]
    fn nested_groups_resolve_through_leaf_health() {
        let outbounds = direct_outbounds(&["a", "b"]);
        let groups = HashMap::from([
            (
                "Outer".to_string(),
                group(PolicyGroupKind::Fallback, &["Inner", "b"]),
            ),
            ("Inner".to_string(), group(PolicyGroupKind::UrlTest, &["a"])),
        ]);
        let state = GroupStateTable::default();

        assert_eq!(
            resolve(&groups, &outbounds, &state, "Outer", "x").as_deref(),
            Some("a"),
            "nested group resolves to its leaf"
        );

        // The nested group's health is the health of what it would dial:
        // ejecting the leaf fails the outer group over.
        state.set_ejected_until_for_test("a", NOW + 100);
        assert_eq!(
            resolve(&groups, &outbounds, &state, "Outer", "x").as_deref(),
            Some("b")
        );
    }

    #[test]
    fn resolution_survives_cycles_depth_and_unsupported_kinds() {
        let outbounds = direct_outbounds(&["a"]);
        let state = GroupStateTable::default();

        let cyclic = HashMap::from([
            ("A".to_string(), group(PolicyGroupKind::Select, &["B"])),
            ("B".to_string(), group(PolicyGroupKind::Select, &["A"])),
        ]);
        assert_eq!(resolve(&cyclic, &outbounds, &state, "A", "x"), None);

        let mut deep = HashMap::new();
        for index in 0..(MAX_GROUP_RESOLVE_DEPTH + 8) {
            deep.insert(
                format!("G{index}"),
                group(PolicyGroupKind::Select, &[&format!("G{}", index + 1)]),
            );
        }
        assert_eq!(resolve(&deep, &outbounds, &state, "G0", "x"), None);

        let relay = HashMap::from([("R".to_string(), group(PolicyGroupKind::Relay, &["a"]))]);
        assert_eq!(
            resolve(&relay, &outbounds, &state, "R", "x"),
            None,
            "relay groups are not implemented and must fail resolution, not panic"
        );

        assert_eq!(
            resolve(&HashMap::new(), &outbounds, &state, "nope", "x"),
            None
        );
    }

    #[test]
    fn network_change_reset_clears_health_but_keeps_selection() {
        let table = GroupStateTable::default();
        table.select("G", "b");
        table.record_probe_success("a", Duration::from_millis(80));
        for _ in 0..OUTBOUND_FALL_THRESHOLD {
            table.record_failure("b", NOW);
        }
        assert!(table.is_ejected("b", NOW));
        assert!(table.probe_ewma_micros("a").is_some());

        table.reset_for_network_change();

        assert!(!table.is_ejected("b", NOW), "stale ejection cleared");
        assert_eq!(
            table.probe_ewma_micros("a"),
            None,
            "old-network latency history cleared"
        );
        assert_eq!(
            table.selection("G").as_deref(),
            Some("b"),
            "user selection survives network changes"
        );
    }

    #[test]
    fn prune_unknown_drops_stale_names_and_keeps_live_ones() {
        let table = GroupStateTable::default();
        table.select("Live", "a");
        table.select("Gone", "b");
        table.set_url_test_pick("Gone", "b");
        table.record_success("a");
        table.record_success("removed");

        table.prune_unknown(|outbound| outbound == "a", |group| group == "Live");

        assert_eq!(table.selection("Live").as_deref(), Some("a"));
        assert_eq!(table.selection("Gone"), None);
        assert!(table.health_snapshot("a").is_some());
        assert!(table.health_snapshot("removed").is_none());
    }

    #[test]
    fn probe_ewma_blends_toward_new_samples() {
        let table = GroupStateTable::default();
        table.record_probe_success("a", Duration::from_millis(100));
        assert_eq!(table.probe_ewma_micros("a"), Some(100_000));

        table.record_probe_success("a", Duration::from_millis(50));
        assert_eq!(
            table.probe_ewma_micros("a"),
            Some(85_000),
            "EWMA(0.3): 100_000*0.7 + 50_000*0.3"
        );
    }

    #[test]
    fn probe_plans_flatten_groups_dedup_nodes_and_skip_select_only_members() {
        let outbounds = direct_outbounds(&["a", "b", "c", "d", "manual-only"]);
        let mut fast = group(PolicyGroupKind::UrlTest, &["a", "Nested"]);
        fast.interval_seconds = Some(60);
        fast.test_url = Some("http://probe.example/gen204".into());
        let groups = HashMap::from([
            ("Fast".to_string(), fast),
            (
                "Nested".to_string(),
                group(PolicyGroupKind::Fallback, &["b"]),
            ),
            (
                "Slow".to_string(),
                group(PolicyGroupKind::LoadBalance, &["a", "c", "d"]),
            ),
            (
                "Manual".to_string(),
                group(PolicyGroupKind::Select, &["manual-only"]),
            ),
        ]);

        // A node's own URL stands in for a group that names none.
        let node_urls = HashMap::from([
            ("a".to_string(), "http://a.example/".to_string()),
            ("c".to_string(), "http://intranet.example/".to_string()),
        ]);
        let plans = derive_probe_plans(&groups, &outbounds, &node_urls);

        let names: Vec<&str> = plans.iter().map(|plan| plan.outbound.as_str()).collect();
        assert_eq!(
            names,
            vec!["a", "b", "c", "d"],
            "flattened, deduped, sorted"
        );
        let plan_a = plans
            .iter()
            .find(|plan| plan.outbound == "a")
            .expect("a planned");
        assert_eq!(
            plan_a.interval,
            Duration::from_secs(60),
            "node in several groups probes at the shortest interval"
        );
        assert_eq!(
            plan_a.test_url, "http://probe.example/gen204",
            "the group's URL before the node's"
        );
        let plan_b = plans
            .iter()
            .find(|plan| plan.outbound == "b")
            .expect("b planned");
        assert_eq!(
            plan_b.test_url, "http://probe.example/gen204",
            "a nested member probes as the outer group says"
        );
        let plan_d = plans
            .iter()
            .find(|plan| plan.outbound == "d")
            .expect("d planned");
        assert_eq!(plan_d.test_url, DEFAULT_PROBE_TEST_URL);
        let plan_c = plans
            .iter()
            .find(|plan| plan.outbound == "c")
            .expect("c planned");
        assert_eq!(
            plan_c.interval,
            Duration::from_secs(DEFAULT_PROBE_INTERVAL_SECS)
        );
        assert_eq!(plan_c.test_url, "http://intranet.example/");
        assert!(
            !names.contains(&"manual-only"),
            "select-only members are not probed"
        );
        for plan in &plans {
            assert!(plan.initial_jitter < plan.interval / 2 + Duration::from_millis(1));
        }
    }

    #[test]
    fn probe_jitter_desynchronizes_many_nodes() {
        let interval = Duration::from_secs(300);
        let jitters: Vec<Duration> = (0..32)
            .map(|index| probe_jitter(&format!("node-{index}"), interval))
            .collect();

        let distinct: HashSet<Duration> = jitters.iter().copied().collect();
        assert!(
            distinct.len() >= 16,
            "32 nodes must not share a handful of probe slots, got {} distinct",
            distinct.len()
        );
        let min = jitters.iter().min().expect("nonempty");
        let max = jitters.iter().max().expect("nonempty");
        assert!(
            max.saturating_sub(*min) >= interval / 10,
            "jitter must spread probes across the interval, got {min:?}..{max:?}"
        );
        assert!(jitters.iter().all(|jitter| *jitter < interval / 2));
    }
}
