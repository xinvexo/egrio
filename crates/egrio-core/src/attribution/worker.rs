//! The Core's single attribution worker: a bounded flow cache in front of
//! the platform scanner. The packet gate and the listener only consult the
//! cache and enqueue a bounded request; only this joined thread calls into
//! the platform.
use super::{FlowKey, FlowScanner, ProcessInfo, ATTRIBUTION_BUDGET, RECORD_BUDGET};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::{watch, Notify};

const MAX_ENTRIES: usize = 4096;
const MAX_REQUESTS: usize = 1024;
/// Flows one scan answers: every queued request. A scan's cost is that of
/// walking every socket of the user's processes, hardly that of the flows it
/// answers, so a storm of new flows should cost few scans. Taking every
/// queued request avoids repeated socket-table walks for small batches.
pub(super) const BATCH: usize = MAX_REQUESTS;
const SCAN_BUDGET: Duration = Duration::from_millis(100);
const POSITIVE_TTL: Duration = Duration::from_millis(250);
const NEGATIVE_TTL: Duration = Duration::from_millis(50);
const REQUEST_TTL: Duration = Duration::from_secs(1);
/// How long requests nothing waits on (a connection record filled in later,
/// a datagram that already went on) gather before a scan, so one scan, whose
/// cost hardly depends on the flows it answers, serves several. A request
/// someone waits on starts the scan at once and takes the gathered ones along.
const GATHER: Duration = Duration::from_millis(200);

#[derive(Clone, Debug)]
pub(super) enum Lookup {
    /// Being looked up: the answer the request will get.
    Pending(Arc<Answer>),
    Ready(Option<Arc<ProcessInfo>>),
}

/// One request's answer. Its lookups wait on it alone: one batch notifying
/// every waiter woke thousands of connections' lookups for each batch of a
/// storm, each to find its own flow still pending.
#[derive(Debug, Default)]
pub(super) struct Answer {
    owner: OnceLock<Option<Arc<ProcessInfo>>>,
    given: Notify,
}

impl Answer {
    fn known(owner: Option<Arc<ProcessInfo>>) -> Arc<Self> {
        let answer = Self::default();
        let _ = answer.owner.set(owner);
        Arc::new(answer)
    }

    fn give(&self, owner: Option<Arc<ProcessInfo>>) {
        if self.owner.set(owner).is_ok() {
            self.given.notify_waiters();
        }
    }
}

struct Entry {
    ticket: u64,
    created: Instant,
    result: Option<(Instant, Option<Arc<ProcessInfo>>)>,
    answer: Arc<Answer>,
}
struct Request {
    flow: FlowKey,
    ticket: u64,
    queued: Instant,
    answer: Arc<Answer>,
}
#[derive(Default)]
struct State {
    entries: HashMap<FlowKey, Entry>,
    requests: VecDeque<Request>,
    /// Someone waits on an answer, so the next batch goes without gathering.
    /// One flag rather than a flag per request: it only ever decides that,
    /// and finding the request to mark was a walk of the queue on every look
    /// while the gate looks for each flow it holds on every pump turn. A
    /// batch clears it; a caller still waiting sets it again on its next
    /// look, which is that same turn.
    urgent: bool,
    next: u64,
}
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    stopped: AtomicBool,
    /// Counts completed batches. Every waiter (the packet gate, each
    /// listener lookup) holds its own receiver, so one batch wakes them all
    /// and a batch finishing before a waiter parks is never lost.
    completed: watch::Sender<u64>,
}

pub(crate) struct AttributionWorker {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}
impl std::fmt::Debug for AttributionWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributionWorker").finish_non_exhaustive()
    }
}
impl AttributionWorker {
    /// Thread-creation failure degrades to unknown attribution; it never
    /// prevents a connection from proceeding.
    pub(crate) fn start(scanner: Arc<dyn FlowScanner>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            stopped: AtomicBool::new(false),
            completed: watch::Sender::new(0),
        });
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("egrio-flow-attribution".into())
            .spawn(move || {
                let _exit = WorkerExit(worker_shared.clone());
                run(&worker_shared, scanner.as_ref());
            });
        match worker {
            Ok(worker) => Self {
                shared,
                worker: Some(worker),
            },
            Err(_) => {
                shared.stopped.store(true, Ordering::Release);
                Self {
                    shared,
                    worker: None,
                }
            }
        }
    }

    /// Batch completions from now on. Subscribe before the lookup a waiter
    /// parks on, so the batch answering it cannot slip in between.
    pub(super) fn completions(&self) -> watch::Receiver<u64> {
        self.shared.completed.subscribe()
    }

    /// Requests a fresh observation of a newly accepted connection's client
    /// socket. The scan runs while the caller does other work (a proxy
    /// handshake); [`OwnerLookup::resolve`] then waits out the rest of the
    /// attribution budget at most. `urgent` starts the scan at once, for a
    /// caller that will wait on the answer; otherwise it gathers.
    pub(crate) fn request(&self, flow: FlowKey, urgent: bool) -> OwnerLookup {
        let answer = match self.lookup(&flow, true, urgent) {
            Lookup::Ready(process) => Answer::known(process),
            Lookup::Pending(answer) => answer,
        };
        OwnerLookup {
            shared: Arc::clone(&self.shared),
            answer,
            deadline: tokio::time::Instant::now() + ATTRIBUTION_BUDGET,
        }
    }

    /// `fresh` marks a new connection (a TCP SYN, an accepted client): its
    /// tuple may have changed owners, so a cached answer does not count.
    /// `urgent` marks a caller that waits on the answer: its request, or
    /// the one already queued for the flow, is scanned without gathering.
    pub(super) fn lookup(&self, flow: &FlowKey, fresh: bool, urgent: bool) -> Lookup {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Lookup::Ready(None);
        }
        let now = Instant::now();
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state.entries.get_mut(flow) {
            if let Some((until, process)) = &mut entry.result {
                if !fresh && now < *until {
                    // A flow that keeps sending keeps its answer: the entry
                    // expires once the flow goes quiet, not under it.
                    *until = now + result_ttl(process.is_some());
                    return Lookup::Ready(process.clone());
                }
            } else if now.duration_since(entry.created) < REQUEST_TTL {
                let pending = Lookup::Pending(Arc::clone(&entry.answer));
                if urgent && !state.urgent {
                    state.urgent = true;
                    self.shared.wake.notify_one();
                }
                return pending;
            }
        }
        if state.requests.len() >= MAX_REQUESTS {
            return Lookup::Ready(None);
        }
        if state.entries.len() >= MAX_ENTRIES {
            // Expired entries only go when the cache is full: dropping them on
            // every request was a scan of the whole cache per new flow.
            state.entries.retain(|_, entry| {
                entry.result.as_ref().map_or(
                    now.duration_since(entry.created) < REQUEST_TTL,
                    |(until, _)| now < *until,
                )
            });
        }
        if state.entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.created)
                .map(|(flow, _)| flow.clone())
            {
                state.entries.remove(&oldest);
            }
        }
        let Some(ticket) = state.next.checked_add(1) else {
            return Lookup::Ready(None);
        };
        state.next = ticket;
        let answer = Arc::new(Answer::default());
        state.entries.insert(
            flow.clone(),
            Entry {
                ticket,
                created: now,
                result: None,
                answer: Arc::clone(&answer),
            },
        );
        state.urgent |= urgent;
        state.requests.push_back(Request {
            flow: flow.clone(),
            ticket,
            queued: now,
            answer: Arc::clone(&answer),
        });
        self.shared.wake.notify_one();
        Lookup::Pending(answer)
    }
}
/// One client socket's owner, requested when its connection is accepted.
/// It does not keep the worker running: a stopped worker answers what it
/// will not scan.
pub(crate) struct OwnerLookup {
    shared: Arc<Shared>,
    /// The request's answer, given at once when the request could not queue
    /// (stopped worker, full queue).
    answer: Arc<Answer>,
    deadline: tokio::time::Instant,
}

impl OwnerLookup {
    /// The owner for a connection record the routing did not wait on, over
    /// the longer [`RECORD_BUDGET`]; the request keeps gathering.
    pub(crate) async fn resolve_for_record(mut self) -> Option<Arc<ProcessInfo>> {
        self.deadline += RECORD_BUDGET.saturating_sub(ATTRIBUTION_BUDGET);
        self.wait(false).await
    }

    /// The owner once the worker answers; unknown once the budget that
    /// started at the request runs out. The routing waits on it, so the scan
    /// starts at once.
    pub(crate) async fn resolve(self) -> Option<Arc<ProcessInfo>> {
        self.wait(true).await
    }

    async fn wait(self, urgent: bool) -> Option<Arc<ProcessInfo>> {
        if urgent && self.answer.owner.get().is_none() {
            // Scan without gathering: this caller waits on the answer.
            let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.requests.is_empty() && !state.urgent {
                state.urgent = true;
                self.shared.wake.notify_one();
            }
        }
        loop {
            // Registered before the check, so an answer given in between
            // still wakes it.
            let given = self.answer.given.notified();
            tokio::pin!(given);
            given.as_mut().enable();
            if let Some(owner) = self.answer.owner.get() {
                return owner.clone();
            }
            if tokio::time::timeout_at(self.deadline, given).await.is_err() {
                return None;
            }
        }
    }
}

struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
        // Requests the worker will never scan are answered as unknown.
        let unanswered = {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            state.requests.drain(..).collect::<Vec<_>>()
        };
        for request in unanswered {
            request.answer.give(None);
        }
        complete_batch(&self.0);
    }
}

fn result_ttl(found: bool) -> Duration {
    if found {
        POSITIVE_TTL
    } else {
        NEGATIVE_TTL
    }
}

fn complete_batch(shared: &Shared) {
    shared
        .completed
        .send_modify(|batches| *batches = batches.wrapping_add(1));
}

fn run(shared: &Shared, scanner: &dyn FlowScanner) {
    loop {
        let requests = {
            let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if shared.stopped.load(Ordering::Acquire) {
                    return;
                }
                let Some(oldest) = state.requests.front() else {
                    state = shared.wake.wait(state).unwrap_or_else(|e| e.into_inner());
                    continue;
                };
                let waited = oldest.queued.elapsed();
                if waited >= GATHER || state.requests.len() >= BATCH || state.urgent {
                    break;
                }
                state = shared
                    .wake
                    .wait_timeout(state, GATHER - waited)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            let n = state.requests.len().min(BATCH);
            state.urgent = false;
            state.requests.drain(..n).collect::<Vec<_>>()
        };
        let flows = requests
            .iter()
            .map(|request| request.flow.clone())
            .collect::<Vec<_>>();
        let results = scanner.scan(&flows, SCAN_BUDGET, &shared.stopped);
        if shared.stopped.load(Ordering::Acquire) {
            for request in requests {
                request.answer.give(None);
            }
            return;
        }
        let now = Instant::now();
        let mut answers = Vec::with_capacity(requests.len());
        {
            let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            for (index, request) in requests.into_iter().enumerate() {
                // A scanner returning fewer rows than requested leaves the
                // remainder unknown instead of misaligning owners.
                let process = results.get(index).cloned().flatten().map(Arc::new);
                if let Some(entry) = state.entries.get_mut(&request.flow) {
                    if entry.ticket == request.ticket {
                        entry.result = Some((now + result_ttl(process.is_some()), process.clone()));
                    }
                }
                answers.push((request.answer, process));
            }
        }
        for (answer, process) in answers {
            answer.give(process);
        }
        complete_batch(shared);
    }
}
impl Drop for AttributionWorker {
    fn drop(&mut self) {
        {
            // Serialize with the wait predicate to avoid a missed stop wakeup.
            let _state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            self.shared.stopped.store(true, Ordering::Release);
            self.shared.wake.notify_all();
        }
        if let Some(worker) = self.worker.take() {
            // The join is bounded by the scanner's contract to return
            // promptly once `stop` is set, which is the same flag a scan in
            // progress is holding (see `run`): every platform scanner checks
            // it inside its per-process loop, so this is one entry's work and
            // not the scan budget. That matters because a retired generation
            // is dropped on a Core executor thread.
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::FlowProtocol;
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};

    struct FnScanner<F>(F);
    impl<F> FlowScanner for FnScanner<F>
    where
        F: Fn(&[FlowKey], &AtomicBool) -> Vec<Option<ProcessInfo>> + Send + Sync,
    {
        fn scan(
            &self,
            flows: &[FlowKey],
            _: Duration,
            stop: &AtomicBool,
        ) -> Vec<Option<ProcessInfo>> {
            (self.0)(flows, stop)
        }
    }
    impl<F> std::fmt::Debug for FnScanner<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("FnScanner")
        }
    }

    pub(in crate::attribution) fn scanner<F>(f: F) -> Arc<dyn FlowScanner>
    where
        F: Fn(&[FlowKey], &AtomicBool) -> Vec<Option<ProcessInfo>> + Send + Sync + 'static,
    {
        Arc::new(FnScanner(f))
    }

    pub(in crate::attribution) fn flow(udp: bool) -> FlowKey {
        FlowKey {
            protocol: if udp {
                FlowProtocol::Udp
            } else {
                FlowProtocol::Tcp
            },
            source_ip: "10.255.255.1".parse().unwrap(),
            source_port: 54123,
            destination_ip: "198.18.55.239".parse().unwrap(),
            destination_port: 443,
        }
    }

    fn named(name: String) -> Option<ProcessInfo> {
        Some(ProcessInfo {
            name: Some(name),
            path: None,
        })
    }

    fn await_ready(worker: &AttributionWorker, key: &FlowKey) -> Option<Arc<ProcessInfo>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Lookup::Ready(result) = worker.lookup(key, false, true) {
                return result;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn keyed(port: u16) -> FlowKey {
        let mut key = flow(false);
        key.source_port = port;
        key
    }

    /// Requests nothing waits on gather into one scan; a request someone
    /// waits on starts the scan at once and takes them along.
    #[test]
    fn unwaited_requests_gather_and_a_waited_one_scans_at_once() {
        let (scanned, scans) = mpsc::channel::<Vec<u16>>();
        let scanned = Mutex::new(scanned);
        let worker = AttributionWorker::start(scanner(move |keys, _| {
            let ports = keys.iter().map(|key| key.source_port).collect();
            scanned.lock().unwrap().send(ports).unwrap();
            vec![None; keys.len()]
        }));
        let started = Instant::now();
        assert!(matches!(
            worker.lookup(&keyed(1), true, false),
            Lookup::Pending(..)
        ));
        thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            worker.lookup(&keyed(2), true, false),
            Lookup::Pending(..)
        ));
        let batch = scans.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(batch, vec![1, 2], "one scan answers both");
        assert!(started.elapsed() >= GATHER - Duration::from_millis(5));

        assert!(matches!(
            worker.lookup(&keyed(3), true, false),
            Lookup::Pending(..)
        ));
        let waited = Instant::now();
        assert!(matches!(
            worker.lookup(&keyed(4), true, true),
            Lookup::Pending(..)
        ));
        let batch = scans.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            batch,
            vec![3, 4],
            "the waited request takes the gathered one along"
        );
        assert!(waited.elapsed() < GATHER / 2, "{:?}", waited.elapsed());

        // A waiter on a request already gathering makes it urgent.
        assert!(matches!(
            worker.lookup(&keyed(5), true, false),
            Lookup::Pending(..)
        ));
        let waited = Instant::now();
        assert!(matches!(
            worker.lookup(&keyed(5), false, true),
            Lookup::Pending(..)
        ));
        assert_eq!(scans.recv_timeout(Duration::from_secs(2)).unwrap(), vec![5]);
        assert!(waited.elapsed() < GATHER / 2, "{:?}", waited.elapsed());
    }

    #[test]
    fn cache_avoids_per_packet_scans_but_a_fresh_syn_requires_a_new_observation() {
        let scans = Arc::new(AtomicUsize::new(0));
        let observed = scans.clone();
        let worker = AttributionWorker::start(scanner(move |keys, _| {
            let id = observed.fetch_add(1, Ordering::SeqCst);
            keys.iter().map(|_| named(format!("scan-{id}"))).collect()
        }));
        let key = flow(false);
        assert!(matches!(
            worker.lookup(&key, true, true),
            Lookup::Pending(..)
        ));
        assert_eq!(
            await_ready(&worker, &key).unwrap().name.as_deref(),
            Some("scan-0")
        );
        for _ in 0..100 {
            assert!(matches!(
                worker.lookup(&key, false, true),
                Lookup::Ready(Some(_))
            ));
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1);
        assert!(matches!(
            worker.lookup(&key, true, true),
            Lookup::Pending(..)
        ));
        assert_eq!(
            await_ready(&worker, &key).unwrap().name.as_deref(),
            Some("scan-1")
        );
    }

    #[test]
    fn an_active_flow_keeps_its_answer_instead_of_rescanning() {
        let scans = Arc::new(AtomicUsize::new(0));
        let observed = scans.clone();
        let worker = AttributionWorker::start(scanner(move |keys, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            keys.iter().map(|_| named("owner".into())).collect()
        }));
        let key = flow(true);
        worker.lookup(&key, false, true);
        assert!(await_ready(&worker, &key).is_some());
        // Each lookup inside the window moves the window: a flow that keeps
        // sending outlives several TTLs on one scan.
        for _ in 0..3 {
            {
                let mut state = worker.shared.state.lock().unwrap();
                state
                    .entries
                    .get_mut(&key)
                    .unwrap()
                    .result
                    .as_mut()
                    .unwrap()
                    .0 = Instant::now() + Duration::from_millis(500);
            }
            // Half a second to go and a twentieth of it slept: the margin has
            // to survive a loaded machine, or the answer expires under the
            // sleep and the test fails for the wrong reason.
            thread::sleep(Duration::from_millis(25));
            assert!(matches!(
                worker.lookup(&key, false, true),
                Lookup::Ready(Some(_))
            ));
            let state = worker.shared.state.lock().unwrap();
            let until = state.entries[&key].result.as_ref().unwrap().0;
            assert!(until > Instant::now() + POSITIVE_TTL / 2);
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn positive_and_negative_results_expire_and_queue_admission_stays_bounded() {
        let worker = AttributionWorker::start(scanner(|keys, _| vec![None; keys.len()]));
        let key = flow(true);
        worker.lookup(&key, false, true);
        assert!(await_ready(&worker, &key).is_none());
        {
            let mut state = worker.shared.state.lock().unwrap();
            state
                .entries
                .get_mut(&key)
                .unwrap()
                .result
                .as_mut()
                .unwrap()
                .0 = Instant::now() - Duration::from_millis(1);
        }
        assert!(matches!(
            worker.lookup(&key, false, true),
            Lookup::Pending(..)
        ));
        for port in 1..5000 {
            let mut key = key.clone();
            key.source_port = port;
            worker.lookup(&key, false, true);
        }
        let state = worker.shared.state.lock().unwrap();
        assert!(state.entries.len() <= MAX_ENTRIES);
        assert!(state.requests.len() <= MAX_REQUESTS);
    }

    #[test]
    fn short_scanner_results_leave_the_remainder_unknown() {
        let worker = AttributionWorker::start(scanner(|_, _| vec![named("only".into())]));
        let first = flow(false);
        let mut second = flow(false);
        second.source_port += 1;
        worker.lookup(&first, false, true);
        worker.lookup(&second, false, true);
        let first = await_ready(&worker, &first);
        let second = await_ready(&worker, &second);
        assert!(first.is_some() || second.is_some());
        assert!(first.is_none() || second.is_none());
    }

    #[test]
    fn dropping_a_busy_worker_signals_and_joins_its_scanner() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let entered_tx = Mutex::new(entered_tx);
        let exited = Arc::new(AtomicBool::new(false));
        let observed = exited.clone();
        let worker = AttributionWorker::start(scanner(move |keys, stop| {
            entered_tx.lock().unwrap().send(()).unwrap();
            while !stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            observed.store(true, Ordering::Release);
            vec![None; keys.len()]
        }));
        worker.lookup(&flow(false), false, true);
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(worker);
        assert!(exited.load(Ordering::Acquire));
    }

    #[test]
    fn dropping_an_idle_worker_does_not_lose_its_stop_wakeup() {
        for _ in 0..32 {
            drop(AttributionWorker::start(scanner(|keys, _| {
                vec![None; keys.len()]
            })));
        }
    }

    #[tokio::test]
    async fn one_completed_batch_wakes_every_waiter_without_polling() {
        let worker = AttributionWorker::start(scanner(|keys, _| {
            keys.iter().map(|_| named("woken".into())).collect()
        }));
        let mut gate = worker.completions();
        let mut listener = worker.completions();
        let key = flow(false);
        assert!(matches!(
            worker.lookup(&key, false, true),
            Lookup::Pending(..)
        ));
        for waiter in [&mut gate, &mut listener] {
            tokio::time::timeout(Duration::from_secs(2), waiter.changed())
                .await
                .expect("batch completion wakes every waiter")
                .expect("the worker outlives its waiters");
        }
        assert!(matches!(
            worker.lookup(&key, false, true),
            Lookup::Ready(Some(_))
        ));
    }

    #[tokio::test]
    async fn a_requested_owner_resolves_once_the_worker_answers() {
        let worker = Arc::new(AttributionWorker::start(scanner(|keys, _| {
            keys.iter().map(|_| named("client".into())).collect()
        })));
        let owner = tokio::time::timeout(
            Duration::from_secs(2),
            worker.request(flow(false), true).resolve(),
        )
        .await
        .expect("an answered lookup resolves within its budget");
        assert_eq!(owner.unwrap().name.as_deref(), Some("client"));
    }

    #[tokio::test]
    async fn a_requested_owner_is_unknown_once_its_budget_runs_out() {
        let release = Arc::new(AtomicBool::new(false));
        let flag = release.clone();
        let worker = Arc::new(AttributionWorker::start(scanner(move |keys, stop| {
            while !flag.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            keys.iter().map(|_| named("late".into())).collect()
        })));
        let started = Instant::now();
        assert!(worker.request(flow(false), true).resolve().await.is_none());
        let waited = started.elapsed();
        assert!(waited >= ATTRIBUTION_BUDGET, "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        release.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn a_new_connection_does_not_reuse_the_cached_owner_of_its_tuple() {
        let scans = Arc::new(AtomicUsize::new(0));
        let observed = scans.clone();
        let worker = Arc::new(AttributionWorker::start(scanner(move |keys, _| {
            let id = observed.fetch_add(1, Ordering::SeqCst);
            keys.iter().map(|_| named(format!("owner-{id}"))).collect()
        })));
        for expected in ["owner-0", "owner-1"] {
            let owner = worker.request(flow(false), true).resolve().await;
            assert_eq!(owner.unwrap().name.as_deref(), Some(expected));
        }
    }

    #[tokio::test]
    async fn waiters_across_batches_each_get_their_own_answer() {
        let worker = Arc::new(AttributionWorker::start(scanner(|keys, _| {
            keys.iter()
                .map(|key| named(format!("port-{}", key.source_port)))
                .collect()
        })));
        let waiters: Vec<_> = (1..=100u16)
            .map(|port| {
                let lookup = worker.request(keyed(port), false);
                tokio::spawn(async move { (port, lookup.resolve_for_record().await) })
            })
            .collect();
        for waiter in waiters {
            let (port, owner) = waiter.await.unwrap();
            assert_eq!(
                owner.unwrap().name.as_deref(),
                Some(format!("port-{port}").as_str()),
                "100 flows take {} batches",
                100usize.div_ceil(BATCH)
            );
        }
    }

    #[tokio::test]
    async fn stopping_the_worker_answers_its_waiters_at_once() {
        let worker = Arc::new(AttributionWorker::start(scanner(|keys, stop| {
            while !stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            vec![None; keys.len()]
        })));
        let scanning = worker.request(keyed(1), true);
        let queued = worker.request(keyed(2), false);
        let waiters = tokio::spawn(async move {
            (
                scanning.resolve_for_record().await,
                queued.resolve_for_record().await,
            )
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = Instant::now();
        tokio::task::spawn_blocking(move || drop(worker))
            .await
            .unwrap();
        let (scanning, queued) = waiters.await.unwrap();
        assert!(scanning.is_none() && queued.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }
}
