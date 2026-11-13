//! Bounded DNS Message caching and request-owned single-flight. A cancelled
//! leader drops its transport and wakes waiters to elect a replacement; no
//! detached query survives the caller that owns it. A negative answer that
//! carries an SOA is cached as RFC 2308 allows (see `wire::negative_ttl`):
//! a name without AAAA records otherwise sends every connection's AAAA
//! question upstream again. Other errors are shared with current waiters but
//! never retained, and no answer is to a query that began before the cache
//! was last cleared.

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hickory_proto::op::Message;
use tokio::sync::watch;
use tokio::time::{timeout_at, Instant};

use super::wire;

const CACHE_CAPACITY: usize = 1024;

type QueryResult = Result<Message, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuerySharing {
    Shared,
    /// Dependency queries may reuse completed answers but cannot wait on a
    /// flight owned by another root query: two roots could otherwise form a
    /// wait cycle even when each individual dependency chain is acyclic.
    Independent,
}

enum Admission {
    Leader(Leader),
    Shared(watch::Receiver<Option<FlightResult>>),
    Independent,
}

#[derive(Debug, Clone)]
enum FlightResult {
    Finished {
        result: QueryResult,
        received: Instant,
    },
    Cancelled,
}

#[derive(Debug)]
struct Flight {
    result: watch::Sender<Option<FlightResult>>,
}

#[derive(Debug)]
struct CachedAnswer {
    message: Message,
    inserted: Instant,
    expires: Instant,
    /// The suspension mark at insertion: an answer from before the host
    /// slept has outlived its TTL by the length of the sleep, which the
    /// monotonic `expires` does not count.
    awake: i64,
}

#[derive(Debug, Default)]
struct SlotState {
    answer: Option<CachedAnswer>,
    flight: Option<Arc<Flight>>,
}

#[derive(Debug, Default)]
struct Slot(Mutex<SlotState>);

#[derive(Debug)]
struct CacheState<K> {
    slots: HashMap<K, (Arc<Slot>, u64)>,
    clock: u64,
}

#[derive(Debug)]
pub(crate) struct DnsCache<K> {
    state: Mutex<CacheState<K>>,
    /// How many times the cache was cleared.
    clears: AtomicU64,
}

impl<K> Default for DnsCache<K> {
    fn default() -> Self {
        Self {
            state: Mutex::new(CacheState {
                slots: HashMap::new(),
                clock: 0,
            }),
            clears: AtomicU64::new(0),
        }
    }
}

impl<K: Eq + Hash + Clone + Debug> DnsCache<K> {
    /// Drops every cached answer; queries in flight finish for their waiters
    /// but keep nothing: they went out before whatever made the answers stale.
    pub(crate) fn clear(&self) {
        // Counted before the answers go, and a leader reads the count under
        // its slot's lock: it either caches before the slot is cleared or
        // sees the count and caches nothing.
        self.clears.fetch_add(1, Ordering::Relaxed);
        let slots: Vec<Arc<Slot>> = {
            let state = self.state.lock().expect("DNS cache");
            state.slots.values().map(|(slot, _)| slot.clone()).collect()
        };
        for slot in slots {
            slot.0.lock().expect("DNS cache slot").answer = None;
        }
    }

    fn slot(&self, key: K) -> Arc<Slot> {
        let mut state = self.state.lock().expect("DNS cache");
        state.clock = state.clock.wrapping_add(1);
        let clock = state.clock;
        if let Some((slot, used)) = state.slots.get_mut(&key) {
            *used = clock;
            return slot.clone();
        }
        if state.slots.len() == CACHE_CAPACITY {
            let oldest = state
                .slots
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
                .expect("full DNS cache");
            state.slots.remove(&oldest);
        }
        let slot = Arc::new(Slot::default());
        state.slots.insert(key, (slot.clone(), clock));
        slot
    }

    pub(crate) async fn resolve(
        &self,
        key: K,
        request_id: u16,
        deadline: Instant,
        sharing: QuerySharing,
        fetch: impl Future<Output = QueryResult>,
    ) -> QueryResult {
        let slot = self.slot(key);
        let mut fetch = Some(fetch);
        loop {
            let admission = {
                let mut state = slot.0.lock().expect("DNS cache slot");
                let now = Instant::now();
                if let Some(answer) = &state.answer {
                    if answer.expires > now && !crate::suspension::slept_since(answer.awake) {
                        let mut message = answer.message.clone();
                        wire::age_ttls(
                            &mut message,
                            now.saturating_duration_since(answer.inserted),
                        );
                        message.metadata.id = request_id;
                        return Ok(message);
                    }
                }
                state.answer = None;
                if let Some(flight) = &state.flight {
                    match sharing {
                        QuerySharing::Shared => Admission::Shared(flight.result.subscribe()),
                        QuerySharing::Independent => Admission::Independent,
                    }
                } else {
                    let (result, _) = watch::channel(None);
                    let flight = Arc::new(Flight { result });
                    state.flight = Some(flight.clone());
                    Admission::Leader(Leader {
                        slot: slot.clone(),
                        flight,
                        clears: self.clears.load(Ordering::Relaxed),
                    })
                }
            };
            let mut waiting = match admission {
                Admission::Leader(guard) => {
                    let result = fetch_until(
                        deadline,
                        fetch.take().expect("only a query owner polls its fetch"),
                    )
                    .await;
                    guard.finish(result.clone(), &self.clears);
                    return result.map(|mut message| {
                        message.metadata.id = request_id;
                        message
                    });
                }
                Admission::Independent => {
                    return fetch_until(
                        deadline,
                        fetch.take().expect("independent query owns its fetch"),
                    )
                    .await
                    .map(|mut message| {
                        message.metadata.id = request_id;
                        message
                    });
                }
                Admission::Shared(waiting) => waiting,
            };
            // Subscribe while holding the slot lock so publication cannot be
            // missed between finding the flight and beginning to wait.
            let finished = timeout_at(deadline, async {
                loop {
                    if let Some(result) = waiting.borrow_and_update().clone() {
                        return result;
                    }
                    if waiting.changed().await.is_err() {
                        return FlightResult::Cancelled;
                    }
                }
            })
            .await
            .map_err(|_| "DNS query deadline expired".to_string())?;
            match finished {
                FlightResult::Finished { result, received } => {
                    return result.map(|mut message| {
                        wire::age_ttls(
                            &mut message,
                            Instant::now().saturating_duration_since(received),
                        );
                        message.metadata.id = request_id;
                        message
                    })
                }
                FlightResult::Cancelled => continue,
            }
        }
    }
}

async fn fetch_until(deadline: Instant, fetch: impl Future<Output = QueryResult>) -> QueryResult {
    timeout_at(deadline, fetch)
        .await
        .map_err(|_| "DNS query deadline expired".to_string())
        .and_then(|result| result)
        .map(|mut message| {
            wire::age_ttls(&mut message, std::time::Duration::ZERO);
            message
        })
}

struct Leader {
    slot: Arc<Slot>,
    flight: Arc<Flight>,
    /// The cache's clear count when the query began.
    clears: u64,
}

impl Leader {
    fn finish(self, result: QueryResult, clears: &AtomicU64) {
        let mut state = self.slot.0.lock().expect("DNS cache slot");
        if state
            .flight
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            let current = clears.load(Ordering::Relaxed) == self.clears;
            if let Some(message) = result.as_ref().ok().filter(|_| current) {
                if let Some(ttl) =
                    wire::positive_ttl(message).or_else(|| wire::negative_ttl(message))
                {
                    let inserted = Instant::now();
                    state.answer = Some(CachedAnswer {
                        message: message.clone(),
                        inserted,
                        expires: inserted + ttl,
                        awake: crate::suspension::mark(),
                    });
                }
            }
            self.flight
                .result
                .send_replace(Some(FlightResult::Finished {
                    result,
                    received: Instant::now(),
                }));
            state.flight = None;
        }
        // The Drop guard observes that this flight is no longer current.
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        let mut state = self.slot.0.lock().expect("DNS cache slot");
        if state
            .flight
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            self.flight
                .result
                .send_replace(Some(FlightResult::Cancelled));
            state.flight = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{rdata::TXT, RData, Record, RecordType};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::Duration;

    fn answer(ttl: u32) -> Message {
        let request = wire::query("cache.test", RecordType::TXT).unwrap();
        let mut answer = wire::response(&request, ResponseCode::NoError);
        answer.add_answer(Record::from_rdata(
            request.queries.first().unwrap().name().clone(),
            ttl,
            RData::TXT(TXT::new(vec!["retained record data".into()])),
        ));
        answer
    }

    /// The answer to an AAAA question for a name with only A records,
    /// with an SOA in authority when `soa` is given (its TTL).
    fn nodata(soa: Option<u32>) -> Message {
        let request = wire::query("v4only.test", RecordType::AAAA).unwrap();
        let mut answer = wire::response(&request, ResponseCode::NoError);
        if let Some(ttl) = soa {
            answer.add_authority(Record::from_rdata(
                hickory_proto::rr::Name::from_ascii("test.").unwrap(),
                ttl,
                RData::SOA(hickory_proto::rr::rdata::SOA::new(
                    hickory_proto::rr::Name::from_ascii("ns.test.").unwrap(),
                    hickory_proto::rr::Name::from_ascii("admin.test.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    3600,
                )),
            ));
        }
        answer
    }

    #[tokio::test(start_paused = true)]
    async fn a_negative_answer_with_an_soa_answers_again_until_its_soa_runs_out() {
        let cache = DnsCache::<String>::default();
        let calls = AtomicUsize::new(0);
        let ask = |key: &'static str, soa| {
            let calls = &calls;
            cache.resolve(
                key.into(),
                1,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(nodata(soa))
                },
            )
        };
        let first = ask("with soa", Some(300)).await.unwrap();
        assert!(first.answers.is_empty());
        tokio::time::advance(Duration::from_secs(100)).await;
        let again = ask("with soa", Some(300)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "answered from the cache");
        assert!(again.answers.is_empty());
        assert_eq!(again.authorities[0].ttl, 200, "its SOA aged");
        tokio::time::advance(Duration::from_secs(201)).await;
        ask("with soa", Some(300)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "asked again past the SOA");

        // Without an SOA nothing says how long it holds: every query asks.
        ask("without soa", None).await.unwrap();
        ask("without soa", None).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn shared_positive_answer_keeps_records_and_ages_each_callers_ttl_and_id() {
        let cache = DnsCache::<String>::default();
        let calls = AtomicUsize::new(0);
        let fetched = cache
            .resolve(
                "key".into(),
                1,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(60))
                },
            )
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(1500)).await;
        let hit = cache
            .resolve(
                "key".into(),
                2,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(60))
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hit.id, 2);
        assert_eq!(hit.answers[0].data, fetched.answers[0].data);
        assert_eq!(hit.answers[0].ttl, 58);
        tokio::time::advance(Duration::from_secs(59)).await;
        cache
            .resolve(
                "key".into(),
                3,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(60))
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_cleared_cache_fetches_again() {
        let cache = DnsCache::<String>::default();
        let calls = AtomicUsize::new(0);
        let resolve = |id| {
            cache.resolve(
                "key".into(),
                id,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(600))
                },
            )
        };
        resolve(1).await.unwrap();
        cache.clear();
        resolve(2).await.unwrap();
        resolve(3).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_answer_to_a_query_from_before_a_clear_is_not_kept() {
        let cache = DnsCache::<String>::default();
        let calls = AtomicUsize::new(0);
        let (reply, replied) = tokio::sync::oneshot::channel::<()>();
        let slow = cache.resolve(
            "key".into(),
            1,
            Instant::now() + Duration::from_secs(5),
            QuerySharing::Shared,
            async {
                calls.fetch_add(1, Ordering::SeqCst);
                replied.await.unwrap();
                Ok(answer(600))
            },
        );
        let clear_meanwhile = async {
            tokio::task::yield_now().await;
            cache.clear();
            reply.send(()).unwrap();
        };
        let (answered, ()) = tokio::join!(slow, clear_meanwhile);
        assert!(answered.is_ok(), "its caller still gets the answer");
        cache
            .resolve(
                "key".into(),
                2,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(600))
                },
            )
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "asked again after the clear"
        );
    }

    #[tokio::test]
    async fn an_answer_from_before_the_host_slept_is_fetched_again() {
        let cache = DnsCache::<String>::default();
        let calls = AtomicUsize::new(0);
        let resolve = |id| {
            cache.resolve(
                "key".into(),
                id,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(600))
                },
            )
        };
        resolve(1).await.unwrap();
        resolve(2).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The host sleeps a minute: the wall clock moves on, the monotonic
        // clock the TTL is measured against does not.
        let slot = cache.slot("key".into());
        slot.0.lock().unwrap().answer.as_mut().unwrap().awake -= 60_000;
        resolve(3).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_waiters_share_success_errors_and_zero_ttl_without_serial_requeries() {
        for mode in 0..3 {
            let cache = Arc::new(DnsCache::<u8>::default());
            let calls = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(tokio::sync::Notify::new());
            let mut tasks = tokio::task::JoinSet::new();
            for id in 0..16 {
                let cache = cache.clone();
                let calls = calls.clone();
                let release = release.clone();
                tasks.spawn(async move {
                    cache
                        .resolve(
                            1,
                            id,
                            Instant::now() + Duration::from_secs(2),
                            QuerySharing::Shared,
                            async {
                                calls.fetch_add(1, Ordering::SeqCst);
                                release.notified().await;
                                if mode == 1 {
                                    Err("upstream failed".into())
                                } else {
                                    Ok(answer(if mode == 2 { 0 } else { 60 }))
                                }
                            },
                        )
                        .await
                });
            }
            // Wait until all tasks have subscribed to the single current flight.
            loop {
                let slot = cache.slot(1);
                let subscribed = slot
                    .0
                    .lock()
                    .unwrap()
                    .flight
                    .as_ref()
                    .map_or(0, |flight| flight.result.receiver_count());
                if subscribed == 15 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            release.notify_one();
            while let Some(result) = tasks.join_next().await {
                assert_eq!(result.unwrap().is_err(), mode == 1);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            // Failure and TTL=0 are not retained for a later request.
            cache
                .resolve(
                    1,
                    99,
                    Instant::now() + Duration::from_secs(1),
                    QuerySharing::Shared,
                    async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(answer(60))
                    },
                )
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), if mode == 0 { 1 } else { 2 });
        }
    }

    #[tokio::test]
    async fn cancelled_leader_releases_waiters_to_elect_a_new_owner() {
        let cache = Arc::new(DnsCache::<u8>::default());
        let (entered, started) = tokio::sync::oneshot::channel();
        let first_cache = cache.clone();
        let owner = tokio::spawn(async move {
            first_cache
                .resolve(
                    1,
                    1,
                    Instant::now() + Duration::from_secs(5),
                    QuerySharing::Shared,
                    async {
                        entered.send(()).unwrap();
                        std::future::pending().await
                    },
                )
                .await
        });
        started.await.unwrap();
        let waiter_cache = cache.clone();
        let waiter = tokio::spawn(async move {
            waiter_cache
                .resolve(
                    1,
                    2,
                    Instant::now() + Duration::from_secs(5),
                    QuerySharing::Shared,
                    async { Ok(answer(60)) },
                )
                .await
        });
        tokio::task::yield_now().await;
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        let answer = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(answer.id, 2);
    }

    #[tokio::test]
    async fn dependency_query_can_pass_a_pending_foreign_flight_without_replacing_it() {
        let cache = Arc::new(DnsCache::<u8>::default());
        let (entered, started) = tokio::sync::oneshot::channel();
        let (finish, waiting) = tokio::sync::oneshot::channel();
        let owner_cache = cache.clone();
        let owner = tokio::spawn(async move {
            owner_cache
                .resolve(
                    1,
                    1,
                    Instant::now() + Duration::from_secs(5),
                    QuerySharing::Shared,
                    async {
                        entered.send(()).unwrap();
                        waiting.await.unwrap();
                        Ok(answer(60))
                    },
                )
                .await
        });
        started.await.unwrap();
        let independent = tokio::time::timeout(
            Duration::from_secs(1),
            cache.resolve(
                1,
                2,
                Instant::now() + Duration::from_secs(2),
                QuerySharing::Independent,
                async { Ok(answer(20)) },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(independent.id, 2);
        assert_eq!(independent.answers[0].ttl, 20);
        assert!(
            !owner.is_finished(),
            "independent query must not cancel or replace its peer"
        );
        finish.send(()).unwrap();
        assert_eq!(owner.await.unwrap().unwrap().answers[0].ttl, 60);
        let cached = cache
            .resolve(
                1,
                3,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Independent,
                async { panic!("dependency lookup should reuse a completed positive answer") },
            )
            .await
            .unwrap();
        assert_eq!(cached.id, 3);
        assert!(cached.answers[0].ttl >= 59);
    }

    #[tokio::test(start_paused = true)]
    async fn waiter_timeout_does_not_cancel_its_owner() {
        let cache = Arc::new(DnsCache::<u8>::default());
        let (finish, waiting) = tokio::sync::oneshot::channel();
        let owner_cache = cache.clone();
        let owner = tokio::spawn(async move {
            owner_cache
                .resolve(
                    1,
                    1,
                    Instant::now() + Duration::from_secs(20),
                    QuerySharing::Shared,
                    async {
                        waiting.await.unwrap();
                        Ok(answer(60))
                    },
                )
                .await
        });
        tokio::task::yield_now().await;
        let error = cache
            .resolve(
                1,
                2,
                Instant::now() + Duration::from_secs(1),
                QuerySharing::Shared,
                async { panic!("waiter must not become owner") },
            )
            .await
            .unwrap_err();
        assert!(error.contains("deadline"));
        assert!(!owner.is_finished());
        finish.send(()).unwrap();
        assert!(owner.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn negative_responses_and_empty_answers_remain_uncached_and_preserve_rcode() {
        for rcode in [
            ResponseCode::NoError,
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
        ] {
            let cache = DnsCache::<u8>::default();
            let calls = AtomicUsize::new(0);
            for id in 0..2 {
                let answer = cache
                    .resolve(
                        1,
                        id,
                        Instant::now() + Duration::from_secs(1),
                        QuerySharing::Shared,
                        async {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(wire::response(
                                &wire::query("empty.test", RecordType::A).unwrap(),
                                rcode,
                            ))
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(answer.response_code, rcode);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn retained_slots_are_bounded_even_without_revisiting_expired_keys() {
        let cache = DnsCache::<usize>::default();
        for key in 0..CACHE_CAPACITY * 3 {
            cache.slot(key);
        }
        let state = cache.state.lock().unwrap();
        assert_eq!(state.slots.len(), CACHE_CAPACITY);
        assert!(!state.slots.contains_key(&0));
    }
}
