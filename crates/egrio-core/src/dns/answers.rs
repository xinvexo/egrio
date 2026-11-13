//! Decoded address answers for the Core's own lookups (DIRECT targets, UDP
//! targets, node endpoints), in front of the wire cache. A hit there still
//! plans the upstreams, builds and encodes a query for the key, formats the
//! path and decodes the reply: for every new connection or UDP flow to a
//! name, some twenty allocations and about a tenth of the CPU a new UDP flow
//! costs. An answer here holds exactly while the wire answer would: until its
//! TTL runs out, the host sleeps, the network changes (the service clears
//! both, and a lookup that began before keeps its answer to itself) or a
//! policy group moves on (the version it was planned at). For [`STALE_GRACE`]
//! past its TTL an answer still serves a lookup while one lookup refreshes it
//! (see [`FamilyAnswers::stale`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::time::{Duration, Instant};

use super::service::QueryPurpose;

/// Names held at once; past it the expired ones go, and if that is not
/// enough, all of them.
const CAPACITY: usize = 4096;
/// How long past its TTL an answer still serves a lookup while it is asked
/// for again. Resolvers can return addresses with only seconds of TTL left,
/// making repeat visits wait for a lookup per new connection. The grace
/// window lets a recent answer serve those lookups while it is refreshed.
pub(super) const STALE_GRACE: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub(super) struct FamilyAnswers {
    names: Mutex<HashMap<String, Vec<FamilyAnswer>>>,
    /// How many times the answers were cleared.
    clears: AtomicU64,
}

#[derive(Debug)]
struct FamilyAnswer {
    ipv6: bool,
    purpose: QueryPurpose,
    business_outbound: Option<String>,
    group_version: u64,
    awake: i64,
    expires: Instant,
    addresses: Arc<[IpAddr]>,
    /// A lookup is refreshing it, served past its TTL.
    refreshing: bool,
}

/// What an answer is for, besides its name.
pub(super) struct AnswerKey<'a> {
    pub(super) ipv6: bool,
    pub(super) purpose: QueryPurpose,
    pub(super) business_outbound: Option<&'a str>,
    pub(super) group_version: u64,
}

impl FamilyAnswer {
    fn answers(&self, key: &AnswerKey<'_>) -> bool {
        self.ipv6 == key.ipv6
            && self.purpose == key.purpose
            && self.business_outbound.as_deref() == key.business_outbound
    }
}

impl FamilyAnswers {
    /// The addresses for `name` (normalized) that are still valid.
    pub(super) fn get(&self, name: &str, key: &AnswerKey<'_>) -> Option<Arc<[IpAddr]>> {
        let names = self.names.lock().expect("DNS answers");
        let answer = names.get(name)?.iter().find(|answer| answer.answers(key))?;
        (answer.group_version == key.group_version
            && answer.expires > Instant::now()
            && !crate::suspension::slept_since(answer.awake))
        .then(|| answer.addresses.clone())
    }

    /// The addresses for `name` past their TTL by less than
    /// [`STALE_GRACE`], otherwise as [`Self::get`] would give them, and
    /// whether the caller is the one to refresh them: the first to take them
    /// since they were last refreshed.
    pub(super) fn stale(&self, name: &str, key: &AnswerKey<'_>) -> Option<(Arc<[IpAddr]>, bool)> {
        let mut names = self.names.lock().expect("DNS answers");
        let answer = names
            .get_mut(name)?
            .iter_mut()
            .find(|answer| answer.answers(key))?;
        let now = Instant::now();
        let usable = answer.group_version == key.group_version
            && now < answer.expires + STALE_GRACE
            && !crate::suspension::slept_since(answer.awake);
        if !usable {
            return None;
        }
        let refresh = !answer.refreshing;
        answer.refreshing = true;
        Some((answer.addresses.clone(), refresh))
    }

    /// A refresh of `name`'s answer for `key` failed: the next lookup to
    /// take it past its TTL tries again.
    pub(super) fn refresh_failed(&self, name: &str, key: &AnswerKey<'_>) {
        let mut names = self.names.lock().expect("DNS answers");
        if let Some(answer) = names
            .get_mut(name)
            .and_then(|answers| answers.iter_mut().find(|answer| answer.answers(key)))
        {
            answer.refreshing = false;
        }
    }

    /// What a lookup reads before it asks, for [`Self::insert`].
    pub(super) fn clears(&self) -> u64 {
        self.clears.load(Ordering::Relaxed)
    }

    /// Keeps the answer to a lookup that began when [`Self::clears`] read
    /// `clears`, unless the answers were cleared since.
    pub(super) fn insert(
        &self,
        name: String,
        key: &AnswerKey<'_>,
        addresses: Arc<[IpAddr]>,
        ttl: Duration,
        clears: u64,
    ) {
        let answer = FamilyAnswer {
            ipv6: key.ipv6,
            purpose: key.purpose,
            business_outbound: key.business_outbound.map(str::to_owned),
            group_version: key.group_version,
            awake: crate::suspension::mark(),
            expires: Instant::now() + ttl,
            addresses,
            refreshing: false,
        };
        let mut names = self.names.lock().expect("DNS answers");
        if self.clears.load(Ordering::Relaxed) != clears {
            return;
        }
        if names.len() >= CAPACITY && !names.contains_key(&name) {
            let now = Instant::now();
            names.retain(|_, answers| {
                answers.retain(|answer| answer.expires + STALE_GRACE > now);
                !answers.is_empty()
            });
            if names.len() >= CAPACITY {
                names.clear();
            }
        }
        let answers = names.entry(name).or_default();
        answers.retain(|held| !held.answers(key));
        answers.push(answer);
    }

    pub(super) fn clear(&self) {
        let mut names = self.names.lock().expect("DNS answers");
        self.clears.fetch_add(1, Ordering::Relaxed);
        names.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ipv6: bool, group_version: u64) -> AnswerKey<'static> {
        AnswerKey {
            ipv6,
            purpose: QueryPurpose::DirectTarget,
            business_outbound: None,
            group_version,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_holds_for_its_family_version_and_ttl() {
        let answers = FamilyAnswers::default();
        let v4: Arc<[IpAddr]> = Arc::from(vec!["192.0.2.1".parse().unwrap()]);
        answers.insert(
            "a.test".into(),
            &key(false, 7),
            v4.clone(),
            Duration::from_secs(30),
            answers.clears(),
        );
        assert_eq!(answers.get("a.test", &key(false, 7)).as_deref(), Some(&*v4));
        assert!(
            answers.get("a.test", &key(true, 7)).is_none(),
            "another family"
        );
        assert!(
            answers.get("a.test", &key(false, 8)).is_none(),
            "a group moved on"
        );
        let other_purpose = AnswerKey {
            purpose: QueryPurpose::ProxyEndpoint,
            ..key(false, 7)
        };
        assert!(answers.get("a.test", &other_purpose).is_none());
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(
            answers.get("a.test", &key(false, 7)).is_none(),
            "its TTL ran out"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_serves_a_while_past_its_ttl_and_one_lookup_refreshes_it() {
        let answers = FamilyAnswers::default();
        let old: Arc<[IpAddr]> = Arc::from(vec!["192.0.2.1".parse().unwrap()]);
        answers.insert(
            "a.test".into(),
            &key(false, 7),
            old.clone(),
            Duration::from_secs(10),
            answers.clears(),
        );
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(answers.get("a.test", &key(false, 7)).is_none());
        // The first to take it past its TTL refreshes it; the next does not.
        assert_eq!(
            answers.stale("a.test", &key(false, 7)),
            Some((old.clone(), true))
        );
        assert_eq!(
            answers.stale("a.test", &key(false, 7)),
            Some((old.clone(), false))
        );
        assert!(
            answers.stale("a.test", &key(false, 8)).is_none(),
            "a group moved on"
        );
        // A refresh that failed lets the next lookup try again.
        answers.refresh_failed("a.test", &key(false, 7));
        assert_eq!(
            answers.stale("a.test", &key(false, 7)),
            Some((old.clone(), true))
        );
        // The refresh's answer is fresh again.
        let new: Arc<[IpAddr]> = Arc::from(vec!["192.0.2.2".parse().unwrap()]);
        answers.insert(
            "a.test".into(),
            &key(false, 7),
            new.clone(),
            Duration::from_secs(10),
            answers.clears(),
        );
        assert_eq!(
            answers.get("a.test", &key(false, 7)).as_deref(),
            Some(&*new)
        );
        // Past the grace, nothing serves.
        tokio::time::advance(Duration::from_secs(10) + STALE_GRACE).await;
        assert!(answers.stale("a.test", &key(false, 7)).is_none());
    }

    #[test]
    fn a_full_table_drops_what_expired_first() {
        let answers = FamilyAnswers::default();
        let address: Arc<[IpAddr]> = Arc::from(vec!["192.0.2.1".parse().unwrap()]);
        for index in 0..CAPACITY {
            answers.insert(
                format!("n{index}.test"),
                &key(false, 0),
                address.clone(),
                Duration::from_secs(60),
                answers.clears(),
            );
        }
        answers.insert(
            "new.test".into(),
            &key(false, 0),
            address,
            Duration::from_secs(60),
            answers.clears(),
        );
        assert!(answers.get("new.test", &key(false, 0)).is_some());
        assert!(answers.names.lock().unwrap().len() <= CAPACITY);
    }

    #[test]
    fn an_answer_to_a_lookup_from_before_a_clear_is_not_kept() {
        let answers = FamilyAnswers::default();
        let began = answers.clears();
        answers.clear();
        answers.insert(
            "a.test".into(),
            &key(false, 0),
            Arc::from(vec!["192.0.2.1".parse().unwrap()]),
            Duration::from_secs(60),
            began,
        );
        assert!(answers.get("a.test", &key(false, 0)).is_none());
    }
}
