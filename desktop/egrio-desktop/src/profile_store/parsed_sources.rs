use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use egrio_core::TrafficPolicyMode;

use crate::profile_source::{parse_source, ParsedSource};

use super::ProfileStoreError;

/// How many parsed sources stay in memory: the active profile and the few
/// others the UI lists next to it. A large rule set costs tens of megabytes.
const KEPT: usize = 4;

/// How many sources' facts stay: more than anyone keeps profiles, and a
/// source's facts are a few words.
const FACTS_KEPT: usize = 256;

/// Parsed profile sources by content hash. A source blob never changes, so an
/// entry stays valid until evicted, and a read composes from it instead of
/// parsing the YAML again.
///
/// The list of profiles reads none of them: it would pull every source
/// through the few kept here, so with a profile more than those each listing
/// parsed them all again and left the active profile's to be parsed by the
/// next read of it. The listing reads [`SourceFacts`] instead, keeping it
/// independent of the parsed-source cache's capacity.
#[derive(Debug, Default)]
pub(super) struct ParsedSources {
    /// Most recently used first.
    recent: Mutex<VecDeque<(String, Arc<ParsedSource>)>>,
    /// What a summary reads, of every source parsed.
    facts: Mutex<HashMap<String, SourceFacts>>,
    #[cfg(test)]
    pub(super) parses: std::sync::atomic::AtomicUsize,
}

/// What a profile's summary reads of its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SourceFacts {
    /// The mode the source writes, if it writes one.
    pub(super) mode: Option<TrafficPolicyMode>,
    pub(super) proxies: usize,
    pub(super) groups: usize,
    pub(super) rules: usize,
}

impl SourceFacts {
    fn of(source: &ParsedSource) -> Self {
        Self {
            mode: source.mode,
            proxies: source.content.proxies.len(),
            groups: source.content.groups.len(),
            rules: source.content.rules.len(),
        }
    }
}

impl ParsedSources {
    /// The parsed source, kept as the most recently used.
    pub(super) fn get_or_parse(
        &self,
        hash: &str,
        raw: impl FnOnce() -> Result<String, ProfileStoreError>,
    ) -> Result<Arc<ParsedSource>, ProfileStoreError> {
        if let Some(parsed) = self.get(hash) {
            return Ok(parsed);
        }
        let parsed = Arc::new(self.parse(hash, raw)?);
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        recent.retain(|(key, _)| key != hash);
        recent.push_front((hash.to_string(), parsed.clone()));
        recent.truncate(KEPT);
        Ok(parsed)
    }

    /// The source's facts, from a parse made before if there was one. A
    /// source parsed for them is kept only in a place nothing else has, and
    /// behind the ones that were used: asking of every profile in turn puts
    /// out none of the sources in use.
    pub(super) fn facts(
        &self,
        hash: &str,
        raw: impl FnOnce() -> Result<String, ProfileStoreError>,
    ) -> Result<SourceFacts, ProfileStoreError> {
        if let Some(facts) = self.known_facts(hash) {
            return Ok(facts);
        }
        let parsed = Arc::new(self.parse(hash, raw)?);
        let facts = SourceFacts::of(&parsed);
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        if recent.len() < KEPT && !recent.iter().any(|(key, _)| key == hash) {
            recent.push_back((hash.to_string(), parsed));
        }
        Ok(facts)
    }

    fn known_facts(&self, hash: &str) -> Option<SourceFacts> {
        let mut facts = self.facts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(known) = facts.get(hash) {
            return Some(*known);
        }
        // Forgotten with the rest when the facts filled up.
        let recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        let (_, parsed) = recent.iter().find(|(key, _)| key == hash)?;
        let known = SourceFacts::of(parsed);
        facts.insert(hash.to_string(), known);
        Some(known)
    }

    /// Parses the source and notes its facts.
    fn parse(
        &self,
        hash: &str,
        raw: impl FnOnce() -> Result<String, ProfileStoreError>,
    ) -> Result<ParsedSource, ProfileStoreError> {
        let parsed = parse_source(&raw()?).map_err(ProfileStoreError::Configuration)?;
        #[cfg(test)]
        self.parses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut facts = self.facts.lock().unwrap_or_else(|p| p.into_inner());
        if facts.len() >= FACTS_KEPT {
            facts.clear();
        }
        facts.insert(hash.to_string(), SourceFacts::of(&parsed));
        Ok(parsed)
    }

    fn get(&self, hash: &str) -> Option<Arc<ParsedSource>> {
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        let index = recent.iter().position(|(key, _)| key == hash)?;
        let entry = recent.remove(index)?;
        let parsed = entry.1.clone();
        recent.push_front(entry);
        Some(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn keeps_only_the_most_recently_used_sources() {
        let sources = ParsedSources::default();
        let parse = |hash: &str| {
            sources
                .get_or_parse(hash, || Ok(format!("rules: ['MATCH,{hash}']\n")))
                .unwrap()
        };
        for hash in ["a", "b", "c", "d"] {
            parse(hash);
        }
        // Using "a" again makes "b" the least recent, so "e" evicts it.
        let a = parse("a");
        parse("e");
        assert_eq!(sources.parses.load(Ordering::Relaxed), 5);
        assert!(Arc::ptr_eq(&a, &parse("a")));
        parse("b");
        assert_eq!(sources.parses.load(Ordering::Relaxed), 6);
    }

    /// Asking every source for its facts parses each once and puts out none
    /// of the sources in use.
    #[test]
    fn facts_come_from_one_parse_and_put_out_no_source_in_use() {
        let sources = ParsedSources::default();
        let raw = |hash: &str| format!("mode: global\nrules: ['MATCH,{hash}']\n");
        let parses = || sources.parses.load(Ordering::Relaxed);
        let used = sources.get_or_parse("used", || Ok(raw("used"))).unwrap();
        for _ in 0..2 {
            for hash in ["a", "used", "b", "c", "d", "e"] {
                let facts = sources.facts(hash, || Ok(raw(hash))).unwrap();
                assert_eq!(
                    facts,
                    SourceFacts {
                        mode: Some(TrafficPolicyMode::Global),
                        proxies: 0,
                        groups: 0,
                        rules: 1,
                    }
                );
            }
        }
        assert_eq!(parses(), 6, "the one in use and each of the others, once");
        // The places nothing had went to the first asked of, behind the one
        // in use.
        let kept = |sources: &ParsedSources| {
            let recent = sources.recent.lock().unwrap();
            recent
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(kept(&sources), ["used", "a", "b", "c"]);
        let again = sources.get_or_parse("used", || Ok(raw("used"))).unwrap();
        assert!(Arc::ptr_eq(&used, &again));
        // One of them is used without another parse; one that was not kept
        // is parsed when it is.
        sources.get_or_parse("b", || Ok(raw("b"))).unwrap();
        assert_eq!(parses(), 6);
        sources.get_or_parse("e", || Ok(raw("e"))).unwrap();
        assert_eq!(parses(), 7);
        assert_eq!(kept(&sources), ["e", "b", "used", "a"]);

        // Facts forgotten come back from a kept source without a parse.
        sources.facts.lock().unwrap().clear();
        assert!(sources.facts("used", || unreachable!()).is_ok());
        assert_eq!(parses(), 7);
        assert!(sources.facts("bad", || Ok("rules: 1\n".into())).is_err());
    }
}
