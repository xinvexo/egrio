use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};
use time::OffsetDateTime;

use crate::profile_source::parse_rule_provider_entries;
use crate::profile_store::{ProfileStore, SavedRuleProvider};
use crate::remote_fetch::{validate_remote_url, RuleSetClient};
use egrio_runtime::Runtime;

/// Outcome of the rules-page "refresh everything" button: which providers
/// got fresh content and which failed (name plus error, so one bad mirror
/// doesn't hide the rest).
#[derive(Debug, Clone, Serialize)]
pub struct RuleProviderRefreshReport {
    pub updated: Vec<SavedRuleProvider>,
    pub unchanged: Vec<SavedRuleProvider>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleProviderUpdateReport {
    pub provider: SavedRuleProvider,
    pub changed: bool,
}

static REFRESHING: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

struct RefreshPermit {
    profile_id: String,
}

impl RefreshPermit {
    fn acquire(profile_id: &str) -> Result<Self, String> {
        let mut pending = REFRESHING.lock().unwrap_or_else(|error| error.into_inner());
        if !pending.insert(profile_id.to_owned()) {
            return Err("rule providers for this profile are already updating".into());
        }
        Ok(Self {
            profile_id: profile_id.to_owned(),
        })
    }
}

impl Drop for RefreshPermit {
    fn drop(&mut self) {
        REFRESHING
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.profile_id);
    }
}

/// One refresh owns admission, its store and one HTTP pool through all cache
/// commits. Runtime application follows after this operation releases admission,
/// because its start preflight may prepare this same profile's dependencies.
struct RuleProviderRefresh {
    profile_id: String,
    store: ProfileStore,
    client: RuleSetClient,
    _permit: RefreshPermit,
}

impl RuleProviderRefresh {
    /// Admission comes first: a refusal builds no client.
    fn begin(
        profile_id: String,
        store: ProfileStore,
        make_client: impl FnOnce() -> Result<RuleSetClient, String>,
    ) -> Result<Self, String> {
        let permit = RefreshPermit::acquire(&profile_id)?;
        Ok(Self {
            profile_id,
            store,
            client: make_client()?,
            _permit: permit,
        })
    }

    async fn update_all(&self) -> Result<RuleProviderRefreshReport, String> {
        let targets = self
            .store
            .rule_provider_fetch_targets(&self.profile_id)
            .map_err(|error| error.to_string())?;
        let mut report = RuleProviderRefreshReport {
            updated: Vec::new(),
            unchanged: Vec::new(),
            failures: Vec::new(),
        };
        for target in targets {
            if target.url.is_none() {
                continue;
            }
            let name = target.name.clone();
            match self.fetch(target).await {
                Ok(result) if result.changed => report.updated.push(result.provider),
                Ok(result) => report.unchanged.push(result.provider),
                Err(error) => report.failures.push(format!("{name}: {error}")),
            }
        }
        Ok(report)
    }

    async fn update_one(&self, provider_name: &str) -> Result<RuleProviderUpdateReport, String> {
        let target = self
            .store
            .rule_provider_fetch_target(&self.profile_id, provider_name)
            .map_err(|error| format!("rule provider '{provider_name}' not found: {error}"))?;
        self.fetch(target).await
    }

    async fn prepare_required(&self) -> Result<(), String> {
        let missing = self
            .store
            .missing_rule_provider_fetch_targets(&self.profile_id)
            .map_err(|error| error.to_string())?;
        for target in missing {
            let name = target.name.clone();
            self.fetch(target)
                .await
                .map_err(|error| format!("prepare rule provider '{name}': {error}"))?;
        }
        // A source replacement may introduce another dependency during these
        // downloads. It must not silently disappear from the next Core start.
        if !self
            .store
            .missing_rule_provider_fetch_targets(&self.profile_id)
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("profile rule dependencies changed during preparation; retry applying the configuration".into());
        }
        Ok(())
    }

    async fn fetch(&self, target: SavedRuleProvider) -> Result<RuleProviderUpdateReport, String> {
        let Some(url) = target.url.as_deref() else {
            return Err(format!(
                "rule provider '{}' has no URL (file-based providers cannot be fetched)",
                target.name,
            ));
        };
        let body = self.client.get(validate_remote_url(url)?).await?;
        let entries = parse_rule_provider_entries(&body);
        if entries.is_empty() {
            return Err(format!(
                "rule provider '{}' response contains no parseable entries",
                target.name,
            ));
        }
        let entry_count = entries.len() as i64;
        let changed = self
            .store
            .save_rule_provider_content(&self.profile_id, &target, &body, entry_count)
            .map_err(|error| error.to_string())?;
        Ok(RuleProviderUpdateReport {
            provider: SavedRuleProvider {
                fetched_at_unix: Some(OffsetDateTime::now_utc().unix_timestamp()),
                entry_count: Some(entry_count),
                ..target
            },
            changed,
        })
    }
}

/// Downloads the rule sets the profile's rules name and the cache lacks,
/// through `runtime`'s Core. Existing caches whose descriptors still match
/// are reused; providers no rule names are not fetched.
pub(crate) async fn prepare_via_core(
    profile_id: String,
    runtime: Arc<Runtime>,
) -> Result<(), String> {
    let store = ProfileStore::open().map_err(|error| error.to_string())?;
    prepare_profile_rule_providers_in(profile_id, store, || RuleSetClient::new(Some(runtime))).await
}

async fn prepare_profile_rule_providers_in(
    profile_id: String,
    store: ProfileStore,
    make_client: impl FnOnce() -> Result<RuleSetClient, String>,
) -> Result<(), String> {
    // An already-usable cache is a read, not a refresh. It must not prevent a
    // configuration preflight while another operation checks for fresh content.
    // Final composition still validates the source and its required contents.
    if store
        .missing_rule_provider_fetch_targets(&profile_id)
        .map_err(|error| error.to_string())?
        .is_empty()
    {
        return Ok(());
    }
    // Missing dependencies require the same refresh admission as manual work.
    // Re-read them after admission, because a refresh may have filled them in
    // between the optimistic cache check and acquiring this operation.
    RuleProviderRefresh::begin(profile_id, store, make_client)?
        .prepare_required()
        .await
}

fn open_refresh(
    profile_id: String,
    core: Option<Arc<Runtime>>,
) -> Result<RuleProviderRefresh, String> {
    let store = ProfileStore::open().map_err(|error| error.to_string())?;
    RuleProviderRefresh::begin(profile_id, store, || RuleSetClient::new(core))
}

/// Refreshes every URL-carrying provider of the profile sequentially,
/// through `core`'s Core when given; failures are collected rather than
/// short-circuiting.
pub async fn update_all_rule_providers(
    profile_id: String,
    core: Option<Arc<Runtime>>,
) -> Result<RuleProviderRefreshReport, String> {
    open_refresh(profile_id, core)?.update_all().await
}

/// Downloads one rule provider's content, caches it next to the profile
/// yaml, and stamps the fetch record the inventory reports. The caller
/// hot-applies the active profile afterwards so the engine recompiles with
/// the fresh entries.
pub async fn update_rule_provider(
    profile_id: String,
    provider_name: String,
    core: Option<Arc<Runtime>>,
) -> Result<RuleProviderUpdateReport, String> {
    open_refresh(profile_id, core)?
        .update_one(&provider_name)
        .await
}

#[cfg(test)]
mod tests;
