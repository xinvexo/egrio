//! GUI configuration repository. A Profile is its source document and the
//! choices made while using it: the traffic mode, group selections and the
//! global outbound. Every setting the app changes is written into the source
//! itself. Source blobs are immutable; publishing their pointer is one
//! manifest replacement.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use egrio_core::profile::{RuleSetBehavior, RuleSetContent};
use egrio_core::{RouteRule, RouteRules, RuleKind, RuntimeProfile, TrafficPolicyMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::configuration::{
    compose, selectable_group, traffic_mode, EffectiveConfigSnapshot, ProfileChoices,
};
use crate::profile_source::{parse_rule_provider_entries, ParsedSource, RuleProvider};

mod host_state;
mod parsed_sources;
use parsed_sources::ParsedSources;
mod projection;
mod providers;
use providers::{providers_for_record, retain_source_provider_cache};
mod rules;
mod sources;
#[cfg(test)]
mod tests;

const CURRENT_SCHEMA_VERSION: i64 = 2;
const MANIFEST_FILE: &str = "configuration/manifest.json";
static STORE_WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderCacheReference {
    name: String,
    descriptor_hash: String,
    content_hash: String,
    fetched_at_unix: i64,
    entry_count: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProfile {
    id: String,
    name: String,
    revision: u64,
    source_content_hash: String,
    /// The mode the user picked. Writing another `mode` into the source
    /// clears it, so the file's new mode takes effect.
    #[serde(default)]
    traffic_mode: Option<TrafficPolicyMode>,
    #[serde(default)]
    group_choices: BTreeMap<String, String>,
    #[serde(default)]
    global_outbound: Option<String>,
    #[serde(default)]
    provider_cache: Vec<ProviderCacheReference>,
    created_at_unix: i64,
    /// When the source last changed: imported, saved in the editor, or
    /// rewritten by the app's own controls. Choices made while using the
    /// profile do not count, so this tells how current the file is.
    updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedProfileSummary {
    pub id: String,
    pub name: String,
    pub revision: String,
    pub source_revision: String,
    pub traffic_policy_mode: TrafficPolicyMode,
    pub global_outbound: Option<String>,
    pub proxies: usize,
    pub groups: usize,
    pub rules: usize,
    /// When the profile's file last changed: imported, saved in the editor
    /// or rewritten by the app's controls. Picking nodes or a mode does not
    /// count.
    pub updated_at_unix: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSourceDocument {
    pub profile_id: String,
    pub yaml: String,
    pub source_revision: String,
}
/// What a profile offers to choose from. It carries no rules, so choosing a
/// node costs the same whatever the size of the rule list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInventory {
    pub profile_id: String,
    pub proxies: Vec<SavedProxyNode>,
    pub groups: Vec<SavedPolicyGroup>,
}
/// The source's rule list with the providers its RULE-SET rules name.
#[derive(Debug, Clone)]
pub struct ProfileRuleList {
    pub profile_id: String,
    /// The source revision rule edits must name: a rule's id is its place
    /// in this source.
    pub source_revision: String,
    /// The rules, in the block the source was read into and the Core's
    /// profile shares: listing them copies none of them.
    pub rules: RouteRules,
    /// What the source calls the type of each rule the Core holds as one of
    /// unknown type, by the rule's place.
    pub unknown_kinds: HashMap<usize, String>,
    /// Why the Core leaves a rule out of routing whatever data it is given,
    /// by the rule's place (`egrio_core::rule_support_issues`): a type it
    /// does not implement or content the type cannot read. Such a rule is
    /// listed, and marked.
    pub unsupported: HashMap<usize, String>,
    pub rule_providers: Vec<SavedRuleProvider>,
}

impl ProfileRuleList {
    /// The id of the rule at `place`, which an edit names it by.
    pub fn rule_id(place: usize) -> String {
        crate::profile_source::rule_id(place)
    }

    /// The place of the rule `id` names, if the list has it.
    pub fn place(&self, id: &str) -> Option<usize> {
        crate::profile_source::rule_index(id).filter(|&place| place < self.rules.len())
    }

    /// The type of the rule at `place` in capitals, as Clash configurations
    /// write it: for a type the Core does not know, the source's own word,
    /// which is what an edit of the rule writes back.
    pub fn kind(&self, place: usize) -> Option<String> {
        let rule = self.rules.get(place)?;
        Some(match self.unknown_kinds.get(&place) {
            Some(written) => written.to_ascii_uppercase(),
            None => rule.kind.as_str().to_ascii_uppercase(),
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRuleProvider {
    pub name: String,
    pub url: Option<String>,
    pub behavior: Option<String>,
    pub fetched_at_unix: Option<i64>,
    pub entry_count: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedProxyNode {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub sort_order: i64,
    /// Why the Core cannot connect through this node, if it cannot
    /// (`egrio_core::proxy_support_issue`); such nodes are listed, not offered.
    pub unsupported: Option<String>,
    /// `hidden: true`: left out of the node list and its latency tests; its
    /// groups still list it.
    pub hidden: bool,
    /// The node's own `test-url`, if it names one; its tests otherwise
    /// request `egrio_core::DEFAULT_PROBE_TEST_URL`.
    pub test_url: Option<String>,
    /// The node or policy group the node reaches its server through
    /// (`dialer-proxy`), if it names one.
    pub dialer_proxy: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedPolicyGroup {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub members: Vec<String>,
    pub sort_order: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    schema_version: i64,
    active_profile_id: Option<String>,
    profiles: Vec<StoredProfile>,
    // Host preferences and recovery remain product state, never engine overlays.
    #[serde(default)]
    app_settings: BTreeMap<String, String>,
}
impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            active_profile_id: None,
            profiles: Vec::new(),
            app_settings: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProfileStoreError {
    #[error("could not resolve application data directory")]
    NoDataDir,
    #[error("profile store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file was published but durability is unconfirmed; reread before retrying ({path}): {source}")]
    PublishedButNotSynced {
        path: String,
        source: std::io::Error,
    },
    #[error("profile store JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid profile configuration: {0}")]
    Configuration(String),
    #[error("unsupported profile store schema {0}")]
    UnsupportedSchema(i64),
    #[error("profile changed; reload before retrying")]
    RevisionConflict,
    #[error("the profile's rule provider changed; discarded the outdated download")]
    StaleRefresh,
    #[error("record not found")]
    NotFound,
    #[error("global outbound is not available in this profile: {0}")]
    InvalidGlobalOutbound(String),
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    data_dir: PathBuf,
    parsed: Arc<ParsedSources>,
}
impl ProfileStore {
    /// Every command opens the application store anew; its parsed sources
    /// outlive the handle.
    pub fn open() -> Result<Self, ProfileStoreError> {
        static PARSED: LazyLock<Arc<ParsedSources>> = LazyLock::new(Default::default);
        let data_dir =
            crate::app_paths::app_data_dir().map_err(|_| ProfileStoreError::NoDataDir)?;
        Self::open_with(&data_dir, PARSED.clone())
    }
    /// An isolated store with parsed sources of its own.
    #[cfg(test)]
    pub fn open_at(data_dir: impl AsRef<Path>) -> Result<Self, ProfileStoreError> {
        Self::open_with(data_dir.as_ref(), Arc::default())
    }
    fn open_with(data_dir: &Path, parsed: Arc<ParsedSources>) -> Result<Self, ProfileStoreError> {
        let store = Self {
            data_dir: data_dir.to_path_buf(),
            parsed,
        };
        store.load()?;
        Ok(store)
    }
    fn manifest_path(&self) -> PathBuf {
        self.data_dir.join(MANIFEST_FILE)
    }
    fn source_path(&self, hash: &str) -> PathBuf {
        self.data_dir
            .join("configuration/sources")
            .join(format!("{hash}.yaml"))
    }
    fn provider_path(&self, descriptor: &str, hash: &str) -> PathBuf {
        self.data_dir
            .join("configuration/provider-cache")
            .join(descriptor)
            .join(hash)
    }
    fn load(&self) -> Result<Manifest, ProfileStoreError> {
        if !self.manifest_path().is_file() {
            return Ok(Manifest::default());
        }
        let doc: Manifest = serde_json::from_str(&fs::read_to_string(self.manifest_path())?)?;
        if doc.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ProfileStoreError::UnsupportedSchema(doc.schema_version));
        }
        Ok(doc)
    }
    fn save(&self, doc: &Manifest) -> Result<(), ProfileStoreError> {
        write_text_file(&self.manifest_path(), &serde_json::to_string_pretty(doc)?)
    }
    fn write<T>(
        &self,
        f: impl FnOnce(&mut Manifest) -> Result<T, ProfileStoreError>,
    ) -> Result<T, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut doc = self.load()?;
        let result = f(&mut doc)?;
        self.save(&doc)?;
        Ok(result)
    }
    fn record<'a>(doc: &'a Manifest, id: &str) -> Result<&'a StoredProfile, ProfileStoreError> {
        doc.profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or(ProfileStoreError::NotFound)
    }
    fn record_mut<'a>(
        doc: &'a mut Manifest,
        id: &str,
    ) -> Result<&'a mut StoredProfile, ProfileStoreError> {
        doc.profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(ProfileStoreError::NotFound)
    }
    fn raw(&self, record: &StoredProfile) -> Result<String, ProfileStoreError> {
        Ok(fs::read_to_string(
            self.source_path(&record.source_content_hash),
        )?)
    }
    fn put_source(&self, raw: &str) -> Result<String, ProfileStoreError> {
        let hash = content_hash(raw);
        let path = self.source_path(&hash);
        if !path.is_file() {
            write_text_file(&path, raw)?;
        }
        Ok(hash)
    }
    /// The record's stored source, parsed at most once while it stays recent.
    fn parsed(&self, record: &StoredProfile) -> Result<Arc<ParsedSource>, ProfileStoreError> {
        self.parsed
            .get_or_parse(&record.source_content_hash, || self.raw(record))
    }
    /// A source that is about to be stored.
    fn parse_new(&self, raw: &str) -> Result<Arc<ParsedSource>, ProfileStoreError> {
        self.parsed
            .get_or_parse(&content_hash(raw), || Ok(raw.to_string()))
    }
    fn compose(
        &self,
        record: &StoredProfile,
        providers: bool,
    ) -> Result<EffectiveConfigSnapshot, ProfileStoreError> {
        self.compose_source(record, &*self.parsed(record)?, providers)
    }
    fn compose_source(
        &self,
        record: &StoredProfile,
        source: &ParsedSource,
        providers: bool,
    ) -> Result<EffectiveConfigSnapshot, ProfileStoreError> {
        let choices = ProfileChoices {
            traffic_mode: record.traffic_mode,
            group_selections: record.group_choices.clone(),
            global_outbound: record.global_outbound.clone(),
        };
        let mut snapshot = compose(&record.id, &record.name, source, &choices)
            .map_err(ProfileStoreError::Configuration)?;
        if providers {
            snapshot.profile.rule_sets = self.load_required_provider_contents(record, source)?;
        }
        Ok(snapshot)
    }
    /// Read from the stored choices, which were validated when saved, and a
    /// few facts of the source, so a summary composes nothing and the list
    /// of profiles keeps no source parsed (see [`ParsedSources`]).
    fn summary(&self, record: &StoredProfile) -> Result<SavedProfileSummary, ProfileStoreError> {
        let facts = self
            .parsed
            .facts(&record.source_content_hash, || self.raw(record))?;
        Ok(SavedProfileSummary {
            id: record.id.clone(),
            name: record.name.clone(),
            revision: record.revision.to_string(),
            source_revision: record.source_content_hash.clone(),
            traffic_policy_mode: traffic_mode(facts.mode, record.traffic_mode),
            global_outbound: record.global_outbound.clone(),
            proxies: facts.proxies,
            groups: facts.groups,
            rules: facts.rules,
            updated_at_unix: record.updated_at_unix,
        })
    }
    pub(crate) fn profile_configuration_snapshot(
        &self,
        id: &str,
    ) -> Result<EffectiveConfigSnapshot, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        self.compose(Self::record(&doc, id)?, false)
    }
    pub(crate) fn active_configuration_snapshot(
        &self,
    ) -> Result<Option<EffectiveConfigSnapshot>, ProfileStoreError> {
        self.active_snapshot(true)
    }

    pub(crate) fn active_settings_snapshot(
        &self,
    ) -> Result<Option<EffectiveConfigSnapshot>, ProfileStoreError> {
        self.active_snapshot(false)
    }

    fn active_snapshot(
        &self,
        include_provider_contents: bool,
    ) -> Result<Option<EffectiveConfigSnapshot>, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        doc.active_profile_id
            .as_deref()
            .map(|id| self.compose(Self::record(&doc, id)?, include_provider_contents))
            .transpose()
    }
    pub fn list_profiles(&self) -> Result<Vec<SavedProfileSummary>, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut summaries = self
            .load()?
            .profiles
            .iter()
            .map(|record| self.summary(record))
            .collect::<Result<Vec<_>, _>>()?;
        summaries.sort_by_key(|s| std::cmp::Reverse(s.updated_at_unix));
        Ok(summaries)
    }
    pub fn profile_summary_by_id(
        &self,
        id: &str,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        self.summary(Self::record(&self.load()?, id)?)
    }
    pub fn active_profile(&self) -> Result<Option<SavedProfileSummary>, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        doc.active_profile_id
            .as_deref()
            .map(|id| self.summary(Self::record(&doc, id)?))
            .transpose()
    }
    pub fn active_profile_document(&self) -> Result<Option<RuntimeProfile>, ProfileStoreError> {
        Ok(self.active_configuration_snapshot()?.map(|s| s.profile))
    }
    pub fn set_active_profile(&self, id: &str) -> Result<SavedProfileSummary, ProfileStoreError> {
        self.write(|doc| {
            let summary = self.summary(Self::record(doc, id)?)?;
            doc.active_profile_id = Some(id.into());
            Ok(summary)
        })
    }
    /// Runtime stop/cleanup, if required, is performed by the configuration service first.
    pub fn delete_profile(&self, id: &str) -> Result<(), ProfileStoreError> {
        self.write(|doc| {
            let before = doc.profiles.len();
            doc.profiles.retain(|p| p.id != id);
            if before == doc.profiles.len() {
                return Err(ProfileStoreError::NotFound);
            }
            if doc.active_profile_id.as_deref() == Some(id) {
                doc.active_profile_id = None;
            }
            Ok(())
        })?;
        // Logical deletion has committed. Cleanup failure must not resurrect it.
        self.cleanup_unreferenced_blobs();
        Ok(())
    }
    pub fn rename_profile(
        &self,
        id: &str,
        name: &str,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            record.name = name.into();
            bump(record);
            self.summary(record)
        })
    }
    pub fn set_group_selection(
        &self,
        id: &str,
        group_id: &str,
        member: &str,
    ) -> Result<(), ProfileStoreError> {
        self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            // A choice depends only on the source groups, so validating it
            // there spares composing the rule list.
            selectable_group(&self.parsed(record)?.content.groups, group_id, member)
                .map_err(ProfileStoreError::Configuration)?;
            record.group_choices.insert(group_id.into(), member.into());
            bump(record);
            Ok(())
        })
    }
    pub fn group_selections(&self, id: &str) -> Result<Vec<(String, String)>, ProfileStoreError> {
        Ok(Self::record(&self.load()?, id)?
            .group_choices
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
    pub fn set_profile_traffic_policy(
        &self,
        id: &str,
        mode: TrafficPolicyMode,
        outbound: Option<String>,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            record.traffic_mode = Some(mode);
            if let Some(outbound) = outbound {
                if outbound.trim().is_empty() {
                    return Err(ProfileStoreError::InvalidGlobalOutbound(outbound));
                }
                record.global_outbound = Some(outbound);
            }
            self.compose(record, false)?;
            bump(record);
            self.summary(record)
        })
    }
    /// Read from the parsed source: composing only adds the choices, which
    /// the inventory does not carry.
    pub fn profile_inventory(&self, id: &str) -> Result<ProfileInventory, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        Ok(projection::inventory(
            &record.id,
            &self.parsed(record)?.content,
        ))
    }
    pub fn profile_rules(&self, id: &str) -> Result<ProfileRuleList, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        let source = self.parsed(record)?;
        Ok(ProfileRuleList {
            profile_id: record.id.clone(),
            source_revision: record.source_content_hash.clone(),
            rules: source.content.rules.clone(),
            unknown_kinds: source.unknown_rule_kinds.clone(),
            unsupported: egrio_core::rule_support_issues(&source.content.rules)
                .into_iter()
                .map(|issue| (issue.rule, issue.message))
                .collect(),
            rule_providers: providers_for_record(record, &source),
        })
    }
    /// What a latency test of the profile's nodes compiles without a Core:
    /// its nodes, groups and DNS, none of its rules.
    pub fn probe_profile(&self, id: &str) -> Result<RuntimeProfile, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        let content = &self.parsed(record)?.content;
        let mut profile = RuntimeProfile::new(&record.name);
        profile.id = record.id.clone();
        profile.dns = content.dns.clone();
        profile.proxies = content.proxies.clone();
        profile.groups = content.groups.clone();
        Ok(profile)
    }
    /// All source/provider reads and preparing writes use STORE_WRITE_LOCK. A
    /// returned effective snapshot owns decoded data and never reopens these blobs.
    fn cleanup_unreferenced_blobs(&self) {
        if let Err(error) = self.collect_unreferenced_blobs() {
            log::warn!("configuration blob cleanup deferred: {error}");
        }
    }

    pub fn collect_unreferenced_blobs(&self) -> Result<(), ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let sources: HashSet<_> = doc
            .profiles
            .iter()
            .map(|p| self.source_path(&p.source_content_hash))
            .collect();
        let providers: HashSet<_> = doc
            .profiles
            .iter()
            .flat_map(|p| p.provider_cache.iter())
            .map(|p| self.provider_path(&p.descriptor_hash, &p.content_hash))
            .collect();
        remove_unreferenced(&self.data_dir.join("configuration/sources"), &sources)?;
        remove_unreferenced(
            &self.data_dir.join("configuration/provider-cache"),
            &providers,
        )?;
        Ok(())
    }
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
fn bump(record: &mut StoredProfile) {
    record.revision = record.revision.saturating_add(1);
}
/// An edit of the source names the source it was made against.
fn check_source(record: &StoredProfile, expected: &str) -> Result<(), ProfileStoreError> {
    if record.source_content_hash != expected {
        Err(ProfileStoreError::RevisionConflict)
    } else {
        Ok(())
    }
}
fn content_hash(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}
fn provider_descriptor(provider: &RuleProvider) -> String {
    content_hash(&format!(
        "{}\0{}\0{}",
        provider.name,
        provider.url.as_deref().unwrap_or(""),
        provider.behavior.as_deref().unwrap_or("")
    ))
}
fn remove_unreferenced(dir: &Path, referenced: &HashSet<PathBuf>) -> Result<(), ProfileStoreError> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            remove_unreferenced(&path, referenced)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(path)?;
            }
        } else if !referenced.contains(&path) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub(crate) fn write_text_file(path: &Path, text: &str) -> Result<(), ProfileStoreError> {
    write_text_file_with_directory_sync(path, text, |parent, created_directories| {
        #[cfg(unix)]
        {
            fs::File::open(parent)?.sync_all()?;
            for directory in created_directories {
                if let Some(container) = directory.parent() {
                    fs::File::open(container)?.sync_all()?;
                }
            }
        }
        #[cfg(not(unix))]
        let _ = (parent, created_directories);
        Ok(())
    })
}

fn write_text_file_with_directory_sync(
    path: &Path,
    text: &str,
    sync_directories: impl FnOnce(&Path, &[PathBuf]) -> Result<(), std::io::Error>,
) -> Result<(), ProfileStoreError> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut created_directories = Vec::new();
    let mut ancestor = parent;
    while !ancestor.exists() {
        created_directories.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().unwrap_or_else(|| Path::new("."));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4()
    ));
    let result = (|| -> Result<(), ProfileStoreError> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_directories(parent, &created_directories).map_err(|source| {
            ProfileStoreError::PublishedButNotSynced {
                path: path.display().to_string(),
                source,
            }
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
