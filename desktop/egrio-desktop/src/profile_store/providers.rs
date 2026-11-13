use super::*;

impl ProfileStore {
    /// Only the providers the rule list names need to block a start.
    pub fn missing_rule_provider_fetch_targets(
        &self,
        id: &str,
    ) -> Result<Vec<SavedRuleProvider>, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        let required = required_provider_definitions(&*self.parsed(record)?)?;
        Ok(required
            .into_iter()
            .filter(|provider| {
                let descriptor = provider_descriptor(provider);
                !record.provider_cache.iter().any(|cache| {
                    cache.name == provider.name
                        && cache.descriptor_hash == descriptor
                        && cache.entry_count > 0
                        && self
                            .provider_path(&descriptor, &cache.content_hash)
                            .metadata()
                            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
                })
            })
            .map(|provider| SavedRuleProvider {
                name: provider.name,
                url: provider.url,
                behavior: provider.behavior,
                fetched_at_unix: None,
                entry_count: None,
            })
            .collect())
    }

    pub(super) fn load_required_provider_contents(
        &self,
        record: &StoredProfile,
        source: &ParsedSource,
    ) -> Result<Vec<RuleSetContent>, ProfileStoreError> {
        required_provider_definitions(source)?
            .into_iter()
            .map(|provider| {
                let descriptor = provider_descriptor(&provider);
                let cache = record.provider_cache.iter().find(|cache| {
                    cache.name == provider.name && cache.descriptor_hash == descriptor
                }).ok_or_else(|| ProfileStoreError::Configuration(format!(
                    "rule provider '{}' has no prepared content; prepare its dependencies before applying", provider.name
                )))?;
                let body = fs::read_to_string(self.provider_path(&descriptor, &cache.content_hash))
                    .map_err(|error| ProfileStoreError::Configuration(format!(
                        "rule provider '{}' cache is unavailable: {error}", provider.name
                    )))?;
                let entries = parse_rule_provider_entries(&body);
                if entries.is_empty() {
                    return Err(ProfileStoreError::Configuration(format!(
                        "rule provider '{}' cache contains no entries", provider.name
                    )));
                }
                let behavior = provider.behavior.as_deref().and_then(RuleSetBehavior::from_clash_text)
                    .expect("required_provider_definitions checked the behavior");
                Ok(RuleSetContent { name: provider.name, behavior, entries })
            })
            .collect()
    }

    pub fn rule_provider_fetch_targets(
        &self,
        id: &str,
    ) -> Result<Vec<SavedRuleProvider>, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        Ok(providers_for_record(record, &*self.parsed(record)?))
    }
    pub fn rule_provider_fetch_target(
        &self,
        id: &str,
        name: &str,
    ) -> Result<SavedRuleProvider, ProfileStoreError> {
        self.rule_provider_fetch_targets(id)?
            .into_iter()
            .find(|p| p.name == name)
            .ok_or(ProfileStoreError::NotFound)
    }
    pub fn save_rule_provider_content(
        &self,
        id: &str,
        target: &SavedRuleProvider,
        body: &str,
        entry_count: i64,
    ) -> Result<bool, ProfileStoreError> {
        let changed = self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            let source = self.parsed(record)?;
            let provider = source
                .rule_providers
                .iter()
                .find(|p| {
                    p.name == target.name && p.url == target.url && p.behavior == target.behavior
                })
                .ok_or(ProfileStoreError::StaleRefresh)?;
            let descriptor = provider_descriptor(provider);
            let hash = content_hash(body);
            let changed = !record.provider_cache.iter().any(|cache| {
                cache.name == target.name
                    && cache.descriptor_hash == descriptor
                    && cache.content_hash == hash
            });
            let path = self.provider_path(&descriptor, &hash);
            if !path.is_file() {
                write_text_file(&path, body)?;
            }
            record
                .provider_cache
                .retain(|cache| cache.name != target.name);
            record.provider_cache.push(ProviderCacheReference {
                name: target.name.clone(),
                descriptor_hash: descriptor,
                content_hash: hash,
                fetched_at_unix: now(),
                entry_count,
            });
            if changed {
                bump(record);
            }
            Ok(changed)
        })?;
        self.cleanup_unreferenced_blobs();
        Ok(changed)
    }
}

pub(super) fn providers_for_record(
    record: &StoredProfile,
    source: &ParsedSource,
) -> Vec<SavedRuleProvider> {
    source
        .rule_providers
        .iter()
        .map(|provider| {
            let descriptor = provider_descriptor(provider);
            let cache = record
                .provider_cache
                .iter()
                .find(|cache| cache.name == provider.name && cache.descriptor_hash == descriptor);
            SavedRuleProvider {
                name: provider.name.clone(),
                url: provider.url.clone(),
                behavior: provider.behavior.clone(),
                fetched_at_unix: cache.map(|c| c.fetched_at_unix),
                entry_count: cache.map(|c| c.entry_count),
            }
        })
        .collect()
}

fn required_provider_definitions(
    source: &ParsedSource,
) -> Result<Vec<RuleProvider>, ProfileStoreError> {
    let definitions = &source.rule_providers;
    let mut seen = HashSet::new();
    let mut required = Vec::new();
    for rule in &source.content.rules {
        // Core explicitly rejects nested RULE-SET in logic expressions and
        // provider contents. Do not invent a second nested-reference grammar.
        if rule.kind != RuleKind::RuleSet {
            continue;
        }
        let name = rule
            .payload
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProfileStoreError::Configuration(
                    "rule set rule is missing its provider name".into(),
                )
            })?;
        if !seen.insert(name.to_string()) {
            continue;
        }
        let provider = definitions
            .iter()
            .find(|provider| provider.name == name)
            .ok_or_else(|| {
                ProfileStoreError::Configuration(format!(
                    "rule provider '{name}' is not declared in the source"
                ))
            })?;
        if provider
            .behavior
            .as_deref()
            .and_then(RuleSetBehavior::from_clash_text)
            .is_none()
        {
            return Err(ProfileStoreError::Configuration(format!(
                "rule provider '{name}' has an unsupported or missing behavior"
            )));
        }
        required.push(provider.clone());
    }
    Ok(required)
}

pub(super) fn retain_source_provider_cache(record: &mut StoredProfile, source: &ParsedSource) {
    let descriptors: HashSet<_> = source
        .rule_providers
        .iter()
        .map(provider_descriptor)
        .collect();
    record
        .provider_cache
        .retain(|cache| descriptors.contains(&cache.descriptor_hash));
}
