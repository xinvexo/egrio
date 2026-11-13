use super::*;
use crate::profile_source::set_top_level_scalar;

impl ProfileStore {
    /// A new profile around a document from elsewhere, a download or a file.
    ///
    /// Such a document does not get to open this machine's proxy to the
    /// network: where it says `allow-lan: true`, the copy kept says `false`.
    /// The listener then takes anyone on the network without a password, to
    /// the proxy's nodes and, through DIRECT, to what only this machine was
    /// meant to reach. Whoever uses the machine turns it on, in the
    /// settings or in the editor.
    pub fn import_profile(
        &self,
        name: String,
        raw: String,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        let raw = if self.parse_new(&raw)?.network.allow_lan {
            set_top_level_scalar(&raw, "allow-lan", "false").map_err(|error| {
                ProfileStoreError::Configuration(format!(
                    "the configuration opens the proxy to the local network (allow-lan: true), \
                     which an imported one may not, and it could not be rewritten: {error}"
                ))
            })?
        } else {
            raw
        };
        self.create_profile(name, raw)
    }

    /// A new profile around a YAML document its user wrote here.
    pub fn create_profile(
        &self,
        name: String,
        raw: String,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        let mut record = StoredProfile {
            id: Uuid::new_v4().to_string(),
            name,
            revision: 1,
            source_content_hash: content_hash(&raw),
            traffic_mode: None,
            group_choices: BTreeMap::new(),
            global_outbound: None,
            provider_cache: Vec::new(),
            created_at_unix: now(),
            updated_at_unix: now(),
        };
        self.compose_source(&record, &*self.parse_new(&raw)?, false)?;
        let saved = self.write(|doc| {
            record.source_content_hash = self.put_source(&raw)?;
            let id = record.id.clone();
            doc.profiles.push(record);
            if doc.active_profile_id.is_none() {
                doc.active_profile_id = Some(id.clone());
            }
            self.summary(Self::record(doc, &id)?)
        })?;
        self.cleanup_unreferenced_blobs();
        Ok(saved)
    }
    pub fn get_profile_source(&self, id: &str) -> Result<ProfileSourceDocument, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        Ok(ProfileSourceDocument {
            profile_id: id.into(),
            yaml: self.raw(record)?,
            source_revision: record.source_content_hash.clone(),
        })
    }
    pub fn save_profile_source(
        &self,
        id: &str,
        raw: String,
        expected_source_revision: &str,
    ) -> Result<SavedProfileSummary, ProfileStoreError> {
        let saved = self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            check_source(record, expected_source_revision)?;
            self.replace_source(record, &raw)?;
            self.summary(record)
        })?;
        self.cleanup_unreferenced_blobs();
        Ok(saved)
    }
    /// The Profile with its source's top-level `key` set to the YAML text
    /// `value`, composed but not stored.
    pub(crate) fn preview_profile_setting(
        &self,
        id: &str,
        expected_source_revision: &str,
        key: &str,
        value: &str,
    ) -> Result<EffectiveConfigSnapshot, ProfileStoreError> {
        let _guard = STORE_WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let doc = self.load()?;
        let record = Self::record(&doc, id)?;
        check_source(record, expected_source_revision)?;
        let raw = set_top_level_scalar(&self.raw(record)?, key, value)
            .map_err(ProfileStoreError::Configuration)?;
        self.compose_source(record, &*self.parse_new(&raw)?, false)
    }
    /// Writes the top-level `key` into the source, keeping the rest of the
    /// file as its author wrote it.
    pub fn set_profile_setting(
        &self,
        id: &str,
        expected_source_revision: &str,
        key: &str,
        value: &str,
    ) -> Result<(), ProfileStoreError> {
        self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            check_source(record, expected_source_revision)?;
            let raw = set_top_level_scalar(&self.raw(record)?, key, value)
                .map_err(ProfileStoreError::Configuration)?;
            self.replace_source(record, &raw)
        })?;
        self.cleanup_unreferenced_blobs();
        Ok(())
    }
    /// Makes `raw` the record's source once it composes with the record's
    /// choices. A source that writes another `mode` clears the picked one.
    pub(super) fn replace_source(
        &self,
        record: &mut StoredProfile,
        raw: &str,
    ) -> Result<(), ProfileStoreError> {
        let source = self.parse_new(raw)?;
        if self.parsed(record)?.mode != source.mode {
            record.traffic_mode = None;
        }
        self.compose_source(record, &source, false)?;
        retain_source_provider_cache(record, &source);
        record.source_content_hash = self.put_source(raw)?;
        record.updated_at_unix = now();
        bump(record);
        Ok(())
    }
}
