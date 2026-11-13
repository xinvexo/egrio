//! The rules page edits the source's `rules` list in place. A rule's id is
//! its position, valid for the source revision it was listed with.
use super::*;
use crate::configuration::known_outbound;
use crate::profile_source::{edit_rules, rule_index, RulesEdit};

impl ProfileStore {
    /// A new rule goes first, ahead of the rules it should take precedence
    /// over.
    pub fn add_profile_rule(
        &self,
        id: &str,
        line: &str,
        expected_source_revision: &str,
    ) -> Result<(), ProfileStoreError> {
        self.edit_profile_rules(
            id,
            expected_source_revision,
            RulesEdit::Insert { at: 0, line },
            Some(0),
        )
    }
    pub fn update_profile_rule(
        &self,
        id: &str,
        rule_id: &str,
        line: &str,
        expected_source_revision: &str,
    ) -> Result<(), ProfileStoreError> {
        let index = position(rule_id)?;
        self.edit_profile_rules(
            id,
            expected_source_revision,
            RulesEdit::Replace { index, line },
            Some(index),
        )
    }
    pub fn delete_profile_rules(
        &self,
        id: &str,
        rule_ids: &[String],
        expected_source_revision: &str,
    ) -> Result<(), ProfileStoreError> {
        let indices = positions(rule_ids)?;
        self.edit_profile_rules(
            id,
            expected_source_revision,
            RulesEdit::Delete { indices: &indices },
            None,
        )
    }
    pub fn reorder_profile_rules(
        &self,
        id: &str,
        ordered_rule_ids: &[String],
        expected_source_revision: &str,
    ) -> Result<(), ProfileStoreError> {
        let order = positions(ordered_rule_ids)?;
        self.edit_profile_rules(
            id,
            expected_source_revision,
            RulesEdit::Reorder { order: &order },
            None,
        )
    }

    /// Applies `edit` to the source and stores the result. The rule the edit
    /// writes, at position `written`, must name what the profile declares.
    fn edit_profile_rules(
        &self,
        id: &str,
        expected_source_revision: &str,
        edit: RulesEdit<'_>,
        written: Option<usize>,
    ) -> Result<(), ProfileStoreError> {
        self.write(|doc| {
            let record = Self::record_mut(doc, id)?;
            check_source(record, expected_source_revision)?;
            let raw =
                edit_rules(&self.raw(record)?, edit).map_err(ProfileStoreError::Configuration)?;
            if let Some(index) = written {
                let source = self.parse_new(&raw)?;
                let rule = source
                    .content
                    .rules
                    .get(index)
                    .ok_or(ProfileStoreError::NotFound)?;
                check_written_rule(&source, &rule)?;
            }
            self.replace_source(record, &raw)
        })?;
        self.cleanup_unreferenced_blobs();
        Ok(())
    }
}

fn position(rule_id: &str) -> Result<usize, ProfileStoreError> {
    rule_index(rule_id).ok_or(ProfileStoreError::NotFound)
}

fn positions(rule_ids: &[String]) -> Result<Vec<usize>, ProfileStoreError> {
    rule_ids.iter().map(|rule_id| position(rule_id)).collect()
}

/// A rule the app writes routes only to an outbound and a rule provider the
/// profile declares. Rules written by hand are their author's to keep
/// consistent: the Core reports a missing outbound when a connection meets
/// the rule.
fn check_written_rule(
    source: &ParsedSource,
    rule: &RouteRule<'_>,
) -> Result<(), ProfileStoreError> {
    if !known_outbound(&source.content, rule.outbound) {
        return Err(ProfileStoreError::Configuration(format!(
            "the rule's outbound is not in this profile: {}",
            rule.outbound
        )));
    }
    if rule.kind == RuleKind::RuleSet
        && !source
            .rule_providers
            .iter()
            .any(|provider| rule.payload == Some(provider.name.as_str()))
    {
        return Err(ProfileStoreError::Configuration(format!(
            "the rule's provider is not in this profile: {}",
            rule.payload.unwrap_or_default()
        )));
    }
    Ok(())
}
