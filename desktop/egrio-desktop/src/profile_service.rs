use std::collections::HashMap;

use egrio_core::{NativeCoreDevice, RouteEvaluation, RouteMatchInput};

use super::profile_store::{ProfileInventory, ProfileRuleList, ProfileStore, SavedProfileSummary};
use crate::profile_source::rule_line;

/// A new profile from a file's content (see [`ProfileStore::import_profile`]).
pub fn import_clash_profile(name: String, yaml: String) -> Result<SavedProfileSummary, String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| store.import_profile(name, yaml))
        .map_err(|error| error.to_string())
}

/// A new profile from what its user wrote in the editor.
pub fn create_profile(name: String, yaml: String) -> Result<SavedProfileSummary, String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| store.create_profile(name, yaml))
        .map_err(|error| error.to_string())
}

pub fn get_profile_source(
    profile_id: String,
) -> Result<crate::profile_store::ProfileSourceDocument, String> {
    ProfileStore::open()
        .and_then(|store| store.get_profile_source(&profile_id))
        .map_err(|error| error.to_string())
}

pub fn save_profile_source(
    profile_id: String,
    yaml: String,
    expected_source_revision: String,
) -> Result<SavedProfileSummary, String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| store.save_profile_source(&profile_id, yaml, &expected_source_revision))
        .map_err(|error| error.to_string())
}

pub fn delete_profile(profile_id: String) -> Result<(), String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| store.delete_profile(&profile_id))
        .map_err(|error| error.to_string())
}

pub fn rename_profile(profile_id: String, name: String) -> Result<SavedProfileSummary, String> {
    let _notify = crate::events::notify_profiles_on_return();
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("profile name cannot be empty".to_string());
    }
    ProfileStore::open()
        .and_then(|store| store.rename_profile(&profile_id, trimmed))
        .map_err(|error| error.to_string())
}

pub fn get_group_selections(profile_id: String) -> Result<HashMap<String, String>, String> {
    ProfileStore::open()
        .and_then(|store| store.group_selections(&profile_id))
        .map(|pairs| pairs.into_iter().collect())
        .map_err(|error| error.to_string())
}

pub fn list_profiles() -> Result<Vec<SavedProfileSummary>, String> {
    ProfileStore::open()
        .and_then(|store| store.list_profiles())
        .map_err(|error| error.to_string())
}

pub fn get_active_profile() -> Result<Option<SavedProfileSummary>, String> {
    ProfileStore::open()
        .and_then(|store| store.active_profile())
        .map_err(|error| error.to_string())
}

pub fn set_active_profile(profile_id: String) -> Result<SavedProfileSummary, String> {
    let _notify = crate::events::notify_profiles_on_return();
    let store = ProfileStore::open().map_err(|error| error.to_string())?;
    store
        .set_active_profile(&profile_id)
        .map_err(|error| error.to_string())
}

pub fn get_profile_inventory(profile_id: String) -> Result<ProfileInventory, String> {
    ProfileStore::open()
        .and_then(|store| store.profile_inventory(&profile_id))
        .map_err(|error| error.to_string())
}

pub fn get_profile_rules(profile_id: String) -> Result<ProfileRuleList, String> {
    ProfileStore::open()
        .and_then(|store| store.profile_rules(&profile_id))
        .map_err(|error| error.to_string())
}

/// Whether any stored profile declares this `server:port` as a proxy node.
/// Gates the latency probe, the one command that dials a caller-chosen
/// endpoint, to endpoints the user's own profiles already point at.
pub fn probe_profile(profile_id: &str) -> Result<egrio_core::RuntimeProfile, String> {
    ProfileStore::open()
        .and_then(|store| store.probe_profile(profile_id))
        .map_err(|error| error.to_string())
}

pub fn reorder_profile_rules(
    profile_id: String,
    ordered_rule_ids: Vec<String>,
    expected_source_revision: String,
) -> Result<(), String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| {
            store.reorder_profile_rules(&profile_id, &ordered_rule_ids, &expected_source_revision)
        })
        .map_err(|error| error.to_string())
}

/// The source line for a rule entered on the rules page, its type written
/// in the uppercase Clash configurations use.
fn rule_text(kind: &str, payload: Option<&str>, outbound: &str, no_resolve: bool) -> String {
    let kind = kind.trim().to_ascii_uppercase();
    let kind = kind.as_str();
    let payload = payload.map(str::trim).filter(|value| !value.is_empty());
    // Logic/regex rule lines have no params segment (their payload may
    // contain commas, so the last segment is always the outbound); appending
    // `,no-resolve` would be parsed as the outbound. Those kinds don't
    // consult DNS anyway, so the flag is dropped rather than written.
    let no_resolve = no_resolve
        && !egrio_core::profile::RuleKind::from_clash_text(kind).payload_may_contain_commas();
    rule_line(kind, payload, outbound.trim(), no_resolve)
}

pub fn add_profile_rule(
    profile_id: String,
    kind: String,
    payload: Option<String>,
    outbound: String,
    no_resolve: bool,
    expected_source_revision: String,
) -> Result<(), String> {
    let _notify = crate::events::notify_profiles_on_return();
    let line = rule_text(&kind, payload.as_deref(), &outbound, no_resolve);
    ProfileStore::open()
        .and_then(|store| store.add_profile_rule(&profile_id, &line, &expected_source_revision))
        .map_err(|error| error.to_string())
}

pub fn update_profile_rule(
    profile_id: String,
    rule_id: String,
    kind: String,
    payload: Option<String>,
    outbound: String,
    no_resolve: bool,
    expected_source_revision: String,
) -> Result<(), String> {
    let _notify = crate::events::notify_profiles_on_return();
    let line = rule_text(&kind, payload.as_deref(), &outbound, no_resolve);
    ProfileStore::open()
        .and_then(|store| {
            store.update_profile_rule(&profile_id, &rule_id, &line, &expected_source_revision)
        })
        .map_err(|error| error.to_string())
}

pub fn delete_profile_rules(
    profile_id: String,
    rule_ids: Vec<String>,
    expected_source_revision: String,
) -> Result<(), String> {
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| {
            store.delete_profile_rules(&profile_id, &rule_ids, &expected_source_revision)
        })
        .map_err(|error| error.to_string())
}

pub fn evaluate_active_profile_route(input: RouteMatchInput) -> Result<RouteEvaluation, String> {
    let store = ProfileStore::open().map_err(|error| error.to_string())?;
    let mut profile = store
        .active_profile_document()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no active profile selected".to_string())?;
    profile.geodata = crate::geodata::content_for(&profile);
    NativeCoreDevice::preview_route(&profile, &input)
}

#[cfg(test)]
mod tests {
    use super::rule_text;

    #[test]
    fn entered_rules_become_canonical_source_lines() {
        assert_eq!(
            rule_text(" domain-suffix ", Some(" example.com "), " DIRECT ", true),
            "DOMAIN-SUFFIX,example.com,DIRECT,no-resolve"
        );
        assert_eq!(
            rule_text("MATCH", Some("  "), "Proxy", false),
            "MATCH,Proxy"
        );
        // A logic payload may contain commas, so no params can follow it.
        assert_eq!(
            rule_text("AND", Some("((DOMAIN,a),(NETWORK,udp))"), "REJECT", true),
            "AND,((DOMAIN,a),(NETWORK,udp)),REJECT"
        );
    }
}
