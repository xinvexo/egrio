//! The rules page's reads and actions: the active profile's rules, which the
//! connections page names too, and the counts of the connections each
//! matched; the changes made from the table and the dialog; the rule sets'
//! updates and the route test. A change is made against the version of the
//! file the page shows, so one made elsewhere in between fails instead of
//! touching other rules. Successes show in place; failures and the summary
//! of a rule set update go to the message record.

use std::net::IpAddr;
use std::path::Path;

use egrio_core::rule_engine::TransportNetwork;
use egrio_core::RouteMatchInput;
use egrio_desktop::models::ProfileRuleList;
use egrio_desktop::operations::{profiles, telemetry};
use egrio_desktop::rule_provider_fetch::RuleProviderRefreshReport;

use super::Ui;
use crate::backend::{Backend, FilePurpose, FileRequest};
use crate::messages::{Level, Source};
use crate::msg::{Msg, RulesMsg};
use crate::node::moved_order;
use crate::pages::rules::{provider_names, shown_selection, RuleDraft};
use crate::state::{Dialog, Section};

impl<B: Backend> Ui<B> {
    /// Reads the active profile's rules.
    pub(super) fn load_rules(&mut self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let profile_id = profile.id.clone();
        self.spawn_blocking(move || {
            Msg::Rules(RulesMsg::Loaded {
                result: profiles::profile_rules(profile_id.clone()),
                profile_id,
            })
        });
    }

    /// Reads the rules again when the list shown is not the active
    /// profile's current file.
    pub(super) fn rules_follow_profile(&mut self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let current = self
            .state
            .rules
            .list_for(&profile.id)
            .is_some_and(|list| list.source_revision == profile.source_revision);
        if !current {
            self.load_rules();
        }
    }

    /// The connections each rule matched, an in-memory read.
    pub(super) fn load_hits(&mut self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let hits = telemetry::rule_hits(&self.desktop.history, &profile.id);
        self.state.rules.set_hits(hits);
    }

    /// The list shown, if it is the active profile's.
    fn shown_rules(&self) -> Option<&ProfileRuleList> {
        let profile = self.state.active_profile.ready().and_then(Option::as_ref)?;
        self.state.rules.list_for(&profile.id)
    }

    fn rule_draft(&mut self) -> Option<&mut RuleDraft> {
        match &mut self.state.dialog {
            Some(Dialog::Rule(draft)) if !draft.pending => Some(draft),
            _ => None,
        }
    }

    pub(super) fn rules(&mut self, msg: RulesMsg) {
        let text = self.state.text();
        match msg {
            RulesMsg::Loaded { profile_id, result } => {
                let active = self
                    .state
                    .active_profile
                    .ready()
                    .and_then(Option::as_ref)
                    .map(|profile| profile.id.as_str());
                // A read for a profile no longer in use.
                if active == Some(profile_id.as_str()) {
                    self.state.rules.set_list(result.into());
                }
            }
            RulesMsg::Filter(filter) => self.state.rules.filter = filter,
            RulesMsg::Select(keys) => self.state.rules.selected = keys,
            RulesMsg::Edit(id) => {
                let Some(list) = self.shown_rules() else {
                    return;
                };
                let draft = list
                    .place(&id)
                    .and_then(|place| RuleDraft::edit(list, place));
                if let Some(draft) = draft {
                    if !self.state.rules.saving && self.state.dialog.is_none() {
                        self.state.dialog = Some(Dialog::Rule(draft));
                    }
                }
            }
            RulesMsg::Add => {
                if self.state.rules.saving || self.state.dialog.is_some() {
                    return;
                }
                if let Some(list) = self.shown_rules() {
                    self.state.dialog = Some(Dialog::Rule(RuleDraft::new(list)));
                }
            }
            RulesMsg::Delete => self.delete_rules(),
            RulesMsg::Deleted(result) => {
                self.state.rules.saving = false;
                match result {
                    Ok(()) => self.state.rules.selected.clear(),
                    Err(error) => self.note(
                        Level::Error,
                        Source::Rules,
                        text.rules_delete_failed(),
                        Some(error),
                    ),
                }
                self.load_rules();
            }
            RulesMsg::Move { keys, to } => self.move_rules(keys, to),
            RulesMsg::Moved(result) => {
                self.state.rules.saving = false;
                if let Err(error) = result {
                    self.note(
                        Level::Error,
                        Source::Rules,
                        text.rules_reorder_failed(),
                        Some(error),
                    );
                }
                // The file's order, also after a failure.
                self.load_rules();
            }
            RulesMsg::RefreshProviders => {
                let Some(profile_id) = self.shown_rules().map(|list| list.profile_id.clone())
                else {
                    return;
                };
                if self.state.rules.refreshing {
                    return;
                }
                self.state.rules.refreshing = true;
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    Msg::Rules(RulesMsg::ProvidersRefreshed(
                        profiles::update_all_rule_providers(&runtime, profile_id).await,
                    ))
                });
            }
            RulesMsg::ProvidersRefreshed(result) => {
                self.state.rules.refreshing = false;
                match result {
                    Ok(report) => self.providers_refreshed(report),
                    Err(error) => self.note(
                        Level::Error,
                        Source::Rules,
                        text.providers_refresh_failed(),
                        Some(error),
                    ),
                }
                self.load_rules();
            }
            RulesMsg::ProviderFetched(result) => {
                if let Err(error) = result {
                    self.note(
                        Level::Error,
                        Source::Rules,
                        text.provider_fetch_failed(),
                        Some(error),
                    );
                }
                self.load_rules();
            }
            RulesMsg::ResetHits => {
                if let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) {
                    telemetry::reset_rule_hits(&self.desktop.history, &profile.id);
                    self.load_hits();
                }
            }
            RulesMsg::RouteTarget(target) => self.state.rules.route.target = target,
            RulesMsg::TestRoute => self.test_route(),
            RulesMsg::RouteTested { target, result } => {
                let route = &mut self.state.rules.route;
                route.running = false;
                route.result = Some((target, *result));
            }
            RulesMsg::DraftKind(kind) => {
                let providers = self.shown_rules().map(provider_names).unwrap_or_default();
                if let Some(draft) = self.rule_draft() {
                    draft.set_kind(&kind, &providers);
                }
            }
            RulesMsg::DraftPayload(payload) => {
                if let Some(draft) = self.rule_draft() {
                    draft.payload = payload;
                }
            }
            RulesMsg::DraftOutbound(outbound) => {
                if let Some(draft) = self.rule_draft() {
                    draft.outbound = outbound;
                }
            }
            RulesMsg::DraftNoResolve(on) => {
                if let Some(draft) = self.rule_draft() {
                    draft.no_resolve = on;
                }
            }
            RulesMsg::PickExecutable => {
                if self.rule_draft().is_some() {
                    self.backend.choose_file(&FileRequest {
                        purpose: FilePurpose::RuleExecutable,
                        extensions: Vec::new(),
                    });
                }
            }
            RulesMsg::ExecutableChosen(path) => {
                let Some(path) = path else {
                    return;
                };
                if let Some(draft) = self.rule_draft() {
                    draft.payload = program_payload(&draft.kind, &path);
                }
            }
            RulesMsg::Save => self.save_rule(),
            RulesMsg::Saved {
                fetch,
                result,
                added,
            } => {
                let failed = if added {
                    text.rule_add_failed()
                } else {
                    text.rule_update_failed()
                };
                match result {
                    Ok(()) => {
                        if matches!(self.state.dialog, Some(Dialog::Rule(_))) {
                            self.state.dialog = None;
                        }
                        if let Some(provider) = fetch {
                            self.fetch_provider(provider);
                        }
                    }
                    Err(error) => {
                        if let Some(Dialog::Rule(draft)) = &mut self.state.dialog {
                            draft.pending = false;
                            draft.error = Some(text.message_line(failed, &error));
                        }
                        self.note(Level::Error, Source::Rules, failed, Some(error));
                    }
                }
                self.load_rules();
            }
        }
    }

    /// Deletes the rules the page shows as selected.
    fn delete_rules(&mut self) {
        let Some(list) = self.shown_rules() else {
            return;
        };
        let ids = shown_selection(&self.state);
        if ids.is_empty() || self.state.rules.saving {
            return;
        }
        let (profile_id, revision) = (list.profile_id.clone(), list.source_revision.clone());
        self.state.rules.saving = true;
        let runtime = self.desktop.runtime.clone();
        self.spawn(async move {
            Msg::Rules(RulesMsg::Deleted(
                profiles::delete_profile_rules(&runtime, profile_id, ids, revision).await,
            ))
        });
    }

    fn move_rules(&mut self, keys: Vec<String>, to: usize) {
        let Some(list) = self.shown_rules() else {
            return;
        };
        if self.state.rules.saving || !self.state.rules.filter.trim().is_empty() {
            return;
        }
        let order: Vec<String> = (0..list.rules.len())
            .map(ProfileRuleList::rule_id)
            .collect();
        let moved = moved_order(&order, &keys, to);
        if moved == order {
            return;
        }
        let runtime = self.desktop.runtime.clone();
        let (profile_id, revision) = (list.profile_id.clone(), list.source_revision.clone());
        self.state.rules.saving = true;
        self.state.rules.reorder(&moved);
        self.spawn(async move {
            Msg::Rules(RulesMsg::Moved(
                profiles::reorder_profile_rules(&runtime, profile_id, moved, revision).await,
            ))
        });
    }

    fn save_rule(&mut self) {
        let providers = self.shown_rules().map(provider_names).unwrap_or_default();
        let rule_sets_online: Vec<String> = self
            .shown_rules()
            .map(|list| {
                list.rule_providers
                    .iter()
                    .filter(|provider| provider.url.is_some() && provider.fetched_at_unix.is_none())
                    .map(|provider| provider.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let runtime = self.desktop.runtime.clone();
        let Some(draft) = self.rule_draft() else {
            return;
        };
        if !draft.can_save(&providers) {
            return;
        }
        draft.pending = true;
        draft.error = None;
        let draft = draft.clone();
        // A rule set a rule now names is downloaded if it never was.
        let fetch = (draft.kind == "RULE-SET")
            .then(|| draft.payload.trim().to_string())
            .filter(|name| rule_sets_online.contains(name));
        let payload = draft.saved_payload();
        self.spawn(async move {
            let added = draft.rule_id.is_none();
            let result = match draft.rule_id {
                Some(rule_id) => {
                    profiles::update_profile_rule(
                        &runtime,
                        draft.profile_id,
                        rule_id,
                        draft.kind,
                        payload,
                        draft.outbound,
                        draft.no_resolve,
                        draft.source_revision,
                    )
                    .await
                }
                None => {
                    profiles::add_profile_rule(
                        &runtime,
                        draft.profile_id,
                        draft.kind,
                        payload,
                        draft.outbound,
                        draft.no_resolve,
                        draft.source_revision,
                    )
                    .await
                }
            };
            Msg::Rules(RulesMsg::Saved {
                fetch,
                result,
                added,
            })
        });
    }

    fn fetch_provider(&mut self, provider: String) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let (runtime, profile_id) = (self.desktop.runtime.clone(), profile.id.clone());
        self.spawn(async move {
            Msg::Rules(RulesMsg::ProviderFetched(
                profiles::update_rule_provider(&runtime, profile_id, provider).await,
            ))
        });
    }

    /// One summary of a rule set update, which shows nowhere else.
    fn providers_refreshed(&mut self, report: RuleProviderRefreshReport) {
        let text = self.state.text();
        let (updated, unchanged, failed) = (
            report.updated.len(),
            report.unchanged.len(),
            report.failures.len(),
        );
        if updated + unchanged + failed == 0 {
            self.note(Level::Info, Source::Rules, text.no_remote_providers(), None);
            return;
        }
        let level = match (failed, updated + unchanged) {
            (0, _) => Level::Info,
            (_, 0) => Level::Error,
            _ => Level::Warning,
        };
        let detail = (!report.failures.is_empty()).then(|| report.failures.join("\n"));
        self.note(
            level,
            Source::Rules,
            text.providers_refreshed(updated, unchanged, failed),
            detail,
        );
    }

    fn test_route(&mut self) {
        let target = self.state.rules.route.target.trim().to_string();
        if target.is_empty() || self.state.rules.route.running {
            return;
        }
        self.state.rules.route.running = true;
        let ip = target.parse::<IpAddr>().ok();
        let input = RouteMatchInput {
            host: ip.is_none().then(|| target.clone()),
            destination_ip: ip,
            process_name: None,
            process_path: None,
            destination_port: Some(443),
            source_ip: None,
            source_port: None,
            network: Some(TransportNetwork::Tcp),
        };
        let runtime = self.desktop.runtime.clone();
        self.spawn(async move {
            let result = profiles::evaluate_active_profile_route(&runtime, input).await;
            Msg::Rules(RulesMsg::RouteTested {
                target,
                result: Box::new(result),
            })
        });
    }

    /// The rules page is shown: its rules and their counts.
    pub(super) fn load_rules_page(&mut self) {
        self.rules_follow_profile();
        self.nodes_follow_profile();
        self.load_hits();
    }

    /// What the rules page reads every two seconds.
    pub(super) fn poll_rules(&mut self) {
        self.load_hits();
    }

    /// The profile's file may have changed: the rules shown follow it.
    pub(super) fn rules_profiles_changed(&mut self) {
        if self.state.section == Section::Rules {
            self.load_rules();
        }
    }
}

/// What a process rule names for the chosen program: its whole path, or its
/// name, an app bundle's without `.app`.
fn program_payload(kind: &str, path: &Path) -> String {
    if kind == "PROCESS-PATH" {
        return path.display().to_string();
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.strip_suffix(".app").map(String::from).unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::program_payload;
    use std::path::Path;

    #[test]
    fn a_process_rule_names_the_program_by_name_or_path() {
        let app = Path::new("/Applications/Telegram.app");
        assert_eq!(program_payload("PROCESS-NAME", app), "Telegram");
        assert_eq!(
            program_payload("PROCESS-PATH", app),
            "/Applications/Telegram.app"
        );
        assert_eq!(
            program_payload("PROCESS-NAME", Path::new("/usr/bin/curl")),
            "curl"
        );
    }
}
