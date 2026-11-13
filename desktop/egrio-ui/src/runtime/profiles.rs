//! The profiles page's reads and actions and its add dialog's imports.
//! Successes show in place; failures go to the message record.

use std::path::Path;

use egrio_desktop::operations::{profiles, settings};

use super::Ui;
use crate::backend::{Backend, FilePurpose, FileRequest};
use crate::messages::{Level, Source};
use crate::msg::{EditorMsg, ImportFailure, Msg, ProfilesMsg};
use crate::pages::profiles::{name_from_url, AddProfile};
use crate::state::{Dialog, ProfileAction, Section};

impl<B: Backend> Ui<B> {
    pub(super) fn load_profiles(&self) {
        self.spawn_blocking(|| Msg::Profiles(ProfilesMsg::Loaded(profiles::list_profiles())));
    }

    /// The list and everything that follows the active profile.
    pub(super) fn reload_after_profile_change(&mut self) {
        self.load_profiles();
        self.load_active_profile();
        self.load_capture();
        self.load_core();
    }

    pub(super) fn profiles(&mut self, msg: ProfilesMsg) {
        let text = self.state.text();
        match msg {
            ProfilesMsg::Loaded(result) => {
                self.state.profiles = result.into();
                self.editor_follows_names();
            }
            ProfilesMsg::Apply(id) => {
                let active = self.state.active_profile.ready().and_then(Option::as_ref);
                if self.busy_with_profiles() || active.is_some_and(|profile| profile.id == id) {
                    return;
                }
                self.state.profile_action = Some((id.clone(), ProfileAction::Apply));
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    Msg::Profiles(ProfilesMsg::Applied(
                        profiles::set_active_profile(&runtime, id).await,
                    ))
                });
            }
            ProfilesMsg::Applied(result) => {
                self.state.profile_action = None;
                self.configuration_changed(
                    result.map(|report| report.application),
                    text.apply_failed(),
                );
                self.reload_after_profile_change();
            }
            ProfilesMsg::Rename(id, name) => {
                let name = name.trim().to_string();
                let current = self
                    .state
                    .profiles
                    .ready()
                    .and_then(|profiles| profiles.iter().find(|profile| profile.id == id))
                    .map(|profile| profile.name.clone());
                if name.is_empty()
                    || current.as_deref() == Some(name.as_str())
                    || self.state.profile_action.is_some()
                {
                    return;
                }
                self.state.profile_action = Some((id.clone(), ProfileAction::Rename));
                self.spawn_blocking(move || {
                    Msg::Profiles(ProfilesMsg::Renamed(profiles::rename_profile(id, name)))
                });
            }
            ProfilesMsg::Renamed(result) => {
                self.state.profile_action = None;
                if let Err(error) = result {
                    self.note(
                        Level::Error,
                        Source::Configuration,
                        text.rename_failed(),
                        Some(error),
                    );
                }
                self.load_profiles();
                self.load_active_profile();
            }
            ProfilesMsg::Reapply(id) => {
                if self.busy_with_profiles() {
                    return;
                }
                self.state.profile_action = Some((id.clone(), ProfileAction::Reapply));
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    Msg::Profiles(ProfilesMsg::Reapplied(
                        settings::reapply_profile(&runtime, id).await,
                    ))
                });
            }
            ProfilesMsg::Reapplied(result) => {
                self.state.profile_action = None;
                self.configuration_changed(result, text.reapply_failed());
                self.reload_after_profile_change();
            }
            ProfilesMsg::AskDelete(id) => self.state.confirm_delete = Some(id),
            ProfilesMsg::CancelDelete => {
                if self.state.profile_action.is_none() {
                    self.state.confirm_delete = None;
                }
            }
            ProfilesMsg::Delete { id, stop_if_active } => {
                if self.state.profile_action.is_some() {
                    return;
                }
                self.state.profile_action = Some((id.clone(), ProfileAction::Delete));
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    Msg::Profiles(ProfilesMsg::Deleted(
                        profiles::delete_profile(&runtime, id, stop_if_active).await,
                    ))
                });
            }
            ProfilesMsg::Deleted(result) => {
                self.state.profile_action = None;
                self.state.confirm_delete = None;
                if let Err(error) = result {
                    self.note(
                        Level::Error,
                        Source::Configuration,
                        text.delete_failed(),
                        Some(error),
                    );
                }
                self.reload_after_profile_change();
            }
            ProfilesMsg::OpenAdd => {
                if self.state.dialog.is_none() {
                    self.state.dialog = Some(Dialog::AddProfile(AddProfile::default()));
                }
            }
            ProfilesMsg::AddName(name) => {
                if let Some(Dialog::AddProfile(draft)) = &mut self.state.dialog {
                    draft.name = name;
                }
            }
            ProfilesMsg::AddUrl(url) => {
                if let Some(Dialog::AddProfile(draft)) = &mut self.state.dialog {
                    draft.url = url;
                }
            }
            ProfilesMsg::Download => {
                let Some(Dialog::AddProfile(draft)) = &mut self.state.dialog else {
                    return;
                };
                let url = draft.url.trim().to_string();
                if draft.pending || url.is_empty() {
                    return;
                }
                draft.pending = true;
                draft.error = None;
                let name = Some(draft.name.trim())
                    .filter(|name| !name.is_empty())
                    .map(String::from)
                    .or_else(|| name_from_url(&url))
                    .unwrap_or_else(|| text.default_profile_name().into());
                self.spawn(async move {
                    let result = profiles::import_remote_profile(name, url)
                        .await
                        .map_err(ImportFailure::Download);
                    Msg::Profiles(ProfilesMsg::Imported(result))
                });
            }
            ProfilesMsg::ChooseFile => {
                if matches!(&self.state.dialog, Some(Dialog::AddProfile(draft)) if !draft.pending) {
                    self.backend.choose_file(&FileRequest {
                        purpose: FilePurpose::ImportProfile,
                        extensions: vec!["yaml".into(), "yml".into(), "txt".into()],
                    });
                }
            }
            ProfilesMsg::FileChosen(path) => {
                let (Some(path), Some(Dialog::AddProfile(draft))) = (path, &mut self.state.dialog)
                else {
                    return;
                };
                if draft.pending {
                    return;
                }
                draft.pending = true;
                draft.error = None;
                let name = Some(draft.name.trim())
                    .filter(|name| !name.is_empty())
                    .map(String::from)
                    .or_else(|| file_stem(&path))
                    .unwrap_or_else(|| text.local_profile_name().into());
                self.spawn_blocking(move || {
                    let result = std::fs::read_to_string(&path)
                        .map_err(|error| {
                            ImportFailure::ReadFile(format!("{}: {error}", path.display()))
                        })
                        .and_then(|yaml| {
                            profiles::import_clash_profile(name, yaml)
                                .map_err(ImportFailure::Import)
                        });
                    Msg::Profiles(ProfilesMsg::Imported(result))
                });
            }
            ProfilesMsg::NewBlank => {
                let Some(Dialog::AddProfile(draft)) = &self.state.dialog else {
                    return;
                };
                if draft.pending {
                    return;
                }
                let name = Some(draft.name.trim())
                    .filter(|name| !name.is_empty())
                    .map(String::from)
                    .unwrap_or_else(|| text.new_profile_name().into());
                self.state.dialog = None;
                self.editor(EditorMsg::New { name });
            }
            ProfilesMsg::Imported(result) => {
                if let Some(Dialog::AddProfile(draft)) = &mut self.state.dialog {
                    draft.pending = false;
                }
                match result {
                    Ok(_) => {
                        self.state.dialog = None;
                        self.reload_after_profile_change();
                    }
                    Err(failure) => {
                        let (title, detail) = match failure {
                            ImportFailure::Download(error) => (text.download_failed(), error),
                            ImportFailure::ReadFile(error) => (text.file_read_failed(), error),
                            ImportFailure::Import(error) => (text.import_failed(), error),
                        };
                        // The open dialog says why where the user asked.
                        if let Some(Dialog::AddProfile(draft)) = &mut self.state.dialog {
                            draft.error = Some(text.message_line(title, &detail));
                        }
                        self.note(Level::Error, Source::Configuration, title, Some(detail));
                    }
                }
            }
        }
    }

    /// An operation on a profile or a profile configuration change runs.
    fn busy_with_profiles(&self) -> bool {
        self.state.profile_action.is_some() || self.state.transition_pending()
    }

    /// Reads the list again when the profiles page shows.
    pub(super) fn profiles_changed(&mut self) {
        if self.state.section == Section::Profiles {
            self.load_profiles();
        }
    }
}

fn file_stem(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(String::from)
}
