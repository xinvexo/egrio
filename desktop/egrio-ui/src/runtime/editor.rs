//! The editor window's reads, checks and saves. The YAML check runs off the
//! main thread, one at a time: edits made while it runs are checked once it
//! returns, so a burst of typing costs one check of its last text.

use std::sync::Arc;

use egrio_desktop::operations::profiles;
use egrio_desktop::profile_source::yaml_problem;
use egrio_desktop::profile_store::ProfileSourceDocument;

use super::Ui;
use crate::backend::Backend;
use crate::editor::{char_index, Document, Editor};
use crate::messages::{Level, Source};
use crate::msg::{EditorMsg, EditorSave, Msg};
use crate::state::Remote;

impl<B: Backend> Ui<B> {
    pub(super) fn editor(&mut self, msg: EditorMsg) {
        match msg {
            EditorMsg::Edit { id, name } => {
                if self.keep_open_editor(Some(&id)) {
                    return;
                }
                let instance = self.next_editor_instance();
                self.load_editor_source(instance, id.clone());
                // A profile being edited is not deleted from under its editor.
                if self.state.confirm_delete.as_deref() == Some(id.as_str()) {
                    self.state.confirm_delete = None;
                }
                self.show_editor(Editor::existing(instance, id, name));
            }
            EditorMsg::New { name } => {
                if self.keep_open_editor(None) {
                    return;
                }
                let instance = self.next_editor_instance();
                let text = self.state.text();
                self.show_editor(Editor::new_profile(instance, name, text));
                self.check_editor();
            }
            EditorMsg::Loaded { instance, result } => self.editor_loaded(instance, result),
            EditorMsg::Changed(draft) => {
                let Some(editor) = self.state.editor.as_mut() else {
                    return;
                };
                let Remote::Ready(document) = &mut editor.document else {
                    return;
                };
                document.change(draft.into());
                editor.save_error = None;
                self.check_editor();
            }
            EditorMsg::Checked {
                instance,
                revision,
                problem,
            } => {
                if let Some(Remote::Ready(document)) = self
                    .state
                    .editor
                    .as_mut()
                    .filter(|editor| editor.instance == instance)
                    .map(|editor| &mut editor.document)
                {
                    document.checking = false;
                    if revision > document.checked {
                        document.checked = revision;
                        document.problem = problem;
                    }
                }
                self.check_editor();
            }
            EditorMsg::Save => self.save_editor(),
            EditorMsg::Saved {
                instance,
                yaml,
                result,
            } => self.editor_saved(instance, yaml, result),
            EditorMsg::Revert => {
                let Some(editor) = self.state.editor.as_mut() else {
                    return;
                };
                if !editor.can_revert() {
                    return;
                }
                editor.save_error = None;
                if let Remote::Ready(document) = &mut editor.document {
                    let saved = document.saved.clone();
                    document.change(saved);
                }
                self.check_editor();
            }
            EditorMsg::ShowProblem => {
                let Some(Remote::Ready(document)) =
                    self.state.editor.as_ref().map(|editor| &editor.document)
                else {
                    return;
                };
                if let Some(at) = document
                    .problem
                    .as_ref()
                    .and_then(|problem| problem.location)
                {
                    let index = char_index(&document.draft, at.line, at.column);
                    self.backend.reveal_in_editor(index);
                }
            }
            // Unsaved changes go with the window.
            EditorMsg::Close => self.state.editor = None,
        }
    }

    /// One editor at a time: an open one that already edits `profile`, or
    /// whose text has changes or is saving, stays as it is and comes to the
    /// front; otherwise it gives way to the one asked for.
    fn keep_open_editor(&mut self, profile: Option<&str>) -> bool {
        let Some(editor) = self.state.editor.as_ref() else {
            return false;
        };
        let same = profile.is_some() && editor.profile.as_deref() == profile;
        let unsaved = editor.saving || editor.document.ready().is_some_and(Document::edited);
        if same || unsaved {
            self.backend.bring_editor_to_front();
        }
        same || unsaved
    }

    /// Shows `editor`, in the open editor window when there is one.
    fn show_editor(&mut self, editor: Editor) {
        if self.state.editor.replace(editor).is_some() {
            self.backend.bring_editor_to_front();
        }
    }

    /// The edited profile was renamed: the window takes its new name.
    pub(super) fn editor_follows_names(&mut self) {
        let (Some(editor), Remote::Ready(profiles)) =
            (self.state.editor.as_mut(), &self.state.profiles)
        else {
            return;
        };
        if let Some(profile) = profiles
            .iter()
            .find(|profile| Some(profile.id.as_str()) == editor.profile.as_deref())
        {
            if profile.name != editor.name {
                editor.name = profile.name.clone();
            }
        }
    }

    fn next_editor_instance(&mut self) -> u64 {
        self.editor_instances += 1;
        self.editor_instances
    }

    fn load_editor_source(&self, instance: u64, id: String) {
        self.spawn_blocking(move || {
            Msg::Editor(EditorMsg::Loaded {
                instance,
                result: profiles::profile_source(id),
            })
        });
    }

    fn editor_loaded(&mut self, instance: u64, result: Result<ProfileSourceDocument, String>) {
        let Some(editor) = self
            .state
            .editor
            .as_mut()
            .filter(|editor| editor.instance == instance)
        else {
            return;
        };
        let source = match result {
            Ok(source) if editor.profile.as_deref() == Some(source.profile_id.as_str()) => source,
            Ok(_) => return,
            Err(error) => {
                if matches!(editor.document, Remote::Loading) {
                    editor.document = Remote::Failed(error);
                }
                return;
            }
        };
        let yaml: Arc<str> = source.yaml.into();
        match &mut editor.document {
            // A file that changed under the user's changes stays theirs; the
            // save then finds that the file moved on.
            Remote::Ready(document) if editor.saving || document.edited() => return,
            Remote::Ready(document) => {
                document.saved = yaml.clone();
                document.source_revision = source.source_revision;
                if document.draft != yaml {
                    document.change(yaml);
                }
            }
            Remote::Loading | Remote::Failed(_) => {
                editor.document =
                    Remote::Ready(Document::new(yaml.clone(), yaml, source.source_revision));
            }
        }
        self.check_editor();
    }

    /// Checks the draft unless a check runs or the last one is of this draft.
    fn check_editor(&mut self) {
        let Some(editor) = self.state.editor.as_mut() else {
            return;
        };
        let instance = editor.instance;
        let Remote::Ready(document) = &mut editor.document else {
            return;
        };
        if document.checking || document.checked == document.revision {
            return;
        }
        document.checking = true;
        let (draft, revision) = (document.draft.clone(), document.revision);
        self.spawn_blocking(move || {
            Msg::Editor(EditorMsg::Checked {
                instance,
                revision,
                problem: yaml_problem(&draft),
            })
        });
    }

    fn save_editor(&mut self) {
        let Some(editor) = self.state.editor.as_mut() else {
            return;
        };
        if !editor.can_save() {
            return;
        }
        let instance = editor.instance;
        let Remote::Ready(document) = &mut editor.document else {
            return;
        };
        // No save goes out with a YAML error: a check behind the draft runs now.
        if document.checked != document.revision {
            document.problem = yaml_problem(&document.draft);
            document.checked = document.revision;
            if document.problem.is_some() {
                return;
            }
        }
        let yaml = document.draft.clone();
        let source_revision = document.source_revision.clone();
        editor.saving = true;
        editor.save_error = None;
        match editor.profile.clone() {
            Some(id) => {
                let runtime = self.desktop.runtime.clone();
                self.spawn(async move {
                    let result = profiles::save_profile_source(
                        &runtime,
                        id,
                        yaml.to_string(),
                        source_revision,
                    )
                    .await
                    .map(|report| EditorSave {
                        profile: report.profile,
                        application: Some(report.application),
                    });
                    Msg::Editor(EditorMsg::Saved {
                        instance,
                        yaml,
                        result,
                    })
                });
            }
            None => {
                let name = editor.name.clone();
                self.spawn_blocking(move || {
                    let result = profiles::create_profile(name, yaml.to_string()).map(|profile| {
                        EditorSave {
                            profile,
                            application: None,
                        }
                    });
                    Msg::Editor(EditorMsg::Saved {
                        instance,
                        yaml,
                        result,
                    })
                });
            }
        }
    }

    fn editor_saved(&mut self, instance: u64, yaml: Arc<str>, result: Result<EditorSave, String>) {
        let text = self.state.text();
        let editor = self
            .state
            .editor
            .as_mut()
            .filter(|editor| editor.instance == instance);
        match result {
            Ok(saved) => {
                if let Some(editor) = editor {
                    editor.saving = false;
                    editor.profile = Some(saved.profile.id.clone());
                    editor.name = saved.profile.name.clone();
                    if let Remote::Ready(document) = &mut editor.document {
                        document.saved = yaml;
                        document.source_revision = saved.profile.source_revision.clone();
                    }
                }
                if let Some(application) = saved.application {
                    self.configuration_changed(Ok(application), text.profile_save_failed());
                }
                self.reload_after_profile_change();
            }
            Err(error) => {
                if let Some(editor) = editor {
                    editor.saving = false;
                    editor.save_error = Some(error.clone());
                }
                self.note(
                    Level::Error,
                    Source::Configuration,
                    text.profile_save_failed(),
                    Some(error),
                );
            }
        }
    }

    /// The profiles changed: an editor without changes reads its file again,
    /// so it shows what another writer left there.
    pub(super) fn editor_profiles_changed(&self) {
        let Some(editor) = self.state.editor.as_ref() else {
            return;
        };
        let Some(id) = editor.profile.clone() else {
            return;
        };
        let edited = editor.document.ready().is_some_and(Document::edited);
        if !editor.saving && !edited {
            self.load_editor_source(editor.instance, id);
        }
    }
}
