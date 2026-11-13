//! The profile editor window: a window of its own, one at a time, editing a
//! saved profile's YAML, or a new profile from the template until its first
//! save, as plain text. The text is checked with the YAML parser the
//! decoding uses as it changes: a text that does not parse cannot be saved,
//! and the status line under it names the first error's line and column and
//! shows the place on request.

use std::sync::Arc;

use egrio_desktop::profile_source::YamlProblem;

use crate::backend::{EditorCommand, EditorView};
use crate::msg::{EditorMsg, Msg};
use crate::node::{
    button, caption, column, placeholder, row, separator, spacer, spinner, symbol, text,
    text_editor, ButtonStyle, Icon, Node, TextStyle, Tone,
};
use crate::state::Remote;
use crate::text::Text;

/// The status line's height, whatever it shows, so the text above never moves.
const STATUS_HEIGHT: f64 = 30.0;

#[derive(Debug, Clone, PartialEq)]
pub struct Editor {
    /// Tells this editor's results from those of one closed before it.
    pub instance: u64,
    /// The saved profile it edits; `None` for a new one until its first save.
    pub profile: Option<String>,
    /// The profile's name, which titles the window and names a new profile.
    pub name: String,
    pub document: Remote<Document>,
    pub saving: bool,
    /// Why the last save failed, until the text changes or saves.
    pub save_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub draft: Arc<str>,
    /// The text as last read or saved; empty for a new profile.
    pub saved: Arc<str>,
    /// The revision of the saved source, which a save must still find;
    /// empty for a new profile.
    pub source_revision: String,
    /// Counts the draft's changes.
    pub revision: u64,
    /// The draft's first YAML error as of the revision `checked`.
    pub problem: Option<YamlProblem>,
    pub checked: u64,
    /// A check runs.
    pub checking: bool,
}

impl Document {
    pub fn new(draft: Arc<str>, saved: Arc<str>, source_revision: String) -> Self {
        Self {
            draft,
            saved,
            source_revision,
            revision: 1,
            problem: None,
            checked: 0,
            checking: false,
        }
    }

    pub fn edited(&self) -> bool {
        self.draft != self.saved
    }

    /// Takes the user's text as the draft.
    pub fn change(&mut self, draft: Arc<str>) {
        self.draft = draft;
        self.revision += 1;
    }
}

impl Editor {
    /// The editor of a saved profile, while its text is read.
    pub fn existing(instance: u64, id: String, name: String) -> Self {
        Self {
            instance,
            profile: Some(id),
            name,
            document: Remote::Loading,
            saving: false,
            save_error: None,
        }
    }

    /// A new profile from the template, written under `name` once saved.
    pub fn new_profile(instance: u64, name: String, text: Text) -> Self {
        Self {
            instance,
            profile: None,
            name,
            document: Remote::Ready(Document::new(
                template(text).into(),
                "".into(),
                String::new(),
            )),
            saving: false,
            save_error: None,
        }
    }

    /// The text changed, its last check found no error, and no save runs.
    pub fn can_save(&self) -> bool {
        match &self.document {
            Remote::Ready(document) => {
                !self.saving && document.edited() && document.problem.is_none()
            }
            _ => false,
        }
    }

    /// The text can go back to the saved one: a saved profile's changes.
    pub fn can_revert(&self) -> bool {
        self.profile.is_some()
            && !self.saving
            && self.document.ready().is_some_and(Document::edited)
    }
}

/// A new profile's text: a listener, one sample node, a group to choose it
/// and a rule sending everything through the group.
pub fn template(text: Text) -> String {
    let sample = text.sample_node_name();
    format!(
        "mixed-port: 7890
mode: rule
allow-lan: false

proxies:
  - name: {sample}
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: password

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - {sample}
      - DIRECT

rules:
  - MATCH,PROXY
"
    )
}

/// The index, in characters, of a place given as a line and a column in
/// characters, both counted from one; a place past the end is the end.
pub fn char_index(text: &str, line: usize, column: usize) -> usize {
    let mut index = 0;
    let mut chars = text.chars();
    let mut current = 1;
    while current < line {
        match chars.next() {
            Some(character) => {
                index += 1;
                if character == '\n' {
                    current += 1;
                }
            }
            None => return index,
        }
    }
    index
        + chars
            .take(column.saturating_sub(1))
            .take_while(|character| *character != '\n')
            .count()
}

/// The window's commands and its content: the text over the status line.
pub fn view(editor: &Editor, text: Text) -> (EditorView, Node) {
    let chrome = EditorView {
        title: editor.name.clone(),
        edited: editor.document.ready().is_some_and(Document::edited),
        revert: EditorCommand {
            label: text.revert().into(),
            enabled: editor.can_revert(),
        },
        save: EditorCommand {
            label: text.save().into(),
            enabled: editor.can_save(),
        },
    };
    let body = match &editor.document {
        Remote::Ready(document) => text_editor(document.draft.clone(), !editor.saving, |text| {
            Msg::Editor(EditorMsg::Changed(text))
        }),
        Remote::Loading => placeholder(text.loading(), None),
        Remote::Failed(error) => placeholder(text.editor_read_failed(), Some(error.clone())),
    }
    .grow();
    (
        chrome,
        column(0.0, vec![body, separator(), status(editor, text)]),
    )
}

/// What the text's state is: saving, why the save failed, its first error,
/// or that it parses.
fn status(editor: &Editor, text: Text) -> Node {
    let items = match &editor.document {
        Remote::Ready(_) if editor.saving => vec![spinner(), caption(text.saving())],
        Remote::Ready(_) if editor.save_error.is_some() => {
            let error = editor.save_error.clone().unwrap_or_default();
            vec![
                symbol(Icon::Warning, Tone::Danger),
                status_text(text.save_failed_detail(&error), Tone::Danger),
            ]
        }
        Remote::Ready(Document {
            problem: Some(problem),
            ..
        }) => {
            let mut items = vec![
                symbol(Icon::Warning, Tone::Danger),
                status_text(text.yaml_problem(problem), Tone::Danger),
                spacer(),
            ];
            if problem.location.is_some() {
                items.push(
                    button(text.show_problem(), ButtonStyle::Plain)
                        .on_press(Msg::Editor(EditorMsg::ShowProblem)),
                );
            }
            items
        }
        Remote::Ready(_) => vec![caption(text.no_yaml_problems())],
        Remote::Loading | Remote::Failed(_) => Vec::new(),
    };
    row(8.0, items)
        .padding(12.0, 0.0)
        .height(STATUS_HEIGHT)
        .key("status")
}

/// One line of the status; the whole of a line cut short is its tooltip.
fn status_text(value: String, tone: Tone) -> Node {
    text(value.clone(), TextStyle::Caption, tone).tooltip(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Lang;

    #[test]
    fn a_place_counts_characters_from_one() {
        let text = "a: 1\nb: [x\n名字: 值\n";
        assert_eq!(char_index(text, 1, 1), 0);
        assert_eq!(char_index(text, 2, 4), 8);
        assert_eq!(char_index(text, 3, 3), 13, "wide characters count once");
        assert_eq!(
            char_index(text, 2, 99),
            10,
            "a column past the line stops at its end"
        );
        assert_eq!(char_index(text, 9, 1), text.chars().count());
    }

    #[test]
    fn the_template_parses_and_a_new_profile_starts_unsaved() {
        let text = Text(Lang::En);
        assert_eq!(
            egrio_desktop::profile_source::yaml_problem(&template(text)),
            None
        );
        let editor = Editor::new_profile(1, "New".into(), text);
        assert!(editor.can_save(), "a new profile saves as it is");
        assert!(!editor.can_revert(), "it has nothing to go back to");
        let (chrome, _) = view(&editor, text);
        assert!(chrome.edited && chrome.save.enabled && !chrome.revert.enabled);
    }

    #[test]
    fn an_error_blocks_saving_and_names_its_place() {
        let text = Text(Lang::En);
        let mut editor = Editor::existing(1, "id".into(), "Profile".into());
        editor.document = Remote::Ready(Document::new(
            "mode: rule\n".into(),
            "mode: rule\n".into(),
            "r1".into(),
        ));
        assert!(!editor.can_save(), "nothing changed");
        let Remote::Ready(document) = &mut editor.document else {
            unreachable!()
        };
        document.change("mode: [rule\n".into());
        document.problem = egrio_desktop::profile_source::yaml_problem(&document.draft);
        document.checked = document.revision;
        assert!(!editor.can_save());
        assert!(editor.can_revert());
        let (_, content) = view(&editor, text);
        let status = content
            .children
            .last()
            .expect("the status line closes the window");
        assert!(
            status.children.iter().any(|child| matches!(
                &child.kind,
                crate::node::Kind::Button(button) if button.label.as_deref() == Some(text.show_problem())
            )),
            "the error's place is a press away"
        );
    }
}
