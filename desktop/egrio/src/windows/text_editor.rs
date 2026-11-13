//! The editor window's document and text edited in place. The document is a
//! multi-line `TextBox` in a monospaced font that scrolls both ways; it
//! reports each edit and takes the interface's text only when that differs
//! from what it last reported, like a text field. Text edited in place is a
//! borderless `TextBox` that commits on Return or when it loses focus and
//! goes back to its text on Esc.

use std::cell::RefCell;
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result};

use egrio_ui::backend::Event;
use egrio_ui::node::{EditableText, TextEditor};

use super::bindings::{
    IControl, IUIElement, ScrollBarVisibility, ScrollViewer, TextBox, TextWrapping, VirtualKey,
};
use super::widgets::TextInput;
use super::xaml::{self, Element};

pub fn text_editor(
    props: &TextEditor,
    node_event: impl Fn(Event) + 'static,
) -> Result<(TextInput, Vec<EventRevoker>)> {
    let field = TextBox::new()?;
    field.fe().SetStyle(&xaml::style(
        "TextBox",
        Some("DefaultTextBoxStyle"),
        &[
            ("FontFamily", xaml::MONO_FONTS.into()),
            ("FontSize", "13".into()),
        ],
    )?)?;
    field.SetAcceptsReturn(true)?;
    field.SetTextWrapping(TextWrapping::NoWrap)?;
    field.SetIsSpellCheckEnabled(false)?;
    ScrollViewer::SetHorizontalScrollBarVisibility(&field, ScrollBarVisibility::Auto)?;
    ScrollViewer::SetVerticalScrollBarVisibility(&field, ScrollBarVisibility::Auto)?;
    let input = TextInput::new(field.clone(), &props.text, true);
    input.write_initial(&props.text)?;
    field.cast::<IControl>()?.SetIsEnabled(props.enabled)?;
    let changed = {
        let reported = input.reported();
        let quiet = input.quiet();
        let control = field.clone();
        field.TextChanged(move |_, _| {
            if quiet.get() {
                return;
            }
            if let Ok(text) = control.Text() {
                let text = unix_lines(&text);
                *reported.borrow_mut() = text.clone();
                node_event(Event::Changed(text));
            }
        })?
    };
    Ok((input, vec![changed]))
}

/// The text with `\n` line breaks: a `TextBox` keeps each as `\r`, which a
/// profile, the editor's line numbers and its unsaved check count as `\n`.
fn unix_lines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn style_text_editor(input: &TextInput, props: &TextEditor) -> Result<()> {
    input
        .field
        .cast::<IControl>()?
        .SetIsEnabled(props.enabled)?;
    // A document the interface put in is read from its start.
    if input.write(&props.text)? {
        input.field.Select(0, 0)?;
    }
    Ok(())
}

/// Selects the character at `index` (counted in characters) and brings it
/// into view.
pub fn reveal(field: &TextBox, index: usize) -> Result<()> {
    let text = field.Text()?;
    // TextBox counts UTF-16 units, with each line break as one.
    let start: usize = text
        .replace("\r\n", "\r")
        .chars()
        .take(index)
        .map(char::len_utf16)
        .sum();
    field
        .cast::<IUIElement>()?
        .Focus(super::bindings::FocusState::Programmatic)?;
    field.Select(start as i32, 1)
}

pub fn editable_text(
    props: &EditableText,
    node_event: impl Fn(Event) + Clone + 'static,
) -> Result<(TextBox, Vec<EventRevoker>)> {
    let field = TextBox::new()?;
    field.SetText(&props.text)?;
    // The text it shows when no edit is in progress: the interface's.
    let shown = Rc::new(RefCell::new(props.text.clone()));
    style_field(&field, props)?;
    // An edit ends on Return, Esc or leaving the field. A changed, nonblank
    // text is committed trimmed; the field shows the interface's text again
    // until the interface has the new one, as on macOS.
    let finish = {
        let shown = shown.clone();
        let control = field.clone();
        let node_event = node_event.clone();
        move |commit: bool| {
            let Ok(text) = control.Text() else { return };
            let edited = text.trim().to_string();
            let original = shown.borrow().clone();
            if text != original {
                let _ = control.SetText(&original);
            }
            if commit && !edited.is_empty() && edited != original {
                node_event(Event::Commit(edited));
            }
        }
    };
    let keys = {
        let control = field.clone();
        let finish = finish.clone();
        field.cast::<IUIElement>()?.KeyDown(move |_, args| {
            let Ok(args) = args.ok() else { return };
            let commit = match args.Key() {
                Ok(VirtualKey::Enter) => true,
                Ok(VirtualKey::Escape) => false,
                _ => return,
            };
            let _ = args.SetHandled(true);
            finish(commit);
            // The keyboard leaves the field, as it does when a disabled
            // control had it.
            if let Ok(control) = control.cast::<IControl>() {
                let _ = control.SetIsEnabled(false);
                let _ = control.SetIsEnabled(true);
            }
        })?
    };
    let left = field
        .cast::<IUIElement>()?
        .LostFocus(move |_, _| finish(true))?;
    EDITABLE.with(|editable| {
        editable
            .borrow_mut()
            .push((field.clone(), Rc::downgrade(&shown)))
    });
    Ok((field, vec![keys, left]))
}

/// The field's look: borderless text in the node's text style, editable
/// only while it is enabled and has somewhere to commit.
fn style_field(field: &TextBox, props: &EditableText) -> Result<()> {
    let mut setters = xaml::text_setters(props.style);
    setters.extend([
        ("BorderThickness", "0".to_string()),
        ("Background", "Transparent".to_string()),
        ("Padding", "4,2,4,2".to_string()),
    ]);
    field.fe().SetStyle(&xaml::style(
        "TextBox",
        Some("DefaultTextBoxStyle"),
        &setters,
    )?)?;
    field
        .cast::<IControl>()?
        .SetIsEnabled(props.enabled && props.on_commit.is_some())
}

thread_local! {
    /// Each in-place text's field and the text it shows, which an update
    /// replaces.
    static EDITABLE: RefCell<Vec<(TextBox, std::rc::Weak<RefCell<String>>)>> =
        const { RefCell::new(Vec::new()) };
}

pub fn style_editable(field: &TextBox, props: &EditableText) -> Result<()> {
    style_field(field, props)?;
    let shown = EDITABLE.with(|editable| {
        let mut editable = editable.borrow_mut();
        editable.retain(|(_, shown)| shown.strong_count() > 0);
        editable
            .iter()
            .find(|(candidate, _)| candidate == field)
            .and_then(|(_, shown)| shown.upgrade())
    });
    if let Some(shown) = shown {
        if *shown.borrow() != props.text {
            *shown.borrow_mut() = props.text.clone();
            field.SetText(&props.text)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::unix_lines;

    #[test]
    fn line_breaks_read_as_newlines() {
        assert_eq!(unix_lines("a\rb\r\nc\n"), "a\nb\nc\n");
    }
}
