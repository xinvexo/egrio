//! The editor window's document and text edited in place. The document is
//! a `GtkTextView` in a monospaced font that scrolls both ways; it reports
//! each edit and takes the interface's text only when that differs from
//! what it last reported, like a text field, so typing and an input
//! method's composition are never interrupted. Text edited in place is a
//! `GtkEditableLabel`, which starts editing on a click, commits on Return
//! or when it loses the focus and goes back to its text on Esc.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::prelude::*;

use egrio_ui::backend::Event;
use egrio_ui::node::{EditableText, TextEditor, Tone};

use super::style;
use super::widgets::quietly;

pub struct EditorParts {
    scroll: gtk::ScrolledWindow,
    view: gtk::TextView,
    /// The text the document last reported.
    reported: Rc<RefCell<String>>,
    quiet: Rc<Cell<bool>>,
}

impl EditorParts {
    pub fn new(props: &TextEditor, node_event: impl Fn(Event) + 'static) -> Self {
        let view = gtk::TextView::new();
        view.set_monospace(true);
        view.set_wrap_mode(gtk::WrapMode::None);
        view.set_left_margin(10);
        view.set_right_margin(10);
        view.set_top_margin(8);
        view.set_bottom_margin(8);
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        scroll.set_child(Some(&view));
        let parts = Self {
            scroll,
            view,
            reported: Rc::new(RefCell::new(props.text.to_string())),
            quiet: Rc::new(Cell::new(false)),
        };
        parts.replace_text(&props.text);
        parts.style(props);
        let buffer = parts.view.buffer();
        {
            let reported = parts.reported.clone();
            let quiet = parts.quiet.clone();
            buffer.connect_changed(move |buffer| {
                if quiet.get() {
                    return;
                }
                let text = buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string();
                *reported.borrow_mut() = text.clone();
                node_event(Event::Changed(text));
            });
        }
        parts
    }

    pub fn widget(&self) -> gtk::Widget {
        self.scroll.clone().upcast()
    }

    pub fn view(&self) -> gtk::TextView {
        self.view.clone()
    }

    pub fn update(&self, props: &TextEditor) {
        self.style(props);
        if *self.reported.borrow() != *props.text {
            *self.reported.borrow_mut() = props.text.to_string();
            self.replace_text(&props.text);
        }
    }

    fn style(&self, props: &TextEditor) {
        self.view.set_editable(props.enabled);
        self.view.set_cursor_visible(props.enabled);
    }

    /// Puts in text the interface chose, as one step undo does not go
    /// back through.
    fn replace_text(&self, text: &str) {
        let buffer = self.view.buffer();
        quietly(&self.quiet, || {
            buffer.begin_irreversible_action();
            buffer.set_text(text);
            buffer.end_irreversible_action();
            buffer.place_cursor(&buffer.start_iter());
        });
    }
}

/// Selects the character at `index`, counted in characters as GTK's text
/// buffer counts offsets, and brings it into view.
pub fn reveal(view: &gtk::TextView, index: usize) {
    let buffer = view.buffer();
    let start = buffer.iter_at_offset(i32::try_from(index).unwrap_or(i32::MAX));
    let mut end = start;
    end.forward_char();
    buffer.select_range(&start, &end);
    view.scroll_to_mark(&buffer.get_insert(), 0.2, false, 0.0, 0.5);
    view.grab_focus();
}

pub struct EditableParts {
    label: gtk::EditableLabel,
    /// The text it shows when no edit is in progress.
    shown: Rc<RefCell<String>>,
}

impl EditableParts {
    pub fn new(props: &EditableText, node_event: impl Fn(Event) + 'static) -> Self {
        let label = gtk::EditableLabel::new(&props.text);
        let shown = Rc::new(RefCell::new(props.text.clone()));
        {
            let shown = shown.clone();
            label.connect_editing_notify(move |label| {
                if label.is_editing() {
                    return;
                }
                let text = label.text().to_string();
                if text != *shown.borrow() {
                    node_event(Event::Commit(text));
                }
            });
        }
        let parts = Self { label, shown };
        parts.style(props);
        parts
    }

    pub fn widget(&self) -> gtk::Widget {
        self.label.clone().upcast()
    }

    pub fn update(&self, props: &EditableText) {
        *self.shown.borrow_mut() = props.text.clone();
        self.style(props);
        self.settle();
    }

    fn style(&self, props: &EditableText) {
        self.label.set_sensitive(props.enabled);
        style::set_text_style(&self.label, props.style, Tone::Default);
    }

    /// Shows the interface's text again when no edit is in progress: the
    /// interface may have refused the last one.
    pub fn settle(&self) {
        if !self.label.is_editing() && self.label.text() != *self.shown.borrow() {
            self.label.set_text(&self.shown.borrow());
        }
    }
}
