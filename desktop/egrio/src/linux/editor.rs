//! The editor window: a window of its own under a header bar whose title is
//! the profile's name, marked with `•` while the text has unsaved changes,
//! with Revert at its start and Save at its end; Ctrl+S saves. Closing asks
//! the interface (the close request is refused), which closes the window in
//! its render. Wayland leaves a new window's place to the compositor, so it
//! opens where GNOME puts it, at the size it had last.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use egrio_ui::backend::{EditorAction, EditorCommand, EditorView, UiEvent};
use egrio_ui::reconcile::Mounted;

use super::widgets::{Post, Surface};
use super::window_state::{self, WindowSize};

/// The window's first size, in logical pixels.
const DEFAULT_SIZE: (i32, i32) = (820, 640);

pub struct EditorWindow {
    window: adw::ApplicationWindow,
    title: adw::WindowTitle,
    revert: gtk::Button,
    save: gtk::Button,
    pub surface: Surface,
    /// Set while the interface closes the window, which then may close.
    closing: Rc<Cell<bool>>,
}

fn command_button(command: &EditorCommand, post: Post, action: EditorAction) -> gtk::Button {
    let button = gtk::Button::with_label(&command.label);
    button.set_sensitive(command.enabled);
    button.connect_clicked(move |_| post(UiEvent::Editor(action)));
    button
}

fn style_command(button: &gtk::Button, command: &EditorCommand) {
    button.set_label(&command.label);
    button.set_sensitive(command.enabled);
}

fn title(view: &EditorView) -> String {
    if view.edited {
        format!("• {}", view.title)
    } else {
        view.title.clone()
    }
}

fn remember_size(window: &adw::ApplicationWindow) {
    let (width, height) = window.default_size();
    window_state::save_editor(WindowSize {
        width,
        height,
        maximized: false,
    });
}

impl EditorWindow {
    pub fn open(app: &adw::Application, view: &EditorView, content: &Mounted, post: Post) -> Self {
        let window = adw::ApplicationWindow::new(app);
        window.set_widget_name("egrio-editor");
        window.set_title(Some(&title(view)));
        let size = window_state::editor().unwrap_or(WindowSize {
            width: DEFAULT_SIZE.0,
            height: DEFAULT_SIZE.1,
            maximized: false,
        });
        window.set_default_size(size.width, size.height);
        window.set_size_request(480, 320);

        let heading = adw::WindowTitle::new(&title(view), "");
        let header = adw::HeaderBar::new();
        header.set_title_widget(Some(&heading));
        let revert = command_button(&view.revert, post, EditorAction::Revert);
        let save = command_button(&view.save, post, EditorAction::Save);
        save.add_css_class("suggested-action");
        header.pack_start(&revert);
        header.pack_end(&save);

        let shortcuts = gtk::ShortcutController::new();
        shortcuts.set_scope(gtk::ShortcutScope::Managed);
        shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>s"),
            Some(gtk::CallbackAction::new(move |_, _| {
                post(UiEvent::Editor(EditorAction::Save));
                glib::Propagation::Stop
            })),
        ));
        window.add_controller(shortcuts);

        let host = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let mut surface = Surface::new(host.clone(), post);
        surface.set_root(content);
        let body = adw::ToolbarView::new();
        body.add_top_bar(&header);
        body.set_content(Some(&host));
        window.set_content(Some(&body));

        let closing = Rc::new(Cell::new(false));
        {
            let closing = closing.clone();
            window.connect_close_request(move |window| {
                if closing.get() {
                    remember_size(window);
                    return glib::Propagation::Proceed;
                }
                post(UiEvent::Editor(EditorAction::Close));
                glib::Propagation::Stop
            });
        }
        window.present();
        Self {
            window,
            title: heading,
            revert,
            save,
            surface,
            closing,
        }
    }

    pub fn update(&self, view: &EditorView) {
        let title = title(view);
        self.window.set_title(Some(&title));
        self.title.set_title(&title);
        style_command(&self.revert, &view.revert);
        style_command(&self.save, &view.save);
    }

    pub fn present(&self, token: Option<&str>) {
        if let Some(token) = token {
            self.window.set_startup_id(token);
        }
        self.window.present();
    }

    pub fn reveal(&self, index: usize) {
        if let Some(view) = self.surface.text_editor() {
            super::text_editor::reveal(&view, index);
        }
    }

    pub fn window(&self) -> &adw::ApplicationWindow {
        &self.window
    }

    /// Saves the window's size for the next editor, as closing it does.
    pub fn remember(&self) {
        remember_size(&self.window);
    }

    pub fn close(self) {
        self.closing.set(true);
        self.window.close();
    }
}
