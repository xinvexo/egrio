//! The test control channel, only in builds with the `test-control` feature
//! and never in a release package: a Unix socket in the data directory,
//! owner-only, taking one command per line and answering `ok`, a result or
//! an error. GTK 4 offers no way to put synthesized input events in its
//! queue, so the commands act on the widgets the way a click or a key
//! reaches them: a button is clicked, a switch flipped, a drop-down's item
//! chosen. The app draws its own windows to PNG files, which needs no
//! screenshot permission from the compositor.
//!
//! Commands act on the place a user works in: an open dialog, else an open
//! popover, else the editor window while it is open, otherwise the main
//! window; `press` falls back to the main window.
//!
//! Commands: `show`, `quit`, `messages` (a click on the message capsule),
//! `navigate <section>`, `press <title>` (the first button with that text or
//! tooltip), `type <n> <text>` (at the end of the `n`th text field, an
//! in-place text taking it whole), `switch <n>`, `choose <n> <item>` and
//! `segment <n> <segment>` (the `n`th switch, drop-down or segmented control
//! of the page or dialog, in view order from 0), `key
//! escape|return|ctrl-s|ctrl-q|ctrl-w`
//! (what the key does where a user works; Return activates the focused
//! field, which presses its dialog's or popover's default button), `scroll
//! <n> <fraction>` (the `n`th scroll area with something to scroll, 0 at its
//! top and 1 at its end), `select-row <n> <row>` and `activate-row <n>
//! <row>` (the `n`th table's row, as a click or a double click does, or a
//! tile grid's tile, as a click does),
//! `drop-rows <from> <to>` (the movable table's row dropped before another,
//! as a drag does),
//! `answer-file <path>|none` (the answer to the file request),
//! `replace-text <text>` and `append-text <text>` (into the editor's text,
//! `\n` for a new line), `menu save|revert|close` (the editor's commands),
//! `close-main` (the main window's close button), `resize <width>
//! <height>`, `capture <path>` (the main window as a PNG), `snapshot <path>`
//! (where a user works, as a PNG), `tray` (the tray's menu), `tray-choose
//! <title>` and `dump [main]` (the widget tree, with each widget's text,
//! whether it is disabled, the default widget and the focused one).

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;

use adw::prelude::*;
use gtk::glib;

use egrio_ui::backend::{EditorAction, TrayAction, TrayView, UiEvent};
use egrio_ui::state::Section;

use super::cells::CellView;

thread_local! {
    /// The tray's menu as the backend last gave it.
    static TRAY: RefCell<Option<TrayView>> = const { RefCell::new(None) };
}

pub fn set_tray(view: &TrayView) {
    TRAY.with(|tray| *tray.borrow_mut() = Some(view.clone()));
}

pub fn start(directory: PathBuf) {
    let path = directory.join("test-control.sock");
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            log::warn!("test control is off: {error}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    log::info!("test control listens on {}", path.display());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut writer = match stream.try_clone() {
                Ok(writer) => writer,
                Err(_) => continue,
            };
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let answer = run(line.trim().to_string());
                let _ = writeln!(writer, "{answer}");
            }
        }
    });
}

/// Runs one command on the main thread and waits for its answer.
fn run(command: String) -> String {
    let (reply, answer) = mpsc::channel();
    super::on_main(move || {
        let _ = reply.send(execute(&command));
    });
    answer.recv().unwrap_or_else(|_| "error: no answer".into())
}

fn execute(command: &str) -> String {
    let (verb, argument) = command.split_once(' ').unwrap_or((command, ""));
    let result = match verb {
        "show" => posted(UiEvent::Tray(TrayAction::ShowMainWindow)),
        "quit" => posted(UiEvent::Tray(TrayAction::Quit)),
        "messages" => capsule().map(|capsule| capsule.emit_clicked()),
        "navigate" => match section(argument) {
            Some(section) => posted(UiEvent::Navigate(section)),
            None => Err(format!("unknown section {argument}")),
        },
        "press" => press(argument),
        "type" => type_text(argument),
        "switch" | "choose" | "segment" => control(verb, argument),
        "key" => key(argument),
        "scroll" => scroll(argument),
        "select-row" | "activate-row" => row(verb == "activate-row", argument),
        "drop-rows" => drop_rows(argument),
        "answer-file" => super::picker::test::answer(
            (argument != "none").then(|| PathBuf::from(argument)),
            super::post,
        ),
        "replace-text" | "append-text" => edit_text(verb == "append-text", argument),
        "menu" => match argument {
            "save" => posted(UiEvent::Editor(EditorAction::Save)),
            "revert" => posted(UiEvent::Editor(EditorAction::Revert)),
            "close" => posted(UiEvent::Editor(EditorAction::Close)),
            _ => Err("usage: menu save|revert|close".into()),
        },
        "close-main" => main_window().map(|window| window.close()),
        "resize" => resize(argument),
        "capture" => main_window().and_then(|window| write_png(window.upcast_ref(), argument)),
        "snapshot" => scope().and_then(|scope| write_png(&scope, argument)),
        "tray" => return tray_menu(),
        "tray-choose" => tray_choose(argument),
        "dump" => return dump(argument == "main"),
        _ => Err(format!("unknown command {verb}")),
    };
    match result {
        Ok(()) => "ok".into(),
        Err(error) => format!("error: {error}"),
    }
}

fn posted(event: UiEvent) -> Result<(), String> {
    super::post(event);
    Ok(())
}

fn section(name: &str) -> Option<Section> {
    Some(match name {
        "activity" => Section::Activity,
        "nodes" => Section::Nodes,
        "profiles" => Section::Profiles,
        "rules" => Section::Rules,
        "connections" => Section::Connections,
        "logs" => Section::Logs,
        "settings" => Section::Settings,
        _ => return None,
    })
}

fn toplevel(name: &str) -> Option<gtk::Window> {
    gtk::Window::list_toplevels()
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Window>().ok())
        .find(|window| window.widget_name() == name && window.is_visible())
}

fn main_window() -> Result<gtk::Window, String> {
    toplevel("egrio-main").ok_or_else(|| "no main window".into())
}

/// The message capsule in the main window's header bar.
fn capsule() -> Result<gtk::Button, String> {
    named(main_window()?.upcast_ref(), "egrio-capsule")
        .and_then(|widget| widget.downcast::<gtk::Button>().ok())
        .ok_or_else(|| "no message capsule".into())
}

/// Every mapped widget under `root` in view order, `root` first.
fn walk(root: &gtk::Widget, found: &mut Vec<gtk::Widget>) {
    if !root.is_mapped() {
        return;
    }
    found.push(root.clone());
    let mut child = root.first_child();
    while let Some(widget) = child {
        child = widget.next_sibling();
        walk(&widget, found);
    }
}

fn mapped(root: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut found = Vec::new();
    walk(root, &mut found);
    found
}

fn named(root: &gtk::Widget, name: &str) -> Option<gtk::Widget> {
    mapped(root)
        .into_iter()
        .find(|widget| widget.widget_name() == name)
}

/// The open popover a user works in: one of the interface's own, which a
/// menu button holds, not a drop-down's list.
fn open_popover(root: &gtk::Widget) -> Option<gtk::Widget> {
    let mut found = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(widget) = stack.pop() {
        if let Some(button) = widget.downcast_ref::<gtk::MenuButton>() {
            if let Some(popover) = button.popover().filter(|popover| popover.is_visible()) {
                found.push(popover.upcast());
            }
        }
        let mut child = widget.first_child();
        while let Some(next) = child {
            child = next.next_sibling();
            stack.push(next);
        }
    }
    found.into_iter().next()
}

/// Where a user works: an open dialog, else an open popover, else the
/// editor window, otherwise the main window's page and drawer.
fn scope() -> Result<gtk::Widget, String> {
    let main = toplevel("egrio-main");
    if let Some(main) = &main {
        let dialog = mapped(main.upcast_ref())
            .into_iter()
            .find(|widget| widget.is::<adw::Dialog>());
        if let Some(dialog) = dialog {
            return Ok(dialog);
        }
        if let Some(popover) = open_popover(main.upcast_ref()) {
            return Ok(popover);
        }
    }
    if let Some(editor) = toplevel("egrio-editor") {
        return Ok(editor.upcast());
    }
    main.map(|main| main.upcast())
        .ok_or_else(|| "no window".into())
}

/// Where a page's controls are: the scope, without the main window's header
/// bars.
fn controls_scope() -> Result<gtk::Widget, String> {
    let scope = scope()?;
    if scope.widget_name() == "egrio-main" {
        return named(&scope, "egrio-page").ok_or_else(|| "no page".into());
    }
    Ok(scope)
}

/// A button's texts: its labels and its tooltip.
fn texts(widget: &gtk::Widget) -> Vec<String> {
    let mut texts: Vec<String> = mapped(widget)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Label>().ok())
        .map(|label| label.text().to_string())
        .collect();
    if let Some(tooltip) = widget.tooltip_text() {
        texts.push(tooltip.to_string());
    }
    texts
}

fn find_button(root: &gtk::Widget, title: &str) -> Option<gtk::Button> {
    mapped(root)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
        .find(|button| texts(button.upcast_ref()).iter().any(|text| text == title))
}

/// Clicks the first button titled `title`, or with that tooltip, where a
/// user works, or in the main window.
fn press(title: &str) -> Result<(), String> {
    let found = scope()
        .ok()
        .and_then(|scope| find_button(&scope, title))
        .or_else(|| {
            main_window()
                .ok()
                .and_then(|main| find_button(main.upcast_ref(), title))
        });
    let button = found.ok_or_else(|| format!("no button {title}"))?;
    if !button.is_sensitive() {
        return Err(format!("{title} is disabled"));
    }
    button.emit_clicked();
    Ok(())
}

fn index_and_rest(argument: &str, usage: &str) -> Result<(usize, String), String> {
    let (index, rest) = argument.split_once(' ').unwrap_or((argument, ""));
    let index = index.parse().map_err(|_| usage.to_string())?;
    Ok((index, rest.to_string()))
}

/// Types `text` at the end of the `n`th editable text, as the keyboard
/// would; an in-place text takes it as its whole new text and commits it.
fn type_text(argument: &str) -> Result<(), String> {
    let (index, text) = index_and_rest(argument, "usage: type <n> <text>")?;
    let scope = scope()?;
    let fields: Vec<gtk::Widget> = mapped(&scope)
        .into_iter()
        .filter(|widget| {
            widget.is::<gtk::Entry>()
                || widget.is::<gtk::SearchEntry>()
                || widget.is::<gtk::EditableLabel>()
        })
        .collect();
    let field = fields
        .get(index)
        .ok_or_else(|| format!("no text field {index}"))?;
    if let Some(label) = field.downcast_ref::<gtk::EditableLabel>() {
        label.start_editing();
        label.set_text(&text);
        label.stop_editing(true);
        return Ok(());
    }
    let editable = field
        .dynamic_cast_ref::<gtk::Editable>()
        .ok_or("not editable")?;
    field.grab_focus();
    let mut position = editable.text().chars().count() as i32;
    editable.insert_text(&text, &mut position);
    editable.set_position(position);
    Ok(())
}

/// Uses the `n`th control of a kind on the page or in the dialog: `switch
/// <n>` flips a switch, `choose <n> <item>` picks a drop-down's item and
/// `segment <n> <segment>` a segmented control's segment.
fn control(verb: &str, argument: &str) -> Result<(), String> {
    let usage = "usage: switch <n> | choose <n> <item> | segment <n> <segment>";
    let (index, choice) = index_and_rest(argument, usage)?;
    let choice: Option<u32> = choice.parse().ok();
    let widgets = mapped(&controls_scope()?);
    match verb {
        "switch" => {
            let switch = widgets
                .into_iter()
                .filter_map(|widget| widget.downcast::<gtk::Switch>().ok())
                .nth(index)
                .ok_or_else(|| format!("no switch {index}"))?;
            switch.set_active(!switch.is_active());
        }
        "choose" => {
            let dropdown = widgets
                .into_iter()
                .filter_map(|widget| widget.downcast::<gtk::DropDown>().ok())
                .nth(index)
                .ok_or_else(|| format!("no drop-down {index}"))?;
            dropdown.set_selected(choice.ok_or("which item?")?);
        }
        _ => {
            let segmented = widgets
                .into_iter()
                .filter(|widget| {
                    widget.has_css_class("linked")
                        && widget
                            .first_child()
                            .is_some_and(|child| child.is::<gtk::ToggleButton>())
                })
                .nth(index)
                .ok_or_else(|| format!("no segmented control {index}"))?;
            let segment = choice.ok_or("which segment?")?;
            let mut child = segmented.first_child();
            for _ in 0..segment {
                child = child.and_then(|child| child.next_sibling());
            }
            let button = child
                .and_then(|child| child.downcast::<gtk::ToggleButton>().ok())
                .ok_or_else(|| format!("no segment {segment}"))?;
            button.set_active(true);
        }
    }
    Ok(())
}

/// What a key does where a user works: Esc closes the dialog, the popover
/// or the drawer, Return presses the dialog's default button, Ctrl+S saves
/// the editor's text.
fn key(name: &str) -> Result<(), String> {
    let scope = scope()?;
    match name {
        "escape" => {
            if let Some(dialog) = scope.downcast_ref::<adw::Dialog>() {
                dialog.close();
            } else if let Some(popover) = scope.downcast_ref::<gtk::Popover>() {
                popover.popdown();
            } else {
                let drawer = main_window()
                    .ok()
                    .and_then(|main| named(main.upcast_ref(), "egrio-drawer"));
                if drawer.is_some() {
                    super::post(UiEvent::CloseDrawer);
                }
            }
            Ok(())
        }
        "return" => {
            // In a field, Return activates it, and the field the default
            // button of its dialog or popover.
            let focus = scope
                .root()
                .and_then(|root| root.focus())
                .filter(|focus| focus.is_ancestor(&scope) && focus.is::<gtk::Text>());
            if let Some(field) = focus {
                // What GtkText's key binding for Return emits.
                field.emit_by_name::<()>("activate", &[]);
                return Ok(());
            }
            let button = if let Some(dialog) = scope.downcast_ref::<adw::Dialog>() {
                dialog.default_widget()
            } else if let Some(popover) = scope.downcast_ref::<gtk::Popover>() {
                popover.default_widget()
            } else {
                return Err("Return acts in a dialog or a popover".into());
            };
            button.ok_or("no default button")?.activate();
            Ok(())
        }
        "ctrl-s" => posted(UiEvent::Editor(EditorAction::Save)),
        // What the application's own shortcuts do.
        "ctrl-q" => posted(UiEvent::QuitRequested),
        "ctrl-w" => {
            scope
                .root()
                .and_then(|root| root.downcast::<gtk::Window>().ok())
                .ok_or("no window")?
                .close();
            Ok(())
        }
        _ => Err("usage: key escape|return|ctrl-s|ctrl-q|ctrl-w".into()),
    }
}

/// Scrolls the `n`th scroll area with something to scroll to `fraction` of
/// the way down: 0 is the top, 1 the end.
fn scroll(argument: &str) -> Result<(), String> {
    let usage = "usage: scroll <n> <fraction>";
    let (index, fraction) = index_and_rest(argument, usage)?;
    let fraction: f64 = fraction.parse().map_err(|_| usage.to_string())?;
    let scroll = mapped(&scope()?)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::ScrolledWindow>().ok())
        .filter(|scroll| {
            let adjustment = scroll.vadjustment();
            adjustment.upper() - adjustment.page_size() > 0.0
        })
        .nth(index)
        .ok_or_else(|| format!("no scroll area {index}"))?;
    let adjustment = scroll.vadjustment();
    let room = adjustment.upper() - adjustment.page_size();
    adjustment.set_value(adjustment.lower() + room * fraction.clamp(0.0, 1.0));
    Ok(())
}

/// The `n`th table, list or tile grid where a user works.
fn table(index: usize) -> Result<gtk::Widget, String> {
    mapped(&scope()?)
        .into_iter()
        .filter(|widget| {
            widget.is::<gtk::ColumnView>()
                || widget.is::<gtk::ListView>()
                || widget.is::<gtk::GridView>()
        })
        .nth(index)
        .ok_or_else(|| format!("no table {index}"))
}

/// Selects a table's row as a click does, or activates it as a double
/// click does.
fn row(activate: bool, argument: &str) -> Result<(), String> {
    let usage = "usage: select-row|activate-row <n> <row>";
    let (index, row) = index_and_rest(argument, usage)?;
    let row: u32 = row.parse().map_err(|_| usage.to_string())?;
    let view = table(index)?;
    if activate {
        view.emit_by_name::<()>("activate", &[&row]);
        return Ok(());
    }
    let model = view
        .property::<Option<gtk::SelectionModel>>("model")
        .ok_or("the table has no rows")?;
    model.select_item(row, true);
    Ok(())
}

/// Drops the `from`th row of the first table whose rows move before its
/// `to`th row, through the drop target the row at `to` has: GTK cannot put
/// a synthesized drag in its queue.
fn drop_rows(argument: &str) -> Result<(), String> {
    let usage = "usage: drop-rows <from> <to>";
    let (from, to) = argument.split_once(' ').ok_or(usage)?;
    let from: u32 = from.parse().map_err(|_| usage.to_string())?;
    let to: u32 = to.parse().map_err(|_| usage.to_string())?;
    let view = table(0)?;
    let model = view
        .property::<Option<gtk::SelectionModel>>("model")
        .ok_or("the table has no rows")?;
    let key = model
        .item(from)
        .and_then(|item| item.downcast::<glib::BoxedAnyObject>().ok())
        .map(|item| item.borrow::<String>().clone())
        .ok_or_else(|| format!("no row {from}"))?;
    let cell = mapped(&view)
        .into_iter()
        .filter_map(|widget| widget.downcast::<CellView>().ok())
        .find(|cell| cell.position() == Some(to))
        .ok_or_else(|| format!("row {to} is not on screen"))?;
    let target = cell
        .observe_controllers()
        .into_iter()
        .filter_map(Result::ok)
        .find_map(|controller| controller.downcast::<gtk::DropTarget>().ok())
        .ok_or("the row takes no drops")?;
    let dropped = target.emit_by_name::<bool>("drop", &[&key.to_value(), &0.0_f64, &0.0_f64]);
    if dropped {
        Ok(())
    } else {
        Err("the table refused the rows".into())
    }
}

/// Types `text` into the editor's document, in place of its text or at its
/// end.
fn edit_text(append: bool, text: &str) -> Result<(), String> {
    let view = mapped(&scope()?)
        .into_iter()
        .find_map(|widget| widget.downcast::<gtk::TextView>().ok())
        .ok_or("no text editor")?;
    let text = text.replace("\\n", "\n");
    let buffer = view.buffer();
    view.grab_focus();
    if append {
        let mut end = buffer.end_iter();
        buffer.insert(&mut end, &text);
    } else {
        buffer.set_text(&text);
    }
    Ok(())
}

/// Gives the main window `<width> <height>` as the size it opens at and
/// takes when not maximized.
fn resize(argument: &str) -> Result<(), String> {
    let usage = "usage: resize <width> <height>";
    let (width, height) = argument.split_once(' ').ok_or(usage)?;
    let width: i32 = width.parse().map_err(|_| usage.to_string())?;
    let height: i32 = height.parse().map_err(|_| usage.to_string())?;
    main_window()?.set_default_size(width, height);
    Ok(())
}

/// Draws `widget` as GTK draws it into the window and writes it as a PNG.
fn write_png(widget: &gtk::Widget, path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("which file?".into());
    }
    let (width, height) = (widget.width(), widget.height());
    if width <= 0 || height <= 0 {
        return Err("nothing is shown".into());
    }
    let paintable = gtk::WidgetPaintable::new(Some(widget));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, f64::from(width), f64::from(height));
    let node = snapshot.to_node().ok_or("nothing is drawn")?;
    let renderer = widget
        .native()
        .and_then(|native| native.renderer())
        .ok_or("no renderer")?;
    let bounds = gtk::graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
    renderer
        .render_texture(&node, Some(&bounds))
        .save_to_png(path)
        .map_err(|error| error.to_string())
}

/// The tray's menu, one item per line: a check, the title, a member's
/// latency in brackets and whether it is disabled; a submenu's items are
/// indented under it. The lines are joined with ` | ` into one answer.
fn tray_menu() -> String {
    TRAY.with(|tray| match tray.borrow().as_ref() {
        Some(view) => view.lines().join(" | "),
        None => "error: no tray".into(),
    })
}

/// Chooses the first enabled tray item titled `title`, as a click on it does.
fn tray_choose(title: &str) -> Result<(), String> {
    let action = TRAY
        .with(|tray| tray.borrow().as_ref().and_then(|view| view.choice(title)))
        .ok_or_else(|| format!("no enabled tray item {title}"))?;
    super::tray_event(action, None);
    Ok(())
}

/// The widget tree where a user works, or the main window's: one widget per
/// line, indented by depth, with its type, its name, its text and whether it
/// is disabled; the lines are joined with ` | `.
fn dump(main: bool) -> String {
    let root = if main {
        main_window().map(|window| window.upcast())
    } else {
        scope()
    };
    let root = match root {
        Ok(root) => root,
        Err(error) => return format!("error: {error}"),
    };
    let mut lines = Vec::new();
    describe(&root, 0, &mut lines);
    lines.join(" | ")
}

fn describe(widget: &gtk::Widget, depth: usize, lines: &mut Vec<String>) {
    if !widget.is_mapped() {
        return;
    }
    let mut line = format!("{}{}", "  ".repeat(depth), widget.type_().name());
    let name = widget.widget_name();
    if name.starts_with("egrio-") {
        line.push_str(&format!(" #{name}"));
    }
    if let Some(label) = widget.downcast_ref::<gtk::Label>() {
        line.push_str(&format!(" {:?}", label.text().as_str()));
    } else if let Some(editable) = widget.dynamic_cast_ref::<gtk::Editable>() {
        if !widget.is::<gtk::Text>() {
            line.push_str(&format!(" [{}]", editable.text()));
        }
    }
    if let Some(switch) = widget.downcast_ref::<gtk::Switch>() {
        line.push_str(if switch.is_active() { " on" } else { " off" });
    }
    if let Some(toggle) = widget.downcast_ref::<gtk::ToggleButton>() {
        if toggle.is_active() {
            line.push_str(" active");
        }
    }
    if let Some(tooltip) = widget.tooltip_text() {
        line.push_str(&format!(" (tooltip {:?})", tooltip.as_str()));
    }
    if !widget.is_sensitive() {
        line.push_str(" disabled");
    }
    // What Return presses, and what has the keyboard.
    if widget.has_default() {
        line.push_str(" default");
    }
    if widget.has_focus() {
        line.push_str(" focused");
    }
    lines.push(line);
    let mut child = widget.first_child();
    while let Some(next) = child {
        child = next.next_sibling();
        describe(&next, depth + 1, lines);
    }
}
