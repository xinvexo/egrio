//! The test control channel, only in builds with the `test-control` feature
//! and never in a release package: a named pipe named after the data
//! directory, open to the user who runs the app and to no one else, taking
//! one command per line and answering `ok`, a result or an error. A pipe has
//! no place in the file system, so its name is written to
//! `test-control.pipe` in that directory, where a harness that knows the
//! data directory finds it.
//!
//! WinUI offers no way to put synthesized input in its queue, so the
//! commands act on the controls the way a click or a key reaches them: a
//! button reports the press its click reports, a switch is flipped, a
//! drop-down's item chosen. They act on the surface a user works in: the
//! open dialog, else the editor window, otherwise the main window's page;
//! `press` reaches on to the page and its drawer. An open flyout's controls
//! belong to the page's surface, so they need no scope of their own, and
//! the indexes of a kind of control count them.
//!
//! The app draws its own windows with `RenderTargetBitmap`, which needs no
//! screenshot permission. That drawing is asynchronous: a screenshot answers
//! once the pixels have been written, and the UI thread stays free to draw
//! meanwhile. The pixels are encoded with the `png` crate this feature pulls
//! in, since no shipping path writes an image.
//!
//! Commands: `show`, `quit`, `messages` (a click on the message capsule),
//! `navigate <section>`, `press <title>` (the first enabled button with that
//! label, or with that tooltip where an icon names it), `type <n> <text>`
//! (at the end of the `n`th one-line field), `switch <n>`, `choose <n>
//! <item>` and `segment <n> <segment>` (the `n`th switch, drop-down or
//! segmented control, in view order from 0), `key escape|return|ctrl-s`
//! (what the key does where a user works), `scroll <n> <fraction>` (the
//! `n`th scroll area with something to scroll, 0 at its top and 1 at its
//! end), `select-row <n> <row>` and `activate-row <n> <row>` (the `n`th
//! table's row as a click and as a double click do, or a tile grid's tile as
//! a click does), `drop-rows <from> <to>` (the first table's row dropped
//! before another, as a drag does), `answer-file <path>|none` (the answer to
//! the file request, which a test-control build takes instead of opening the
//! picker), `replace-text <text>` and `append-text <text>` (into the
//! editor's document, `\n` for a new line), `menu save|revert|close` (the
//! editor's commands), `close-main` (the main window's close button),
//! `resize <width> <height>`, `capture <path>` (the main window as a PNG),
//! `snapshot <path>` (where a user works, as a PNG), `tray` (the tray's
//! menu), `tray-choose <title>` and `dump [main]` (the controls where a user
//! works, or the main window's, with what each shows and whether it is
//! disabled).

use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use windows_core::Interface;
use windows_future::{
    AsyncActionCompletedHandler, AsyncOperationCompletedHandler, AsyncStatus, IAsyncOperation,
};

use egrio_ui::backend::{EditorAction, Event, ToolbarAction, TrayAction, UiEvent};
use egrio_ui::node::ButtonKey;
use egrio_ui::reconcile::NodeId;
use egrio_ui::state::Section;

use super::bindings::{
    Button, ConnectNamedPipe, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    CreateNamedPipeW, CryptographicBuffer, DependencyObject, FrameworkElement, ISelector, IWindow2,
    LocalFree, RenderTargetBitmap, SizeInt32, TextBlock, UIElement, VisualTreeHelper,
    ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    SDDL_REVISION_1, SECURITY_ATTRIBUTES,
};
use super::widgets::{Control, Surface};
use super::WindowsBackend;

/// How long a command may take before the channel answers that it did not:
/// a screenshot draws the window and writes a file, the rest are immediate.
const ANSWER_BUDGET: Duration = Duration::from_secs(10);
/// Characters of a text a dump reads.
const TEXT_DUMPED: usize = 160;
/// Rows a dump reads, which stands for what a table shows: its own count
/// says how many it has.
const ROWS_DUMPED: usize = 20;
/// The pipe takes one command and answers one line, so a small buffer is
/// enough for both directions.
const PIPE_BUFFER: u32 = 64 * 1024;
/// Only the user who owns the pipe may open it: no one else has any access
/// ([SDDL](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format)).
const PIPE_SECURITY: windows_core::PCWSTR = windows_core::w!("D:P(A;;GA;;;OW)");

/// The pipe for `directory`: one app instance per data directory, so its
/// path names the pipe.
fn pipe_name(directory: &Path) -> String {
    // FNV-1a over the path, so the name is this directory's and stays the
    // same across restarts.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in directory.to_string_lossy().to_lowercase().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!(r"\\.\pipe\egrio-test-control-{hash:016x}")
}

pub fn start(directory: PathBuf) {
    let name = pipe_name(&directory);
    if let Err(error) = std::fs::write(directory.join("test-control.pipe"), &name) {
        log::warn!("test control is off: {error}");
        return;
    }
    log::info!("test control listens on {name}");
    std::thread::spawn(move || serve(&name));
}

/// Takes one client at a time: a harness sends its commands in order and
/// waits for each answer.
fn serve(name: &str) {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    loop {
        let pipe = match instance(&wide) {
            Ok(pipe) => pipe,
            Err(error) => {
                log::warn!("test control stopped: {error}");
                return;
            }
        };
        // SAFETY: a connected pipe instance this thread owns; the file
        // closes the handle when the client goes.
        let pipe = unsafe { std::fs::File::from_raw_handle(pipe) };
        let mut writer = match pipe.try_clone() {
            Ok(writer) => writer,
            Err(_) => continue,
        };
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            // One command, one line back: an answer carrying a line break
            // of its own (a document's text) escapes it.
            let answer = one_line(&ask(line.trim().to_string()));
            if writeln!(writer, "{answer}").is_err() {
                break;
            }
        }
    }
}

fn one_line(answer: &str) -> String {
    answer.replace('\r', "\\r").replace('\n', "\\n")
}

/// One pipe instance, waiting for a client to open it.
fn instance(name: &[u16]) -> Result<*mut core::ffi::c_void, String> {
    let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and a pointer that receives the
    // descriptor the call allocates.
    let described = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PIPE_SECURITY,
            SDDL_REVISION_1 as u32,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if !described.as_bool() {
        return Err(format!(
            "the pipe's security descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: false.into(),
    };
    // SAFETY: a NUL-terminated name and the attributes above, which outlive
    // the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            windows_core::PCWSTR(name.as_ptr()),
            PIPE_ACCESS_DUPLEX as u32,
            (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS) as u32,
            PIPE_UNLIMITED_INSTANCES as u32,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            &attributes,
        )
    };
    // SAFETY: the descriptor the conversion allocated above.
    unsafe { LocalFree(descriptor) };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(format!("the pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: a pipe instance this thread owns, waiting synchronously.
    let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
    if connected.as_bool()
        || std::io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED)
    {
        Ok(pipe)
    } else {
        Err(format!(
            "a client on the pipe: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// Runs one command on the UI thread and waits for its answer, which a
/// screenshot sends once it has drawn.
fn ask(command: String) -> String {
    let (reply, answer) = mpsc::channel();
    super::on_main(move || execute(&command, reply));
    answer
        .recv_timeout(ANSWER_BUDGET)
        .unwrap_or_else(|_| "error: no answer".into())
}

fn execute(command: &str, reply: mpsc::Sender<String>) {
    let (verb, argument) = command.split_once(' ').unwrap_or((command, ""));
    let answered = reply.clone();
    let result: Result<Option<String>, String> = match verb {
        "show" => posted(UiEvent::Tray(TrayAction::ShowMainWindow)),
        "quit" => posted(UiEvent::Tray(TrayAction::Quit)),
        "messages" => posted(UiEvent::Toolbar(ToolbarAction::Messages)),
        "navigate" => match section(argument) {
            Some(section) => posted(UiEvent::Navigate(section)),
            None => Err(format!("unknown section {argument}")),
        },
        "press" => press(argument).map(|()| None),
        "type" => type_text(argument).map(|()| None),
        "switch" | "choose" | "segment" => control(verb, argument).map(|()| None),
        "key" => key(argument).map(|()| None),
        "scroll" => scroll(argument).map(|()| None),
        "select-row" | "activate-row" => row(verb == "activate-row", argument).map(|()| None),
        "drop-rows" => drop_rows(argument).map(|()| None),
        "answer-file" => {
            super::picker::test::answer((argument != "none").then(|| PathBuf::from(argument)))
                .map(|()| None)
        }
        "replace-text" | "append-text" => edit_text(verb == "append-text", argument).map(|()| None),
        "menu" => match argument {
            "save" => posted(UiEvent::Editor(EditorAction::Save)),
            "revert" => posted(UiEvent::Editor(EditorAction::Revert)),
            "close" => posted(UiEvent::Editor(EditorAction::Close)),
            _ => Err("usage: menu save|revert|close".into()),
        },
        // As the user's close does: the window goes once the interface
        // hears of it, which also lets the interface forget it.
        "close-main" => posted(UiEvent::WindowClosed),
        "resize" => resize(argument).map(|()| None),
        "capture" => capture(argument, reply).map(|()| None),
        "snapshot" => snapshot(argument, reply).map(|()| None),
        "tray" => tray_menu().map(Some),
        "tray-choose" => tray_choose(argument).map(|()| None),
        "dump" => dump(argument == "main").map(Some),
        _ => Err(format!("unknown command {verb}")),
    };
    // A screenshot answers from its drawing, so it asks for no answer here.
    let answer = match result {
        Ok(Some(answer)) => answer,
        Ok(None) => "ok".into(),
        Err(error) => format!("error: {error}"),
    };
    if !matches!(verb, "capture" | "snapshot") || answer.starts_with("error") {
        let _ = answered.send(answer);
    }
}

fn posted(event: UiEvent) -> Result<Option<String>, String> {
    super::post(event);
    Ok(None)
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

/// Runs `work` with the interface's backend, which owns the windows WinUI
/// keeps no list of.
fn with_backend<R>(work: impl FnOnce(&WindowsBackend) -> R) -> Result<R, String> {
    super::UI.with(|ui| {
        let ui = ui
            .try_borrow()
            .map_err(|_| "the interface is busy".to_string())?;
        let ui = ui.as_ref().ok_or("the interface is not ready")?;
        Ok(work(ui.backend()))
    })
}

fn with_main<R>(
    work: impl FnOnce(&super::window::MainWindow) -> Result<R, String>,
) -> Result<R, String> {
    with_backend(|backend| match backend.window.as_ref() {
        Some(window) => work(window),
        None => Err("no main window".into()),
    })?
}

/// Runs `work` with the surface a user works in: the open dialog's, else
/// the editor window's, otherwise the main window's page.
fn with_scope<R>(work: impl FnOnce(&Surface) -> Result<R, String>) -> Result<R, String> {
    with_backend(|backend| {
        if let Some(dialog) = backend
            .window
            .as_ref()
            .and_then(|window| window.dialog.as_ref())
        {
            return work(&dialog.surface().borrow());
        }
        if let Some(editor) = backend.editor.as_ref() {
            return work(&editor.surface);
        }
        match backend.window.as_ref() {
            Some(window) => work(&window.content),
            None => Err("no window".into()),
        }
    })?
}

/// Asks each surface a press reaches, in order — where a user works, then
/// the main window's page and its drawer — until one answers.
fn in_reach<R>(ask: impl Fn(&Surface) -> Option<R>) -> Result<Option<R>, String> {
    with_backend(|backend| {
        if let Some(dialog) = backend
            .window
            .as_ref()
            .and_then(|window| window.dialog.as_ref())
        {
            if let Some(answer) = ask(&dialog.surface().borrow()) {
                return Some(answer);
            }
        }
        if let Some(editor) = backend.editor.as_ref() {
            if let Some(answer) = ask(&editor.surface) {
                return Some(answer);
            }
        }
        if let Some(window) = backend.window.as_ref() {
            if let Some(answer) = ask(&window.content) {
                return Some(answer);
            }
            if let Some(answer) = ask(&window.drawer) {
                return Some(answer);
            }
        }
        None
    })
}

/// Presses the first enabled button named `title`, as a click on it does.
/// A disabled button of that name is reported instead of pressed.
fn press(title: &str) -> Result<(), String> {
    enum Found {
        Enabled(NodeId),
        Disabled,
    }
    let found = in_reach(|surface| {
        surface
            .controls()
            .into_iter()
            .find_map(|(_, control)| match control {
                Control::Button { id, name, enabled } if name == Some(title) => Some(if enabled {
                    Found::Enabled(id)
                } else {
                    Found::Disabled
                }),
                Control::Composite { id, element }
                    if button_names(element).iter().any(|name| name == title) =>
                {
                    Some(Found::Enabled(id))
                }
                _ => None,
            })
    })?;
    match found {
        Some(Found::Enabled(id)) => {
            super::post(UiEvent::Node {
                id,
                event: Event::Press,
            });
            Ok(())
        }
        Some(Found::Disabled) => Err(format!("{title} is disabled")),
        None => Err(format!("no button {title}")),
    }
}

/// The labels of the buttons in `element`'s visual tree.
fn button_names(element: &FrameworkElement) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(element) = element.cast::<DependencyObject>() {
        collect_button_names(&element, &mut names);
    }
    names
}

fn collect_button_names(element: &DependencyObject, names: &mut Vec<String>) {
    if element.cast::<Button>().is_ok() {
        names.extend(texts(element));
        return;
    }
    for child in children(element) {
        collect_button_names(&child, names);
    }
}

/// The text every text block in `element`'s visual tree shows.
fn texts(element: &DependencyObject) -> Vec<String> {
    let mut found = Vec::new();
    if let Ok(label) = element.cast::<TextBlock>() {
        let text = label.Text().unwrap_or_default();
        let glyph = text
            .chars()
            .all(|char| ('\u{e000}'..='\u{f8ff}').contains(&char));
        if !text.is_empty() && !glyph {
            found.push(text);
        }
    }
    for child in children(element) {
        found.extend(texts(&child));
    }
    found
}

fn children(element: &DependencyObject) -> Vec<DependencyObject> {
    let count = VisualTreeHelper::GetChildrenCount(element).unwrap_or(0);
    (0..count)
        .filter_map(|index| VisualTreeHelper::GetChild(element, index).ok())
        .collect()
}

fn index_and_rest(argument: &str, usage: &str) -> Result<(usize, String), String> {
    let (index, rest) = argument.split_once(' ').unwrap_or((argument, ""));
    let index = index.parse().map_err(|_| usage.to_string())?;
    Ok((index, rest.to_string()))
}

fn win(error: windows_core::Error) -> String {
    error.message()
}

/// Types `text` at the end of the `n`th one-line field, as the keyboard
/// does; the editor's document takes `replace-text` and `append-text`.
fn type_text(argument: &str) -> Result<(), String> {
    let usage = "usage: type <n> <text>";
    let (index, text) = index_and_rest(argument, usage)?;
    if text.is_empty() {
        return Err(usage.into());
    }
    with_scope(|surface| {
        let field = surface
            .controls()
            .into_iter()
            .filter_map(|(_, control)| match control {
                Control::Text(field, false) => Some(field.clone()),
                _ => None,
            })
            .nth(index)
            .ok_or_else(|| format!("no text field {index}"))?;
        let current = field.Text().map_err(win)?;
        field.SetText(&format!("{current}{text}")).map_err(win)
    })
}

/// Uses the `n`th control of a kind where a user works: `switch <n>` flips a
/// switch, `choose <n> <item>` picks a drop-down's item and `segment <n>
/// <segment>` a segmented control's segment.
fn control(verb: &str, argument: &str) -> Result<(), String> {
    let usage = "usage: switch <n> | choose <n> <item> | segment <n> <segment>";
    let (index, choice) = index_and_rest(argument, usage)?;
    let choice: Option<usize> = choice.parse().ok();
    with_scope(|surface| {
        let controls = surface.controls();
        match verb {
            "switch" => {
                let (toggle, enabled) = controls
                    .into_iter()
                    .filter_map(|(_, control)| match control {
                        Control::Switch(toggle, props) => Some((toggle.clone(), props.enabled)),
                        _ => None,
                    })
                    .nth(index)
                    .ok_or_else(|| format!("no switch {index}"))?;
                if !enabled {
                    return Err(format!("switch {index} is disabled"));
                }
                let on = toggle.IsOn().map_err(win)?;
                toggle.SetIsOn(!on).map_err(win)
            }
            "choose" => {
                let (combo, options, enabled) = controls
                    .into_iter()
                    .filter_map(|(_, control)| match control {
                        Control::Select(combo, props) => {
                            Some((combo.clone(), props.options.len(), props.enabled))
                        }
                        _ => None,
                    })
                    .nth(index)
                    .ok_or_else(|| format!("no drop-down {index}"))?;
                if !enabled {
                    return Err(format!("drop-down {index} is disabled"));
                }
                let item = choice.ok_or("which item?")?;
                if item >= options {
                    return Err(format!("no item {item}"));
                }
                combo
                    .cast::<ISelector>()
                    .map_err(win)?
                    .SetSelectedIndex(item as i32)
                    .map_err(win)
            }
            _ => {
                let (bar, enabled) = controls
                    .into_iter()
                    .filter_map(|(_, control)| match control {
                        Control::Segmented(bar, props) => Some((bar.clone(), props.enabled)),
                        _ => None,
                    })
                    .nth(index)
                    .ok_or_else(|| format!("no segmented control {index}"))?;
                if !enabled {
                    return Err(format!("segmented control {index} is disabled"));
                }
                let segment = choice.ok_or("which segment?")?;
                let items = bar.Items().map_err(win)?;
                let item = items
                    .GetAt(segment as u32)
                    .map_err(|_| format!("no segment {segment}"))?;
                bar.SetSelectedItem(&item).map_err(win)
            }
        }
    })
}

/// What a key does where a user works: Esc presses the dialog's cancel
/// button or closes the drawer, Return the dialog's default button, Ctrl+S
/// saves the editor's document.
fn key(name: &str) -> Result<(), String> {
    let button = |key: ButtonKey| -> Result<(), String> {
        let id = with_backend(|backend| {
            backend
                .window
                .as_ref()
                .and_then(|window| window.dialog.as_ref())
                .and_then(|dialog| dialog.surface().borrow().button_with_key(key))
        })?;
        match id {
            Some(id) => {
                super::post(UiEvent::Node {
                    id,
                    event: Event::Press,
                });
                Ok(())
            }
            None => Err("no button takes that key".into()),
        }
    };
    match name {
        "escape" => {
            if button(ButtonKey::Escape).is_err() {
                super::post(UiEvent::CloseDrawer);
            }
            Ok(())
        }
        "return" => button(ButtonKey::Return),
        "ctrl-s" => {
            super::post(UiEvent::Editor(EditorAction::Save));
            Ok(())
        }
        _ => Err("usage: key escape|return|ctrl-s".into()),
    }
}

/// Scrolls the `n`th scroll area with something to scroll to `fraction` of
/// the way down: 0 is the top, 1 the end. WinUI moves the view on the next
/// layout pass, so a dump in the same batch still reads the old offset.
fn scroll(argument: &str) -> Result<(), String> {
    let usage = "usage: scroll <n> <fraction>";
    let (index, fraction) = index_and_rest(argument, usage)?;
    let fraction: f64 = fraction.parse().map_err(|_| usage.to_string())?;
    with_scope(|surface| {
        let scroll = surface
            .controls()
            .into_iter()
            .filter_map(|(_, control)| match control {
                Control::Scroll(scroll) => Some(scroll.clone()),
                _ => None,
            })
            .filter(|scroll| scroll.ScrollableHeight().unwrap_or(0.0) > 0.0)
            .nth(index)
            .ok_or_else(|| format!("no scroll area {index}"))?;
        let room = scroll.ScrollableHeight().map_err(win)?;
        scroll
            .ChangeViewWithOptionalAnimation(
                None,
                Some(room * fraction.clamp(0.0, 1.0)),
                None,
                true,
            )
            .map_err(win)
            .map(|_| ())
    })
}

/// Selects a table's row as a click does, activates it as a double click
/// does, or presses a tile grid's tile.
fn row(activate: bool, argument: &str) -> Result<(), String> {
    let usage = "usage: select-row|activate-row <n> <row>";
    let (index, row) = index_and_rest(argument, usage)?;
    let row: usize = row.parse().map_err(|_| usage.to_string())?;
    with_scope(|surface| {
        let mut tables = 0;
        for (_, control) in surface.controls() {
            match control {
                Control::Table(table) => {
                    if tables == index {
                        let key = table
                            .rows()
                            .get(row)
                            .cloned()
                            .ok_or_else(|| format!("no row {row}"))?;
                        if activate {
                            table.activate(key);
                            return Ok(());
                        }
                        return table.select(row).map_err(win);
                    }
                    tables += 1;
                }
                Control::Tiles(tiles) => {
                    if tables == index {
                        let key = tiles
                            .tiles()
                            .get(row)
                            .cloned()
                            .ok_or_else(|| format!("no tile {row}"))?;
                        tiles.press(key);
                        return Ok(());
                    }
                    tables += 1;
                }
                _ => {}
            }
        }
        Err(format!("no table {index}"))
    })
}

/// Drops the `from`th row of the first table before its `to`th row, as a
/// drag does: WinUI gives no way to put a synthesized drag in its queue.
fn drop_rows(argument: &str) -> Result<(), String> {
    let usage = "usage: drop-rows <from> <to>";
    let (from, to) = argument.split_once(' ').ok_or(usage)?;
    let from: usize = from.parse().map_err(|_| usage.to_string())?;
    let to: usize = to.parse().map_err(|_| usage.to_string())?;
    with_scope(|surface| {
        let table = surface
            .controls()
            .into_iter()
            .find_map(|(_, control)| match control {
                Control::Table(table) => Some(table),
                _ => None,
            })
            .ok_or("no table")?;
        let rows = table.rows();
        if to > rows.len() {
            return Err(format!("no row {to}"));
        }
        let key = rows
            .get(from)
            .cloned()
            .ok_or_else(|| format!("no row {from}"))?;
        table.moved(vec![key], to);
        Ok(())
    })
}

/// Writes `text` into the editor's document, in place of its text or at its
/// end.
fn edit_text(append: bool, text: &str) -> Result<(), String> {
    let text = text.replace("\\n", "\n");
    with_scope(|surface| {
        let field = surface
            .controls()
            .into_iter()
            .find_map(|(_, control)| match control {
                Control::Text(field, true) => Some(field.clone()),
                _ => None,
            })
            .ok_or("no text editor")?;
        let whole = if append {
            format!("{}{text}", field.Text().map_err(win)?)
        } else {
            text.clone()
        };
        field.SetText(&whole).map_err(win)
    })
}

/// Gives the main window `<width> <height>` as its size.
fn resize(argument: &str) -> Result<(), String> {
    let usage = "usage: resize <width> <height>";
    let (width, height) = argument.split_once(' ').ok_or(usage)?;
    let width: i32 = width.parse().map_err(|_| usage.to_string())?;
    let height: i32 = height.parse().map_err(|_| usage.to_string())?;
    with_main(|window| {
        window
            .window()
            .cast::<IWindow2>()
            .map_err(win)?
            .AppWindow()
            .map_err(win)?
            .Resize(SizeInt32 { width, height })
            .map_err(win)
    })
}

fn capture(path: &str, reply: mpsc::Sender<String>) -> Result<(), String> {
    let content = with_main(|window| {
        window
            .window()
            .Content()
            .map_err(|error| format!("the window's content: {}", win(error)))
    })?;
    write_png(&content, path, reply)
}

fn snapshot(path: &str, reply: mpsc::Sender<String>) -> Result<(), String> {
    let host = with_scope(|surface| surface.host().cast::<UIElement>().map_err(win))?;
    write_png(&host, path, reply)
}

thread_local! {
    /// The bitmap a screenshot is drawing into, which only the UI thread
    /// touches. The pixels come out of it after the drawing, so it has to
    /// outlive both steps: asked of a bitmap already released, they come
    /// back as nothing at all.
    static DRAWN: std::cell::RefCell<Option<RenderTargetBitmap>> =
        const { std::cell::RefCell::new(None) };
}

/// Draws `element` as WinUI draws it and writes it as a PNG. Both steps are
/// asynchronous and their completions may land on another thread, so each
/// comes back to the UI thread for the next; the answer goes out from the
/// last one.
fn write_png(element: &UIElement, path: &str, reply: mpsc::Sender<String>) -> Result<(), String> {
    if path.is_empty() {
        return Err("which file?".into());
    }
    if DRAWN.with(|drawn| drawn.borrow().is_some()) {
        return Err("a screenshot is already being drawn".into());
    }
    let bitmap =
        RenderTargetBitmap::new().map_err(|error| format!("the bitmap: {}", win(error)))?;
    let render = bitmap
        .RenderAsync(element)
        .map_err(|error| format!("the drawing: {}", win(error)))?;
    DRAWN.with(|drawn| *drawn.borrow_mut() = Some(bitmap));
    let path = PathBuf::from(path);
    render
        .SetCompleted(&AsyncActionCompletedHandler::new(move |_, status| {
            let drawn = status == AsyncStatus::Completed;
            let (path, reply) = (path.clone(), reply.clone());
            super::on_main(move || pixels(drawn, path, reply));
            Ok(())
        }))
        .map_err(|error| {
            DRAWN.with(|drawn| *drawn.borrow_mut() = None);
            format!("waiting for the drawing: {}", win(error))
        })
}

/// The window has been drawn: asks the bitmap for its pixels, which arrive
/// on whatever thread the buffer is ready on and are written there.
fn pixels(drawn: bool, path: PathBuf, reply: mpsc::Sender<String>) {
    let bitmap = DRAWN.with(|bitmap| bitmap.borrow().clone());
    let Some(bitmap) = bitmap else { return };
    if !drawn {
        fail(&reply, "error: the window did not draw".into());
        return;
    }
    let (width, height) = match (bitmap.PixelWidth(), bitmap.PixelHeight()) {
        (Ok(width), Ok(height)) if width > 0 && height > 0 => (width, height),
        _ => {
            fail(&reply, "error: nothing is shown".into());
            return;
        }
    };
    let operation = match bitmap.GetPixelsAsync() {
        Ok(operation) => operation,
        Err(error) => {
            fail(
                &reply,
                format!("error: asking for the pixels: {}", win(error)),
            );
            return;
        }
    };
    let failed = reply.clone();
    let taken = operation.SetCompleted(&AsyncOperationCompletedHandler::new(
        move |operation: windows_core::Ref<IAsyncOperation<super::bindings::IBuffer>>, status| {
            let answer = match (operation.ok(), status) {
                (Ok(operation), AsyncStatus::Completed) => operation
                    .GetResults()
                    .map_err(|error| format!("the pixels: {}", win(error)))
                    .and_then(|buffer| {
                        let mut bytes = windows_core::Array::new();
                        CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes)
                            .map_err(|error| format!("copying the pixels: {}", win(error)))?;
                        encode(&bytes, width, height, &path)
                    })
                    .map_or_else(|error| format!("error: {error}"), |()| "ok".into()),
                _ => "error: the window's pixels did not arrive".into(),
            };
            let _ = reply.send(answer);
            super::on_main(release);
            Ok(())
        },
    ));
    if let Err(error) = taken {
        fail(
            &failed,
            format!("error: waiting for the pixels: {}", win(error)),
        );
    }
}

/// Answers a screenshot that cannot go on, and lets its bitmap go.
fn fail(reply: &mpsc::Sender<String>, message: String) {
    let _ = reply.send(message);
    release();
}

/// Lets the bitmap go, on the UI thread that holds it.
fn release() {
    DRAWN.with(|drawn| *drawn.borrow_mut() = None);
}

/// Writes the window's pixels as a PNG: WinUI draws them premultiplied in
/// BGRA order, the file takes them as RGBA.
fn encode(bgra: &[u8], width: i32, height: i32, path: &Path) -> Result<(), String> {
    let (width, height) = (width as u32, height as u32);
    let expected = width as usize * height as usize * 4;
    if bgra.len() < expected {
        return Err("the window's pixels are short".into());
    }
    let mut rgba = Vec::with_capacity(expected);
    for pixel in bgra[..expected].chunks_exact(4) {
        rgba.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
    }
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut writer| writer.write_image_data(&rgba))
        .map_err(|error| error.to_string())
}

/// The tray's menu, one item per line: a check, the title, a member's
/// latency in brackets and whether it is disabled; a submenu's items are
/// indented under it. The lines are joined with ` | ` into one answer.
fn tray_menu() -> Result<String, String> {
    let (view, _) = super::tray::menu().ok_or("no tray")?;
    Ok(view.lines().join(" | "))
}

/// Chooses the first enabled tray item titled `title`, as a click on it does.
fn tray_choose(title: &str) -> Result<(), String> {
    let (view, post) = super::tray::menu().ok_or("no tray")?;
    let action = view
        .choice(title)
        .ok_or_else(|| format!("no enabled tray item {title}"))?;
    post(UiEvent::Tray(action));
    Ok(())
}

/// A document is as long as the user made it; a dump is a line, so it
/// takes the start of the text and says how much it left.
fn cut(text: &str) -> String {
    let mut shown: String = text.chars().take(TEXT_DUMPED).collect();
    let left = text.chars().count().saturating_sub(shown.chars().count());
    if left > 0 {
        shown.push_str(&format!("… and {left} more"));
    }
    shown
}

fn disabled(enabled: bool) -> &'static str {
    if enabled {
        ""
    } else {
        " disabled"
    }
}

/// The controls where a user works, or the main window's page: one per
/// line, indented by depth, with what it shows and its state; the lines are
/// joined with ` | `.
fn dump(main: bool) -> Result<String, String> {
    let describe = |surface: &Surface| -> Result<String, String> {
        let mut lines = Vec::new();
        for (depth, control) in surface.controls() {
            let indent = "  ".repeat(depth);
            let line = match control {
                Control::Button { name, enabled, .. } => {
                    format!("Button {:?}{}", name.unwrap_or_default(), disabled(enabled))
                }
                Control::Switch(toggle, props) => format!(
                    "Switch {}{}",
                    if toggle.IsOn().unwrap_or(false) {
                        "on"
                    } else {
                        "off"
                    },
                    disabled(props.enabled)
                ),
                Control::Select(combo, props) => format!(
                    "Select {:?} selected {:?}{}",
                    props.options,
                    combo
                        .cast::<ISelector>()
                        .and_then(|selector| selector.SelectedIndex())
                        .unwrap_or(-1),
                    disabled(props.enabled)
                ),
                Control::Segmented(_, props) => format!(
                    "Segmented {:?} selected {:?}{}",
                    props.options,
                    props.selected,
                    disabled(props.enabled)
                ),
                Control::Text(field, editor) => format!(
                    "{} [{}]",
                    if editor { "Editor" } else { "Field" },
                    cut(&field.Text().unwrap_or_default())
                ),
                Control::Scroll(scroll) => format!(
                    "Scroll {:.0} of {:.0}",
                    scroll.VerticalOffset().unwrap_or(0.0),
                    scroll.ScrollableHeight().unwrap_or(0.0)
                ),
                Control::Table(table) => {
                    let (shown, rows) = table.shown(ROWS_DUMPED);
                    let more = rows.saturating_sub(shown.len());
                    format!(
                        "Table {rows} rows {shown:?}{}",
                        if more > 0 {
                            format!(" and {more} more")
                        } else {
                            String::new()
                        }
                    )
                }
                Control::Tiles(tiles) => {
                    format!("Tiles {:?}", tiles.shown())
                }
                Control::Label(label) => {
                    format!("Text {:?}", label.Text().unwrap_or_default())
                }
                Control::Radio => "Radio".into(),
                Control::Named(kind, label) => {
                    format!("{kind} {:?}", label.Text().unwrap_or_default())
                }
                Control::Composite { element, .. } => {
                    let shown = element
                        .cast::<DependencyObject>()
                        .map(|element| texts(&element))
                        .unwrap_or_default();
                    format!("Composite {shown:?}")
                }
                Control::Other(kind) => kind.into(),
            };
            lines.push(format!("{indent}{line}"));
        }
        Ok(lines.join(" | "))
    };
    if main {
        with_main(|window| describe(&window.content))
    } else {
        with_scope(describe)
    }
}
