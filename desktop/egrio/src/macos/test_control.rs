//! The test control channel, only in builds with the `test-control` feature
//! and never in a release package: a Unix socket in the data directory,
//! owner-only, taking one command per line and answering `ok` or an error.
//! System tests drive the app through it the way a user would, and the app
//! renders its own window to a PNG, which needs no screen-recording
//! permission. Commands act on the window a user works in: an open
//! popover, the editor window while it is open, otherwise the main window.
//!
//! Commands: `show`, `navigate <section>`, `messages` (the toolbar's message
//! button), `press <title>` (the first button with that title in the window a
//! user works in, else in the main window or its dialog), `type <n> <text>` (into the `n`th editable text
//! field), `answer-file <path>` (the answer to the open panel, or to the last one), `scroll <n>
//! <fraction>` (the `n`th scroll view with something to scroll, 0 at its
//! top and 1 at its end), `snapshot-dialog
//! <path>`, `switch <n>`, `choose <n> <item>` and `segment <n> <segment>`
//! (the `n`th switch, pop-up or segmented control in view order), `key
//! escape|return|cmd-s|cmd-q|up|down|left|right` (a key press), `click <x> <y>` and
//! `double-click <x> <y>` (in points from the window's top left),
//! `drop-rows <from> <to>` (a table's dragged row dropped before another),
//! `tray` (the run loop's mode, then the tray's menu), `tray-choose <title>`
//! (a tray item chosen),
//! `tray-open` and `tray-close` (the tray's menu opened or closed), `replace-text <text>` and
//! `append-text <text>` (into the window's text editor, `\n` for a new
//! line), `menu save|revert|close` (a menu item's action through the
//! responder chain), `close-main` (the main window's close button), `compose <text>`
//! (marked text, as an input method composes it), `marked` (whether the
//! text being typed still composes, and where its selection is), `resize <width> <height>` (the window's content
//! size), `snapshot <path>` and `capture <path>` (the window as a PNG;
//! `capture help <path>` the hover help that shows and `capture tray <path>`
//! the tray's group submenu that shows, or the first group's rows without
//! opening it),
//! `snapshot-class <class> <path>` (the first view of that class), `dump
//! [main]` (the window's view tree, or the main window's, with what each
//! button and text field shows and which controls are disabled) and `quit`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;

use dispatch2::DispatchQueue;
use objc2::runtime::NSObjectProtocol;
use objc2::{AnyThread, ClassType, MainThreadMarker};
use objc2_app_kit::{
    NSApplication, NSBitmapImageFileType, NSEvent, NSEventModifierFlags, NSEventType,
};
use objc2_foundation::{NSDictionary, NSPoint, NSString};

use egrio_ui::backend::{ToolbarAction, TrayAction, UiEvent};
use egrio_ui::state::Section;

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
    DispatchQueue::main().exec_async(move || {
        let _ = reply.send(execute(&command));
    });
    answer.recv().unwrap_or_else(|_| "error: no answer".into())
}

fn execute(command: &str) -> String {
    let (verb, argument) = command.split_once(' ').unwrap_or((command, ""));
    let event = match verb {
        "show" => UiEvent::Tray(TrayAction::ShowMainWindow),
        "quit" => UiEvent::Tray(TrayAction::Quit),
        "messages" => UiEvent::Toolbar(ToolbarAction::Messages),
        "navigate" => match section(argument) {
            Some(section) => UiEvent::Navigate(section),
            None => return format!("error: unknown section {argument}"),
        },
        "snapshot" => {
            return snapshot(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "dump" => return dump(argument == "main"),
        "key" => {
            return key(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "replace-text" | "append-text" => {
            return edit_text(verb == "append-text", argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "compose" => {
            return compose(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "marked" => return marked().unwrap_or_else(|error| format!("error: {error}")),
        "close-main" => {
            return close_main()
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "menu" => {
            return menu(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "click" => {
            return click(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "resize" => {
            return resize(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "type" => {
            return type_text(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "answer-file" => {
            return answer_file(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "capture" => {
            return capture(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "snapshot-dialog" => {
            return snapshot_dialog(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "tray" => return tray_menu(),
        "tray-choose" => {
            return tray_choose(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "tray-open" | "tray-close" => {
            return tray_track(verb == "tray-open")
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "double-click" => {
            return double_click(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "drop-rows" => {
            return drop_rows(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "scroll" => {
            return scroll(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "switch" | "choose" | "segment" => {
            return control(verb, argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "press" => {
            return press(argument)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"))
        }
        "snapshot-class" => {
            let (class, path) = argument.split_once(' ').unwrap_or((argument, ""));
            return snapshot_class(class, path)
                .map(|()| "ok".into())
                .unwrap_or_else(|error| format!("error: {error}"));
        }
        _ => return format!("error: unknown command {verb}"),
    };
    super::post(event);
    "ok".into()
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

/// Gives the main window's content `<width> <height>` points, as dragging its
/// edge would, within its minimum size.
fn resize(argument: &str) -> Result<(), String> {
    let (width, height) = argument
        .split_once(' ')
        .and_then(|(width, height)| Some((width.parse::<f64>().ok()?, height.parse::<f64>().ok()?)))
        .ok_or("usage: resize <width> <height>")?;
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    window.setContentSize(objc2_foundation::NSSize::new(width, height));
    Ok(())
}

/// Uses the `n`th control of a kind in the window a user types into (an
/// open dialog, else the front window), counted in view order from 0: `switch <n>` flips a switch, `choose <n> <item>` picks a
/// pop-up's item, `segment <n> <segment>` picks a segmented control's
/// segment. Each sends its action as a click does.
fn control(verb: &str, argument: &str) -> Result<(), String> {
    let mut words = argument
        .split_whitespace()
        .map(|word| word.parse::<usize>());
    let index = words
        .next()
        .and_then(Result::ok)
        .ok_or("usage: switch <n> | choose <n> <item> | segment <n> <segment>")?;
    let choice = words.next().and_then(Result::ok);
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = key_window(mtm)?;
    let frame = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    let class = match verb {
        "switch" => objc2_app_kit::NSSwitch::class(),
        "choose" => objc2_app_kit::NSPopUpButton::class(),
        _ => objc2_app_kit::NSSegmentedControl::class(),
    };
    let mut found = Vec::new();
    collect(&frame, class, &mut found);
    let view = found
        .get(index)
        .ok_or_else(|| format!("no {verb} control {index}"))?;
    if let Some(switch) = view.downcast_ref::<objc2_app_kit::NSSwitch>() {
        unsafe { switch.performClick(None) };
    } else if let Some(popup) = view.downcast_ref::<objc2_app_kit::NSPopUpButton>() {
        popup.selectItemAtIndex(choice.ok_or("which item?")? as isize);
        send_action(popup);
    } else if let Some(segmented) = view.downcast_ref::<objc2_app_kit::NSSegmentedControl>() {
        segmented.setSelectedSegment(choice.ok_or("which segment?")? as isize);
        send_action(segmented);
    }
    Ok(())
}

/// Scrolls the `n`th scroll view in view order that has something to
/// scroll, to `fraction` of the way down: 0 is the top, 1 the end.
fn scroll(argument: &str) -> Result<(), String> {
    let usage = "usage: scroll <n> <fraction>";
    let (index, fraction) = argument.split_once(' ').ok_or(usage)?;
    let index: usize = index.parse().map_err(|_| usage)?;
    let fraction: f64 = fraction.parse().map_err(|_| usage)?;
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    let frame = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    let mut found = Vec::new();
    collect(&frame, objc2_app_kit::NSScrollView::class(), &mut found);
    let scrolls: Vec<_> = found
        .iter()
        .filter_map(|view| view.downcast_ref::<objc2_app_kit::NSScrollView>())
        .filter_map(|scroll| {
            let document = scroll.documentView()?;
            let room = document.frame().size.height - scroll.contentView().bounds().size.height;
            (room > 0.0).then_some((scroll, room, document.isFlipped()))
        })
        .collect();
    let (scroll, room, flipped) = scrolls
        .get(index)
        .ok_or_else(|| format!("no scrollable view {index}"))?;
    let down = room * fraction.clamp(0.0, 1.0);
    let clip = scroll.contentView();
    clip.scrollToPoint(objc2_foundation::NSPoint::new(
        0.0,
        if *flipped { down } else { room - down },
    ));
    scroll.reflectScrolledClipView(&clip);
    Ok(())
}

fn send_action(control: &objc2_app_kit::NSControl) {
    if let Some(action) = control.action() {
        unsafe { control.sendAction_to(Some(action), control.target().as_deref()) };
    }
}

fn collect(
    view: &objc2_app_kit::NSView,
    class: &objc2::runtime::AnyClass,
    found: &mut Vec<objc2::rc::Retained<objc2_app_kit::NSView>>,
) {
    if view.isKindOfClass(class) {
        found.push(objc2::Message::retain(view));
    }
    for child in view.subviews().iter() {
        collect(&child, class, found);
    }
}

/// The window a user works in: the editor window while it is open,
/// otherwise the main window.
fn front_window(mtm: MainThreadMarker) -> Option<objc2::rc::Retained<objc2_app_kit::NSWindow>> {
    use objc2_app_kit::NSUserInterfaceItemIdentification;
    let windows = NSApplication::sharedApplication(mtm).windows();
    // An open popover takes the keyboard and the pointer while it shows.
    let popover = windows.iter().find(|window| {
        window.isVisible()
            && window
                .contentView()
                .is_some_and(|content| holds(&content, super::popover::IDENTIFIER))
    });
    if popover.is_some() {
        return popover;
    }
    let editor = windows.iter().find(|window| {
        window.isVisible()
            && window
                .identifier()
                .is_some_and(|identifier| identifier.to_string() == super::editor::IDENTIFIER)
    });
    editor.or_else(|| {
        windows
            .iter()
            .find(|window| window.isVisible() && window.contentViewController().is_some())
    })
}

/// Whether `view` or one under it has `identifier`.
fn holds(view: &objc2_app_kit::NSView, identifier: &str) -> bool {
    use objc2_app_kit::NSUserInterfaceItemIdentification;
    view.identifier()
        .is_some_and(|own| own.to_string() == identifier)
        || view
            .subviews()
            .iter()
            .any(|child| holds(&child, identifier))
}

/// The window the user types into: the front window's dialog when one is
/// open, else the front window.
fn key_window(
    mtm: MainThreadMarker,
) -> Result<objc2::rc::Retained<objc2_app_kit::NSWindow>, String> {
    let window = front_window(mtm).ok_or("no main window")?;
    Ok(window.attachedSheet().unwrap_or(window))
}

/// Types `text` into the `n`th editable text field, through its field
/// editor as the keyboard would: `type <n> <text>`.
fn type_text(argument: &str) -> Result<(), String> {
    let (index, text) = argument.split_once(' ').ok_or("usage: type <n> <text>")?;
    let index: usize = index.parse().map_err(|_| "usage: type <n> <text>")?;
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = key_window(mtm)?;
    let content = window.contentView().ok_or("no content")?;
    let mut fields = Vec::new();
    collect(&content, objc2_app_kit::NSTextField::class(), &mut fields);
    let field = fields
        .iter()
        .filter_map(|view| view.downcast_ref::<objc2_app_kit::NSTextField>())
        .filter(|field| field.isEditable())
        .nth(index)
        .ok_or_else(|| format!("no editable text field {index}"))?;
    window.makeFirstResponder(Some(field));
    let editor = field
        .currentEditor()
        .ok_or("the field did not start editing")?;
    unsafe {
        let _: () = objc2::msg_send![&*editor, insertText: &*NSString::from_str(text)];
    }
    Ok(())
}

/// Types `text` into the window's text editor as the keyboard would, in
/// place of its whole text or at its end.
fn edit_text(append: bool, text: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = key_window(mtm)?;
    let content = window.contentView().ok_or("no content")?;
    let mut views = Vec::new();
    collect(&content, objc2_app_kit::NSTextView::class(), &mut views);
    let view = views
        .iter()
        .find_map(|view| view.downcast_ref::<objc2_app_kit::NSTextView>())
        .ok_or("no text editor")?;
    window.makeFirstResponder(Some(view));
    let text = NSString::from_str(&text.replace("\\n", "\n"));
    unsafe {
        if append {
            let _: () =
                objc2::msg_send![view, moveToEndOfDocument: None::<&objc2::runtime::AnyObject>];
        } else {
            let _: () = objc2::msg_send![view, selectAll: None::<&objc2::runtime::AnyObject>];
        }
        let _: () = objc2::msg_send![view, insertText: &*text];
    }
    Ok(())
}

/// The text view taking the keyboard in the window a user works in: a text
/// editor, or the field editor of the text field being edited.
fn typing_view(
    mtm: MainThreadMarker,
) -> Result<objc2::rc::Retained<objc2_app_kit::NSTextView>, String> {
    key_window(mtm)?
        .firstResponder()
        .and_then(|responder| responder.downcast::<objc2_app_kit::NSTextView>().ok())
        .ok_or_else(|| "nothing takes the keyboard".into())
}

/// Composes `text` as an input method does, as marked text at the caret
/// that is not yet committed.
fn compose(text: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let view = typing_view(mtm)?;
    let marked = NSString::from_str(text);
    let length = marked.length();
    unsafe {
        let _: () = objc2::msg_send![
            &*view,
            setMarkedText: &*marked,
            selectedRange: objc2_foundation::NSRange::new(length, 0),
            replacementRange: objc2_foundation::NSRange::new(objc2_foundation::NSNotFound as usize, 0),
        ];
    }
    Ok(())
}

/// Whether the text view taking the keyboard still composes, and its text.
fn marked() -> Result<String, String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let view = typing_view(mtm)?;
    let composing: bool = unsafe { objc2::msg_send![&*view, hasMarkedText] };
    let range: objc2_foundation::NSRange = unsafe { objc2::msg_send![&*view, markedRange] };
    let selected = view.selectedRange();
    Ok(format!(
        "marked {composing} {}+{} selected {}+{} {:?}",
        range.location,
        range.length,
        selected.location,
        selected.length,
        view.string().to_string()
    ))
}

/// Closes the main window as its close button does.
fn close_main() -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = NSApplication::sharedApplication(mtm)
        .windows()
        .iter()
        .find(|window| window.isVisible() && window.contentViewController().is_some())
        .ok_or("no main window")?;
    window.performClose(None);
    Ok(())
}

/// Sends a File menu item's action to the first responder, as the menu does.
fn menu(item: &str) -> Result<(), String> {
    let action = match item {
        "save" => objc2::sel!(saveDocument:),
        "revert" => objc2::sel!(revertDocumentToSaved:),
        "close" => objc2::sel!(performClose:),
        _ => return Err(format!("unknown menu item {item}")),
    };
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let sent =
        unsafe { NSApplication::sharedApplication(mtm).sendAction_to_from(action, None, None) };
    if sent {
        Ok(())
    } else {
        Err(format!("nothing took {item}"))
    }
}

/// Answers the open panel with `path`, as if the user picked it there.
fn answer_file(path: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    for window in NSApplication::sharedApplication(mtm).windows().iter() {
        if let Some(panel) = window.downcast_ref::<objc2_app_kit::NSOpenPanel>() {
            if panel.isVisible() {
                unsafe { panel.cancel(None) };
            }
        }
    }
    super::post(UiEvent::FileChosen {
        purpose: super::panels::asked(),
        path: Some(PathBuf::from(path)),
    });
    Ok(())
}

/// Writes the main window as the window server composites it, materials
/// and all, as a PNG at `path`.
fn capture(argument: &str) -> Result<(), String> {
    // Deprecated for ScreenCaptureKit, which needs the screen recording
    // permission; a window of this process needs none.
    #[allow(deprecated)]
    use objc2_core_graphics::{CGWindowImageOption, CGWindowListCreateImage, CGWindowListOption};
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    // `capture help <path>` writes the hover help that shows, and `capture
    // tray <path>` a group of the tray.
    let (window, path) = if let Some(path) = argument.strip_prefix("help ") {
        (
            super::hover_help::shown_window().ok_or("no hover help shows")?,
            path,
        )
    } else if let Some(path) = argument.strip_prefix("tray ") {
        // The window server gives no image of a menu's window: its views
        // draw themselves instead.
        let menu = shown_tray_menu()?;
        return super::tray::with_group_rows(mtm, &menu, |rows| write_png(rows, path))
            .ok_or("the tray has no group")?;
    } else {
        (front_window(mtm).ok_or("no main window")?, argument)
    };
    #[allow(deprecated)]
    let image = CGWindowListCreateImage(
        // `CGRectNull`: the window's own bounds.
        objc2_foundation::NSRect::new(
            NSPoint::new(f64::INFINITY, f64::INFINITY),
            objc2_foundation::NSSize::new(0.0, 0.0),
        ),
        CGWindowListOption::OptionIncludingWindow,
        window.windowNumber() as u32,
        CGWindowImageOption::BoundsIgnoreFraming | CGWindowImageOption::BestResolution,
    )
    .ok_or("the window server gave no image")?;
    let rep = objc2_app_kit::NSBitmapImageRep::initWithCGImage(
        objc2_app_kit::NSBitmapImageRep::alloc(),
        &image,
    );
    let data = unsafe {
        rep.representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }
    .ok_or("PNG encoding failed")?;
    if data.writeToFile_atomically(&NSString::from_str(path), true) {
        Ok(())
    } else {
        Err(format!("cannot write {path}"))
    }
}

/// Writes the main window's open dialog as a PNG at `path`.
fn snapshot_dialog(path: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    let sheet = window.attachedSheet().ok_or("no dialog")?;
    let frame = sheet
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    write_png(&frame, path)
}

/// Clicks the first button titled `title`, or with that tooltip, in the
/// main window, or in its dialog while one is open.
fn press(title: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    // The window a user works in first, then the main window and its dialog.
    let main = NSApplication::sharedApplication(mtm)
        .windows()
        .iter()
        .find(|window| window.isVisible() && window.contentViewController().is_some());
    let windows = [
        Some(key_window(mtm)?),
        main.clone().and_then(|main| main.attachedSheet()),
        main,
    ];
    let button = windows
        .iter()
        .flatten()
        .filter_map(|window| {
            window
                .contentView()
                .and_then(|content| unsafe { content.superview() })
        })
        .find_map(|frame| find_button(&frame, title))
        .ok_or_else(|| format!("no button titled {title}"))?;
    unsafe { button.performClick(None) };
    Ok(())
}

fn find_button(
    view: &objc2_app_kit::NSView,
    title: &str,
) -> Option<objc2::rc::Retained<objc2_app_kit::NSButton>> {
    if let Some(button) = view.downcast_ref::<objc2_app_kit::NSButton>() {
        // A symbol-only button goes by its hover help.
        let help = super::hover_help::of(button);
        if button.title().to_string() == title || help.as_deref() == Some(title) {
            return Some(objc2::Message::retain(button));
        }
    }
    view.subviews()
        .iter()
        .find_map(|child| find_button(&child, title))
}

/// Queues a key press for the front window, which arrives as a typed key
/// does.
fn key(name: &str) -> Result<(), String> {
    let arrow = NSEventModifierFlags::NumericPad | NSEventModifierFlags::Function;
    let (characters, code, modifiers) = match name {
        // `kVK_Escape` in HIToolbox's `Events.h`.
        "escape" => ("\u{1b}", 0x35, NSEventModifierFlags::empty()),
        // `kVK_Return`.
        "return" => ("\r", 0x24, NSEventModifierFlags::empty()),
        // `kVK_ANSI_S`.
        "cmd-s" => ("s", 0x01, NSEventModifierFlags::Command),
        // `kVK_ANSI_Q`.
        "cmd-q" => ("q", 0x0C, NSEventModifierFlags::Command),
        // The arrow keys, which move through an open menu: `kVK_UpArrow`
        // and its neighbours, typing `NSUpArrowFunctionKey` and its
        // neighbours (`NSEvent.h`) as function keys of the numeric pad.
        "up" => ("\u{f700}", 0x7E, arrow),
        "down" => ("\u{f701}", 0x7D, arrow),
        "left" => ("\u{f702}", 0x7B, arrow),
        "right" => ("\u{f703}", 0x7C, arrow),
        _ => return Err(format!("unknown key {name}")),
    };
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    let window = front_window(mtm).ok_or("no main window")?;
    let characters = NSString::from_str(characters);
    let event = NSEvent::keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode(
        NSEventType::KeyDown,
        NSPoint::new(0.0, 0.0),
        modifiers,
        0.0,
        window.windowNumber(),
        None,
        &characters,
        &characters,
        false,
        code,
    )
    .ok_or("cannot make the key event")?;
    app.postEvent_atStart(&event, false);
    Ok(())
}

/// Queues a mouse click for the main window at `x y`, in points from the
/// window's top left, which arrives as a click of the mouse does.
/// Points from the window's top left, as numbers in `argument`.
fn points(argument: &str, count: usize, usage: &str) -> Result<Vec<f64>, String> {
    let numbers: Vec<f64> = argument
        .split_whitespace()
        .map(|word| word.parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|_| usage.to_string())?;
    if numbers.len() == count {
        Ok(numbers)
    } else {
        Err(usage.into())
    }
}

/// Posts mouse events at points from the front window's top left.
fn mouse(events: &[(NSEventType, f64, f64, isize)]) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    let window = front_window(mtm).ok_or("no main window")?;
    let height = window.frame().size.height;
    // Times as AppKit's own events carry them, a little apart.
    let start = objc2_foundation::NSProcessInfo::processInfo().systemUptime();
    for (index, &(kind, x, y, clicks)) in events.iter().enumerate() {
        // Window coordinates start at the bottom left.
        let event = NSEvent::mouseEventWithType_location_modifierFlags_timestamp_windowNumber_context_eventNumber_clickCount_pressure(
            kind,
            NSPoint::new(x, height - y),
            NSEventModifierFlags::empty(),
            start + index as f64 * 0.016,
            window.windowNumber(),
            None,
            0,
            clicks,
            1.0,
        )
        .ok_or("cannot make the mouse event")?;
        app.postEvent_atStart(&event, false);
    }
    Ok(())
}

fn click(argument: &str) -> Result<(), String> {
    let at = points(argument, 2, "usage: click <x> <y>")?;
    mouse(&[
        (NSEventType::LeftMouseDown, at[0], at[1], 1),
        (NSEventType::LeftMouseUp, at[0], at[1], 1),
    ])
}

fn double_click(argument: &str) -> Result<(), String> {
    let at = points(argument, 2, "usage: double-click <x> <y>")?;
    mouse(&[
        (NSEventType::LeftMouseDown, at[0], at[1], 1),
        (NSEventType::LeftMouseUp, at[0], at[1], 1),
        (NSEventType::LeftMouseDown, at[0], at[1], 2),
        (NSEventType::LeftMouseUp, at[0], at[1], 2),
    ])
}

fn shown_tray_menu() -> Result<objc2::rc::Retained<objc2_app_kit::NSMenu>, String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    super::tray::status_item()
        .and_then(|item| item.menu(mtm))
        .ok_or_else(|| "no tray menu".to_string())
}

/// The tray's icon, dimmed or plain, then its menu, one item per line: a
/// check, the title, a row's latency in brackets, and whether it is
/// disabled.
fn tray_menu() -> String {
    match shown_tray_menu() {
        Ok(menu) => {
            // The run loop's mode tells whether a menu is tracking now.
            let mode = objc2_foundation::NSRunLoop::mainRunLoop()
                .currentMode()
                .map(|mode| mode.to_string())
                .unwrap_or_default();
            let dimmed = MainThreadMarker::new()
                .and_then(|mtm| super::tray::status_item()?.button(mtm))
                .is_some_and(|button| button.appearsDisabled());
            let mut lines = vec![
                format!("icon {}", if dimmed { "dimmed" } else { "plain" }),
                format!("mode {mode}"),
            ];
            super::tray::describe(&menu, 0, &mut lines);
            lines.join("\\n")
        }
        Err(error) => format!("error: {error}"),
    }
}

fn tray_choose(title: &str) -> Result<(), String> {
    let menu = shown_tray_menu()?;
    if super::tray::choose(&menu, title) {
        Ok(())
    } else {
        Err(format!("no enabled tray item {title}"))
    }
}

/// Opens the tray's menu as a click on its icon does, or closes it. The
/// click runs from a timer, so the menu's tracking starts outside this
/// command and later commands still run while it is open.
fn tray_track(open: bool) -> Result<(), String> {
    use objc2_foundation::NSObjectNSDelayedPerforming;
    let item = super::tray::status_item().ok_or("no tray item")?;
    if open {
        let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
        let button = item.button(mtm).ok_or("no tray button")?;
        unsafe {
            button.performSelector_withObject_afterDelay(objc2::sel!(performClick:), None, 0.0)
        };
    } else {
        shown_tray_menu()?.cancelTracking();
    }
    Ok(())
}

/// Drops the `from`th row of the first table whose rows move before its
/// `to`th row, as a drag would: AppKit's drag session follows the real
/// pointer, so a posted drag cannot drop.
fn drop_rows(argument: &str) -> Result<(), String> {
    let at = points(argument, 2, "usage: drop-rows <from> <to>")?;
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    let frame = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    let mut tables = Vec::new();
    collect(&frame, objc2_app_kit::NSTableView::class(), &mut tables);
    let movable = tables
        .iter()
        .filter_map(|view| view.downcast_ref::<objc2_app_kit::NSTableView>())
        .find(|table| super::table::rows_move(table))
        .ok_or("no table whose rows move")?;
    super::table::drop_rows(movable, at[0] as usize, at[1] as usize)
}

/// The main window's view tree with each view's class and frame, one view
/// per line, indented by depth.
fn dump(main: bool) -> String {
    let Some(mtm) = MainThreadMarker::new() else {
        return "error: not on the main thread".into();
    };
    let window = if main {
        NSApplication::sharedApplication(mtm)
            .windows()
            .iter()
            .find(|window| window.isVisible() && window.contentViewController().is_some())
    } else {
        front_window(mtm)
    };
    let Some(window) = window else {
        return "error: no main window".into();
    };
    let mut lines = Vec::new();
    // Which window takes the keyboard, by its title, or `-` when none does.
    let key = NSApplication::sharedApplication(mtm)
        .keyWindow()
        .map(|key| {
            format!(
                "{} \"{}\"",
                key.class().name().to_string_lossy(),
                key.title()
            )
        })
        .unwrap_or_else(|| "-".into());
    let dock = if NSApplication::sharedApplication(mtm).activationPolicy()
        == objc2_app_kit::NSApplicationActivationPolicy::Regular
    {
        "dock"
    } else {
        "no-dock"
    };
    lines.push(format!("key {key} {dock}"));
    // From the frame view: a full-height sidebar lives beside the content view.
    if let Some(frame) = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
    {
        walk(&frame, 0, &mut lines);
    }
    lines.join("\\n")
}

fn walk(view: &objc2_app_kit::NSView, depth: usize, lines: &mut Vec<String>) {
    let frame = view.frame();
    let class = view.class().name().to_string_lossy().into_owned();
    // What a control shows and whether it takes input.
    let mut state = String::new();
    if let Some(control) = view.downcast_ref::<objc2_app_kit::NSControl>() {
        if let Some(switch) = view.downcast_ref::<objc2_app_kit::NSSwitch>() {
            let on = switch.state() == objc2_app_kit::NSControlStateValueOn;
            state.push_str(if on { " on" } else { " off" });
        } else if let Some(button) = view.downcast_ref::<objc2_app_kit::NSButton>() {
            state.push_str(&format!(" \"{}\"", button.title()));
        } else if let Some(field) = view.downcast_ref::<objc2_app_kit::NSTextField>() {
            state.push_str(&format!(" \"{}\"", field.stringValue()));
        }
        if !control.isEnabled() {
            state.push_str(" disabled");
        }
    }
    lines.push(format!(
        "{}{class} {:.0},{:.0} {:.0}x{:.0}{state}",
        "  ".repeat(depth),
        frame.origin.x,
        frame.origin.y,
        frame.size.width,
        frame.size.height
    ));
    if depth < 24 {
        for child in view.subviews().iter() {
            walk(&child, depth + 1, lines);
        }
    }
}

/// Writes the first view of `class` in the main window as a PNG at `path`:
/// for views a window snapshot cannot render, such as those behind a
/// vibrant material.
fn snapshot_class(class: &str, path: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    let frame = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    let view = find_class(&frame, class).ok_or_else(|| format!("no {class} view"))?;
    write_png(&view, path)
}

fn find_class(
    view: &objc2_app_kit::NSView,
    class: &str,
) -> Option<objc2::rc::Retained<objc2_app_kit::NSView>> {
    if view.class().name().to_string_lossy() == class {
        return Some(objc2::Message::retain(view));
    }
    view.subviews()
        .iter()
        .find_map(|child| find_class(&child, class))
}

fn write_png(view: &objc2_app_kit::NSView, path: &str) -> Result<(), String> {
    let bounds = view.bounds();
    let image = view
        .bitmapImageRepForCachingDisplayInRect(bounds)
        .ok_or("no bitmap")?;
    view.cacheDisplayInRect_toBitmapImageRep(bounds, &image);
    let data = unsafe {
        image.representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }
    .ok_or("PNG encoding failed")?;
    if data.writeToFile_atomically(&NSString::from_str(path), true) {
        Ok(())
    } else {
        Err(format!("cannot write {path}"))
    }
}

/// Writes the main window, title bar included, as a PNG at `path`.
fn snapshot(path: &str) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window = front_window(mtm).ok_or("no main window")?;
    // The content view's superview is the window's frame view, which draws the toolbar too.
    let frame = window
        .contentView()
        .and_then(|content| unsafe { content.superview() })
        .ok_or("no frame view")?;
    let bounds = frame.bounds();
    let image = frame
        .bitmapImageRepForCachingDisplayInRect(bounds)
        .ok_or("no bitmap")?;
    frame.cacheDisplayInRect_toBitmapImageRep(bounds, &image);
    let data = unsafe {
        image.representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }
    .ok_or("PNG encoding failed")?;
    if data.writeToFile_atomically(&NSString::from_str(path), true) {
        Ok(())
    } else {
        Err(format!("cannot write {path}"))
    }
}
