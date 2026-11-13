//! The editor window: a window of its own, as large as it was last time
//! (`window_state.rs`), centered over the main window when that is open and
//! on the screen otherwise, and kept within the display's work area. Its
//! title is the profile's name, marked with `*` while the text has unsaved
//! changes as Windows editors do; a row over the text holds Revert and Save,
//! and Ctrl+S saves. Closing asks the interface (`AppWindow.Closing`,
//! cancelled), which closes the window in its render.

use std::cell::Cell;
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result};

use egrio_ui::backend::{Appearance, EditorAction, EditorCommand, EditorView, UiEvent};
use egrio_ui::reconcile::Mounted;

use super::bindings::{
    Border, Button, DisplayArea, DisplayAreaFallback, ElementTheme, Grid, HorizontalAlignment,
    IButtonBase, IContentControl, IControl, IOverlappedPresenter3, IPanel, IUIElement, IWindow2,
    KeyboardAccelerator, MicaBackdrop, Orientation, PointInt32, RowDefinition, SizeInt32,
    StackPanel, TitleBarTheme, UIElement, VirtualKey, VirtualKeyModifiers, Window,
};
use super::widgets::{check, Post, Surface};
use super::window_state::{self, Which};
use super::xaml::{self, Element};

/// The window's first size and the least it takes, in device-independent
/// pixels.
const SIZE: (f64, f64) = (820.0, 640.0);
const MIN_SIZE: (f64, f64) = (480.0, 320.0);
const INSET: f64 = 12.0;

pub struct EditorWindow {
    window: Window,
    root: Grid,
    revert: Button,
    save: Button,
    pub surface: Surface,
    /// Set while the interface closes the window, which then may close.
    closing: Rc<Cell<bool>>,
    _events: Vec<EventRevoker>,
}

fn command_button(
    command: &EditorCommand,
    post: Post,
    action: EditorAction,
) -> Result<(Button, EventRevoker)> {
    let button = Button::new()?;
    style_command(&button, command)?;
    let click = button
        .cast::<IButtonBase>()?
        .Click(move |_, _| post(UiEvent::Editor(action)))?;
    Ok((button, click))
}

fn style_command(button: &Button, command: &EditorCommand) -> Result<()> {
    button
        .cast::<IContentControl>()?
        .SetContent(&xaml::boxed(&command.label)?)?;
    button.cast::<IControl>()?.SetIsEnabled(command.enabled)
}

fn title(view: &EditorView) -> String {
    if view.edited {
        format!("*{}", view.title)
    } else {
        view.title.clone()
    }
}

impl EditorWindow {
    pub fn open(
        over: Option<&Window>,
        view: &EditorView,
        content: &Mounted,
        appearance: Appearance,
        post: Post,
    ) -> Result<Self> {
        let window = Window::new()?;
        window.SetTitle(&title(view))?;
        let window2 = window.cast::<IWindow2>()?;
        window2.SetSystemBackdrop(&MicaBackdrop::new()?)?;

        let root = Grid::new()?;
        for length in [xaml::auto(), xaml::star()] {
            let row = RowDefinition::new()?;
            row.SetHeight(length)?;
            root.RowDefinitions()?.Append(&row)?;
        }
        let commands = StackPanel::new()?;
        commands.SetOrientation(Orientation::Horizontal)?;
        commands.SetSpacing(8.0)?;
        commands
            .fe()
            .SetHorizontalAlignment(HorizontalAlignment::Right)?;
        commands.fe().SetMargin(xaml::uniform(INSET))?;
        let (revert, revert_click) = command_button(&view.revert, post, EditorAction::Revert)?;
        let (save, save_click) = command_button(&view.save, post, EditorAction::Save)?;
        save.fe()
            .SetStyle(&xaml::resource::<super::bindings::Style>(
                "AccentButtonStyle",
            )?)?;
        let accelerator = KeyboardAccelerator::new()?;
        accelerator.SetKey(VirtualKey::S)?;
        accelerator.SetModifiers(VirtualKeyModifiers::Control)?;
        save.cast::<IUIElement>()?
            .KeyboardAccelerators()?
            .Append(&accelerator)?;
        commands
            .panel()
            .Children()?
            .Append(&revert.cast::<UIElement>()?)?;
        commands
            .panel()
            .Children()?
            .Append(&save.cast::<UIElement>()?)?;
        root.cast::<IPanel>()?
            .Children()?
            .Append(&commands.cast::<UIElement>()?)?;

        let host = Border::new()?;
        host.fe().SetMargin(super::bindings::Thickness {
            left: INSET,
            top: 0.0,
            right: INSET,
            bottom: INSET,
        })?;
        Grid::SetRow(&host, 1)?;
        root.cast::<IPanel>()?
            .Children()?
            .Append(&host.cast::<UIElement>()?)?;
        window.SetContent(&root)?;
        let mut surface = Surface::new(host, post);
        surface.set_root(content);

        let closing = Rc::new(Cell::new(false));
        let app_window = window2.AppWindow()?;
        let close_requested = {
            let closing = closing.clone();
            app_window.Closing(move |_, args| {
                if closing.get() {
                    return;
                }
                if let Ok(args) = args.ok() {
                    check(args.SetCancel(true), "keep the editor open");
                }
                post(UiEvent::Editor(EditorAction::Close));
            })?
        };
        place(&window, over)?;
        super::hwnd::set_icon(&window);

        let this = Self {
            window,
            root,
            revert,
            save,
            surface,
            closing,
            _events: vec![revert_click, save_click, close_requested],
        };
        this.set_appearance(appearance)?;
        this.window.Activate()?;
        Ok(this)
    }

    pub fn update(&self, view: &EditorView) -> Result<()> {
        self.window.SetTitle(&title(view))?;
        style_command(&self.revert, &view.revert)?;
        style_command(&self.save, &view.save)
    }

    pub fn set_appearance(&self, appearance: Appearance) -> Result<()> {
        let (theme, bar) = match appearance {
            Appearance::System => (ElementTheme::Default, TitleBarTheme::UseDefaultAppMode),
            Appearance::Light => (ElementTheme::Light, TitleBarTheme::Light),
            Appearance::Dark => (ElementTheme::Dark, TitleBarTheme::Dark),
        };
        self.root.fe().SetRequestedTheme(theme)?;
        self.window
            .cast::<IWindow2>()?
            .AppWindow()?
            .TitleBar()?
            .cast::<super::bindings::IAppWindowTitleBar3>()?
            .SetPreferredTheme(bar)
    }

    /// Saves the window's size, for the next time it opens.
    pub fn remember_place(&self) {
        window_state::remember(&self.window, Which::Editor);
    }

    pub fn bring_to_front(&self) {
        check(
            super::hwnd::restore_and_focus(&self.window),
            "bring the editor forward",
        );
    }

    pub fn reveal(&self, index: usize) {
        if let Some(field) = self.surface.text_editor() {
            check(
                super::text_editor::reveal(&field, index),
                "reveal in the editor",
            );
        }
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    pub fn close(self) {
        self.remember_place();
        self.closing.set(true);
        check(self.window.Close(), "close the editor");
    }
}

/// Sizes the window as it was last time, or at its first size, keeps it
/// from getting smaller than it can be used at, and centers it over `over`,
/// or on the screen, within the display's work area.
fn place(window: &Window, over: Option<&Window>) -> Result<()> {
    let app_window = window.cast::<IWindow2>()?.AppWindow()?;
    let scale = super::hwnd::scale(over.unwrap_or(window));
    if let Ok(presenter) = app_window
        .Presenter()
        .and_then(|presenter| presenter.cast::<IOverlappedPresenter3>())
    {
        check(
            presenter.SetPreferredMinimumWidth(Some((MIN_SIZE.0 * scale) as i32)),
            "set the editor's least width",
        );
        check(
            presenter.SetPreferredMinimumHeight(Some((MIN_SIZE.1 * scale) as i32)),
            "set the editor's least height",
        );
    }
    let fallback = if over.is_some() {
        DisplayAreaFallback::Nearest
    } else {
        DisplayAreaFallback::Primary
    };
    let area = DisplayArea::GetFromWindowId(
        match over {
            Some(over) => over.cast::<IWindow2>()?.AppWindow()?.Id()?,
            None => app_window.Id()?,
        },
        fallback,
    )?
    .WorkArea()?;
    let wanted = window_state::saved(Which::Editor).map_or(
        ((SIZE.0 * scale) as i32, (SIZE.1 * scale) as i32),
        |placement| (placement.width(), placement.height()),
    );
    let size = SizeInt32 {
        width: wanted.0.min(area.width),
        height: wanted.1.min(area.height),
    };
    app_window.Resize(size)?;
    let (left, top, width, height) = match over {
        Some(over) => {
            let main = over.cast::<IWindow2>()?.AppWindow()?;
            let (position, size) = (main.Position()?, main.Size()?);
            (position.x, position.y, size.width, size.height)
        }
        None => (area.x, area.y, area.width, area.height),
    };
    let x = (left + (width - size.width) / 2).clamp(area.x, area.x + area.width - size.width);
    let y = (top + (height - size.height) / 2).clamp(area.y, area.y + area.height - size.height);
    app_window.Move(PointInt32 { x, y })
}
