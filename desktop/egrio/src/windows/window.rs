//! The main window's shell: a WinUI window whose content runs up under the
//! title bar ("Title bar customization"). The title bar's row carries the
//! app's icon and name over the sidebar, and over the page the message
//! capsule (`messages.rs`), in line with the page, and the toolbar (the
//! capture switches and the traffic mode), the capsule and the toolbar as
//! the window's interactive title bar content (`title_bar.rs`); there is no
//! page title, the sidebar's selection names the page. Under it a navigation
//! view has the sections down its side and the page beside them. The message
//! panel is the capsule's surface grown out of it over the page, as wide as
//! the open capsule and as tall as its messages, without moving the page; a
//! click in the sidebar or the page closes it and still acts on what it
//! lands on, and Esc closes it unless a text field takes the key. While the
//! window is inactive, the title bar's icon and name fade as the system's do
//! ("Windows app title bar").

use std::cell::Cell;
use std::rc::Rc;

use windows_core::{EventRevoker, IInspectable, Interface, Result};

use egrio_ui::backend::{
    Appearance, CaptureToggle, MainView, NavItem, PolicyControl, ToggleState, ToolbarAction,
    UiEvent, DRAWER_HEIGHT, PAGE_MIN_WIDTH,
};
use egrio_ui::node::{TextStyle, Tone};
use egrio_ui::reconcile::Mounted;
use egrio_ui::state::Section;

use super::bindings::{
    AutomationProperties, Border, ColumnDefinition, ElementTheme, FocusManager, FocusState,
    FontIcon, FrameworkElement, Grid, HorizontalAlignment, IButtonBase, IContentControl, IControl,
    IPanel, IToggleButton, IUIElement, IWindow2, Image, MicaBackdrop, NavigationView,
    NavigationViewBackButtonVisible, NavigationViewItem, NavigationViewPaneDisplayMode,
    Orientation, RowDefinition, SelectorBar, SelectorBarItem, StackPanel, TextBlock, ThemeShadow,
    Thickness, TitleBarHeightOption, TitleBarTheme, ToggleButton, ToolTipService, UIElement,
    VerticalAlignment, VirtualKey, Window, WindowActivationState,
};
use super::dialog::Dialog;
use super::messages::{self, Capsule};
use super::title_bar::Regions;
use super::widgets::{check, label, Post, Surface};
use super::window_state::{self, Which};
use super::xaml::{self, Element};

/// The window's first size and the least it takes, in device-independent
/// pixels: the page's least width beside the sidebar.
const DEFAULT_SIZE: (f64, f64) = (1120.0, 720.0);
const MIN_HEIGHT: f64 = 640.0;
/// The sidebar's one width; the page takes the rest of the window.
const SIDEBAR_WIDTH: f64 = 180.0;
/// The distance between the title bar's row and the messages under it, and
/// the panel's inner margin elsewhere.
const DRAWER_GAP: f64 = 4.0;
const DRAWER_INSET: f64 = 16.0;
/// The page's distance from its pane's edges, which the message capsule
/// keeps from the sidebar too.
const PAGE_INSET: f64 = 16.0;
/// The tall title bar's height, which interactive title bar content takes
/// ("Windows app title bar").
const TITLE_BAR_HEIGHT: f64 = 48.0;
/// The window's name, which the taskbar and the task switcher show.
const APP_NAME: &str = "Egrio";
/// The app icon's size and its distance from the window's edge and from the
/// name, and how far the title bar's text fades in an inactive window
/// ("Windows app title bar"; `TitleBarDeactivatedOpacity`).
const ICON_SIZE: f64 = 16.0;
const ICON_SPACING: f64 = 16.0;
const INACTIVE_OPACITY: f64 = 0.5;
/// The toolbar's distance from the caption buttons.
const TOOLBAR_TRAILING: f64 = 12.0;

struct Toggle {
    button: ToggleButton,
    dot: FontIcon,
    label: TextBlock,
}

struct Toolbar {
    system_proxy: Option<Toggle>,
    tun: Toggle,
    policy: SelectorBar,
    quiet: Rc<Cell<bool>>,
}

pub struct MainWindow {
    window: Window,
    root: Grid,
    _regions: Regions,
    nav: NavigationView,
    nav_items: Vec<(Section, NavigationViewItem)>,
    /// The message panel's surface, which is the capsule's, and the host of
    /// its messages over it.
    panel_surface: Border,
    panel_host: Border,
    drawer_growth: Rc<Growth>,
    drawer_open: Rc<Cell<bool>>,
    capsule: Rc<Capsule>,
    toolbar: Toolbar,
    quiet: Rc<Cell<bool>>,
    /// Set once the window closed, by the user or by `close`.
    closed: Rc<Cell<bool>>,
    pub content: Surface,
    pub drawer: Surface,
    /// The open dialog, over the window.
    pub dialog: Option<Dialog>,
    view: MainView,
    post: Post,
    _events: Vec<EventRevoker>,
}

fn toggle(post: Post, action: ToolbarAction) -> Result<(Toggle, EventRevoker)> {
    let button = ToggleButton::new()?;
    let content = StackPanel::new()?;
    content.SetOrientation(Orientation::Horizontal)?;
    content.SetSpacing(8.0)?;
    let dot = FontIcon::new()?;
    let label = label("", TextStyle::Body, Tone::Default)?;
    content
        .panel()
        .Children()?
        .Append(&dot.cast::<UIElement>()?)?;
    content
        .panel()
        .Children()?
        .Append(&label.cast::<UIElement>()?)?;
    button.cast::<IContentControl>()?.SetContent(&content)?;
    let click = button
        .cast::<IButtonBase>()?
        .Click(move |_, _| post(UiEvent::Toolbar(action.clone())))?;
    Ok((Toggle { button, dot, label }, click))
}

fn style_toggle(toggle: &Toggle, view: &CaptureToggle) -> Result<()> {
    toggle.label.SetText(&view.label)?;
    let tone = match (view.state, view.on) {
        (ToggleState::Pending | ToggleState::Warning, _) => Tone::Warning,
        (ToggleState::Idle, true) => Tone::Success,
        (ToggleState::Idle, false) => Tone::Faint,
    };
    toggle.dot.fe().SetStyle(&xaml::icon_style(tone, 8.0)?)?;
    // CircleFill.
    toggle.dot.SetGlyph("\u{EA3B}")?;
    toggle
        .button
        .cast::<IToggleButton>()?
        .SetIsChecked(Some(view.on))?;
    toggle
        .button
        .cast::<IControl>()?
        .SetIsEnabled(view.enabled)?;
    AutomationProperties::SetName(&toggle.button, &view.label)?;
    set_tooltip(&toggle.button, view.tooltip.as_deref())
}

fn set_tooltip(element: &impl Interface, tooltip: Option<&str>) -> Result<()> {
    match tooltip {
        Some(text) => ToolTipService::SetToolTip(&xaml::as_element(element)?, &xaml::boxed(text)?),
        None => ToolTipService::SetToolTip(&xaml::as_element(element)?, None::<&IInspectable>),
    }
}

impl Toolbar {
    fn new(view: &MainView, post: Post) -> Result<(Self, StackPanel, Vec<EventRevoker>)> {
        let panel = StackPanel::new()?;
        panel.SetOrientation(Orientation::Horizontal)?;
        panel.SetSpacing(8.0)?;
        panel.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        let mut events = Vec::new();
        let system_proxy = match view.toolbar.system_proxy {
            Some(_) => {
                let (toggle, click) = toggle(post, ToolbarAction::ToggleSystemProxy)?;
                events.push(click);
                Some(toggle)
            }
            None => None,
        };
        let (tun, click) = toggle(post, ToolbarAction::ToggleTun)?;
        events.push(click);

        let quiet = Rc::new(Cell::new(true));
        // As tall as the switches beside it: the bar's and its items' own
        // padding (`SelectorBarPadding`, `SelectorBarItemPadding`) leave
        // little of the title bar's height.
        let policy = SelectorBar::new()?;
        policy.cast::<IControl>()?.SetPadding(xaml::uniform(0.0))?;
        for label in &view.toolbar.policy.labels {
            let item = SelectorBarItem::new()?;
            item.SetText(label)?;
            item.cast::<IControl>()?.SetPadding(Thickness {
                left: 12.0,
                top: 6.0,
                right: 12.0,
                bottom: 5.0,
            })?;
            policy.Items()?.Append(&item)?;
        }
        {
            let quiet = quiet.clone();
            let control = policy.clone();
            events.push(policy.SelectionChanged(move |_, _| {
                if quiet.get() {
                    return;
                }
                let Ok(selected) = control.SelectedItem() else {
                    return;
                };
                let mut index = 0;
                if control
                    .Items()
                    .and_then(|items| items.IndexOf(&selected, &mut index))
                    .unwrap_or(false)
                {
                    post(UiEvent::Toolbar(ToolbarAction::Policy(index as usize)));
                }
            })?);
        }
        // The traffic mode first, then the capture switches.
        let children = panel.panel().Children()?;
        children.Append(&policy.cast::<UIElement>()?)?;
        if let Some(toggle) = &system_proxy {
            children.Append(&toggle.button.cast::<UIElement>()?)?;
        }
        children.Append(&tun.button.cast::<UIElement>()?)?;

        let toolbar = Self {
            system_proxy,
            tun,
            policy,
            quiet,
        };
        toolbar.update(view)?;
        toolbar.quiet.set(false);
        Ok((toolbar, panel, events))
    }

    fn update(&self, view: &MainView) -> Result<()> {
        if let (Some(toggle), Some(view)) = (&self.system_proxy, &view.toolbar.system_proxy) {
            style_toggle(toggle, view)?;
        }
        style_toggle(&self.tun, &view.toolbar.tun)?;
        self.style_policy(&view.toolbar.policy)
    }

    fn style_policy(&self, policy: &PolicyControl) -> Result<()> {
        let previous = self.quiet.replace(true);
        let result = (|| {
            let items = self.policy.Items()?;
            for (index, label) in policy.labels.iter().enumerate() {
                if let Ok(item) = items.GetAt(index as u32) {
                    item.SetText(label)?;
                }
            }
            match policy.selected {
                Some(index) => self.policy.SetSelectedItem(&items.GetAt(index as u32)?)?,
                None => self.policy.SetSelectedItem(None::<&SelectorBarItem>)?,
            }
            self.policy
                .cast::<IControl>()?
                .SetIsEnabled(policy.enabled)?;
            set_tooltip(&self.policy, policy.tooltip.as_deref())
        })();
        self.quiet.set(previous);
        result
    }
}

fn nav_item(item: &NavItem) -> Result<NavigationViewItem> {
    let entry = NavigationViewItem::new()?;
    entry
        .cast::<IContentControl>()?
        .SetContent(&xaml::boxed(&item.label)?)?;
    let icon = FontIcon::new()?;
    icon.SetGlyph(xaml::glyph(item.icon))?;
    entry.SetIcon(&icon)?;
    Ok(entry)
}

/// The title bar's row: the app's icon and name over the sidebar, the
/// message capsule over the page, in line with it, then free space, the
/// toolbar (placed by the window) and a column under the caption buttons.
struct Header {
    grid: Grid,
    caption: ColumnDefinition,
    brand: StackPanel,
    icon: Image,
}

/// The header's columns for the capsule and the toolbar.
const CAPSULE_COLUMN: i32 = 1;
const TOOLBAR_COLUMN: i32 = 3;

impl Header {
    fn new(scale: f64, capsule: &FrameworkElement) -> Result<Self> {
        let grid = Grid::new()?;
        let mut columns = Vec::new();
        for length in [
            xaml::pixels(SIDEBAR_WIDTH),
            xaml::auto(),
            xaml::star(),
            xaml::auto(),
            xaml::pixels(0.0),
        ] {
            let column = ColumnDefinition::new()?;
            column.SetWidth(length)?;
            grid.ColumnDefinitions()?.Append(&column)?;
            columns.push(column);
        }
        let brand = StackPanel::new()?;
        brand.SetOrientation(Orientation::Horizontal)?;
        brand.SetSpacing(ICON_SPACING)?;
        brand.fe().SetMargin(Thickness {
            left: ICON_SPACING,
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
        })?;
        brand.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        let icon = Image::new()?;
        icon.fe().SetWidth(ICON_SIZE)?;
        icon.fe().SetHeight(ICON_SIZE)?;
        if let Some(png) = super::hwnd::mark_image((ICON_SIZE * scale).round() as i32) {
            icon.SetSource(&super::images::bitmap(png)?)?;
        }
        let name = label(APP_NAME, TextStyle::Caption, Tone::Default)?;
        name.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        brand
            .panel()
            .Children()?
            .Append(&icon.cast::<UIElement>()?)?;
        brand
            .panel()
            .Children()?
            .Append(&name.cast::<UIElement>()?)?;

        capsule.SetMargin(Thickness {
            left: PAGE_INSET,
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
        })?;
        Grid::SetColumn(capsule, CAPSULE_COLUMN)?;
        let children = grid.cast::<IPanel>()?.Children()?;
        children.Append(&brand.cast::<UIElement>()?)?;
        children.Append(&capsule.cast::<UIElement>()?)?;
        let caption = columns.pop().expect("the caption buttons' column");
        Ok(Self {
            grid,
            caption,
            brand,
            icon,
        })
    }
}

/// The message panel, which is the capsule's surface grown out of it: it
/// starts at the capsule's top under the title bar's row, which draws the
/// capsule over it as the panel's head, and has the capsule's width and
/// rounded ends; closed, it is the capsule's own size. The surface is drawn
/// as WinUI draws a flyout, so it is the same kind of surface as the other
/// transient panels: in-app acrylic and a 1-pixel stroke (`FlyoutPresenter`'s
/// style), raised to 32 while open ("Layering and elevation in Windows") and
/// resting on the title bar while closed. A theme shadow outside a popup
/// falls only on the elements it names (`ThemeShadow`), here the page under
/// the panel. The messages lie in a host of their own over the surface,
/// which cuts them off while the panel moves: an element given less room
/// than its content is drawn at the content's size and clipped, which would
/// cut the surface's rounded bottom off with them. Returns the surface and
/// the host.
fn drawer_panel(page: &Border) -> Result<(Border, Border)> {
    let radius = messages::HEIGHT / 2.0;
    let surface: Border = xaml::load(
        "Border",
        &format!(
            "BorderThickness='1' CornerRadius='{radius}' Height='{}' \
             Background='{{ThemeResource AcrylicInAppFillColorDefaultBrush}}' \
             BorderBrush='{{ThemeResource SurfaceStrokeColorFlyoutBrush}}'",
            messages::HEIGHT
        ),
        "<Border.Shadow><ThemeShadow/></Border.Shadow>",
    )?;
    let shadow: ThemeShadow = surface.ui().Shadow()?.cast()?;
    shadow.Receivers()?.Append(&page.cast::<UIElement>()?)?;
    let host = Border::new()?;
    Ok((surface, host))
}

/// Hangs the panel's surface and its messages' host from the capsule: the
/// same top, leading edge and width, its messages under the title bar's row,
/// at most `DRAWER_HEIGHT` tall and clear of the window's bottom margin.
fn place_drawer(capsule: &Capsule, surface: &Border, host: &Border, root: &Grid) -> Result<()> {
    let element = capsule.element();
    if element.ActualWidth()? <= 0.0 {
        return Ok(());
    }
    let origin = element
        .ui()
        .TransformToVisual(&root.cast::<UIElement>()?)?
        .TransformBounds(super::bindings::Rect {
            x: 0.0,
            y: 0.0,
            width: 1.0,
            height: 1.0,
        })?;
    let (left, top) = (f64::from(origin.x), f64::from(origin.y));
    for element in [surface.fe(), host.fe()] {
        element.SetMargin(Thickness {
            left,
            top,
            right: 0.0,
            bottom: 0.0,
        })?;
        element.SetWidth(capsule.width())?;
    }
    host.SetPadding(Thickness {
        left: DRAWER_INSET,
        top: (TITLE_BAR_HEIGHT - top).max(messages::HEIGHT) + DRAWER_GAP,
        right: DRAWER_INSET,
        bottom: DRAWER_INSET,
    })?;
    let room = root.fe().ActualHeight()? - top - PAGE_INSET;
    host.fe().SetMaxHeight(DRAWER_HEIGHT.min(room.max(0.0)))
}

/// How high the open panel is raised over the page.
const ELEVATION: f32 = 32.0;

/// The panel growing out of the capsule or shrinking back into it: its height
/// moves between the capsule's and its messages', its messages fade in or
/// out, and it rises to its elevation or settles back onto the title bar,
/// over a few frames of a dispatcher timer, as the capsule moves. While it
/// moves its messages keep the open panel's size, so it uncovers them rather
/// than laying them out again at every step.
struct Growth {
    surface: Border,
    host: Border,
    timer: super::bindings::DispatcherQueueTimer,
    motion: Cell<Option<GrowthMotion>>,
    /// The height it was given last and how open it is, from 0 to 1.
    height: Cell<f64>,
    openness: Cell<f64>,
}

#[derive(Clone, Copy)]
struct GrowthMotion {
    height: (f64, f64),
    openness: (f64, f64),
    started: std::time::Instant,
}

impl Growth {
    fn new(surface: &Border, host: &Border) -> Result<(Rc<Self>, Vec<EventRevoker>)> {
        let timer = super::bindings::DispatcherQueue::GetForCurrentThread()?.CreateTimer()?;
        timer.SetInterval(windows_time::TimeSpan::from_millis(messages::FRAME))?;
        timer.SetIsRepeating(true)?;
        let growth = Rc::new(Self {
            surface: surface.clone(),
            host: host.clone(),
            timer: timer.clone(),
            motion: Cell::new(None),
            height: Cell::new(messages::HEIGHT),
            openness: Cell::new(0.0),
        });
        growth.show(messages::HEIGHT, 0.0)?;
        let weak = Rc::downgrade(&growth);
        let tick = timer.Tick(move |_, _| {
            if let Some(growth) = weak.upgrade() {
                check(growth.step(), "grow the message panel");
            }
        })?;
        // The open panel's surface is as tall as its messages.
        let weak = Rc::downgrade(&growth);
        let follow = host.fe().SizeChanged(move |_, _| {
            let Some(growth) = weak.upgrade() else { return };
            if growth.motion.get().is_none() && growth.openness.get() > 0.0 {
                check(
                    growth
                        .host
                        .fe()
                        .ActualHeight()
                        .and_then(|height| growth.surface.fe().SetHeight(height)),
                    "fit the message panel to its messages",
                );
            }
        })?;
        Ok((growth, vec![tick, follow]))
    }

    /// What the panel shows, its messages.
    fn messages(&self) -> Option<FrameworkElement> {
        self.host.Child().ok()?.cast().ok()
    }

    /// Opens the panel from where it is to its messages' height at
    /// `open_width`, or closes it back to the capsule's height.
    fn start(&self, open: bool, open_width: f64) -> Result<()> {
        let host = self.host.fe();
        let padding = self.host.Padding()?;
        let (vertical, horizontal) = (padding.top + padding.bottom, padding.left + padding.right);
        let to = match self.messages() {
            Some(messages) if open => {
                let width = (open_width - horizontal).max(0.0);
                messages.SetWidth(width)?;
                messages.SetHeight(f64::NAN)?;
                messages.ui().Measure(super::bindings::Size {
                    width: width as f32,
                    height: f32::INFINITY,
                })?;
                let content = f64::from(messages.ui().DesiredSize()?.height);
                let height = (content + vertical).min(host.MaxHeight()?);
                messages.SetHeight((height - vertical).max(0.0))?;
                height
            }
            Some(messages) => {
                messages.SetWidth(messages.ActualWidth()?)?;
                messages.SetHeight(messages.ActualHeight()?)?;
                messages::HEIGHT
            }
            None if open => vertical,
            None => messages::HEIGHT,
        };
        self.motion.set(Some(GrowthMotion {
            height: (self.height.get(), to),
            openness: (self.openness.get(), if open { 1.0 } else { 0.0 }),
            started: std::time::Instant::now(),
        }));
        self.timer.Start()
    }

    fn step(&self) -> Result<()> {
        let Some(motion) = self.motion.get() else {
            return self.timer.Stop();
        };
        let progress =
            (motion.started.elapsed().as_secs_f64() / messages::DURATION.as_secs_f64()).min(1.0);
        let eased = messages::ease(progress);
        let along = |(from, to): (f64, f64)| from + (to - from) * eased;
        self.show(along(motion.height), along(motion.openness))?;
        if progress < 1.0 {
            return Ok(());
        }
        self.motion.set(None);
        self.timer.Stop()?;
        // Open, it follows its messages again; closed, it stays the
        // capsule's surface.
        if motion.openness.1 > 0.0 {
            self.host.fe().SetHeight(f64::NAN)?;
            if let Some(messages) = self.messages() {
                messages.SetWidth(f64::NAN)?;
                messages.SetHeight(f64::NAN)?;
            }
        }
        Ok(())
    }

    /// Shows where it is again, on messages put in it since.
    fn reshow(&self) -> Result<()> {
        self.show(self.height.get(), self.openness.get())
    }

    fn show(&self, height: f64, openness: f64) -> Result<()> {
        self.height.set(height);
        self.openness.set(openness);
        self.surface.fe().SetHeight(height)?;
        self.host.fe().SetHeight(height)?;
        if let Some(messages) = self.messages() {
            messages.ui().SetOpacity(openness)?;
        }
        self.surface.ui().SetTranslation(super::bindings::Vector3 {
            x: 0.0,
            y: 0.0,
            z: ELEVATION * openness as f32,
        })
    }
}

impl MainWindow {
    pub fn open(
        view: &MainView,
        content: &Mounted,
        drawer: &Mounted,
        appearance: Appearance,
        post: Post,
    ) -> Result<Self> {
        let window = Window::new()?;
        window.SetTitle(APP_NAME)?;
        window.SetExtendsContentIntoTitleBar(true)?;
        let window2 = window.cast::<IWindow2>()?;
        window2.SetSystemBackdrop(&MicaBackdrop::new()?)?;
        let app_window = window2.AppWindow()?;
        app_window
            .TitleBar()?
            .cast::<super::bindings::IAppWindowTitleBar2>()?
            .SetPreferredHeightOption(TitleBarHeightOption::Tall)?;
        let scale = super::hwnd::system_scale();

        let root = Grid::new()?;
        for length in [xaml::pixels(TITLE_BAR_HEIGHT), xaml::star()] {
            let row = RowDefinition::new()?;
            row.SetHeight(length)?;
            root.RowDefinitions()?.Append(&row)?;
        }
        let capsule = Rc::new(Capsule::new(post)?);
        let header = Header::new(scale, &capsule.element())?;
        let (toolbar, toolbar_panel, mut events) = Toolbar::new(view, post)?;
        toolbar_panel.fe().SetMargin(Thickness {
            left: 0.0,
            top: 0.0,
            right: TOOLBAR_TRAILING,
            bottom: 0.0,
        })?;
        Grid::SetColumn(&toolbar_panel, TOOLBAR_COLUMN)?;
        {
            let start = capsule.element();
            let end = toolbar_panel.cast::<FrameworkElement>()?;
            capsule.set_room(move || messages::room_before(&start, &end));
        }
        header
            .grid
            .cast::<IPanel>()?
            .Children()?
            .Append(&toolbar_panel.cast::<UIElement>()?)?;

        let nav = NavigationView::new()?;
        Grid::SetRow(&nav, 1)?;
        let nav2 = nav.cast::<super::bindings::INavigationView2>()?;
        nav2.SetPaneDisplayMode(NavigationViewPaneDisplayMode::Left)?;
        nav2.SetIsBackButtonVisible(NavigationViewBackButtonVisible::Collapsed)?;
        nav.SetIsPaneToggleButtonVisible(false)?;
        nav.SetIsSettingsVisible(false)?;
        nav.SetOpenPaneLength(SIDEBAR_WIDTH)?;
        nav.SetAlwaysShowHeader(false)?;
        let mut nav_items = Vec::new();
        for item in &view.nav {
            let entry = nav_item(item)?;
            nav.MenuItems()?.Append(&entry.cast::<IInspectable>()?)?;
            nav_items.push((item.section, entry));
        }
        root.cast::<IPanel>()?
            .Children()?
            .Append(&nav.cast::<UIElement>()?)?;

        let page_host = Border::new()?;
        page_host.fe().SetMargin(xaml::uniform(PAGE_INSET))?;
        nav.cast::<IContentControl>()?.SetContent(&page_host)?;

        // The panel lies in the window's grid beside the navigation view
        // rather than in a split view's pane, whose clip would cut its shadow
        // off. It spans the title bar's row too, under the header, which
        // comes last and so draws the capsule over the panel as its head.
        let (panel_surface, panel_host) = drawer_panel(&page_host)?;
        for part in [&panel_surface, &panel_host] {
            Grid::SetRow(part, 0)?;
            Grid::SetRowSpan(part, 2)?;
            part.fe()
                .SetHorizontalAlignment(HorizontalAlignment::Left)?;
            part.fe().SetVerticalAlignment(VerticalAlignment::Top)?;
            root.cast::<IPanel>()?
                .Children()?
                .Append(&part.cast::<UIElement>()?)?;
        }
        root.cast::<IPanel>()?
            .Children()?
            .Append(&header.grid.cast::<UIElement>()?)?;
        let (drawer_growth, grow) = Growth::new(&panel_surface, &panel_host)?;
        events.extend(grow);
        let drawer_open = Rc::new(Cell::new(false));
        // A press that no control takes reaches the navigation view; one a
        // control takes moves the keyboard focus there, since the drawer's
        // opening took it out to the message button.
        let close_drawer = {
            let drawer_open = drawer_open.clone();
            Rc::new(move || {
                if drawer_open.get() {
                    post(UiEvent::CloseDrawer);
                }
            })
        };
        {
            let close = close_drawer.clone();
            events.push(nav.ui().PointerPressed(move |_, _| close())?);
        }
        events.push(nav.ui().GotFocus(move |_, _| close_drawer())?);
        {
            let drawer_open = drawer_open.clone();
            events.push(root.cast::<IUIElement>()?.KeyDown(move |_, args| {
                let Ok(args) = args.ok() else { return };
                if drawer_open.get() && args.Key() == Ok(VirtualKey::Escape) {
                    let _ = args.SetHandled(true);
                    post(UiEvent::CloseDrawer);
                }
            })?);
        }

        let quiet = Rc::new(Cell::new(true));
        {
            let quiet = quiet.clone();
            let sections: Vec<(Section, NavigationViewItem)> = nav_items.clone();
            events.push(nav.SelectionChanged(move |_, args| {
                if quiet.get() {
                    return;
                }
                let Some(selected) = args.ok().ok().and_then(|args| args.SelectedItem().ok())
                else {
                    return;
                };
                if let Some((section, _)) = sections
                    .iter()
                    .find(|(_, item)| item.cast::<IInspectable>().ok().as_ref() == Some(&selected))
                {
                    post(UiEvent::Navigate(*section));
                }
            })?);
        }
        let closed = Rc::new(Cell::new(false));
        {
            let closed = closed.clone();
            events.push(window.Closed(move |_, _| {
                if !closed.replace(true) {
                    post(UiEvent::WindowClosed);
                }
            })?);
        }

        {
            let faded = [header.brand.cast::<UIElement>()?];
            events.push(window.Activated(move |_, args| {
                let state = args
                    .ok()
                    .ok()
                    .and_then(|args| args.WindowActivationState().ok());
                let opacity = if state == Some(WindowActivationState::Deactivated) {
                    INACTIVE_OPACITY
                } else {
                    1.0
                };
                for element in &faded {
                    check(element.ui().SetOpacity(opacity), "fade the title bar");
                }
            })?);
        }

        // The capsule and the panel follow the window's size.
        {
            let place = {
                let capsule = capsule.clone();
                let (surface, host) = (panel_surface.clone(), panel_host.clone());
                let root = root.clone();
                move || {
                    check(
                        place_drawer(&capsule, &surface, &host, &root),
                        "place the message panel",
                    )
                }
            };
            let fit = {
                let place = place.clone();
                let capsule = capsule.clone();
                move || {
                    capsule.fit();
                    place();
                }
            };
            events.push(root.fe().SizeChanged(move |_, _| fit())?);
            events.push(capsule.element().SizeChanged(move |_, _| place())?);
            let (surface, host) = (panel_surface.clone(), panel_host.clone());
            capsule.on_width(move |width| {
                for element in [surface.fe(), host.fe()] {
                    check(element.SetWidth(width), "widen the message panel");
                }
            });
        }

        window.SetContent(&root)?;
        let regions = Regions::track(
            &window,
            &header.grid,
            &header.caption,
            &header.icon.cast::<FrameworkElement>()?,
            &[toolbar_panel.cast::<FrameworkElement>()?, capsule.element()],
        )?;

        let mut content_surface = Surface::new(page_host, post);
        content_surface.set_root(content);
        let mut drawer_surface = Surface::new(panel_host.clone(), post);
        drawer_surface.set_root(drawer);
        drawer_growth.reshow()?;

        // Where it was last time, or the default size where Windows puts it.
        let saved = window_state::saved(Which::Main);
        match saved {
            Some(placement) => window_state::restore(&window, placement),
            None => app_window.Resize(super::bindings::SizeInt32 {
                width: (DEFAULT_SIZE.0 * scale) as i32,
                height: (DEFAULT_SIZE.1 * scale) as i32,
            })?,
        }
        {
            // Closing by the user remembers the place too.
            let hwnd = super::hwnd::handle(&window)?;
            events.push(app_window.Closing(move |_, _| {
                window_state::remember_handle(hwnd, Which::Main);
            })?);
        }
        if let Ok(presenter) = app_window
            .Presenter()
            .and_then(|presenter| presenter.cast::<super::bindings::IOverlappedPresenter3>())
        {
            let min_width = SIDEBAR_WIDTH + PAGE_MIN_WIDTH;
            check(
                presenter.SetPreferredMinimumWidth(Some((min_width * scale) as i32)),
                "set the least width",
            );
            check(
                presenter.SetPreferredMinimumHeight(Some((MIN_HEIGHT * scale) as i32)),
                "set the least height",
            );
        }

        let this = Self {
            window,
            root,
            _regions: regions,
            nav,
            nav_items,
            panel_surface,
            panel_host,
            drawer_growth,
            drawer_open,
            capsule,
            toolbar,
            quiet,
            closed,
            content: content_surface,
            drawer: drawer_surface,
            dialog: None,
            view: view.clone(),
            post,
            _events: events,
        };
        this.select_section(view)?;
        this.capsule.update(&view.toolbar.messages)?;
        this.show_drawer(view.drawer_open)?;
        this.set_appearance(appearance)?;
        this.quiet.set(false);
        super::hwnd::set_icon(&this.window);
        this.window.Activate()?;
        if saved.is_some_and(|placement| placement.maximized) {
            check(
                app_window
                    .Presenter()
                    .and_then(|presenter| presenter.cast::<super::bindings::IOverlappedPresenter>())
                    .and_then(|presenter| presenter.Maximize()),
                "maximize the window again",
            );
        }
        Ok(this)
    }

    fn select_section(&self, view: &MainView) -> Result<()> {
        let Some((_, item)) = self
            .nav_items
            .iter()
            .find(|(section, _)| *section == view.section)
        else {
            return Ok(());
        };
        let previous = self.quiet.replace(true);
        let result = self.nav.SetSelectedItem(&item.cast::<IInspectable>()?);
        self.quiet.set(previous);
        result
    }

    pub fn update(&mut self, view: &MainView) -> Result<()> {
        if view.nav != self.view.nav {
            for ((_, entry), item) in self.nav_items.iter().zip(&view.nav) {
                entry
                    .cast::<IContentControl>()?
                    .SetContent(&xaml::boxed(&item.label)?)?;
            }
        }
        if view.section != self.view.section {
            self.select_section(view)?;
        }
        if view.toolbar != self.view.toolbar {
            self.toolbar.update(view)?;
            self.capsule.update(&view.toolbar.messages)?;
        }
        if view.drawer_open != self.view.drawer_open {
            self.show_drawer(view.drawer_open)?;
        }
        self.view = view.clone();
        Ok(())
    }

    fn show_drawer(&self, open: bool) -> Result<()> {
        if self.drawer_open.replace(open) == open {
            return Ok(());
        }
        place_drawer(
            &self.capsule,
            &self.panel_surface,
            &self.panel_host,
            &self.root,
        )?;
        self.drawer_growth.start(open, self.capsule.open_width())?;
        // The keyboard follows into the panel, so Tab reaches its controls
        // rather than the sidebar, whose focus closes it.
        if open {
            if let Ok(first) = FocusManager::FindFirstFocusableElement(&self.panel_host) {
                first
                    .cast::<IUIElement>()?
                    .Focus(FocusState::Programmatic)?;
            }
        }
        Ok(())
    }

    /// The toolbar's controls and the pages' show the interface's values
    /// again after the user moved one.
    pub fn settle(&self) {
        check(self.toolbar.update(&self.view), "settle the toolbar");
        check(
            self.capsule.update(&self.view.toolbar.messages),
            "settle the message capsule",
        );
        check(self.select_section(&self.view), "settle the sidebar");
        self.content.settle();
        self.drawer.settle();
        if let Some(dialog) = self.dialog.as_ref() {
            dialog.settle();
        }
    }

    pub fn open_dialog(&mut self, tree: &Mounted, appearance: Appearance) -> Result<()> {
        self.close_dialog();
        self.dialog = Some(Dialog::open(&self.root, tree, appearance, self.post)?);
        Ok(())
    }

    pub fn close_dialog(&mut self) {
        if let Some(dialog) = self.dialog.take() {
            dialog.close();
        }
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
            .SetPreferredTheme(bar)?;
        if let Some(dialog) = &self.dialog {
            dialog.set_appearance(appearance)?;
        }
        Ok(())
    }

    pub fn bring_to_front(&self) -> Result<()> {
        super::hwnd::restore_and_focus(&self.window)
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    /// Saves where the window is, for the next time it opens.
    pub fn remember_place(&self) {
        if !self.closed.get() {
            window_state::remember(&self.window, Which::Main);
        }
    }

    pub fn close(&self) {
        if !self.closed.replace(true) {
            window_state::remember(&self.window, Which::Main);
            check(self.window.Close(), "close the main window");
        }
    }
}
