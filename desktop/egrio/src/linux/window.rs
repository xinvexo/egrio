//! The main window's shell: an `AdwApplicationWindow` holding an
//! `AdwNavigationSplitView`, whose sidebar and page each have a header bar
//! of their own ("AdwNavigationSplitView" in the libadwaita documentation).
//! GTK places the window buttons by the desktop's `gtk-decoration-layout`
//! and libadwaita draws the corners and the shadow. The sidebar lists the
//! sections at one fixed width. The page's header bar carries the message
//! capsule at its start, in line with the page, and the capture switches
//! and the traffic mode at its end; there is no page title, the sidebar's
//! selection names the page.
//!
//! The message panel is the capsule's surface grown out of it over the
//! page, in a `GtkOverlay` over the page's header bar and the page
//! (`messages.rs`): as wide as the open capsule, as tall as its messages up
//! to a cap, without moving the page. A click in the sidebar or the page
//! outside it closes it and still acts on what it lands on, and Esc closes
//! it unless a control takes the key. The overlay split view libadwaita
//! offers for a side pane would not do: its shield takes the click that
//! closes it (`adw-overlay-split-view.c`).

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, glib, graphene};

use egrio_ui::backend::{
    CaptureToggle, MainView, PolicyControl, ToggleState, ToolbarAction, UiEvent, PAGE_MIN_WIDTH,
};
use egrio_ui::node::{Icon, TextStyle, Tone};
use egrio_ui::reconcile::Mounted;
use egrio_ui::state::Section;

use super::dialog::Dialog;
use super::messages::Capsule;
use super::style;
use super::widgets::{quietly, Post, Surface};
use super::window_state::{self, WindowSize};

/// The window's first size and the least height, in logical pixels; the
/// least width is the sidebar beside the page's least width.
const DEFAULT_SIZE: (i32, i32) = (1120, 720);
const MIN_HEIGHT: i32 = 640;
/// The sidebar's one width; the page takes the rest of the window.
const SIDEBAR_WIDTH: f64 = 180.0;
/// The page's distance from its pane's edges.
const PAGE_INSET: i32 = 12;
const APP_NAME: &str = "Egrio";

struct Toggle {
    button: gtk::ToggleButton,
    dot: gtk::Box,
    label: gtk::Label,
}

struct Toolbar {
    system_proxy: Toggle,
    tun: Toggle,
    policy: gtk::Box,
    modes: Vec<gtk::ToggleButton>,
    quiet: Rc<Cell<bool>>,
}

pub struct MainWindow {
    window: adw::ApplicationWindow,
    page: adw::NavigationPage,
    capsule: Capsule,
    sidebar: gtk::ListBox,
    rows: Vec<(Section, gtk::ListBoxRow, gtk::Label)>,
    page_host: gtk::Box,
    drawer_open: Rc<Cell<bool>>,
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
}

fn toggle(post: Post, action: ToolbarAction) -> Toggle {
    let button = gtk::ToggleButton::new();
    let content = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    dot.add_css_class("egrio-dot");
    dot.set_valign(gtk::Align::Center);
    let label = gtk::Label::new(None);
    content.append(&dot);
    content.append(&label);
    button.set_child(Some(&content));
    // A click asks; the interface decides what the button shows.
    button.connect_clicked(move |_| post(UiEvent::Toolbar(action.clone())));
    Toggle { button, dot, label }
}

fn style_toggle(toggle: &Toggle, view: &CaptureToggle) {
    toggle.label.set_text(&view.label);
    let tone = match (view.state, view.on) {
        (ToggleState::Pending | ToggleState::Warning, _) => Tone::Warning,
        (ToggleState::Idle, true) => Tone::Success,
        (ToggleState::Idle, false) => Tone::Default,
    };
    style::set_tone(&toggle.dot, tone);
    if toggle.button.is_active() != view.on {
        toggle.button.set_active(view.on);
    }
    toggle.button.set_sensitive(view.enabled);
    toggle.button.set_tooltip_text(view.tooltip.as_deref());
}

impl Toolbar {
    fn new(view: &MainView, post: Post) -> (Self, gtk::Box) {
        let bar = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let system_proxy = toggle(post, ToolbarAction::ToggleSystemProxy);
        let tun = toggle(post, ToolbarAction::ToggleTun);
        let quiet = Rc::new(Cell::new(true));
        let policy = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        policy.add_css_class("linked");
        let mut modes: Vec<gtk::ToggleButton> = Vec::new();
        for (index, label) in view.toolbar.policy.labels.iter().enumerate() {
            let mode = gtk::ToggleButton::with_label(label);
            if let Some(first) = modes.first() {
                mode.set_group(Some(first));
            }
            let quiet = quiet.clone();
            mode.connect_toggled(move |mode| {
                if !quiet.get() && mode.is_active() {
                    post(UiEvent::Toolbar(ToolbarAction::Policy(index)));
                }
            });
            policy.append(&mode);
            modes.push(mode);
        }
        // The traffic mode first, then the capture switches.
        bar.append(&policy);
        bar.append(&system_proxy.button);
        bar.append(&tun.button);
        let toolbar = Self {
            system_proxy,
            tun,
            policy,
            modes,
            quiet,
        };
        toolbar.update(view);
        toolbar.quiet.set(false);
        (toolbar, bar)
    }

    fn update(&self, view: &MainView) {
        match &view.toolbar.system_proxy {
            Some(toggle) => {
                self.system_proxy.button.set_visible(true);
                style_toggle(&self.system_proxy, toggle);
            }
            None => self.system_proxy.button.set_visible(false),
        }
        style_toggle(&self.tun, &view.toolbar.tun);
        self.style_policy(&view.toolbar.policy);
    }

    fn style_policy(&self, policy: &PolicyControl) {
        quietly(&self.quiet, || {
            for (mode, label) in self.modes.iter().zip(&policy.labels) {
                if mode.label().as_deref() != Some(label.as_str()) {
                    mode.set_label(label);
                }
            }
            match policy.selected.and_then(|index| self.modes.get(index)) {
                Some(mode) => mode.set_active(true),
                None => {
                    for mode in &self.modes {
                        mode.set_active(false);
                    }
                }
            }
        });
        self.policy.set_sensitive(policy.enabled);
        self.policy.set_tooltip_text(policy.tooltip.as_deref());
    }
}

fn nav_row(icon: Icon, label: &str) -> (gtk::ListBoxRow, gtk::Label) {
    let line = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    line.append(&style::image(icon, Tone::Default, 16));
    let label = style::label(label, TextStyle::Body, Tone::Default);
    line.append(&label);
    let row = gtk::ListBoxRow::new();
    row.set_child(Some(&line));
    (row, label)
}

/// Saves the window's size, and whether it is maximized, for its next opening.
fn remember_size(window: &adw::ApplicationWindow) {
    let (width, height) = window.default_size();
    window_state::save_main(WindowSize {
        width,
        height,
        maximized: window.is_maximized(),
    });
}

impl MainWindow {
    pub fn open(
        app: &adw::Application,
        view: &MainView,
        content: &Mounted,
        drawer: &Mounted,
        post: Post,
    ) -> Self {
        let window = adw::ApplicationWindow::new(app);
        window.set_widget_name("egrio-main");
        window.set_title(Some(APP_NAME));
        window.set_size_request(SIDEBAR_WIDTH as i32 + PAGE_MIN_WIDTH as i32, MIN_HEIGHT);
        let size = window_state::main().unwrap_or(WindowSize {
            width: DEFAULT_SIZE.0,
            height: DEFAULT_SIZE.1,
            maximized: false,
        });
        window.set_default_size(size.width, size.height);
        if size.maximized {
            window.maximize();
        }
        let quiet = Rc::new(Cell::new(true));

        let sidebar = gtk::ListBox::new();
        sidebar.add_css_class("navigation-sidebar");
        let mut rows = Vec::new();
        for item in &view.nav {
            let (row, label) = nav_row(item.icon, &item.label);
            sidebar.append(&row);
            rows.push((item.section, row, label));
        }
        {
            let quiet = quiet.clone();
            let sections: Vec<(Section, gtk::ListBoxRow)> = rows
                .iter()
                .map(|(section, row, _)| (*section, row.clone()))
                .collect();
            sidebar.connect_row_selected(move |_, selected| {
                if quiet.get() {
                    return;
                }
                if let Some((section, _)) =
                    selected.and_then(|selected| sections.iter().find(|(_, row)| row == selected))
                {
                    post(UiEvent::Navigate(*section));
                }
            });
        }
        let sidebar_scroll = gtk::ScrolledWindow::new();
        sidebar_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        sidebar_scroll.set_child(Some(&sidebar));
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.set_title_widget(Some(&adw::WindowTitle::new(APP_NAME, "")));
        let sidebar_view = adw::ToolbarView::new();
        sidebar_view.add_top_bar(&sidebar_header);
        sidebar_view.set_content(Some(&sidebar_scroll));
        let sidebar_page = adw::NavigationPage::new(&sidebar_view, APP_NAME);

        // No page title: the sidebar's selection names the page. The capsule
        // floats over the header bar where an empty mark starts it, in line
        // with the page, so its width moves nothing, and its surface, the
        // message panel, under it over the bar and the page.
        let start = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        start.set_margin_start(PAGE_INSET / 2);
        let header = adw::HeaderBar::new();
        header.set_show_title(false);
        header.pack_start(&start);
        let (toolbar, bar) = Toolbar::new(view, post);
        header.pack_end(&bar);

        let page_host = gtk::Box::new(gtk::Orientation::Vertical, 0);
        page_host.set_margin_start(PAGE_INSET);
        page_host.set_margin_end(PAGE_INSET);
        page_host.set_margin_top(PAGE_INSET);
        page_host.set_margin_bottom(PAGE_INSET);
        let page_view = adw::ToolbarView::new();
        page_view.add_top_bar(&header);
        page_view.set_content(Some(&page_host));
        let frame = gtk::Overlay::new();
        frame.set_widget_name("egrio-page");
        frame.set_child(Some(&page_view));
        let capsule = Capsule::new(
            &frame,
            start.upcast_ref(),
            bar.upcast_ref(),
            header.upcast_ref(),
            post,
        );
        capsule.update(&view.toolbar.messages);
        let page = adw::NavigationPage::new(&frame, &view.title);

        let split = adw::NavigationSplitView::new();
        split.set_min_sidebar_width(SIDEBAR_WIDTH);
        split.set_max_sidebar_width(SIDEBAR_WIDTH);
        split.set_sidebar(Some(&sidebar_page));
        split.set_content(Some(&page));
        window.set_content(Some(&split));

        let drawer_open = Rc::new(Cell::new(false));
        // A press in the sidebar, or in the page outside the panel, closes
        // the panel before it reaches what it lands on, which it still does;
        // the header bar's controls, the capsule among them, leave it to
        // themselves.
        {
            let click = gtk::GestureClick::new();
            click.set_button(0);
            click.set_propagation_phase(gtk::PropagationPhase::Capture);
            let drawer_open = drawer_open.clone();
            let (panel, header) = (capsule.panel().clone(), header.clone());
            click.connect_pressed(move |gesture, _, x, y| {
                let Some(area) = gesture.widget() else {
                    return;
                };
                let point = graphene::Point::new(x as f32, y as f32);
                let inside = |widget: &gtk::Widget| {
                    widget
                        .compute_bounds(&area)
                        .is_some_and(|bounds| bounds.contains_point(&point))
                };
                if drawer_open.get() && !inside(panel.upcast_ref()) && !inside(header.upcast_ref())
                {
                    post(UiEvent::CloseDrawer);
                }
            });
            frame.add_controller(click);
        }
        {
            let click = gtk::GestureClick::new();
            click.set_button(0);
            click.set_propagation_phase(gtk::PropagationPhase::Capture);
            let drawer_open = drawer_open.clone();
            click.connect_pressed(move |_, _, _, _| {
                if drawer_open.get() {
                    post(UiEvent::CloseDrawer);
                }
            });
            sidebar.add_controller(click);
        }
        {
            let keys = gtk::EventControllerKey::new();
            let drawer_open = drawer_open.clone();
            keys.connect_key_pressed(move |_, key, _, _| {
                if drawer_open.get() && key == gdk::Key::Escape {
                    post(UiEvent::CloseDrawer);
                    return glib::Propagation::Stop;
                }
                glib::Propagation::Proceed
            });
            window.add_controller(keys);
        }
        let closed = Rc::new(Cell::new(false));
        {
            let closed = closed.clone();
            window.connect_close_request(move |window| {
                remember_size(window);
                if !closed.replace(true) {
                    post(UiEvent::WindowClosed);
                }
                glib::Propagation::Proceed
            });
        }

        let mut content_surface = Surface::new(page_host.clone(), post);
        content_surface.set_root(content);
        let mut drawer_surface = Surface::new(capsule.host().clone(), post);
        drawer_surface.set_root(drawer);
        drawer_open.set(view.drawer_open);
        let this = Self {
            window,
            page,
            capsule,
            sidebar,
            rows,
            page_host,
            drawer_open,
            toolbar,
            quiet,
            closed,
            content: content_surface,
            drawer: drawer_surface,
            dialog: None,
            view: view.clone(),
            post,
        };
        this.select_section(view.section);
        this.quiet.set(false);
        this
    }

    fn select_section(&self, section: Section) {
        if let Some((_, row, _)) = self
            .rows
            .iter()
            .find(|(candidate, _, _)| *candidate == section)
        {
            quietly(&self.quiet, || self.sidebar.select_row(Some(row)));
        }
    }

    pub fn update(&mut self, view: &MainView) {
        if view.title != self.view.title {
            self.page.set_title(&view.title);
        }
        if view.toolbar.messages != self.view.toolbar.messages {
            self.capsule.update(&view.toolbar.messages);
        }
        if view.nav != self.view.nav {
            for ((_, _, label), item) in self.rows.iter().zip(&view.nav) {
                label.set_text(&item.label);
            }
        }
        if view.section != self.view.section {
            self.select_section(view.section);
        }
        if view.toolbar != self.view.toolbar {
            self.toolbar.update(view);
        }
        if view.drawer_open != self.view.drawer_open {
            self.show_drawer(view.drawer_open);
        }
        self.view = view.clone();
    }

    /// Notes the panel opening or closing; the capsule grows it out of
    /// itself or back.
    fn show_drawer(&self, open: bool) {
        self.drawer_open.set(open);
        // The page's controls give up the keyboard to the capsule.
        let focus_in_page = gtk::prelude::GtkWindowExt::focus(&self.window)
            .is_some_and(|focus| focus.is_ancestor(&self.page_host));
        if open && focus_in_page {
            self.capsule.button().grab_focus();
        }
    }

    /// The toolbar's controls and the pages' show the interface's values
    /// again after the user moved one.
    pub fn settle(&self) {
        self.toolbar.update(&self.view);
        self.select_section(self.view.section);
        self.content.settle();
        self.drawer.settle();
        if let Some(dialog) = self.dialog.as_ref() {
            dialog.settle();
        }
    }

    pub fn open_dialog(&mut self, tree: &Mounted) {
        self.close_dialog();
        self.dialog = Some(Dialog::open(&self.window, tree, self.post));
    }

    pub fn close_dialog(&mut self) {
        if let Some(dialog) = self.dialog.take() {
            dialog.close();
        }
    }

    pub fn present(&self, token: Option<&str>) {
        if let Some(token) = token {
            self.window.set_startup_id(token);
        }
        self.window.present();
    }

    pub fn window(&self) -> &adw::ApplicationWindow {
        &self.window
    }

    /// Saves the window's size for its next opening, as closing it does.
    pub fn remember(&self) {
        if !self.closed.get() {
            remember_size(&self.window);
        }
    }

    pub fn close(&self) {
        if !self.closed.replace(true) {
            self.window.close();
        }
    }
}
