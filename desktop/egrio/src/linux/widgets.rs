//! Realizes component trees as GTK widgets and applies the reconciler's
//! patches to them. A surface (the page, the drawer, a dialog, the editor's
//! content) owns the widgets of one tree; every realized node keeps its
//! widget, its parent and its children's ids.
//!
//! Stacks are `GtkBox`es. Each child's expansion is set explicitly: along
//! the stack's axis it takes the space left when it grows, across it never
//! expands, so a growing grandchild never makes its parent grow as GTK's
//! propagated expansion would. Changes the interface makes to a control (a
//! new selection, a switch set back) are applied quietly so they do not
//! echo back as events.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    Attrs, Axis, Badge, Button, ButtonKey, ButtonStyle, Card, CrossAlign, Fact, Facts, Fields,
    Group, Icon, Kind, Placeholder, Popover, Radio, Segmented, Select, SettingRow, Switch, Symbol,
    Text, TextField, TextStyle, Tone,
};
use egrio_ui::reconcile::{Mounted, NodeId, Patch};

use super::chart::ChartView;
use super::exact::ExactSize;
use super::style;
use super::table::TableHost;
use super::text_editor::{EditableParts, EditorParts};
use super::tiles::TilesHost;

pub type Post = fn(UiEvent);

struct Native {
    /// What the parent holds: the widget itself, or the box that gives it
    /// an exact size.
    outer: gtk::Widget,
    widget: gtk::Widget,
    exact: Option<ExactSize>,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    attrs: Attrs,
    part: Part,
}

enum Part {
    /// Children in a line: a stack, a card's inside or a split, whose
    /// first child takes the leading width.
    Line {
        line: gtk::Box,
        axis: Axis,
        align: CrossAlign,
        leading: Option<f64>,
    },
    /// Shows its one child and scrolls it vertically.
    Scroll(gtk::ScrolledWindow),
    Popover(PopoverParts),
    /// A setting group's rows.
    Group(adw::PreferencesGroup),
    /// A setting row's controls, at its end.
    Row(adw::ActionRow),
    Leaf,
    Text(gtk::Label),
    Badge(gtk::Label),
    Symbol(gtk::Image),
    Button(ButtonParts),
    Segmented(SegmentedParts),
    Switch {
        switch: gtk::Switch,
        props: Switch,
        quiet: Rc<Cell<bool>>,
    },
    Select {
        dropdown: gtk::DropDown,
        props: Select,
        quiet: Rc<Cell<bool>>,
    },
    Radio(RadioParts),
    Field(FieldParts),
    Editor(EditorParts),
    Editable(EditableParts),
    /// The facts' labels, changed in place while their shape stays.
    Facts(FactsParts),
    /// Rebuilt whole on each update: fields and placeholders.
    Composite(gtk::Box),
    Table(TableHost),
    Tiles(TilesHost),
    Chart(ChartView),
}

pub struct ButtonParts {
    pub button: gtk::Button,
    icon: gtk::Image,
    spinner: gtk::Spinner,
    label: gtk::Label,
    /// The key that presses it in a dialog.
    key: Option<ButtonKey>,
    /// The label, which names it for assistive technologies; an icon-only
    /// button takes its tooltip as its name.
    title: Option<String>,
}

pub struct SegmentedParts {
    line: gtk::Box,
    buttons: Vec<gtk::ToggleButton>,
    props: Segmented,
    quiet: Rc<Cell<bool>>,
}

pub struct RadioParts {
    check: gtk::CheckButton,
    /// A button outside the window in the radio's group: GTK draws a check
    /// button in a group as a radio, and choosing the partner unchooses it.
    partner: gtk::CheckButton,
    props: Radio,
    quiet: Rc<Cell<bool>>,
}

/// A search field's width, as the macOS search field prefers.
const SEARCH_WIDTH: i32 = 240;

/// A text field or search field, which reports every edit.
pub struct FieldParts {
    field: gtk::Editable,
    /// The text the field last reported, which the interface's value is
    /// compared with before it is written back.
    reported: Rc<RefCell<String>>,
    quiet: Rc<Cell<bool>>,
}

pub struct PopoverParts {
    button: gtk::MenuButton,
    popover: gtk::Popover,
    icon: gtk::Image,
    label: gtk::Label,
}

/// A line of facts.
pub struct FactsParts {
    line: gtk::Box,
    facts: Vec<FactView>,
}

/// A fact's widgets and what they show.
struct FactView {
    name: gtk::Label,
    value: gtk::Label,
    mark: Option<gtk::Image>,
    shown: Fact,
}

pub struct Surface {
    host: gtk::Box,
    root: Option<NodeId>,
    nodes: HashMap<NodeId, Native>,
    post: Post,
    /// Set by any change the surface's tree went through, which a dialog
    /// reads to find its default button again.
    changed: Cell<bool>,
}

/// Runs a change the interface makes, so the control's events stay silent.
pub fn quietly(quiet: &Cell<bool>, change: impl FnOnce()) {
    let previous = quiet.replace(true);
    change();
    quiet.set(previous);
}

impl Surface {
    /// A surface whose root fills `host`.
    pub fn new(host: gtk::Box, post: Post) -> Self {
        Self {
            host,
            root: None,
            nodes: HashMap::new(),
            post,
            changed: Cell::new(false),
        }
    }

    /// Realizes `root` as the whole content, replacing what was there.
    pub fn set_root(&mut self, root: &Mounted) {
        if let Some(old) = self.root.take() {
            if let Some(native) = self.nodes.get(&old) {
                self.host.remove(&native.outer);
            }
            self.forget(old);
        }
        self.build(root);
        let outer = self.nodes[&root.id].outer.clone();
        outer.set_hexpand(true);
        outer.set_vexpand(true);
        outer.set_halign(gtk::Align::Fill);
        outer.set_valign(gtk::Align::Fill);
        self.host.append(&outer);
        self.root = Some(root.id);
        self.changed.set(true);
        self.refresh_popover_defaults();
    }

    pub fn apply(&mut self, patches: Vec<Patch>) {
        for patch in patches {
            match patch {
                Patch::Update { id, attrs, kind } => self.update(id, attrs, &kind),
                Patch::Insert {
                    parent,
                    index,
                    node,
                } => {
                    self.build(&node);
                    self.insert_child(parent, index, node.id);
                }
                Patch::Remove { parent, id } => {
                    self.detach_child(parent, id);
                    self.forget(id);
                }
                Patch::Move { parent, id, index } => {
                    self.detach_child(parent, id);
                    self.insert_child(parent, index, id);
                }
                Patch::Replace { old, node } => self.replace(old, &node),
            }
        }
        self.changed.set(true);
        self.refresh_popover_defaults();
    }

    /// Whether the tree changed since the last call.
    pub fn take_changed(&self) -> bool {
        self.changed.replace(false)
    }

    /// Makes each popover's button for Return its default widget, which
    /// Return in the popover's fields presses, as a dialog's does.
    fn refresh_popover_defaults(&self) {
        for (id, native) in &self.nodes {
            if let Part::Popover(parts) = &native.part {
                let button = self.button_under(*id, ButtonKey::Return);
                parts.popover.set_default_widget(button.as_ref());
            }
        }
    }

    /// The button for `key` in the subtree of `id`.
    fn button_under(&self, id: NodeId, key: ButtonKey) -> Option<gtk::Button> {
        let native = self.nodes.get(&id)?;
        match &native.part {
            Part::Button(parts) if parts.key == Some(key) => Some(parts.button.clone()),
            _ => native
                .children
                .iter()
                .find_map(|child| self.button_under(*child, key)),
        }
    }

    /// Shows each switch, segmented control, drop-down, radio and in-place
    /// text its interface value again: after the user moved one, the
    /// interface may have refused the change.
    pub fn settle(&self) {
        for native in self.nodes.values() {
            match &native.part {
                Part::Segmented(parts) => {
                    quietly(&parts.quiet, || style_segmented(parts, &parts.props))
                }
                Part::Switch {
                    switch,
                    props,
                    quiet,
                } => quietly(quiet, || style_switch(switch, props)),
                Part::Select {
                    dropdown,
                    props,
                    quiet,
                } => quietly(quiet, || style_select(dropdown, props)),
                Part::Radio(parts) => style_radio(parts, &parts.props),
                Part::Editable(parts) => parts.settle(),
                _ => {}
            }
        }
    }

    /// The surface's text editor, if it has one.
    pub fn text_editor(&self) -> Option<gtk::TextView> {
        self.nodes.values().find_map(|native| match &native.part {
            Part::Editor(parts) => Some(parts.view()),
            _ => None,
        })
    }

    /// The button a key presses, such as a dialog's cancel button for Esc.
    pub fn button_with_key(&self, key: ButtonKey) -> Option<(NodeId, gtk::Button)> {
        self.nodes
            .iter()
            .find_map(|(id, native)| match &native.part {
                Part::Button(parts) if parts.key == Some(key) => Some((*id, parts.button.clone())),
                _ => None,
            })
    }

    fn build(&mut self, mounted: &Mounted) {
        let (widget, part) = self.realize(mounted.id, &mounted.kind);
        let mut native = Native {
            outer: widget.clone(),
            widget,
            exact: None,
            parent: None,
            children: Vec::new(),
            attrs: Attrs::default(),
            part,
        };
        if mounted.attrs.width.is_some() || mounted.attrs.height.is_some() {
            wrap(&mut native);
        }
        apply_attrs(&mut native, &mounted.attrs);
        self.nodes.insert(mounted.id, native);
        for (index, child) in mounted.children.iter().enumerate() {
            self.build(child);
            self.insert_child(mounted.id, index, child.id);
        }
    }

    fn realize(&self, id: NodeId, kind: &Kind) -> (gtk::Widget, Part) {
        let post = self.post;
        let node_event = move |event: Event| post(UiEvent::Node { id, event });
        match kind {
            Kind::Stack(stack) => {
                let line = gtk::Box::new(orientation(stack.axis), stack.spacing as i32);
                line.set_margin_start(stack.padding.horizontal as i32);
                line.set_margin_end(stack.padding.horizontal as i32);
                line.set_margin_top(stack.padding.vertical as i32);
                line.set_margin_bottom(stack.padding.vertical as i32);
                let part = Part::Line {
                    line: line.clone(),
                    axis: stack.axis,
                    align: stack.align,
                    leading: None,
                };
                (line.upcast(), part)
            }
            Kind::Card(card) => {
                let frame = gtk::Box::new(gtk::Orientation::Vertical, 0);
                frame.add_css_class("card");
                frame.set_overflow(gtk::Overflow::Hidden);
                let line = gtk::Box::new(gtk::Orientation::Vertical, 0);
                line.set_hexpand(true);
                line.set_vexpand(true);
                frame.append(&line);
                style_card(&frame, &line, card);
                let part = Part::Line {
                    line,
                    axis: Axis::Vertical,
                    align: CrossAlign::Fill,
                    leading: None,
                };
                (frame.upcast(), part)
            }
            Kind::Split(split) => {
                let line = gtk::Box::new(gtk::Orientation::Horizontal, 12);
                let part = Part::Line {
                    line: line.clone(),
                    axis: Axis::Horizontal,
                    align: CrossAlign::Fill,
                    leading: Some(split.leading),
                };
                (line.upcast(), part)
            }
            Kind::Spacer => (
                gtk::Box::new(gtk::Orientation::Horizontal, 0).upcast(),
                Part::Leaf,
            ),
            Kind::Separator => (
                gtk::Separator::new(gtk::Orientation::Horizontal).upcast(),
                Part::Leaf,
            ),
            Kind::Text(text) => {
                let label = gtk::Label::new(None);
                label.set_xalign(0.0);
                style_text(&label, text);
                style::help_when_cut(&label);
                (label.clone().upcast(), Part::Text(label))
            }
            Kind::Badge(badge) => {
                let label = badge_label(badge);
                (label.clone().upcast(), Part::Badge(label))
            }
            Kind::Symbol(symbol) => {
                let image = gtk::Image::new();
                image.set_pixel_size(16);
                style_symbol(&image, symbol);
                (image.clone().upcast(), Part::Symbol(image))
            }
            Kind::Button(button) => {
                let parts = button_parts(button);
                parts
                    .button
                    .connect_clicked(move |_| node_event(Event::Press));
                (parts.button.clone().upcast(), Part::Button(parts))
            }
            Kind::Segmented(segmented) => {
                let parts = segmented_parts(segmented, node_event);
                (parts.line.clone().upcast(), Part::Segmented(parts))
            }
            Kind::Switch(props) => {
                let switch = gtk::Switch::new();
                let quiet = Rc::new(Cell::new(false));
                quietly(&quiet, || style_switch(&switch, props));
                {
                    let quiet = quiet.clone();
                    switch.connect_active_notify(move |switch| {
                        if !quiet.get() {
                            node_event(Event::Toggle(switch.is_active()));
                        }
                    });
                }
                let part = Part::Switch {
                    switch: switch.clone(),
                    props: props.clone(),
                    quiet,
                };
                (switch.upcast(), part)
            }
            Kind::Select(props) => {
                let dropdown = dropdown(&props.options);
                let quiet = Rc::new(Cell::new(false));
                quietly(&quiet, || style_select(&dropdown, props));
                {
                    let quiet = quiet.clone();
                    dropdown.connect_selected_notify(move |dropdown| {
                        let selected = dropdown.selected();
                        if !quiet.get() && selected != gtk::INVALID_LIST_POSITION {
                            node_event(Event::Select(selected as usize));
                        }
                    });
                }
                let part = Part::Select {
                    dropdown: dropdown.clone(),
                    props: props.clone(),
                    quiet,
                };
                (dropdown.upcast(), part)
            }
            Kind::Radio(props) => {
                let check = gtk::CheckButton::new();
                let partner = gtk::CheckButton::new();
                check.set_group(Some(&partner));
                let parts = RadioParts {
                    check: check.clone(),
                    partner,
                    props: props.clone(),
                    quiet: Rc::new(Cell::new(false)),
                };
                style_radio(&parts, props);
                {
                    let quiet = parts.quiet.clone();
                    check.connect_toggled(move |check| {
                        if !quiet.get() && check.is_active() {
                            node_event(Event::Press);
                        }
                    });
                }
                (check.upcast(), Part::Radio(parts))
            }
            Kind::TextField(props) | Kind::SearchField(props) => {
                let parts = field_parts(props, matches!(kind, Kind::SearchField(_)), node_event);
                (parts.field.clone().upcast(), Part::Field(parts))
            }
            Kind::TextEditor(props) => {
                let parts = EditorParts::new(props, node_event);
                (parts.widget(), Part::Editor(parts))
            }
            Kind::EditableText(props) => {
                let parts = EditableParts::new(props, node_event);
                (parts.widget(), Part::Editable(parts))
            }
            Kind::Group(group) => {
                let view = adw::PreferencesGroup::new();
                style_group(&view, group);
                (view.clone().upcast(), Part::Group(view))
            }
            Kind::SettingRow(row) => {
                let view = adw::ActionRow::new();
                view.set_use_markup(false);
                style_setting_row(&view, row);
                (view.clone().upcast(), Part::Row(view))
            }
            Kind::Facts(facts) => {
                let line = gtk::Box::new(gtk::Orientation::Horizontal, 20);
                let mut parts = FactsParts {
                    line: line.clone(),
                    facts: Vec::new(),
                };
                parts.show(facts);
                (line.upcast(), Part::Facts(parts))
            }
            Kind::Fields(fields) => {
                let holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
                fill_fields(&holder, fields);
                (holder.clone().upcast(), Part::Composite(holder))
            }
            Kind::Placeholder(placeholder) => {
                let holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
                fill_placeholder(&holder, placeholder, node_event);
                (holder.clone().upcast(), Part::Composite(holder))
            }
            Kind::Table(table) => {
                let host = TableHost::new(id, table, post);
                (host.widget(), Part::Table(host))
            }
            Kind::Tiles(tiles) => {
                let host = TilesHost::new(id, tiles, post);
                (host.widget(), Part::Tiles(host))
            }
            Kind::Chart(chart) => {
                let view = ChartView::new(chart.clone());
                (view.widget(), Part::Chart(view))
            }
            Kind::Spinner => {
                let spinner = gtk::Spinner::new();
                spinner.set_spinning(true);
                spinner.set_size_request(16, 16);
                (spinner.upcast(), Part::Leaf)
            }
            Kind::Scroll => {
                let scroll = gtk::ScrolledWindow::new();
                scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
                // As tall as its content where nothing sizes it, as in the
                // message panel, scrolling once its container caps it.
                scroll.set_propagate_natural_height(true);
                (scroll.clone().upcast(), Part::Scroll(scroll))
            }
            Kind::Popover(props) => {
                let parts = popover_parts(props);
                (parts.button.clone().upcast(), Part::Popover(parts))
            }
        }
    }

    fn update(&mut self, id: NodeId, attrs: Attrs, kind: &Kind) {
        let post = self.post;
        let Some(native) = self.nodes.get_mut(&id) else {
            return;
        };
        let grow_changed = native.attrs.grow != attrs.grow;
        let needs_wrap =
            native.exact.is_none() && (attrs.width.is_some() || attrs.height.is_some());
        apply_attrs(native, &attrs);
        // A container whose layout changed places its children again.
        let mut relayout = false;
        match (&mut native.part, kind) {
            (
                Part::Line {
                    line, axis, align, ..
                },
                Kind::Stack(props),
            ) => {
                line.set_spacing(props.spacing as i32);
                line.set_margin_start(props.padding.horizontal as i32);
                line.set_margin_end(props.padding.horizontal as i32);
                line.set_margin_top(props.padding.vertical as i32);
                line.set_margin_bottom(props.padding.vertical as i32);
                if *axis != props.axis || *align != props.align {
                    *axis = props.axis;
                    *align = props.align;
                    line.set_orientation(orientation(props.axis));
                    relayout = true;
                }
            }
            (Part::Line { line, .. }, Kind::Card(card)) => {
                if let Ok(frame) = native.widget.clone().downcast::<gtk::Box>() {
                    style_card(&frame, line, card);
                }
            }
            (Part::Line { leading, .. }, Kind::Split(split)) => {
                relayout = *leading != Some(split.leading);
                *leading = Some(split.leading);
            }
            (Part::Group(view), Kind::Group(group)) => style_group(view, group),
            (Part::Row(view), Kind::SettingRow(row)) => style_setting_row(view, row),
            (Part::Text(label), Kind::Text(text)) => style_text(label, text),
            (Part::Badge(label), Kind::Badge(badge)) => style_badge(label, badge),
            (Part::Symbol(image), Kind::Symbol(symbol)) => style_symbol(image, symbol),
            (Part::Button(parts), Kind::Button(button)) => {
                parts.key = button.key;
                parts.title = button.label.clone();
                style_button(parts, button);
            }
            (Part::Segmented(parts), Kind::Segmented(new)) => {
                if parts.props.options != new.options {
                    let node_event = move |event: Event| post(UiEvent::Node { id, event });
                    rebuild_segments(parts, &new.options, node_event);
                }
                parts.props = new.clone();
                quietly(&parts.quiet, || style_segmented(parts, new));
            }
            (
                Part::Switch {
                    switch,
                    props,
                    quiet,
                },
                Kind::Switch(new),
            ) => {
                *props = new.clone();
                quietly(quiet, || style_switch(switch, new));
            }
            (
                Part::Select {
                    dropdown,
                    props,
                    quiet,
                },
                Kind::Select(new),
            ) => {
                if props.options != new.options {
                    quietly(quiet, || {
                        let options: Vec<&str> = new.options.iter().map(String::as_str).collect();
                        dropdown.set_model(Some(&gtk::StringList::new(&options)));
                    });
                }
                *props = new.clone();
                quietly(quiet, || style_select(dropdown, new));
            }
            (Part::Radio(parts), Kind::Radio(new)) => {
                parts.props = new.clone();
                style_radio(parts, new);
            }
            (Part::Field(parts), Kind::TextField(props) | Kind::SearchField(props)) => {
                style_field(parts, props)
            }
            (Part::Editor(parts), Kind::TextEditor(props)) => parts.update(props),
            (Part::Editable(parts), Kind::EditableText(props)) => parts.update(props),
            (Part::Facts(parts), Kind::Facts(facts)) => parts.show(facts),
            (Part::Composite(holder), Kind::Fields(fields)) => fill_fields(holder, fields),
            (Part::Composite(holder), Kind::Placeholder(placeholder)) => {
                let node_event = move |event: Event| post(UiEvent::Node { id, event });
                fill_placeholder(holder, placeholder, node_event);
            }
            (Part::Table(host), Kind::Table(table)) => host.update(table),
            (Part::Tiles(host), Kind::Tiles(tiles)) => host.update(tiles),
            (Part::Chart(view), Kind::Chart(chart)) => view.set_chart(chart.clone()),
            (Part::Popover(parts), Kind::Popover(props)) => style_popover(parts, props),
            _ => {}
        }
        name_button(&self.nodes[&id]);
        if relayout {
            self.place_children(id);
        }
        let parent = self.nodes[&id].parent;
        if needs_wrap {
            // The node gained a fixed size: it moves into a box that holds it.
            if let Some(parent) = parent {
                let index = self.index_in(parent, id);
                self.detach_child(parent, id);
                if let Some(native) = self.nodes.get_mut(&id) {
                    wrap(native);
                    let attrs = std::mem::take(&mut native.attrs);
                    apply_attrs(native, &attrs);
                }
                self.insert_child(parent, index, id);
            }
        } else if grow_changed {
            if let Some(parent) = parent {
                self.place(parent, id);
            }
        }
    }

    fn index_in(&self, parent: NodeId, child: NodeId) -> usize {
        self.nodes[&parent]
            .children
            .iter()
            .position(|id| *id == child)
            .unwrap_or(0)
    }

    fn replace(&mut self, old: NodeId, node: &Mounted) {
        match self.nodes.get(&old).and_then(|native| native.parent) {
            Some(parent) => {
                let index = self.index_in(parent, old);
                self.detach_child(parent, old);
                self.forget(old);
                self.build(node);
                self.insert_child(parent, index, node.id);
            }
            // The root changed component: realize the new root in its place.
            None => self.set_root(node),
        }
    }

    /// Puts `child` at `index` among `parent`'s children.
    fn insert_child(&mut self, parent: NodeId, index: usize, child: NodeId) {
        let Some(native) = self.nodes.get_mut(&parent) else {
            return;
        };
        let index = index.min(native.children.len());
        native.children.insert(index, child);
        // A split's leading pane takes its fixed width.
        let leading = index == 0
            && matches!(
                native.part,
                Part::Line {
                    leading: Some(_),
                    ..
                }
            );
        let Some(node) = self.nodes.get_mut(&child) else {
            return;
        };
        node.parent = Some(parent);
        if leading && node.exact.is_none() {
            wrap(node);
        }
        let outer = node.outer.clone();
        let native = &self.nodes[&parent];
        match &native.part {
            Part::Line { line, .. } => {
                let previous = index
                    .checked_sub(1)
                    .map(|previous| self.nodes[&native.children[previous]].outer.clone());
                line.insert_child_after(&outer, previous.as_ref());
            }
            Part::Scroll(scroll) => scroll.set_child(Some(&outer)),
            Part::Popover(parts) => parts.popover.set_child(Some(&outer)),
            Part::Group(_) | Part::Row(_) => self.readd_children(parent),
            _ => {}
        }
        self.place(parent, child);
    }

    fn detach_child(&mut self, parent: NodeId, child: NodeId) {
        let Some(outer) = self.nodes.get(&child).map(|native| native.outer.clone()) else {
            return;
        };
        let Some(native) = self.nodes.get_mut(&parent) else {
            return;
        };
        native.children.retain(|id| *id != child);
        match &native.part {
            Part::Line { line, .. } => line.remove(&outer),
            Part::Scroll(scroll) => scroll.set_child(None::<&gtk::Widget>),
            Part::Popover(parts) => parts.popover.set_child(None::<&gtk::Widget>),
            Part::Group(group) => group.remove(&outer),
            Part::Row(row) => row.remove(&outer),
            _ => {}
        }
    }

    /// Puts a setting group's rows or a row's controls back in order: GTK
    /// only appends to them.
    fn readd_children(&self, parent: NodeId) {
        let native = &self.nodes[&parent];
        let children: Vec<gtk::Widget> = native
            .children
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|child| child.outer.clone())
            .collect();
        match &native.part {
            Part::Group(group) => {
                for child in &children {
                    if child.parent().is_some() {
                        group.remove(child);
                    }
                }
                for child in &children {
                    group.add(child);
                }
            }
            Part::Row(row) => {
                for child in &children {
                    if child.parent().is_some() {
                        row.remove(child);
                    }
                }
                for child in &children {
                    row.add_suffix(child);
                }
                // A row with only a switch toggles it when clicked.
                let switch = match children.as_slice() {
                    [only] => only.clone().downcast::<gtk::Switch>().ok(),
                    _ => None,
                };
                row.set_activatable_widget(switch.as_ref());
            }
            _ => {}
        }
    }

    /// Places every child of a container again, after its layout changed.
    fn place_children(&self, id: NodeId) {
        for child in &self.nodes[&id].children {
            self.place(id, *child);
        }
    }

    /// Gives a child its expansion and alignment in its parent.
    fn place(&self, parent: NodeId, child: NodeId) {
        let Some(native) = self.nodes.get(&parent) else {
            return;
        };
        let Some(node) = self.nodes.get(&child) else {
            return;
        };
        let outer = &node.outer;
        let natural = keeps_natural_size(&node.part);
        match &native.part {
            Part::Line {
                axis,
                align,
                leading,
                ..
            } => {
                let first = native.children.first() == Some(&child);
                let grow = match leading {
                    Some(_) => !first,
                    None => node.attrs.grow,
                };
                if let (Some(width), true, Some(exact)) = (leading, first, &node.exact) {
                    exact.set_size(Some(*width), node.attrs.height);
                }
                let across = cross(*align, natural);
                match axis {
                    Axis::Vertical => {
                        outer.set_vexpand(grow);
                        outer.set_hexpand(false);
                        outer.set_halign(across);
                        outer.set_valign(gtk::Align::Fill);
                    }
                    Axis::Horizontal => {
                        outer.set_hexpand(grow);
                        outer.set_vexpand(false);
                        outer.set_valign(across);
                        outer.set_halign(if natural {
                            gtk::Align::Start
                        } else {
                            gtk::Align::Fill
                        });
                    }
                }
            }
            Part::Scroll(_) => {
                // Its natural height, scrolled once it is taller.
                outer.set_valign(gtk::Align::Start);
                outer.set_halign(gtk::Align::Fill);
                outer.set_vexpand(false);
                outer.set_hexpand(false);
            }
            Part::Popover(_) => {
                outer.set_margin_start(6);
                outer.set_margin_end(6);
                outer.set_margin_top(6);
                outer.set_margin_bottom(6);
            }
            Part::Row(_) => {
                outer.set_valign(gtk::Align::Center);
                outer.set_vexpand(false);
                outer.set_hexpand(false);
            }
            _ => {}
        }
    }

    /// Forgets a node and everything under it.
    fn forget(&mut self, id: NodeId) {
        if let Some(native) = self.nodes.remove(&id) {
            for child in native.children {
                self.forget(child);
            }
        }
    }
}

/// Moves a node's widget into a box that gives it an exact size; the box
/// becomes what its parent holds.
fn wrap(native: &mut Native) {
    let exact = ExactSize::new(&native.widget);
    native.outer = exact.clone().upcast();
    native.exact = Some(exact);
}

/// Controls GTK draws stretched when they get more room than they need,
/// which keep their own size across a stack instead.
fn keeps_natural_size(part: &Part) -> bool {
    matches!(
        part,
        Part::Switch { .. } | Part::Badge(_) | Part::Radio(_) | Part::Symbol(_)
    )
}

fn orientation(axis: Axis) -> gtk::Orientation {
    match axis {
        Axis::Vertical => gtk::Orientation::Vertical,
        Axis::Horizontal => gtk::Orientation::Horizontal,
    }
}

fn cross(align: CrossAlign, natural: bool) -> gtk::Align {
    match align {
        CrossAlign::Start => gtk::Align::Start,
        CrossAlign::Center => gtk::Align::Center,
        CrossAlign::End => gtk::Align::End,
        CrossAlign::Fill if natural => gtk::Align::Start,
        CrossAlign::Fill => gtk::Align::Fill,
    }
}

fn apply_attrs(native: &mut Native, attrs: &Attrs) {
    if let Some(exact) = &native.exact {
        exact.set_size(attrs.width, attrs.height);
    }
    if native.attrs.tooltip != attrs.tooltip {
        native.widget.set_tooltip_text(attrs.tooltip.as_deref());
        // Without help of its own, a text's help is its whole text while cut.
        if attrs.tooltip.is_none() && matches!(native.part, Part::Text(_)) {
            native.widget.set_has_tooltip(true);
        }
    }
    native.attrs = attrs.clone();
}

/// A button without text takes its tooltip as its name ("GtkAccessible":
/// the label property).
fn name_button(native: &Native) {
    let Part::Button(parts) = &native.part else {
        return;
    };
    if parts.title.is_none() {
        if let Some(name) = native.attrs.tooltip.as_deref() {
            parts
                .button
                .update_property(&[gtk::accessible::Property::Label(name)]);
        }
    }
}

fn style_card(frame: &gtk::Box, line: &gtk::Box, card: &Card) {
    let padding = card.padding as i32;
    line.set_spacing(card.spacing as i32);
    line.set_margin_start(padding);
    line.set_margin_end(padding);
    line.set_margin_top(padding);
    line.set_margin_bottom(padding);
    if card.selected {
        frame.add_css_class("egrio-selected");
    } else {
        frame.remove_css_class("egrio-selected");
    }
}

pub fn style_text(label: &gtk::Label, text: &Text) {
    if label.text() != text.text {
        label.set_text(&text.text);
    }
    style::set_text_style(label, text.style, text.tone);
    if text.single_line {
        label.set_wrap(false);
        label.set_single_line_mode(true);
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    } else {
        label.set_single_line_mode(false);
        label.set_ellipsize(gtk::pango::EllipsizeMode::None);
        label.set_wrap(true);
        label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    }
    label.set_selectable(text.selectable);
}

/// A badge: short text on a tinted rounded surface of its tone.
pub fn badge_label(badge: &Badge) -> gtk::Label {
    let label = gtk::Label::new(None);
    label.add_css_class("egrio-badge");
    label.set_valign(gtk::Align::Center);
    style_badge(&label, badge);
    label
}

pub fn style_badge(label: &gtk::Label, badge: &Badge) {
    label.set_text(&badge.text);
    style::set_tone(label, badge.tone);
}

fn style_symbol(image: &gtk::Image, symbol: &Symbol) {
    image.set_icon_name(Some(style::icon_name(symbol.icon)));
    style::set_tone(image, symbol.tone);
}

fn button_parts(props: &Button) -> ButtonParts {
    let button = gtk::Button::new();
    let content = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let icon = gtk::Image::new();
    let label = gtk::Label::new(None);
    content.append(&icon);
    content.append(&label);
    // A busy button keeps its size: the spinner turns over its icon, or over
    // its label when it has none, which stays laid out, drawn clear. The
    // overlay is as wide as the content, so its start is the icon's.
    let spinner = gtk::Spinner::new();
    spinner.set_valign(gtk::Align::Center);
    let holder = gtk::Overlay::new();
    holder.set_halign(gtk::Align::Center);
    holder.set_child(Some(&content));
    holder.add_overlay(&spinner);
    button.set_child(Some(&holder));
    let parts = ButtonParts {
        button,
        icon,
        spinner,
        label,
        key: props.key,
        title: props.label.clone(),
    };
    style_button(&parts, props);
    parts
}

fn style_button(parts: &ButtonParts, props: &Button) {
    style::set_button_style(&parts.button, props.style);
    let busy = props.busy;
    parts.button.set_sensitive(props.enabled && !busy);
    parts.icon.set_visible(props.icon.is_some());
    if let Some(icon) = props.icon {
        parts.icon.set_icon_name(Some(style::icon_name(icon)));
        style::set_tone(&parts.icon, props.tone);
    }
    parts.label.set_visible(props.label.is_some());
    parts.label.set_text(props.label.as_deref().unwrap_or(""));
    // The spinner takes the icon's place, or the label's without an icon.
    let covered: gtk::Widget = if props.icon.is_some() {
        parts.icon.clone().upcast()
    } else {
        parts.label.clone().upcast()
    };
    parts.icon.set_opacity(1.0);
    parts.label.set_opacity(1.0);
    covered.set_opacity(if busy { 0.0 } else { 1.0 });
    parts.spinner.set_halign(if props.icon.is_some() {
        gtk::Align::Start
    } else {
        gtk::Align::Center
    });
    parts.spinner.set_visible(busy);
    parts.spinner.set_spinning(busy);
    for (class, wanted) in [
        ("image-button", props.label.is_none()),
        ("text-button", props.label.is_some() && props.icon.is_none()),
        (
            "image-text-button",
            props.label.is_some() && props.icon.is_some(),
        ),
    ] {
        if wanted {
            parts.button.add_css_class(class);
        } else {
            parts.button.remove_css_class(class);
        }
    }
}

fn segmented_parts(
    props: &Segmented,
    node_event: impl Fn(Event) + Clone + 'static,
) -> SegmentedParts {
    let line = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    line.add_css_class("linked");
    let mut parts = SegmentedParts {
        line,
        buttons: Vec::new(),
        props: props.clone(),
        quiet: Rc::new(Cell::new(false)),
    };
    rebuild_segments(&mut parts, &props.options, node_event);
    quietly(&parts.quiet.clone(), || style_segmented(&parts, props));
    parts
}

/// One toggle button per option, grouped so one is chosen at a time.
fn rebuild_segments(
    parts: &mut SegmentedParts,
    options: &[String],
    node_event: impl Fn(Event) + Clone + 'static,
) {
    quietly(&parts.quiet.clone(), || {
        for button in parts.buttons.drain(..) {
            parts.line.remove(&button);
        }
        for (index, option) in options.iter().enumerate() {
            let button = gtk::ToggleButton::with_label(option);
            if let Some(first) = parts.buttons.first() {
                button.set_group(Some(first));
            }
            let quiet = parts.quiet.clone();
            let node_event = node_event.clone();
            button.connect_toggled(move |button| {
                if !quiet.get() && button.is_active() {
                    node_event(Event::Select(index));
                }
            });
            parts.line.append(&button);
            parts.buttons.push(button);
        }
    });
}

fn style_segmented(parts: &SegmentedParts, props: &Segmented) {
    parts.line.set_sensitive(props.enabled);
    match props.selected.and_then(|index| parts.buttons.get(index)) {
        Some(button) => button.set_active(true),
        None => {
            for button in &parts.buttons {
                button.set_active(false);
            }
        }
    }
}

fn style_switch(switch: &gtk::Switch, props: &Switch) {
    switch.set_sensitive(props.enabled);
    if switch.is_active() != props.on {
        switch.set_active(props.on);
    }
}

/// A drop-down whose button cuts a long choice with an ellipsis, so the
/// width the interface gives it holds; the list shows the whole options.
fn dropdown(options: &[String]) -> gtk::DropDown {
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    let dropdown = gtk::DropDown::new(
        Some(gtk::StringList::new(&options)),
        None::<gtk::Expression>,
    );
    dropdown.set_factory(Some(&string_factory(true)));
    dropdown.set_list_factory(Some(&string_factory(false)));
    dropdown
}

fn string_factory(ellipsize: bool) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(move |_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let label = gtk::Label::new(None);
        label.set_xalign(0.0);
        if ellipsize {
            label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        }
        item.set_child(Some(&label));
    });
    factory.connect_bind(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let text = item
            .item()
            .and_then(|object| object.downcast::<gtk::StringObject>().ok())
            .map(|object| object.string());
        if let (Some(label), Some(text)) = (
            item.child()
                .and_then(|child| child.downcast::<gtk::Label>().ok()),
            text,
        ) {
            label.set_text(&text);
        }
    });
    factory
}

fn style_select(dropdown: &gtk::DropDown, props: &Select) {
    dropdown.set_sensitive(props.enabled);
    let wanted = props
        .selected
        .filter(|index| *index < props.options.len())
        .map_or(gtk::INVALID_LIST_POSITION, |index| index as u32);
    if dropdown.selected() != wanted {
        dropdown.set_selected(wanted);
    }
}

fn style_radio(parts: &RadioParts, props: &Radio) {
    parts.check.set_sensitive(props.enabled);
    quietly(&parts.quiet, || {
        if props.selected {
            parts.check.set_active(true);
        } else {
            parts.partner.set_active(true);
        }
    });
}

fn field_parts(
    props: &TextField,
    search: bool,
    node_event: impl Fn(Event) + 'static,
) -> FieldParts {
    let field: gtk::Editable = if search {
        let entry = gtk::SearchEntry::new();
        // One width, so typing never moves what sits beside it.
        entry.set_width_request(SEARCH_WIDTH);
        entry.upcast()
    } else {
        gtk::Entry::new().upcast()
    };
    // Return in a dialog's field presses its default button.
    set_if_present(&field, "activates-default", true);
    let parts = FieldParts {
        field: field.clone(),
        reported: Rc::new(RefCell::new(props.value.clone())),
        quiet: Rc::new(Cell::new(false)),
    };
    quietly(&parts.quiet, || field.set_text(&props.value));
    style_field(&parts, props);
    {
        let reported = parts.reported.clone();
        let quiet = parts.quiet.clone();
        field.connect_changed(move |field| {
            if quiet.get() {
                return;
            }
            let text = field.text().to_string();
            *reported.borrow_mut() = text.clone();
            node_event(Event::Changed(text));
        });
    }
    parts
}

/// Sets a property that only some of a control's kinds have.
fn set_if_present(object: &impl IsA<glib::Object>, name: &str, value: impl Into<glib::Value>) {
    if object.find_property(name).is_some() {
        object.set_property_from_value(name, &value.into());
    }
}

/// Writes the interface's text into the field only when it differs from
/// what the field last reported, so typing and an input method's
/// composition are never interrupted.
fn style_field(parts: &FieldParts, props: &TextField) {
    set_if_present(&parts.field, "placeholder-text", props.placeholder.as_str());
    parts.field.set_sensitive(props.enabled);
    if *parts.reported.borrow() != props.value {
        *parts.reported.borrow_mut() = props.value.clone();
        quietly(&parts.quiet, || parts.field.set_text(&props.value));
    }
}

/// libadwaita reads a group's title and description as Pango markup.
fn style_group(view: &adw::PreferencesGroup, group: &Group) {
    view.set_title(&glib::markup_escape_text(&group.title));
    view.set_description(
        group
            .note
            .as_deref()
            .map(glib::markup_escape_text)
            .as_deref(),
    );
}

fn style_setting_row(view: &adw::ActionRow, row: &SettingRow) {
    view.set_title(&row.label);
    view.set_subtitle(row.description.as_deref().unwrap_or(""));
}

fn popover_parts(props: &Popover) -> PopoverParts {
    let button = gtk::MenuButton::new();
    // A plain button, as a toolbar's are, until hovered.
    button.set_has_frame(false);
    let content = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let icon = gtk::Image::new();
    let label = gtk::Label::new(None);
    content.append(&icon);
    content.append(&label);
    button.set_child(Some(&content));
    let popover = gtk::Popover::new();
    button.set_popover(Some(&popover));
    let parts = PopoverParts {
        button,
        popover,
        icon,
        label,
    };
    style_popover(&parts, props);
    parts
}

fn style_popover(parts: &PopoverParts, props: &Popover) {
    // A popover whose button turns off closes, rather than staying open
    // with its content dimmed.
    if !props.enabled {
        parts.popover.popdown();
    }
    parts.button.set_sensitive(props.enabled);
    parts.label.set_text(&props.label);
    parts.icon.set_visible(props.icon.is_some());
    if let Some(icon) = props.icon {
        parts.icon.set_icon_name(Some(style::icon_name(icon)));
    }
}

fn clear(holder: &gtk::Box) {
    while let Some(child) = holder.first_child() {
        holder.remove(&child);
    }
}

impl FactsParts {
    /// Shows `facts`, in place while they keep their shape (how many, which
    /// are monospaced, which carry a warning), so a value that changes every
    /// second moves nothing else and a warning's help stays open.
    fn show(&mut self, facts: &Facts) {
        let same_shape = self.facts.len() == facts.items.len()
            && self.facts.iter().zip(&facts.items).all(|(view, fact)| {
                view.shown.mono == fact.mono
                    && view.shown.warning.is_some() == fact.warning.is_some()
            });
        if same_shape {
            for (view, fact) in self.facts.iter_mut().zip(&facts.items) {
                view.show(fact);
            }
            return;
        }
        clear(&self.line);
        self.facts = facts
            .items
            .iter()
            .map(|fact| FactView::new(&self.line, fact))
            .collect();
    }
}

impl FactView {
    /// The fact's label, its value with figures of equal width, and when the
    /// value needs attention a warning mark explaining why, at the end of
    /// `line`.
    fn new(line: &gtk::Box, fact: &Fact) -> Self {
        let pair = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let name = style::label(&fact.label, TextStyle::Caption, Tone::Muted);
        pair.append(&name);
        let value = style::label(
            &fact.value,
            if fact.mono {
                TextStyle::Mono
            } else {
                TextStyle::Body
            },
            Tone::Default,
        );
        if !fact.mono {
            value.add_css_class("numeric");
        }
        value.set_selectable(fact.mono);
        pair.append(&value);
        let mark = fact.warning.as_ref().map(|warning| {
            let mark = style::image(Icon::Warning, Tone::Warning, 14);
            mark.set_tooltip_text(Some(warning));
            pair.append(&mark);
            mark
        });
        line.append(&pair);
        Self {
            name,
            value,
            mark,
            shown: fact.clone(),
        }
    }

    /// Shows `fact`, of this fact's shape, touching only what changed.
    fn show(&mut self, fact: &Fact) {
        if fact.label != self.shown.label {
            self.name.set_text(&fact.label);
        }
        if fact.value != self.shown.value {
            self.value.set_text(&fact.value);
        }
        if let (Some(mark), Some(warning)) = (&self.mark, &fact.warning) {
            if fact.warning != self.shown.warning {
                mark.set_tooltip_text(Some(warning));
            }
        }
        self.shown = fact.clone();
    }
}

/// Labelled values in a grid, each label above its value; a wide field
/// takes a row of its own and wraps.
fn fill_fields(holder: &gtk::Box, fields: &Fields) {
    clear(holder);
    let grid = gtk::Grid::new();
    grid.set_column_spacing(16);
    grid.set_row_spacing(12);
    grid.set_column_homogeneous(true);
    let columns = fields.columns.max(1) as i32;
    let (mut row, mut column) = (0, 0);
    for field in &fields.items {
        if field.wide && column > 0 {
            row += 1;
            column = 0;
        }
        let cell = gtk::Box::new(gtk::Orientation::Vertical, 2);
        cell.set_hexpand(true);
        cell.append(&style::label(&field.label, TextStyle::Caption, Tone::Muted));
        for value in &field.values {
            let text = style::label(
                value,
                if field.mono {
                    TextStyle::Mono
                } else {
                    TextStyle::Body
                },
                Tone::Default,
            );
            if !field.mono {
                text.add_css_class("numeric");
            }
            text.set_selectable(true);
            if field.wide {
                text.set_single_line_mode(false);
                text.set_ellipsize(gtk::pango::EllipsizeMode::None);
                text.set_wrap(true);
                text.set_wrap_mode(gtk::pango::WrapMode::WordChar);
            }
            cell.append(&text);
        }
        let span = if field.wide { columns } else { 1 };
        grid.attach(&cell, column, row, span, 1);
        column += span;
        if column >= columns {
            row += 1;
            column = 0;
        }
    }
    holder.append(&grid);
}

/// A placeholder's text centered in its space, with its action under it.
fn fill_placeholder(
    holder: &gtk::Box,
    placeholder: &Placeholder,
    node_event: impl Fn(Event) + 'static,
) {
    clear(holder);
    let center = gtk::Box::new(gtk::Orientation::Vertical, 6);
    center.set_halign(gtk::Align::Center);
    center.set_valign(gtk::Align::Center);
    center.set_vexpand(true);
    let wrapping = |text: &str, style: TextStyle, tone: Tone| {
        let label = style::label(text, style, tone);
        label.set_single_line_mode(false);
        label.set_ellipsize(gtk::pango::EllipsizeMode::None);
        label.set_wrap(true);
        label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        label.set_justify(gtk::Justification::Center);
        label.set_xalign(0.5);
        label
    };
    center.append(&wrapping(&placeholder.title, TextStyle::Body, Tone::Muted));
    if let Some(detail) = &placeholder.detail {
        center.append(&wrapping(detail, TextStyle::Caption, Tone::Faint));
    }
    if let Some(action) = &placeholder.action {
        let parts = button_parts(&Button {
            label: Some(action.label.clone()),
            icon: action.icon,
            tone: Tone::Default,
            style: ButtonStyle::Primary,
            key: None,
            enabled: true,
            busy: false,
            on_press: None,
        });
        parts.button.set_halign(gtk::Align::Center);
        parts.button.set_margin_top(8);
        parts.button.add_css_class("pill");
        parts
            .button
            .connect_clicked(move |_| node_event(Event::Press));
        center.append(&parts.button);
    }
    holder.append(&center);
}
