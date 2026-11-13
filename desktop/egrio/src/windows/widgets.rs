//! Realizes component trees as WinUI elements and applies the reconciler's
//! patches to them. A surface (the page, the drawer, a dialog, the editor's
//! content) owns the elements of one tree; every realized node keeps its
//! element, its children's ids and the event registrations its controls need.
//!
//! Stacks are `Grid`s with one track per child: a child that grows gets a
//! star track and takes what the others leave, the rest size to their
//! content. Changes the interface makes to a control (a new selection, a
//! switch set back) are applied quietly so they do not echo back as events.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use windows_core::{EventRevoker, IInspectable, Interface, Result};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    Attrs, Axis, Badge, Button, ButtonKey, Card, CrossAlign, Fact, Facts, Field, Fields, Group,
    Kind, Placeholder, Radio, Segmented, Select, SettingRow, Switch, Symbol, Text, TextField,
    TextStyle, Tone,
};
use egrio_ui::reconcile::{Mounted, NodeId, Patch};

use super::bindings::{
    AutomationProperties, Border, ColumnDefinition, ComboBox, FontIcon, FrameworkElement, Grid,
    HorizontalAlignment, IButtonBase, IContentControl, IControl, IPanel, ISelector, IToggleButton,
    IUIElement, Orientation, ProgressRing, RadioButton, RowDefinition, ScrollBarVisibility,
    ScrollMode, ScrollViewer, SelectorBar, SelectorBarItem, StackPanel, TextAlignment, TextBlock,
    TextBox, TextTrimming, TextWrapping, ToggleSwitch, ToolTipService, UIElement,
    VerticalAlignment, Visibility,
};
use super::chart::ChartView;
use super::table::TableHost;
use super::tiles::TilesHost;
use super::xaml::{self, Element};

pub type Post = fn(UiEvent);

struct Native {
    element: FrameworkElement,
    children: Vec<NodeId>,
    attrs: Attrs,
    part: Part,
    /// Whether it gives way along its parent's axis: one line of text is
    /// cut with an ellipsis instead of pushing what follows it out of the
    /// line (see [`Surface::relayout`]).
    yields: bool,
    _events: Vec<EventRevoker>,
}

/// How a container lays out its children.
#[derive(Clone, Copy, PartialEq)]
enum Layout {
    Stack,
    /// Two panes: the first `leading` wide, the second takes the rest.
    Split(f64),
    /// A setting group's rows, a line between each two.
    Rows,
}

enum Part {
    Container {
        grid: Grid,
        axis: Axis,
        align: CrossAlign,
        layout: Layout,
        decor: Decor,
    },
    /// Shows its one child: a scroll view or a popover's panel.
    Single(SingleHost),
    Leaf,
    Text(TextBlock),
    Badge {
        surface: Border,
        label: TextBlock,
    },
    Symbol(FontIcon),
    Button(ButtonParts),
    Segmented {
        bar: SelectorBar,
        props: Segmented,
        quiet: Rc<Cell<bool>>,
    },
    Switch {
        toggle: ToggleSwitch,
        props: Switch,
        quiet: Rc<Cell<bool>>,
    },
    Select {
        combo: ComboBox,
        props: Select,
        quiet: Rc<Cell<bool>>,
    },
    Radio {
        radio: RadioButton,
        props: Radio,
    },
    TextInput(TextInput),
    /// Rebuilt whole on each update: facts, fields and placeholders.
    Composite {
        /// The placeholder's button registration, which a rebuild replaces.
        events: Vec<EventRevoker>,
    },
    Table(TableHost),
    Tiles(TilesHost),
    Chart(ChartView),
}

enum SingleHost {
    Scroll(ScrollViewer),
    Popover(super::popover::PopoverParts),
}

/// What a container shows besides its children.
enum Decor {
    None,
    Group {
        title: TextBlock,
        note: TextBlock,
    },
    /// A setting row's name and explanation, and the line above it, which
    /// its group hides on the first row.
    Row {
        label: TextBlock,
        description: TextBlock,
        surface: Border,
    },
}

pub struct ButtonParts {
    pub button: super::bindings::Button,
    /// The key that presses it in a dialog.
    key: Option<ButtonKey>,
    /// Whether it can be pressed now, by the pointer or its key.
    enabled: Cell<bool>,
    icon: FontIcon,
    spinner: ProgressRing,
    label: TextBlock,
    /// The label, which names the button for assistive technology; an
    /// icon-only button takes its tooltip as its name.
    title: Option<String>,
}

pub struct TextInput {
    pub field: TextBox,
    /// A text editor's document rather than a one-line field.
    pub editor: bool,
    /// The text the field last reported, which the interface's value is
    /// compared with before it is written back.
    reported: Rc<RefCell<String>>,
    quiet: Rc<Cell<bool>>,
}

pub struct Surface {
    host: Border,
    root: Option<NodeId>,
    nodes: HashMap<NodeId, Native>,
    post: Post,
}

/// What the test control channel sees of a realized node: the control it
/// is, with what driving it needs. The channel acts on these the way a
/// click or a key reaches them, so it drives the same controls a user does
/// (see [`super::test_control`]).
#[cfg(feature = "test-control")]
pub(super) enum Control<'a> {
    Button {
        id: NodeId,
        /// Its label, or the tooltip that names an icon-only button.
        name: Option<&'a str>,
        enabled: bool,
    },
    Switch(&'a ToggleSwitch, &'a Switch),
    Select(&'a ComboBox, &'a Select),
    Segmented(&'a SelectorBar, &'a Segmented),
    /// A one-line field, or the editor's document.
    Text(&'a TextBox, bool),
    Scroll(&'a ScrollViewer),
    Table(&'a TableHost),
    Tiles(&'a TilesHost),
    Label(&'a TextBlock),
    Radio,
    /// A part that names what it holds: a setting group, a setting row.
    Named(&'static str, &'a TextBlock),
    /// A part the interface rebuilds whole — facts, fields, a placeholder
    /// and the button it offers. What it shows is in elements of its own,
    /// which the channel reads from the visual tree, and a press on its
    /// button is a press on the part.
    Composite {
        id: NodeId,
        element: &'a FrameworkElement,
    },
    Other(&'static str),
}

#[cfg(feature = "test-control")]
impl Surface {
    /// Every realized node in view order, with its depth and the control it
    /// is.
    pub(super) fn controls(&self) -> Vec<(usize, Control<'_>)> {
        let mut found = Vec::new();
        if let Some(root) = self.root {
            self.walk(root, 0, &mut found);
        }
        found
    }

    fn walk<'a>(&'a self, id: NodeId, depth: usize, found: &mut Vec<(usize, Control<'a>)>) {
        let Some(native) = self.nodes.get(&id) else {
            return;
        };
        let control = match &native.part {
            Part::Button(parts) => Control::Button {
                id,
                name: parts.title.as_deref().or(native.attrs.tooltip.as_deref()),
                enabled: parts.enabled.get(),
            },
            Part::Switch { toggle, props, .. } => Control::Switch(toggle, props),
            Part::Select { combo, props, .. } => Control::Select(combo, props),
            Part::Segmented { bar, props, .. } => Control::Segmented(bar, props),
            Part::TextInput(input) => Control::Text(&input.field, input.editor),
            Part::Single(SingleHost::Scroll(scroll)) => Control::Scroll(scroll),
            Part::Table(table) => Control::Table(table),
            Part::Tiles(tiles) => Control::Tiles(tiles),
            Part::Text(label) => Control::Label(label),
            Part::Radio { .. } => Control::Radio,
            Part::Container { decor, .. } => match decor {
                Decor::Group { title, .. } => Control::Named("Group", title),
                Decor::Row { label, .. } => Control::Named("Row", label),
                Decor::None => Control::Other("Container"),
            },
            Part::Single(SingleHost::Popover(_)) => Control::Other("Popover"),
            Part::Badge { .. } => Control::Other("Badge"),
            Part::Symbol(_) => Control::Other("Symbol"),
            Part::Composite { .. } => Control::Composite {
                id,
                element: &native.element,
            },
            Part::Chart(_) => Control::Other("Chart"),
            Part::Leaf => Control::Other("Leaf"),
        };
        found.push((depth, control));
        for child in &native.children {
            self.walk(*child, depth + 1, found);
        }
    }

    /// Where the surface's root is, for a snapshot of it.
    pub(super) fn host(&self) -> &Border {
        &self.host
    }
}

/// Shows what a cut text says in full, and takes the tooltip back when it
/// fits again. A tooltip the interface gave the text is left alone: only
/// the text's own is managed here.
fn tell_trimmed_text(block: &TextBlock) -> Result<()> {
    let text = block.Text()?;
    let current = ToolTipService::GetToolTip(block)
        .ok()
        .and_then(|tooltip| xaml::unboxed(&tooltip));
    if block.IsTextTrimmed()? {
        if current.is_none() {
            ToolTipService::SetToolTip(block, &xaml::boxed(&text)?)?;
        }
    } else if current.as_deref() == Some(text.as_str()) {
        ToolTipService::SetToolTip(block, None::<&IInspectable>)?;
    }
    Ok(())
}

/// Whether a node gives way along its parent's axis: one line of text,
/// which is cut with an ellipsis, or a name edited in place. Everything
/// else keeps the width it asks for.
/// What an element takes when nothing limits it, which is the most a
/// child that gives way is given.
fn natural_width(element: &FrameworkElement) -> Result<f64> {
    let ui = element.cast::<IUIElement>()?;
    ui.Measure(super::bindings::Size {
        width: f32::INFINITY,
        height: f32::INFINITY,
    })?;
    Ok(f64::from(ui.DesiredSize()?.width))
}

fn yields(kind: &Kind) -> bool {
    match kind {
        Kind::Text(text) => text.single_line,
        Kind::EditableText(_) => true,
        _ => false,
    }
}

/// Logs a failed WinUI call; the interface goes on with what it has.
pub fn check(result: Result<()>, what: &str) {
    if let Err(error) = result {
        log::warn!("WinUI {what}: {error}");
    }
}

impl Surface {
    /// A surface whose root fills `host`.
    pub fn new(host: Border, post: Post) -> Self {
        Self {
            host,
            root: None,
            nodes: HashMap::new(),
            post,
        }
    }

    /// Realizes `root` as the whole content, replacing what was there.
    pub fn set_root(&mut self, root: &Mounted) {
        if let Some(old) = self.root.take() {
            self.remove(old);
        }
        match self.build(root) {
            Ok(element) => check(self.host.SetChild(&element), "set the root"),
            Err(error) => log::warn!("WinUI build the root: {error}"),
        }
        self.root = Some(root.id);
    }

    pub fn apply(&mut self, patches: Vec<Patch>) {
        for patch in patches {
            let result = match patch {
                Patch::Update { id, attrs, kind } => self.update(id, attrs, &kind),
                Patch::Insert {
                    parent,
                    index,
                    node,
                } => self
                    .build(&node)
                    .and_then(|_| self.insert_child(parent, index, node.id)),
                Patch::Remove { parent, id } => {
                    let detached = self.detach_child(parent, id);
                    self.remove(id);
                    detached
                }
                Patch::Move { parent, id, index } => self
                    .detach_child(parent, id)
                    .and_then(|()| self.insert_child(parent, index, id)),
                Patch::Replace { old, node } => self.replace(old, &node),
            };
            check(result, "apply a patch");
        }
    }

    /// Shows each switch, segmented control, pop-up and radio its interface
    /// value again: after the user moved one, the interface may have refused
    /// the change.
    pub fn settle(&self) {
        for native in self.nodes.values() {
            let result = match &native.part {
                Part::Segmented { bar, props, quiet } => {
                    quietly(quiet, || style_segmented(bar, props))
                }
                Part::Switch {
                    toggle,
                    props,
                    quiet,
                } => quietly(quiet, || style_switch(toggle, props)),
                Part::Select {
                    combo,
                    props,
                    quiet,
                } => quietly(quiet, || style_select(combo, props)),
                Part::Radio { radio, props } => style_radio(radio, props),
                _ => Ok(()),
            };
            check(result, "settle a control");
        }
    }

    /// The surface's text editor, if it has one.
    pub fn text_editor(&self) -> Option<TextBox> {
        self.nodes.values().find_map(|native| match &native.part {
            Part::TextInput(input) if input.editor => Some(input.field.clone()),
            _ => None,
        })
    }

    /// The button a key presses, such as a dialog's cancel button for Esc.
    pub fn button_with_key(&self, key: ButtonKey) -> Option<NodeId> {
        self.nodes
            .iter()
            .find_map(|(id, native)| match &native.part {
                Part::Button(parts) if parts.key == Some(key) && parts.enabled.get() => Some(*id),
                _ => None,
            })
    }

    fn build(&mut self, mounted: &Mounted) -> Result<FrameworkElement> {
        let (element, part, events) = self.realize(mounted.id, &mounted.kind)?;
        let mut native = Native {
            element: element.clone(),
            children: Vec::new(),
            attrs: Attrs::default(),
            part,
            yields: yields(&mounted.kind),
            _events: events,
        };
        apply_attrs(&mut native, &mounted.attrs)?;
        name_button(&native)?;
        self.nodes.insert(mounted.id, native);
        for (index, child) in mounted.children.iter().enumerate() {
            self.build(child)?;
            self.insert_child(mounted.id, index, child.id)?;
        }
        Ok(element)
    }

    fn realize(
        &self,
        id: NodeId,
        kind: &Kind,
    ) -> Result<(FrameworkElement, Part, Vec<EventRevoker>)> {
        let post = self.post;
        let node_event = move |event: Event| post(UiEvent::Node { id, event });
        fn leaf<T: Interface>(
            element: &T,
            part: Part,
        ) -> Result<(FrameworkElement, Part, Vec<EventRevoker>)> {
            Ok((xaml::as_element(element)?, part, Vec::new()))
        }
        Ok(match kind {
            Kind::Stack(stack) => {
                let grid = Grid::new()?;
                grid.SetRowSpacing(if stack.axis == Axis::Vertical {
                    stack.spacing
                } else {
                    0.0
                })?;
                grid.SetColumnSpacing(if stack.axis == Axis::Horizontal {
                    stack.spacing
                } else {
                    0.0
                })?;
                grid.SetPadding(xaml::thickness(
                    stack.padding.horizontal,
                    stack.padding.vertical,
                ))?;
                let part = container(&grid, stack.axis, stack.align, Layout::Stack, Decor::None);
                leaf(&grid, part)?
            }
            Kind::Card(card) => {
                let surface = Border::new()?;
                let inner = Grid::new()?;
                inner.SetRowSpacing(card.spacing)?;
                inner.SetPadding(xaml::uniform(card.padding))?;
                surface.SetChild(&inner)?;
                style_card(&surface, card)?;
                let part = container(
                    &inner,
                    Axis::Vertical,
                    CrossAlign::Fill,
                    Layout::Stack,
                    Decor::None,
                );
                leaf(&surface, part)?
            }
            Kind::Split(split) => {
                let grid = Grid::new()?;
                grid.SetColumnSpacing(12.0)?;
                let part = container(
                    &grid,
                    Axis::Horizontal,
                    CrossAlign::Fill,
                    Layout::Split(split.leading),
                    Decor::None,
                );
                leaf(&grid, part)?
            }
            Kind::Spacer => leaf(&Border::new()?, Part::Leaf)?,
            Kind::Separator => {
                let line = Border::new()?;
                line.fe().SetStyle(&xaml::style(
                    "Border",
                    None,
                    &[("Background", xaml::theme("DividerStrokeColorDefaultBrush"))],
                )?)?;
                line.fe().SetHeight(1.0)?;
                leaf(&line, Part::Leaf)?
            }
            Kind::Text(text) => {
                let block = TextBlock::new()?;
                style_text(&block, text)?;
                // Text cut to fit tells the rest in a tooltip, as a label
                // too narrow for its text does on macOS.
                let trimmed = block.IsTextTrimmedChanged(|block, _| {
                    if let Ok(block) = block.ok() {
                        check(tell_trimmed_text(block), "a cut text's tooltip");
                    }
                })?;
                (xaml::as_element(&block)?, Part::Text(block), vec![trimmed])
            }
            Kind::Badge(badge) => {
                let (surface, label) = badge_view(badge)?;
                leaf(&surface.clone(), Part::Badge { surface, label })?
            }
            Kind::Symbol(symbol) => {
                let icon = FontIcon::new()?;
                style_symbol(&icon, symbol)?;
                leaf(&icon, Part::Symbol(icon.clone()))?
            }
            Kind::Button(button) => {
                let parts = button_view(button)?;
                let click = parts
                    .button
                    .cast::<IButtonBase>()?
                    .Click(move |_, _| node_event(Event::Press))?;
                if let Some(key) = button.key {
                    super::keys::accelerator(&parts.button, key)?;
                }
                (
                    xaml::as_element(&parts.button)?,
                    Part::Button(parts),
                    vec![click],
                )
            }
            Kind::Segmented(segmented) => {
                let bar = SelectorBar::new()?;
                let quiet = Rc::new(Cell::new(false));
                let items = bar.Items()?;
                for option in &segmented.options {
                    let item = SelectorBarItem::new()?;
                    item.SetText(option)?;
                    items.Append(&item)?;
                }
                quietly(&quiet, || style_segmented(&bar, segmented))?;
                let changed = {
                    let quiet = quiet.clone();
                    bar.SelectionChanged(move |sender, _| {
                        if quiet.get() {
                            return;
                        }
                        if let Some(index) = sender
                            .ok()
                            .ok()
                            .and_then(|bar| selected_index(bar).ok().flatten())
                        {
                            node_event(Event::Select(index));
                        }
                    })?
                };
                let part = Part::Segmented {
                    bar: bar.clone(),
                    props: segmented.clone(),
                    quiet,
                };
                (xaml::as_element(&bar)?, part, vec![changed])
            }
            Kind::Switch(switch) => {
                let toggle = ToggleSwitch::new()?;
                toggle.SetOnContent(None::<&IInspectable>)?;
                toggle.SetOffContent(None::<&IInspectable>)?;
                xaml::framework(&toggle)?.SetMinWidth(0.0)?;
                let quiet = Rc::new(Cell::new(false));
                quietly(&quiet, || style_switch(&toggle, switch))?;
                let toggled = {
                    let quiet = quiet.clone();
                    let control = toggle.clone();
                    toggle.Toggled(move |_, _| {
                        if !quiet.get() {
                            if let Ok(on) = control.IsOn() {
                                node_event(Event::Toggle(on));
                            }
                        }
                    })?
                };
                let part = Part::Switch {
                    toggle: toggle.clone(),
                    props: switch.clone(),
                    quiet,
                };
                (xaml::as_element(&toggle)?, part, vec![toggled])
            }
            Kind::Select(select) => {
                let combo = ComboBox::new()?;
                let quiet = Rc::new(Cell::new(false));
                quietly(&quiet, || style_select(&combo, select))?;
                let changed = {
                    let quiet = quiet.clone();
                    let control = combo.clone();
                    combo.cast::<ISelector>()?.SelectionChanged(move |_, _| {
                        if quiet.get() {
                            return;
                        }
                        let index = control
                            .cast::<ISelector>()
                            .and_then(|selector| selector.SelectedIndex());
                        if let Ok(index) = index {
                            if index >= 0 {
                                node_event(Event::Select(index as usize));
                            }
                        }
                    })?
                };
                let part = Part::Select {
                    combo: combo.clone(),
                    props: select.clone(),
                    quiet,
                };
                (xaml::as_element(&combo)?, part, vec![changed])
            }
            Kind::Radio(radio) => {
                let button = RadioButton::new()?;
                // A group of its own: the interface decides what is chosen.
                button.SetGroupName(&format!("egrio-{id}"))?;
                xaml::framework(&button)?.SetMinWidth(0.0)?;
                style_radio(&button, radio)?;
                let click = button
                    .cast::<IButtonBase>()?
                    .Click(move |_, _| node_event(Event::Press))?;
                let part = Part::Radio {
                    radio: button.clone(),
                    props: radio.clone(),
                };
                (xaml::as_element(&button)?, part, vec![click])
            }
            Kind::TextField(props) | Kind::SearchField(props) => {
                let search = matches!(kind, Kind::SearchField(_));
                let (input, events) = text_input(props, search, node_event)?;
                let element = if search {
                    xaml::as_element(&search_box(&input.field)?)?
                } else {
                    xaml::as_element(&input.field)?
                };
                (element, Part::TextInput(input), events)
            }
            Kind::TextEditor(props) => {
                let (input, events) = super::text_editor::text_editor(props, node_event)?;
                (
                    xaml::as_element(&input.field)?,
                    Part::TextInput(input),
                    events,
                )
            }
            Kind::EditableText(props) => {
                let (field, events) = super::text_editor::editable_text(props, node_event)?;
                let input = TextInput::new(field.clone(), &props.text, false);
                (xaml::as_element(&field)?, Part::TextInput(input), events)
            }
            Kind::Group(group) => {
                let (element, rows, decor) = group_view(group)?;
                let part = container(&rows, Axis::Vertical, CrossAlign::Fill, Layout::Rows, decor);
                (xaml::as_element(&element)?, part, Vec::new())
            }
            Kind::SettingRow(row) => {
                let (surface, controls, decor) = setting_row_view(row)?;
                let part = container(
                    &controls,
                    Axis::Horizontal,
                    CrossAlign::Center,
                    Layout::Stack,
                    decor,
                );
                (xaml::as_element(&surface)?, part, Vec::new())
            }
            Kind::Facts(facts) => {
                let panel = StackPanel::new()?;
                fill_facts(&panel, facts)?;
                leaf(&panel, Part::Composite { events: Vec::new() })?
            }
            Kind::Fields(fields) => {
                let grid = Grid::new()?;
                fill_fields(&grid, fields)?;
                leaf(&grid, Part::Composite { events: Vec::new() })?
            }
            Kind::Placeholder(placeholder) => {
                // A host the stack may stretch, the placeholder centered in it.
                let host = Border::new()?;
                let panel = StackPanel::new()?;
                host.SetChild(&panel)?;
                let events = fill_placeholder(&panel, placeholder, node_event)?;
                leaf(&host, Part::Composite { events })?
            }
            Kind::Table(table) => {
                let host = TableHost::new(id, table, post)?;
                (host.element(), Part::Table(host), Vec::new())
            }
            Kind::Tiles(tiles) => {
                let host = TilesHost::new(id, tiles, post)?;
                (host.element(), Part::Tiles(host), Vec::new())
            }
            Kind::Chart(chart) => {
                let view = ChartView::new(chart.clone())?;
                (view.element(), Part::Chart(view), Vec::new())
            }
            Kind::Spinner => {
                let ring = ProgressRing::new()?;
                ring.SetIsActive(true)?;
                let element = xaml::framework(&ring)?;
                element.SetWidth(16.0)?;
                element.SetHeight(16.0)?;
                leaf(&ring, Part::Leaf)?
            }
            Kind::Scroll => {
                let scroll = ScrollViewer::new()?;
                ScrollViewer::SetHorizontalScrollBarVisibility(
                    &scroll,
                    ScrollBarVisibility::Disabled,
                )?;
                ScrollViewer::SetHorizontalScrollMode(&scroll, ScrollMode::Disabled)?;
                ScrollViewer::SetVerticalScrollBarVisibility(&scroll, ScrollBarVisibility::Auto)?;
                leaf(&scroll, Part::Single(SingleHost::Scroll(scroll.clone())))?
            }
            Kind::Popover(props) => {
                let parts = super::popover::PopoverParts::new(props)?;
                let element = xaml::as_element(&parts.button)?;
                (
                    element,
                    Part::Single(SingleHost::Popover(parts)),
                    Vec::new(),
                )
            }
        })
    }

    fn update(&mut self, id: NodeId, attrs: Attrs, kind: &Kind) -> Result<()> {
        let post = self.post;
        let Some(native) = self.nodes.get_mut(&id) else {
            return Ok(());
        };
        let attrs_changed = native.attrs != attrs;
        // Text that gives way is capped at what it takes to show, so its
        // parent measures it again whenever it changes.
        let gives_way = native.yields || yields(kind);
        native.yields = yields(kind);
        apply_attrs(native, &attrs)?;
        // A change to how a container lays its children out, which only it
        // knows: a split pane's leading width.
        let mut relayout = false;
        match (&mut native.part, kind) {
            (Part::Container { grid, axis, .. }, Kind::Stack(props)) => {
                grid.SetRowSpacing(if props.axis == Axis::Vertical {
                    props.spacing
                } else {
                    0.0
                })?;
                grid.SetColumnSpacing(if props.axis == Axis::Horizontal {
                    props.spacing
                } else {
                    0.0
                })?;
                grid.SetPadding(xaml::thickness(
                    props.padding.horizontal,
                    props.padding.vertical,
                ))?;
                *axis = props.axis;
            }
            (Part::Container { grid, .. }, Kind::Card(card)) => {
                grid.SetRowSpacing(card.spacing)?;
                grid.SetPadding(xaml::uniform(card.padding))?;
                style_card(&native.element.cast()?, card)?;
            }
            (
                Part::Container {
                    decor: Decor::Group { title, note },
                    ..
                },
                Kind::Group(group),
            ) => style_group(title, note, group)?,
            (
                Part::Container {
                    decor:
                        Decor::Row {
                            label, description, ..
                        },
                    ..
                },
                Kind::SettingRow(row),
            ) => style_setting_row(label, description, row)?,
            (
                Part::Container {
                    layout: layout @ Layout::Split(_),
                    ..
                },
                Kind::Split(split),
            ) => {
                if *layout != Layout::Split(split.leading) {
                    *layout = Layout::Split(split.leading);
                    relayout = true;
                }
            }
            (Part::Text(block), Kind::Text(text)) => style_text(block, text)?,
            (Part::Badge { surface, label }, Kind::Badge(badge)) => {
                style_badge(surface, label, badge)?
            }
            (Part::Symbol(icon), Kind::Symbol(symbol)) => style_symbol(icon, symbol)?,
            (Part::Button(parts), Kind::Button(button)) => {
                style_button(parts, button)?;
                if parts.key != button.key {
                    parts.button.ui().KeyboardAccelerators()?.Clear()?;
                    if let Some(key) = button.key {
                        super::keys::accelerator(&parts.button, key)?;
                    }
                }
                parts.key = button.key;
                parts.title = button.label.clone();
            }
            (Part::Segmented { bar, props, quiet }, Kind::Segmented(new)) => {
                if props.options != new.options {
                    let items = bar.Items()?;
                    quietly(quiet, || {
                        items.Clear()?;
                        for option in &new.options {
                            let item = SelectorBarItem::new()?;
                            item.SetText(option)?;
                            items.Append(&item)?;
                        }
                        Ok(())
                    })?;
                }
                quietly(quiet, || style_segmented(bar, new))?;
                *props = new.clone();
            }
            (
                Part::Switch {
                    toggle,
                    props,
                    quiet,
                },
                Kind::Switch(new),
            ) => {
                quietly(quiet, || style_switch(toggle, new))?;
                *props = new.clone();
            }
            (
                Part::Select {
                    combo,
                    props,
                    quiet,
                },
                Kind::Select(new),
            ) => {
                quietly(quiet, || style_select(combo, new))?;
                *props = new.clone();
            }
            (Part::Radio { radio, props }, Kind::Radio(new)) => {
                style_radio(radio, new)?;
                *props = new.clone();
            }
            (Part::TextInput(input), Kind::TextField(props) | Kind::SearchField(props)) => {
                style_text_input(input, &props.value, &props.placeholder, props.enabled)?
            }
            (Part::TextInput(input), Kind::TextEditor(props)) => {
                super::text_editor::style_text_editor(input, props)?
            }
            (Part::TextInput(input), Kind::EditableText(props)) => {
                super::text_editor::style_editable(&input.field, props)?
            }
            (Part::Composite { .. }, Kind::Facts(facts)) => {
                fill_facts(&native.element.cast()?, facts)?
            }
            (Part::Composite { .. }, Kind::Fields(fields)) => {
                fill_fields(&native.element.cast()?, fields)?
            }
            (Part::Composite { events }, Kind::Placeholder(placeholder)) => {
                let node_event = move |event: Event| post(UiEvent::Node { id, event });
                let host: Border = native.element.cast()?;
                *events = fill_placeholder(&host.Child()?.cast()?, placeholder, node_event)?;
            }
            (Part::Table(host), Kind::Table(table)) => host.update(table)?,
            (Part::Tiles(host), Kind::Tiles(tiles)) => host.update(tiles)?,
            (Part::Chart(view), Kind::Chart(chart)) => view.set_chart(chart.clone())?,
            (Part::Single(SingleHost::Popover(parts)), Kind::Popover(props)) => {
                parts.update(props)?
            }
            _ => {}
        }
        name_button(native)?;
        if relayout {
            self.relayout(id)?;
        }
        // A child that starts or stops growing changes its parent's tracks,
        // and so does one whose text is now another width.
        if attrs_changed || gives_way {
            if let Some(parent) = self.parent_of(id) {
                self.relayout(parent)?;
            }
        }
        Ok(())
    }

    fn parent_of(&self, id: NodeId) -> Option<NodeId> {
        self.nodes
            .iter()
            .find(|(_, native)| native.children.contains(&id))
            .map(|(parent, _)| *parent)
    }

    fn replace(&mut self, old: NodeId, node: &Mounted) -> Result<()> {
        match self.parent_of(old) {
            Some(parent) => {
                let index = self.nodes[&parent]
                    .children
                    .iter()
                    .position(|child| *child == old)
                    .unwrap_or(0);
                self.detach_child(parent, old)?;
                self.remove(old);
                self.build(node)?;
                self.insert_child(parent, index, node.id)
            }
            None => {
                // The root changed component: realize the new root in its place.
                self.set_root(node);
                Ok(())
            }
        }
    }

    fn insert_child(&mut self, parent: NodeId, index: usize, child: NodeId) -> Result<()> {
        let element: UIElement = self.nodes[&child].element.cast()?;
        let Some(native) = self.nodes.get_mut(&parent) else {
            return Ok(());
        };
        let index = index.min(native.children.len());
        native.children.insert(index, child);
        match &native.part {
            Part::Container { grid, .. } => {
                grid.cast::<IPanel>()?
                    .Children()?
                    .InsertAt(index as u32, &element)?;
            }
            Part::Single(SingleHost::Scroll(scroll)) => {
                scroll.cast::<IContentControl>()?.SetContent(&element)?
            }
            Part::Single(SingleHost::Popover(parts)) => parts.set_content(&element)?,
            _ => {}
        }
        self.relayout(parent)
    }

    fn detach_child(&mut self, parent: NodeId, child: NodeId) -> Result<()> {
        let Some(element) = self.nodes.get(&child).map(|native| native.element.clone()) else {
            return Ok(());
        };
        let Some(native) = self.nodes.get_mut(&parent) else {
            return Ok(());
        };
        native.children.retain(|id| *id != child);
        match &native.part {
            Part::Container { grid, .. } => {
                let children = grid.cast::<IPanel>()?.Children()?;
                let mut index = 0;
                if children.IndexOf(&element.cast::<UIElement>()?, &mut index)? {
                    children.RemoveAt(index)?;
                }
            }
            Part::Single(SingleHost::Scroll(scroll)) => scroll
                .cast::<IContentControl>()?
                .SetContent(None::<&IInspectable>)?,
            Part::Single(SingleHost::Popover(parts)) => parts.clear_content()?,
            _ => {}
        }
        self.relayout(parent)
    }

    /// Gives a container's children their tracks and places, and their
    /// alignment across its axis.
    fn relayout(&self, id: NodeId) -> Result<()> {
        let Some(native) = self.nodes.get(&id) else {
            return Ok(());
        };
        let Part::Container {
            grid,
            axis,
            align,
            layout,
            ..
        } = &native.part
        else {
            return Ok(());
        };
        let children: Vec<(&FrameworkElement, &Attrs, bool)> = native
            .children
            .iter()
            .filter_map(|child| self.nodes.get(child))
            .map(|child| (&child.element, &child.attrs, child.yields))
            .collect();
        let rows = grid.RowDefinitions()?;
        let columns = grid.ColumnDefinitions()?;
        rows.Clear()?;
        columns.Clear()?;
        for (index, (element, attrs, yields)) in children.iter().enumerate() {
            // A child that gives way takes a share of the line rather than
            // the width it asks for, so a long text is cut instead of
            // pushing what follows out; the cap keeps it from growing past
            // its text when the line has room to spare.
            let gives_way = *yields && !attrs.grow && *axis == Axis::Horizontal;
            let length = match layout {
                Layout::Split(leading) if index == 0 => xaml::pixels(*leading),
                Layout::Split(_) => xaml::star(),
                _ if gives_way => xaml::weighted_star(GIVES_WAY_SHARE),
                _ if attrs.grow => xaml::star(),
                _ => xaml::auto(),
            };
            let framework = xaml::framework(*element)?;
            match axis {
                Axis::Vertical => {
                    let row = RowDefinition::new()?;
                    row.SetHeight(length)?;
                    rows.Append(&row)?;
                    Grid::SetRow(*element, index as i32)?;
                    Grid::SetColumn(*element, 0)?;
                    framework.SetHorizontalAlignment(horizontal(*align))?;
                    framework.SetVerticalAlignment(VerticalAlignment::Stretch)?;
                }
                Axis::Horizontal => {
                    let column = ColumnDefinition::new()?;
                    column.SetWidth(length)?;
                    if gives_way {
                        column.SetMaxWidth(natural_width(element)?)?;
                    }
                    columns.Append(&column)?;
                    Grid::SetColumn(*element, index as i32)?;
                    Grid::SetRow(*element, 0)?;
                    framework.SetVerticalAlignment(vertical(*align))?;
                    framework.SetHorizontalAlignment(HorizontalAlignment::Stretch)?;
                }
            }
        }
        if *layout == Layout::Rows {
            self.refresh_separators(&native.children)?;
        }
        Ok(())
    }

    /// Hides the line above a group's first row.
    fn refresh_separators(&self, rows: &[NodeId]) -> Result<()> {
        for (index, row) in rows.iter().enumerate() {
            if let Some(Part::Container {
                decor: Decor::Row { surface, .. },
                ..
            }) = self.nodes.get(row).map(|native| &native.part)
            {
                let top = if index == 0 { 0.0 } else { 1.0 };
                surface.SetBorderThickness(super::bindings::Thickness {
                    left: 0.0,
                    top,
                    right: 0.0,
                    bottom: 0.0,
                })?;
            }
        }
        Ok(())
    }

    /// Forgets a node and everything under it.
    fn remove(&mut self, id: NodeId) {
        if let Some(native) = self.nodes.remove(&id) {
            for child in native.children {
                self.remove(child);
            }
        }
    }
}

fn container(grid: &Grid, axis: Axis, align: CrossAlign, layout: Layout, decor: Decor) -> Part {
    Part::Container {
        grid: grid.clone(),
        axis,
        align,
        layout,
        decor,
    }
}

fn horizontal(align: CrossAlign) -> HorizontalAlignment {
    match align {
        CrossAlign::Start => HorizontalAlignment::Left,
        CrossAlign::Center => HorizontalAlignment::Center,
        CrossAlign::End => HorizontalAlignment::Right,
        CrossAlign::Fill => HorizontalAlignment::Stretch,
    }
}

fn vertical(align: CrossAlign) -> VerticalAlignment {
    match align {
        CrossAlign::Start => VerticalAlignment::Top,
        CrossAlign::Center => VerticalAlignment::Center,
        CrossAlign::End => VerticalAlignment::Bottom,
        CrossAlign::Fill => VerticalAlignment::Stretch,
    }
}

/// Runs a change the interface makes, so the control's events stay silent.
fn quietly(quiet: &Cell<bool>, change: impl FnOnce() -> Result<()>) -> Result<()> {
    let previous = quiet.replace(true);
    let result = change();
    quiet.set(previous);
    result
}

fn apply_attrs(native: &mut Native, attrs: &Attrs) -> Result<()> {
    if native.attrs.width != attrs.width {
        native.element.SetWidth(attrs.width.unwrap_or(f64::NAN))?;
    }
    if native.attrs.height != attrs.height {
        native.element.SetHeight(attrs.height.unwrap_or(f64::NAN))?;
    }
    if native.attrs.tooltip != attrs.tooltip {
        match &attrs.tooltip {
            Some(tooltip) => ToolTipService::SetToolTip(&native.element, &xaml::boxed(tooltip)?)?,
            None => ToolTipService::SetToolTip(&native.element, None::<&IInspectable>)?,
        }
    }
    native.attrs = attrs.clone();
    Ok(())
}

/// Content that is not a string gives a button no name of its own
/// ("Basic accessibility information": accessible name).
fn name_button(native: &Native) -> Result<()> {
    let Part::Button(parts) = &native.part else {
        return Ok(());
    };
    let name = parts.title.as_deref().or(native.attrs.tooltip.as_deref());
    AutomationProperties::SetName(&parts.button, name.unwrap_or(""))
}

fn style_card(surface: &Border, card: &Card) -> Result<()> {
    surface.fe().SetStyle(&xaml::style(
        "Border",
        None,
        &[
            (
                "Background",
                xaml::theme("CardBackgroundFillColorDefaultBrush"),
            ),
            (
                "BorderBrush",
                xaml::theme(if card.selected {
                    "AccentFillColorDefaultBrush"
                } else {
                    "CardStrokeColorDefaultBrush"
                }),
            ),
        ],
    )?)?;
    surface.SetBorderThickness(xaml::uniform(1.0))?;
    surface.SetCornerRadius(xaml::corners(8.0))
}

pub fn style_text(block: &TextBlock, text: &Text) -> Result<()> {
    block
        .fe()
        .SetStyle(&xaml::text_style(text.style, text.tone)?)?;
    block.SetText(&text.text)?;
    if text.single_line {
        block.SetTextWrapping(TextWrapping::NoWrap)?;
        block.SetTextTrimming(TextTrimming::CharacterEllipsis)?;
    } else {
        block.SetTextWrapping(TextWrapping::Wrap)?;
        block.SetTextTrimming(TextTrimming::None)?;
    }
    block.SetIsTextSelectionEnabled(text.selectable)
}

/// A text block of a style and tone, for parts the widgets compose.
pub fn label(value: &str, style: TextStyle, tone: Tone) -> Result<TextBlock> {
    let block = TextBlock::new()?;
    block.fe().SetStyle(&xaml::text_style(style, tone)?)?;
    block.SetText(value)?;
    block.SetTextTrimming(TextTrimming::CharacterEllipsis)?;
    Ok(block)
}

pub fn badge_view(badge: &Badge) -> Result<(Border, TextBlock)> {
    let surface = Border::new()?;
    surface.SetCornerRadius(xaml::corners(4.0))?;
    surface.SetPadding(xaml::thickness(6.0, 1.0))?;
    xaml::framework(&surface)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    let label = TextBlock::new()?;
    surface.SetChild(&label)?;
    style_badge(&surface, &label, badge)?;
    Ok((surface, label))
}

pub fn style_badge(surface: &Border, label: &TextBlock, badge: &Badge) -> Result<()> {
    surface.fe().SetStyle(&xaml::tone_surface(badge.tone)?)?;
    label
        .fe()
        .SetStyle(&xaml::text_style(TextStyle::Caption, badge.tone)?)?;
    label.SetText(&badge.text)
}

fn style_symbol(icon: &FontIcon, symbol: &Symbol) -> Result<()> {
    icon.fe().SetStyle(&xaml::icon_style(symbol.tone, 16.0)?)?;
    icon.SetGlyph(xaml::glyph(symbol.icon))
}

/// A busy button's ring, as large as its icon.
const BUSY_RING: f64 = 14.0;
/// The share of a line a track that may only shrink asks for, against the
/// one share each of the tracks beside it: it is capped at what its text
/// needs, so asking for nearly everything leaves it taking its text's
/// width while the line has room, and shrinking first when it has not.
const GIVES_WAY_SHARE: f64 = 1000.0;
/// A search field's width, as the macOS search field prefers.
const SEARCH_WIDTH: f64 = 240.0;
/// Where the find symbol sits from the field's start, and where its text
/// begins after it.
const SEARCH_GLYPH_INSET: f64 = 10.0;
const SEARCH_TEXT_INSET: f64 = 32.0;

/// A button's content: the icon and the label in a line, and the ring over
/// them while the button is busy.
fn button_view(props: &Button) -> Result<ButtonParts> {
    let button = super::bindings::Button::new()?;
    let content = Grid::new()?;
    let line = StackPanel::new()?;
    line.SetOrientation(Orientation::Horizontal)?;
    line.SetSpacing(8.0)?;
    let icon = FontIcon::new()?;
    let spinner = ProgressRing::new()?;
    let ring = xaml::framework(&spinner)?;
    ring.SetWidth(BUSY_RING)?;
    ring.SetHeight(BUSY_RING)?;
    ring.SetMinWidth(BUSY_RING)?;
    ring.SetMinHeight(BUSY_RING)?;
    ring.SetVerticalAlignment(VerticalAlignment::Center)?;
    let label = TextBlock::new()?;
    let children = line.panel().Children()?;
    children.Append(&icon.cast::<UIElement>()?)?;
    children.Append(&label.cast::<UIElement>()?)?;
    let layers = content.cast::<IPanel>()?.Children()?;
    layers.Append(&line.cast::<UIElement>()?)?;
    layers.Append(&spinner.cast::<UIElement>()?)?;
    button.cast::<IContentControl>()?.SetContent(&content)?;
    let parts = ButtonParts {
        button,
        key: props.key,
        enabled: Cell::new(true),
        icon,
        spinner,
        label,
        title: props.label.clone(),
    };
    style_button(&parts, props)?;
    Ok(parts)
}

fn style_button(parts: &ButtonParts, props: &Button) -> Result<()> {
    xaml::framework(&parts.button)?.SetStyle(&xaml::button_style(props.style)?)?;
    let control = parts.button.cast::<IControl>()?;
    parts.enabled.set(props.enabled && !props.busy);
    control.SetIsEnabled(parts.enabled.get())?;
    if props.label.is_none() {
        control.SetPadding(xaml::uniform(6.0))?;
    }
    fn show<T: Interface>(element: &T, shown: bool) -> Result<()> {
        element.cast::<IUIElement>()?.SetVisibility(if shown {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })
    }
    // A busy button keeps its size: the ring turns where its icon is, or
    // over its label when it has none, and what it covers stays laid out,
    // unseen.
    let busy = props.busy;
    show(&parts.icon, props.icon.is_some())?;
    parts.icon.ui().SetOpacity(if busy { 0.0 } else { 1.0 })?;
    parts
        .label
        .ui()
        .SetOpacity(if busy && props.icon.is_none() {
            0.0
        } else {
            1.0
        })?;
    parts
        .spinner
        .fe()
        .SetHorizontalAlignment(if props.icon.is_some() {
            HorizontalAlignment::Left
        } else {
            HorizontalAlignment::Center
        })?;
    show(&parts.spinner, busy)?;
    parts.spinner.SetIsActive(busy)?;
    if let Some(icon) = props.icon {
        parts
            .icon
            .fe()
            .SetStyle(&xaml::icon_style(props.tone, 14.0)?)?;
        parts.icon.SetGlyph(xaml::glyph(icon))?;
    }
    show(&parts.label, props.label.is_some())?;
    parts.label.SetText(props.label.as_deref().unwrap_or(""))
}

fn selected_index(bar: &SelectorBar) -> Result<Option<usize>> {
    let selected = match bar.SelectedItem() {
        Ok(item) => item,
        Err(_) => return Ok(None),
    };
    let items = bar.Items()?;
    let mut index = 0;
    Ok(items
        .IndexOf(&selected, &mut index)?
        .then_some(index as usize))
}

fn style_segmented(bar: &SelectorBar, props: &Segmented) -> Result<()> {
    bar.cast::<IControl>()?.SetIsEnabled(props.enabled)?;
    let items = bar.Items()?;
    match props
        .selected
        .filter(|index| (*index as u32) < items.Size().unwrap_or(0))
    {
        Some(index) => {
            if selected_index(bar)? != Some(index) {
                bar.SetSelectedItem(&items.GetAt(index as u32)?)?;
            }
        }
        None => bar.SetSelectedItem(None::<&SelectorBarItem>)?,
    }
    Ok(())
}

fn style_switch(toggle: &ToggleSwitch, props: &Switch) -> Result<()> {
    toggle.cast::<IControl>()?.SetIsEnabled(props.enabled)?;
    if toggle.IsOn()? != props.on {
        toggle.SetIsOn(props.on)?;
    }
    Ok(())
}

fn style_select(combo: &ComboBox, props: &Select) -> Result<()> {
    let control = combo.cast::<IControl>()?;
    control.SetIsEnabled(props.enabled)?;
    let items = combo.cast::<super::bindings::IItemsControl>()?.Items()?;
    let current: Vec<String> = (0..items.Size()?)
        .filter_map(|index| items.GetAt(index).ok())
        .filter_map(|item| xaml::unboxed(&item))
        .collect();
    if current != props.options {
        items.Clear()?;
        for option in &props.options {
            items.Append(&xaml::boxed(option)?)?;
        }
    }
    let wanted = props.selected.map_or(-1, |index| index as i32);
    let selector = combo.cast::<ISelector>()?;
    if selector.SelectedIndex()? != wanted {
        selector.SetSelectedIndex(wanted)?;
    }
    Ok(())
}

fn style_radio(radio: &RadioButton, props: &Radio) -> Result<()> {
    radio.cast::<IControl>()?.SetIsEnabled(props.enabled)?;
    radio
        .cast::<IToggleButton>()?
        .SetIsChecked(Some(props.selected))
}

/// A search field with the find symbol at its start, where Windows' own
/// search boxes carry it; the field's own padding leaves the room.
fn search_box(field: &TextBox) -> Result<Grid> {
    let grid = Grid::new()?;
    let glyph = FontIcon::new()?;
    glyph.fe().SetStyle(&xaml::icon_style(Tone::Muted, 14.0)?)?;
    // Segoe Fluent's Search, which no interface icon stands for: the
    // symbol belongs to the platform's search box, not to the page.
    glyph.SetGlyph("\u{E721}")?;
    let placed = glyph.fe();
    placed.SetHorizontalAlignment(HorizontalAlignment::Left)?;
    placed.SetVerticalAlignment(VerticalAlignment::Center)?;
    placed.SetMargin(xaml::thickness(SEARCH_GLYPH_INSET, 0.0))?;
    glyph.ui().SetIsHitTestVisible(false)?;
    let children = grid.cast::<IPanel>()?.Children()?;
    children.Append(&field.cast::<UIElement>()?)?;
    children.Append(&glyph.cast::<UIElement>()?)?;
    Ok(grid)
}

fn text_input(
    props: &TextField,
    search: bool,
    node_event: impl Fn(Event) + 'static,
) -> Result<(TextInput, Vec<EventRevoker>)> {
    let field = TextBox::new()?;
    field.SetIsSpellCheckEnabled(false)?;
    if search {
        // A search field keeps one width, so typing never moves what sits
        // beside it; Windows' own clear button ends it while there is text.
        field.fe().SetStyle(&xaml::style(
            "TextBox",
            Some("DefaultTextBoxStyle"),
            &[("Padding", format!("{SEARCH_TEXT_INSET},5,6,6"))],
        )?)?;
        field.fe().SetWidth(SEARCH_WIDTH)?;
    }
    let input = TextInput::new(field.clone(), &props.value, false);
    quietly(&input.quiet, || {
        field.SetText(&props.value)?;
        field.SetPlaceholderText(&props.placeholder)?;
        field.cast::<IControl>()?.SetIsEnabled(props.enabled)
    })?;
    let changed = {
        let reported = input.reported.clone();
        let quiet = input.quiet.clone();
        let control = field.clone();
        field.TextChanged(move |_, _| {
            if quiet.get() {
                return;
            }
            if let Ok(text) = control.Text() {
                *reported.borrow_mut() = text.clone();
                node_event(Event::Changed(text));
            }
        })?
    };
    Ok((input, vec![changed]))
}

/// Writes the interface's text into the field only when it differs from what
/// the field last reported, so typing and an input method's composition are
/// never interrupted.
pub fn style_text_input(
    input: &TextInput,
    value: &str,
    placeholder: &str,
    enabled: bool,
) -> Result<()> {
    quietly(&input.quiet, || {
        input.field.SetPlaceholderText(placeholder)?;
        input.field.cast::<IControl>()?.SetIsEnabled(enabled)?;
        if *input.reported.borrow() != value {
            *input.reported.borrow_mut() = value.to_string();
            input.field.SetText(value)?;
        }
        Ok(())
    })
}

impl TextInput {
    pub fn new(field: TextBox, value: &str, editor: bool) -> Self {
        Self {
            field,
            editor,
            reported: Rc::new(RefCell::new(value.to_string())),
            quiet: Rc::new(Cell::new(false)),
        }
    }

    pub fn reported(&self) -> Rc<RefCell<String>> {
        self.reported.clone()
    }

    pub fn quiet(&self) -> Rc<Cell<bool>> {
        self.quiet.clone()
    }

    /// Puts the first text in without reporting it.
    pub fn write_initial(&self, value: &str) -> Result<()> {
        quietly(&self.quiet, || self.field.SetText(value))
    }

    /// Puts in text the interface chose, and says whether it had to: its
    /// undo history was of the text it replaced, so it goes.
    pub fn write(&self, value: &str) -> Result<bool> {
        let mut written = false;
        quietly(&self.quiet, || {
            if *self.reported.borrow() != value {
                *self.reported.borrow_mut() = value.to_string();
                self.field.SetText(value)?;
                self.field.ClearUndoRedoHistory()?;
                written = true;
            }
            Ok(())
        })?;
        Ok(written)
    }
}

fn group_view(group: &Group) -> Result<(StackPanel, Grid, Decor)> {
    let panel = StackPanel::new()?;
    panel.SetSpacing(8.0)?;
    let header = StackPanel::new()?;
    header.SetOrientation(Orientation::Horizontal)?;
    header.SetSpacing(8.0)?;
    let title = label("", TextStyle::Heading, Tone::Default)?;
    let note = label("", TextStyle::Caption, Tone::Muted)?;
    xaml::framework(&note)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    header
        .panel()
        .Children()?
        .Append(&title.cast::<UIElement>()?)?;
    header
        .panel()
        .Children()?
        .Append(&note.cast::<UIElement>()?)?;
    let surface = Border::new()?;
    style_card(
        &surface,
        &Card {
            padding: 0.0,
            spacing: 0.0,
            selected: false,
        },
    )?;
    let rows = Grid::new()?;
    surface.SetChild(&rows)?;
    panel
        .panel()
        .Children()?
        .Append(&header.cast::<UIElement>()?)?;
    panel
        .panel()
        .Children()?
        .Append(&surface.cast::<UIElement>()?)?;
    style_group(&title, &note, group)?;
    Ok((panel, rows, Decor::Group { title, note }))
}

fn style_group(title: &TextBlock, note: &TextBlock, group: &Group) -> Result<()> {
    title.SetText(&group.title)?;
    note.SetText(group.note.as_deref().unwrap_or(""))?;
    note.cast::<IUIElement>()?
        .SetVisibility(if group.note.is_some() {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })
}

fn setting_row_view(row: &SettingRow) -> Result<(Border, Grid, Decor)> {
    let surface = Border::new()?;
    surface.fe().SetStyle(&xaml::style(
        "Border",
        None,
        &[("BorderBrush", xaml::theme("CardStrokeColorDefaultBrush"))],
    )?)?;
    surface.SetPadding(xaml::thickness(16.0, 12.0))?;
    let line = Grid::new()?;
    line.SetColumnSpacing(16.0)?;
    let columns = line.ColumnDefinitions()?;
    for length in [xaml::star(), xaml::auto()] {
        let column = ColumnDefinition::new()?;
        column.SetWidth(length)?;
        columns.Append(&column)?;
    }
    let text = StackPanel::new()?;
    text.SetSpacing(2.0)?;
    xaml::framework(&text)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    let name = label("", TextStyle::Body, Tone::Default)?;
    let description = TextBlock::new()?;
    description
        .fe()
        .SetStyle(&xaml::text_style(TextStyle::Caption, Tone::Muted)?)?;
    description.SetTextWrapping(TextWrapping::Wrap)?;
    text.panel()
        .Children()?
        .Append(&name.cast::<UIElement>()?)?;
    text.panel()
        .Children()?
        .Append(&description.cast::<UIElement>()?)?;
    let controls = Grid::new()?;
    controls.SetColumnSpacing(8.0)?;
    xaml::framework(&controls)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    Grid::SetColumn(&controls, 1)?;
    line.cast::<IPanel>()?
        .Children()?
        .Append(&text.cast::<UIElement>()?)?;
    line.cast::<IPanel>()?
        .Children()?
        .Append(&controls.cast::<UIElement>()?)?;
    surface.SetChild(&line)?;
    style_setting_row(&name, &description, row)?;
    Ok((
        surface.clone(),
        controls,
        Decor::Row {
            label: name,
            description,
            surface,
        },
    ))
}

fn style_setting_row(name: &TextBlock, description: &TextBlock, row: &SettingRow) -> Result<()> {
    name.SetText(&row.label)?;
    description.SetText(row.description.as_deref().unwrap_or(""))?;
    description
        .cast::<IUIElement>()?
        .SetVisibility(if row.description.is_some() {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })
}

/// The facts in a line: each label, its value and, when the value needs
/// attention, a warning mark explaining why.
/// The facts in a line. Facts of the same shape as the ones shown take
/// their new values in place, so a warning's tooltip under the pointer
/// stays open while the values refresh.
fn fill_facts(panel: &StackPanel, facts: &Facts) -> Result<()> {
    panel.SetOrientation(Orientation::Horizontal)?;
    panel.SetSpacing(20.0)?;
    let children = panel.panel().Children()?;
    if children.Size()? as usize == facts.items.len() {
        let pairs: Vec<StackPanel> = (0..children.Size()?)
            .filter_map(|index| children.GetAt(index).ok())
            .filter_map(|child| child.cast::<StackPanel>().ok())
            .collect();
        let same_shape = pairs.len() == facts.items.len()
            && pairs.iter().zip(&facts.items).all(|(pair, fact)| {
                pair.panel()
                    .Children()
                    .and_then(|parts| parts.Size())
                    .is_ok_and(|size| size as usize == 2 + usize::from(fact.warning.is_some()))
            });
        if same_shape {
            for (pair, fact) in pairs.iter().zip(&facts.items) {
                refill_fact(pair, fact)?;
            }
            return Ok(());
        }
    }
    children.Clear()?;
    for fact in &facts.items {
        children.Append(&fact_view(fact)?.cast::<UIElement>()?)?;
    }
    Ok(())
}

/// Gives a fact's views new text; the warning's tooltip only when its text
/// changed, which the mark keeps in its tag.
fn refill_fact(pair: &StackPanel, fact: &Fact) -> Result<()> {
    let parts = pair.panel().Children()?;
    let name: TextBlock = parts.GetAt(0)?.cast()?;
    name.SetText(&fact.label)?;
    let value: TextBlock = parts.GetAt(1)?.cast()?;
    value.fe().SetStyle(&xaml::text_style(
        if fact.mono {
            TextStyle::Mono
        } else {
            TextStyle::Body
        },
        Tone::Default,
    )?)?;
    value.SetText(&fact.value)?;
    if let Some(warning) = &fact.warning {
        let mark: FontIcon = parts.GetAt(2)?.cast()?;
        let shown = mark.fe().Tag().ok().and_then(|tag| xaml::unboxed(&tag));
        if shown.as_deref() != Some(warning.as_str()) {
            ToolTipService::SetToolTip(&mark, &xaml::boxed(warning)?)?;
            mark.fe().SetTag(&xaml::boxed(warning)?)?;
        }
    }
    Ok(())
}

fn fact_view(fact: &Fact) -> Result<StackPanel> {
    let pair = StackPanel::new()?;
    pair.SetOrientation(Orientation::Horizontal)?;
    pair.SetSpacing(6.0)?;
    let children = pair.panel().Children()?;
    let name = label(&fact.label, TextStyle::Caption, Tone::Muted)?;
    xaml::framework(&name)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    children.Append(&name.cast::<UIElement>()?)?;
    let value = label(
        &fact.value,
        if fact.mono {
            TextStyle::Mono
        } else {
            TextStyle::Body
        },
        Tone::Default,
    )?;
    xaml::framework(&value)?.SetVerticalAlignment(VerticalAlignment::Center)?;
    children.Append(&value.cast::<UIElement>()?)?;
    if let Some(warning) = &fact.warning {
        let mark = FontIcon::new()?;
        mark.fe()
            .SetStyle(&xaml::icon_style(Tone::Warning, 14.0)?)?;
        mark.SetGlyph(xaml::glyph(egrio_ui::node::Icon::Warning))?;
        ToolTipService::SetToolTip(&mark, &xaml::boxed(warning)?)?;
        mark.fe().SetTag(&xaml::boxed(warning)?)?;
        children.Append(&mark.cast::<UIElement>()?)?;
    }
    Ok(pair)
}

/// Labelled values in a grid, each label above its value; a wide field takes
/// a row of its own and wraps.
fn fill_fields(grid: &Grid, fields: &Fields) -> Result<()> {
    let columns = fields.columns.max(1);
    grid.SetColumnSpacing(16.0)?;
    grid.SetRowSpacing(12.0)?;
    let definitions = grid.ColumnDefinitions()?;
    definitions.Clear()?;
    for _ in 0..columns {
        let column = ColumnDefinition::new()?;
        column.SetWidth(xaml::star())?;
        definitions.Append(&column)?;
    }
    let rows = grid.RowDefinitions()?;
    rows.Clear()?;
    let children = grid.cast::<IPanel>()?.Children()?;
    children.Clear()?;
    let (mut row, mut column) = (0usize, 0usize);
    for field in &fields.items {
        if field.wide && column > 0 {
            row += 1;
            column = 0;
        }
        if column == 0 {
            let definition = RowDefinition::new()?;
            definition.SetHeight(xaml::auto())?;
            rows.Append(&definition)?;
        }
        let cell = field_view(field)?;
        Grid::SetRow(&cell, row as i32)?;
        Grid::SetColumn(&cell, column as i32)?;
        if field.wide {
            Grid::SetColumnSpan(&cell, columns as i32)?;
            row += 1;
            column = 0;
        } else {
            column += 1;
            if column == columns {
                row += 1;
                column = 0;
            }
        }
        children.Append(&cell.cast::<UIElement>()?)?;
    }
    Ok(())
}

fn field_view(field: &Field) -> Result<StackPanel> {
    let cell = StackPanel::new()?;
    cell.SetSpacing(2.0)?;
    let children = cell.panel().Children()?;
    children.Append(&label(&field.label, TextStyle::Caption, Tone::Muted)?.cast::<UIElement>()?)?;
    for value in &field.values {
        let text = label(
            value,
            if field.mono {
                TextStyle::Mono
            } else {
                TextStyle::Body
            },
            Tone::Default,
        )?;
        text.SetIsTextSelectionEnabled(true)?;
        if field.wide {
            text.SetTextWrapping(TextWrapping::Wrap)?;
        }
        children.Append(&text.cast::<UIElement>()?)?;
    }
    Ok(cell)
}

/// A placeholder's text centered in its space, with its action under it.
fn fill_placeholder(
    panel: &StackPanel,
    placeholder: &Placeholder,
    node_event: impl Fn(Event) + 'static,
) -> Result<Vec<EventRevoker>> {
    panel.SetSpacing(6.0)?;
    let framework = xaml::framework(panel)?;
    framework.SetHorizontalAlignment(HorizontalAlignment::Center)?;
    framework.SetVerticalAlignment(VerticalAlignment::Center)?;
    let children = panel.panel().Children()?;
    children.Clear()?;
    let title = label(&placeholder.title, TextStyle::Body, Tone::Muted)?;
    title.SetTextAlignment(TextAlignment::Center)?;
    title.SetTextWrapping(TextWrapping::Wrap)?;
    children.Append(&title.cast::<UIElement>()?)?;
    if let Some(detail) = &placeholder.detail {
        let detail = label(detail, TextStyle::Caption, Tone::Faint)?;
        detail.SetTextAlignment(TextAlignment::Center)?;
        detail.SetTextWrapping(TextWrapping::Wrap)?;
        children.Append(&detail.cast::<UIElement>()?)?;
    }
    let mut events = Vec::new();
    if let Some(action) = &placeholder.action {
        let parts = button_view(&Button {
            label: Some(action.label.clone()),
            icon: action.icon,
            tone: Tone::Default,
            style: egrio_ui::node::ButtonStyle::Primary,
            key: None,
            enabled: true,
            busy: false,
            on_press: None,
        })?;
        let button = xaml::framework(&parts.button)?;
        button.SetHorizontalAlignment(HorizontalAlignment::Center)?;
        button.SetMargin(super::bindings::Thickness {
            left: 0.0,
            top: 8.0,
            right: 0.0,
            bottom: 0.0,
        })?;
        events.push(
            parts
                .button
                .cast::<IButtonBase>()?
                .Click(move |_, _| node_event(Event::Press))?,
        );
        children.Append(&parts.button.cast::<UIElement>()?)?;
    }
    Ok(events)
}
