//! Realizes component trees as AppKit views and applies the reconciler's
//! patches to them. A surface (the page content, the drawer) owns the views
//! of one tree; every realized node keeps its view, its children's ids and
//! the objects its controls need alive.

use std::collections::HashMap;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::runtime::NSObjectProtocol;
use objc2::{define_class, msg_send, MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSBox, NSBoxType, NSButton, NSButtonType, NSColor, NSControlSize, NSControlStateValueOff,
    NSControlStateValueOn, NSImageScaling, NSImageView, NSLayoutAttribute, NSLayoutConstraint,
    NSLayoutConstraintOrientation, NSLineBreakMode, NSPopUpButton, NSProgressIndicator,
    NSProgressIndicatorStyle, NSScrollView, NSSegmentSwitchTracking, NSSegmentedControl,
    NSStackView, NSStackViewDistribution, NSSwitch, NSTextField, NSTextView, NSTitlePosition,
    NSUserInterfaceLayoutOrientation, NSView,
};
use objc2_foundation::{NSArray, NSEdgeInsets, NSString};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    Attrs, Axis, Badge, Button, ButtonStyle, Card, CrossAlign, Fact, Facts, Field, Fields, Group,
    Kind, Padding, Placeholder, Radio, Segmented, Select, SettingRow, Switch, Symbol, Text,
    TextStyle, Tone,
};
use egrio_ui::reconcile::{Mounted, NodeId, Patch};

use super::button::{button_view, style_button};
use super::chart::ChartView;
use super::popover::{self, PopoverParts};
use super::style;
use super::table::TableHost;
use super::target::ActionTarget;
use super::text::{self, TextDelegate};
use super::text_editor::{self, TextEditorDelegate};
use super::tiles::TilesHost;

/// Content hugging for a component that keeps its size, and one that takes
/// the space left. A stack that keeps its size hugs below what text resists
/// compression with, so it never squeezes its text to stay small.
const KEEP: f32 = 750.0;
const STACK_KEEP: f32 = 300.0;
pub const TEXT_COMPRESSION: f32 = 500.0;
const STRETCH: f32 = 1.0;
/// How strongly a scroll view keeps its content's height: below a stack's
/// hugging, so a growing scroll view stretches before its sibling stacks
/// do, and above an empty filler's, which takes the space a scroll view
/// that does not grow leaves.
const SCROLL_HUG: f32 = 290.0;

pub struct FillerIvars;

define_class!(
    /// Empty space that gives way first: zero intrinsic size, so its lowest
    /// hugging and compression priorities decide who takes or gives space.
    #[unsafe(super(NSView))]
    #[name = "EgrioFiller"]
    #[thread_kind = MainThreadOnly]
    #[ivars = FillerIvars]
    pub struct Filler;

    unsafe impl NSObjectProtocol for Filler {}

    impl Filler {
        #[unsafe(method(intrinsicContentSize))]
        fn intrinsic_content_size(&self) -> objc2_foundation::NSSize {
            objc2_foundation::NSSize { width: 0.0, height: 0.0 }
        }
    }
);

impl Filler {
    pub fn view(mtm: MainThreadMarker) -> Retained<NSView> {
        let this = Self::alloc(mtm).set_ivars(FillerIvars);
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        for orientation in [
            NSLayoutConstraintOrientation::Horizontal,
            NSLayoutConstraintOrientation::Vertical,
        ] {
            this.setContentHuggingPriority_forOrientation(STRETCH, orientation);
            this.setContentCompressionResistancePriority_forOrientation(STRETCH, orientation);
        }
        Retained::into_super(this)
    }
}

pub struct FlippedIvars;

define_class!(
    /// A scroll view's document: flipped, so content shorter than the
    /// visible area sits at its top.
    #[unsafe(super(NSView))]
    #[name = "EgrioFlippedView"]
    #[thread_kind = MainThreadOnly]
    #[ivars = FlippedIvars]
    pub struct Flipped;

    unsafe impl NSObjectProtocol for Flipped {}

    impl Flipped {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }
    }
);

impl Flipped {
    pub fn view(mtm: MainThreadMarker) -> Retained<NSView> {
        let this = Self::alloc(mtm).set_ivars(FlippedIvars);
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        Retained::into_super(this)
    }
}

struct Native {
    view: Retained<NSView>,
    children: Vec<NodeId>,
    attrs: Attrs,
    part: Part,
    sizing: Vec<Retained<NSLayoutConstraint>>,
}

enum Part {
    /// A stack, a card's inner stack, a split's line of panes, a setting
    /// group's rows or a setting row's controls.
    Container {
        stack: Retained<NSStackView>,
        axis: Axis,
        align: CrossAlign,
        filler: Option<Retained<NSView>>,
        /// A split's leading pane width; `None` otherwise.
        split: Option<f64>,
        /// The parent stretches it along its own axis, so it needs an empty
        /// view to take what its children leave when none of them grows.
        stretched: bool,
        /// Each child's constraint filling the stack across its axis.
        fills: HashMap<NodeId, Retained<NSLayoutConstraint>>,
        decor: Decor,
    },
    Leaf,
    Text(Retained<NSTextField>),
    Badge {
        label: Retained<NSTextField>,
        surface: Retained<NSBox>,
    },
    Symbol(Retained<NSImageView>),
    Button {
        button: Retained<NSButton>,
        _target: Retained<ActionTarget>,
    },
    Segmented {
        control: Retained<NSSegmentedControl>,
        props: Segmented,
        _target: Retained<ActionTarget>,
    },
    Switch {
        control: Retained<NSSwitch>,
        props: Switch,
        _target: Retained<ActionTarget>,
    },
    Select {
        control: Retained<NSPopUpButton>,
        props: Select,
        _target: Retained<ActionTarget>,
    },
    Radio {
        button: Retained<NSButton>,
        props: Radio,
        _target: Retained<ActionTarget>,
    },
    /// A text field or text edited in place.
    TextInput {
        field: Retained<NSTextField>,
        delegate: Retained<TextDelegate>,
    },
    /// A text editor, in the scroll view that is the node's view.
    TextEditor {
        view: Retained<NSTextView>,
        delegate: Retained<TextEditorDelegate>,
    },
    /// The facts' labels, updated in place while their shape stays.
    Facts(Vec<FactParts>),
    /// Rebuilt whole on each update: fields.
    Composite,
    /// Rebuilt whole on each update; its button, if any, keeps its target.
    Placeholder {
        target: Retained<ActionTarget>,
    },
    Table(TableHost),
    Tiles(TilesHost),
    /// A popover's button; its one child fills the popover's content.
    Popover(PopoverParts),
    Chart(Retained<ChartView>),
    /// A scroll view; its child fills the document view's width.
    Scroll {
        document: Retained<NSView>,
    },
}

/// What a container shows besides its children.
enum Decor {
    None,
    /// A setting group's title and note above its surface.
    Group {
        title: Retained<NSTextField>,
        note: Retained<NSTextField>,
    },
    /// A setting row's name and explanation before its controls, and the
    /// line above it, which its group hides on the first row.
    Row {
        label: Retained<NSTextField>,
        description: Retained<NSTextField>,
        separator: Retained<NSBox>,
    },
}

fn container(
    stack: Retained<NSStackView>,
    axis: Axis,
    align: CrossAlign,
    split: Option<f64>,
    decor: Decor,
) -> Part {
    Part::Container {
        stack,
        axis,
        align,
        filler: None,
        split,
        stretched: false,
        fills: HashMap::new(),
        decor,
    }
}

pub struct Surface {
    mtm: MainThreadMarker,
    host: Retained<NSView>,
    root: Option<NodeId>,
    /// The root's distance from the host's safe area, kept for a new root.
    inset: NSEdgeInsets,
    nodes: HashMap<NodeId, Native>,
    post: fn(UiEvent),
}

/// The same inset on every edge.
pub fn even_insets(inset: f64) -> NSEdgeInsets {
    NSEdgeInsets {
        top: inset,
        left: inset,
        bottom: inset,
        right: inset,
    }
}

impl Surface {
    /// A surface whose root view fills `host`'s safe area within the insets
    /// its root is set with.
    pub fn new(mtm: MainThreadMarker, host: Retained<NSView>, post: fn(UiEvent)) -> Self {
        Self {
            mtm,
            host,
            root: None,
            inset: NO_INSETS,
            nodes: HashMap::new(),
            post,
        }
    }

    /// The view the surface's content fills.
    pub fn host(&self) -> &NSView {
        &self.host
    }

    /// Realizes `root` as the whole content, replacing what was there;
    /// `inset.left` and `inset.right` are the leading and trailing insets.
    pub fn set_root(&mut self, root: &Mounted, inset: NSEdgeInsets) {
        self.inset = inset;
        if let Some(old) = self.root.take() {
            self.remove(old);
        }
        let view = self.build(root);
        self.set_stretched(root.id, true);
        view.setTranslatesAutoresizingMaskIntoConstraints(false);
        self.host.addSubview(&view);
        let guide = self.host.safeAreaLayoutGuide();
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            view.leadingAnchor()
                .constraintEqualToAnchor_constant(&guide.leadingAnchor(), inset.left),
            view.trailingAnchor()
                .constraintEqualToAnchor_constant(&guide.trailingAnchor(), -inset.right),
            view.topAnchor()
                .constraintEqualToAnchor_constant(&guide.topAnchor(), inset.top),
            view.bottomAnchor()
                .constraintEqualToAnchor_constant(&guide.bottomAnchor(), -inset.bottom),
        ]));
        self.root = Some(root.id);
    }

    pub fn apply(&mut self, patches: Vec<Patch>) {
        let changed = !patches.is_empty();
        for patch in patches {
            match patch {
                Patch::Update { id, attrs, kind } => self.update(id, attrs, &kind),
                Patch::Insert {
                    parent,
                    index,
                    node,
                } => {
                    let view = self.build(&node);
                    self.insert_child(parent, index, node.id, &view);
                }
                Patch::Remove { parent, id } => {
                    self.detach_child(parent, id);
                    self.remove(id);
                }
                Patch::Move { parent, id, index } => {
                    let view = self.nodes[&id].view.clone();
                    self.detach_child(parent, id);
                    self.insert_child(parent, index, id, &view);
                }
                Patch::Replace { old, node } => self.replace(old, &node),
            }
        }
        // An open popover takes its content's new size.
        if changed {
            for native in self.nodes.values() {
                if let Part::Popover(parts) = &native.part {
                    parts.refit();
                }
            }
        }
    }

    /// Shows each switch, segmented control and pop-up its interface value
    /// again: after the user moved one, the interface may have refused the
    /// change.
    /// The text view of the surface's text editor, if it has one.
    pub fn text_editor(&self) -> Option<Retained<NSTextView>> {
        self.nodes.values().find_map(|native| match &native.part {
            Part::TextEditor { view, .. } => Some(view.clone()),
            _ => None,
        })
    }

    pub fn settle(&self) {
        for native in self.nodes.values() {
            match &native.part {
                Part::Segmented { control, props, .. } => style_segmented(control, props),
                Part::Switch { control, props, .. } => style_switch(control, props),
                Part::Select { control, props, .. } => style_select(control, props),
                Part::Radio { button, props, .. } => style_radio(button, props),
                _ => {}
            }
        }
    }

    /// Hides the line above a group's first row.
    fn refresh_separators(&self, group: NodeId) {
        let Some(native) = self.nodes.get(&group) else {
            return;
        };
        if !matches!(
            native.part,
            Part::Container {
                decor: Decor::Group { .. },
                ..
            }
        ) {
            return;
        }
        for (index, child) in native.children.iter().enumerate() {
            if let Some(Part::Container {
                decor: Decor::Row { separator, .. },
                ..
            }) = self.nodes.get(child).map(|native| &native.part)
            {
                separator.setHidden(index == 0);
            }
        }
    }

    fn build(&mut self, mounted: &Mounted) -> Retained<NSView> {
        let (view, part) = self.realize(mounted.id, &mounted.kind);
        let mut native = Native {
            view: view.clone(),
            children: Vec::new(),
            attrs: Attrs::default(),
            part,
            sizing: Vec::new(),
        };
        apply_attrs(&mut native, &mounted.attrs);
        self.nodes.insert(mounted.id, native);
        for (index, child) in mounted.children.iter().enumerate() {
            let child_view = self.build(child);
            self.insert_child(mounted.id, index, child.id, &child_view);
        }
        view
    }

    fn realize(&self, id: NodeId, kind: &Kind) -> (Retained<NSView>, Part) {
        let mtm = self.mtm;
        match kind {
            Kind::Stack(stack) => {
                let view = new_stack(
                    mtm,
                    stack.axis,
                    stack.spacing,
                    stack.align,
                    edge_insets(stack.padding),
                );
                let part = container(view.clone(), stack.axis, stack.align, None, Decor::None);
                (into_view(&view), part)
            }
            Kind::Card(card) => {
                let surface = card_box(mtm);
                let inner = new_stack(
                    mtm,
                    Axis::Vertical,
                    card.spacing,
                    CrossAlign::Fill,
                    NSEdgeInsets {
                        top: card.padding,
                        left: card.padding,
                        bottom: card.padding,
                        right: card.padding,
                    },
                );
                pin(&inner, &surface_content(&surface), 0.0);
                style_card(&surface, card);
                (
                    into_view(&surface),
                    container(inner, Axis::Vertical, CrossAlign::Fill, None, Decor::None),
                )
            }
            Kind::Split(split) => {
                let line = new_stack(
                    mtm,
                    Axis::Horizontal,
                    12.0,
                    CrossAlign::Fill,
                    NSEdgeInsets {
                        top: 0.0,
                        left: 0.0,
                        bottom: 0.0,
                        right: 0.0,
                    },
                );
                let part = container(
                    line.clone(),
                    Axis::Horizontal,
                    CrossAlign::Fill,
                    Some(split.leading),
                    Decor::None,
                );
                (into_view(&line), part)
            }
            Kind::Spacer => (Filler::view(mtm), Part::Leaf),
            Kind::Separator => {
                let line = NSBox::new(mtm);
                line.setBoxType(NSBoxType::Separator);
                (into_view(&line), Part::Leaf)
            }
            Kind::Text(text) => {
                let field = text_field(mtm, text);
                (into_view(&field), Part::Text(field))
            }
            Kind::Badge(badge) => {
                let (surface, label) = badge_view(mtm, badge);
                (into_view(&surface), Part::Badge { label, surface })
            }
            Kind::Symbol(symbol) => {
                let image = symbol_view(mtm, symbol);
                (into_view(&image), Part::Symbol(image))
            }
            Kind::Button(button) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |_| {
                    post(UiEvent::Node {
                        id,
                        event: Event::Press,
                    })
                });
                let control = button_view(mtm, button, &target);
                (
                    into_view(&control),
                    Part::Button {
                        button: control,
                        _target: target,
                    },
                )
            }
            Kind::Segmented(segmented) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |sender: &AnyObject| {
                    let selected: isize = unsafe { msg_send![sender, selectedSegment] };
                    if selected >= 0 {
                        post(UiEvent::Node {
                            id,
                            event: Event::Select(selected as usize),
                        });
                    }
                });
                let control = segmented_view(mtm, segmented, &target);
                (
                    into_view(&control),
                    Part::Segmented {
                        control,
                        props: segmented.clone(),
                        _target: target,
                    },
                )
            }
            Kind::Switch(switch) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |sender: &AnyObject| {
                    let state: isize = unsafe { msg_send![sender, state] };
                    post(UiEvent::Node {
                        id,
                        event: Event::Toggle(state == NSControlStateValueOn),
                    });
                });
                let control = NSSwitch::new(mtm);
                let object: &AnyObject = target.as_ref();
                unsafe {
                    control.setTarget(Some(object));
                    control.setAction(Some(ActionTarget::selector()));
                }
                style_switch(&control, switch);
                (
                    into_view(&control),
                    Part::Switch {
                        control,
                        props: switch.clone(),
                        _target: target,
                    },
                )
            }
            Kind::Select(select) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |sender: &AnyObject| {
                    let selected: isize = unsafe { msg_send![sender, indexOfSelectedItem] };
                    if selected >= 0 {
                        post(UiEvent::Node {
                            id,
                            event: Event::Select(selected as usize),
                        });
                    }
                });
                let control = NSPopUpButton::new(mtm);
                control.setPullsDown(false);
                let object: &AnyObject = target.as_ref();
                unsafe {
                    control.setTarget(Some(object));
                    control.setAction(Some(ActionTarget::selector()));
                }
                style_select(&control, select);
                (
                    into_view(&control),
                    Part::Select {
                        control,
                        props: select.clone(),
                        _target: target,
                    },
                )
            }
            Kind::Radio(radio) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |_| {
                    post(UiEvent::Node {
                        id,
                        event: Event::Press,
                    })
                });
                let button = NSButton::new(mtm);
                button.setButtonType(NSButtonType::Radio);
                button.setTitle(&NSString::from_str(""));
                let object: &AnyObject = target.as_ref();
                unsafe {
                    button.setTarget(Some(object));
                    button.setAction(Some(ActionTarget::selector()));
                }
                style_radio(&button, radio);
                (
                    into_view(&button),
                    Part::Radio {
                        button,
                        props: radio.clone(),
                        _target: target,
                    },
                )
            }
            Kind::TextField(props) => {
                let (field, delegate) = text::text_field(mtm, props, self.post, id);
                (into_view(&field), Part::TextInput { field, delegate })
            }
            Kind::SearchField(props) => {
                let (field, delegate) = text::search_field(mtm, props, self.post, id);
                (into_view(&field), Part::TextInput { field, delegate })
            }
            Kind::TextEditor(props) => {
                let (scroll, view, delegate) = text_editor::text_editor(mtm, props, self.post, id);
                (into_view(&scroll), Part::TextEditor { view, delegate })
            }
            Kind::EditableText(props) => {
                let (field, delegate) = text::editable_text(mtm, props, self.post, id);
                (into_view(&field), Part::TextInput { field, delegate })
            }
            Kind::Group(group) => {
                let views = group_view(mtm, group);
                let decor = Decor::Group {
                    title: views.title,
                    note: views.note,
                };
                (
                    views.view,
                    container(views.rows, Axis::Vertical, CrossAlign::Fill, None, decor),
                )
            }
            Kind::SettingRow(row) => {
                let views = setting_row_view(mtm, row);
                let decor = Decor::Row {
                    label: views.label,
                    description: views.description,
                    separator: views.separator,
                };
                (
                    views.view,
                    container(
                        views.controls,
                        Axis::Horizontal,
                        CrossAlign::Center,
                        None,
                        decor,
                    ),
                )
            }
            Kind::Facts(facts) => {
                let container = NSView::new(mtm);
                let parts = fill_facts(mtm, &container, facts);
                (container, Part::Facts(parts))
            }
            Kind::Fields(fields) => (
                composite(mtm, |container| fill_fields(mtm, container, fields)),
                Part::Composite,
            ),
            Kind::Placeholder(placeholder) => {
                let post = self.post;
                let target = ActionTarget::new(mtm, move |_| {
                    post(UiEvent::Node {
                        id,
                        event: Event::Press,
                    })
                });
                (
                    composite(mtm, |container| {
                        fill_placeholder(mtm, container, placeholder, &target)
                    }),
                    Part::Placeholder { target },
                )
            }
            Kind::Table(table) => {
                let host = TableHost::new(mtm, id, table, self.post);
                (host.view(), Part::Table(host))
            }
            Kind::Tiles(tiles) => {
                let host = TilesHost::new(mtm, id, tiles, self.post);
                (host.view(), Part::Tiles(host))
            }
            Kind::Popover(props) => {
                let parts = PopoverParts::new(mtm, props);
                (into_view(&parts.button), Part::Popover(parts))
            }
            Kind::Chart(chart) => {
                let view = ChartView::new(mtm, chart.clone());
                (into_view(&view), Part::Chart(view))
            }
            Kind::Scroll => {
                let (scroll, document) = scroll_view(mtm);
                (into_view(&scroll), Part::Scroll { document })
            }
            Kind::Spinner => {
                let spinner = small_spinner(mtm);
                unsafe { spinner.startAnimation(None) };
                (into_view(&spinner), Part::Leaf)
            }
        }
    }

    fn update(&mut self, id: NodeId, attrs: Attrs, kind: &Kind) {
        let mtm = self.mtm;
        let Some(native) = self.nodes.get_mut(&id) else {
            return;
        };
        apply_attrs(native, &attrs);
        match (&mut native.part, kind) {
            (Part::Container { stack, axis, .. }, Kind::Stack(props)) => {
                stack.setSpacing(props.spacing);
                stack.setEdgeInsets(edge_insets(props.padding));
                *axis = props.axis;
            }
            (Part::Container { stack, .. }, Kind::Card(card)) => {
                stack.setSpacing(card.spacing);
                style_card(&native.view, card);
            }
            (Part::Radio { button, props, .. }, Kind::Radio(new)) => {
                style_radio(button, new);
                *props = new.clone();
            }
            (
                Part::TextInput { field, delegate },
                Kind::TextField(props) | Kind::SearchField(props),
            ) => text::style_text_field(field, delegate, props),
            (Part::TextEditor { view, delegate }, Kind::TextEditor(props)) => {
                text_editor::style_text_editor(view, delegate, props)
            }
            (Part::TextInput { field, delegate }, Kind::EditableText(props)) => {
                text::style_editable(field, delegate, props)
            }
            (Part::Text(field), Kind::Text(text)) => style_text_field(field, text),
            (Part::Badge { label, surface }, Kind::Badge(badge)) => {
                style_badge(label, surface, badge)
            }
            (Part::Symbol(image), Kind::Symbol(symbol)) => style_symbol(image, symbol),
            (Part::Button { button, .. }, Kind::Button(props)) => style_button(button, props),
            (Part::Segmented { control, props, .. }, Kind::Segmented(new)) => {
                style_segmented(control, new);
                *props = new.clone();
            }
            (Part::Switch { control, props, .. }, Kind::Switch(new)) => {
                style_switch(control, new);
                *props = new.clone();
            }
            (Part::Select { control, props, .. }, Kind::Select(new)) => {
                style_select(control, new);
                *props = new.clone();
            }
            (
                Part::Container {
                    decor: Decor::Group { title, note },
                    ..
                },
                Kind::Group(group),
            ) => style_group(title, note, group),
            (
                Part::Container {
                    decor:
                        Decor::Row {
                            label, description, ..
                        },
                    ..
                },
                Kind::SettingRow(row),
            ) => style_setting_row(label, description, row),
            (Part::Facts(parts), Kind::Facts(facts)) => {
                let same_shape = parts.len() == facts.items.len()
                    && parts.iter().zip(&facts.items).all(|(part, fact)| {
                        part.shown.mono == fact.mono
                            && part.shown.warning.is_some() == fact.warning.is_some()
                    });
                if same_shape {
                    for (part, fact) in parts.iter_mut().zip(&facts.items) {
                        part.show(fact);
                    }
                } else {
                    refill(&native.view, |container| {
                        *parts = fill_facts(mtm, container, facts)
                    });
                }
            }
            (Part::Composite, Kind::Fields(fields)) => refill(&native.view, |container| {
                fill_fields(mtm, container, fields)
            }),
            (Part::Placeholder { target }, Kind::Placeholder(placeholder)) => {
                refill(&native.view, |container| {
                    fill_placeholder(mtm, container, placeholder, target)
                })
            }
            (Part::Table(host), Kind::Table(table)) => host.update(table),
            (Part::Tiles(host), Kind::Tiles(tiles)) => host.update(tiles),
            (Part::Popover(parts), Kind::Popover(props)) => parts.update(props),
            (Part::Chart(view), Kind::Chart(chart)) => view.set_chart(chart.clone()),
            _ => {}
        }
    }

    fn replace(&mut self, old: NodeId, node: &Mounted) {
        let parent = self
            .nodes
            .iter()
            .find(|(_, native)| native.children.contains(&old))
            .map(|(id, _)| *id);
        match parent {
            Some(parent) => {
                let index = self.nodes[&parent]
                    .children
                    .iter()
                    .position(|child| *child == old)
                    .unwrap_or(0);
                self.detach_child(parent, old);
                self.remove(old);
                let view = self.build(node);
                self.insert_child(parent, index, node.id, &view);
            }
            None => {
                // The root changed component: realize the new root in its place.
                self.set_root(node, self.inset);
            }
        }
    }

    fn insert_child(&mut self, parent: NodeId, index: usize, child: NodeId, view: &NSView) {
        let child_attrs = self
            .nodes
            .get(&child)
            .map(|native| native.attrs.clone())
            .unwrap_or_default();
        let sibling_attrs: Vec<Attrs> = self.nodes[&parent]
            .children
            .iter()
            .filter_map(|id| self.nodes.get(id).map(|native| native.attrs.clone()))
            .chain(std::iter::once(child_attrs.clone()))
            .collect();
        // How the child hugs its content: a stack (or a card's stack) hugs
        // through its own priority, a leaf through its intrinsic size. A
        // child that does not grow keeps its natural size, so an empty view
        // inside it never stretches it.
        let stretched = match (
            self.nodes.get(&parent).map(|native| &native.part),
            self.nodes.get(&child).map(|native| &native.part),
        ) {
            (
                Some(Part::Container {
                    axis, align, split, ..
                }),
                // A setting group or row lays out its own views and sizes
                // like a leaf.
                Some(Part::Container {
                    axis: child_axis,
                    decor: Decor::None,
                    ..
                }),
            ) => {
                if axis == child_axis {
                    child_attrs.grow || split.is_some()
                } else {
                    *align == CrossAlign::Fill
                }
            }
            _ => false,
        };
        self.set_stretched(child, stretched);
        if let (Some(parent_native), Some(child_native)) =
            (self.nodes.get(&parent), self.nodes.get(&child))
        {
            if let Part::Container { axis, align, .. } = &parent_native.part {
                let main = if child_attrs.grow { STRETCH } else { KEEP };
                let cross = if *align == CrossAlign::Fill {
                    STRETCH
                } else {
                    KEEP
                };
                let (main_orientation, cross_orientation) =
                    (orientation_of(*axis), cross_orientation_of(*axis));
                match &child_native.part {
                    Part::Container {
                        stack,
                        decor: Decor::None,
                        ..
                    } => {
                        let keep = |priority: f32| {
                            if priority == KEEP {
                                STACK_KEEP
                            } else {
                                priority
                            }
                        };
                        stack.setHuggingPriority_forOrientation(keep(main), main_orientation);
                        stack.setHuggingPriority_forOrientation(keep(cross), cross_orientation);
                    }
                    _ => {
                        // Across the axis a leaf fills the stack or keeps its size.
                        view.setContentHuggingPriority_forOrientation(main, main_orientation);
                        view.setContentHuggingPriority_forOrientation(cross, cross_orientation);
                    }
                }
            }
        }
        let Some(native) = self.nodes.get_mut(&parent) else {
            return;
        };
        let index = index.min(native.children.len());
        native.children.insert(index, child);
        if let Part::Scroll { document } = &native.part {
            pin(view, document, 0.0);
        }
        if let Part::Popover(parts) = &native.part {
            pin(view, &parts.host, popover::INSET);
        }
        if let Part::Container {
            stack,
            axis,
            align,
            split,
            fills,
            ..
        } = &mut native.part
        {
            let orientation = orientation_of(*axis);
            match *split {
                // The leading pane keeps its width; the other takes the rest.
                Some(leading) if index == 0 => {
                    stack.insertArrangedSubview_atIndex(view, 0);
                    view.widthAnchor()
                        .constraintEqualToConstant(leading)
                        .setActive(true);
                }
                Some(_) => {
                    stack.addArrangedSubview(view);
                    view.setContentHuggingPriority_forOrientation(STRETCH, orientation);
                }
                None => stack.insertArrangedSubview_atIndex(view, index as isize),
            }
            if *align == CrossAlign::Fill {
                let insets = stack.edgeInsets();
                let constraint = match axis {
                    Axis::Vertical => view.widthAnchor().constraintEqualToAnchor_constant(
                        &stack.widthAnchor(),
                        -(insets.left + insets.right),
                    ),
                    Axis::Horizontal => view.heightAnchor().constraintEqualToAnchor_constant(
                        &stack.heightAnchor(),
                        -(insets.top + insets.bottom),
                    ),
                };
                constraint.setActive(true);
                fills.insert(child, constraint);
            }
        }
        refresh_filler(native, &sibling_attrs);
        self.refresh_separators(parent);
    }

    /// Records whether a container's parent stretches it along its axis and
    /// adds or drops its empty view to match.
    fn set_stretched(&mut self, id: NodeId, value: bool) {
        let children: Vec<Attrs> = match self.nodes.get(&id) {
            Some(native) => native
                .children
                .iter()
                .filter_map(|child| self.nodes.get(child).map(|native| native.attrs.clone()))
                .collect(),
            None => return,
        };
        if let Some(native) = self.nodes.get_mut(&id) {
            if let Part::Container { stretched, .. } = &mut native.part {
                *stretched = value;
            }
            refresh_filler(native, &children);
        }
    }

    fn detach_child(&mut self, parent: NodeId, child: NodeId) {
        let Some(view) = self.nodes.get(&child).map(|native| native.view.clone()) else {
            return;
        };
        let remaining: Vec<Attrs> = self.nodes[&parent]
            .children
            .iter()
            .filter(|id| **id != child)
            .filter_map(|id| self.nodes.get(id).map(|native| native.attrs.clone()))
            .collect();
        let Some(native) = self.nodes.get_mut(&parent) else {
            return;
        };
        native.children.retain(|id| *id != child);
        if let Part::Container { stack, fills, .. } = &mut native.part {
            if let Some(constraint) = fills.remove(&child) {
                constraint.setActive(false);
            }
            stack.removeArrangedSubview(&view);
        }
        view.removeFromSuperview();
        refresh_filler(native, &remaining);
        self.refresh_separators(parent);
    }

    /// Forgets a node and everything under it.
    fn remove(&mut self, id: NodeId) {
        if let Some(native) = self.nodes.remove(&id) {
            native.view.removeFromSuperview();
            for child in native.children {
                self.remove(child);
            }
        }
    }
}

fn edge_insets(padding: Padding) -> NSEdgeInsets {
    NSEdgeInsets {
        top: padding.vertical,
        left: padding.horizontal,
        bottom: padding.vertical,
        right: padding.horizontal,
    }
}

fn into_view<T: AsRef<NSView>>(view: &Retained<T>) -> Retained<NSView> {
    let view: &NSView = (**view).as_ref();
    view.retain()
}

fn orientation_of(axis: Axis) -> NSLayoutConstraintOrientation {
    match axis {
        Axis::Vertical => NSLayoutConstraintOrientation::Vertical,
        Axis::Horizontal => NSLayoutConstraintOrientation::Horizontal,
    }
}

fn cross_orientation_of(axis: Axis) -> NSLayoutConstraintOrientation {
    match axis {
        Axis::Vertical => NSLayoutConstraintOrientation::Horizontal,
        Axis::Horizontal => NSLayoutConstraintOrientation::Vertical,
    }
}

fn new_stack(
    mtm: MainThreadMarker,
    axis: Axis,
    spacing: f64,
    align: CrossAlign,
    insets: NSEdgeInsets,
) -> Retained<NSStackView> {
    let stack = NSStackView::new(mtm);
    stack.setOrientation(match axis {
        Axis::Vertical => NSUserInterfaceLayoutOrientation::Vertical,
        Axis::Horizontal => NSUserInterfaceLayoutOrientation::Horizontal,
    });
    stack.setSpacing(spacing);
    stack.setEdgeInsets(insets);
    stack.setDistribution(NSStackViewDistribution::Fill);
    stack.setDetachesHiddenViews(false);
    stack.setAlignment(match (axis, align) {
        (Axis::Vertical, CrossAlign::Center) => NSLayoutAttribute::CenterX,
        (Axis::Vertical, CrossAlign::End) => NSLayoutAttribute::Trailing,
        (Axis::Vertical, _) => NSLayoutAttribute::Leading,
        (Axis::Horizontal, CrossAlign::Start) => NSLayoutAttribute::Top,
        (Axis::Horizontal, CrossAlign::End) => NSLayoutAttribute::Bottom,
        (Axis::Horizontal, CrossAlign::Fill) => NSLayoutAttribute::Top,
        (Axis::Horizontal, CrossAlign::Center) => NSLayoutAttribute::CenterY,
    });
    stack
}

/// A stack with no growing child gets an empty view that takes the space
/// left, so its children keep their sizes at the start.
fn refresh_filler(native: &mut Native, children: &[Attrs]) {
    let Part::Container {
        stack,
        filler,
        split,
        stretched,
        ..
    } = &mut native.part
    else {
        return;
    };
    if split.is_some() {
        return;
    }
    let needs = *stretched && !children.iter().any(|attrs| attrs.grow);
    match (needs, filler.is_some()) {
        (true, false) => {
            let view = Filler::view(MainThreadMarker::from(&**stack));
            stack.addArrangedSubview(&view);
            *filler = Some(view);
        }
        (false, true) => {
            if let Some(view) = filler.take() {
                stack.removeArrangedSubview(&view);
                view.removeFromSuperview();
            }
        }
        (true, true) => {
            // Keep it last.
            if let Some(view) = filler.as_ref() {
                stack.removeArrangedSubview(view);
                stack.addArrangedSubview(view);
            }
        }
        (false, false) => {}
    }
}

fn apply_attrs(native: &mut Native, attrs: &Attrs) {
    for constraint in native.sizing.drain(..) {
        constraint.setActive(false);
    }
    let view = &native.view;
    if let Some(width) = attrs.width {
        let constraint = view.widthAnchor().constraintEqualToConstant(width);
        constraint.setActive(true);
        native.sizing.push(constraint);
    }
    if let Some(height) = attrs.height {
        let constraint = view.heightAnchor().constraintEqualToConstant(height);
        constraint.setActive(true);
        native.sizing.push(constraint);
    }
    super::hover_help::set(view, attrs.tooltip.as_deref());
    native.attrs = attrs.clone();
}

/// Pins `view` to `container`'s edges.
pub fn pin(view: &NSView, container: &NSView, inset: f64) {
    view.setTranslatesAutoresizingMaskIntoConstraints(false);
    container.addSubview(view);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        view.leadingAnchor()
            .constraintEqualToAnchor_constant(&container.leadingAnchor(), inset),
        view.trailingAnchor()
            .constraintEqualToAnchor_constant(&container.trailingAnchor(), -inset),
        view.topAnchor()
            .constraintEqualToAnchor_constant(&container.topAnchor(), inset),
        view.bottomAnchor()
            .constraintEqualToAnchor_constant(&container.bottomAnchor(), -inset),
    ]));
}

/// A vertical scroll view whose document is as wide as the visible area and
/// as tall as its content. The scroll view itself is as tall as its content
/// where nothing sizes it, as in the message panel, and scrolls once its
/// container caps it.
fn scroll_view(mtm: MainThreadMarker) -> (Retained<NSScrollView>, Retained<NSView>) {
    let scroll = NSScrollView::new(mtm);
    scroll.setHasVerticalScroller(true);
    scroll.setHasHorizontalScroller(false);
    scroll.setAutohidesScrollers(true);
    scroll.setDrawsBackground(false);
    let document = Flipped::view(mtm);
    document.setTranslatesAutoresizingMaskIntoConstraints(false);
    scroll.setDocumentView(Some(&document));
    let clip = scroll.contentView();
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        document
            .leadingAnchor()
            .constraintEqualToAnchor(&clip.leadingAnchor()),
        document
            .trailingAnchor()
            .constraintEqualToAnchor(&clip.trailingAnchor()),
        document
            .topAnchor()
            .constraintEqualToAnchor(&clip.topAnchor()),
    ]));
    let hug = scroll
        .heightAnchor()
        .constraintEqualToAnchor(&document.heightAnchor());
    hug.setPriority(SCROLL_HUG);
    hug.setActive(true);
    (scroll, document)
}

const NO_INSETS: NSEdgeInsets = NSEdgeInsets {
    top: 0.0,
    left: 0.0,
    bottom: 0.0,
    right: 0.0,
};

fn small_spinner(mtm: MainThreadMarker) -> Retained<NSProgressIndicator> {
    let spinner = NSProgressIndicator::new(mtm);
    spinner.setStyle(NSProgressIndicatorStyle::Spinning);
    spinner.setControlSize(NSControlSize::Small);
    spinner.setIndeterminate(true);
    spinner
}

fn style_card(view: &NSView, card: &Card) {
    if let Some(surface) = view.downcast_ref::<NSBox>() {
        let edge = if card.selected {
            NSColor::controlAccentColor().colorWithAlphaComponent(0.55)
        } else {
            NSColor::separatorColor()
        };
        surface.setBorderColor(&edge);
    }
}

fn style_radio(button: &NSButton, props: &Radio) {
    button.setState(if props.selected {
        NSControlStateValueOn
    } else {
        NSControlStateValueOff
    });
    button.setEnabled(props.enabled && props.on_select.is_some());
}

fn style_switch(control: &NSSwitch, props: &Switch) {
    control.setState(if props.on {
        NSControlStateValueOn
    } else {
        NSControlStateValueOff
    });
    control.setEnabled(props.enabled && props.on_toggle.is_some());
}

fn style_select(control: &NSPopUpButton, props: &Select) {
    let titles: Vec<String> = control
        .itemTitles()
        .iter()
        .map(|title| title.to_string())
        .collect();
    if titles != props.options {
        control.removeAllItems();
        for option in &props.options {
            control.addItemWithTitle(&NSString::from_str(option));
        }
    }
    control.selectItemAtIndex(props.selected.map(|index| index as isize).unwrap_or(-1));
    control.setEnabled(props.enabled && props.on_select.is_some());
}

/// A setting group's views: its title and note over a surface whose rows
/// are `rows`' children.
struct GroupViews {
    view: Retained<NSView>,
    rows: Retained<NSStackView>,
    title: Retained<NSTextField>,
    note: Retained<NSTextField>,
}

fn group_view(mtm: MainThreadMarker, group: &Group) -> GroupViews {
    let outer = new_stack(mtm, Axis::Vertical, 6.0, CrossAlign::Fill, NO_INSETS);
    let header = new_stack(
        mtm,
        Axis::Horizontal,
        8.0,
        CrossAlign::Center,
        NSEdgeInsets {
            top: 0.0,
            left: 4.0,
            bottom: 0.0,
            right: 4.0,
        },
    );
    let title = label(mtm, "");
    title.setFont(Some(&style::group_title_font()));
    title.setTextColor(Some(&NSColor::secondaryLabelColor()));
    let note = label(mtm, "");
    note.setFont(Some(&style::font(TextStyle::Caption)));
    note.setTextColor(Some(&NSColor::tertiaryLabelColor()));
    note.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    note.setContentCompressionResistancePriority_forOrientation(
        TEXT_COMPRESSION,
        NSLayoutConstraintOrientation::Horizontal,
    );
    header.addArrangedSubview(&title);
    header.addArrangedSubview(&note);
    header.addArrangedSubview(&Filler::view(mtm));
    let surface = card_box(mtm);
    let rows = new_stack(mtm, Axis::Vertical, 0.0, CrossAlign::Fill, NO_INSETS);
    pin(&rows, &surface_content(&surface), 0.0);
    outer.addArrangedSubview(&header);
    outer.addArrangedSubview(&surface);
    for view in [into_view(&header), into_view(&surface)] {
        view.widthAnchor()
            .constraintEqualToAnchor(&outer.widthAnchor())
            .setActive(true);
    }
    style_group(&title, &note, group);
    GroupViews {
        view: into_view(&outer),
        rows,
        title,
        note,
    }
}

fn style_group(title: &NSTextField, note: &NSTextField, group: &Group) {
    title.setStringValue(&NSString::from_str(&group.title));
    note.setStringValue(&NSString::from_str(group.note.as_deref().unwrap_or("")));
    note.setHidden(group.note.is_none());
}

/// A setting row's views: the line above it, its name and explanation, and
/// `controls` for its children at the end.
struct RowViews {
    view: Retained<NSView>,
    controls: Retained<NSStackView>,
    label: Retained<NSTextField>,
    description: Retained<NSTextField>,
    separator: Retained<NSBox>,
}

fn setting_row_view(mtm: MainThreadMarker, row: &SettingRow) -> RowViews {
    let view = NSView::new(mtm);
    let separator = NSBox::new(mtm);
    separator.setBoxType(NSBoxType::Separator);
    separator.setTranslatesAutoresizingMaskIntoConstraints(false);
    view.addSubview(&separator);
    let label = label(mtm, "");
    label.setFont(Some(&style::font(TextStyle::Body)));
    let description = NSTextField::wrappingLabelWithString(&NSString::from_str(""), mtm);
    description.setFont(Some(&style::font(TextStyle::Caption)));
    description.setTextColor(Some(&NSColor::secondaryLabelColor()));
    description.setSelectable(false);
    let names = new_stack(mtm, Axis::Vertical, 2.0, CrossAlign::Start, NO_INSETS);
    // A row without an explanation centers its name.
    names.setDetachesHiddenViews(true);
    names.addArrangedSubview(&label);
    names.addArrangedSubview(&description);
    names.setHuggingPriority_forOrientation(STRETCH, NSLayoutConstraintOrientation::Horizontal);
    let controls = new_stack(mtm, Axis::Horizontal, 8.0, CrossAlign::Center, NO_INSETS);
    controls.setHuggingPriority_forOrientation(KEEP, NSLayoutConstraintOrientation::Horizontal);
    controls.setContentCompressionResistancePriority_forOrientation(
        KEEP,
        NSLayoutConstraintOrientation::Horizontal,
    );
    let line = new_stack(
        mtm,
        Axis::Horizontal,
        16.0,
        CrossAlign::Center,
        NSEdgeInsets {
            top: 10.0,
            left: 16.0,
            bottom: 10.0,
            right: 16.0,
        },
    );
    line.addArrangedSubview(&names);
    line.addArrangedSubview(&controls);
    pin(&line, &view, 0.0);
    view.heightAnchor()
        .constraintGreaterThanOrEqualToConstant(48.0)
        .setActive(true);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        separator
            .leadingAnchor()
            .constraintEqualToAnchor_constant(&view.leadingAnchor(), 16.0),
        separator
            .trailingAnchor()
            .constraintEqualToAnchor_constant(&view.trailingAnchor(), -16.0),
        separator
            .topAnchor()
            .constraintEqualToAnchor(&view.topAnchor()),
    ]));
    style_setting_row(&label, &description, row);
    RowViews {
        view,
        controls,
        label,
        description,
        separator,
    }
}

fn style_setting_row(label: &NSTextField, description: &NSTextField, row: &SettingRow) {
    label.setStringValue(&NSString::from_str(&row.label));
    description.setStringValue(&NSString::from_str(
        row.description.as_deref().unwrap_or(""),
    ));
    description.setHidden(row.description.is_none());
}

pub(super) fn card_box(mtm: MainThreadMarker) -> Retained<NSBox> {
    let surface = NSBox::new(mtm);
    surface.setBoxType(NSBoxType::Custom);
    surface.setTitlePosition(NSTitlePosition::NoTitle);
    surface.setCornerRadius(10.0);
    surface.setBorderWidth(1.0);
    surface.setBorderColor(&NSColor::separatorColor());
    surface.setFillColor(&NSColor::controlBackgroundColor());
    surface.setContentViewMargins(objc2_foundation::NSSize {
        width: 0.0,
        height: 0.0,
    });
    surface
}

fn surface_content(surface: &NSBox) -> Retained<NSView> {
    surface.contentView().expect("a box has a content view")
}

fn label(mtm: MainThreadMarker, value: &str) -> Retained<NSTextField> {
    NSTextField::labelWithString(&NSString::from_str(value), mtm)
}

fn text_field(mtm: MainThreadMarker, text: &Text) -> Retained<NSTextField> {
    let field = if text.single_line {
        label(mtm, &text.text)
    } else {
        NSTextField::wrappingLabelWithString(&NSString::from_str(&text.text), mtm)
    };
    style_text_field(&field, text);
    field
}

fn style_text_field(field: &NSTextField, text: &Text) {
    field.setStringValue(&NSString::from_str(&text.text));
    field.setFont(Some(&style::font(text.style)));
    field.setTextColor(Some(&style::color(text.tone)));
    field.setSelectable(text.selectable);
    if text.single_line {
        field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        field.setMaximumNumberOfLines(1);
        field.setAllowsExpansionToolTips(true);
        field.setContentCompressionResistancePriority_forOrientation(
            TEXT_COMPRESSION,
            NSLayoutConstraintOrientation::Horizontal,
        );
    } else {
        field.setLineBreakMode(NSLineBreakMode::ByWordWrapping);
        field.setMaximumNumberOfLines(0);
        field.setContentCompressionResistancePriority_forOrientation(
            TEXT_COMPRESSION,
            NSLayoutConstraintOrientation::Horizontal,
        );
    }
}

/// A badge's surface and label, for table cells.
pub fn badge(
    mtm: MainThreadMarker,
    text: &str,
    tone: egrio_ui::node::Tone,
) -> (Retained<NSBox>, Retained<NSTextField>) {
    badge_view(
        mtm,
        &Badge {
            text: text.into(),
            tone,
        },
    )
}

fn badge_view(mtm: MainThreadMarker, badge: &Badge) -> (Retained<NSBox>, Retained<NSTextField>) {
    let surface = NSBox::new(mtm);
    surface.setBoxType(NSBoxType::Custom);
    surface.setTitlePosition(NSTitlePosition::NoTitle);
    surface.setCornerRadius(5.0);
    surface.setBorderWidth(0.0);
    surface.setContentViewMargins(objc2_foundation::NSSize {
        width: 0.0,
        height: 0.0,
    });
    let text = label(mtm, &badge.text);
    text.setFont(Some(&style::badge_font()));
    let content = surface_content(&surface);
    text.setTranslatesAutoresizingMaskIntoConstraints(false);
    content.addSubview(&text);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        text.leadingAnchor()
            .constraintEqualToAnchor_constant(&content.leadingAnchor(), 6.0),
        text.trailingAnchor()
            .constraintEqualToAnchor_constant(&content.trailingAnchor(), -6.0),
        text.topAnchor()
            .constraintEqualToAnchor_constant(&content.topAnchor(), 2.0),
        text.bottomAnchor()
            .constraintEqualToAnchor_constant(&content.bottomAnchor(), -2.0),
    ]));
    style_badge(&text, &surface, badge);
    surface
        .setContentHuggingPriority_forOrientation(KEEP, NSLayoutConstraintOrientation::Horizontal);
    (surface, text)
}

pub fn style_badge(text: &NSTextField, surface: &NSBox, badge: &Badge) {
    text.setStringValue(&NSString::from_str(&badge.text));
    let color = style::color(badge.tone);
    text.setTextColor(Some(&color));
    surface.setFillColor(&color.colorWithAlphaComponent(0.14));
}

fn symbol_view(mtm: MainThreadMarker, symbol: &Symbol) -> Retained<NSImageView> {
    let view = NSImageView::new(mtm);
    view.setImageScaling(NSImageScaling::ScaleProportionallyUpOrDown);
    style_symbol(&view, symbol);
    view
}

fn style_symbol(view: &NSImageView, symbol: &Symbol) {
    view.setImage(style::symbol(symbol.icon).as_deref());
    view.setContentTintColor(Some(&style::color(symbol.tone)));
}

fn segmented_view(
    mtm: MainThreadMarker,
    props: &Segmented,
    target: &ActionTarget,
) -> Retained<NSSegmentedControl> {
    let control = NSSegmentedControl::new(mtm);
    control.setTrackingMode(NSSegmentSwitchTracking::SelectOne);
    let target: &AnyObject = target.as_ref();
    unsafe {
        control.setTarget(Some(target));
        control.setAction(Some(ActionTarget::selector()));
    }
    style_segmented(&control, props);
    control
}

fn style_segmented(control: &NSSegmentedControl, props: &Segmented) {
    if control.segmentCount() != props.options.len() as isize {
        control.setSegmentCount(props.options.len() as isize);
    }
    for (index, option) in props.options.iter().enumerate() {
        control.setLabel_forSegment(&NSString::from_str(option), index as isize);
    }
    control.setSelectedSegment(props.selected.map(|index| index as isize).unwrap_or(-1));
    control.setEnabled(props.enabled);
}

fn composite(mtm: MainThreadMarker, fill: impl FnOnce(&NSView)) -> Retained<NSView> {
    let container = NSView::new(mtm);
    fill(&container);
    container
}

fn refill(container: &NSView, fill: impl FnOnce(&NSView)) {
    for view in container.subviews().iter() {
        view.removeFromSuperview();
    }
    fill(container);
}

/// A fact's views and what they show.
struct FactParts {
    name: Retained<NSTextField>,
    value: Retained<NSTextField>,
    mark: Option<Retained<NSImageView>>,
    shown: Fact,
}

impl FactParts {
    /// Shows `fact`, which has this fact's shape, touching only what changed.
    fn show(&mut self, fact: &Fact) {
        if fact.label != self.shown.label {
            self.name.setStringValue(&NSString::from_str(&fact.label));
        }
        if fact.value != self.shown.value {
            self.value.setStringValue(&NSString::from_str(&fact.value));
        }
        if let (Some(mark), Some(warning)) = (&self.mark, &fact.warning) {
            if fact.warning != self.shown.warning {
                super::hover_help::set(mark, Some(warning));
            }
        }
        self.shown = fact.clone();
    }
}

fn fill_facts(mtm: MainThreadMarker, container: &NSView, facts: &Facts) -> Vec<FactParts> {
    let zero = NSEdgeInsets {
        top: 0.0,
        left: 0.0,
        bottom: 0.0,
        right: 0.0,
    };
    let line = new_stack(mtm, Axis::Horizontal, 24.0, CrossAlign::Center, zero);
    let mut parts = Vec::new();
    for fact in &facts.items {
        let pair = new_stack(mtm, Axis::Horizontal, 6.0, CrossAlign::Center, zero);
        let name = label(mtm, &fact.label);
        name.setFont(Some(&style::font(TextStyle::Caption)));
        name.setTextColor(Some(&NSColor::secondaryLabelColor()));
        let value = label(mtm, &fact.value);
        let font = if fact.mono {
            style::font(TextStyle::Mono)
        } else {
            style::numeric_font(12.0)
        };
        value.setFont(Some(&font));
        value.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        value.setContentCompressionResistancePriority_forOrientation(
            TEXT_COMPRESSION,
            NSLayoutConstraintOrientation::Horizontal,
        );
        pair.addArrangedSubview(&name);
        pair.addArrangedSubview(&value);
        let mark = fact.warning.as_ref().map(|warning| {
            let mark = NSImageView::new(mtm);
            mark.setImage(style::named_symbol("exclamationmark.triangle.fill").as_deref());
            mark.setContentTintColor(Some(&NSColor::systemOrangeColor()));
            super::hover_help::set(&mark, Some(warning));
            pair.addArrangedSubview(&mark);
            mark
        });
        line.addArrangedSubview(&pair);
        parts.push(FactParts {
            name,
            value,
            mark,
            shown: fact.clone(),
        });
    }
    line.addArrangedSubview(&Filler::view(mtm));
    pin(&line, container, 0.0);
    parts
}

fn fill_fields(mtm: MainThreadMarker, container: &NSView, fields: &Fields) {
    let columns = fields.columns.max(1);
    let zero = NSEdgeInsets {
        top: 0.0,
        left: 0.0,
        bottom: 0.0,
        right: 0.0,
    };
    let rows = new_stack(mtm, Axis::Vertical, 8.0, CrossAlign::Fill, zero);
    let mut fills = Vec::new();
    let mut add_row = |cells: Vec<Retained<NSView>>| {
        let line = new_stack(mtm, Axis::Horizontal, 24.0, CrossAlign::Start, zero);
        line.setDistribution(NSStackViewDistribution::FillEqually);
        for cell in &cells {
            line.addArrangedSubview(cell);
        }
        rows.addArrangedSubview(&line);
        fills.push(
            line.widthAnchor()
                .constraintEqualToAnchor(&rows.widthAnchor()),
        );
    };
    let mut current: Vec<Retained<NSView>> = Vec::new();
    for field in &fields.items {
        if field.wide {
            if !current.is_empty() {
                pad(mtm, &mut current, columns);
                add_row(std::mem::take(&mut current));
            }
            add_row(vec![field_view(mtm, field)]);
            continue;
        }
        current.push(field_view(mtm, field));
        if current.len() == columns {
            add_row(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        pad(mtm, &mut current, columns);
        add_row(current);
    }
    pin(&rows, container, 0.0);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&fills));
}

/// Fills a short row with empty cells, so its columns line up with full rows.
fn pad(mtm: MainThreadMarker, cells: &mut Vec<Retained<NSView>>, columns: usize) {
    while cells.len() < columns {
        cells.push(NSView::new(mtm));
    }
}

fn field_view(mtm: MainThreadMarker, field: &Field) -> Retained<NSView> {
    let column = new_stack(
        mtm,
        Axis::Vertical,
        2.0,
        CrossAlign::Fill,
        NSEdgeInsets {
            top: 0.0,
            left: 0.0,
            bottom: 0.0,
            right: 0.0,
        },
    );
    let name = label(mtm, &field.label);
    name.setFont(Some(&style::font(TextStyle::Caption)));
    name.setTextColor(Some(&NSColor::secondaryLabelColor()));
    column.addArrangedSubview(&name);
    for value in &field.values {
        let text = if field.wide {
            NSTextField::wrappingLabelWithString(&NSString::from_str(value), mtm)
        } else {
            label(mtm, value)
        };
        let font = if field.mono {
            style::font(TextStyle::Mono)
        } else {
            style::numeric_font(12.0)
        };
        text.setFont(Some(&font));
        text.setSelectable(true);
        if !field.wide {
            text.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
            text.setAllowsExpansionToolTips(true);
        }
        text.setContentCompressionResistancePriority_forOrientation(
            TEXT_COMPRESSION,
            NSLayoutConstraintOrientation::Horizontal,
        );
        column.addArrangedSubview(&text);
    }
    into_view(&column)
}

fn fill_placeholder(
    mtm: MainThreadMarker,
    container: &NSView,
    placeholder: &Placeholder,
    target: &ActionTarget,
) {
    let column = new_stack(
        mtm,
        Axis::Vertical,
        6.0,
        CrossAlign::Center,
        NSEdgeInsets {
            top: 24.0,
            left: 20.0,
            bottom: 24.0,
            right: 20.0,
        },
    );
    let title = label(mtm, &placeholder.title);
    title.setFont(Some(&style::font(TextStyle::Body)));
    title.setTextColor(Some(&NSColor::secondaryLabelColor()));
    column.addArrangedSubview(&title);
    if let Some(detail) = &placeholder.detail {
        let text = NSTextField::wrappingLabelWithString(&NSString::from_str(detail), mtm);
        text.setFont(Some(&style::font(TextStyle::Caption)));
        text.setTextColor(Some(&NSColor::tertiaryLabelColor()));
        text.setAlignment(objc2_app_kit::NSTextAlignment::Center);
        column.addArrangedSubview(&text);
    }
    if let Some(action) = &placeholder.action {
        column.setCustomSpacing_afterView(
            12.0,
            &column.arrangedSubviews().lastObject().expect("the title"),
        );
        let button = button_view(
            mtm,
            &Button {
                label: Some(action.label.clone()),
                icon: action.icon,
                tone: Tone::Default,
                style: ButtonStyle::Primary,
                key: None,
                enabled: true,
                busy: false,
                on_press: Some(action.on_press.clone()),
            },
            target,
        );
        column.addArrangedSubview(&button);
    }
    // Centered, so the placeholder takes whatever space its parent gives.
    column.setTranslatesAutoresizingMaskIntoConstraints(false);
    container.addSubview(&column);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        column
            .centerXAnchor()
            .constraintEqualToAnchor(&container.centerXAnchor()),
        column
            .centerYAnchor()
            .constraintEqualToAnchor(&container.centerYAnchor()),
        column
            .leadingAnchor()
            .constraintGreaterThanOrEqualToAnchor_constant(&container.leadingAnchor(), 0.0),
        column
            .topAnchor()
            .constraintGreaterThanOrEqualToAnchor_constant(&container.topAnchor(), 0.0),
    ]));
}
